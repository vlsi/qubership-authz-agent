// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package regogen

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// Ref is an operand the module reads from the request: an attribute of the
// resource, the subject, or a PIP. The projection puts its value record into
// input under the reference's ID, or, for a network PIP, the stub nc.pip
// returns it.
type Ref struct {
	// ID is the name of the reference in the module: op, rt, or rN.
	ID string
	// Key identifies the operand across the generator and the projection: the
	// operand as the specification writes it, as JSON, such as
	// ["res", ".a.b"] or ["subj", "roles"].
	Key string
	// Kind is the operand kind of the specification's tables.
	Kind spectables.Kind
	// Network is set for an operand whose value comes from a network call:
	// a GENERAL or FILTERED PIP and subject.entitledResources.
	Network bool
	// Segments is set when a MATCH guard reads the path segments of the value.
	Segments bool
	// Subset is set when IS SUBSET reads the value's element tokens.
	Subset bool
	domain spectables.Domain
}

// litVal is a literal operand with its record.
type litVal struct {
	kind  spectables.Kind
	class spectables.Class
	key   string
	keys  []string
	raw   string // the text of a string literal
	// num is the number <, <=, >, and >= read the literal as, nil for none.
	num *jsonvalue.Decimal
	// sa and sb are the tokens IS SUBSET reads of the literal on the left and
	// on the right.
	sa [][]string
	sb []string
}

// side is one operand of a comparison: a literal, a pattern, a reference, or a
// value the generator knows to be in one state.
type side struct {
	kind    spectables.Kind
	lit     *litVal
	pattern string
	ref     *Ref
	// fixed is the only state the operand can be in at this leaf, when the
	// generator knows it: subject.permissionScope outside a pass of iterate.
	fixed spectables.State
}

func (s *side) isPattern() bool { return s.kind == spectables.KindPattern }

var jsonpathRE = regexp.MustCompile(`\[|\.\.|\*|\?|\(`)

// resourceKind is the operand kind of a resource path in the tables: the
// whole resource, a JSONPath (brackets, .., *, ?, or a call), one attribute,
// or a nested attribute.
func resourceKind(path string) spectables.Kind {
	switch {
	case path == "":
		return spectables.KindResource
	case jsonpathRE.MatchString(path):
		return spectables.KindResJSONPath
	case strings.Count(path, ".") == 1:
		return spectables.KindResPath
	default:
		return spectables.KindResNested
	}
}

func specKey(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// SpecKey returns the operand as the specification writes it, as JSON. The
// projection matches resolved values to references by it.
func SpecKey(o policyir.Operand) (string, bool) {
	switch o := o.(type) {
	case policyir.Resource:
		if o.Path == ".null" {
			return specKey("null"), true
		}
		return specKey("res", o.Path), true
	case policyir.Subject:
		if o.Attr == policyir.SubjectPermissionScope {
			return specKey("subj", "permissionScope."+o.Key), true
		}
		return specKey("subj", string(o.Attr)), true
	case policyir.PIPRef:
		return specKey("subj", strings.TrimPrefix(o.Name, "subject.")), true
	case policyir.Entitled:
		return specKey("ent", o.ResourceType, o.As), true
	}
	return "", false
}

// literal returns the record of a literal operand.
func literal(o policyir.Operand) (*litVal, error) { return literalSplit(o, nil) }

// literalSplit returns the record of a literal operand; split, when not nil,
// reads a list of two or more quoted strings from its token.
func literalSplit(o policyir.Operand, split func(raw string) ([]jsonvalue.Value, error)) (*litVal, error) {
	var v jsonvalue.Value
	var kind spectables.Kind
	switch o := o.(type) {
	case policyir.String:
		v, kind = o.Value, spectables.KindLitStr
	case policyir.Number:
		v, kind = jsonvalue.Number(o.Text), spectables.KindLitNum
	case policyir.Bool:
		v, kind = o.Value, spectables.KindLitBool
	case policyir.List:
		items := make([]jsonvalue.Value, len(o.Items))
		num := true
		for i, it := range o.Items {
			switch it := it.(type) {
			case policyir.String:
				items[i], num = it.Value, false
			case policyir.Number:
				items[i] = jsonvalue.Number(it.Text)
			case policyir.Bool:
				items[i], num = it.Value, false
			}
		}
		strs := true
		for _, it := range o.Items {
			if _, ok := it.(policyir.String); !ok {
				strs = false
			}
		}
		v = items
		if strs && len(o.Items) > 1 && split != nil {
			parts, err := split(o.Raw)
			if err != nil {
				return nil, err
			}
			if parts != nil {
				v = parts
			}
		}
		switch {
		case num && len(items) == 1:
			kind = spectables.KindListNum1
		case num:
			kind = spectables.KindListNumN
		case len(items) == 1:
			kind = spectables.KindListStr1
		default:
			kind = spectables.KindListStrN
		}
	default:
		return nil, fmt.Errorf("operand %T is not a literal", o)
	}
	rec := legacyvalue.Of(v)
	l := &litVal{kind: kind, keys: rec.Keys}
	if s, ok := v.(string); ok {
		l.raw = s
	}
	if rec.Key != nil {
		l.key = *rec.Key
	}
	switch o := o.(type) {
	case policyir.String:
		if d, ok := jsonvalue.ParseBigDecimal(o.Value); ok {
			l.num = &d
		}
	case policyir.Number:
		l.num = literalNumber(o.Text)
	}
	num := literalNumberText
	if _, ok := o.(policyir.List); ok {
		num = listNumberText
	}
	l.sa, l.sb = subsetLeft(v, num), subsetRight(v, num, false)
	switch kind {
	case spectables.KindLitStr:
		l.class = spectables.ClassString
	case spectables.KindLitNum, spectables.KindLitBool:
		l.class = spectables.ClassScalar
	default:
		l.class = spectables.ClassList
	}
	return l, nil
}

// operandKind returns the kind of a non-literal operand in the specification's
// tables, whether it comes from the network, and whether the tenant declares
// it (a PIP reference may name a PIP the tenant does not declare).
func (g *gen) operandKind(o policyir.Operand) (kind spectables.Kind, network, declared bool, err error) {
	switch o := o.(type) {
	case policyir.Operation:
		return spectables.KindOperation, false, true, nil
	case policyir.ResourceType:
		return spectables.KindResourceType, false, true, nil
	case policyir.Resource:
		if o.Path == ".null" {
			return spectables.KindNull, false, true, nil
		}
		return resourceKind(o.Path), false, true, nil
	case policyir.Subject:
		return spectables.Kind("subj." + string(o.Attr)), false, true, nil
	case policyir.Entitled:
		return spectables.KindEntitled, true, true, nil
	case policyir.PIPRef:
		if o.Name == "subject.permissionScope" {
			return spectables.KindSubjPermissionScope, false, true, nil
		}
		pip, ok := g.tree.PIP(o.Name)
		if !ok {
			g.fail(Failure{Set: g.where.set, PIP: o.Name, Reason: "not declared"})
			return "", false, false, nil
		}
		if pip.Isolated != "" {
			g.fail(Failure{Set: g.where.set, PIP: o.Name, Reason: "isolated: " + pip.Isolated})
			return "", false, false, nil
		}
		switch pip.Type {
		case policyir.PIPGeneral, "":
			return spectables.KindPIPGeneral, true, true, nil
		case policyir.PIPFiltered:
			return spectables.KindPIPFiltered, true, true, nil
		case policyir.PIPHeader:
			return spectables.KindPIPHeader, false, true, nil
		case policyir.PIPToken:
			return spectables.KindPIPToken, false, true, nil
		case policyir.PIPMapping:
			return spectables.KindPIPMapping, false, true, nil
		}
		return "", false, true, fmt.Errorf("PIP %s of type %s", o.Name, pip.Type)
	case policyir.PassValue:
		return spectables.KindSubjPermissionScope, false, true, nil
	case policyir.Unsupported:
		return "", false, true, fmt.Errorf("unsupported %s operand %q", o.Form, o.Text)
	}
	return "", false, true, fmt.Errorf("operand %T", o)
}

// ref returns the reference of an operand, creating it on first use.
func (g *gen) ref(o policyir.Operand, kind spectables.Kind, network bool) (*Ref, error) {
	var key, id string
	switch o.(type) {
	case policyir.Operation:
		key, id = specKey("operation"), "op"
	case policyir.ResourceType:
		key, id = specKey("resourceType"), "rt"
	default:
		k, ok := SpecKey(o)
		if !ok {
			return nil, fmt.Errorf("operand %T has no reference", o)
		}
		key = k
	}
	if r, ok := g.refs[key]; ok {
		return r, nil
	}
	dom, ok := g.tab.Domain(spectables.ProfileAgent, kind)
	if !ok {
		return nil, fmt.Errorf("kind %s has no domain", kind)
	}
	if id == "" {
		g.nextRef++
		id = fmt.Sprintf("r%d", g.nextRef)
	}
	r := &Ref{ID: id, Key: key, Kind: kind, Network: network, domain: dom}
	g.refs[key] = r
	g.refList = append(g.refList, r)
	return r, nil
}

// side builds one operand of a comparison.
func (g *gen) side(o policyir.Operand) (*side, error) {
	switch o := o.(type) {
	case policyir.Pattern:
		return &side{kind: spectables.KindPattern, pattern: o.Text}, nil
	case policyir.String, policyir.Number, policyir.Bool, policyir.List:
		l, err := literalSplit(o, g.splitList)
		if err != nil {
			return nil, err
		}
		return &side{kind: l.kind, lit: l}, nil
	case policyir.Operation:
		if g.fixedOp != nil {
			l, _ := literal(policyir.String{Value: *g.fixedOp})
			return &side{kind: spectables.KindOperation, lit: &litVal{kind: spectables.KindOperation,
				class: spectables.ClassString, key: l.key, keys: l.keys, raw: l.raw, num: l.num, sa: l.sa, sb: l.sb}}, nil
		}
	case policyir.Subject:
		if o.Attr == policyir.SubjectPermissionScope {
			return &side{kind: spectables.KindSubjPermissionScope, fixed: spectables.StateScopeOutside}, nil
		}
	}
	kind, network, declared, err := g.operandKind(o)
	if err != nil {
		return nil, err
	}
	if !declared {
		return nil, errUndeclared
	}
	r, err := g.ref(o, kind, network)
	if err != nil {
		return nil, err
	}
	return &side{kind: kind, ref: r}, nil
}

// splitList reads a literal list of two or more quoted strings as the
// profile's knobs say: string_list_split ELEMENTS keeps the items as written
// (nil), SPLIT and SPLIT_TRIM read them from the token, quotes dropped, split
// at every comma, trailing empty parts dropped, and SPLIT_TRIM trims each part
// by idiom_list_item_trim, java_trim cutting characters up to U+0020 as Java's
// String.trim does. Any other value of a knob is an error, not a default.
func (g *gen) splitList(raw string) ([]jsonvalue.Value, error) {
	mode, err := g.stringKnob("string_list_split")
	if err != nil {
		return nil, err
	}
	switch mode {
	case "ELEMENTS":
		return nil, nil
	case "SPLIT", "SPLIT_TRIM":
	default:
		return nil, fmt.Errorf("knob string_list_split is %q", mode)
	}
	trim := func(p string) string { return p }
	if mode == "SPLIT_TRIM" {
		how, err := g.stringKnob("idiom_list_item_trim")
		if err != nil {
			return nil, err
		}
		if how != "java_trim" {
			return nil, fmt.Errorf("knob idiom_list_item_trim is %q", how)
		}
		trim = func(p string) string { return strings.TrimFunc(p, func(r rune) bool { return r <= ' ' }) }
	}
	parts := strings.Split(strings.ReplaceAll(raw, "'", ""), ",")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	out := make([]jsonvalue.Value, len(parts))
	for i, p := range parts {
		out[i] = trim(p)
	}
	return out, nil
}

// stringKnob returns a knob of the agent profile that holds a string.
func (g *gen) stringKnob(name string) (string, error) {
	raw, ok := g.tab.Knob(spectables.ProfileAgent, name)
	if !ok {
		return "", fmt.Errorf("the export carries no knob %s", name)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("knob %s: %w", name, err)
	}
	return v, nil
}
