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
	"slices"
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
	domain   spectables.Domain
}

// litVal is a literal operand with its record.
type litVal struct {
	kind  spectables.Kind
	class spectables.Class
	key   string
	keys  []string
	raw   string // the text of a string literal
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
func literal(o policyir.Operand) (*litVal, error) {
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
		v = items
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
	if kind == spectables.KindResource {
		// The export's domain of the whole resource holds only an object, and
		// a request may send a string, a number, or a list. A value of those
		// classes takes the cells of a resource attribute (resourceKind).
		path, _ := g.tab.Domain(spectables.ProfileAgent, spectables.KindResPath)
		for _, cl := range path.Classes {
			if !slices.Contains(dom.Classes, cl) {
				dom.Classes = append(slices.Clone(dom.Classes), cl)
			}
		}
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
		l, err := literal(o)
		if err != nil {
			return nil, err
		}
		return &side{kind: l.kind, lit: l}, nil
	case policyir.Operation:
		if g.fixedOp != nil {
			l, _ := literal(policyir.String{Value: *g.fixedOp})
			return &side{kind: spectables.KindOperation, lit: &litVal{kind: spectables.KindOperation,
				class: spectables.ClassString, key: l.key, keys: l.keys, raw: l.raw}}, nil
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
