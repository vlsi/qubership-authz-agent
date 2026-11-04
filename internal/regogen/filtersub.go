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
	"context"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// A placeholder ${…} of a predicate is replaced by the value of its source,
// as legacy renders it: without escaping, a scalar as its text, a list as its
// items in the dialect's quotes. A value that holds a placeholder is
// substituted again, and $${x} is the text ${x}. A source that fails, a
// placeholder of an undeclared PIP, and one of the resource fail the whole
// filter with DENY.
//
// The knobs of the agent profile this follows: idiom_template=
// recursive_escape, idiom_render_number_text=plain_stripped,
// idiom_render_quote=none, list_order=sorted, dedupe_lists=true,
// permissions_order=hashset, permissions_capacity=GROWTH,
// mongo_uuid_for_mapping=true, mongo_uuid_for_untyped=true,
// mongo_uuid_for_regular=false, object_placeholder=EMPTY,
// scalar_body_placeholder=KEEP, null_body_keeps_placeholder=true,
// empty_header_is_empty_value=true, token_error_placeholder=deny_all,
// unresolved_placeholder=DENY_ALL, resource_type_text=request,
// custom_param_source=FIRST_WORD, custom_param_resource=TEXT_BARE,
// custom_param_non_string=VALUE.

// valueKind is how a source's value renders.
type valueKind int

const (
	valScalar valueKind = iota // its text
	valList                    // items in quotes
	valUUID                    // items in quotes, in MongoDB as {"$uuid": …}
	valKeep                    // the placeholder as written
	valEmpty                   // no value
)

type sourceValue struct {
	kind  valueKind
	text  string // valScalar, valKeep
	items []jsonvalue.Value
}

// substituter renders the predicates of one filter request.
type substituter struct {
	m   *Module
	ctx context.Context
	req *Request
	// general caches the value of each GENERAL or FILTERED PIP: one call per
	// filter.
	general map[string]sourceValue
}

// term returns the predicates preds of the rule key with their
// placeholders substituted, in pass (-1 outside an iterate).
func (s *substituter) term(preds policyir.Predicates, key string, pass int) (*fexpr, error) {
	t := &fterm{key: key, text: map[policyir.Dialect]string{}, template: map[policyir.Dialect]string{},
		subst: map[policyir.Dialect]map[string]string{}}
	for _, d := range slices.Sorted(maps.Keys(preds.Text)) {
		text := preds.Text[d]
		if d == policyir.DialectQueryDSL {
			text = strings.ReplaceAll(text, "${resourceType}", s.resourceType())
		}
		t.template[d] = text
		t.subst[d] = map[string]string{}
		out, err := s.substitute(text, d, pass, t.subst[d])
		if err != nil {
			return nil, err
		}
		t.text[d] = out
	}
	if c := preds.Custom; c != nil {
		ct := &customTerm{Predicate: c.Predicate, Params: map[string]jsonvalue.Value{}}
		for name, raw := range c.Params {
			v, err := s.param(raw, pass)
			if err != nil {
				return nil, err
			}
			ct.Params[name] = v
		}
		t.custom = ct
	}
	return &fexpr{kind: "leaf", term: t}, nil
}

// substitute renders each placeholder of text for dialect d and records in
// seen the text each became. A value holding a placeholder is rendered
// again, four times at most; $${x} stays as the text ${x}.
func (s *substituter) substitute(text string, d policyir.Dialect, pass int, seen map[string]string) (string, error) {
	var failure error
	one := func(m string) string {
		name := m[2 : len(m)-1]
		v, err := s.source(name, pass)
		if err != nil {
			failure = err
			return m
		}
		out := renderValue(v, d)
		seen[name] = out
		return out
	}
	out := placeholderRE.ReplaceAllStringFunc(strings.ReplaceAll(text, "$${", "\x00{"), one)
	for range 4 {
		again := placeholderRE.ReplaceAllStringFunc(out, one)
		if again == out {
			break
		}
		out = again
	}
	if failure != nil {
		return "", failure
	}
	return strings.ReplaceAll(out, "\x00{", "${"), nil
}

func (s *substituter) resourceType() string {
	switch v := s.req.Body.ResourceType.(type) {
	case string:
		return v
	case nil:
		return "None"
	}
	return legacyvalue.Text(s.req.Body.ResourceType)
}

// source returns the value of the placeholder expr.
func (s *substituter) source(expr string, pass int) (sourceValue, error) {
	if expr == "resourceType" {
		return sourceValue{kind: valScalar, text: s.resourceType()}, nil
	}
	name, ok := strings.CutPrefix(expr, "subject.")
	if !ok {
		return sourceValue{}, errDenyAll
	}
	switch name {
	case "id", "name", "type":
		v := s.req.Values[specKey("subj", name)]
		if v.State != spectables.StateValue {
			return sourceValue{kind: valScalar, text: "None"}, nil
		}
		return sourceValue{kind: valScalar, text: filterScalarText(v.Value)}, nil
	case "roles", "scopes":
		v := s.req.Values[specKey("subj", name)]
		l, _ := v.Value.([]jsonvalue.Value)
		return sourceValue{kind: valList, items: l}, nil
	case "permissions":
		v := s.m.permissions(s.req)
		switch v.State {
		case spectables.StateValue:
			l, _ := v.Value.([]jsonvalue.Value)
			return sourceValue{kind: valUUID, items: hashSetOrder(l)}, nil
		case spectables.StateEmptyColl:
			return sourceValue{kind: valEmpty}, nil
		}
		return sourceValue{}, errDenyAll
	}
	if key, ok := strings.CutPrefix(name, "permissionScope."); ok {
		sc := s.req.Scope
		if pass < 0 || sc == nil || pass >= len(sc.grants) {
			return sourceValue{}, errDenyAll
		}
		vals, ok := sc.grants[pass][key]
		if !ok {
			return sourceValue{}, errDenyAll
		}
		return sourceValue{kind: valList, items: sortedItems(vals)}, nil
	}
	decl, ok := s.m.pips(expr)
	if !ok || decl.Isolated != "" {
		return sourceValue{}, errDenyAll
	}
	switch decl.Type {
	case policyir.PIPHeader, policyir.PIPToken:
		var v Resolved
		if decl.Type == policyir.PIPHeader {
			v = headerPIP(decl, s.req.Headers)
		} else {
			v = tokenPIP(decl, s.req.Claims)
		}
		switch v.State {
		case spectables.StateValue:
			if l, ok := v.Value.([]jsonvalue.Value); ok {
				return sourceValue{kind: valUUID, items: l}, nil
			}
			return sourceValue{kind: valUUID, items: []jsonvalue.Value{v.Value}}, nil
		case spectables.StateError:
			return sourceValue{}, errDenyAll
		}
		return sourceValue{kind: valEmpty}, nil
	case policyir.PIPGeneral, policyir.PIPFiltered:
		return s.generalValue(decl, expr)
	}
	// a MAPPING PIP by its own name reads as ABSENT, as in a condition
	return sourceValue{}, errDenyAll
}

// generalValue calls the GENERAL or FILTERED PIP decl, once per filter.
func (s *substituter) generalValue(decl *policyir.PIP, expr string) (sourceValue, error) {
	if v, ok := s.general[decl.Name]; ok {
		if v.kind < 0 {
			return sourceValue{}, errDenyAll
		}
		return v, nil
	}
	v, err := s.callGeneral(decl, expr)
	if err != nil {
		s.general[decl.Name] = sourceValue{kind: -1}
		return sourceValue{}, err
	}
	s.general[decl.Name] = v
	return v, nil
}

func (s *substituter) callGeneral(decl *policyir.PIP, expr string) (sourceValue, error) {
	keep := sourceValue{kind: valKeep, text: expr}
	q := pipCall(&Ref{pip: decl}, s.req, s.m.pips)
	if o, ok := q.Value.(ast.Object); ok {
		if st := o.Get(ast.StringTerm("s")); st != nil {
			if st.Value.Compare(ast.String(spectables.StateError)) == 0 {
				return sourceValue{}, errDenyAll
			}
			return keep, nil
		}
	}
	resp, err := regobuiltins.Send(s.ctx, q)
	if err != nil {
		return sourceValue{}, errDenyAll
	}
	jp, err := pipPath(decl)
	if err != nil {
		return sourceValue{}, errDenyAll
	}
	r, err := pipResolve(rego.BuiltinContext{Context: s.ctx}, resp, jp)
	if err != nil {
		return sourceValue{}, errDenyAll
	}
	kind := valUUID
	if decl.ReturnType == "JSON" || decl.ReturnType == "REGULAR" {
		kind = valList
	}
	switch r.State {
	case spectables.StateError:
		return sourceValue{}, errDenyAll
	case spectables.StatePIPNull:
		return keep, nil
	case spectables.StatePIPEmpty:
		return sourceValue{kind: valEmpty}, nil
	case spectables.StateScalarOdd:
		if jp == "" {
			// a number or a boolean as the whole body: the placeholder stays
			return keep, nil
		}
		return sourceValue{kind: kind, items: []jsonvalue.Value{r.Value}}, nil
	}
	switch x := r.Value.(type) {
	case *jsonvalue.Object:
		return sourceValue{kind: valEmpty}, nil
	case []jsonvalue.Value:
		items := sortedItems(x)
		if len(items) == 0 {
			return sourceValue{kind: valEmpty}, nil
		}
		return sourceValue{kind: kind, items: items}, nil
	}
	return sourceValue{kind: kind, items: []jsonvalue.Value{r.Value}}, nil
}

// param returns the value of a customPredicate parameter written as raw: the
// placeholder its first word names when that word starts with subject. or
// is resourceType, the text resource for the bare word resource, and null
// for any other word. A boolean or null goes in as it is, and a leading
// space fails the filter.
func (s *substituter) param(raw string, pass int) (jsonvalue.Value, error) {
	v, err := jsonvalue.Decode([]byte(raw))
	if err != nil {
		return nil, errDenyAll
	}
	var src string
	switch x := v.(type) {
	case nil, bool:
		return x, nil
	case jsonvalue.Number:
		src = string(x)
	case string:
		src = x
	default:
		return nil, errDenyAll
	}
	word, _, _ := strings.Cut(src, " ")
	switch {
	case word == "":
		return nil, errDenyAll
	case word == "resource":
		return word, nil
	case !strings.HasPrefix(word, "subject.") && word != "resourceType":
		return nil, nil
	}
	sv, err := s.source(word, pass)
	if err != nil {
		return nil, err
	}
	switch sv.kind {
	case valScalar, valKeep:
		return sv.text, nil
	case valEmpty:
		return []jsonvalue.Value{}, nil
	}
	return slices.Clone(sv.items), nil
}

// renderValue is the text of v in dialect d.
func renderValue(v sourceValue, d policyir.Dialect) string {
	if (v.kind == valList || v.kind == valUUID) && len(v.items) == 0 {
		v.kind = valEmpty
	}
	switch v.kind {
	case valScalar:
		return v.text
	case valKeep:
		return "${" + v.text + "}"
	case valEmpty:
		switch d {
		case policyir.DialectSQL:
			return "NULL"
		case policyir.DialectQueryDSL:
			return `""`
		case policyir.DialectMongoDB:
			return "[  ]"
		}
		return ""
	}
	items := make([]string, len(v.items))
	for i, x := range v.items {
		items[i] = itemText(x)
	}
	switch d {
	case policyir.DialectSQL:
		return "'" + strings.Join(items, "', '") + "'"
	case policyir.DialectMongoDB:
		if v.kind == valUUID {
			return `[ { "$uuid": "` + strings.Join(items, `" }, { "$uuid": "`) + `" } ]`
		}
		return `[ "` + strings.Join(items, `", "`) + `" ]`
	}
	return `"` + strings.Join(items, `", "`) + `"`
}

// itemText is the text of an item of a list: a number with its trailing
// zeros stripped and in plain notation, a boolean as true or false.
func itemText(v jsonvalue.Value) string {
	if n, ok := v.(jsonvalue.Number); ok {
		return plainStripped(string(n))
	}
	return filterScalarText(v)
}

func filterScalarText(v jsonvalue.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	}
	return legacyvalue.Text(v)
}

// sortedItems returns vals without repeats, ordered by their text.
func sortedItems(vals []jsonvalue.Value) []jsonvalue.Value {
	out := dedupe(vals)
	slices.SortStableFunc(out, func(a, b jsonvalue.Value) int { return strings.Compare(canonText(a), canonText(b)) })
	return out
}

func canonText(v jsonvalue.Value) string {
	if n, ok := v.(jsonvalue.Number); ok {
		return legacyvalue.Text(n)
	}
	return filterScalarText(v)
}

// hashSetOrder returns the names without repeats in the order a
// java.util.HashSet of them iterates: by bucket of their String.hashCode,
// then by insertion. The table has 16 buckets and doubles whenever the size
// passes three quarters of them, as when the names are added one by one.
func hashSetOrder(vals []jsonvalue.Value) []jsonvalue.Value {
	var out []jsonvalue.Value
	seen := map[string]bool{}
	for _, v := range vals {
		t := canonText(v)
		if !seen[t] {
			seen[t] = true
			out = append(out, v)
		}
	}
	n := uint32(16)
	for float64(len(out)) > 0.75*float64(n) {
		n *= 2
	}
	bucket := func(v jsonvalue.Value) uint32 {
		var h uint32
		for _, c := range utf16.Encode([]rune(canonText(v))) {
			h = 31*h + uint32(c)
		}
		return (h ^ h>>16) & (n - 1)
	}
	slices.SortStableFunc(out, func(a, b jsonvalue.Value) int { return int(bucket(a)) - int(bucket(b)) })
	return out
}

func sortedKeys[K ~string, V any](m map[K]V) []K { return slices.Sorted(maps.Keys(m)) }
