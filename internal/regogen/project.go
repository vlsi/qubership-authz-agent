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
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regogen/spectables"
)

// Resolved is the value of one operand on a request, as the specification's
// Ctx.resolve gives it: a state and, in state VALUE, the value.
type Resolved struct {
	State      spectables.State
	Value      jsonvalue.Value
	HeaderList bool // a HEADER or GENERAL list, class hl
}

// Request is what the projection reads of a check/resource request. Resolving
// the operands (reading the token, calling PIPs, walking the resource) is not
// the generator's job; the prototype takes the values the specification
// resolved.
type Request struct {
	Operation, ResourceType string
	Roles                   []string
	M2M                     bool
	// Values holds the resolved value of each operand, by [Ref.Key].
	Values map[string]Resolved
	// Nodes holds the interval of each iterate set, by set ID: lo and hi,
	// each P, N, or D.
	Nodes map[string][2]string
}

// Record is the value record of a reference, as the module reads it.
type Record struct {
	S    string
	T    string
	K    *string
	KS   []string
	Raw  *string
	Segs []string
	// N0 is set for a list that holds a null element; its keys leave the
	// null out.
	N0 bool
	// TK is the key of the text a string equals a list or an object by
	// (structureText).
	TK *string
	// Len is the number of elements of a list, null elements included.
	Len *int
	// O is the key two lists are equal by, their typed elements as a set, and
	// the key two objects are equal by, member by member.
	O *string
	// EA and EB hold the tokens of the elements of a list, or of a value
	// read as a list of one, such that two elements are equal under the
	// collection operators exactly when the EA of one meets the EB of the
	// other: EA holds the token of the element's value (eqToken), and EB
	// adds, for a list or an object, the token of its text, which a string
	// equals it by.
	EA, EB []string
}

// Input is the projection of a request into the input of a module.
type Input struct {
	Records map[string]Record // by reference ID, network PIPs included
	SRoles  []string
	M2M     bool
	G       []string
	nodes   map[string][2]string
	refs    []*Ref
}

// class is the class of a value in state VALUE that is not null: the class
// of legacyvalue, with its one class for an object, a nested list, and a list
// with a null element split three ways.
func class(v jsonvalue.Value, lv legacyvalue.Record) spectables.Class {
	switch {
	case lv.State == legacyvalue.StateNullElement:
		return spectables.ClassNullElement
	case lv.State == legacyvalue.StateEmptyColl:
		// the whole resource can be an empty list in state VALUE
		return spectables.ClassList
	case lv.Class != legacyvalue.ClassOther:
		return spectables.Class(lv.Class)
	}
	if _, ok := v.(*jsonvalue.Object); ok {
		return spectables.ClassObject
	}
	return spectables.ClassNested
}

func record(r *Ref, v Resolved) Record {
	rec := Record{S: string(v.State)}
	if v.State == spectables.StateSingleOdd {
		// a one-element GENERAL list of null, a boolean, or an object: the
		// collection operators read it as a list
		lv := legacyvalue.Of(v.Value)
		rec.KS = lv.Keys
		if rec.KS == nil {
			rec.KS = []string{}
		}
		rec.N0 = lv.State == legacyvalue.StateNullElement
		rec.EA, rec.EB = elementTokens(v.Value)
		return rec
	}
	if v.State != spectables.StateValue {
		return rec
	}
	if v.Value == nil {
		rec.T = string(spectables.ClassNull)
		return rec
	}
	lv := legacyvalue.Of(v.Value)
	cl := class(v.Value, lv)
	if cl == spectables.ClassList && v.HeaderList {
		cl = spectables.ClassHeaderList
	}
	rec.T = string(cl)
	rec.EA, rec.EB = elementTokens(v.Value)
	switch cl {
	case spectables.ClassString, spectables.ClassScalar:
		rec.K = lv.Key
		rec.KS = []string{*lv.Key}
	default:
		rec.KS = lv.Keys
		if rec.KS == nil {
			rec.KS = []string{}
		}
		rec.N0 = lv.State == legacyvalue.StateNullElement
		tk := legacyvalue.Fold(structureText(v.Value))
		rec.TK = &tk
		rec.O = lv.Structure
		if l, ok := v.Value.([]jsonvalue.Value); ok {
			n := len(l)
			rec.Len = &n
		}
		if lv.State == legacyvalue.StateEmptyColl {
			// the record of an empty list carries no structure key; it is []
			empty := "[]"
			rec.O = &empty
		}
	}
	if s, ok := v.Value.(string); ok {
		rec.Raw = &s
		if r.Segments {
			rec.Segs = strings.Split(s, "/")
		}
	}
	return rec
}

// elementTokens returns the EA and EB of a value, a list or a value read as
// a list of one.
func elementTokens(v jsonvalue.Value) (ea, eb []string) {
	l, ok := v.([]jsonvalue.Value)
	if !ok {
		l = []jsonvalue.Value{v}
	}
	ea, eb = []string{}, []string{}
	for _, e := range l {
		if t, ok := eqToken(e); ok {
			ea = append(ea, t)
			eb = append(eb, t)
		}
		switch e.(type) {
		case []jsonvalue.Value, *jsonvalue.Object:
			eb = append(eb, "t:"+legacyvalue.Fold(structureText(e)))
		}
	}
	return ea, eb
}

// eqToken returns the token two elements are equal by when neither is a
// string facing a list or an object: a scalar by its key, as
// equalsIgnoreCase compares the texts; an object by its members, with their
// case; a list by its elements in order, each by its token. Null equals
// nothing, so null and a list that holds one have no token.
func eqToken(e jsonvalue.Value) (string, bool) {
	switch e := e.(type) {
	case nil:
		return "", false
	case *jsonvalue.Object:
		return "o:" + *legacyvalue.Of(e).Structure, true
	case []jsonvalue.Value:
		parts := make([]string, len(e))
		for i, x := range e {
			t, ok := eqToken(x)
			if !ok {
				return "", false
			}
			parts[i] = t
		}
		b, err := json.Marshal(parts)
		if err != nil {
			panic(err)
		}
		return "l:" + string(b), true
	}
	return "t:" + *legacyvalue.Of(e).Key, true
}

// Project builds the input of the module for a request. It fails when the
// request lacks the value of an operand the module reads.
func Project(m *Module, req Request) (*Input, error) {
	in := &Input{Records: map[string]Record{}, M2M: req.M2M, nodes: req.Nodes, refs: m.Refs}
	for _, r := range req.Roles {
		in.SRoles = append(in.SRoles, legacyvalue.Fold(r))
	}
	for _, r := range m.Refs {
		var v Resolved
		switch r.ID {
		case "op":
			v = Resolved{State: spectables.StateValue, Value: req.Operation}
		case "rt":
			v = Resolved{State: spectables.StateValue, Value: req.ResourceType}
		default:
			var ok bool
			if v, ok = req.Values[r.Key]; !ok {
				return nil, fmt.Errorf("no resolved value of %s (%s)", r.Key, r.ID)
			}
		}
		in.Records[r.ID] = record(r, v)
	}
	for _, id := range m.IterateSets {
		if _, ok := req.Nodes[id]; !ok {
			return nil, fmt.Errorf("no interval of the iterate set %s", id)
		}
	}
	in.G = EvalGroups(m, in)
	return in, nil
}

func strTerm(s string) *ast.Term { return ast.StringTerm(s) }

func strsTerm(ss []string) *ast.Term {
	ts := make([]*ast.Term, len(ss))
	for i, s := range ss {
		ts[i] = ast.StringTerm(s)
	}
	return ast.ArrayTerm(ts...)
}

func (r Record) term() *ast.Term {
	o := ast.NewObject([2]*ast.Term{strTerm("s"), strTerm(r.S)})
	if r.T != "" {
		o.Insert(strTerm("t"), strTerm(r.T))
	}
	if r.K != nil {
		o.Insert(strTerm("k"), strTerm(*r.K))
	}
	if r.KS != nil {
		o.Insert(strTerm("ks"), strsTerm(r.KS))
	}
	if r.Raw != nil {
		o.Insert(strTerm("raw"), strTerm(*r.Raw))
	}
	if r.N0 {
		o.Insert(strTerm("n0"), ast.BooleanTerm(true))
	}
	if r.TK != nil {
		o.Insert(strTerm("tk"), strTerm(*r.TK))
	}
	if r.O != nil {
		o.Insert(strTerm("o"), strTerm(*r.O))
	}
	if r.Len != nil {
		o.Insert(strTerm("ln"), ast.IntNumberTerm(*r.Len))
	}
	if r.EA != nil {
		o.Insert(strTerm("ea"), strsTerm(r.EA))
		o.Insert(strTerm("eb"), strsTerm(r.EB))
	}
	return ast.NewTerm(o)
}

// Value returns the input as a Rego value: maps s, t, k, ks, raw, seg, eseg,
// nseg, n0, tk, o, ln, ea, and eb from a reference ID to a field of its
// record, then sroles, m2m, and g. A network PIP's record is not in it:
// nc.pip returns it.
func (in *Input) Value() ast.Value {
	fields := map[string]ast.Object{}
	for _, f := range []string{"s", "t", "k", "ks", "raw", "seg", "eseg", "nseg", "n0", "tk", "o", "ln", "ea",
		"eb"} {
		fields[f] = ast.NewObject()
	}
	for _, r := range in.refs {
		if r.Network {
			continue
		}
		rec := in.Records[r.ID]
		id := strTerm(r.ID)
		fields["s"].Insert(id, strTerm(rec.S))
		if rec.T != "" {
			fields["t"].Insert(id, strTerm(rec.T))
		}
		if rec.K != nil {
			fields["k"].Insert(id, strTerm(*rec.K))
		}
		if rec.KS != nil {
			fields["ks"].Insert(id, strsTerm(rec.KS))
		}
		if rec.Raw != nil {
			fields["raw"].Insert(id, strTerm(*rec.Raw))
		}
		if rec.N0 {
			fields["n0"].Insert(id, ast.BooleanTerm(true))
		}
		if rec.TK != nil {
			fields["tk"].Insert(id, strTerm(*rec.TK))
		}
		if rec.O != nil {
			fields["o"].Insert(id, strTerm(*rec.O))
		}
		if rec.Len != nil {
			fields["ln"].Insert(id, ast.IntNumberTerm(*rec.Len))
		}
		if rec.EA != nil {
			fields["ea"].Insert(id, strsTerm(rec.EA))
			fields["eb"].Insert(id, strsTerm(rec.EB))
		}
		if rec.Segs != nil {
			fields["seg"].Insert(id, strsTerm(rec.Segs))
			rev := slices.Clone(rec.Segs)
			slices.Reverse(rev)
			fields["eseg"].Insert(id, strsTerm(rev))
			fields["nseg"].Insert(id, ast.IntNumberTerm(len(rec.Segs)))
		}
	}
	o := ast.NewObject()
	for f, v := range fields {
		o.Insert(strTerm(f), ast.NewTerm(v))
	}
	o.Insert(strTerm("sroles"), strsTerm(in.SRoles))
	o.Insert(strTerm("m2m"), ast.BooleanTerm(in.M2M))
	o.Insert(strTerm("g"), strsTerm(in.G))
	return o
}

// PIPRecord returns the record nc.pip returns for a network reference, and
// false for an unknown one.
func (in *Input) PIPRecord(id string) (*ast.Term, bool) {
	r, ok := in.Records[id]
	if !ok {
		return nil, false
	}
	return r.term(), true
}

// NodeInterval returns the record nc.node returns for an iterate set: lo and
// hi, each P, N, or D.
func (in *Input) NodeInterval(id string) (*ast.Term, bool) {
	iv, ok := in.nodes[id]
	if !ok {
		return nil, false
	}
	return ast.ObjectTerm([2]*ast.Term{strTerm("lo"), strTerm(iv[0])},
		[2]*ast.Term{strTerm("hi"), strTerm(iv[1])}), true
}

// structureText is the text a string compares a list or an object by, as the
// agent profile prints it: the members in document order, a scalar member as
// its Java text with a number stripped of trailing zeros in plain notation,
// and a member that is itself a list or an object as compact JSON with its
// numbers as written.
func structureText(v jsonvalue.Value) string {
	member := func(x jsonvalue.Value) string {
		switch x := x.(type) {
		case []jsonvalue.Value, *jsonvalue.Object:
			return jsonText(x)
		case nil:
			return "null"
		case bool:
			return strconv.FormatBool(x)
		case jsonvalue.Number:
			return plainStripped(string(x))
		case string:
			return x
		}
		return ""
	}
	var parts []string
	switch v := v.(type) {
	case []jsonvalue.Value:
		for _, x := range v {
			parts = append(parts, member(x))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *jsonvalue.Object:
		for _, k := range v.Keys() {
			x, _ := v.Get(k)
			parts = append(parts, k+"="+member(x))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return member(v)
}

// jsonText is compact JSON with the numbers as the document writes them.
func jsonText(v jsonvalue.Value) string {
	var parts []string
	switch v := v.(type) {
	case []jsonvalue.Value:
		for _, x := range v {
			parts = append(parts, jsonText(x))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *jsonvalue.Object:
		for _, k := range v.Keys() {
			x, _ := v.Get(k)
			parts = append(parts, jsonString(k)+":"+jsonText(x))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case jsonvalue.Number:
		return string(v)
	case string:
		return jsonString(v)
	case bool:
		return strconv.FormatBool(v)
	}
	return "null"
}

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

var numberRE = regexp.MustCompile(`^(-?)(\d*)(?:\.(\d*))?(?:[eE]([-+]?\d+))?$`)

// plainStripped is BigDecimal.stripTrailingZeros().toPlainString() of a
// number's text: 5.50 is 5.5, 5.0 is 5, 1e3 is 1000.
func plainStripped(text string) string {
	m := numberRE.FindStringSubmatch(text)
	if m == nil {
		return text
	}
	coef := strings.TrimLeft(m[2]+m[3], "0")
	exp := -len(m[3])
	if m[4] != "" {
		e, err := strconv.Atoi(m[4])
		if err != nil {
			return text
		}
		exp += e
	}
	for strings.HasSuffix(coef, "0") {
		coef = coef[:len(coef)-1]
		exp++
	}
	if coef == "" {
		return "0"
	}
	var out string
	switch point := len(coef) + exp; {
	case exp >= 0:
		out = coef + strings.Repeat("0", exp)
	case point > 0:
		out = coef[:point] + "." + coef[point:]
	default:
		out = "0." + strings.Repeat("0", -point) + coef
	}
	return m[1] + out
}
