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
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// The text a string compares a structure by prints a scalar member as Java
// text with numbers stripped of trailing zeros, and a nested member as
// compact JSON with its numbers as written. The expected texts are what the
// specification's agent profile prints.
func TestStructureText(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`["x", null]`, `[x, null]`},
		{`[1.0, true]`, `[1, true]`},
		{`[1.50e1, -0.0, 100]`, `[15, 0, 100]`},
		{`[["a"], "b"]`, `[["a"], b]`},
		{`{"k": {"b": "c"}}`, `{k={"b":"c"}}`},
		{`{"a": [1.0]}`, `{a=[1.0]}`},
		{`[]`, `[]`},
	} {
		v, err := jsonvalue.Decode([]byte(tc.value))
		if err != nil {
			t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
		}
		if got := structureText(v); got != tc.want {
			t.Errorf("structureText(%s) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// The record of a value carries the folded text a string compares it by
// (TK), the tokens of its elements (EA), and those tokens with the folded
// text of each nested list or object after the element's own token (EB). A
// list with a number or null is not a list of strings, whose text TK takes
// from the folded Java text.
func TestRecordReadsTheTokensOfTheElements(t *testing.T) {
	for _, tc := range []struct {
		value, tk string
		ea, eb    []string
	}{
		{`["Ab", "c"]`, `[ab, c]`, []string{"t:ab", "t:c"}, []string{"t:ab", "t:c"}},
		{`[]`, `[]`, []string{}, []string{}},
		{`["x", ["Y"], "Z"]`, `[x, ["y"], z]`, []string{"t:x", `l:["t:y"]`, "t:z"},
			[]string{"t:x", `l:["t:y"]`, "t:[y]", "t:z"}},
		{`[1.0, "A"]`, `[1, a]`, []string{"t:1.0", "t:a"}, []string{"t:1.0", "t:a"}},
		{`[null, "A"]`, `[null, a]`, []string{"t:a"}, []string{"t:a"}},
		{`"Q"`, ``, []string{"t:q"}, []string{"t:q"}},
	} {
		t.Run(tc.value, func(t *testing.T) {
			v, err := jsonvalue.Decode([]byte(tc.value))
			if err != nil {
				t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
			}
			rec := record(&Ref{}, Resolved{State: spectables.StateValue, Value: v})
			tk := ""
			if rec.TK != nil {
				tk = *rec.TK
			}
			if tk != tc.tk || !slices.Equal(rec.EA, tc.ea) || !slices.Equal(rec.EB, tc.eb) {
				t.Errorf("record(%s): tk %q, ea %q, eb %q; want tk %q, ea %q, eb %q", tc.value, tk, rec.EA, rec.EB,
					tc.tk, tc.ea, tc.eb)
			}
		})
	}
}

// A record holds a field that is costly to build, the keys, the text, the
// structure key, or the element tokens of a list, where the module reads it
// and the record of every field holds it, and nowhere else: CONTAINS reads
// the keys alone, as do the policies of a subject's permissions, and == with
// a string reads the text. The value is a list of strings, an empty list, or
// a one-element GENERAL list of an object, whose record has no text.
func TestARecordHoldsTheFieldsTheModuleReads(t *testing.T) {
	for _, tc := range []struct{ condition, state, value string }{
		{"subject.permissions CONTAINS 'p1'", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == 'p1'", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == resource.b", "VALUE", `["p1", "p2"]`},
		{"subject.permissions CONTAINS ANY resource.b", "VALUE", `["p1", "p2"]`},
		{"subject.permissions IS EMPTY", "VALUE", `["p1", "p2"]`},
		{"subject.permissions == resource.b", "VALUE", `[]`},
		{"subject.permissions CONTAINS ANY resource.b", "VALUE", `[]`},
		{"subject.g CONTAINS 'p1'", "SINGLE_ODD", `[{"a": 1}]`},
		{"subject.g CONTAINS ANY resource.b", "SINGLE_ODD", `[{"a": 1}]`},
		{"subject.g == 'x'", "SINGLE_ODD", `[{"a": 1}]`},
	} {
		t.Run(tc.condition+" "+tc.value, func(t *testing.T) {
			condition := tc.condition
			id, key, pips := "subject.permissions", `["subj","permissions"]`, ""
			if tc.state == "SINGLE_ODD" {
				id, key, pips = "subject.g", `["subj","g"]`, generalPIPs
			}
			values := map[string]Resolved{key: resolved(t, tc.state, tc.value),
				`["res",".b"]`: resolved(t, "VALUE", `["p2"]`)}
			m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", condition, pips), table(t),
				DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			in, err := Project(m, Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: values})
			if err != nil {
				t.Fatalf("Project: %v", err)
			}
			rec, ok := in.Records[id]
			if !ok {
				t.Fatalf("the input holds no record of %s", id)
			}
			whole := record(&Ref{}, values[key])
			i := slices.IndexFunc(m.Refs, func(r *Ref) bool { return r.ID == id })
			if i < 0 {
				t.Fatalf("the module has no reference %s", id)
			}
			// a copy, so that reading the expressions marks no field
			r := *m.Refs[i]
			s := &side{ref: &r}
			for f, has := range map[string][2]bool{"ks": {rec.KS != nil, whole.KS != nil},
				"tk": {rec.TK != nil, whole.TK != nil}, "o": {rec.O != nil, whole.O != nil},
				"ea": {rec.EA != nil, whole.EA != nil}} {
				reads := strings.Contains(m.Text, s.field(f))
				if f == "ea" {
					reads = reads || strings.Contains(m.Text, s.field("eb"))
				}
				if has[0] != (reads && has[1]) {
					t.Errorf("the module reads %s of %s: %v, the record of every field holds it: %v, "+
						"the record holds it: %v", f, id, reads, has[1], has[0])
				}
			}
		})
	}
}

// The input carries a field of a record where the text of the module reads
// it, and the subject groups read the others from the record in Go: with
// groups, CONTAINS of the subject's permissions moves into a group, and the
// input keeps the keys of the permissions out while the record holds them.
func TestTheInputCarriesTheFieldsTheTextReads(t *testing.T) {
	const id, key = "subject.permissions", `["subj","permissions"]`
	req := Request{Body: Body{Operation: "read", ResourceType: "doc"},
		Values: map[string]Resolved{key: resolved(t, "VALUE", `["p1", "p2"]`)}}
	for _, groups := range []bool{false, true} {
		opt := DefaultOptions()
		opt.Groups = groups
		m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.permissions CONTAINS 'p1'",
			""), table(t), opt)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		in := mustProject(t, m, req)
		if in.Records[id].KS == nil {
			t.Errorf("groups %v: the record of %s holds no keys", groups, id)
		}
		ks := in.Value().(ast.Object).Get(ast.StringTerm("ks")).Value.(ast.Object).Get(ast.StringTerm(id))
		reads := strings.Contains(m.Text, "input.ks"+refIndex(id))
		if (ks != nil) != reads {
			t.Errorf("groups %v: the text reads input.ks of %s: %v, the input carries it: %v", groups, id, reads,
				ks != nil)
		}
		if reads == groups {
			t.Errorf("groups %v: the text reads input.ks of %s: %v", groups, id, reads)
		}
	}
}

// markEmitted sets each field the text reads of the reference it reads it
// of, and no other: every field name, n0 and nseg among them, after input
// and after p, the record of a pass value, with the index of a name that is
// an identifier and of one that is not. A field read with no index is set
// for every reference.
func TestMarkEmittedSetsTheFieldsTheTextReads(t *testing.T) {
	x, ab := &Ref{ID: "x"}, &Ref{ID: "a.b<"}
	for _, f := range recordFields {
		for _, text := range []string{
			"input." + f + refIndex(x.ID) + " == 1\n  not input.s" + refIndex(ab.ID),
			"some p in input.ps\n  p." + f + refIndex(x.ID) + "[0]\n  p.s" + refIndex(ab.ID),
		} {
			markEmitted([]*Ref{x, ab}, text)
			if want := fieldsKnown | fieldBit(f); x.emit != want {
				t.Errorf("%q: emit of x %b, want %b", text, x.emit, want)
			}
			if want := fieldsKnown | fieldBit("s"); ab.emit != want {
				t.Errorf("%q: emit of %s %b, want %b", text, ab.ID, ab.emit, want)
			}
		}
	}
	markEmitted([]*Ref{x, ab}, "count(input.ks) > 0")
	if want := fieldsKnown | fieldBit("ks"); x.emit != want || ab.emit != want {
		t.Errorf("input.ks with no index: emit %b and %b, want %b for both", x.emit, ab.emit, want)
	}
}
