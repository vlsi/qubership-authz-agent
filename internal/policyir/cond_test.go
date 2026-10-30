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

package policyir

import (
	"testing"
)

func TestNewCompare(t *testing.T) {
	t.Parallel()

	res := Resource{Path: ".a"}
	one := List{Items: []Literal{String{Value: "x"}}}
	cases := []struct {
		name    string
		op      Operator
		left    Operand
		right   Operand
		wantErr bool
	}{
		{"binary operator with both sides", OpEQ, res, String{Value: "x"}, false},
		{"binary operator without a right side", OpEQ, res, nil, true},
		{"unary operator without a right side", OpIsNull, res, nil, false},
		{"unary operator with a right side", OpIsNull, res, String{Value: "x"}, true},
		{"unknown operator", Operator("LIKE"), res, String{Value: "x"}, true},
		{"nil left", OpEQ, nil, String{Value: "x"}, true},
		{"literal on the left", OpIn, String{Value: "r"}, Subject{Attr: SubjectRoles}, false},
		{"list on the left", OpEQ, one, res, true},
		{"pattern on the left", OpEQ, Pattern{Text: "/a/*"}, res, true},
		{"pattern right of MATCH", OpMatch, res, Pattern{Text: "/a/*"}, false},
		{"resource right of NOT MATCH", OpNotMatch, res, Resource{Path: ".p"}, true},
		{"subject right of MATCH", OpMatch, res, Subject{Attr: SubjectName}, true},
		{"PIP right of MATCH", OpMatch, res, PIPRef{Name: "subject.p"}, true},
		{"pass value right of MATCH", OpMatch, res, PassValue{Var: "v", Key: "k"}, true},
		{"string right of MATCH", OpMatch, res, String{Value: "/a/*"}, true},
		{"pattern right of EQ", OpEQ, res, Pattern{Text: "/a/*"}, true},
		{"list right of IN", OpIn, res, one, false},
		{"list right of EQ", OpEQ, res, one, true},
		{"string right of IN", OpIn, res, String{Value: "x"}, true},
		{"number right of CONTAINS ANY", OpContainsAny, res, Number{Text: "5"}, true},
		{"attribute right of IN", OpIn, res, Subject{Attr: SubjectRoles}, false},
		{"unsupported right of EQ", OpEQ, res, Unsupported{Form: FormJSONPath, Text: "resource.a[0:2:1]"}, false},
		{"unsupported right of MATCH", OpMatch, res, Unsupported{Form: FormSyntax, Text: "x"}, false},
		{"FILTERED reference on the right", OpIn, res, PIPRef{Name: "subject.o.filtered", Filtered: true, FilteredOperation: "READ"}, false},
		{"FILTERED reference on the left", OpIn, PIPRef{Name: "subject.o.filtered", Filtered: true}, one, true},
		{"FILTERED reference without the .filtered suffix", OpIn, res, PIPRef{Name: "subject.o", Filtered: true}, true},
		{"FILTERED reference right of MATCH", OpMatch, res, PIPRef{Name: "subject.o.filtered", Filtered: true}, true},
		{"PIP reference with no name", OpEQ, PIPRef{}, String{Value: "x"}, true},
		{"permissionScope with a key", OpEQ, Subject{Attr: SubjectPermissionScope, Key: "a.b"}, String{Value: "x"}, false},
		{"permissionScope without a key", OpEQ, Subject{Attr: SubjectPermissionScope}, String{Value: "x"}, true},
		{"pass value without a key", OpEQ, PassValue{Var: "v"}, String{Value: "x"}, true},
		{"roles with a key", OpEQ, Subject{Attr: SubjectRoles, Key: "a"}, String{Value: "x"}, true},
		{"unknown subject attribute", OpEQ, Subject{Attr: "entitledResources"}, String{Value: "x"}, true},
		{"entitledResources with no as names", OpEQ, Entitled{ResourceType: "order"}, String{Value: "x"}, true},
		{"pass value with no var", OpEQ, PassValue{Key: "region"}, String{Value: "x"}, true},
		{"empty pattern", OpMatch, res, Pattern{}, true},
		{"number as a pattern", OpMatch, res, Pattern{Text: "5"}, true},
		{"subject attribute as a pattern", OpMatch, res, Pattern{Text: "subject.name"}, true},
		{"subject attribute and a wildcard character as a pattern", OpMatch, res, Pattern{Text: "subject.name%"}, false},
		{"unsupported operand of an unknown form", OpEQ, res, Unsupported{Form: "regex", Text: "x"}, true},
		{"filter operation without FILTERED", OpIn, res, PIPRef{Name: "subject.o", FilteredOperation: "READ"}, true},
		{"invalid number on the right", OpEQ, res, Number{Text: "5."}, true},
		{"invalid path on the left", OpEQ, Resource{Path: "a"}, String{Value: "x"}, true},
		{"path package jsonpath refuses on the left", OpEQ, Resource{Path: ".a[0:2:1]"}, String{Value: "x"}, true},
		{"path package jsonpath refuses right of EQ", OpEQ, res, Resource{Path: ".a[0:2:1]"}, true},
		{"attribute pattern with a space inside brackets", OpMatch, res, Pattern{Text: "resource.a[0, 1]"}, false},
		{"pattern with a space", OpMatch, res, Pattern{Text: "/a b"}, true},
		{"pattern with a vertical tab", OpMatch, res, Pattern{Text: "/a\vb"}, true},
		{"pattern with a non-ASCII letter", OpMatch, res, Pattern{Text: "/é"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCompare(tc.op, tc.left, tc.right)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("NewCompare(%s, %#v, %#v) error = %v, want error %t", tc.op, tc.left, tc.right, err, tc.wantErr)
			}
		})
	}
}

// The operators that take no right operand, and those whose literal right
// operand is a list, are the parser's sets; an operator added to Operators
// without a decision about both fails here.
func TestOperatorArityAndListSets(t *testing.T) {
	t.Parallel()

	unary := map[Operator]bool{OpIsNull: true, OpIsNotNull: true, OpIsEmpty: true, OpIsNotEmpty: true}
	list := map[Operator]bool{
		OpIn: true, OpNotIn: true, OpContainsAny: true, OpNotContainsAny: true, OpIsSubset: true, OpIsNotSubset: true,
	}
	binary := map[Operator]bool{
		OpEQ: true, OpNE: true, OpLT: true, OpLE: true, OpGT: true, OpGE: true, OpContains: true, OpNotContains: true,
		OpMatch: true, OpNotMatch: true,
	}
	if got, want := len(Operators()), len(unary)+len(list)+len(binary); got != want {
		t.Errorf("len(Operators()) = %d, want %d: classify the new operator here", got, want)
	}
	for _, op := range Operators() {
		if !unary[op] && !list[op] && !binary[op] {
			t.Errorf("operator %s is in none of the sets of this test", op)
		}
		if got := op.Unary(); got != unary[op] {
			t.Errorf("%s.Unary() = %t, want %t", op, got, unary[op])
		}
		if got := op.TakesList(); got != list[op] {
			t.Errorf("%s.TakesList() = %t, want %t", op, got, list[op])
		}
	}
}

func TestConditionHasOr(t *testing.T) {
	t.Parallel()

	if got := one(PlaceRuleCondition, readOp, readOp).HasOr(); got {
		t.Errorf("HasOr() of one conjunction = true, want false")
	}
	two := &Condition{Place: PlaceRuleCondition, Disjuncts: [][]Atom{{readOp}, {readOp}}}
	if got := two.HasOr(); !got {
		t.Errorf("HasOr() of two disjuncts = false, want true")
	}
}

func TestNewNumber(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text    string
		wantErr bool
	}{
		{"0", false},
		{"005", false},
		{"12.30", false},
		{"-7", false},
		{"-0.5", false},
		{"-0.05", false},
		{"-05", true},
		{"-0", true},
		{"-0.0", true},
		{"-0.50", true},
		{".5", true},
		{"5.", true},
		{"5e0", true},
		{"５", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			_, err := NewNumber(tc.text)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("NewNumber(%q) error = %v, want error %t", tc.text, err, tc.wantErr)
			}
		})
	}
}

func TestNewList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		items   []Literal
		wantErr bool
	}{
		{"one string", "", []Literal{String{Value: "a"}}, false},
		{"two numbers", "1, 2", []Literal{Number{Text: "1"}, Number{Text: "2"}}, false},
		{"two booleans", "true,false", []Literal{Bool{Value: true}, Bool{Value: false}}, false},
		{"no items", "", nil, true},
		{"a string and a number", "'a',1", []Literal{String{Value: "a"}, Number{Text: "1"}}, true},
		{"an invalid number", "", []Literal{Number{Text: "-05"}}, true},
		{"two items without a raw token", "", []Literal{String{Value: "a"}, String{Value: "b"}}, true},
		{"one item with a raw token", "'a'", []Literal{String{Value: "a"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewList(tc.raw, tc.items...)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("NewList(%q, %v) error = %v, want error %t", tc.raw, tc.items, err, tc.wantErr)
			}
		})
	}
}

func TestNewCondition(t *testing.T) {
	t.Parallel()

	atom := Compare{Op: OpEQ, Left: Operation{}, Right: String{Value: "READ"}}
	cases := []struct {
		name      string
		place     Place
		disjuncts [][]Atom
		wantErr   bool
	}{
		{"one atom", PlaceRuleCondition, [][]Atom{{atom}}, false},
		{"two disjuncts", PlaceSetTarget, [][]Atom{{atom}, {Const{Value: true}, IsM2M{}}}, false},
		{"access with an empty operation", PlaceRuleCondition, [][]Atom{{Access{Operation: ""}}}, false},
		{"unknown place", Place("filter"), [][]Atom{{atom}}, true},
		{"no disjuncts", PlaceRuleCondition, nil, true},
		{"an empty disjunct", PlaceRuleCondition, [][]Atom{{atom}, {}}, true},
		{"a nil atom", PlaceRuleCondition, [][]Atom{{nil}}, true},
		{"an invalid comparison", PlaceRuleCondition, [][]Atom{{Compare{Op: OpEQ, Left: Operation{}}}}, true},
		{"an unsupported atom without text", PlaceRuleCondition, [][]Atom{{Unsupported{Form: FormSyntax}}}, true},
		{"an unsupported atom of an unknown form", PlaceRuleCondition, [][]Atom{{Unsupported{Form: "x", Text: "x"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCondition(tc.place, tc.disjuncts...)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("NewCondition(%q, %v) error = %v, want error %t", tc.place, tc.disjuncts, err, tc.wantErr)
			}
		})
	}
}

func TestNewConditionCopiesDisjuncts(t *testing.T) {
	t.Parallel()

	d := []Atom{Const{Value: true}}
	c, err := NewCondition(PlaceRuleCondition, d)
	if err != nil {
		t.Fatal(err)
	}
	d[0] = Const{Value: false}
	if got := FormatCondition(c); got != "TRUE" {
		t.Errorf("FormatCondition after the caller changed its slice = %q, want %q", got, "TRUE")
	}
}
