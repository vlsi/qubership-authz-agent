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
	"slices"
	"testing"
)

func TestTreeUnsupportedIsEmptyForAValidTree(t *testing.T) {
	t.Parallel()

	p := validParts()
	tree, err := NewTree(p.simplified, p.sets, p.pips)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.Unsupported(); len(got) != 0 {
		t.Errorf("Unsupported() = %v, want none", got)
	}
}

// An iterate counts as nested under any iterating ancestor, not only under its
// parent, so s4 below s3, which does not iterate, is reported too.
func TestTreeUnsupportedListsEveryForm(t *testing.T) {
	t.Parallel()

	p := validParts()
	p.simplified[0].Policies[0].Condition = one(PlaceSimplified,
		Compare{Op: OpEQ, Left: Unsupported{Form: FormJSONPath, Text: "resource.a[0:2:1]"}, Right: String{Value: "x"}})
	p.rule().Condition = one(PlaceRuleCondition,
		readOp, Unsupported{Form: FormSyntax, Text: "resource.a  == 1"})
	p.sets[0].Policies[0].Target = one(PlacePolicyTarget,
		Compare{Op: OpEQ, Left: Resource{Path: ".a"}, Right: Unsupported{Form: FormJSONPath, Text: "resource.b[0:2:1]"}})
	p.sets[0].Sets = append(p.sets[0].Sets,
		&PolicySet{ID: "s3", Sets: []*PolicySet{{ID: "s4", Iterate: &Iterate{Var: "w", Algorithm: AlgorithmDenyOverrides}}}})
	p.pips[0].Unsupported = "query, body"
	tree, err := NewTree(p.simplified, p.sets, p.pips)
	if err != nil {
		t.Fatal(err)
	}

	want := []Finding{
		{Where: `pip "subject.region"`, Form: FormPIPExtension, Text: "query, body"},
		{Where: `simplified "d"/"c"/"uri" > policy "sp1" > condition`, Form: FormJSONPath, Text: "resource.a[0:2:1]"},
		{Where: `set "s1" > policy "p1" > target`, Form: FormJSONPath, Text: "resource.b[0:2:1]"},
		{Where: `set "s1" > policy "p1" > rule "r1" > condition`, Form: FormSyntax, Text: "resource.a  == 1"},
		{Where: `set "s1" > set "s3" > set "s4"`, Form: FormNestedIterate, Text: "iterate var w"},
	}
	if got := tree.Unsupported(); !slices.Equal(got, want) {
		t.Errorf("Unsupported() =\n%v\nwant\n%v", got, want)
	}
}

// Findings in two sibling sets that share an ID name each set by its position.
func TestTreeUnsupportedTellsApartSiblingsThatShareAnID(t *testing.T) {
	t.Parallel()

	target := func(text string) *Condition {
		return &Condition{Place: PlaceSetTarget, Disjuncts: [][]Atom{{Unsupported{Form: FormSyntax, Text: text}}}}
	}
	tree, err := NewTree(nil, []*PolicySet{{ID: "s", Target: target("a")}, {ID: "s", Target: target("b")}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []Finding{
		{Where: `set "s" #0 > target`, Form: FormSyntax, Text: "a"},
		{Where: `set "s" #1 > target`, Form: FormSyntax, Text: "b"},
	}
	if got := tree.Unsupported(); !slices.Equal(got, want) {
		t.Errorf("Unsupported() =\n%v\nwant\n%v", got, want)
	}
}
