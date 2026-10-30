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

// The tree holds every node type, every atom type, and every operand type, so
// a type left without a case in Dump shows up here as a <T> placeholder.
func TestTreeDump(t *testing.T) {
	t.Parallel()

	pips := []*PIP{
		{Name: "subject.tier", Type: PIPToken, Claim: "tier", DefaultValue: `"none"`, Domain: "D"},
		{Name: "subject.owners.filtered", Type: PIPFiltered, URL: "http://pip/owners", ResourceType: "order",
			Unsupported: "timeoutSeconds"},
		{
			Name: "subject.region", Type: PIPGeneral, URL: "http://pip/region", HTTPMethod: "POST",
			JSONPath: "$.region", ReturnType: "JSON", Headers: "X-A,X-B",
			RequestAttributes: map[string]string{"z": `"${subject.id}"`, "a": "1", "m": "true", "c": "null", "x": "[]", "b": `{"k":2}`},
		},
	}
	simplified := []*SimplifiedGroup{{
		Domain: "d", Component: "c", ResourceType: "ALL",
		Policies: []*SimplifiedPolicy{{
			ID: "sp1", Frontend: true, Operation: "ALL", Roles: []string{"admin", "viewer"},
			Condition: one(PlaceSimplified, IsM2M{}, Const{Value: false}),
			Predicates: Predicates{
				Text:   map[Dialect]string{DialectQueryDSL: "q", DialectRSQL: "r"},
				Custom: &CustomPredicate{Predicate: "byOwner", Params: map[string]string{"y": "null", "x": `"subject.id"`}},
			},
		}},
	}}
	sets := []*PolicySet{
		{
			ID: "s1", Name: "orders", Domain: "d", Algorithm: AlgorithmDenyOverrides,
			Target: one(PlaceSetTarget, Compare{Op: OpEQ, Left: ResourceType{}, Right: String{Value: "order"}},
				Compare{Op: OpIsNotNull, Left: Subject{Attr: SubjectPermissionScope, Key: "a.b"}}),
			Iterate: &Iterate{Var: "v", Algorithm: AlgorithmPermitOverrides},
			Policies: []*Policy{{
				ID: "p1", Name: "P", Target: nil,
				Rules: []*Rule{
					{
						ID: "r1", Name: "R", Effect: EffectAllow,
						Target: one(PlaceRuleTarget, Compare{Op: OpIn, Left: Operation{},
							Right: List{Items: []Literal{String{Value: "READ"}, String{Value: "EDIT"}}, Raw: "'READ','EDIT'"}}),
						Condition: &Condition{Place: PlaceRuleCondition, Disjuncts: [][]Atom{
							{
								Compare{Op: OpGE, Left: Resource{Path: ".amount"}, Right: Number{Text: "12.30"}},
								Compare{Op: OpIsNotEmpty, Left: Subject{Attr: SubjectRoles}},
							},
							{Access{Operation: "EDIT"}, Access{Denied: true, Operation: "DELETE"}},
							{
								Compare{Op: OpEQ, Left: PIPRef{Name: "subject.region.code"}, Right: PassValue{Var: "v", Key: "region"}},
								Compare{Op: OpEQ, Left: Subject{Attr: SubjectID}, Right: Unsupported{Form: FormJSONPath, Text: "resource.a[0:2:1]"}},
								Compare{Op: OpContains, Left: Bool{Value: true}, Right: PIPRef{Name: "subject.owners.filtered", Filtered: true}},
							},
							{
								Compare{Op: OpNotMatch, Left: Resource{Path: "['path']"}, Right: Pattern{Text: "/api/*"}},
								Compare{Op: OpIsSubset, Left: Entitled{ResourceType: "order", As: []string{"id", "owner"}}, Right: Resource{Path: ".null"}},
								Unsupported{Form: FormJSONPath, Text: "x.y"},
							},
						}},
						Predicates: Predicates{Text: map[Dialect]string{
							DialectMongoDB: `{"r": 1}`, DialectSQL: "r = 1", DialectRSQL: "r==1",
						}},
					},
					{ID: "r2", Effect: EffectAbsent, Frontend: true},
				},
			}},
			Sets: []*PolicySet{{ID: "s2", AlwaysFails: "iterate without an algorithm"}},
		},
	}
	tree, err := NewTree(simplified, sets, pips)
	if err != nil {
		t.Fatal(err)
	}

	want := `pip "subject.tier" type=TOKEN claim="tier" defaultValue="none" domain="D"
pip "subject.owners.filtered" type=FILTERED url="http://pip/owners" resourceType="order" unsupported="timeoutSeconds"
pip "subject.region" type=GENERAL url="http://pip/region" httpMethod="POST" jsonPath="$.region" returnType="JSON" headers="X-A,X-B" requestAttributes={"a": 1, "b": {"k":2}, "c": null, "m": true, "x": [], "z": "${subject.id}"}
simplified "" name="" domain="d" component="c" resourceType="ALL"
  policy "sp1" operation="ALL" roles=["admin", "viewer"] frontend
    condition[simplified]: subject.isM2M AND FALSE
    predicate rsql "r"
    predicate querydsl "q"
    customPredicate "byOwner" params={"x": "subject.id", "y": null}
set "s1" name="orders" domain="d" algorithm=DENY_OVERRIDES
  target[set_target]: resourceType EQ "order" AND subject.permissionScope["a.b"] IS_NOT_NULL
  iterate var="v" algorithm=PERMIT_OVERRIDES
  policy "p1" name="P" algorithm=absent
    rule "r1" name="R" effect=ALLOW
      target[rule_target]: operation IN ["READ", "EDIT"] raw="'READ','EDIT'"
      condition[rule_condition]: resource.amount GE 12.30 AND subject.roles IS_NOT_EMPTY OR subject allowed "EDIT" on resource AND subject denied "DELETE" on resource OR pip("subject.region.code") EQ pass("v")["region"] AND subject.id EQ unsupported(jsonpath "resource.a[0:2:1]") AND true CONTAINS pip("subject.owners.filtered") FILTERED "" OR resource['path'] NOT_MATCH pattern("/api/*") AND subject.entitledResources.of("order").as["id", "owner"] IS_SUBSET resource.null AND unsupported(jsonpath "x.y")
      predicate rsql "r==1"
      predicate sql "r = 1"
      predicate mongodb "{\"r\": 1}"
    rule "r2" name="" effect=absent frontend
  set "s2" name="" domain="" algorithm=absent
    always fails: "iterate without an algorithm"
`
	if got := tree.Dump(); got != want {
		t.Errorf("Dump() =\n%s\nwant\n%s", got, want)
	}
}

// A resource path that holds a character outside printable ASCII is quoted, so
// a newline in a bracket key cannot start a line of its own in the dump.
func TestFormatOperandQuotesAPathOutsidePrintableASCII(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{"a newline", "['a\nb']", `resource"['a\nb']"`},
		{"a tab", "['a\tb']", `resource"['a\tb']"`},
		{"a letter outside ASCII", "['\u00e9']", `resource"['é']"`},
		{"a space", "['a b']", `resource['a b']`},
		{"a dotted path", ".a.b", `resource.a.b`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatOperand(Resource{Path: tc.path}); got != tc.want {
				t.Errorf("FormatOperand(Resource{Path: %q}) = %s, want %s", tc.path, got, tc.want)
			}
		})
	}
}
