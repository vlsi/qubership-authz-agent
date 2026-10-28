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
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// tenantWithSet returns the tree of a tenant whose export holds one set with
// one policy, both of the algorithm given, and one rule of the effect and
// condition given.
func tenantWithSet(t *testing.T, algorithm, effect, condition string) *policyir.Tree {
	t.Helper()
	sets := fmt.Sprintf(`{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %[1]q, "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": %[1]q,
			"tenantId": "t1", "rules": [{"ruleId": "r1", "target": "operation == 'read'",
				"condition": %[2]q, "effect": %[3]q, "tenantId": "t1"}]}]}]}`, algorithm, condition, effect)
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		t.Fatalf("FromRegular: no tree of t1; failed %v, dropped %v", exp.Failed, exp.Dropped)
	}
	return tree
}

func table(t *testing.T) *spectables.Table {
	t.Helper()
	tab, err := DefaultTable()
	if err != nil {
		t.Fatalf("DefaultTable: %v", err)
	}
	return tab
}

// resolved is a value the specification resolved for an operand: a state
// alone, or VALUE with the JSON text of the value.
func resolved(t *testing.T, state, value string) Resolved {
	t.Helper()
	r := Resolved{State: spectables.State(state)}
	if value != "" {
		v, err := jsonvalue.Decode([]byte(value))
		if err != nil {
			t.Fatalf("jsonvalue.Decode(%s): %v", value, err)
		}
		r.Value = v
	}
	return r
}

// decide generates the module of tree with opt, and evaluates the read of a
// doc whose operand key holds v.
func decide(t *testing.T, tree *policyir.Tree, opt Options, key string, v Resolved) bool {
	t.Helper()
	return decideValues(t, tree, opt, map[string]Resolved{key: v})
}

// decideValues is decide with the values of several operands, by key.
func decideValues(t *testing.T, tree *policyir.Tree, opt Options, values map[string]Resolved) bool {
	t.Helper()
	m, err := Generate(tree, table(t), opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + opt.Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, regobuiltins.Options()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
	}
	in, err := Project(m, Request{Operation: "read", ResourceType: "doc", Values: values})
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	rs, err := pq.Eval(context.Background(), rego.EvalParsedInput(in.Value()))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	return len(rs) == 1 && rs[0].Expressions[0].Value == true
}

const keyA = `["res",".a"]`

// The cells of EQ(res:path, lit:str) give a string value the comparison of
// keys under equalsIgnoreCase, and the state ABSENT the false rail.
func TestEqualityOfAnAttributeAndALiteral(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a == 'Ab'")
	for _, tc := range []struct {
		name         string
		state, value string
		want         bool
	}{
		{"the same text allows", "VALUE", `"Ab"`, true},
		{"another case allows", "VALUE", `"aB"`, true},
		{"another text denies", "VALUE", `"Ac"`, false},
		{"a missing attribute denies", "ABSENT", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, tc.state, tc.value)); got != tc.want {
				t.Errorf("allow(resource.a = %s %s) = %v, want %v", tc.state, tc.value, got, tc.want)
			}
		})
	}
}

// The export's domain of the whole resource holds only an object, and a
// request may send a string; the generator answers it with the cells of a
// resource attribute.
func TestAWholeResourceStringComparesByValue(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource == 'btn'")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"the named string allows", `"btn"`, true},
		{"another string denies", `"menu"`, false},
		{"an object denies", `{"id": "btn"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), `["res",""]`, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(resource = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// A null element on the left of CONTAINS ends the rule in legacy, and the
// agent reads the end as an undefined leaf. Under PERMIT_UNLESS_DENY a DENY
// rule permits only when its condition is false, so the null element denies
// where a list without the value permits.
func TestANullElementLeavesContainsUndefined(t *testing.T) {
	tree := tenantWithSet(t, "PERMIT_UNLESS_DENY", "DENY", "resource.a CONTAINS 'v'")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"a list without the value is false and permits", `["w"]`, true},
		{"a list with the value is true and denies", `["v"]`, false},
		{"a null element is undefined and denies", `[null, "w"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(resource.a = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// A value-dependent cell the templates do not cover is a generation error
// that names the operator and the kinds, never a false rail. Two attributes
// of class x (an object, or a list holding a null or a list) under == have no
// template; the same attribute against a literal is the control that
// generates.
func TestAValueDependentCellWithoutATemplateFailsGeneration(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a == resource.b")
	_, err := Generate(tree, table(t), DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "EQ(res:path x, res:path x)") {
		t.Errorf("Generate(resource.a == resource.b) error = %v, want one naming EQ(res:path x, res:path x)", err)
	}
	control := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a == 'x'")
	if _, err := Generate(control, table(t), DefaultOptions()); err != nil {
		t.Errorf("Generate(resource.a == 'x') error = %v, want none", err)
	}
}

// Two lists under == are equal as sets of their typed elements: order and
// repeats do not matter, case does.
func TestTwoListsAreEqualAsSets(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.roles == subject.scopes")
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"another order and a repeat allow", `["x", "y"]`, `["y", "x", "x"]`, true},
		{"another case denies", `["x"]`, `["X"]`, false},
		{"a number and its text deny", `[5]`, `["5"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","roles"]`: resolved(t, "VALUE", tc.a),
				`["subj","scopes"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(roles = %s, scopes = %s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// A null element that leaves CONTAINS undefined does not make an ALLOW rule
// permit either: with the value in a list without a null, the same rule
// permits.
func TestANullElementDoesNotMakeContainsTrue(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a CONTAINS 'v'")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"a list with the value is true and allows", `["v"]`, true},
		{"a null element beside the value is undefined and denies", `[null, "v"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(resource.a = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// NOT IN with literals is the negation of IN on a string value, under
// equalsIgnoreCase.
func TestNotInALiteralList(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a NOT IN 'x', 'y'")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"a value outside the list allows", `"z"`, true},
		{"a listed value denies", `"y"`, false},
		{"a listed value in another case denies", `"X"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(resource.a = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// In a MATCH pattern, * matches characters other than /, and the pattern
// matches the whole value. The literal segments become index guards, so a
// wrong segment count must deny as well.
func TestMatchAPathPattern(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.p MATCH /api/*/items")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"one segment in place of the star allows", `"/api/v1/items"`, true},
		{"two segments in place of the star deny", `"/api/v1/x/items"`, false},
		{"a trailing slash denies", `"/api/v1/items/"`, false},
		{"another last segment denies", `"/api/v1/item"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), `["res",".p"]`, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(resource.p = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// subject allowed 'write' on resource reads the decision for operation write
// from a copy of the tree where the operation is that constant.
func TestSubjectAllowedReadsTheDecisionForAnotherOperation(t *testing.T) {
	sets := `{"policySets": [
		{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [
				{"ruleId": "r1", "target": "operation == 'read'", "condition": "subject allowed 'write' on resource",
				 "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r2", "target": "operation == 'write'", "condition": "resource.a == 'w'",
				 "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	tree := exp.Trees["t1"]
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"a resource the subject may write may be read", `"w"`, true},
		{"a resource the subject may not write may not be read", `"z"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, "VALUE", tc.value)); got != tc.want {
				t.Errorf("allow(read, resource.a = %s) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// The flat module, the module with a rule per node, and the module with
// subject groups answer alike: the forms differ in how the index finds
// candidates, not in the decision. The roles leaf reads only the subject, so
// the third form moves it into a group.
func TestTheFormsOfTheModuleAnswerAlike(t *testing.T) {
	tree := tenantWithSet(t, "DENY_OVERRIDES", "ALLOW",
		"subject.roles CONTAINS 'admin' AND resource.a IN 'x', 'y' OR resource.a CONTAINS 'z'")
	noflat := DefaultOptions()
	noflat.Flat = false
	groups := DefaultOptions()
	groups.Groups = true
	if m, err := Generate(tree, table(t), groups); err != nil || len(m.Groups) == 0 {
		t.Fatalf("Generate with groups: %d groups, error %v; want at least one group", len(m.Groups), err)
	}
	forms := map[string]Options{"flat": DefaultOptions(), "without inlining": noflat, "with groups": groups}
	const roles = `["subj","roles"]`
	for _, tc := range []struct {
		name, roles, value string
		want               bool
	}{
		{"an admin reading a listed value is allowed", `["admin"]`, `"Y"`, true},
		{"a guest reading a listed value is denied", `["guest"]`, `"y"`, false},
		{"an admin reading an unlisted value is denied", `["admin"]`, `"w"`, false},
		{"anyone reading a list with z is allowed", `["guest"]`, `["z"]`, true},
		{"a null element beside z is denied", `["guest"]`, `[null, "z"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{roles: resolved(t, "VALUE", tc.roles), keyA: resolved(t, "VALUE", tc.value)}
			for form, opt := range forms {
				if got := decideValues(t, tree, opt, values); got != tc.want {
					t.Errorf("allow(roles = %s, resource.a = %s) %s = %v, want %v", tc.roles, tc.value, form, got,
						tc.want)
				}
			}
		})
	}
}
