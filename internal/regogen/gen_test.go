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
	return decideWith(t, tree, table(t), opt, values)
}

// decideWith is decideValues with the tables given.
func decideWith(t *testing.T, tree *policyir.Tree, tab *spectables.Table, opt Options, values map[string]Resolved) bool {
	t.Helper()
	m, err := Generate(tree, tab, opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return evalModule(t, m, Request{Operation: "read", ResourceType: "doc", Values: values})
}

// evalModule compiles the module and evaluates the request.
func evalModule(t *testing.T, m *Module, req Request) bool {
	t.Helper()
	opt := DefaultOptions()
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + opt.Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, regobuiltins.Options()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
	}
	in, err := Project(m, req)
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

// A request may send the whole resource as a string, and the resource then
// compares by value. An export whose domain of the whole resource held only
// an object answered every such leaf with a constant false.
func TestAWholeResourceStringComparesByValue(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource == 'btn'")
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"the named string allows", `"btn"`, true},
		{"another string denies", `"menu"`, false},
		{"an object denies", `{"id": "btn"}`, false},
		{"null in state VALUE denies", `null`, false},
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
// that names the operator and the kinds, never a false rail. < of two
// string attributes depends on the values through the rule rel, which has no
// template; the same attribute under == with a literal is the control that
// generates.
func TestAValueDependentCellWithoutATemplateFailsGeneration(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a < resource.b")
	_, err := Generate(tree, table(t), DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "LT(res:path ") {
		t.Errorf("Generate(resource.a < resource.b) error = %v, want one naming LT(res:path ...)", err)
	}
	control := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a == 'x'")
	if _, err := Generate(control, table(t), DefaultOptions()); err != nil {
		t.Errorf("Generate(resource.a == 'x') error = %v, want none", err)
	}
}

// A subject list of two or more values on the right of == or != answers
// with the profile's setting right_list_scalar_ops, false for the agent,
// before the lists are compared; a list of one compares as a set, and !=
// negates it.
func TestALongListOnTheRightOfEqualityAnswersTheSetting(t *testing.T) {
	for _, tc := range []struct {
		name, op, roles, scopes string
		want                    bool
	}{
		{"== with two scopes is false however the lists compare", "==", `["x", "y"]`, `["y", "x"]`, false},
		{"!= with two scopes is false too", "!=", `["x"]`, `["x", "y"]`, false},
		{"== with one scope compares the lists", "==", `["x"]`, `["x"]`, true},
		{"!= with one scope negates the comparison", "!=", `["x"]`, `["X"]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.roles "+tc.op+" subject.scopes")
			values := map[string]Resolved{`["subj","roles"]`: resolved(t, "VALUE", tc.roles),
				`["subj","scopes"]`: resolved(t, "VALUE", tc.scopes)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(roles %s scopes, roles = %s, scopes = %s) = %v, want %v", tc.op, tc.roles, tc.scopes,
					got, tc.want)
			}
		})
	}
}

// A list operand compared with a resource attribute list under == is equal
// as a set of its typed elements: order and repeats do not matter, case
// does.
func TestAListEqualsAnAttributeListAsASet(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.permissions == resource.a")
	for _, tc := range []struct {
		name, perm, a string
		want          bool
	}{
		{"another order and a repeat allow", `["x", "y"]`, `["y", "x", "x"]`, true},
		{"another case denies", `["x"]`, `["X"]`, false},
		{"a number and its text deny", `["5"]`, `[5]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","permissions"]`: resolved(t, "VALUE", tc.perm),
				keyA: resolved(t, "VALUE", tc.a)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(permissions = %s, resource.a = %s) = %v, want %v", tc.perm, tc.a, got, tc.want)
			}
		})
	}
}

// IN of two objects compares them member by member: the same keys and, for
// each, a value of the same JSON type that is equal.
func TestAnObjectIsInAnEqualObject(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a IN resource.b")
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"the same members allow", `{"k": "v", "n": 1}`, `{"n": 1, "k": "v"}`, true},
		{"another value denies", `{"k": "v"}`, `{"k": "w"}`, false},
		{"a number and its text deny", `{"n": 1}`, `{"n": "1"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a = %s, resource.b = %s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// editedTable loads the embedded export with one node rule replaced; the
// test fails when the export no longer holds the rule as written.
func editedTable(t *testing.T, from, to string) *spectables.Table {
	t.Helper()
	if !bytes.Contains(agentTables, []byte(from)) {
		t.Fatalf("the embedded export has no node rule %s", from)
	}
	tab, err := spectables.Load(bytes.NewReader(bytes.ReplaceAll(agentTables, []byte(from), []byte(to))))
	if err != nil {
		t.Fatalf("Load(edited export): %v", err)
	}
	return tab
}

// An absent condition takes the export's absent expression, while a
// simplified policy without a condition grants by its operation and roles
// whatever that expression is.
func TestAnAbsentConditionTakesTheExportsAbsentExpression(t *testing.T) {
	sets := `{"policySets": [
		{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r1", "target": "operation == 'read'", "effect": "ALLOW",
				"tenantId": "t1"}]}]},
		{"policySetId": "s2", "name": "s2", "status": "ACTIVE", "type": "SIMPLIFIED",
		 "target": "resourceType == 'note'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p2", "target": "operation == 'read'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r2", "target": "subject.roles CONTAINS ANY 'reader'",
				"effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	tree := exp.Trees["t1"]
	if len(tree.Simplified) != 1 {
		t.Fatalf("FromRegular read %d simplified groups, want 1", len(tree.Simplified))
	}
	falseTable := editedTable(t, `"absent_expression": "T"`, `"absent_expression": "F"`)
	for _, tc := range []struct {
		name  string
		tab   *spectables.Table
		rtype string
		want  bool
	}{
		{"a rule without a condition applies when absent is true", table(t), "doc", true},
		{"a rule without a condition does not apply when absent is false", falseTable, "doc", false},
		{"a simplified policy without a condition grants when absent is false", falseTable, "note", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Generate(tree, tc.tab, DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got := evalModule(t, m, Request{Operation: "read", ResourceType: tc.rtype, Roles: []string{"reader"}})
			if got != tc.want {
				t.Errorf("allow(read %s) = %v, want %v", tc.rtype, got, tc.want)
			}
		})
	}
}

// A rule whose effect is neither ALLOW nor DENY counts as the export's
// effects say: USE_FILTER_CONDITION denies by the export, and permits once
// the export says so.
func TestAnOtherEffectCountsAsTheExportSays(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "USE_FILTER_CONDITION", "resource.a == 'x'")
	permits := editedTable(t, `"USE_FILTER_CONDITION": "deny"`, `"USE_FILTER_CONDITION": "permit"`)
	for _, tc := range []struct {
		name string
		tab  *spectables.Table
		want bool
	}{
		{"deny by the export's effects", table(t), false},
		{"permit once the export says so", permits, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWith(t, tree, tc.tab, DefaultOptions(), map[string]Resolved{keyA: resolved(t, "VALUE", `"x"`)}); got != tc.want {
				t.Errorf("allow(resource.a = \"x\") = %v, want %v", got, tc.want)
			}
		})
	}
}

// The generator combines children by the node rules of the export, not by
// constants of its own. Under PERMIT_UNLESS_DENY a node whose only rule does
// not apply permits by the export's rules; with "none" changed to "na" in the
// export, the same tree denies.
func TestTheNodeRulesComeFromTheExport(t *testing.T) {
	edited := editedTable(t,
		`"PERMIT_UNLESS_DENY": {"permit": "permit", "deny": "deny", "both": "deny", "none": "permit"}`,
		`"PERMIT_UNLESS_DENY": {"permit": "permit", "deny": "deny", "both": "deny", "none": "na"}`)
	tree := tenantWithSet(t, "PERMIT_UNLESS_DENY", "DENY", "resource.a == 'x'")
	for _, tc := range []struct {
		name string
		tab  *spectables.Table
		want bool
	}{
		{"none permits under the export's rules", table(t), true},
		{"none denies once the export says na", edited, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWith(t, tree, tc.tab, DefaultOptions(), map[string]Resolved{keyA: resolved(t, "VALUE", `"y"`)}); got != tc.want {
				t.Errorf("allow(resource.a = \"y\") = %v, want %v", got, tc.want)
			}
		})
	}
}

// A list or an object compares with a string by the text the profile prints
// for it, in either order and under equalsIgnoreCase; a number inside prints
// without trailing zeros.
func TestAStructureComparesWithAStringByItsText(t *testing.T) {
	keyB := `["res",".b"]`
	for _, tc := range []struct {
		name, condition, a, b string
		want                  bool
	}{
		{"a list equals its text in another case", "resource.a == '[X, y]'", `["x", "y"]`, "", true},
		{"a number element prints without its trailing zero", "resource.a == '[1]'", `[1.0]`, "", true},
		{"a list does not equal another text", "resource.a == '[y]'", `["x"]`, "", false},
		{"a string equals the text of a list on the right", "resource.b == resource.a", `["x"]`, `"[x]"`, true},
		{"an object contains its text", "resource.a CONTAINS '{k=v}'", `{"k": "v"}`, "", true},
		{"a list is in literals that hold its text", "resource.a IN '[x]', 'z'", `["x"]`, "", true},
		{"a list is not in literals that hold its elements", "resource.a IN 'x', 'z'", `["x"]`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", tc.condition)
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a)}
			if tc.b != "" {
				values[keyB] = resolved(t, "VALUE", tc.b)
			}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(%s, resource.a = %s, resource.b = %s) = %v, want %v", tc.condition, tc.a, tc.b, got,
					tc.want)
			}
		})
	}
}

// A string compared under == with a right operand in state NULL equals it
// only as the text [], since the profile reads that operand as an empty list.
func TestAStringEqualsANullOperandOnlyAsAnEmptyList(t *testing.T) {
	for _, tc := range []struct {
		name, op, b string
		want        bool
	}{
		{"[] equals it", "==", `"[]"`, true},
		{"another string does not", "==", `"x"`, false},
		{"another string differs from it", "!=", `"x"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.b "+tc.op+" resource.a")
			values := map[string]Resolved{keyA: resolved(t, "NULL", ""), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.b %s resource.a, resource.b = %s, resource.a in NULL) = %v, want %v", tc.op,
					tc.b, got, tc.want)
			}
		})
	}
}

// Two lists, nested ones included, are equal as sets of their elements; a
// list inside keeps its order. Two objects are equal by their members, a
// number by its value, a string with its case.
func TestStructuresEqualByTheirElements(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"nested lists in another order are equal", `[["a"], "b"]`, `["b", ["a"]]`, true},
		{"a list inside keeps its order", `[["a", "c"]]`, `[["c", "a"]]`, false},
		{"lists with a null in another order are equal", `[null, "x"]`, `["x", null]`, true},
		{"a list with a null differs from one without", `[null, "x"]`, `["x"]`, false},
		{"objects with equal numbers are equal", `{"n": 1}`, `{"n": 1.0}`, true},
		{"objects with strings in another case differ", `{"k": "V"}`, `{"k": "v"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a == resource.b")
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a = %s, resource.b = %s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// A literal list of two or more quoted strings splits at every comma, so an
// item with a comma inside is two values; a list of one is not split.
func TestALiteralListSplitsAtCommas(t *testing.T) {
	for _, tc := range []struct {
		name, condition, a string
		want               bool
	}{
		{"a string with a comma is not in a split list", "resource.a IN 'a,b', 'x'", `"a,b"`, false},
		{"a part of the split item is in it", "resource.a IN 'a,b', 'x'", `"a"`, true},
		{"a list text with a comma is not in a split list", "resource.a IN '[null, abc]', 'x'", `[null, "abc"]`, false},
		{"a list text without a comma is in it", "resource.a IN '[null]', 'x'", `[null]`, true},
		{"a list of one item is not split", "resource.a IN 'a,b'", `"a,b"`, true},
		{"each part is trimmed", "resource.a IN ' a', 'x'", `"a"`, true},
		{"an empty part is kept", "resource.a IN 'a', ''", `""`, true},
		{"a list of numbers is not read as text", "resource.a IN 1, 2", `2`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", tc.condition)
			if got := decide(t, tree, DefaultOptions(), keyA, resolved(t, "VALUE", tc.a)); got != tc.want {
				t.Errorf("allow(%s, resource.a = %s) = %v, want %v", tc.condition, tc.a, got, tc.want)
			}
		})
	}
}

// CONTAINS ANY with a null element on both sides compares the values, and a
// null equals nothing; with a null on the left only, it ends the rule, which
// the agent reads as undefined.
func TestContainsAnyWithNullsOnBothSidesCompares(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a CONTAINS ANY resource.b")
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"a common value allows", `[null, "x"]`, `[null, "x"]`, true},
		{"no common value but the nulls denies", `[null, "y"]`, `[null, "x"]`, false},
		{"a null on the left only is undefined and denies", `[null, "x"]`, `["x"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a = %s, resource.b = %s) = %v, want %v", tc.a, tc.b, got, tc.want)
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
