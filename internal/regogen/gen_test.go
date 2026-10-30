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

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

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
	return tenantWithSetAndPIPs(t, algorithm, effect, condition, "")
}

// tenantWithSetAndPIPs is tenantWithSet with the PIP declarations given, a
// comma-separated list of JSON objects without their tenantId.
func tenantWithSetAndPIPs(t *testing.T, algorithm, effect, condition, pips string) *policyir.Tree {
	t.Helper()
	sets := fmt.Sprintf(`{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE",
		"target": "resourceType == 'doc'", "combiningAlgorithm": %[1]q, "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": %[1]q,
			"tenantId": "t1", "rules": [{"ruleId": "r1", "target": "operation == 'read'",
				"condition": %[2]q, "effect": %[3]q, "tenantId": "t1"}]}]}]}`, algorithm, condition, effect)
	pips = strings.ReplaceAll(pips, "{", `{"tenantId": "t1", `)
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": [`+pips+`]}`))
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
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// nc.pip answers a network PIP from the projection, as the agent's
	// built-in would after its call
	pip := rego.Function1(&rego.Function{Name: "nc.pip", Decl: types.NewFunction(types.Args(types.S), types.A)},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			r, ok := in.PIPRecord(string(a.Value.(ast.String)))
			if !ok {
				return nil, fmt.Errorf("nc.pip: no record of %v", a)
			}
			return r, nil
		})
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + opt.Package + ".allow"),
		rego.Module("gen.rego", m.Text), pip}, regobuiltins.Options()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
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

// How a literal list is read comes from the export's knobs: with
// string_list_split ELEMENTS a list of two or more items keeps them as
// written, so an item with a comma inside is one value.
func TestTheExportDecidesHowALiteralListIsRead(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a IN 'a,b', 'x'")
	elements := editedTable(t, `"string_list_split": "SPLIT_TRIM"`, `"string_list_split": "ELEMENTS"`)
	for _, tc := range []struct {
		name string
		tab  *spectables.Table
		want bool
	}{
		{"a split list does not hold the item with a comma", table(t), false},
		{"a list of items as written holds it", elements, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWith(t, tree, tc.tab, DefaultOptions(), map[string]Resolved{keyA: resolved(t, "VALUE", `"a,b"`)}); got != tc.want {
				t.Errorf("allow(resource.a = \"a,b\") = %v, want %v", got, tc.want)
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

// Under == a number, a boolean, or an object equals no list, whatever it
// holds: only a string compares with a list's text. A subject list of two or
// more values answers != with the setting right_list_scalar_ops, false for
// the agent, before that.
func TestANumberOrAnObjectEqualsNoList(t *testing.T) {
	const nested, id = `["res",".a.b"]`, `["subj","id"]`
	for _, tc := range []struct {
		name, op, a, id string
		want            bool
	}{
		{"a number is not a list that holds its text", "!=", `5`, `["5"]`, true},
		{"a number equals no list", "==", `5`, `["5"]`, false},
		{"an object is not a list that holds its text", "!=", `{"k": "v"}`, `["{k=v}"]`, true},
		{"a list of two values answers the setting", "!=", `5`, `["5", "6"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a.b "+tc.op+" subject.id")
			values := map[string]Resolved{nested: resolved(t, "VALUE", tc.a), id: resolved(t, "VALUE", tc.id)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a.b %s subject.id, resource.a.b = %s, subject.id = %s) = %v, want %v", tc.op,
					tc.a, tc.id, got, tc.want)
			}
		})
	}
}

// A subject list on the right of CONTAINS or NOT CONTAINS compares element
// by element when it holds one value; with two or more it answers the
// setting right_list_scalar_ops, false for the agent, under either operator.
func TestAStringContainsASubjectListOfOneValue(t *testing.T) {
	for _, tc := range []struct {
		name, op, id string
		want         bool
	}{
		{"one equal value allows", "CONTAINS", `["x"]`, true},
		{"one other value denies", "CONTAINS", `["y"]`, false},
		{"one other value is not contained", "NOT CONTAINS", `["y"]`, true},
		{"two values with an equal one answer the setting", "CONTAINS", `["x", "y"]`, false},
		{"two other values answer the setting under the negation", "NOT CONTAINS", `["y", "z"]`, false},
		{"a list of null holds nothing, so it is not contained", "NOT CONTAINS", `[null]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a "+tc.op+" subject.id")
			values := map[string]Resolved{keyA: resolved(t, "VALUE", `"x"`), `["subj","id"]`: resolved(t, "VALUE", tc.id)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a %s subject.id, subject.id = %s) = %v, want %v", tc.op, tc.id, got, tc.want)
			}
		})
	}
}

// An object on the right of CONTAINS or CONTAINS ANY is one candidate: a
// string on the left equals it by its text, an object by its members, with
// their case, and a list element of another kind not at all.
func TestAnObjectOnTheRightIsOneCandidate(t *testing.T) {
	const object = `{"k": "v"}`
	for _, tc := range []struct {
		name, op, a string
		want        bool
	}{
		{"a string equals the object's text in another case", "CONTAINS", `"{K=v}"`, true},
		{"a string with another text denies", "CONTAINS", `"{k=w}"`, false},
		{"a list of strings holds the text", "CONTAINS", `["z", "{k=v}"]`, true},
		{"an object element with the same members allows", "CONTAINS", `[{"k": "v"}, ["q"]]`, true},
		{"an object element in another case denies", "CONTAINS", `[{"k": "V"}, ["q"]]`, false},
		{"a string element beside a list holds the text", "CONTAINS", `["{k=v}", ["q"]]`, true},
		{"a list element with the text inside denies", "CONTAINS", `[["{k=v}"]]`, false},
		{"an object with the same members has one in common", "CONTAINS ANY", object, true},
		{"an object in another case has none", "CONTAINS ANY", `{"k": "V"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a "+tc.op+" resource.b")
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", object)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a %s resource.b, resource.a = %s, resource.b = %s) = %v, want %v", tc.op,
					tc.a, object, got, tc.want)
			}
		})
	}
}

// generalPIPs declares subject.g and subject.h as GENERAL PIPs.
const generalPIPs = `{"name": "subject.g", "pipType": "GENERAL", "url": "http://g"},
	{"name": "subject.h", "pipType": "GENERAL", "url": "http://h"}`

// A one-element GENERAL list of null (SINGLE_ODD) fails the PIP on the left
// of CONTAINS ANY, and the agent reads that as undefined; one of a boolean
// is a list without a null. On the right the list of null is a value, so a
// null element on the left ends the rule only against the list of a boolean.
// Under PERMIT_UNLESS_DENY a DENY rule permits only when its condition is
// false, which tells false from undefined.
func TestASingleOddListUnderContainsAny(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "PERMIT_UNLESS_DENY", "DENY", "subject.g CONTAINS ANY subject.h", generalPIPs)
	for _, tc := range []struct {
		name                 string
		gState, g, hState, h string
		want                 bool
	}{
		{"a boolean against an empty PIP is false", "SINGLE_ODD", `[true]`, "PIP_EMPTY", "", true},
		{"a null against an empty PIP is undefined", "SINGLE_ODD", `[null]`, "PIP_EMPTY", "", false},
		{"a boolean against a list with a null is false", "SINGLE_ODD", `[true]`, "VALUE", `[null, "x"]`, true},
		{"a null on the left is undefined against a list with a null", "SINGLE_ODD", `[null]`, "VALUE",
			`[null, "x"]`, false},
		{"a null element against a boolean ends the rule", "VALUE", `[null, "x"]`, "SINGLE_ODD", `[true]`, false},
		{"a null element against a null compares the values", "VALUE", `[null, "x"]`, "SINGLE_ODD", `[null]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","g"]`: resolved(t, tc.gState, tc.g),
				`["subj","h"]`: resolved(t, tc.hState, tc.h)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(subject.g = %s %s, subject.h = %s %s) = %v, want %v", tc.gState, tc.g, tc.hState,
					tc.h, got, tc.want)
			}
		})
	}
}

// A null whole resource is in no list, and a one-element GENERAL list of null
// on the right of IN ends the rule, which the agent reads as undefined.
func TestANullResourceIsInNoSingleOddList(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "PERMIT_UNLESS_DENY", "DENY", "resource IN subject.g", generalPIPs)
	for _, tc := range []struct {
		name, g string
		want    bool
	}{
		{"a list of a boolean is false and permits", `[true]`, true},
		{"a list of null is undefined and denies", `[null]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["res",""]`: resolved(t, "VALUE", "null"),
				`["subj","g"]`: resolved(t, "SINGLE_ODD", tc.g)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource = null, subject.g = SINGLE_ODD %s) = %v, want %v", tc.g, got, tc.want)
			}
		})
	}
}

// A string on the left of CONTAINS equals a list or an object element of a
// subject list by the element's text, under equalsIgnoreCase.
func TestAStringEqualsAStructureElementByItsText(t *testing.T) {
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a CONTAINS subject.id")
	for _, tc := range []struct {
		name, a, id string
		want        bool
	}{
		{"the text of an object element in another case allows", `"{K=v}"`, `[{"k": "v"}]`, true},
		{"the text of a list element allows", `"[x]"`, `[["x"]]`, true},
		{"an element of a list element denies", `"x"`, `[["x"]]`, false},
		{"the text of a nested member allows", `"{k=[\"a\"]}"`, `[{"k": ["a"]}]`, true},
		{"the Java text of a nested member denies", `"{k=[a]}"`, `[{"k": ["a"]}]`, false},
		{"two values with an equal one answer the setting", `"x"`, `[["q"], "x"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["subj","id"]`: resolved(t, "VALUE", tc.id)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a = %s, subject.id = %s) = %v, want %v", tc.a, tc.id, got, tc.want)
			}
		})
	}
}

// A one-element GENERAL list of an object (SINGLE_ODD) has an element in
// common with an equal object on the right of CONTAINS ANY: the members
// decide, with their case.
func TestASingleOddObjectContainsAnEqualObject(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g CONTAINS ANY resource.b", generalPIPs)
	for _, tc := range []struct {
		name, g string
		want    bool
	}{
		{"the same members allow", `[{"k": "v"}]`, true},
		{"a member in another case denies", `[{"k": "V"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","g"]`: resolved(t, "SINGLE_ODD", tc.g),
				`["res",".b"]`: resolved(t, "VALUE", `{"k": "v"}`)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(subject.g = SINGLE_ODD %s, resource.b = {\"k\": \"v\"}) = %v, want %v", tc.g, got,
					tc.want)
			}
		})
	}
}

// A one-element GENERAL list (SINGLE_ODD) contains no element of an empty
// resource list, which CONTAINS reads as one value; a list of null fails the
// PIP, and the agent reads that as undefined.
func TestASingleOddListContainsNoEmptyAttributeList(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "PERMIT_UNLESS_DENY", "DENY", "subject.g CONTAINS resource.b", generalPIPs)
	for _, tc := range []struct {
		name, g string
		want    bool
	}{
		{"a list of a boolean is false and permits", `[true]`, true},
		{"a list of null is undefined and denies", `[null]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","g"]`: resolved(t, "SINGLE_ODD", tc.g),
				`["res",".b"]`: resolved(t, "EMPTY_COLL", "[]")}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(subject.g = SINGLE_ODD %s, resource.b = EMPTY_COLL) = %v, want %v", tc.g, got, tc.want)
			}
		})
	}
}

// Two lists have an element in common under CONTAINS ANY, or a list on the
// left contains a subject list of one value, when two elements are equal: an
// object by its members, with their case, and a list by its elements in
// order, each as equalsIgnoreCase compares texts.
func TestStructureElementsAreEqualByValue(t *testing.T) {
	for _, tc := range []struct {
		name, condition, a, b string
		want                  bool
	}{
		{"an object element with the same members", "resource.a CONTAINS subject.id", `[{"k": "v"}]`,
			`[{"k": "v"}]`, true},
		{"an object element in another case", "resource.a CONTAINS subject.id", `[{"k": "V"}]`, `[{"k": "v"}]`,
			false},
		{"a list element in another case", "resource.a CONTAINS ANY subject.id", `[["A"]]`, `[["a"]]`, true},
		{"a list element in another order", "resource.a CONTAINS ANY subject.id", `[["a", "b"]]`, `[["b", "a"]]`,
			false},
		{"a list element with a null equals nothing", "resource.a CONTAINS ANY subject.id", `[[null]]`, `[[null]]`,
			false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", tc.condition)
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["subj","id"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(%s, resource.a = %s, subject.id = %s) = %v, want %v", tc.condition, tc.a, tc.b, got,
					tc.want)
			}
		})
	}
}

// An object on the left of CONTAINS contains a string by its text or an
// equal object, never a list, even one that holds its text.
func TestAnObjectContainsNoList(t *testing.T) {
	for _, tc := range []struct {
		op   string
		want bool
	}{{"CONTAINS", false}, {"NOT CONTAINS", true}} {
		t.Run(tc.op, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a "+tc.op+" subject.id")
			values := map[string]Resolved{keyA: resolved(t, "VALUE", `{"k": "v"}`),
				`["subj","id"]`: resolved(t, "VALUE", `["{k=v}"]`)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource.a = {\"k\": \"v\"} %s subject.id = [\"{k=v}\"]) = %v, want %v", tc.op, got,
					tc.want)
			}
		})
	}
}

// A resource list attribute on the right of CONTAINS is one value, so no
// element on the left equals it, an equal list element included, whatever
// the list holds.
func TestAResourceListOnTheRightIsOneValue(t *testing.T) {
	tree := tenantWithSet(t, "PERMIT_UNLESS_DENY", "DENY", "resource.a CONTAINS resource.b")
	for _, tc := range []struct{ name, a, b string }{
		{"an equal list element", `[["x"]]`, `[["x"]]`},
		{"an element of a list with a null", `["x"]`, `[null, "x"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			if got := decideValues(t, tree, DefaultOptions(), values); !got {
				t.Errorf("allow(resource.a = %s CONTAINS resource.b = %s) = false, want true: the condition is false",
					tc.a, tc.b)
			}
		})
	}
}

// A null whole resource is in no list without a null, and NOT IN holds.
func TestANullResourceIsInNoList(t *testing.T) {
	for _, tc := range []struct {
		op   string
		want bool
	}{{"IN", false}, {"NOT IN", true}} {
		t.Run(tc.op, func(t *testing.T) {
			tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource "+tc.op+" subject.id")
			values := map[string]Resolved{`["res",""]`: resolved(t, "VALUE", "null"),
				`["subj","id"]`: resolved(t, "VALUE", `["x"]`)}
			if got := decideValues(t, tree, DefaultOptions(), values); got != tc.want {
				t.Errorf("allow(resource = null %s subject.id = [\"x\"]) = %v, want %v", tc.op, got, tc.want)
			}
		})
	}
}
