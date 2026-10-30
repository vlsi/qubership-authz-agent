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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
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

// evalModule compiles the module and evaluates allow for the request.
func evalModule(t *testing.T, m *Module, req Request) bool {
	t.Helper()
	return evalRule(t, m, req, "allow") == true
}

// evalRule compiles the module and evaluates rule for the request, decision
// and maybe from the module of Options.Decision; nil when the rule is
// undefined.
func evalRule(t *testing.T, m *Module, req Request, rule string) any {
	t.Helper()
	pkg, text := DefaultOptions().Package, m.Text
	if rule == "decision" || rule == "maybe" {
		pkg, text = pkg+"_decision", m.DecisionText
	}
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
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + pkg + "." + rule),
		rego.Module("gen.rego", text), pip}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, text)
	}
	rs, err := pq.Eval(in.Context(context.Background()), rego.EvalParsedInput(in.Value()))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(rs) != 1 {
		return nil
	}
	return rs[0].Expressions[0].Value
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

// A value-dependent cell whose value rule no template implements is a
// generation error that names the operator and the kinds, never a false rail.
// The export is edited so that < of two string attributes names array_eq,
// which no template implements; the same leaf generates from the export as
// it is.
func TestAValueDependentCellWithoutATemplateFailsGeneration(t *testing.T) {
	const cell = `{"op":"LT","left":{"kind":"res:path","state":"VALUE","class":"s"},` +
		`"right":{"kind":"res:path","state":"VALUE","class":"s"},"outcome":"by_value","outcomes":["T","F"],"value_rule":[`
	tab := editedTable(t, cell+`"rel"]}`, cell+`"array_eq"]}`)
	tree := tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a < resource.b")
	_, err := Generate(tree, tab, DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "LT(res:path ") {
		t.Errorf("Generate(resource.a < resource.b) with rule array_eq: error = %v, want one naming LT(res:path ...)",
			err)
	}
	if _, err := Generate(tree, table(t), DefaultOptions()); err != nil {
		t.Errorf("Generate(resource.a < resource.b) error = %v, want none", err)
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

// editedTable loads the embedded export with every occurrence of from
// replaced by to; the test fails when the export no longer holds from.
func editedTable(t *testing.T, from, to string) *spectables.Table {
	t.Helper()
	if !bytes.Contains(agentTables, []byte(from)) {
		t.Fatalf("the embedded export has no text %s", from)
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

// leafOutcome evaluates condition as the only leaf of two modules, one where
// an ALLOW rule permits on its true rail and one where a DENY rule permits on
// its false rail, and returns T, F, or U for neither.
func leafOutcome(t *testing.T, condition string, opt Options, values map[string]Resolved) string {
	t.Helper()
	return leafOutcomeWithPIPs(t, condition, "", opt, values)
}

// leafOutcomeWithPIPs is leafOutcome with the PIP declarations given, as
// tenantWithSetAndPIPs takes them.
func leafOutcomeWithPIPs(t *testing.T, condition, pips string, opt Options, values map[string]Resolved) string {
	t.Helper()
	isTrue := decideValues(t, tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", condition, pips), opt, values)
	isFalse := decideValues(t, tenantWithSetAndPIPs(t, "PERMIT_UNLESS_DENY", "DENY", condition, pips), opt, values)
	switch {
	case isTrue && isFalse:
		t.Fatalf("%s is on both rails", condition)
	case isTrue:
		return "T"
	case isFalse:
		return "F"
	}
	return "U"
}

// <, <=, >, and >= compare the numbers the values read as: a string that
// BigDecimal reads, and a number of the input rounded to a double, which
// leaves 4.99999999999999999999 equal to 5. A value that reads as no number,
// a boolean, and a number of the input beyond the range of a double compare
// false; the string "1e400" is a number. A literal compares by its exact
// value, and one that reads as no number, or a fraction beyond the range of a
// double, compares false. The false rail holds each of them, which a negated
// comparison would leave undefined where the number is missing.
func TestARelationalComparisonComparesTheNumbersOfTheValues(t *testing.T) {
	big := "1" + strings.Repeat("0", 400)
	for _, tc := range []struct {
		name, condition, a, want string
	}{
		{"a smaller number", "resource.a < 5", `3`, "T"},
		{"a string that reads as a smaller number", "resource.a < 5", `"3"`, "T"},
		{"the bound itself", "resource.a < 5", `5`, "F"},
		{"the bound itself under <=", "resource.a <= 5", `5`, "T"},
		{"the bound itself under >=", "resource.a >= 5", `5`, "T"},
		{"the bound itself under >", "resource.a > 5", `5`, "F"},
		{"a fraction the double rounds to the bound", "resource.a < 5", `4.99999999999999999999`, "F"},
		{"a string that reads as no number", "resource.a < 5", `"abc"`, "F"},
		{"a boolean", "resource.a < 5", `true`, "F"},
		{"a number beyond the double range", "resource.a > 5", `1e400`, "F"},
		{"a string beyond the double range", "resource.a > 5", `"1e400"`, "T"},
		{"a string below a literal by its exact value", "resource.a < 0.30000000000000001", `"0.3"`, "T"},
		{"a string above a literal by its exact value", "resource.a < 0.30000000000000001", `"0.30000000000000002"`,
			"F"},
		{"a string literal that reads as no number", "resource.a < 'abc'", `"a"`, "F"},
		{"a boolean literal", "resource.a < true", `0`, "F"},
		{"a literal fraction beyond the double range", "resource.a < " + big + ".5", `5`, "F"},
		{"a literal integer beyond the double range", "resource.a < " + big, `5`, "T"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a)}
			if got := leafOutcome(t, tc.condition, DefaultOptions(), values); got != tc.want {
				t.Errorf("%s with resource.a = %s is %s, want %s", tc.condition, tc.a, got, tc.want)
			}
		})
	}
}

// Two attributes compare as numbers at any exponent, a negative one by its
// magnitude reversed, zero between the signs and equal to minus zero, and two
// strings that read as no number compare false.
func TestTwoAttributesCompareAsNumbers(t *testing.T) {
	for _, tc := range []struct {
		name, op, a, b, want string
	}{
		{"two strings that read as numbers, not as text", "<", `"10"`, `"9"`, "F"},
		{"two negative numbers", "<", `-1.55`, `-1.5`, "T"},
		{"two positive numbers that share leading digits", "<", `1.5`, `1.55`, "T"},
		{"zero and a positive number", "<", `0`, `1`, "T"},
		{"a negative number and zero", "<", `-1`, `0`, "T"},
		{"a negative and a positive number", "<", `-1`, `1`, "T"},
		{"zero and minus zero", "<", `0`, `-0`, "F"},
		{"zero and minus zero under <=", "<=", `0`, `-0`, "T"},
		{"two exponents beyond the double range", "<", `"1e400"`, `"1e401"`, "T"},
		{"two negative exponents beyond the double range", "<", `"-1e401"`, `"-1e400"`, "T"},
		{"two strings that read as no number", "<", `"x"`, `"y"`, "F"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), `["res",".b"]`: resolved(t, "VALUE", tc.b)}
			cond := "resource.a " + tc.op + " resource.b"
			if got := leafOutcome(t, cond, DefaultOptions(), values); got != tc.want {
				t.Errorf("%s with resource.a = %s, resource.b = %s is %s, want %s", cond, tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// A comparison of subject attributes joins a subject group, which Go
// evaluates by the same numbers: with a literal on either side, and between
// two attributes.
func TestASubjectGroupComparesTheNumbers(t *testing.T) {
	opt := DefaultOptions()
	opt.Groups = true
	for _, tc := range []struct {
		name, condition, id, subjName, want string
	}{
		{"a smaller number", "subject.id < 5", `3`, `""`, "T"},
		{"a larger number", "subject.id < 5", `7`, `""`, "F"},
		{"a string that reads as no number", "subject.id < 5", `"abc"`, `""`, "F"},
		{"a literal on the left above the value", "5 > subject.id", `3`, `""`, "T"},
		{"a literal on the left below the value", "5 > subject.id", `7`, `""`, "F"},
		{"two attributes in order", "subject.id < subject.name", `1`, `2`, "T"},
		{"two attributes out of order", "subject.id < subject.name", `2`, `1`, "F"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","id"]`: resolved(t, "VALUE", tc.id),
				`["subj","name"]`: resolved(t, "VALUE", tc.subjName)}
			if got := leafOutcome(t, tc.condition, opt, values); got != tc.want {
				t.Errorf("%s with subject.id = %s, subject.name = %s is %s, want %s", tc.condition, tc.id, tc.subjName,
					got, tc.want)
			}
		})
	}
}

// IS SUBSET holds when the left value, read as a list, is not empty and each
// of its elements equals an element on the right: with case, a number equal to
// its text, a list equal to a string by its Java text, and null equal to
// nothing. An object on the right equals nothing. A resource attribute or a
// PIP on the right is one value, so an element there that is not a string
// equals nothing.
func TestIsSubsetComparesElementsWithCase(t *testing.T) {
	const perms, b, id, g = `["subj","permissions"]`, `["res",".b"]`, `["subj","id"]`, `["subj","g"]`
	for _, tc := range []struct {
		name, condition, a, rightKey, right, want string
	}{
		{"every element on the right", "resource.a IS SUBSET subject.permissions", `["x"]`, perms, `["x", "y"]`, "T"},
		{"an element in another case", "resource.a IS SUBSET subject.permissions", `["X"]`, perms, `["x"]`, "F"},
		{"a number and its text", "resource.a IS SUBSET subject.permissions", `[5]`, perms, `["5"]`, "T"},
		{"a list and its text", "resource.a IS SUBSET subject.permissions", `[["abc"]]`, perms, `["[abc]"]`, "T"},
		{"a string read as a list of one", "resource.a IS SUBSET subject.permissions", `"x"`, perms, `["x"]`, "T"},
		{"a null element", "resource.a IS SUBSET subject.permissions", `["x", null]`, perms, `["x"]`, "F"},
		{"a number in a resource attribute on the right", "resource.a IS SUBSET resource.b", `[5]`, b, `[5]`, "F"},
		{"a string in a resource attribute on the right", "resource.a IS SUBSET resource.b", `[5]`, b, `["5"]`, "T"},
		{"an object on the right", "resource.a IS SUBSET subject.id", `[{}]`, id, `[{}]`, "F"},
		{"a string where the object was", "resource.a IS SUBSET subject.id", `["x"]`, id, `["x"]`, "T"},
		{"a number in a PIP on the right", "resource.a IS SUBSET subject.g", `[5]`, g, `[5]`, "F"},
		{"a string in a PIP on the right", "resource.a IS SUBSET subject.g", `[5]`, g, `["5"]`, "T"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a), tc.rightKey: resolved(t, "VALUE", tc.right)}
			if got := leafOutcomeWithPIPs(t, tc.condition, generalPIPs, DefaultOptions(), values); got != tc.want {
				t.Errorf("%s with %s and %s is %s, want %s", tc.condition, tc.a, tc.right, got, tc.want)
			}
		})
	}
}

// A string on the left of IS SUBSET never equals a boolean on the right,
// while a boolean on the left does.
func TestAStringIsNoSubsetOfABoolean(t *testing.T) {
	for _, tc := range []struct{ a, want string }{{`"true"`, "F"}, {`true`, "T"}} {
		t.Run(tc.a, func(t *testing.T) {
			values := map[string]Resolved{keyA: resolved(t, "VALUE", tc.a)}
			if got := leafOutcome(t, "resource.a IS SUBSET true", DefaultOptions(), values); got != tc.want {
				t.Errorf("resource.a = %s IS SUBSET true is %s, want %s", tc.a, got, tc.want)
			}
		})
	}
}

// An empty whole resource is a subset of nothing, so IS NOT SUBSET holds for
// it as for a list with an element outside the right.
func TestAnEmptyResourceIsNotASubset(t *testing.T) {
	for _, tc := range []struct{ resource, want string }{{`[]`, "T"}, {`["y"]`, "T"}, {`["x"]`, "F"}} {
		t.Run(tc.resource, func(t *testing.T) {
			values := map[string]Resolved{`["res",""]`: resolved(t, "VALUE", tc.resource)}
			if got := leafOutcome(t, "resource IS NOT SUBSET 'x'", DefaultOptions(), values); got != tc.want {
				t.Errorf("resource = %s IS NOT SUBSET 'x' is %s, want %s", tc.resource, got, tc.want)
			}
		})
	}
}

// IS SUBSET of subject lists joins a subject group, which Go evaluates by the
// same tokens: against literals and between two attributes.
func TestASubjectGroupComparesSubsets(t *testing.T) {
	opt := DefaultOptions()
	opt.Groups = true
	for _, tc := range []struct {
		name, condition, perms, roles, want string
	}{
		{"every element listed", "subject.permissions IS SUBSET 'x', 'y'", `["x"]`, `[]`, "T"},
		{"an element not listed", "subject.permissions IS SUBSET 'x', 'y'", `["x", "z"]`, `[]`, "F"},
		{"an element in another case", "subject.permissions IS SUBSET 'x', 'y'", `["X"]`, `[]`, "F"},
		{"every element in the roles", "subject.permissions IS SUBSET subject.roles", `["x"]`, `["x", "y"]`, "T"},
		{"an element not in the roles", "subject.permissions IS SUBSET subject.roles", `["x", "z"]`, `["x"]`, "F"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{`["subj","permissions"]`: resolved(t, "VALUE", tc.perms),
				`["subj","roles"]`: resolved(t, "VALUE", tc.roles)}
			if got := leafOutcome(t, tc.condition, opt, values); got != tc.want {
				t.Errorf("%s with subject.permissions = %s, subject.roles = %s is %s, want %s", tc.condition, tc.perms,
					tc.roles, got, tc.want)
			}
		})
	}
}

// A one-element GENERAL list of a boolean, null, or an object (SINGLE_ODD) on
// the left of IS SUBSET is a list: the boolean equals its text, and null and
// an object equal no string.
func TestASingleOddListOnTheLeftOfIsSubsetIsAList(t *testing.T) {
	for _, tc := range []struct{ g, want string }{{`[true]`, "T"}, {`[null]`, "F"}, {`[{}]`, "F"}} {
		t.Run(tc.g, func(t *testing.T) {
			values := map[string]Resolved{`["subj","g"]`: resolved(t, "SINGLE_ODD", tc.g),
				`["res",".b"]`: resolved(t, "VALUE", `["true"]`)}
			got := leafOutcomeWithPIPs(t, "subject.g IS SUBSET resource.b", generalPIPs, DefaultOptions(), values)
			if got != tc.want {
				t.Errorf("subject.g = SINGLE_ODD %s IS SUBSET resource.b = [\"true\"] is %s, want %s", tc.g, got, tc.want)
			}
		})
	}
}

// A list value, the whole resource or the subject's scopes, is empty by its
// length; a string is not empty.
func TestAListIsEmptyByItsLength(t *testing.T) {
	const resource, scopes = `["res",""]`, `["subj","scopes"]`
	for _, tc := range []struct {
		name, condition, key, value, want string
	}{
		{"an empty resource list", "resource IS EMPTY", resource, `[]`, "T"},
		{"a resource list with an element", "resource IS EMPTY", resource, `["a"]`, "F"},
		{"a resource string", "resource IS EMPTY", resource, `"x"`, "F"},
		{"an empty resource list under IS NOT EMPTY", "resource IS NOT EMPTY", resource, `[]`, "F"},
		{"a resource list with an element under IS NOT EMPTY", "resource IS NOT EMPTY", resource, `["a"]`, "T"},
		{"no scopes", "subject.scopes IS EMPTY", scopes, `[]`, "T"},
		{"a scope", "subject.scopes IS EMPTY", scopes, `["a"]`, "F"},
		{"no scopes under IS NOT EMPTY", "subject.scopes IS NOT EMPTY", scopes, `[]`, "F"},
		{"a scope under IS NOT EMPTY", "subject.scopes IS NOT EMPTY", scopes, `["a"]`, "T"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]Resolved{tc.key: resolved(t, "VALUE", tc.value)}
			if got := leafOutcome(t, tc.condition, DefaultOptions(), values); got != tc.want {
				t.Errorf("%s with %s is %s, want %s", tc.condition, tc.value, got, tc.want)
			}
		})
	}
}

// In the copy of the tree for one operation, the operation is a literal, and
// a comparison of it with literals is decided at generation: the rule that
// subject allowed reads holds exactly where that comparison does.
func TestAComparisonOfTheOperationWithLiteralsIsDecidedAtGeneration(t *testing.T) {
	for _, tc := range []struct {
		name, operation, condition string
		want                       bool
	}{
		{"the operation in a literal list", "write", "operation IS SUBSET 'write', 'x'", true},
		{"the operation outside a literal list", "write", "operation IS SUBSET 'x', 'y'", false},
		{"an operation that reads as a smaller number", "3", "operation < 5", true},
		{"an operation that reads as a larger number", "7", "operation < 5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets := fmt.Sprintf(`{"policySets": [
				{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
				 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
				 "policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
					"tenantId": "t1", "rules": [
						{"ruleId": "r1", "target": "operation == 'read'", "condition": "subject allowed '%[1]s' on resource",
						 "effect": "ALLOW", "tenantId": "t1"},
						{"ruleId": "r2", "target": "operation == '%[1]s'", "condition": %[2]q,
						 "effect": "ALLOW", "tenantId": "t1"}]}]}]}`, tc.operation, tc.condition)
			exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
			if err != nil {
				t.Fatalf("FromRegular: %v", err)
			}
			if got := decideValues(t, exp.Trees["t1"], DefaultOptions(), nil); got != tc.want {
				t.Errorf("allow(read) where subject allowed %q reads %s = %v, want %v", tc.operation, tc.condition, got,
					tc.want)
			}
		})
	}
}

// IN with two or more literals is one membership clause for a scalar's key
// and one for a structure's text, however many literals there are: a clause
// per literal would grow the module with every value a condition lists. A
// single literal is an equality instead, and is not compared here.
func TestInWithLiteralsDoesNotGrowWithTheirNumber(t *testing.T) {
	generate := func(condition string) *Module {
		m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", condition), table(t), DefaultOptions())
		if err != nil {
			t.Fatalf("Generate(%s): %v", condition, err)
		}
		return m
	}
	m5 := generate("resource.a IN 'a', 'b', 'c', 'd', 'e'")
	two, five, m5text := generate("resource.a IN 'x', 'y'").Stats.AllowClauses, m5.Stats.AllowClauses, m5.Text
	if five != two {
		t.Errorf("allow clauses of IN with five literals = %d, want %d as with two", five, two)
		t.Log(m5text)
	}
}

// CONTAINS ANY with literals takes one clause per literal for the attribute
// classes whose keys it reads and one for those whose element tokens it reads:
// the classes that read one field share a clause, which checks that the class
// is one of them.
func TestContainsAnyWithLiteralsTakesTwoClausesPerLiteral(t *testing.T) {
	const condition = "resource.a CONTAINS ANY 'a', 'b', 'c', 'd', 'e'"
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", condition), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate(%s): %v", condition, err)
	}
	if got := m.Stats.AllowClauses; got != 10 {
		t.Errorf("allow clauses of %s = %d, want 10", condition, got)
		t.Log(m.Text)
	}
}

// The clauses CONTAINS ANY shares among attribute classes, on its true and
// false rails, hold for a value of each class they join and for no list with
// a null element, whose keys hold the literal too: a null element leaves
// CONTAINS ANY undefined. A subject attribute joins a subject group, whose
// evaluator reads the shared class check in Go.
func TestAJoinedClassCheckAdmitsOnlyTheClassesItJoins(t *testing.T) {
	grouped := DefaultOptions()
	grouped.Groups = true
	for _, operand := range []struct {
		name, attribute, key string
		opt                  Options
	}{
		{"a resource attribute", "resource.a", keyA, DefaultOptions()},
		{"a subject attribute in a group", "subject.id", `["subj","id"]`, grouped},
	} {
		condition := operand.attribute + " CONTAINS ANY 'x', '5'"
		for _, tc := range []struct {
			name, value, want string
		}{
			{"a string literal", `"x"`, "T"},
			{"a number literal", `5`, "T"},
			{"a list holding a literal", `["w", "x"]`, "T"},
			{"a list holding no literal", `["w"]`, "F"},
			{"a list holding a literal and a null element", `[null, "x"]`, "U"},
		} {
			t.Run(operand.name+"/"+tc.name, func(t *testing.T) {
				values := map[string]Resolved{operand.key: resolved(t, "VALUE", tc.value)}
				if got := leafOutcome(t, condition, operand.opt, values); got != tc.want {
					t.Errorf("%s with %s = %s is %s, want %s", condition, operand.attribute, tc.value, got, tc.want)
				}
			})
		}
	}
}

// A clause holds only where one class satisfies every class check of a
// reference in it, a check that allows several classes included.
func TestAClauseNeedsAClassEveryClassCheckAllows(t *testing.T) {
	one := func(cl string) expr { return expr{fact: fact{ref: "r1", field: 't', val: cl}} }
	some := func(cls ...string) expr { return expr{fact: fact{ref: "r1", field: 't', vals: cls}} }
	for _, tc := range []struct {
		name string
		c    clause
		want bool
	}{
		{"a class among those allowed", clause{some("l", "n", "s"), one("s")}, true},
		{"a class outside those allowed", clause{some("l", "n", "s"), one("xo")}, false},
		{"two sets that share a class", clause{some("l", "n"), some("n", "xo")}, true},
		{"two sets that share no class", clause{some("l", "n", "s"), some("xl", "xo")}, false},
		{"a set and a class of another reference", clause{some("l", "n"),
			{fact: fact{ref: "r2", field: 't', val: "xo"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := consistent(tc.c); got != tc.want {
				t.Errorf("consistent(%+v) = %v, want %v", tc.c, got, tc.want)
			}
		})
	}
}

// The same tree and options give the same module byte for byte, the same
// subject groups, and the same report, however Go orders its maps from one
// run to the next.
func TestTheSameTreeGivesTheSameModule(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "DENY_OVERRIDES", "ALLOW",
		"subject.roles CONTAINS 'admin' AND resource.a IN 'x', 'y' OR resource.a CONTAINS ANY subject.g "+
			"OR subject.id < 5 AND resource.b IS SUBSET 'p', 'q' OR resource.c MATCH /api/*/items "+
			"OR resource.d == subject.name", generalPIPs)
	opt := DefaultOptions()
	opt.Groups, opt.Report = true, true
	first, err := Generate(tree, table(t), opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for range 5 {
		m, err := Generate(tree, table(t), opt)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if m.Text != first.Text {
			t.Fatalf("a second generation of one tree differs:\n%s\nfirst:\n%s", m.Text, first.Text)
		}
		if !reflect.DeepEqual(m.Groups, first.Groups) {
			t.Fatalf("a second generation of one tree has other groups: %v, first %v", m.Groups, first.Groups)
		}
		if len(m.Report) != len(first.Report) {
			t.Fatalf("a second generation of one tree has %d report entries, first %d", len(m.Report),
				len(first.Report))
		}
		for i := range m.Report {
			if !reflect.DeepEqual(m.Report[i], first.Report[i]) {
				t.Fatalf("report entry %d of a second generation = %+v, first %+v", i, m.Report[i], first.Report[i])
			}
		}
	}
}

// With Report set, the module carries a report entry for every comparison: the
// set, policy, and rule of its condition, where the condition stands, the
// comparison as written, and for each pair of operand points the cell's
// outcome and, for a value-dependent cell, the value rules of its template.
func TestTheReportNamesTheCellAndTemplateOfEachComparison(t *testing.T) {
	opt := DefaultOptions()
	opt.Report = true
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a < 5"), table(t), opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var leaf *LeafReport
	for i, r := range m.Report {
		if r.Place == spectables.PlaceRuleCondition {
			leaf = &m.Report[i]
		}
	}
	if leaf == nil {
		t.Fatalf("the report has no rule condition: %+v", m.Report)
	}
	if got, want := [4]string{leaf.Set, leaf.Policy, leaf.Rule, leaf.Leaf}, [4]string{"s1", "p1", "r1", "resource.a < 5"}; got != want {
		t.Errorf("set, policy, rule, and leaf of the rule condition = %q, want %q", got, want)
	}
	num := spectables.Point{Kind: spectables.KindLitNum, State: spectables.StateValue, Class: spectables.ClassScalar}
	want := map[spectables.Point]CellReport{
		{Kind: spectables.KindResPath, State: spectables.StateValue, Class: spectables.ClassString}: {
			Outcome: spectables.OutcomeByValue, Template: "rel"},
		{Kind: spectables.KindResPath, State: spectables.StateAbsent}: {Outcome: spectables.OutcomeF},
	}
	for _, c := range leaf.Cells {
		w, ok := want[c.Left]
		if !ok {
			continue
		}
		delete(want, c.Left)
		if c.Right != num || c.Outcome != w.Outcome || c.Template != w.Template {
			t.Errorf("cell at %+v = %+v, want right %+v, outcome %s, template %q", c.Left, c, num, w.Outcome,
				w.Template)
		}
	}
	for p := range want {
		t.Errorf("the report has no cell at %+v", p)
	}
	m2, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a < 5"), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate without Report: %v", err)
	}
	if len(m2.Report) != 0 {
		t.Errorf("without Report the module carries %d report entries, want none", len(m2.Report))
	}
}

// The report places each comparison: a set target, a policy target, the
// condition of a simplified policy, a comparison over an undeclared PIP with
// no cells, and the comparisons of the copy of the tree that subject allowed
// reads, after which the next comparison of the same condition is the tree's
// own again. A by_value cell names its template, including a fixed one for
// two literals and single_odd for a SINGLE_ODD list.
func TestTheReportPlacesEachComparison(t *testing.T) {
	sets := `{"policySets": [
		{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p1", "target": "resource.t == 'y'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [
				{"ruleId": "r1", "target": "operation == 'read'",
				 "condition": "subject allowed 'write' on resource AND resource.a < 5", "effect": "ALLOW",
				 "tenantId": "t1"},
				{"ruleId": "r2", "target": "operation == 'write'", "condition": "subject.g IS SUBSET resource.b",
				 "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r3", "target": "operation == 'read'", "condition": "subject.nope == 'x'",
				 "effect": "ALLOW", "tenantId": "t1"}]}]},
		{"policySetId": "s2", "name": "s2", "status": "ACTIVE", "type": "SIMPLIFIED",
		 "target": "resourceType == 'note'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p2", "target": "operation == 'read'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r4", "target": "subject.roles CONTAINS ANY 'reader'",
				"condition": "resource.c == 'x'", "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets),
		[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	opt := DefaultOptions()
	opt.Report = true
	m, err := Generate(exp.Trees["t1"], table(t), opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	type where struct {
		set, policy, rule string
		place             spectables.Place
		operation         string
		depth             int
		leaf              string
	}
	entries := map[where]LeafReport{}
	for _, r := range m.Report {
		entries[where{r.Set, r.Policy, r.Rule, r.Place, r.Operation, r.Depth, r.Leaf}] = r
	}
	for _, w := range []where{
		{"s1", "", "", spectables.PlaceSetTarget, "", 0, `resourceType == "doc"`},
		{"s1", "p1", "", spectables.PlacePolicyTarget, "", 0, `resource.t == "y"`},
		{"s2", "r4", "", spectables.PlaceSimplified, "", 0, `resource.c == "x"`},
		{"s1", "p1", "r1", spectables.PlaceRuleCondition, "write", 1, "resource.a < 5"},
		{"s1", "p1", "r1", spectables.PlaceRuleCondition, "", 0, "resource.a < 5"},
	} {
		if _, ok := entries[w]; !ok {
			t.Errorf("the report has no entry %+v", w)
		}
	}
	undeclared := where{"s1", "p1", "r3", spectables.PlaceRuleCondition, "", 0, `pip("subject.nope") == "x"`}
	if r, ok := entries[undeclared]; !ok || len(r.Cells) != 0 {
		t.Errorf("entry %+v = %+v, present %v; want one without cells", undeclared, r, ok)
	}
	template := func(w where, left spectables.State) string {
		for _, c := range entries[w].Cells {
			if c.Left.State == left {
				return c.Template
			}
		}
		return "no such cell"
	}
	copyTarget := where{"s1", "p1", "r1", spectables.PlaceRuleTarget, "write", 1, `operation == "read"`}
	if got := template(copyTarget, spectables.StateValue); got != "two literals compared at generation" {
		t.Errorf("template of %+v = %q, want two literals compared at generation", copyTarget, got)
	}
	odd := where{"s1", "p1", "r2", spectables.PlaceRuleCondition, "", 0, `pip("subject.g") IS SUBSET resource.b`}
	if got := template(odd, spectables.StateSingleOdd); got != "single_odd,subset" {
		t.Errorf("template of the SINGLE_ODD cell of %+v = %q, want single_odd,subset", odd, got)
	}
}

// A tree with a form the agent cannot execute is rejected as a whole, and the
// error lists every such form with its place, so that no form runs in part;
// the same tree without them generates.
func TestAFormTheAgentCannotExecuteRejectsTheTenant(t *testing.T) {
	sets := `{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r1", "target": %q,
				"condition": %q, "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	generate := func(target, condition string) (*Module, error) {
		exp, err := policyir.FromRegular([]byte(fmt.Sprintf(sets, target, condition)), []byte(`{"pips": []}`))
		if err != nil {
			t.Fatalf("FromRegular: %v", err)
		}
		return Generate(exp.Trees["t1"], table(t), DefaultOptions())
	}
	_, err := generate("operation == == 'read'", "resource.a[(@.length-1)] == 'x'")
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("Generate error = %v, want a *RejectedError", err)
	}
	want := []Rejection{
		{`set "s1" > policy "p1" > rule "r1" > target`, policyir.FormSyntax, "operation == == 'read'"},
		{`set "s1" > policy "p1" > rule "r1" > condition`, policyir.FormJSONPath, "resource.a[(@.length-1)]"},
	}
	if !reflect.DeepEqual(rej.Rejections, want) {
		t.Errorf("Rejections = %+v, want %+v", rej.Rejections, want)
	}
	if _, err := generate("operation == 'read'", "resource.a == 'x'"); err != nil {
		t.Errorf("Generate without the forms: %v, want no error", err)
	}
}

// A comparison the generator does not translate rejects the tenant too, and
// the rejection names the place of its condition.
func TestAComparisonWithoutATemplateRejectsTheTenantAtItsPlace(t *testing.T) {
	const cell = `{"op":"LT","left":{"kind":"res:path","state":"VALUE","class":"s"},` +
		`"right":{"kind":"res:path","state":"VALUE","class":"s"},"outcome":"by_value","outcomes":["T","F"],"value_rule":[`
	tab := editedTable(t, cell+`"rel"]}`, cell+`"array_eq"]}`)
	_, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a < resource.b"), tab,
		DefaultOptions())
	var rej *RejectedError
	if !errors.As(err, &rej) || len(rej.Rejections) != 1 {
		t.Fatalf("Generate error = %v, want a *RejectedError with one rejection", err)
	}
	r := rej.Rejections[0]
	if r.Where != `set "s1" > policy "p1" > rule "r1" > rule_condition` || r.Form != FormGenerator {
		t.Errorf("rejection = %+v, want one at the rule condition of r1 with form %s", r, FormGenerator)
	}
}

// A set a damaged export leaves unusable fails as a source does under its
// target, and the module lists it as a failure instead of taking the whole
// tenant out of service. Here the two sets of one policySetId would each
// permit alone, being PERMIT_UNLESS_DENY without policies; isolated, they
// deny under their targets, and the tenant's other set answers as usual.
func TestAnIsolatedSetFailsUnderItsTargetOnly(t *testing.T) {
	sets := `{"policySets": [
		{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'r1'", "tenantId": "t1",
		 "combiningAlgorithm": "PERMIT_UNLESS_DENY"},
		{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'r2'", "tenantId": "t1",
		 "combiningAlgorithm": "PERMIT_UNLESS_DENY"},
		{"policySetId": "ok", "status": "ACTIVE", "target": "resourceType == 'other'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		 "tenantId": "t1", "policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r", "target": "true", "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	m, err := Generate(exp.Trees["t1"], table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	reason := "isolated: the tenant has 2 top-level sets with this policySetId"
	if want := []Failure{{Set: "s", Reason: reason}}; !reflect.DeepEqual(m.Failures, want) {
		t.Errorf("Failures = %+v, want %+v", m.Failures, want)
	}
	for _, tc := range []struct {
		resourceType string
		want         bool
	}{{"r1", false}, {"r2", false}, {"other", true}} {
		if got := evalModule(t, m, Request{Operation: "read", ResourceType: tc.resourceType}); got != tc.want {
			t.Errorf("allow(read %s) = %v, want %v", tc.resourceType, got, tc.want)
		}
	}
	single := `{"policySets": [{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'r1'",
		"tenantId": "t1", "combiningAlgorithm": "PERMIT_UNLESS_DENY"}]}`
	exp, err = policyir.FromRegular([]byte(single), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	if m, err = Generate(exp.Trees["t1"], table(t), DefaultOptions()); err != nil {
		t.Fatalf("Generate of the set alone: %v", err)
	}
	if !evalModule(t, m, Request{Operation: "read", ResourceType: "r1"}) {
		t.Errorf("allow(read r1) of the set alone = false, want true: only its isolation denies")
	}
}

// A condition that reads a PIP the tenant declares more than once, or not at
// all, reads a failed source: the comparison is undefined, so an ALLOW rule
// does not permit, and the module lists the PIP as a failure. With one
// declaration the same rule permits.
func TestAnIsolatedOrUndeclaredPIPFails(t *testing.T) {
	const tok = `{"name": "subject.x", "pipType": "TOKEN", "claim": "c"}`
	for _, tc := range []struct {
		name, pips string
		want       bool
		failures   []Failure
	}{
		{"one declaration", tok, true, nil},
		{"two declarations", tok + ", " + tok, false,
			[]Failure{{Set: "s1", PIP: "subject.x", Reason: "isolated: declared 2 times"}}},
		{"no declaration", "", false, []Failure{{Set: "s1", PIP: "subject.x", Reason: "not declared"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.x == 'v'", tc.pips)
			m, err := Generate(tree, table(t), DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if !reflect.DeepEqual(m.Failures, tc.failures) {
				t.Errorf("Failures = %+v, want %+v", m.Failures, tc.failures)
			}
			values := map[string]Resolved{`["subj","x"]`: resolved(t, "VALUE", `"v"`)}
			if got := evalModule(t, m, Request{Operation: "read", ResourceType: "doc", Values: values}); got != tc.want {
				t.Errorf("allow(subject.x = v) = %v, want %v", got, tc.want)
			}
		})
	}
}

// A set the legacy service never evaluates, such as one whose iterate runs
// over something other than the permission scope, is listed as a failure too.
func TestASetLegacyNeverEvaluatesIsAFailure(t *testing.T) {
	sets := `{"policySets": [{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'doc'",
		"tenantId": "t1", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"iterate": {"foreach": "subject.roles", "combiningAlgorithm": "DENY_UNLESS_PERMIT"}}]}`
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	m, err := Generate(exp.Trees["t1"], table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if want := []Failure{{Set: "s", Reason: `iterate foreach "subject.roles"`}}; !reflect.DeepEqual(m.Failures, want) {
		t.Errorf("Failures = %+v, want %+v", m.Failures, want)
	}
}

// A comparison the generator cannot translate inside the copy of the tree
// that subject allowed reads rejects the tenant once, placed in that copy.
func TestARejectionInACopyOfTheTreeNamesTheCopy(t *testing.T) {
	const cell = `{"op":"LT","left":{"kind":"res:path","state":"VALUE","class":"s"},` +
		`"right":{"kind":"res:path","state":"VALUE","class":"s"},"outcome":"by_value","outcomes":["T","F"],"value_rule":[`
	tab := editedTable(t, cell+`"rel"]}`, cell+`"array_eq"]}`)
	sets := `{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [
				{"ruleId": "r1", "target": "operation == 'read'", "condition": "subject allowed 'write' on resource",
				 "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r2", "target": "operation == 'write'", "condition": "resource.a < resource.b",
				 "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	_, err = Generate(exp.Trees["t1"], tab, DefaultOptions())
	var rej *RejectedError
	if !errors.As(err, &rej) || len(rej.Rejections) != 1 {
		t.Fatalf("Generate error = %v, want a *RejectedError with one rejection", err)
	}
	want := `set "s1" > policy "p1" > rule "r2" > rule_condition > (subject allowed "write")`
	if r := rej.Rejections[0]; r.Where != want || r.Form != FormGenerator {
		t.Errorf("rejection = %+v, want one at %s with form %s", r, want, FormGenerator)
	}
}

// An export whose knob holds a value the generator does not know is a defect
// of the export, not a form of the tenant, so the error is no rejection.
func TestAnUnknownKnobValueIsNoRejection(t *testing.T) {
	tab := editedTable(t, `"string_list_split": "SPLIT_TRIM"`, `"string_list_split": "BY_HAND"`)
	_, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a IN 'x', 'y'"), tab, DefaultOptions())
	var rej *RejectedError
	if err == nil || errors.As(err, &rej) {
		t.Errorf("Generate error = %v, want an error that is not a *RejectedError", err)
	}
}

// iterateTree is a tenant whose one set iterates over the permission scope
// under algorithm, with one ALLOW rule whose condition compares the pass's
// domain with the resource's.
func iterateTree(t *testing.T, algorithm, condition string) *policyir.Tree {
	t.Helper()
	sets := fmt.Sprintf(`{"policySets": [{"policySetId": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": %q},
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r1", "target": "true", "condition": %q,
				"effect": "ALLOW", "tenantId": "t1"}]}]}]}`, algorithm, condition)
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	return exp.Trees["t1"]
}

// An iterate evaluates its set once per assignment of the permission scope,
// with subject.permissionScope.<key> reading the pass, and combines the passes
// by its algorithm: under DENY_UNLESS_PERMIT one permitting pass permits, and
// no pass denies. A permission scope that cannot be read leaves the node
// unknown, which denies.
func TestAnIterateCombinesItsPasses(t *testing.T) {
	const domain = `["subj","permissionScope.domain"]`
	pass := func(v string) map[string]Resolved { return map[string]Resolved{domain: resolved(t, "VALUE", v)} }
	for _, form := range []struct {
		name string
		opt  func(*Options)
	}{{"flat", func(*Options) {}}, {"without inlining", func(o *Options) { o.Flat = false }},
		{"with groups", func(o *Options) { o.Groups = true }}} {
		opt := DefaultOptions()
		form.opt(&opt)
		m, err := Generate(iterateTree(t, "DENY_UNLESS_PERMIT", "subject.permissionScope.domain CONTAINS resource.domain"),
			table(t), opt)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		for _, tc := range []struct {
			name  string
			scope Scope
			want  bool
		}{
			{"the second of two passes holds the domain", Scope{Passes: []map[string]Resolved{pass(`["x"]`), pass(`["d"]`)}}, true},
			{"no pass holds the domain", Scope{Passes: []map[string]Resolved{pass(`["x"]`), pass(`["y"]`)}}, false},
			{"no pass at all", Scope{Passes: []map[string]Resolved{}}, false},
			{"a scope that cannot be read", Scope{Failed: true}, false},
		} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				req := Request{Operation: "read", ResourceType: "doc", Scope: &tc.scope,
					Values: map[string]Resolved{`["res",".domain"]`: resolved(t, "VALUE", `"d"`)}}
				if got := evalModule(t, m, req); got != tc.want {
					t.Errorf("allow(resource.domain = d, scope %+v) = %v, want %v", tc.scope, got, tc.want)
				}
			})
		}
	}
}

// Under PERMIT_UNLESS_DENY an iterate with no pass permits, the algorithm's
// outcome over no children, while a scope that cannot be read leaves the
// node unknown and denies.
func TestAnEmptyScopeAndAFailedScopeDiffer(t *testing.T) {
	m, err := Generate(iterateTree(t, "PERMIT_UNLESS_DENY", "resource.domain == 'never'"), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, tc := range []struct {
		name  string
		scope Scope
		want  bool
	}{{"no pass", Scope{Passes: []map[string]Resolved{}}, true}, {"a failed scope", Scope{Failed: true}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Operation: "read", ResourceType: "doc", Scope: &tc.scope,
				Values: map[string]Resolved{`["res",".domain"]`: resolved(t, "VALUE", `"d"`)}}
			if got := evalModule(t, m, req); got != tc.want {
				t.Errorf("allow(scope %+v) = %v, want %v", tc.scope, got, tc.want)
			}
		})
	}
}

// subject allowed inside an iterate reads the decision in the current pass,
// which the generator does not translate yet, so the tenant is rejected.
func TestSubjectAllowedInsideAnIterateRejectsTheTenant(t *testing.T) {
	_, err := Generate(iterateTree(t, "DENY_UNLESS_PERMIT", "subject allowed 'write' on resource"), table(t),
		DefaultOptions())
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Rejections[0].Form != FormGenerator {
		t.Errorf("Generate error = %v, want a *RejectedError of form %s", err, FormGenerator)
	}
}

// nestedIterateTree is a tenant whose PERMIT_UNLESS_DENY set holds a set that
// iterates over the permission scope: inner is the nested set's algorithm,
// iter the iterate's, and the nested set's one rule has the effect and
// condition given. The parent permits unless the nested set denies or is
// unknown, so its answer tells a deny, a not applicable, and an unknown node
// apart.
func nestedIterateTree(t *testing.T, inner, iter, effect, condition string) *policyir.Tree {
	t.Helper()
	sets := fmt.Sprintf(`{"policySets": [{"policySetId": "parent", "status": "ACTIVE", "target": "true",
		"combiningAlgorithm": "PERMIT_UNLESS_DENY", "tenantId": "t1", "policySets": [
		{"policySetId": "s1", "target": "resourceType == 'doc'", "combiningAlgorithm": %q, "tenantId": "t1",
		 "iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": %q},
		 "policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": %[1]q, "tenantId": "t1",
			"rules": [{"ruleId": "r1", "target": "true", "condition": %[3]q, "effect": %[4]q, "tenantId": "t1"}]}]}]}]}`,
		inner, iter, condition, effect)
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

// Under a PERMIT_UNLESS_DENY parent the outcome of the iterate's node shows:
// a scope that cannot be read leaves it unknown, which denies, while no pass
// gives PERMIT_OVERRIDES' not applicable, which permits; a denying pass makes
// DENY_OVERRIDES deny; and where the set's target does not hold, the node is
// not applicable whatever the scope.
func TestTheOutcomeOfAnIterateNode(t *testing.T) {
	const domain = `["subj","permissionScope.domain"]`
	pass := func(v string) map[string]Resolved { return map[string]Resolved{domain: resolved(t, "VALUE", v)} }
	const cond = "subject.permissionScope.domain CONTAINS resource.domain"
	for _, tc := range []struct {
		name, inner, iter, effect, resourceType string
		scope                                   Scope
		want                                    bool
	}{
		{"a failed scope is unknown", "DENY_UNLESS_PERMIT", "PERMIT_OVERRIDES", "ALLOW", "doc",
			Scope{Failed: true}, false},
		{"no pass is not applicable under PERMIT_OVERRIDES", "DENY_UNLESS_PERMIT", "PERMIT_OVERRIDES", "ALLOW", "doc",
			Scope{Passes: []map[string]Resolved{}}, true},
		{"a pass whose rule denies makes DENY_OVERRIDES deny", "PERMIT_UNLESS_DENY", "DENY_OVERRIDES", "DENY", "doc",
			Scope{Passes: []map[string]Resolved{pass(`["x"]`), pass(`["d"]`)}}, false},
		{"passes whose rule does not deny permit under DENY_OVERRIDES", "PERMIT_UNLESS_DENY", "DENY_OVERRIDES",
			"DENY", "doc", Scope{Passes: []map[string]Resolved{pass(`["x"]`)}}, true},
		{"a failed scope under a target that does not hold", "DENY_UNLESS_PERMIT", "PERMIT_OVERRIDES", "ALLOW",
			"other", Scope{Failed: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Generate(nestedIterateTree(t, tc.inner, tc.iter, tc.effect, cond), table(t), DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			req := Request{Operation: "read", ResourceType: tc.resourceType, Scope: &tc.scope,
				Values: map[string]Resolved{`["res",".domain"]`: resolved(t, "VALUE", `"d"`)}}
			if got := evalModule(t, m, req); got != tc.want {
				t.Errorf("allow(%s, scope %+v) = %v, want %v", tc.resourceType, tc.scope, got, tc.want)
			}
		})
	}
}

// A pass reads subject groups as the tree does, a DENY rule in a pass denies
// under DENY_OVERRIDES, and a rule that a condition both inside and outside an
// iterate shares stays a rule of the tree outside and a function of the pass
// inside, in every form of the module, aliases and a rule without a condition
// included.
func TestAnIterateInEveryFormOfTheModule(t *testing.T) {
	const domain = `["subj","permissionScope.domain"]`
	sets := `{"policySets": [
		{"policySetId": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_UNLESS_PERMIT"},
		 "policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [
				{"ruleId": "r1", "target": "true", "effect": "DENY", "tenantId": "t1",
				 "condition": "subject.g == 'x'"},
				{"ruleId": "r2", "target": "true", "effect": "ALLOW", "tenantId": "t1",
				 "condition": "subject.roles CONTAINS 'r' AND subject.permissionScope.domain CONTAINS resource.domain"},
				{"ruleId": "r3", "target": "operation == 'audit'", "effect": "ALLOW", "tenantId": "t1"}]}]},
		{"policySetId": "s2", "status": "ACTIVE", "target": "resourceType == 'note'",
		 "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		 "policies": [{"policyId": "p2", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [{"ruleId": "r4", "target": "true", "effect": "DENY", "tenantId": "t1",
				"condition": "subject.g == 'x'"},
				{"ruleId": "r5", "target": "true", "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	exp, err := policyir.FromRegular([]byte(sets),
		[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	for _, form := range []struct {
		name string
		opt  func(*Options)
	}{{"flat", func(*Options) {}}, {"without inlining", func(o *Options) { o.Flat = false }},
		{"with groups", func(o *Options) { o.Groups = true }},
		{"with aliases", func(o *Options) { o.Flat, o.AliasClauses = false, 0 }}} {
		opt := DefaultOptions()
		form.opt(&opt)
		m, err := Generate(exp.Trees["t1"], table(t), opt)
		if err != nil {
			t.Fatalf("Generate %s: %v", form.name, err)
		}
		for _, tc := range []struct {
			name, resourceType, roles, g string
			want                         bool
		}{
			{"a pass with the domain and the role", "doc", `["r"]`, `"y"`, true},
			{"the role missing", "doc", `["q"]`, `"y"`, false},
			{"the PIP that the DENY rule reads denies", "doc", `["r"]`, `"x"`, false},
			{"the same condition outside the iterate denies", "note", `["q"]`, `"x"`, false},
			{"the same condition false outside the iterate permits", "note", `["q"]`, `"y"`, true},
		} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				req := Request{Operation: "read", ResourceType: tc.resourceType, Roles: []string{"r"},
					Scope: &Scope{Passes: []map[string]Resolved{{domain: resolved(t, "VALUE", `["d"]`)}}},
					Values: map[string]Resolved{`["res",".domain"]`: resolved(t, "VALUE", `"d"`),
						`["subj","roles"]`: resolved(t, "VALUE", tc.roles), `["subj","g"]`: resolved(t, "VALUE", tc.g)}}
				if got := evalModule(t, m, req); got != tc.want {
					t.Errorf("allow(%s, roles %s, subject.g %s) = %v, want %v", tc.resourceType, tc.roles, tc.g, got,
						tc.want)
				}
			})
		}
	}
}

// With Decision, a second module answers decision, and the module of allow
// keeps only allow: decision is permit where it allows,
// deny where no node may permit, and unknown where the denial depends on a
// value or a source the agent could not read. Every value known never gives
// unknown, and one top-level node that permits decides beside an unknown one.
// Without Decision the module has no rule decision.
func TestTheDecisionTellsAnUnknownDenialApart(t *testing.T) {
	sets := func(rules string) string {
		return `{"policySets": [{"policySetId": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES",
				"tenantId": "t1", "rules": [` + rules + `]}]}]}`
	}
	const (
		allowG   = `{"ruleId": "a", "target": "true", "condition": "subject.g == 'x'", "effect": "ALLOW", "tenantId": "t1"}`
		allowAll = `{"ruleId": "b", "target": "true", "effect": "ALLOW", "tenantId": "t1"}`
		denyG    = `{"ruleId": "c", "target": "true", "condition": "subject.g == 'x'", "effect": "DENY", "tenantId": "t1"}`
		allowNo  = `{"ruleId": "d", "target": "true", "condition": "subject.none == 'x'", "effect": "ALLOW", "tenantId": "t1"}`
		otherSet = `, {"policySetId": "s2", "status": "ACTIVE", "target": "resourceType == 'doc'",
			"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", "policies": [{"policyId": "p2",
			"target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1", "rules": [` + allowAll + `]}]}`
	)
	for _, tc := range []struct {
		name, export, state, value, want string
	}{
		{"an ALLOW rule's value permits", sets(allowG), "VALUE", `"x"`, "permit"},
		{"an ALLOW rule's other value denies", sets(allowG), "VALUE", `"y"`, "deny"},
		{"an ALLOW rule's failed PIP leaves the denial unknown", sets(allowG), "ERROR", "", "unknown"},
		{"a DENY rule's value denies beside a permit", sets(allowAll + "," + denyG), "VALUE", `"x"`, "deny"},
		{"a DENY rule's other value lets the permit through", sets(allowAll + "," + denyG), "VALUE", `"y"`, "permit"},
		{"a DENY rule's failed PIP leaves the denial unknown", sets(allowAll + "," + denyG), "ERROR", "", "unknown"},
		{"an undeclared PIP leaves the denial unknown", sets(allowNo), "VALUE", `"x"`, "unknown"},
		{"a top-level node that permits decides beside an unknown one",
			strings.TrimSuffix(sets(allowAll+","+denyG), "]}") + otherSet + "]}", "ERROR", "", "permit"},
	} {
		exp, err := policyir.FromRegular([]byte(tc.export),
			[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
		if err != nil {
			t.Fatalf("FromRegular: %v", err)
		}
		tree, ok := exp.Trees["t1"]
		if !ok {
			t.Fatalf("FromRegular: no tree of t1; failed %v", exp.Failed)
		}
		for _, form := range []struct {
			name string
			opt  func(*Options)
		}{{"flat", func(*Options) {}}, {"without inlining", func(o *Options) { o.Flat = false }},
			{"with groups", func(o *Options) { o.Groups = true }}} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				opt := DefaultOptions()
				opt.Decision = true
				form.opt(&opt)
				m, err := Generate(tree, table(t), opt)
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				req := Request{Operation: "read", ResourceType: "doc",
					Values: map[string]Resolved{`["subj","g"]`: resolved(t, tc.state, tc.value)}}
				if strings.Contains(m.Text, "maybe") {
					t.Errorf("the module of allow holds maybe; the decision module should:\n%s", m.Text)
				}
				if got := evalRule(t, m, req, "decision"); got != tc.want {
					t.Errorf("decision(subject.g = %s %s) = %v, want %s", tc.state, tc.value, got, tc.want)
				}
			})
		}
	}
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g == 'x'", generalPIPs),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate without Decision: %v", err)
	}
	if m.DecisionText != "" || strings.Contains(m.Text, "maybe") {
		t.Errorf("without Decision, the decision module is %q and the module mentions maybe: %v; want neither",
			m.DecisionText, strings.Contains(m.Text, "maybe"))
	}
}

// nc.resource_path gives a resource path the state the specification's
// resolve_resource gives it: a missing member, a path through a missing
// parent, a path that starts with a bracket, and no resource or a null one
// are ABSENT; an index past the end INDEX_OOB; a wildcard that selects
// nothing EMPTY_SEL; one null NULL; one empty list EMPTY_COLL; anything else
// VALUE. A selection the package stops as too large is ERROR.
func TestAResourcePathTakesTheStateOfItsSelection(t *testing.T) {
	deep := strings.Repeat(`{"key":`, 60) + `1` + strings.Repeat(`}`, 60)
	for _, tc := range []struct {
		name, doc, path, want string
	}{
		{"a wildcard that selects values", `{"items": [{"id": "x"}]}`, ".items[*].id", "VALUE"},
		{"a wildcard that selects nothing", `{"items": []}`, ".items[*].id", "EMPTY_SEL"},
		{"a missing member", `{"other": 1}`, ".items[*].id", "ABSENT"},
		{"a missing parent", `{"a": {}}`, ".a.x", "ABSENT"},
		{"a path that starts with a bracket", `{"key": "value"}`, "['key']", "ABSENT"},
		{"no resource or a null one", ``, ".items[*].id", "ABSENT"},
		{"an index past the end", `{"items": []}`, ".items[0].id", "INDEX_OOB"},
		{"one null", `{"items": [{"id": null}]}`, ".items[0].id", "NULL"},
		{"one empty list", `{"items": [{"id": []}]}`, ".items[0].id", "EMPTY_COLL"},
		{"one value", `{"items": [{"id": "x"}]}`, ".items[0].id", "VALUE"},
		{"a selection too large to make", deep, "..key", "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc jsonvalue.Value
			if tc.doc != "" {
				var err error
				if doc, err = jsonvalue.Decode([]byte(tc.doc)); err != nil {
					t.Fatalf("Decode(%s): %v", tc.doc, err)
				}
			}
			rec, err := JSONPathRecord(doc, tc.path)
			if err != nil {
				t.Fatalf("JSONPathRecord: %v", err)
			}
			if got := rec.Get(ast.StringTerm("s")); got == nil || got.Value.Compare(ast.String(tc.want)) != 0 {
				t.Errorf("state of %s over %s = %v, want %s", tc.path, tc.doc, got, tc.want)
			}
		})
	}
}

// A condition over a resource path that needs jsonPath reads the record
// nc.resource_path returns from the request's resource, in every form of the
// module, and decides as the specification does in each state of the
// selection: the members of an object in the document's order and a number
// with its text, two such paths in one comparison, and a selection too large
// to make, which is undefined as a failed source is.
func TestAJSONPathOperandIsReadFromTheResource(t *testing.T) {
	deep := `{"o": ` + strings.Repeat(`{"key":`, 60) + `"x"` + strings.Repeat(`}`, 60) + `}`
	for _, tc := range []struct {
		name, condition, doc, want string
	}{
		{"a selected value contains the literal", "resource.items[*].id CONTAINS 'x'", `{"items": [{"id": "x"}, {"id": "y"}]}`, "T"},
		{"no selected value is the literal", "resource.items[*].id CONTAINS 'x'", `{"items": [{"id": "y"}]}`, "F"},
		{"the wildcard selects nothing", "resource.items[*].id CONTAINS 'x'", `{"items": []}`, "F"},
		{"the member is missing", "resource.items[*].id CONTAINS 'x'", `{"other": 1}`, "F"},
		{"no resource", "resource.items[*].id CONTAINS 'x'", ``, "F"},
		{"an indexed value differing in letter case", "resource.items[0].id == 'x'", `{"items": [{"id": "X"}]}`, "T"},
		{"an index past the end", "resource.items[0].id == 'x'", `{"items": []}`, "F"},
		{"an indexed null", "resource.items[0].id == 'x'", `{"items": [{"id": null}]}`, "F"},
		{"an indexed list", "resource.items[0].id == 'x'", `{"items": [{"id": ["x"]}]}`, "F"},
		{"a pattern that matches", "resource.items[0].p MATCH /a/*", `{"items": [{"p": "/a/b"}]}`, "T"},
		{"a pattern that does not match", "resource.items[0].p MATCH /a/*", `{"items": [{"p": "/a/b/c"}]}`, "F"},
		{"keys in the document's order", "resource.o.keys() == '[b, a]'", `{"o": {"b": 1, "a": 2}}`, "T"},
		{"keys in sorted order", "resource.o.keys() == '[a, b]'", `{"o": {"b": 1, "a": 2}}`, "F"},
		{"a number with its text", "resource.items[0].n == '1.0'", `{"items": [{"n": 1.0}]}`, "T"},
		{"a number without its fraction", "resource.items[0].n == '1'", `{"items": [{"n": 1.0}]}`, "F"},
		{"two paths with equal values", "resource.a[0] == resource.b[0]", `{"a": ["x"], "b": ["X"]}`, "T"},
		{"two paths with other values", "resource.a[0] == resource.b[0]", `{"a": ["x"], "b": ["y"]}`, "F"},
		{"two paths, the second past the end", "resource.a[0] == resource.b[0]", `{"a": ["x"], "b": []}`, "F"},
		{"a selection too large to make", "resource.o..key CONTAINS 'x'", deep, "U"},
	} {
		var doc jsonvalue.Value
		if tc.doc != "" {
			var err error
			if doc, err = jsonvalue.Decode([]byte(tc.doc)); err != nil {
				t.Fatalf("Decode(%s): %v", tc.doc, err)
			}
		}
		for _, form := range []struct {
			name string
			opt  func(*Options)
		}{{"flat", func(*Options) {}}, {"without inlining", func(o *Options) { o.Flat = false }},
			{"with groups", func(o *Options) { o.Groups = true }}} {
			t.Run(form.name+"/"+tc.name, func(t *testing.T) {
				opt := DefaultOptions()
				form.opt(&opt)
				got := "U"
				for _, rail := range []struct {
					alg, effect, outcome string
				}{{"DENY_UNLESS_PERMIT", "ALLOW", "T"}, {"PERMIT_UNLESS_DENY", "DENY", "F"}} {
					m, err := Generate(tenantWithSet(t, rail.alg, rail.effect, tc.condition), table(t), opt)
					if err != nil {
						t.Fatalf("Generate: %v", err)
					}
					if !strings.Contains(m.Text, "nc.resource_path(input.resource") {
						t.Fatalf("the module does not read the path through nc.resource_path:\n%s", m.Text)
					}
					if evalModule(t, m, Request{Operation: "read", ResourceType: "doc", Resource: doc}) {
						got = rail.outcome
					}
				}
				if got != tc.want {
					t.Errorf("%s over %s is %s, want %s", tc.condition, tc.doc, got, tc.want)
				}
			})
		}
	}
}

// A node no unknown value reaches has its hi bound equal to its lo bound, so
// with Decision the module reads the lo clauses for it: maybe has the clauses
// of allow, and neither a rule of a hi bound nor the hi rule of a subject
// allowed copy appears. A condition over a GENERAL PIP is the control that
// keeps the hi bound.
func TestAnAlwaysKnownTreeAddsNoHiBound(t *testing.T) {
	sets := `{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_OVERRIDES", "tenantId": "t1",
			"rules": [
				{"ruleId": "r1", "target": "operation == 'read'", "condition": "subject allowed 'write' on resource",
				 "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r2", "target": "operation == 'write'", "condition": %q, "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r3", "target": "true", "condition": "resource.b == 'no'", "effect": "DENY",
				 "tenantId": "t1"}]}]}]}`
	for _, tc := range []struct {
		name, condition string
		hi              bool
	}{
		{"an attribute of the resource", "resource.a == 'w'", false},
		{"a GENERAL PIP", "subject.g == 'w'", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp, err := policyir.FromRegular([]byte(fmt.Sprintf(sets, tc.condition)),
				[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
			if err != nil {
				t.Fatalf("FromRegular: %v", err)
			}
			opt := DefaultOptions()
			opt.Decision, opt.Flat = true, false
			m, err := Generate(exp.Trees["t1"], table(t), opt)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			allow, maybe := strings.Count(m.Text, "\nallow if"), strings.Count(m.DecisionText, "\nmaybe if")
			hiRules := strings.Contains(m.DecisionText, "_hiP") || strings.Contains(m.DecisionText, "_hiD")
			if hiRules != tc.hi || !tc.hi && maybe != allow {
				t.Errorf("module over %s: hi rules %v (want %v), %d maybe and %d allow clauses:\n%s", tc.condition,
					hiRules, tc.hi, maybe, allow, m.DecisionText)
			}
		})
	}
}

// Each source of an unknown value leaves a denial unknown with Decision: a
// set a damaged export isolates, an iterate over a permission scope that
// cannot be read, and a simplified policy over a failed PIP.
func TestEachSourceOfAnUnknownLeavesTheDenialUnknown(t *testing.T) {
	const pips = `{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`
	isolated := `{"policySets": [
		{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'doc'", "tenantId": "t1",
		 "combiningAlgorithm": "PERMIT_UNLESS_DENY"},
		{"policySetId": "s", "status": "ACTIVE", "target": "resourceType == 'other'", "tenantId": "t1",
		 "combiningAlgorithm": "PERMIT_UNLESS_DENY"}]}`
	simplified := `{"policySets": [{"policySetId": "s2", "name": "s2", "status": "ACTIVE", "type": "SIMPLIFIED",
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"policies": [{"policyId": "p2", "target": "operation == 'read'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": "t1", "rules": [{"ruleId": "r2", "target": "subject.roles CONTAINS ANY 'reader'",
				"condition": "subject.g == 'x'", "effect": "ALLOW", "tenantId": "t1"}]}]}]}`
	tree := func(sets string) *policyir.Tree {
		exp, err := policyir.FromRegular([]byte(sets), []byte(pips))
		if err != nil {
			t.Fatalf("FromRegular: %v", err)
		}
		return exp.Trees["t1"]
	}
	for _, tc := range []struct {
		name string
		tree *policyir.Tree
		req  Request
	}{
		{"an isolated set", tree(isolated), Request{Operation: "read", ResourceType: "doc"}},
		{"an iterate over a failed scope", iterateTree(t, "DENY_UNLESS_PERMIT",
			"subject.permissionScope.domain CONTAINS resource.domain"),
			Request{Operation: "read", ResourceType: "doc", Scope: &Scope{Failed: true},
				Values: map[string]Resolved{`["res",".domain"]`: resolved(t, "VALUE", `"d"`)}}},
		{"a simplified policy over a failed PIP", tree(simplified),
			Request{Operation: "read", ResourceType: "doc", Roles: []string{"reader"},
				Values: map[string]Resolved{`["subj","g"]`: resolved(t, "ERROR", "")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := DefaultOptions()
			opt.Decision = true
			m, err := Generate(tc.tree, table(t), opt)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got := evalRule(t, m, tc.req, "decision"); got != "unknown" {
				t.Errorf("decision = %v, want unknown", got)
			}
		})
	}
}

// subject denied reads the decision of a copy of the tree for another
// operation. Over a copy that reads only known values the leaf is two-valued;
// over one that reads a failed PIP the denial is unknown.
func TestSubjectDeniedOverACopyOfTheTree(t *testing.T) {
	sets := `{"policySets": [{"policySetId": "s1", "name": "s1", "status": "ACTIVE", "target": "resourceType == 'doc'",
		"combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
		"policies": [{"policyId": "p1", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"rules": [
				{"ruleId": "r1", "target": "operation == 'read'", "condition": "subject denied 'write' on resource",
				 "effect": "ALLOW", "tenantId": "t1"},
				{"ruleId": "r2", "target": "operation == 'write'", "condition": %q, "effect": "ALLOW",
				 "tenantId": "t1"}]}]}]}`
	for _, tc := range []struct {
		name, condition, key, state, value, want string
	}{
		{"a known value the write permits", "resource.a == 'w'", keyA, "VALUE", `"w"`, "deny"},
		{"a known value the write denies", "resource.a == 'w'", keyA, "VALUE", `"z"`, "permit"},
		{"a PIP value the write permits", "subject.g == 'w'", `["subj","g"]`, "VALUE", `"w"`, "deny"},
		{"a PIP value the write denies", "subject.g == 'w'", `["subj","g"]`, "VALUE", `"z"`, "permit"},
		{"a failed PIP", "subject.g == 'w'", `["subj","g"]`, "ERROR", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp, err := policyir.FromRegular([]byte(fmt.Sprintf(sets, tc.condition)),
				[]byte(`{"pips": [{"tenantId": "t1", "name": "subject.g", "pipType": "GENERAL", "url": "http://g"}]}`))
			if err != nil {
				t.Fatalf("FromRegular: %v", err)
			}
			opt := DefaultOptions()
			opt.Decision = true
			m, err := Generate(exp.Trees["t1"], table(t), opt)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			req := Request{Operation: "read", ResourceType: "doc",
				Values: map[string]Resolved{tc.key: resolved(t, tc.state, tc.value)}}
			if got := evalRule(t, m, req, "decision"); got != tc.want {
				t.Errorf("decision(%s with %s %s) = %v, want %s", tc.condition, tc.state, tc.value, got, tc.want)
			}
			if got := evalModule(t, m, req); got != (tc.want == "permit") {
				t.Errorf("allow(%s with %s %s) = %v, want %v", tc.condition, tc.state, tc.value, got,
					tc.want == "permit")
			}
		})
	}
}

// Decision adds the decision module and leaves the module of allow and its
// statistics as they are without it.
func TestDecisionLeavesTheModuleOfAllowAlone(t *testing.T) {
	tree := tenantWithSetAndPIPs(t, "DENY_OVERRIDES", "ALLOW",
		"subject.roles CONTAINS 'admin' AND resource.a IN 'x', 'y' OR subject.g == 'z'", generalPIPs)
	off, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	opt := DefaultOptions()
	opt.Decision = true
	on, err := Generate(tree, table(t), opt)
	if err != nil {
		t.Fatalf("Generate with Decision: %v", err)
	}
	if on.Text != off.Text {
		t.Errorf("the module of allow differs with Decision:\n%s\nwithout:\n%s", on.Text, off.Text)
	}
	if on.Stats.Clauses != off.Stats.Clauses || on.Stats.Rules != off.Stats.Rules || on.Stats.Bytes != off.Stats.Bytes {
		t.Errorf("Stats with Decision %+v, without %+v; want equal clauses, rules, and bytes", on.Stats, off.Stats)
	}
	if on.Stats.DecisionClauses == 0 || off.Stats.DecisionClauses != 0 {
		t.Errorf("DecisionClauses with Decision %d, without %d; want some and none", on.Stats.DecisionClauses,
			off.Stats.DecisionClauses)
	}
}
