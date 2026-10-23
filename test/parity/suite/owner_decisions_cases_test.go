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

//go:build integration

package paritysuite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"authz-agent/test/parity/suite/model"
)

// formSet is a top-level export set with the id set-1 and the name s1, and
// the members of extra merged in.
func formSet(extra string) any {
	var set map[string]any
	if err := json.Unmarshal([]byte(`{"policySetId":"set-1","name":"s1","tenantId":"t",`+extra+`}`), &set); err != nil {
		panic(err)
	}
	return set
}

// formsOf returns the kind and the description of each form of the export.
func formsOf(policySets, pips []any) [][2]string {
	var out [][2]string
	for _, f := range exportForms(policySets, pips) {
		out = append(out, [2]string{f.kind, f.what})
	}
	return out
}

func TestExportForms(t *testing.T) {
	pipX := []any{map[string]any{"name": "subject.x.value"}}
	for _, tc := range []struct {
		name string
		set  string
		pips []any
		want [][2]string
	}{
		{"iterate without combiningAlgorithm", `"iterate":{"foreach":"subject.permissionScope"}`, nil,
			[][2]string{{formNeverEvaluated, "iterate without combiningAlgorithm"}}},
		{"iterate with a null combiningAlgorithm", `"iterate":{"foreach":"subject.permissionScope","combiningAlgorithm":null}`, nil,
			[][2]string{{formNeverEvaluated, "iterate without combiningAlgorithm"}}},
		{"iterate over another attribute", `"iterate":{"foreach":"subject.roles","combiningAlgorithm":"DENY_OVERRIDES"}`, nil,
			[][2]string{{formNeverEvaluated, `foreach over "subject.roles"`}}},
		{"iterate over the permission scope with an algorithm", `"iterate":{"foreach":"subject.permissionScope","combiningAlgorithm":"DENY_OVERRIDES"}`, nil,
			nil},
		{"a rule reads an attribute no PIP declares", `"policies":[{"rules":[{"condition":"subject.x == 'v'"}]}]`, nil,
			[][2]string{{formUndeclaredPIP, "subject.x with no PIP declared"}}},
		{"a set target reads an attribute no PIP declares", `"target":"subject.x == 'v'"`, nil,
			[][2]string{{formUndeclaredPIP, "subject.x with no PIP declared"}}},
		{"a rule reads an attribute a PIP declares", `"policies":[{"rules":[{"condition":"subject.x == 'v'"}]}]`, pipX,
			nil},
		{"a rule reads an attribute of the token", `"policies":[{"rules":[{"condition":"subject.roles CONTAINS 'R'"}]}]`, nil,
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, formsOf([]any{formSet(tc.set)}, tc.pips)); diff != "" {
				t.Errorf("exportForms(%s) (-want +got):\n%s", tc.set, diff)
			}
		})
	}
}

// The /health check accepts a name of any set above the form, so a form in a
// nested set carries the chain from the top-level set down.
func TestExportForms_AFormInANestedSetCarriesTheSetsAboveIt(t *testing.T) {
	set := formSet(`"policySets":[{"policySetId":"set-2","name":"s2","tenantId":"t","iterate":{"foreach":"subject.roles","combiningAlgorithm":"DENY_OVERRIDES"}}]`)
	forms := exportForms([]any{set}, nil)
	if len(forms) != 1 {
		t.Fatalf("exportForms returned %d forms, want 1", len(forms))
	}
	if diff := cmp.Diff([]string{"set-1", "s1", "set-2", "s2"}, forms[0].sets); diff != "" {
		t.Errorf("sets (-want +got):\n%s", diff)
	}
}

// ownerFixture is a golden tree under a temporary directory for the regular
// case c1 of resource type RT.
type ownerFixture struct {
	t    *testing.T
	root string
}

func (fx ownerFixture) write(dir, name string, v any) {
	fx.t.Helper()
	path := filepath.Join(fx.root, dir, "regular", "c1", name+".json")
	raw, err := json.Marshal(v)
	if err != nil {
		fx.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		fx.t.Fatal(err)
	}
}

// cases runs regularOwnerDecisionCases over a file whose case c1 has the
// sets and the requests given as JSON, in the stand's tenant "stand".
func (fx ownerFixture) cases(sets, requests string) []ownerDecisionCase {
	fx.t.Helper()
	var f caseFile
	doc := `{"cases":[{"id":"c1","resourceType":"RT","sets":` + sets + `,"requests":` + requests + `}]}`
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		fx.t.Fatal(err)
	}
	out, err := regularOwnerDecisionCases("owner.json", f, fx.root, "stand")
	if err != nil {
		fx.t.Fatal(err)
	}
	return out
}

// decisionPaths returns the golden paths of the decisions of each case.
func decisionPaths(cases []ownerDecisionCase) [][]string {
	var out [][]string
	for _, c := range cases {
		paths := []string{}
		for _, d := range c.decisions {
			paths = append(paths, d.path)
		}
		out = append(out, paths)
	}
	return out
}

const (
	iterateWithoutAlgorithm = `[{"key":"s","target":"true","iterate":{"foreach":"subject.permissionScope"},"policies":[]}]`
	readsUndeclaredPIP      = `[{"key":"s","target":"true","policies":[{"key":"p","target":"true","rules":[{"key":"r","condition":"subject.x == 'v'","effect":"ALLOW"}]}]}]`
	oneRead                 = `[{"name":"read","operation":"READ"}]`
)

// The upload golden decides whether legacy took the set at all: a refused
// upload left nothing in the export.
func TestRegularOwnerDecisionCases_OnlyAnAcceptedUploadMakesACase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   [][]string
	}{
		{"accepted", 200, [][]string{{"regular/c1/read"}}},
		{"refused", 400, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := ownerFixture{t, t.TempDir()}
			fx.write("load-policy-sets-v1", "upload-1", model.PolicyLoadOutcome{Status: tc.status})
			fx.write("check-resource-v1-outcome", "read", model.CheckResourceOutcome{Status: 500})
			if diff := cmp.Diff(tc.want, decisionPaths(fx.cases(iterateWithoutAlgorithm, oneRead))); diff != "" {
				t.Errorf("decisions (-want +got):\n%s", diff)
			}
		})
	}
}

// A case that declares PIPs reaches its upload only after legacy accepted the
// declaration.
func TestRegularOwnerDecisionCases_ARefusedDeclarationMakesNoCase(t *testing.T) {
	fx := ownerFixture{t, t.TempDir()}
	fx.write("load-simplified-policies-v1", "declare-the-domain", model.PolicyLoadOutcome{Status: 400})
	fx.write("load-policy-sets-v1", "upload-1", model.PolicyLoadOutcome{Status: 200})
	var f caseFile
	doc := `{"pips":{"p":{"name":"subject.y"}},"cases":[{"id":"c1","resourceType":"RT","pips":["p"],"sets":` +
		iterateWithoutAlgorithm + `,"requests":[]}]}`
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatal(err)
	}
	cases, err := regularOwnerDecisionCases("owner.json", f, fx.root, "stand")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 0 {
		t.Errorf("regularOwnerDecisionCases returned %d cases, want none", len(cases))
	}
}

// A decision is the agent's to refuse only where legacy failed it because of
// the form: the status the form fails with, the case's resource type and
// tenant, and a request legacy's validation passes.
func TestRegularOwnerDecisionCases_ADecisionDependsOnTheFormOnlyWhereLegacyFailedItThere(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request string
		status  int
		want    []string
	}{
		{"legacy answered 500", `{"name":"read","operation":"READ"}`, 500, []string{"regular/c1/read"}},
		{"legacy answered 200", `{"name":"read","operation":"READ"}`, 200, []string{}},
		{"another resource type", `{"name":"read","operation":"READ","type":"OTHER"}`, 500, []string{}},
		{"another tenant", `{"name":"read","operation":"READ","tenantId":"other"}`, 500, []string{}},
		{"the stand's tenant named", `{"name":"read","operation":"READ","tenantId":"stand"}`, 500, []string{"regular/c1/read"}},
		{"an empty operation", `{"name":"read","emptyOperation":true}`, 500, []string{}},
		{"a filter without an operation", `{"name":"read","filter":true,"omitOperation":true}`, 500, []string{}},
		{"a bulk item without an operation", `{"name":"read","bulk":[{"id":"1","operation":""}]}`, 500, []string{}},
		{"a bulk item without operations", `{"name":"read","bulkOperations":[{"id":"1","operations":[]}]}`, 500, []string{}},
		{"a request that pins a route", `{"name":"read","operation":"READ","pins":{"/r":{"statusCode":200}}}`, 500, []string{}},
		{"a request filed by order class", `{"name":"read","operation":"READ","classifyBy":"/r"}`, 500, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := ownerFixture{t, t.TempDir()}
			fx.write("load-policy-sets-v1", "upload-1", model.PolicyLoadOutcome{Status: 200})
			fx.write("check-resource-v1-outcome", "read", model.CheckResourceOutcome{Status: tc.status})
			if diff := cmp.Diff([][]string{tc.want}, decisionPaths(fx.cases(iterateWithoutAlgorithm, "["+tc.request+"]"))); diff != "" {
				t.Errorf("decisions (-want +got):\n%s", diff)
			}
		})
	}
}

// An attribute the agent needs a PIP for may be one legacy resolves without
// one, so a set that reads it makes a case only where legacy refused a check
// of the case with 400.
func TestRegularOwnerDecisionCases_AnUndeclaredPIPMakesACaseOnlyWhenLegacyRefusedACheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   [][]string
	}{
		{"refused with 400", 400, [][]string{{"regular/c1/read"}}},
		{"answered 200", 200, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := ownerFixture{t, t.TempDir()}
			fx.write("load-policy-sets-v1", "upload-1", model.PolicyLoadOutcome{Status: 200})
			fx.write("check-resource-v1-outcome", "read", model.CheckResourceOutcome{Status: tc.status})
			if diff := cmp.Diff(tc.want, decisionPaths(fx.cases(readsUndeclaredPIP, oneRead))); diff != "" {
				t.Errorf("decisions (-want +got):\n%s", diff)
			}
		})
	}
}

// The export of a regular case carries the set as legacy's v3 export does,
// and as JSON decodes it, so the iterate algorithm the upload sent as null is
// null and not a typed nil.
func TestRegularOwnerDecisionCases_TheExportCarriesTheSetAsLegacyExportsIt(t *testing.T) {
	fx := ownerFixture{t, t.TempDir()}
	fx.write("load-policy-sets-v1", "upload-1", model.PolicyLoadOutcome{Status: 200})
	cases := fx.cases(iterateWithoutAlgorithm, `[]`)
	if len(cases) != 1 {
		t.Fatalf("regularOwnerDecisionCases returned %d cases, want 1", len(cases))
	}
	want := map[string]any{
		"policySetId": derivedID("c1", "set/s"), "name": "c1 s", "status": "ACTIVE", "target": "true",
		"type": "DEFAULT", "tenantId": "stand", "policies": []any{}, "policySets": []any{},
		"iterate": map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": nil},
	}
	if diff := cmp.Diff([]any{want}, cases[0].policySets); diff != "" {
		t.Errorf("policySets (-want +got):\n%s", diff)
	}
}

// readsX is a set of tenant whose rule reads subject.x, which no PIP declares.
func readsX(id, tenant string) any {
	return map[string]any{"policySetId": id, "tenantId": tenant, "policies": []any{map[string]any{
		"rules": []any{map[string]any{"condition": "subject.x == 'v'"}}}}}
}

// legacyPointCases runs legacyOwnerDecisionCases over a point of the case c1
// whose export holds sets and whose one decision, check, is sent in tenant
// and recorded by legacy with status.
func legacyPointCases(t *testing.T, sets []any, tenant string, status int) []ownerDecisionCase {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "check-resource-v1-outcome", "sequence", "c1", "check.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(model.CheckResourceOutcome{Status: status})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	lc := legacyExportCase{file: "owner.json", id: "c1", resourceType: "RT", tenant: tenant,
		points: []legacyExportPoint{{step: "write", policySets: sets, pips: []any{},
			decisions: []legacyDecision{{request: isolatedRequest{name: "check", operation: "READ"},
				tenant: tenant, path: "sequence/c1/check"}}}}}
	cases, err := legacyOwnerDecisionCases(lc, root, "stand")
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// A point of part A whose raw reads hold a set that reads an undeclared PIP
// makes a case only where legacy refused a check of the point with 400.
func TestLegacyOwnerDecisionCases_AnUndeclaredPIPMakesACaseOnlyWhenLegacyRefusedACheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   [][]string
	}{
		{"refused with 400", 400, [][]string{{"sequence/c1/check"}}},
		{"answered 200", 200, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cases := legacyPointCases(t, []any{readsX("set-t", "t")}, "t", tc.status)
			if diff := cmp.Diff(tc.want, decisionPaths(cases)); diff != "" {
				t.Errorf("decisions (-want +got):\n%s", diff)
			}
		})
	}
}

// A refusal confirms the undeclared PIP of its own tenant: legacy refuses
// every check of a tenant whose set reads one, and says nothing about the
// sets of another tenant.
func TestLegacyOwnerDecisionCases_ARefusalConfirmsTheUndeclaredPIPOfItsTenantOnly(t *testing.T) {
	cases := legacyPointCases(t, []any{readsX("set-t", "t"), readsX("set-u", "u")}, "u", 400)
	if len(cases) != 1 {
		t.Fatalf("legacyOwnerDecisionCases returned %d cases, want 1", len(cases))
	}
	var tenants []string
	for _, f := range cases[0].forms {
		tenants = append(tenants, f.tenant)
	}
	if diff := cmp.Diff([]string{"u"}, tenants); diff != "" {
		t.Errorf("tenants of the confirmed forms (-want +got):\n%s", diff)
	}
}

func TestRefusalProblem(t *testing.T) {
	allowed := []string{"1"}
	none := []string{}
	for _, tc := range []struct {
		name    string
		outcome any
		want    string
	}{
		{"a check denied", &model.CheckResourceOutcome{Status: 200}, ""},
		{"a check allowed", &model.CheckResourceOutcome{Status: 200, Decision: true}, `an allow: {"status":200,"decision":true}`},
		{"a check failed", &model.CheckResourceOutcome{Status: 500}, `status 500: {"status":500,"decision":false}`},
		{"a bulk check with no id", &model.CheckResourceBulkOutcome{Status: 200, Allowed: &none}, ""},
		{"a bulk check with an id", &model.CheckResourceBulkOutcome{Status: 200, Allowed: &allowed}, `an allow: {"status":200,"allowed":["1"]}`},
		{"bulk operations with no id", &model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: &map[string][]string{"READ": {}}}, ""},
		{"bulk operations with an id", &model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: &map[string][]string{"READ": {"1"}}},
			`an allow: {"status":200,"decision":{"READ":["1"]}}`},
		{"a v2 check allowed", &model.CheckResourceV2Outcome{Status: 200, Decision: true}, `an allow: {"status":200,"decision":true}`},
		{"v2 bulk operations with an id", &model.CheckResourceBulkOperationsV2Outcome{Status: 200, Decision: &map[string][]string{"READ": {"1"}}},
			`an allow: {"status":200,"decision":{"READ":["1"]}}`},
		{"a v2 filter USE_FILTER_CONDITION", &model.FilterV2Outcome{Status: 200, Result: model.OldFilterEvaluationResult{CalculationResult: "USE_FILTER_CONDITION"}},
			`an allow: {"status":200,"result":{"calculationResult":"USE_FILTER_CONDITION"}}`},
		{"an answer of another type", true, "an answer of type bool, which this test cannot judge"},
		{"a filter DENY", &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{CalculationResult: "DENY"}}, ""},
		{"a filter ALLOW", &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{CalculationResult: "ALLOW"}},
			`an allow: {"status":200,"result":{"calculationResult":"ALLOW"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusalProblem(tc.outcome); got != tc.want {
				t.Errorf("refusalProblem() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The goldens hold a regular set that iterates over subject.roles and one
// whose condition reads subject.isM2M with no PIP, and legacy failed the
// decisions of both; the selection over the recorded case files finds them.
func TestAllOwnerDecisionCases_FindsTheRecordedForms(t *testing.T) {
	cases, err := allOwnerDecisionCases("testdata/golden", "default")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range cases {
		got[c.name] = decisionPaths([]ownerDecisionCase{c})[0]
	}
	for name, want := range map[string][]string{
		"round28/reach-sets.json/r28reach-foreach-roles": {"regular/r28reach-foreach-roles/read", "regular/r28reach-foreach-roles/filter"},
		"round15/questions.json/q15-is-m2m-or":           {"regular/q15-is-m2m-or/reader", "regular/q15-is-m2m-or/service-account"},
	} {
		if diff := cmp.Diff(want, got[name]); diff != "" {
			t.Errorf("decisions of %s (-want +got):\n%s", name, diff)
		}
	}
}
