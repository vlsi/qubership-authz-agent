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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"authz-agent/test/parity/suite/model"
)

// legacyFixture is a golden tree under a temporary directory for one
// sequence case, legacy-case in tenant parity-legacy-case.
type legacyFixture struct {
	t    *testing.T
	root string
}

func newLegacyFixture(t *testing.T) legacyFixture {
	return legacyFixture{t: t, root: t.TempDir()}
}

func (fx legacyFixture) write(dir, step string, v any) {
	fx.t.Helper()
	path := filepath.Join(fx.root, dir, "sequence", "legacy-case", step+".json")
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

// status records the status golden of a write step of operation op.
func (fx legacyFixture) status(op, step string, status int) {
	b, _, _ := bindingOf(papOperations()[op], "")
	fx.write(b.Golden, step, model.PolicyLoadOutcome{Status: status})
}

// rawSets records a raw read of the policy sets holding sets.
func (fx legacyFixture) rawSets(step string, sets ...any) {
	fx.write("pap-read-raw-v1", step, model.PapReadRawOutcome{Status: 200, Body: map[string]any{"policySets": append([]any{}, sets...)}})
}

// rawPIPs records a raw read of the PIPs holding pips.
func (fx legacyFixture) rawPIPs(step string, pips ...any) {
	fx.write("pap-read-raw-v1", step, model.PapReadRawOutcome{Status: 200, Body: map[string]any{"pips": append([]any{}, pips...)}})
}

// legacyCase builds the case legacy-case from steps, given as JSON, in the
// tenant parity-legacy-case, and runs legacyExportCases over it.
func (fx legacyFixture) legacyCase(steps string) legacyExportCase {
	fx.t.Helper()
	var f caseFile
	doc := `{"cases":[{"id":"legacy-case","resourceType":"PARITY_LEGACY","tenant":"parity-legacy-case","steps":` + steps + `}]}`
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		fx.t.Fatal(err)
	}
	cases, err := legacyExportCases("legacy.json", f, fx.root)
	if err != nil {
		fx.t.Fatal(err)
	}
	if len(cases) != 1 {
		fx.t.Fatalf("legacyExportCases returned %d cases, want 1", len(cases))
	}
	return cases[0]
}

// A step that writes simplified policies and reads the policy sets back
// before its decision.
const legacyWriteAndDecide = `{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],
	"observe":["status","read-raw:read-config-sets","decide:check"],"onRefusal":"continue",
	"requests":[{"name":"check","operation":"READ"}]}`

// pointPaths returns the golden paths of the decisions of each point.
func pointPaths(lc legacyExportCase) [][]string {
	var out [][]string
	for _, p := range lc.points {
		var paths []string
		for _, d := range p.decisions {
			paths = append(paths, d.path)
		}
		out = append(out, paths)
	}
	return out
}

func TestLegacyExportCases_ARawReadOfTheWrittenDocumentAndAnUnwrittenOneMakeAPoint(t *testing.T) {
	fx := newLegacyFixture(t)
	set := map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "parity-legacy-case"}
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write", set)
	lc := fx.legacyCase("[" + legacyWriteAndDecide + "]")
	if diff := cmp.Diff([][]string{{"sequence/legacy-case/check"}}, pointPaths(lc)); diff != "" {
		t.Fatalf("points (-want +got):\n%s\nuncompared: %v", diff, lc.uncompared)
	}
	p := lc.points[0]
	if diff := cmp.Diff([]any{set}, p.policySets); diff != "" {
		t.Errorf("policySets (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{
		"tenant parity-legacy-case policySets: raw read of write",
		"tenant parity-legacy-case pips: unwritten",
	}, p.evidence); diff != "" {
		t.Errorf("evidence (-want +got):\n%s", diff)
	}
}

// An accepted PIP write needs a raw read of the PIPs before the decision is
// compared; with one, the point carries the PIPs it shows.
func TestLegacyExportCases_AnAcceptedPIPWriteIsComparedOnlyWithARawReadOfThePIPs(t *testing.T) {
	pip := map[string]any{"name": "subject.x", "pipType": "TOKEN", "tenantId": "parity-legacy-case"}
	for _, tc := range []struct {
		name    string
		observe string
		want    []any // the point's PIPs; nil: the decision is not compared
	}{
		{"without a raw read of the PIPs", `["status"]`, nil},
		{"with a raw read of the PIPs", `["status","read-raw:read-config-pips"]`, []any{pip}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newLegacyFixture(t)
			fx.status("write-domain-pips", "pips", 201)
			fx.rawPIPs("pips", pip)
			fx.status("write-domain-policies", "write", 201)
			fx.rawSets("write")
			lc := fx.legacyCase(`[{"name":"pips","op":"write-domain-pips","args":{"domain":"D"},"body":[],"onRefusal":"continue",
				"observe":` + tc.observe + `},` + legacyWriteAndDecide + `]`)
			if tc.want == nil {
				if len(lc.points) != 0 {
					t.Errorf("points = %v, want none", pointPaths(lc))
				}
				if got := lc.uncompared["sequence/legacy-case/check"]; !strings.HasPrefix(got, "no raw read of pips at step write") {
					t.Errorf("uncompared reason = %q, want it to start with %q", got, "no raw read of pips at step write")
				}
				return
			}
			if len(lc.points) != 1 {
				t.Fatalf("points = %v, want one; uncompared: %v", pointPaths(lc), lc.uncompared)
			}
			if diff := cmp.Diff(tc.want, lc.points[0].pips); diff != "" {
				t.Errorf("pips (-want +got):\n%s", diff)
			}
		})
	}
}

// The status of a write decides whether it changed the export: a refused
// write leaves a raw read before it valid, an accepted one does not, and one
// whose status is not recorded is taken to have changed it.
func TestLegacyExportCases_AWriteBetweenTheRawReadAndTheDecisionKeepsTheReadOnlyWhenRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int // 0: not recorded
		compared bool
	}{
		{"refused with 400", 400, true},
		{"accepted with 201", 201, false},
		{"status not recorded", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newLegacyFixture(t)
			fx.rawSets("before")
			if tc.status != 0 {
				fx.status("write-domain-policies", "write", tc.status)
			}
			lc := fx.legacyCase(`[{"name":"before","op":"read-config-sets","observe":["read-raw:read-config-sets"]},
				{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],"observe":["status","decide:check"],
				 "onRefusal":"continue","requests":[{"name":"check","operation":"READ"}]}]`)
			if got := len(lc.points) == 1; got != tc.compared {
				t.Errorf("compared = %v, want %v; uncompared: %v", got, tc.compared, lc.uncompared)
			}
		})
	}
}

func TestLegacyExportCases_ARawReadAfterTheDecisionWithNoWriteBetweenCoversIt(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("after")
	lc := fx.legacyCase(`[{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],"observe":["status","decide:check"],
		"onRefusal":"continue","requests":[{"name":"check","operation":"READ"}]},
		{"name":"after","op":"read-config-sets","observe":["read-raw:read-config-sets"]}]`)
	if diff := cmp.Diff([][]string{{"sequence/legacy-case/check"}}, pointPaths(lc)); diff != "" {
		t.Errorf("points (-want +got):\n%s\nuncompared: %v", diff, lc.uncompared)
	}
}

// Decisions share a point while the export stays the same, and an accepted
// write between them starts a new one.
func TestLegacyExportCases_DecisionsShareAPointUntilAnAcceptedWrite(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "w1", 201)
	fx.status("write-domain-policies", "w2", 201)
	fx.rawSets("w1")
	fx.rawSets("w2")
	lc := fx.legacyCase(`[{"name":"w1","op":"write-domain-policies","args":{"domain":"D"},"body":[],
		"observe":["status","read-raw:read-config-sets","decide:a","decide:b"],"onRefusal":"continue",
		"requests":[{"name":"a","operation":"READ"},{"name":"b","operation":"READ"}]},
		{"name":"w2","op":"write-domain-policies","args":{"domain":"D"},"body":[],
		"observe":["status","read-raw:read-config-sets","decide:c"],"onRefusal":"continue",
		"requests":[{"name":"c","operation":"READ"}]}]`)
	want := [][]string{{"sequence/legacy-case/a", "sequence/legacy-case/b"}, {"sequence/legacy-case/c"}}
	if diff := cmp.Diff(want, pointPaths(lc)); diff != "" {
		t.Errorf("points (-want +got):\n%s", diff)
	}
}

// The stand's own tenant holds the seeded fixtures, so a document no step
// wrote there is unknown rather than empty.
func TestLegacyExportCases_InTheStandsTenantAnUnwrittenDocumentIsUnknown(t *testing.T) {
	fx := newLegacyFixture(t)
	var f caseFile
	doc := `{"cases":[{"id":"legacy-case","resourceType":"PARITY_LEGACY","steps":[` + legacyWriteAndDecide + `]}]}`
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatal(err)
	}
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write")
	cases, err := legacyExportCases("legacy.json", f, fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || len(cases[0].points) != 0 {
		t.Fatalf("cases = %+v, want one case with no point", cases)
	}
	if got := cases[0].uncompared["sequence/legacy-case/check"]; !strings.HasPrefix(got, "no raw read of pips") {
		t.Errorf("uncompared reason = %q, want it to start with %q", got, "no raw read of pips")
	}
}

func TestLegacyExportCases_AStepInAnotherTenantAddsThatTenantsDocuments(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.status("write-domain-policies", "other", 201)
	fx.rawSets("write", map[string]any{"type": "SIMPLIFIED", "tenantId": "parity-legacy-case"})
	fx.rawSets("other", map[string]any{"type": "SIMPLIFIED", "tenantId": "parity-legacy-other"})
	lc := fx.legacyCase(`[{"name":"other","op":"write-domain-policies","args":{"domain":"D"},"body":[],"tenant":"parity-legacy-other",
		"observe":["status","read-raw:read-config-sets"],"onRefusal":"continue"},` + legacyWriteAndDecide + `]`)
	if len(lc.points) != 1 {
		t.Fatalf("points = %v, want one; uncompared: %v", pointPaths(lc), lc.uncompared)
	}
	if got := len(lc.points[0].policySets); got != 2 {
		t.Errorf("policy sets of the point = %d, want 2, one per tenant", got)
	}
	if !slices.Contains(lc.points[0].features, "tenant") {
		t.Errorf("features = %v, want tenant among them", lc.points[0].features)
	}
}

// An accepted write between the decision and a later raw read leaves the
// decision uncompared: the read shows the export after the write.
func TestLegacyExportCases_ARawReadAfterAnAcceptedWriteDoesNotCoverAnEarlierDecision(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.status("write-domain-policies", "again", 201)
	fx.rawSets("after")
	lc := fx.legacyCase(`[{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],"observe":["status","decide:check"],
		"onRefusal":"continue","requests":[{"name":"check","operation":"READ"}]},
		{"name":"again","op":"write-domain-policies","args":{"domain":"D"},"body":[],"onRefusal":"continue"},
		{"name":"after","op":"read-config-sets","observe":["read-raw:read-config-sets"]}]`)
	if len(lc.points) != 0 {
		t.Errorf("points = %v, want none", pointPaths(lc))
	}
	if got := lc.uncompared["sequence/legacy-case/check"]; !strings.HasPrefix(got, "no raw read of policySets") {
		t.Errorf("uncompared reason = %q, want it to start with %q", got, "no raw read of policySets")
	}
}

// A raw read the PAP refused shows nothing, and keeps an unwritten document
// from counting as empty.
func TestLegacyExportCases_ARefusedRawReadLeavesTheDecisionUncompared(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.write("pap-read-raw-v1", "before", model.PapReadRawOutcome{Status: 500, Body: "boom"})
	lc := fx.legacyCase(`[{"name":"before","op":"read-config-sets","observe":["read-raw:read-config-sets","decide:check"],
		"requests":[{"name":"check","operation":"READ"}]}]`)
	if len(lc.points) != 0 {
		t.Errorf("points = %v, want none", pointPaths(lc))
	}
	want := "no raw read of policySets at step before: tenant parity-legacy-case policySets (the raw read of before answered 500)"
	if got := lc.uncompared["sequence/legacy-case/check"]; got != want {
		t.Errorf("uncompared reason = %q, want %q", got, want)
	}
}

// A tenant another case of the file also runs in may hold what that case
// left, so a document no step of this case wrote there is unknown.
func TestLegacyExportCases_ATenantSharedWithAnotherCaseIsNotTakenAsEmpty(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write")
	var f caseFile
	doc := `{"tenant":"parity-legacy-shared","cases":[{"id":"other","resourceType":"PARITY_OTHER","steps":[]},
		{"id":"legacy-case","resourceType":"PARITY_LEGACY","steps":[` + legacyWriteAndDecide + `]}]}`
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatal(err)
	}
	cases, err := legacyExportCases("legacy.json", f, fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || cases[1].id != "legacy-case" || len(cases[1].points) != 0 {
		t.Fatalf("cases = %+v, want other and then legacy-case, with no point", cases)
	}
}

// An operation exportDocsWritten does not list may change either document.
func TestLegacyExportCases_AnUnlistedOperationChangesBothDocuments(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("assign-permissions", "assign", 200)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write")
	lc := fx.legacyCase(`[{"name":"assign","op":"assign-permissions","body":{},"onRefusal":"continue"},` + legacyWriteAndDecide + `]`)
	if got := lc.uncompared["sequence/legacy-case/check"]; !strings.HasPrefix(got, "no raw read of pips") {
		t.Errorf("uncompared reason = %q, want it to start with %q; points: %v", got, "no raw read of pips", pointPaths(lc))
	}
}

// A request that names a tenant of its own adds that tenant's documents to
// what the point has to show.
func TestLegacyExportCases_ARequestOfAnotherTenantNeedsThatTenantsDocuments(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write")
	lc := fx.legacyCase(`[{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],
		"observe":["status","read-raw:read-config-sets","decide:check"],"onRefusal":"continue",
		"requests":[{"name":"check","operation":"READ","tenantId":""}]}]`)
	if len(lc.points) != 0 {
		t.Errorf("points = %v, want none: the stand's tenant is not shown", pointPaths(lc))
	}
}

// An uncompared decision between two that see the same export splits them
// into two points, since the replay mounts the export again after it.
func TestLegacyExportCases_AnUncomparedDecisionSplitsAPoint(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write")
	lc := fx.legacyCase(`[{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],
		"observe":["status","read-raw:read-config-sets","decide:a","decide:b","decide:c"],"onRefusal":"continue",
		"requests":[{"name":"a","operation":"READ"},{"name":"b","operation":"READ","classifyBy":"/r"},{"name":"c","operation":"READ"}]}]`)
	want := [][]string{{"sequence/legacy-case/a"}, {"sequence/legacy-case/c"}}
	if diff := cmp.Diff(want, pointPaths(lc)); diff != "" {
		t.Errorf("points (-want +got):\n%s\nuncompared: %v", diff, lc.uncompared)
	}
}

// A request that names a tenant the export's elements do not belong to gets
// the feature tenant, and a point of its own apart from the decisions of the
// case's tenant, which do not.
func TestLegacyExportCases_ARequestOfATenantTheExportDoesNotHoldIsAPointWithTheTenantFeature(t *testing.T) {
	fx := newLegacyFixture(t)
	fx.status("write-domain-policies", "write", 201)
	fx.rawSets("write", map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "parity-legacy-case"})
	lc := fx.legacyCase(`[{"name":"write","op":"write-domain-policies","args":{"domain":"D"},"body":[],
		"observe":["status","read-raw:read-config-sets","decide:home","decide:spelled"],"onRefusal":"continue",
		"requests":[{"name":"home","operation":"READ"},{"name":"spelled","operation":"READ","tenantId":"PARITY-LEGACY-CASE"}]}]`)
	want := [][]string{{"sequence/legacy-case/home"}, {"sequence/legacy-case/spelled"}}
	if diff := cmp.Diff(want, pointPaths(lc)); diff != "" {
		t.Fatalf("points (-want +got):\n%s\nuncompared: %v", diff, lc.uncompared)
	}
	if diff := cmp.Diff([][]string{nil, {"tenant"}}, [][]string{lc.points[0].features, lc.points[1].features}); diff != "" {
		t.Errorf("features of the points (-want +got):\n%s", diff)
	}
}

func TestLegacyExportCases_ACaseThatReadsNoExportLeavesEveryDecisionUncompared(t *testing.T) {
	fx := newLegacyFixture(t)
	lc := fx.legacyCase(`[{"name":"probe","op":"read-domain-pips","args":{"domain":"D"},"observe":["read-raw:read-domain-pips","decide:check"],
		"requests":[{"name":"check","operation":"READ"}]}]`)
	if len(lc.points) != 0 || lc.uncompared["sequence/legacy-case/check"] == "" {
		t.Errorf("points = %v, uncompared = %v; want no point and check uncompared", pointPaths(lc), lc.uncompared)
	}
}

func TestExportFeatures_ListWhatTheConversionDropsInClassOrder(t *testing.T) {
	sets := []any{
		map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "a", "policies": []any{
			map[string]any{"rules": []any{map[string]any{"effect": "DENY", "condition": "subject.parityX == 'v'"}}},
		}},
		map[string]any{"type": "DEFAULT", "status": "ACTIVE", "tenantId": "a", "policySets": []any{
			map[string]any{"status": "INACTIVE"},
		}},
	}
	pips := []any{
		map[string]any{"pipType": "MAPPING", "tenantId": "b"},
		map[string]any{"pipType": "GENERAL", "beanName": "x"},
		map[string]any{"pipType": "GENERAL"},
		map[string]any{"name": "subject.untyped"},
	}
	before := []legacyEvent{{kind: "write", op: "customize-pips", args: map[string]any{"level": "PROJECT"}}}
	want := []string{"set-type:DEFAULT", "set-type:none", "status:nested:INACTIVE", "rule-effect:DENY",
		"customization:PROJECT", "tenant", "pip-kind:MAPPING", "pip-kind:GENERAL-beanName", "pip-kind:none",
		"undeclared-pip:parityX"}
	if diff := cmp.Diff(want, exportFeatures(sets, pips, before, "\x00")); diff != "" {
		t.Errorf("exportFeatures (-want +got):\n%s", diff)
	}
}

func TestExportFeatures_AnActiveSimplifiedExportOfOneTenantHasNone(t *testing.T) {
	sets := []any{map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "a", "policies": []any{
		map[string]any{"rules": []any{map[string]any{"effect": "ALLOW"}}},
	}}}
	pips := []any{map[string]any{"pipType": "TOKEN", "tenantId": "a"}}
	if got := exportFeatures(sets, pips, nil, "a"); len(got) != 0 {
		t.Errorf("exportFeatures = %v, want none", got)
	}
	if diff := cmp.Diff([]string{"simplified"}, featureFamilies(nil)); diff != "" {
		t.Errorf("featureFamilies(nil) (-want +got):\n%s", diff)
	}
}

// A request that names a tenant gets the feature tenant when an element of
// the export belongs to another tenant, its spelling in another case
// included; the agent does not read the tenant of the request.
func TestExportFeatures_ATenantOfTheRequestOtherThanTheExportsIsTheTenantFeature(t *testing.T) {
	sets := []any{map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "parity-t"}}
	for _, tc := range []struct {
		name    string
		request string
		want    []string
	}{
		{"the export's tenant", "parity-t", nil},
		{"no tenant of its own", "\x00", nil},
		{"the export's tenant in upper case", "PARITY-T", []string{"tenant"}},
		{"the export's tenant with a trailing space", "parity-t ", []string{"tenant"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, exportFeatures(sets, nil, nil, tc.request)); diff != "" {
				t.Errorf("exportFeatures(request %q) (-want +got):\n%s", tc.request, diff)
			}
		})
	}
}

// policyReading is an ACTIVE SIMPLIFIED set of one policy whose rule has the
// target target and the condition condition.
func policyReading(target, condition string) []any {
	return []any{map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "a", "policies": []any{
		map[string]any{"target": "operation == 'READ'", "rules": []any{
			map[string]any{"effect": "ALLOW", "target": target, "condition": condition},
		}},
	}}}
}

// A rule that reads a subject attribute which is neither one the agent
// resolves on its own (a token claim, the entitlements) nor named by a PIP of
// the export gets the feature undeclared-pip with that
// attribute; a PIP whose name starts with subject.<attribute> declares it.
func TestExportFeatures_ASubjectAttributeNoPIPDeclaresIsUndeclaredPIP(t *testing.T) {
	const roles = "subject.roles CONTAINS ANY 'ROLE_PARITY_READER'"
	for _, tc := range []struct {
		name              string
		target, condition string
		pips              []any
		want              []string
	}{
		{"an attribute with no PIP", roles, "subject.parityX == 'v' OR resource.a == 'y'", nil,
			[]string{"undeclared-pip:parityX"}},
		{"an attribute a PIP declares", roles, "subject.parityX == 'v' OR resource.a == 'y'",
			[]any{map[string]any{"name": "subject.parityX", "pipType": "TOKEN"}}, nil},
		{"a PIP of another attribute", roles, "subject.parityX == 'v'",
			[]any{map[string]any{"name": "subject.parityY", "pipType": "TOKEN"}}, []string{"undeclared-pip:parityX"}},
		{"a name with a dash", roles, "subject.parityR16S-dash == 'v'", nil, []string{"undeclared-pip:parityR16S-dash"}},
		{"a name that starts with a digit", roles, "subject.1parity == 'v'", nil, []string{"undeclared-pip:1parity"}},
		{"permissions with no MAPPING", roles, "subject.permissions CONTAINS 'P'", nil,
			[]string{"undeclared-pip:permissions"}},
		{"permissions with a PIP of a nested name", roles, "subject.permissions CONTAINS 'P'",
			[]any{map[string]any{"name": "subject.permissions.parity", "pipType": "TOKEN"}}, nil},
		{"the token claims", roles, "subject.id == resource.owner AND subject.name == 'n'", nil, nil},
		{"the entitlements", roles, "resource.id IN subject.entitledResources.of('R').as('id')", nil, nil},
		{"an attribute in a quoted literal", roles, "resource.a == 'subject.parityX'", nil, nil},
		{"an attribute in a double-quoted literal", roles, `resource.a == "subject.parityX"`, nil, nil},
		{"a resource path that contains subject", roles, "resource.subject.parityX == 'v'", nil, nil},
		{"a placeholder in a quoted literal", roles, "resource.owner == '${subject.parityX}'", nil,
			[]string{"undeclared-pip:parityX"}},
		{"an attribute in the target", "subject.parityX == 'v'", "", nil, []string{"undeclared-pip:parityX"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, exportFeatures(policyReading(tc.target, tc.condition), tc.pips, nil, "a")); diff != "" {
				t.Errorf("exportFeatures(condition %q) (-want +got):\n%s", tc.condition, diff)
			}
		})
	}
}

// The reads that count are those of a policy's own target and condition as
// well as of its rules, in a SIMPLIFIED set at any depth; a set of another
// type is classified by its type alone.
func TestExportFeatures_UndeclaredPIPReadsOfPoliciesAndNestedSimplifiedSets(t *testing.T) {
	reading := func(typ string) map[string]any {
		return map[string]any{"type": typ, "status": "ACTIVE", "tenantId": "a", "policies": []any{
			map[string]any{"condition": "subject.parityX == 'v'"},
		}}
	}
	for _, tc := range []struct {
		name string
		sets []any
		want []string
	}{
		{"a policy-level condition", []any{reading("SIMPLIFIED")}, []string{"undeclared-pip:parityX"}},
		{"a nested SIMPLIFIED set", []any{map[string]any{"type": "SIMPLIFIED", "status": "ACTIVE", "tenantId": "a",
			"policySets": []any{reading("SIMPLIFIED")}}}, []string{"undeclared-pip:parityX"}},
		{"a DEFAULT set", []any{reading("DEFAULT")}, []string{"set-type:DEFAULT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, exportFeatures(tc.sets, nil, nil, "a")); diff != "" {
				t.Errorf("exportFeatures (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLegacyClass(t *testing.T) {
	p := legacyExportPoint{features: []string{"set-type:DEFAULT", "tenant"}}
	for _, tc := range []struct {
		name   string
		p      legacyExportPoint
		loaded bool
		want   string
	}{
		{"an export the agent did not load", p, false, "pull-failure"},
		{"a loaded export with features", p, true, "set-type:DEFAULT"},
		{"a loaded export without features", legacyExportPoint{}, true, "agent"},
		{"a tenant feature before an undeclared PIP", legacyExportPoint{features: []string{"tenant", "undeclared-pip:x"}}, true, "tenant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := legacyClass(tc.p, tc.loaded); got != tc.want {
				t.Errorf("legacyClass(loaded=%v) = %q, want %q", tc.loaded, got, tc.want)
			}
		})
	}
}

func TestAcceptedLegacyDifference(t *testing.T) {
	for _, tc := range []struct {
		name       string
		class      string
		wrongAllow bool
		want       bool
	}{
		{"a regular set of a named type", "set-type:DEFAULT", false, true},
		{"a regular set that allows what the golden denies", "set-type:DEFAULT", true, false},
		{"a class with no decision", "tenant", false, false},
		{"an undeclared PIP that denies", "undeclared-pip:parityX", false, true},
		{"an undeclared PIP that allows what the golden denies", "undeclared-pip:parityX", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := acceptedLegacyDifference(tc.class, tc.wrongAllow); got != tc.want {
				t.Errorf("acceptedLegacyDifference(%q, %v) accepted = %v, want %v", tc.class, tc.wrongAllow, got, tc.want)
			}
		})
	}
}

func TestWithUniqueGeneratedIDs_GivesEachMaskedIDItsOwnUUID(t *testing.T) {
	in := []any{map[string]any{"policySetId": generatedUUID, "policies": []any{map[string]any{"policyId": generatedUUID}}}}
	out := withUniqueGeneratedIDs(in, "seed")
	set := out[0].(map[string]any)
	setID, policyID := set["policySetId"].(string), set["policies"].([]any)[0].(map[string]any)["policyId"].(string)
	if !wholeUUID.MatchString(setID) || !wholeUUID.MatchString(policyID) || setID == policyID {
		t.Errorf("ids = %q, %q; want two distinct UUIDs", setID, policyID)
	}
	if in[0].(map[string]any)["policySetId"] != generatedUUID {
		t.Errorf("input policySetId = %v, want %q kept", in[0].(map[string]any)["policySetId"], generatedUUID)
	}
}

func TestLegacyExportDocuments_AppendTheCanarySet(t *testing.T) {
	p := legacyExportPoint{policySets: []any{map[string]any{"name": "case set"}}, pips: []any{}}
	ps, pips, err := legacyExportDocuments(p, "PARITY_EXPORT_CANARY_7")
	if err != nil {
		t.Fatal(err)
	}
	var sets struct {
		PolicySets []map[string]any `json:"policySets"`
	}
	if err := json.Unmarshal(ps, &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets.PolicySets) != 2 || sets.PolicySets[1]["target"] != "resourceType == 'PARITY_EXPORT_CANARY_7'" {
		t.Errorf("policySets = %s, want the case set and then the canary of PARITY_EXPORT_CANARY_7", ps)
	}
	if string(pips) != `{"pips":[]}` {
		t.Errorf("pips = %s, want {\"pips\":[]}", pips)
	}
	if len(p.policySets) != 1 {
		t.Errorf("the point's policy sets = %v, want the case set alone", p.policySets)
	}
}

func TestLegacyGoldenPaths_TakeTheGoldenElseItsOrderClassVariants(t *testing.T) {
	fx := newLegacyFixture(t)
	dir := Meta(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME).GoldenDir
	fx.write(dir, "plain", true)
	fx.write(dir, "classed-when-the-pip-was-read", true)
	fx.write(dir, "classed-when-the-pip-was-skipped", true)
	for _, tc := range []struct {
		subCase string
		want    []string
	}{
		{"sequence/legacy-case/plain", []string{dir + "/sequence/legacy-case/plain.json"}},
		{"sequence/legacy-case/classed", []string{
			dir + "/sequence/legacy-case/classed-when-the-pip-was-read.json",
			dir + "/sequence/legacy-case/classed-when-the-pip-was-skipped.json",
		}},
		{"sequence/legacy-case/absent", nil},
	} {
		if diff := cmp.Diff(tc.want, legacyGoldenPaths(fx.root, PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, tc.subCase)); diff != "" {
			t.Errorf("legacyGoldenPaths(%s) (-want +got):\n%s", tc.subCase, diff)
		}
	}
}

func TestLegacyExportReport_ListsWrongAllowsFirstAndCountsPerFamilyAndClass(t *testing.T) {
	results := []legacyResult{
		{exportResult: exportResult{Path: "a", Class: "agent", Families: []string{"simplified"}, Verdict: verdictMatch}},
		{exportResult: exportResult{Path: "b", Class: "agent", Families: []string{"simplified"}, Verdict: verdictDiffers}},
		{exportResult: exportResult{Path: "c", Class: "tenant", Families: []string{"tenant"}, Verdict: verdictDiffers}, WrongAllow: true},
		{exportResult: exportResult{Path: "e", Class: "undeclared-pip:x", Families: []string{"simplified"}, Verdict: verdictAccepted}, WrongAllow: true},
	}
	report := legacyExportReport(results, map[string]string{"d": "no raw read of pips at step s: tenant t pips"})
	// The columns are padded; compare with single spaces.
	flat := strings.Join(strings.Fields(report), " ")
	for _, want := range []string{
		"4 goldens compared, 1 decisions without a legacy export",
		"family simplified match 1, accepted 1, differs 1, skipped 0",
		"class undeclared-pip:x differs 1, wrong allows 1",
		"class agent differs 1, wrong allows 0",
		"class tenant differs 1, wrong allows 1",
		"uncompared 1: no raw read of pips",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	if wa, d := strings.Index(report, "WRONG ALLOW c"), strings.Index(report, "DIFFERS b"); wa < 0 || d < 0 || wa > d {
		t.Errorf("report lists the wrong allow c after the difference b, or omits one:\n%s", report)
	}
	if strings.Contains(report, " e (") {
		t.Errorf("report lists the accepted wrong allow e among the differences:\n%s", report)
	}
}

// Every case file under testdata/cases builds into part A's cases, so a
// change of the case format or of the goldens that breaks the walk fails
// without a stand.
func TestAllLegacyExportCases_ReadTheRecordedRawReads(t *testing.T) {
	cases, err := allLegacyExportCases("testdata/golden")
	if err != nil {
		t.Fatal(err)
	}
	points := 0
	for _, lc := range cases {
		points += len(lc.points)
	}
	if points == 0 {
		t.Fatalf("no point with a legacy export among %d cases with raw reads", len(cases))
	}
}
