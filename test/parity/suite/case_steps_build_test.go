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

package paritysuite

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"authz-agent/test/parity/suite/model"

	"github.com/google/go-cmp/cmp"
)

// The expected calls follow the binding table testdata/pap-operations.json and
// the rules stepSpec states; they are written out, not computed by the code
// under test.

func TestStepCall(t *testing.T) {
	cases := []struct {
		name       string
		step       stepSpec
		want       *papCall
		wantGolden ParityEndpointID
	}{
		{"a write fills the path parameter and sends the body with the placeholders replaced",
			stepSpec{Op: "write-domain-policies", Args: map[string]any{"domain": "PARITY_{{resourceType}}"},
				Body: json.RawMessage(`[{"resourceType": "{{resourceType}}"}]`)},
			&papCall{method: http.MethodPut, path: "/access/v1/simplifiedPolicies/domainPolicies/PARITY_RT", query: url.Values{},
				body: []any{map[string]any{"resourceType": "RT"}}},
			PSUITE_LOAD_SIMPLIFIED_POLICIES},
		{"a variant binding sends its own method, and its status goes under pap-status-v1",
			stepSpec{Op: "write-domain-pips", Binding: "patch", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`)},
			&papCall{method: http.MethodPatch, path: "/access/v1/simplifiedPolicies/domainPIPs/D", query: url.Values{}, body: []any{}},
			PSUITE_PAP_STATUS},
		{"a query argument is sent as a parameter, a boolean as true or false",
			stepSpec{Op: "delete-set-customization", Args: map[string]any{"id": "s/1", "level": "PROJECT", "recursive": false}},
			&papCall{method: http.MethodDelete, path: "/access/v1/config/customization/policySet/s%2F1",
				query: url.Values{"level": {"PROJECT"}, "recursive": {"false"}}},
			PSUITE_DELETE_CUSTOMIZATION},
		{"a step without a body sends none",
			stepSpec{Op: "change-set-status", Args: map[string]any{"id": "s", "transition": "archive"}},
			&papCall{method: http.MethodPost, path: "/access/v1/policySets/s/archive", query: url.Values{}},
			PSUITE_PAP_STATUS},
		{"a JSON null body is sent as null, not as no body",
			stepSpec{Op: "import-sets", Body: json.RawMessage(`null`)},
			&papCall{method: http.MethodPost, path: "/access/v1/config/import", query: url.Values{}, body: json.RawMessage("null")},
			PSUITE_PAP_STATUS},
		{"a read step sends no call of its own",
			stepSpec{Op: "read-config-sets"}, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, golden, err := stepCall(tc.step, "RT")
			if err != nil {
				t.Fatalf("stepCall(%s): %v", tc.step.Op, err)
			}
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(papCall{})); diff != "" {
				t.Errorf("stepCall(%s) mismatch (-want +got):\n%s", tc.step.Op, diff)
			}
			if golden != tc.wantGolden {
				t.Errorf("stepCall(%s) golden = %s, want %s", tc.step.Op, Meta(golden).GoldenDir, Meta(tc.wantGolden).GoldenDir)
			}
		})
	}
}

// Every callable binding of the table records its status under a golden kind
// the catalog knows, so a step of any operation can run; the table comes from
// another repository and could name a kind this suite has no endpoint for.
func TestPAPOperations_EveryCallableWriteHasAGoldenEndpoint(t *testing.T) {
	for op, o := range papOperations() {
		for name, b := range o.Bindings {
			if o.Kind == "read" || strings.Contains(b.Path, "*") {
				continue
			}
			if _, ok := goldenEndpoint(b.Golden); !ok {
				t.Errorf("%s/%s files its status under %q, which no endpoint of the catalog has", op, name, b.Golden)
			}
		}
	}
}

func TestReadCall_SendsTheReadOperationsGETWithTheStepsArguments(t *testing.T) {
	got, err := readCall("read-domain-pips", map[string]any{"domain": "D", "other": "x"}, "RT")
	if err != nil {
		t.Fatal(err)
	}
	want := papCall{method: http.MethodGet, path: "/access/v1/simplifiedPolicies/domainPIPs/D", query: url.Values{}}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("readCall(read-domain-pips) mismatch (-want +got):\n%s", diff)
	}
}

// Each case breaks one rule of stepSpec, and caseStepProblems names it; the
// valid step beside them reports nothing, so a problem comes from the broken
// rule and not from the rest of the step.
func TestCaseStepProblems(t *testing.T) {
	write := func(edit func(*stepSpec)) stepSpec {
		st := stepSpec{Name: "s", Op: "write-domain-policies", Args: map[string]any{"domain": "D"},
			Body: json.RawMessage(`[]`), Observe: []string{"status", "decide:here"}, Requests: []requestSpec{{Name: "here"}}}
		edit(&st)
		return st
	}
	cases := []struct {
		name string
		step stepSpec
		want string // a part of the one problem reported; empty for none
	}{
		{"a valid write", write(func(*stepSpec) {}), ""},
		{"an unknown operation", write(func(st *stepSpec) { st.Op = "write-nothing" }), `operation "write-nothing"`},
		{"an unknown binding", write(func(st *stepSpec) { st.Binding = "post-twice" }), `binding "post-twice"`},
		{"a decision as a step", stepSpec{Name: "s", Op: "decide-resource"}, "a request of decide: observes"},
		{"an argument the binding does not take", write(func(st *stepSpec) { st.Args["level"] = "PROJECT" }), "argument level"},
		{"a value outside the argument's values",
			stepSpec{Name: "s", Op: "change-set-status", Args: map[string]any{"id": "x", "transition": "retire"}}, "none of activate"},
		{"a missing path argument", write(func(st *stepSpec) { delete(st.Args, "domain") }), "path parameter domain"},
		{"a write that does not observe status first", write(func(st *stepSpec) { st.Observe = []string{"decide:here", "status"} }), "observes decide:here first"},
		{"a decision with no such request", write(func(st *stepSpec) { st.Observe = []string{"status", "decide:there", "decide:here"} }), "decide:there"},
		{"a request no observation sends", write(func(st *stepSpec) { st.Observe = []string{"status"} }), "request here"},
		{"two reads, one golden", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read:read-domain-pips", "read:read-config-pips", "decide:here"}
		}), "read twice"},
		{"an unknown observation", write(func(st *stepSpec) { st.Observe = []string{"status", "decide:here", "log"} }), `"log"`},
		{"status on a read", stepSpec{Name: "s", Op: "read-config-sets", Observe: []string{"status"}}, "status on the read"},
		{"a body on a read", stepSpec{Name: "s", Op: "read-config-sets", Body: json.RawMessage(`[]`)}, "body, onRefusal, or binding"},
		{"a binding on a read", stepSpec{Name: "s", Op: "read-config-sets", Binding: "get"}, "body, onRefusal, or binding"},
		{"error-class after another observation", write(func(st *stepSpec) {
			st.Observe = []string{"status", "decide:here", "error-class"}
		}), `observes "error-class" at 3`},
		{"error-class with an argument", write(func(st *stepSpec) {
			st.Observe = []string{"status", "error-class:x", "decide:here"}
		}), `observes "error-class:x" at 2`},
		{"error-class right after status", write(func(st *stepSpec) {
			st.Observe = []string{"status", "error-class", "decide:here"}
		}), ""},
		{"an unknown onRefusal", write(func(st *stepSpec) { st.OnRefusal = "retry" }), `onRefusal "retry"`},
		{"a read through a write", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read:write-domain-pips", "decide:here"}
		}), "no read operation"},
		{"a raw read through a write", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read-raw:write-domain-pips", "decide:here"}
		}), "no read operation"},
		{"a narrowed read and a raw read", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read:read-domain-pips", "read-raw:read-config-sets", "decide:here"}
		}), ""},
		{"two raw reads, one golden", write(func(st *stepSpec) {
			st.Observe = []string{"status", "read-raw:read-domain-pips", "read-raw:read-config-sets", "decide:here"}
		}), "read-raw twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseStepProblems(caseSpec{ID: "c"}, tc.step)
			switch {
			case tc.want == "" && len(got) > 0:
				t.Errorf("caseStepProblems = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("caseStepProblems = %q, want one problem containing %q", got, tc.want)
			}
		})
	}
}

// A tenant is read only on a case with steps and no sets and on a step of
// such a case, and such a case reads nothing but its steps, pins, and tenant.
// A step's tenant differs from the tenant its case or its file names; the
// stand's tenant is not known offline.
func TestCaseFileProblems_SequenceCasesAndTenants(t *testing.T) {
	step := []stepSpec{{Name: "read", Op: "read-config-sets"}}
	stepIn := func(tenant string) []stepSpec {
		return []stepSpec{{Name: "read", Op: "read-config-sets", Tenant: stringOf(tenant)}}
	}
	sets := []setSpec{{Key: "s"}}
	cases := []struct {
		name string
		file caseFile
		want string
	}{
		{"a sequence case in a tenant of its own",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: step}}}, ""},
		{"a file tenant over sequence cases",
			caseFile{Tenant: stringOf("t"), Cases: []caseSpec{{ID: "c", Steps: step}}}, ""},
		{"a tenant on a case with sets",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Sets: sets}}}, "runs in a tenant"},
		{"a file tenant beside a case without steps",
			caseFile{Tenant: stringOf("t"), Cases: []caseSpec{{ID: "c", Condition: "true"}}}, "runs in a tenant"},
		{"a sequence case with a condition",
			caseFile{Cases: []caseSpec{{ID: "c", Condition: "true", Steps: step}}}, "does not read"},
		{"a sequence case with no step",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{}}}}, "empty list"},
		{"steps beside customize",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Steps: step, Customize: []customizeStep{{Name: "x", OmitLevel: true}}}}},
			"both steps and customize"},
		{"two steps with one name",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: append(step, step...)}}}, "names another step"},
		{"an empty tenant",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf(""), Steps: step}}}, "is no tenant"},
		{"a step in another tenant than its case's",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: stepIn("t2")}}}, ""},
		{"a step in another tenant than the stand's",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: stepIn("t2")}}}, ""},
		{"a step tenant in a case with sets",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Steps: stepIn("t2")}}}, "only a step of a case with steps and no sets"},
		{"an empty step tenant",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: stepIn("")}}}, "is no tenant"},
		{"a step tenant that is the case's",
			caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: stepIn("t")}}}, "runs in already"},
		{"a step tenant that is the file's",
			caseFile{Tenant: stringOf("t"), Cases: []caseSpec{{ID: "c", Steps: stepIn("t")}}}, "runs in already"},
		{"a step named as the case's upload",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Steps: []stepSpec{{Name: "upload-1", Op: "read-config-sets"}}}}},
			"records a golden under too"},
		{"a sequence step named as an upload of a case with sets",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "declare-the-domain", Op: "read-config-sets"}}}}}, ""},
		{"a step named as a request of the case",
			caseFile{Cases: []caseSpec{{ID: "c", Sets: sets, Requests: []requestSpec{{Name: "read"}}, Steps: step}}},
			"records a golden under too"},
		{"a sequence step's request with user-management fields",
			caseFile{Cases: []caseSpec{{ID: "c", UserManagement: map[string]PipStubResponse{DefaultRoute: {}}, Steps: []stepSpec{
				{Name: "d", Op: "read-config-sets", Observe: []string{"decide:read"}, Requests: []requestSpec{
					{Name: "read", UserID: stringOf("u"), UserManagementCalls: true,
						UserManagement: map[string]PipStubResponse{"/users/u": {}}}}}}}}}, ""},
		{"a sequence step's request with a user-management route that is no path",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{
				{Name: "d", Op: "read-config-sets", Observe: []string{"decide:read"}, Requests: []requestSpec{
					{Name: "read", UserManagement: map[string]PipStubResponse{"users": {}}}}}}}}},
			`case c request read pins the user-management route "users"`},
		{"a pip-call on a route nothing pins",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x"}}}}}}, "nothing pins"},
		{"a pip-call beside the case's own pipCalls",
			caseFile{Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}, Cases: []caseSpec{{ID: "c", Sets: sets, PIPCalls: "/api/v1/pip/x",
				Steps: []stepSpec{{Name: "r", Op: "read-config-sets", Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x"}}}}}},
			"counts the calls of the whole case"},
		{"a pip-call beside a request that clears the log",
			caseFile{Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}, Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r",
				Op: "read-config-sets", Observe: []string{"read:read-config-sets", "pip-call:/api/v1/pip/x", "decide:d"},
				Requests: []requestSpec{{Name: "d", PIPCalls: "/api/v1/pip/x"}}}}}}},
			"clears the call log"},
		{"a request pinned by a request decided before it",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "decide:pins", "decide:reads"},
				Requests: []requestSpec{{Name: "reads", ClassifyBy: "/api/v1/pip/x"},
					{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}}}}}}}}, ""},
		{"a pip-call on a route a request decided before it pins",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe:  []string{"read:read-config-sets", "decide:pins", "pip-call:/api/v1/pip/x"},
				Requests: []requestSpec{{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}}}}}}}}, ""},
		{"two requests of a step with one name",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe:  []string{"read:read-config-sets", "decide:d"},
				Requests: []requestSpec{{Name: "d"}, {Name: "d", Subject: "m2m"}}}}}}}, "two requests named d"},
		{"a request decided before the request that pins its route",
			caseFile{Cases: []caseSpec{{ID: "c", Steps: []stepSpec{{Name: "r", Op: "read-config-sets",
				Observe: []string{"read:read-config-sets", "decide:reads", "decide:pins"},
				Requests: []requestSpec{{Name: "pins", Pins: map[string]PipStubResponse{"/api/v1/pip/x": {}}},
					{Name: "reads", ClassifyBy: "/api/v1/pip/x"}}}}}}}, "nothing pins"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseFileProblems(tc.file)
			switch {
			case tc.want == "" && len(got) > 0:
				t.Errorf("caseFileProblems = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("caseFileProblems = %q, want one problem containing %q", got, tc.want)
			}
		})
	}
}

func TestNarrowStepRead_DropsTheEnvelopeStampsAndListsTheTenantsOfTheKeptElements(t *testing.T) {
	body := `{"hash": "h", "lastModificationTimestamp": 1, "policySets": [
		{"name": "c1 s", "tenantId": "t1", "createdWhen": 5},
		{"name": "other", "tenantId": "default"}]}`
	got := narrowStepRead(http.StatusOK, []byte(body), []string{"c1"})
	want := &model.PapReadOutcome{Status: http.StatusOK,
		Body:        map[string]any{"policySets": []any{map[string]any{"name": "c1 s", "tenantId": "t1"}}},
		KeptTenants: []string{"t1"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("narrowStepRead mismatch (-want +got):\n%s", diff)
	}
}

func TestNarrowStepRead_ListsNoTenantWhenTheMarkersKeepNone(t *testing.T) {
	body := `{"pips": [{"name": "other", "tenantId": "default"}]}`
	got := narrowStepRead(http.StatusOK, []byte(body), []string{"c1"})
	text, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"status":200,"body":{"pips":[]}}`; string(text) != want {
		t.Errorf("narrowStepRead = %s, want %s", text, want)
	}
}

func TestNarrowStepRead_TakesTheTenantsFromWhatTheGoldenKeeps(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"a list body", http.StatusOK,
			`[{"name": "c1 a", "tenantId": "t1"}, {"name": "b", "tenantId": "t2"}]`,
			`{"status":200,"body":[{"name":"c1 a","tenantId":"t1"}],"keptTenants":["t1"]}`},
		{"a tenantId nested in a kept element", http.StatusOK,
			`{"policySets": [{"name": "c1 s", "policies": [{"tenantId": "t3"}]}, {"name": "b", "tenantId": "t2"}]}`,
			`{"status":200,"body":{"policySets":[{"name":"c1 s","policies":[{"tenantId":"t3"}]}]},"keptTenants":["t3"]}`},
		{"a member of an object body that is no list", http.StatusOK,
			`{"tenantId": "t4", "pips": [{"name": "b", "tenantId": "t2"}]}`,
			`{"status":200,"body":{"pips":[],"tenantId":"t4"},"keptTenants":["t4"]}`},
		{"a number in a kept element", http.StatusOK,
			`{"pips": [{"name": "c1 n", "priority": 2, "tenantId": "t1"}]}`,
			`{"status":200,"body":{"pips":[{"name":"c1 n","priority":2,"tenantId":"t1"}]},"keptTenants":["t1"]}`},
		{"an error answer", http.StatusNotFound,
			`{"tenantId": "t1"}`,
			`{"status":404}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, err := json.Marshal(narrowStepRead(tc.status, []byte(tc.body), []string{"c1"}))
			if err != nil {
				t.Fatal(err)
			}
			if string(text) != tc.want {
				t.Errorf("narrowStepRead = %s, want %s", text, tc.want)
			}
		})
	}
}

// A golden recorded before keptTenants lists the tenants of the whole body
// under tenants; it has to differ from what the suite records now, so that
// it is recorded again rather than passing with the member dropped.
func TestPapReadOutcome_AGoldenWithTheFormerTenantsDiffersFromANewRead(t *testing.T) {
	golden := &model.PapReadOutcome{}
	if err := json.Unmarshal([]byte(`{"status":200,"body":{"pips":[]},"tenants":["default"]}`), golden); err != nil {
		t.Fatal(err)
	}
	read := narrowStepRead(http.StatusOK, []byte(`{"pips": [{"name": "b", "tenantId": "default"}]}`), []string{"c1"})
	if cmp.Equal(golden, read) {
		t.Errorf("a golden with tenants %v equals the read %+v", golden.Tenants, read)
	}
}

func TestRawStepRead(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		tenant string
		want   *model.PapReadRawOutcome
	}{
		{"the elements of the case's tenant and those without a tenant", http.StatusOK,
			`{"pips": [{"name": "a", "tenantId": "t1"}, {"name": "b", "tenantId": "t2"}, {"name": "c"}, {"name": "d", "tenantId": "t1"}]}`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK, Body: map[string]any{"pips": []any{
				map[string]any{"name": "a", "tenantId": "t1"}, map[string]any{"name": "c"}, map[string]any{"name": "d", "tenantId": "t1"}}}}},
		{"an array body without the elements of another tenant, null and non-object elements kept", http.StatusOK,
			`[{"tenantId": "t2"}, {"tenantId": "t1"}, {"tenantId": null}, 5]`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK, Body: []any{float64(5), map[string]any{"tenantId": "t1"}, map[string]any{"tenantId": nil}}}},
		{"an empty tenant keeps every tenant", http.StatusOK, `[{"tenantId": "t2"}, {"tenantId": "t1"}]`, "",
			&model.PapReadRawOutcome{Status: http.StatusOK, Body: []any{map[string]any{"tenantId": "t1"}, map[string]any{"tenantId": "t2"}}}},
		{"an object without its envelope stamps, nested members kept", http.StatusOK,
			`{"hash": "h", "lastModificationTimestamp": 1, "timestamp": "now", "policySets": [{"hash": "x", "tenantId": "t1"}]}`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK,
				Body: map[string]any{"policySets": []any{map[string]any{"hash": "x", "tenantId": "t1"}}}}},
		{"the sets sorted, each without its write stamps and with its rules sorted", http.StatusOK,
			`{"policySets": [
				{"name": "b", "createdWhen": 5, "lastModifiedWhen": 6, "createdBy": "u", "lastModifiedBy": "u",
				 "rules": [{"name": "r2", "createdWhen": 7}, {"name": "r1"}]},
				{"name": "a", "other": "kept"}]}`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK, Body: map[string]any{"policySets": []any{
				map[string]any{"name": "a", "other": "kept"},
				map[string]any{"name": "b", "rules": []any{map[string]any{"name": "r1"}, map[string]any{"name": "r2"}}}}}}},
		{"an array whole, sorted by the text of its elements without their stamps", http.StatusOK,
			`[{"name": "b"}, {"name": "a", "lastModifiedWhen": 1}]`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK, Body: []any{map[string]any{"name": "a"}, map[string]any{"name": "b"}}}},
		{"a text body as text", http.StatusNotFound, `no such domain`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusNotFound, Body: "no such domain"}},
		{"a text error body without the framework code and the server's address", http.StatusNotFound,
			`PARITY000404: no resource at https://pap.internal:8443/api/v9/x`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusNotFound, Body: "no resource at /api/v9/x"}},
		{"a JSON error body without the framework code and the server's address", http.StatusNotFound,
			`{"timestamp": "now", "message": "PARITY000404: no resource at http://10.0.0.7:8080/api/v9/x"}`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusNotFound, Body: map[string]any{"message": "no resource at /api/v9/x"}}},
		{"an accepted body keeps a URL and a code-shaped text", http.StatusOK,
			`[{"url": "http://pip-mock:8090/a", "name": "PARITY000404: x"}]`, "t1",
			&model.PapReadRawOutcome{Status: http.StatusOK,
				Body: []any{map[string]any{"url": "http://pip-mock:8090/a", "name": "PARITY000404: x"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, rawStepRead(tc.status, []byte(tc.body), tc.tenant)); diff != "" {
				t.Errorf("rawStepRead(%d, %s, %q) mismatch (-want +got):\n%s", tc.status, tc.body, tc.tenant, diff)
			}
		})
	}
}

func TestErrorOutcome(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   *model.PapErrorOutcome
	}{
		{"an accepted call records no body", http.StatusOK, `{"x": 1}`, &model.PapErrorOutcome{Status: http.StatusOK}},
		{"a JSON error body without its timestamp", http.StatusBadRequest, `{"timestamp": "now", "message": "bad"}`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: map[string]any{"message": "bad"}}},
		{"a text error body as text", http.StatusConflict, `exists`, &model.PapErrorOutcome{Status: http.StatusConflict, Body: "exists"}},
		{"a text error body without its reference chain", http.StatusBadRequest, `bad: a == (through reference chain: x.Y["condition"])`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: "bad: a =="}},
		{"a JSON error body without the reference chain of its message", http.StatusBadRequest,
			`{"message": "bad (through reference chain: x.Y[\"condition\"])", "status": 400}`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: map[string]any{"message": "bad", "status": float64(400)}}},
		{"a text error body without the server's class names", http.StatusBadRequest,
			"value of type `com.example.web.ParityWidgetDto` refused",
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: "value of type `<redacted>` refused"}},
		{"a JSON array body without class names", http.StatusBadRequest, `["see ParityWidgetEntity", 5]`,
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: []any{"see <redacted>", float64(5)}}},
		{"a JSON error body without class names at any depth", http.StatusConflict,
			`{"errors": [{"detail": "net.example.Store refused"}], "message": "see ParityWidgetEntity"}`,
			&model.PapErrorOutcome{Status: http.StatusConflict,
				Body: map[string]any{"errors": []any{map[string]any{"detail": "<redacted> refused"}}, "message": "see <redacted>"}}},
		{"a JSON error body without its source position tail and quoted type names", http.StatusBadRequest,
			"{\"message\": \"Cannot coerce `acme.ParityText` (`ParityCoercionConfig`)\\n at [Source: REDACTED (`acme.ParityFeature.X` disabled); line: 1, column: 9]\"}",
			&model.PapErrorOutcome{Status: http.StatusBadRequest, Body: map[string]any{"message": "Cannot coerce `<redacted>` (`<redacted>`)"}}},
		{"a text error body without its framework code and the server's address", http.StatusNotFound,
			`PARITY001234: no resource for https://pap.internal:8443/api/v9/x`,
			&model.PapErrorOutcome{Status: http.StatusNotFound, Body: "no resource for /api/v9/x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, errorOutcome(tc.status, []byte(tc.body))); diff != "" {
				t.Errorf("errorOutcome(%d, %s) mismatch (-want +got):\n%s", tc.status, tc.body, diff)
			}
		})
	}
}

// The PAP stores an element written without a UUID in its id member under a
// UUID of its own; a read records that id as generatedUUID, so that it does
// not differ from one stand to the next, and keeps every id the case wrote.
func TestGeneratedIDsMask(t *testing.T) {
	const written = "00000000-0000-0000-0000-00000000000a"
	const generated = "3f1c2b4a-0000-4000-8000-0000000000b1"
	cases := []struct {
		name, sent, read, want string
	}{
		{"a set written with a null policySetId",
			`[{"policySetId": null, "name": "s", "policies": []}]`,
			`{"policySets": [{"name": "s", "policySetId": "` + generated + `"}]}`,
			`{"policySets":[{"name":"s","policySetId":"<generated UUID>"}]}`},
		{"a set written without a policySetId",
			`[{"name": "s", "policies": []}]`,
			`{"policySets": [{"name": "s", "policySetId": "` + generated + `"}]}`,
			`{"policySets":[{"name":"s","policySetId":"<generated UUID>"}]}`},
		{"a policy written with a blank policyId",
			`[{"policySetId": "` + written + `", "name": "s", "policies": [{"policyId": " ", "name": "p", "rules": []}]}]`,
			`[{"name": "s", "policySetId": "` + written + `", "policies": [{"name": "p", "policyId": "` + generated + `"}]}]`,
			`[{"name":"s","policies":[{"name":"p","policyId":"<generated UUID>"}],"policySetId":"` + written + `"}]`},
		{"a rule written without a ruleId",
			`[{"name": "p", "policyId": "` + written + `", "rules": [{"name": "r"}]}]`,
			`[{"name": "r", "ruleId": "` + generated + `"}]`,
			`[{"name":"r","ruleId":"<generated UUID>"}]`},
		{"a rule written with a ruleId that is no UUID",
			`[{"name": "p", "policyId": "` + written + `", "rules": [{"ruleId": "parity-r", "name": "r"}]}]`,
			`[{"name": "r", "ruleId": "` + generated + `"}]`,
			`[{"name":"r","ruleId":"<generated UUID>"}]`},
		{"an id the case wrote with spaces around it",
			`[{"policySetId": " ` + written + ` ", "name": "s", "policies": []}]`,
			`[{"name": "s", "policySetId": "` + written + `"}]`,
			`[{"name": "s", "policySetId": "` + written + `"}]`},
		{"an element of another name",
			`[{"policySetId": null, "name": "s", "policies": []}]`,
			`[{"name": "simplified", "policySetId": "` + generated + `"}]`,
			`[{"name": "simplified", "policySetId": "` + generated + `"}]`},
		{"a customization path of UUIDs",
			`[{"policySetId": "` + written + `/", "name": "s", "policies": []}]`,
			`[{"name": "s", "policySetId": "` + generated + `"}]`,
			`[{"name": "s", "policySetId": "` + generated + `"}]`},
		{"a case whose ids are all UUIDs",
			`[{"policySetId": "` + written + `", "name": "s", "policies": [{"policyId": "` + written + `", "name": "p", "rules": []}]}]`,
			`[{"name": "s", "policySetId": "` + generated + `"}]`,
			`[{"name": "s", "policySetId": "` + generated + `"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := caseGeneratedIDs([]any{json.RawMessage(tc.sent)})
			var got, want any
			if err := json.Unmarshal(ids.mask([]byte(tc.read)), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mask(%s) after sending %s mismatch (-want +got):\n%s", tc.read, tc.sent, diff)
			}
		})
	}
}

// The PAP names, in a "duplicates in rules" refusal, whichever of the policies
// with the rule it met second, which differs between stands; the refusal
// records duplicatingPolicy in its place when a body of the case wrote the
// rule into more than one policy, and keeps the ruleId and the policySetId.
func TestDuplicatedRulesMask(t *testing.T) {
	const (
		set   = "00000000-0000-0000-0000-00000000000a"
		p1    = "00000000-0000-0000-0000-0000000000b1"
		p2    = "00000000-0000-0000-0000-0000000000b2"
		rule  = "00000000-0000-0000-0000-0000000000c1"
		other = "00000000-0000-0000-0000-0000000000c2"
	)
	policy := func(id string, rules ...string) string {
		var list []string
		for _, r := range rules {
			list = append(list, `{"name": "r", "ruleId": "`+r+`"}`)
		}
		return `{"name": "` + id + `", "policyId": "` + id + `", "rules": [` + strings.Join(list, ", ") + `]}`
	}
	sets := func(policies ...string) string {
		return `[{"name": "s", "policySetId": "` + set + `", "policies": [` + strings.Join(policies, ", ") + `]}]`
	}
	refusal := func(rule, policy string) string {
		return `{"message": "Next duplicates were found:\nduplicates in rules: [\n\t{RuleId=` + rule +
			`, policyId=` + policy + `, policySetId=` + set + `}]\n"}`
	}
	cases := []struct {
		name string
		sent []string
		body string
		want string
	}{
		{"a rule in two policies of one body",
			[]string{sets(policy(p1, rule), policy(p2, rule))},
			refusal(rule, p2), refusal(rule, duplicatingPolicy)},
		{"a rule in upper case in the refusal",
			[]string{sets(policy(p1, rule), policy(p2, rule))},
			refusal(strings.ToUpper(rule), p1), refusal(strings.ToUpper(rule), duplicatingPolicy)},
		{"a rule twice in one policy",
			[]string{sets(policy(p1, rule, rule), policy(p2, other))},
			refusal(rule, p1), refusal(rule, p1)},
		{"a rule in one policy of each of two bodies",
			[]string{sets(policy(p1, rule)), sets(policy(p2, rule))},
			refusal(rule, p2), refusal(rule, p2)},
		{"an entry of another rule",
			[]string{sets(policy(p1, rule), policy(p2, rule))},
			refusal(other, p2), refusal(other, p2)},
		{"another message",
			[]string{sets(policy(p1, rule), policy(p2, rule))},
			`{"message": "{RuleId=` + rule + `, policyId=` + p2 + `}"}`,
			`{"message": "{RuleId=` + rule + `, policyId=` + p2 + `}"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []any
			for _, sent := range tc.sent {
				bodies = append(bodies, json.RawMessage(sent))
			}
			if got := string(caseDuplicatedRules(bodies).mask([]byte(tc.body))); got != tc.want {
				t.Errorf("mask(%s) after sending %v\n got %s\nwant %s", tc.body, tc.sent, got, tc.want)
			}
		})
	}
}

// A case file of round 44 or later records the body of a 400 or 409 answer;
// an earlier one, and a file outside a round directory, record the status
// alone, so that its goldens stay as they were.
func TestRecordsErrorBodies(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"round44/spell-data.json", true},
		{"round45/tenant-fresh.json", true},
		{"round100/x.json", true},
		{"round43/open-m2m-level.json", false},
		{"round9/x.json", false},
		{"early/x.json", false},
		{"round44.json", false},
	}
	for _, tc := range cases {
		if got := recordsErrorBodies(tc.name); got != tc.want {
			t.Errorf("recordsErrorBodies(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// Only a 400 or 409 answer of a file that records bodies gets a message, shaped
// as errorOutcome shapes the body of an error-class observation.
func TestRefusalMessage(t *testing.T) {
	cases := []struct {
		name   string
		record bool
		status int
		body   string
		want   any
	}{
		{"a 400 text body", true, http.StatusBadRequest, `bad: a ==`, "bad: a =="},
		{"a 409 JSON body without its timestamp", true, http.StatusConflict, `{"timestamp": "now", "message": "exists"}`,
			map[string]any{"message": "exists"}},
		{"a 400 empty body", true, http.StatusBadRequest, ``, ""},
		{"a 404 body", true, http.StatusNotFound, `missing`, nil},
		{"a 500 body", true, http.StatusInternalServerError, `boom`, nil},
		{"an accepted call", true, http.StatusOK, `true`, nil},
		{"a 400 body of a file that records none", false, http.StatusBadRequest, `bad`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, refusalMessage(tc.record, tc.status, []byte(tc.body))); diff != "" {
				t.Errorf("refusalMessage(%t, %d, %s) mismatch (-want +got):\n%s", tc.record, tc.status, tc.body, diff)
			}
		})
	}
}

// A recorded error body keeps the PAP's reason for a refusal and loses the
// names of the server's classes, packages, stack frames, and exceptions, which
// must not reach the published goldens. A qualified JDK name stays; a bare
// exception name is replaced, JDK or not. The inputs follow the shape of
// Spring and Jackson errors; the names in them are made up.
func TestWithoutServerNames(t *testing.T) {
	cases := []struct {
		name, message, want string
	}{
		{"a Spring validation message",
			"Validation failed for argument [0] in public org.example.http.Response<java.lang.Void> " +
				"com.example.pap.web.ParityWidgetController.upload(java.util.List<com.example.pap.dto.ParityWidgetDto>): " +
				"[Field error in object 'parityWidgetDto' on field 'name': rejected value [null]; " +
				"codes [NotNull.parityWidgetDto.name,NotNull.name]; default message [must not be null]]",
			"Validation failed for argument [0] in public <redacted><java.lang.Void> " +
				"<redacted>(java.util.List<<redacted>>): " +
				"[Field error in object 'parityWidgetDto' on field 'name': rejected value [null]; " +
				"codes [NotNull.parityWidgetDto.name,NotNull.name]; default message [must not be null]]"},
		{"a Jackson MismatchedInputException",
			"Cannot deserialize value of type `java.util.ArrayList<com.example.pap.dto.ParityWidgetDto>` " +
				"from Object value (token `JsonToken.START_OBJECT`)",
			"Cannot deserialize value of type `<redacted>` from Object value (token `<redacted>`)"},
		{"a Jackson InvalidFormatException with its path",
			"JSON parse error: Cannot deserialize value of type `com.example.pap.model.EffectKind` from String \"PERMITX\": " +
				"not one of the values accepted for Enum class: [ALLOW, DENY] (through reference chain: " +
				"java.util.ArrayList[0]->com.example.pap.dto.ParityRuleDto[\"effect\"])",
			"JSON parse error: Cannot deserialize value of type `<redacted>` from String \"PERMITX\": " +
				"not one of the values accepted for Enum class: [ALLOW, DENY]"},
		{"a bare class name in backticks and quotes",
			"Cannot construct instance of `ParityWidgetEntity` (no Creators, like default constructor, exist); " +
				"'ParityWidgetMapper' failed",
			"Cannot construct instance of `<redacted>` (no Creators, like default constructor, exist); '<redacted>' failed"},
		{"a wrapped cause with stack frames",
			"Request processing failed: com.example.pap.ParityWidgetException: Expression [resource.a ==]: " +
				"Invalid expression; nested exception is java.lang.IllegalStateException: parser stopped\n" +
				"\tat com.example.pap.Parser.parse(Parser.java:42)\n\tat com.example.pap.Parser$Visitor.visit(Unknown Source)",
			"Request processing failed: <redacted>: Expression [resource.a ==]: " +
				"Invalid expression; nested exception is java.lang.IllegalStateException: parser stopped\n" +
				"\tat <redacted>\n\tat <redacted>"},
		{"a source position and a nested class alone", "thrown at Parser.java:42 by Parser$Visitor",
			"thrown at <redacted> by <redacted>"},
		{"a bare exception name", "ParityWidgetException after NullPointerException",
			"<redacted> after <redacted>"},
		{"a package without a class", "no bean in com.example.pap", "no bean in <redacted>"},
		{"a package under io", "scanned io.example.pap.web", "scanned <redacted>"},
		{"a class under another root", "dto.ParityThing and acme.pap.ParityWidget failed", "<redacted> and <redacted> failed"},
		{"a java segment inside a server name", "com.example.java.ParityWidgetDto and org.acme.javax.dto.ParityThing refused",
			"<redacted> and <redacted> refused"},
		{"a JDK name under javax", "javax.validation.ConstraintViolationException: name", "javax.validation.ConstraintViolationException: name"},
		{"a cause line and frames of every form",
			"Caused by: com.example.pap.ParityWidgetException: bad\n\tat com.example.Bar.<init>(Bar.java:10)\n" +
				"\tat com.example.Baz.run(Baz.kt:7)\n\tat com.example.Qux.call(Native Method)\n\tat com.example.Gen.go(<generated>)",
			"Caused by: <redacted>: bad\n\tat <redacted>\n\tat <redacted>\n\tat <redacted>\n\tat <redacted>"},
		{"a proxy class and a Kotlin position", "ParityWidget$$EnhancerByProxy$$1a2b failed at Bar.kt:12",
			"<redacted> failed at <redacted>"},
		{"an attribute without the resource prefix", "owner.Id == subject.id", "<redacted> == subject.id"},
		{"plain words", "Bad Request: Error in the policy, the Service is busy",
			"Bad Request: Error in the policy, the Service is busy"},
		{"a JSON path", "no value at $.items[0].a, $['k'].OwnerService, $.store.Book, or $.items[*].owner.Id",
			"no value at $.items[0].a, $['k'].OwnerService, $.store.Book, or $.items[*].owner.Id"},
		{"attribute names and operator words",
			"resource.a == 'y' OR subject.parityAllowed IS NULL AND resource.o.Id NOT IN ('v') OR resource.o.OwnerService IS NULL",
			"resource.a == 'y' OR subject.parityAllowed IS NULL AND resource.o.Id NOT IN ('v') OR resource.o.OwnerService IS NULL"},
		{"a placeholder, a version, and a header name", "${subject.id} on 6.1.6 in X-Parity-Request",
			"${subject.id} on 6.1.6 in X-Parity-Request"},
		{"PARITY names", "the domain PARITY_ISOLATED_B has no PIP for PARITY_PAYMENT",
			"the domain PARITY_ISOLATED_B has no PIP for PARITY_PAYMENT"},
		{"a URL of the stub", "call to http://pip-mock:8090/api/v1/pip/s44-sent failed",
			"call to http://pip-mock:8090/api/v1/pip/s44-sent failed"},
		{"a source position tail", "Unexpected end of input\n at [Source: REDACTED (`acme.ParityFeature.PARITY_SOURCE` disabled); line: 1, column: 27]",
			"Unexpected end of input"},
		{"a source position tail before a reference chain",
			"bad value at [Source: (String)\"[1]\"; line: 3, column: 1] (through reference chain: x.Y[0])",
			"bad value"},
		{"a qualified type in backticks", "Cannot coerce `acme.util.ParityText` to `acme.lang.ParityNumber[]`",
			"Cannot coerce `<redacted>` to `<redacted>`"},
		{"a qualified type with nested type parameters in double quotes",
			`expected "acme.util.ParityMap<acme.lang.ParityText, acme.util.ParityList<acme.ParityUuid>>" here`,
			`expected "<redacted>" here`},
		{"a constant of a type in backticks", "unexpected token (`ParityToken.VALUE_STRING`)",
			"unexpected token (`<redacted>`)"},
		{"a method in a null-pointer message", `Cannot invoke "acme.ParityText.size()" because "parity" is null; "ParityList.get(int)" failed`,
			`Cannot invoke "<redacted>" because "parity" is null; "<redacted>" failed`},
		{"a bare class name in backticks", "coercion of `ParityCoercionConfig` refused; use `parityHint` or `PARITY_MODE`",
			"coercion of `<redacted>` refused; use `parityHint` or `PARITY_MODE`"},
		{"quoted attributes, paths, and lower-case dotted values", "'resource.o.Id', \"subject.parityX\", `$.a.B`, and 'parity.a.b' are kept",
			"'resource.o.Id', \"subject.parityX\", `$.a.B`, and 'parity.a.b' are kept"},
		{"a framework code and the server's own URL",
			"PARITY001234: no handler for http://pap.internal:8080/api/v9/parity?tenant_id=x",
			"no handler for /api/v9/parity?tenant_id=x"},
		{"a code-shaped text inside a message", "the name PARITY001234: x at http://pip-mock:8090/a is taken",
			"the name PARITY001234: x at http://pip-mock:8090/a is taken"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withoutServerNames(tc.message); got != tc.want {
				t.Errorf("withoutServerNames(%q)\n got %q\nwant %q", tc.message, got, tc.want)
			}
		})
	}
}
