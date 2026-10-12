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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-agent/test/parity/suite/model"
)

func TestGoldenRow_TakesTheLongestGoldenDirectory(t *testing.T) {
	cases := []struct {
		path    string
		id      ParityEndpointID
		subCase string
	}{
		{"check-resource-v1/tenant/t2-other-tenant-policy.json", PSUITE_ROW_2_CHECK_RESOURCE_V1, "tenant/t2-other-tenant-policy"},
		{"check-resource-v1-outcome/sequence/p45-fresh-domain/here.json", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, "sequence/p45-fresh-domain/here"},
		{"check-filter-v1-outcome/regular/c/filter.json", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/c/filter"},
	}
	for _, tc := range cases {
		id, sub, ok := goldenRow(tc.path)
		if !ok || id != tc.id || sub != tc.subCase {
			t.Errorf("goldenRow(%q) = %d, %q, %v; want %d, %q, true", tc.path, id, sub, ok, tc.id, tc.subCase)
		}
	}
	if _, _, ok := goldenRow("no-such-kind/x.json"); ok {
		t.Errorf(`goldenRow("no-such-kind/x.json") found a row, want none`)
	}
}

func TestDecisionOutcome_BuildsTheGoldenShapeOfEachRow(t *testing.T) {
	ids := []string{"b", "a"}
	byOp := map[string][]string{"READ": {"b", "a"}}
	cases := []struct {
		name   string
		id     ParityEndpointID
		status int
		body   string
		want   any
	}{
		{"an allowed check", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, 200, "true", &model.CheckResourceOutcome{Status: 200, Decision: true}},
		{"a refused check denies", PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, 400, `{"message":"x"}`, &model.CheckResourceOutcome{Status: 400}},
		{"a plain check", PSUITE_ROW_2_CHECK_RESOURCE_V1, 200, "false", ptr(false)},
		{"bulk ids are sorted", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, 200, `["b","a"]`, &model.CheckResourceBulkOutcome{Status: 200, Allowed: &[]string{"a", "b"}}},
		{"bulk operations ids are sorted", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, 200, `{"READ":["b","a"]}`, &model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: &map[string][]string{"READ": {"a", "b"}}}},
		{"a refused filter has no result", PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, 500, "boom", &model.FilterOutcome{Status: 500}},
		{"a plain bulk keeps the wire order", PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, 200, `["b","a"]`, &ids},
		{"plain bulk operations keep the wire order", PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, 200, `{"READ":["b","a"]}`, &byOp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decisionOutcome(tc.id, tc.status, []byte(tc.body))
			if err != nil {
				t.Fatalf("decisionOutcome(%d, %d, %s): %v", tc.id, tc.status, tc.body, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("decisionOutcome(%d, %d, %s) = %s, want %s", tc.id, tc.status, tc.body, show(got), show(tc.want))
			}
		})
	}
}

func TestDecisionOutcome_RefusesAFailedPlainRow(t *testing.T) {
	for _, id := range []ParityEndpointID{PSUITE_ROW_6_CHECK_FILTER_V1, PSUITE_ROW_2_CHECK_RESOURCE_V1} {
		if got, err := decisionOutcome(id, 500, []byte("false")); err == nil {
			t.Errorf("decisionOutcome(%d, 500) = %s, want an error: the plain row has no status to carry", id, show(got))
		}
	}
}

func TestParseTokenLabel(t *testing.T) {
	cases := []struct {
		label string
		want  tokenLabel
		ok    bool
	}{
		{"parity/m2m:parity-m2m", tokenLabel{realm: "parity", client: "parity-m2m"}, true},
		{"parity-mt-b/user:mt-b@parity-end-user", tokenLabel{realm: "parity-mt-b", user: "mt-b", client: "parity-end-user"}, true},
		{"Bearer eyJ", tokenLabel{}, false},
	}
	for _, tc := range cases {
		got, ok := parseTokenLabel(tc.label)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseTokenLabel(%q) = %+v, %v; want %+v, %v", tc.label, got, ok, tc.want, tc.ok)
		}
	}
}

func TestLoadedAfterMount_WantsAWholePullAfterTheMountThenTheNext(t *testing.T) {
	call := func(paths ...string) []PipStubCall {
		out := make([]PipStubCall, len(paths))
		for i, p := range paths {
			out[i] = PipStubCall{Path: p}
		}
		return out
	}
	cases := []struct {
		name  string
		calls []PipStubCall
		want  bool
	}{
		{"nothing fetched", call(), false},
		{"a pull that started before the mount", call(exportPIPsPath), false},
		{"a pull after the mount, still converting", call(exportPolicySetsPath, exportPIPsPath), false},
		{"the next pull started", call(exportPolicySetsPath, exportPIPsPath, exportPolicySetsPath), true},
		{"a pull that fetched the previous policy sets, then one still converting", call(exportPIPsPath, exportPolicySetsPath), false},
		{"a pull that fetched the previous policy sets, then a whole pull", call(exportPIPsPath, exportPolicySetsPath, exportPIPsPath, exportPolicySetsPath), true},
	}
	for _, tc := range cases {
		if got := loadedAfterMount(tc.calls); got != tc.want {
			t.Errorf("%s: loadedAfterMount(%s) = %v, want %v", tc.name, callPaths(tc.calls), got, tc.want)
		}
	}
}

func TestReadExportBundle_RefusesAnotherVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.json"), `{"version": 99, "functions": []}`)
	if _, err := readExportBundle(dir); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Errorf("readExportBundle(version 99) = %v, want an error naming the version", err)
	}
}

func TestBundleExports_JoinsTheElementsOfAnExport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "elements.json"), `{"s1":{"name":"one"},"p1":{"name":"subject.x"}}`)
	writeFile(t, filepath.Join(dir, "exports", "x.json"), `{"policySets":["s1","s1"],"pips":["p1"]}`)
	b, err := openBundleExports(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps, pips, err := b.documents("x")
	if err != nil {
		t.Fatal(err)
	}
	if string(ps) != `{"policySets":[{"name":"one"},{"name":"one"}]}` || string(pips) != `{"pips":[{"name":"subject.x"}]}` {
		t.Errorf("documents(x) = %s, %s", ps, pips)
	}
	writeFile(t, filepath.Join(dir, "exports", "y.json"), `{"policySets":["missing"],"pips":[]}`)
	if _, _, err := b.documents("y"); err == nil {
		t.Errorf("documents(y) with an unknown element id succeeded, want an error")
	}
}

// fakeStand is the agent, its export source, and the PIP stub of one replay:
// the agent answers each check with the decision the test sets for the
// mounted export.
type fakeStand struct {
	mu      sync.Mutex
	mounted string
	answers map[string]string // mounted policySets text -> check body
	pins    []string
	sent    []*http.Request
}

func (f *fakeStand) Mount(_ context.Context, policySets, _ json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mounted = string(policySets)
	return nil
}

func (f *fakeStand) agent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sent = append(f.sent, r)
		_, _ = io.WriteString(w, f.answers[f.mounted])
	})
}

func (f *fakeStand) stub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.pins = append(f.pins, r.URL.Path+" "+string(body))
		f.mu.Unlock()
		if r.URL.Path == "/pip-stub/calls" {
			_, _ = io.WriteString(w, "[]")
		}
	})
}

// replayBundle replays fn against a fake stand whose agent answers allowed
// under the export "allows" and denied under "denies" and the empty export,
// with the goldens given.
func replayBundle(t *testing.T, fn exportFunction, goldens map[string]string) ([]exportResult, *fakeStand) {
	t.Helper()
	results, stand := replayFunctions(t, []exportFunction{fn}, goldens)
	return results[0], stand
}

// replayFunctions replays fns in order against one fake stand, as
// replayBundle does, and returns the verdicts of each function.
func replayFunctions(t *testing.T, fns []exportFunction, goldens map[string]string) ([][]exportResult, *fakeStand) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "elements.json"), `{"a":{"name":"allows"},"d":{"name":"denies"}}`)
	writeFile(t, filepath.Join(dir, "exports", "allows.json"), `{"policySets":["a"],"pips":[]}`)
	writeFile(t, filepath.Join(dir, "exports", "denies.json"), `{"policySets":["d"],"pips":[]}`)
	goldenDir := filepath.Join(dir, "golden")
	for path, text := range goldens {
		writeFile(t, filepath.Join(goldenDir, path), text)
	}
	exports, err := openBundleExports(dir)
	if err != nil {
		t.Fatal(err)
	}
	stand := &fakeStand{answers: map[string]string{
		`{"policySets":[{"name":"allows"}]}`: "true", `{"policySets":[{"name":"denies"}]}`: "false",
		string(emptyExportPolicySets): "false"}}
	agent, stub := httptest.NewServer(stand.agent()), httptest.NewServer(stand.stub())
	t.Cleanup(agent.Close)
	t.Cleanup(stub.Close)
	r := &exportReplayer{
		exports: exports, baseURL: agent.URL, source: stand, client: agent.Client(), goldenDir: goldenDir,
		stubs: func(string) *PipController { return NewPipController(stub.URL) },
		tokens: func(label string) (string, error) {
			if strings.HasPrefix(label, "absent/") {
				return "", fmt.Errorf("%w: absent", errNoRealm)
			}
			return "token-of-" + label, nil
		},
	}
	var all [][]exportResult
	for _, fn := range fns {
		results, err := r.replay(context.Background(), fn)
		if err != nil {
			t.Fatalf("replay %s: %v", fn.Test, err)
		}
		all = append(all, results)
	}
	return all, stand
}

func check(label string) exportEvent {
	return exportEvent{Ev: "http", Method: "POST", Path: "/access/v1/check/resource", Query: "tenant_id=default",
		Headers: map[string]string{"Authorization": label}, Body: json.RawMessage(`{"type":"T","operation":"READ"}`)}
}

func golden(path, class string, agent string) exportEvent {
	return exportEvent{Ev: "golden", Path: path, Class: class, Status: "pinned", Agent: json.RawMessage(agent)}
}

const outcomePath = "check-resource-v1-outcome/sequence/c/"

func TestExportReplayer_JudgesEachGoldenByTheMountedExport(t *testing.T) {
	allowed, denied := `{"status":200,"decision":true}`, `{"status":200,"decision":false}`
	cases := []struct {
		name   string
		export string
		class  string
		agent  string
		golden string
		want   exportVerdict
	}{
		{"the agent answers as legacy", "allows", "agree", allowed, allowed, verdictMatch},
		{"the agent differs in a class nobody accepted", "allows", "tenant", allowed, denied, verdictDiffers},
		{"the agent differs as the accepted class predicts", "denies", "set-type", denied, allowed, verdictAccepted},
		{"the agent differs in an accepted class, but not as predicted", "denies", "set-type", allowed, allowed, verdictDiffers},
		{"the agent allows what legacy denies, as an accepted class predicts", "allows", "set-type", allowed, denied, verdictDiffers},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn := exportFunction{Test: "TestX", Events: []exportEvent{
				{Ev: "export", ID: tc.export}, check("parity/m2m:parity-m2m"), golden(outcomePath+"q.json", tc.class, tc.agent)}}
			results, _ := replayBundle(t, fn, map[string]string{outcomePath + "q.json": tc.golden})
			if len(results) != 1 || results[0].Verdict != tc.want {
				t.Fatalf("results = %+v, want one %s", results, tc.want)
			}
		})
	}
}

// A function whose decisions come before any export the agent loaded, as when
// the pull of its first export fails, is judged under the empty export, not
// under the export the function before it mounted.
func TestExportReplayer_StartsEachFunctionFromTheEmptyExport(t *testing.T) {
	allowed, denied := `{"status":200,"decision":true}`, `{"status":200,"decision":false}`
	before := exportFunction{Test: "TestBefore", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"), golden(outcomePath+"a.json", "agree", "")}}
	after := exportFunction{Test: "TestAfter", Events: []exportEvent{
		check("parity/m2m:parity-m2m"), golden(outcomePath+"d.json", "agree", "")}}
	results, _ := replayFunctions(t, []exportFunction{before, after},
		map[string]string{outcomePath + "a.json": allowed, outcomePath + "d.json": denied})
	if got := results[1]; len(got) != 1 || got[0].Verdict != verdictMatch {
		t.Errorf("TestAfter after TestBefore: results = %+v, want one match with the decision of the empty export", got)
	}
}

func TestExportReplayer_SendsTheRecordedRequestWithMintedTokens(t *testing.T) {
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "pin", Mock: "http://localhost:28191", Path: "/api/v1/pip/x", Responses: []PipStubResponse{{StatusCode: 200, Body: []string{"m"}}}},
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"),
		golden(outcomePath+"q.json", "agree", `{"status":200,"decision":true}`)}}
	_, stand := replayBundle(t, fn, map[string]string{outcomePath + "q.json": `{"status":200,"decision":true}`})
	if len(stand.sent) != 1 {
		t.Fatalf("the agent received %d requests, want 1", len(stand.sent))
	}
	req := stand.sent[0]
	if got := req.Header.Get("Authorization"); got != "Bearer token-of-parity/m2m:parity-m2m" {
		t.Errorf("Authorization = %q, want the token minted for the label", got)
	}
	if req.URL.RawQuery != "tenant_id=default" || req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request query %q, Content-Type %q; want tenant_id=default and application/json", req.URL.RawQuery, req.Header.Get("Content-Type"))
	}
	if len(stand.pins) == 0 || !strings.Contains(stand.pins[0], "/api/v1/pip/x") {
		t.Errorf("stub calls = %q, want the pin of /api/v1/pip/x first", stand.pins)
	}
}

func TestExportReplayer_PassesAClassifiedGoldenOnEitherVariant(t *testing.T) {
	read, skipped := outcomePath+"q-when-the-pip-was-read.json", outcomePath+"q-when-the-pip-was-skipped.json"
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"),
		golden(read, "agree", ""), golden(skipped, "agree", "")}}
	results, _ := replayBundle(t, fn, map[string]string{
		read: `{"status":200,"decision":false}`, skipped: `{"status":200,"decision":true}`})
	if len(results) != 1 || results[0].Verdict != verdictMatch {
		t.Errorf("results = %+v, want one match: the skip variant holds the agent's answer", results)
	}
}

func TestExportReplayer_FailsAClassifiedGoldenWithAVariantTheSuiteCannotRead(t *testing.T) {
	read, skipped := outcomePath+"q-when-the-pip-was-read.json", outcomePath+"q-when-the-pip-was-skipped.json"
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"),
		golden(read, "agree", ""), golden(skipped, "agree", "")}}
	results, _ := replayBundle(t, fn, map[string]string{read: `{"status":200,"decision":true}`})
	if len(results) != 1 || results[0].Verdict != verdictDiffers {
		t.Errorf("results = %+v, want one difference: the skip variant is missing although the read variant matches", results)
	}
}

func TestExportReplayer_FailsAGoldenTheSuiteCannotRead(t *testing.T) {
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"),
		golden(outcomePath+"missing.json", "agree", `{"status":200,"decision":true}`)}}
	results, _ := replayBundle(t, fn, map[string]string{})
	if len(results) != 1 || results[0].Verdict != verdictDiffers || !strings.Contains(results[0].Detail, "cannot read") {
		t.Errorf("results = %+v, want one golden that differs because the suite cannot read it", results)
	}
}

func TestExportReplayer_SkipsATokenOfARealmTheStandLacks(t *testing.T) {
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("absent/m2m:parity-m2m"),
		golden(outcomePath+"q.json", "tenant", `{"status":200,"decision":true}`)}}
	results, _ := replayBundle(t, fn, map[string]string{outcomePath + "q.json": `{"status":200,"decision":false}`})
	if len(results) != 1 || results[0].Verdict != verdictSkipped ||
		!strings.Contains(results[0].Detail, "no such realm") {
		t.Errorf("results = %+v, want one skipped golden naming the realm", results)
	}
}

func ptr[T any](v T) *T { return &v }

func show(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLabelTokens_RefusesWhatTheStandCannotMint(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostForm.Get("username") {
		case "mt-a":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
		case "mt-b":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Account disabled"}`)
		case "parity-other":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"unknown_error"}`)
		}
	}))
	defer idp.Close()
	lt := newLabelTokens(Config{IDPBaseURL: idp.URL + "/auth/realms/parity", M2MClientID: "parity-m2m",
		EndUserClientID: "parity-end-user"})
	if _, err := lt.token("parity/user:parity-reader@parity-end-user"); err == nil || errors.Is(err, errNoIdentity) {
		t.Errorf("token(a user the identity provider fails on with 500) = %v, want an error that is not errNoIdentity", err)
	}
	if _, err := lt.token("parity/user:parity-other@parity-end-user"); err == nil || errors.Is(err, errNoIdentity) {
		t.Errorf("token(a refused client, 401 invalid_client) = %v, want an error that is not errNoIdentity", err)
	}
	if _, err := lt.token("parity/user:mt-b@parity-end-user"); !errors.Is(err, errNoIdentity) {
		t.Errorf("token(400 invalid_grant) = %v, want errNoIdentity", err)
	}
	if err := checkKnownUser(lt); err == nil {
		t.Errorf("checkKnownUser with an identity provider that fails on parity-reader = nil, want an error")
	}
	down := newLabelTokens(Config{IDPBaseURL: "http://127.0.0.1:1/auth/realms/parity", EndUserClientID: "parity-end-user"})
	if _, err := down.token("parity/user:mt-a@parity-end-user"); err == nil || errors.Is(err, errNoIdentity) {
		t.Errorf("token(an unreachable identity provider) = %v, want an error that is not errNoIdentity", err)
	}
	if _, err := lt.token("parity-mt-b/user:mt-b@parity-end-user"); !errors.Is(err, errNoRealm) {
		t.Errorf("token(a realm the stand lacks) = %v, want errNoRealm", err)
	}
	if _, err := lt.token("parity/m2m:no-such-client"); err == nil || !strings.Contains(err.Error(), "no-such-client") {
		t.Errorf("token(an unknown client) = %v, want an error naming the client", err)
	}
	if _, err := lt.token("parity/user:mt-a@parity-end-user"); !errors.Is(err, errNoIdentity) {
		t.Errorf("token(a user the realm cannot issue a token for) = %v, want errNoIdentity", err)
	}
	if _, err := lt.token("Bearer x"); err == nil {
		t.Errorf("token(not a label) succeeded, want an error")
	}
}

func TestRealmOf_IgnoresATrailingSlash(t *testing.T) {
	for base, want := range map[string]string{
		"http://idp:8080/auth/realms/parity":   "parity",
		"http://idp:8080/auth/realms/parity/":  "parity",
		"http://idp:8080/auth/realms/parity//": "parity",
	} {
		if got := realmOf(base); got != want {
			t.Errorf("realmOf(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestStubFor_SendsTheEntitlementsPinsToTheirStub(t *testing.T) {
	pip, ea := NewPipController("http://pip"), NewPipController("http://ea")
	stubs := stubFor(pip, ea)
	for mock, want := range map[string]*PipController{
		"http://localhost:28192": ea, "http://entitlements-mock:8080": ea, "http://localhost:28191": pip,
	} {
		if got := stubs(mock); got != want {
			t.Errorf("stubFor(%s) = the stub at %s, want the one at %s", mock, got.baseURL, want.baseURL)
		}
	}
}

func TestStubExportSource_MountsAndWaitsForTheNextPull(t *testing.T) {
	var mu sync.Mutex
	var configured string
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/pip-stub/configure":
			body, _ := io.ReadAll(r.Body)
			configured = string(body)
		case "/pip-stub/calls":
			// The agent's next pull shows up on the third poll.
			polls++
			calls := `[]`
			if polls >= 3 {
				calls = `[{"path":"` + exportPIPsPath + `"},{"path":"` + exportPolicySetsPath + `"},{"path":"` + exportPIPsPath + `"},{"path":"` + exportPolicySetsPath + `"}]`
			}
			_, _ = io.WriteString(w, calls)
		}
	}))
	defer srv.Close()
	src := &stubExportSource{stub: NewPipController(srv.URL), timeout: 5 * time.Second, poll: time.Millisecond}
	if err := src.Mount(context.Background(), json.RawMessage(`{"policySets":[]}`), json.RawMessage(`{"pips":[]}`)); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if !strings.Contains(configured, exportPolicySetsPath) || !strings.Contains(configured, exportPIPsPath) {
		t.Errorf("configured routes = %s, want both export paths", configured)
	}
	if polls < 3 {
		t.Errorf("Mount returned after %d polls, before the agent's next pull", polls)
	}
}

func TestStubExportSource_ReportsTheCallsItSawOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pip-stub/calls" {
			_, _ = io.WriteString(w, `[{"path":"`+exportPIPsPath+`"}]`)
		}
	}))
	defer srv.Close()
	src := &stubExportSource{stub: NewPipController(srv.URL), timeout: 20 * time.Millisecond, poll: time.Millisecond}
	err := src.Mount(context.Background(), json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), exportPIPsPath) {
		t.Errorf("Mount = %v, want a timeout that lists the calls seen", err)
	}
}

func TestExportReport_CountsVerdictsPerFamilyAndListsTenantDifferencesFirst(t *testing.T) {
	got := exportReport([]exportResult{
		{Path: "a.json", Class: "set-type", Families: []string{"policy-set"}, Verdict: verdictDiffers},
		{Path: "b.json", Class: "tenant", Families: []string{"tenant"}, Verdict: verdictDiffers},
		{Path: "c.json", Class: "agree", Families: []string{"policy-set"}, Verdict: verdictMatch},
		{Path: "d.json", Class: "agree", Verdict: verdictSkipped},
	})
	for _, want := range []string{
		"export-fed agent: 4 goldens",
		"family none           match 0, accepted 0, differs 0, skipped 1",
		"family policy-set     match 1, accepted 0, differs 1, skipped 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("exportReport lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "DIFFERS b.json") > strings.Index(got, "DIFFERS a.json") {
		t.Errorf("exportReport lists the tenant difference after another:\n%s", got)
	}
}

func TestExportReplayer_FailsAGoldenOfAnUnknownKind(t *testing.T) {
	fn := exportFunction{Test: "TestX", Events: []exportEvent{
		{Ev: "export", ID: "allows"}, check("parity/m2m:parity-m2m"), golden("no-such-kind/c/q.json", "agree", "")}}
	results, _ := replayBundle(t, fn, map[string]string{"no-such-kind/c/q.json": "true"})
	if len(results) != 1 || results[0].Verdict != verdictDiffers {
		t.Errorf("results = %+v, want one difference: no row reads that golden directory", results)
	}
}

func TestExportRunProblem_NamesARunThatComparedNothing(t *testing.T) {
	cases := []struct {
		name    string
		results []exportResult
		want    bool
	}{
		{"no golden selected", nil, true},
		{"every golden skipped", []exportResult{{Verdict: verdictSkipped}, {Verdict: verdictSkipped}}, true},
		{"one golden compared", []exportResult{{Verdict: verdictSkipped}, {Verdict: verdictDiffers}}, false},
	}
	for _, tc := range cases {
		if got := exportRunProblem(tc.results); (got != "") != tc.want {
			t.Errorf("%s: exportRunProblem = %q, want a problem: %v", tc.name, got, tc.want)
		}
	}
}

func TestGrantsMore_TakesTheAnswerThatAllowsMoreThanEveryVariant(t *testing.T) {
	ids := func(xs ...string) *model.CheckResourceBulkOutcome {
		return &model.CheckResourceBulkOutcome{Status: 200, Allowed: &xs}
	}
	ops2 := func(m map[string][]string) *model.CheckResourcesResponse {
		return &model.CheckResourcesResponse{Decision: m}
	}
	opsOutcome := func(m map[string][]string) *model.CheckResourceBulkOperationsOutcome {
		return &model.CheckResourceBulkOperationsOutcome{Status: 200, Decision: &m}
	}
	filter := func(r string) *model.FilterOutcome {
		return &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{CalculationResult: r}}
	}
	cases := []struct {
		name   string
		actual any
		wants  []any
		want   bool
	}{
		{"an allow where legacy denies", &model.CheckResourceOutcome{Status: 200, Decision: true}, []any{&model.CheckResourceOutcome{Status: 200}}, true},
		{"a deny where legacy allows", &model.CheckResourceOutcome{Status: 200}, []any{&model.CheckResourceOutcome{Status: 200, Decision: true}}, false},
		{"an allow where legacy refuses", &model.CheckResourceOutcome{Status: 200, Decision: true}, []any{&model.CheckResourceOutcome{Status: 400}}, true},
		{"an id legacy leaves out", ids("a", "b"), []any{ids("a")}, true},
		{"fewer ids", ids("a"), []any{ids("a", "b")}, false},
		{"ALLOW where legacy filters", filter("ALLOW"), []any{filter("USE_FILTER_CONDITION")}, true},
		{"a filter where legacy allows", filter("USE_FILTER_CONDITION"), []any{filter("ALLOW")}, false},
		{"an allow that one variant also gives", ptr(true), []any{ptr(false), ptr(true)}, false},
		{"a plain v1 id legacy leaves out", &[]string{"a", "b"}, []any{&[]string{"a"}}, true},
		{"fewer plain v1 ids", &[]string{"a"}, []any{&[]string{"a", "b"}}, false},
		{"a plain v1 operation on an id legacy leaves out", &map[string][]string{"READ": {"a", "b"}}, []any{&map[string][]string{"READ": {"a"}}}, true},
		{"fewer plain v1 operations", &map[string][]string{"READ": {"a"}}, []any{&map[string][]string{"READ": {"a", "b"}}}, false},
		{"a plain v1 ALLOW where legacy filters", &model.OldFilterEvaluationResult{CalculationResult: "ALLOW"}, []any{&model.OldFilterEvaluationResult{CalculationResult: "USE_FILTER_CONDITION"}}, true},
		{"a plain v1 DENY where legacy filters", &model.OldFilterEvaluationResult{CalculationResult: "DENY"}, []any{&model.OldFilterEvaluationResult{CalculationResult: "USE_FILTER_CONDITION"}}, false},
		{"a v2 allow where legacy denies", &model.CheckResourceResponse{Decision: true}, []any{&model.CheckResourceResponse{}}, true},
		{"a v2 deny where legacy allows", &model.CheckResourceResponse{}, []any{&model.CheckResourceResponse{Decision: true}}, false},
		{"a v2 operation on an id legacy leaves out", ops2(map[string][]string{"READ": {"a", "b"}}), []any{ops2(map[string][]string{"READ": {"a"}})}, true},
		{"fewer v2 operations", ops2(map[string][]string{"READ": {"a"}}), []any{ops2(map[string][]string{"READ": {"a"}, "UPDATE": {"a"}})}, false},
		{"a v2 ALLOW where legacy filters", &model.FilterResponse{CalculationResult: "ALLOW"}, []any{&model.FilterResponse{CalculationResult: "USE_FILTER_CONDITION"}}, true},
		{"a v2 filter where legacy allows", &model.FilterResponse{CalculationResult: "USE_FILTER_CONDITION"}, []any{&model.FilterResponse{CalculationResult: "ALLOW"}}, false},
		{"no id where legacy refuses", ids(), []any{&model.CheckResourceBulkOutcome{Status: 400}}, false},
		{"an id where legacy refuses", ids("a"), []any{&model.CheckResourceBulkOutcome{Status: 400}}, true},
		{"no operation where legacy refuses", opsOutcome(map[string][]string{}), []any{&model.CheckResourceBulkOperationsOutcome{Status: 400}}, false},
		{"an operation where legacy refuses", opsOutcome(map[string][]string{"READ": {"a"}}), []any{&model.CheckResourceBulkOperationsOutcome{Status: 400}}, true},
	}
	for _, tc := range cases {
		if got := grantsMore(tc.actual, tc.wants); got != tc.want {
			t.Errorf("%s: grantsMore(%s, %s) = %v, want %v", tc.name, show(tc.actual), show(tc.wants), got, tc.want)
		}
	}
}

func TestLoadExportFedConfig_RefusesAPullTimeoutThatIsNotPositiveSeconds(t *testing.T) {
	for _, v := range []string{"0", "-5", "1m", "x"} {
		t.Setenv("PARITY_EXPORT_PULL_TIMEOUT_SECONDS", v)
		if _, err := LoadExportFedConfig(); err == nil {
			t.Errorf("LoadExportFedConfig with PARITY_EXPORT_PULL_TIMEOUT_SECONDS=%q succeeded, want an error", v)
		}
	}
	t.Setenv("PARITY_EXPORT_PULL_TIMEOUT_SECONDS", "45")
	if cfg, err := LoadExportFedConfig(); err != nil || cfg.PullTimeout != 45*time.Second {
		t.Errorf("LoadExportFedConfig with 45 = %v, %v; want 45s", cfg.PullTimeout, err)
	}
}
