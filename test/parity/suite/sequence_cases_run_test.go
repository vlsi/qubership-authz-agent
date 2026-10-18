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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// runSequenceCasesAgainst runs the sequence cases of f through runSequenceCases
// against an in-process PAP and returns, for every request it received, the
// method, the path, and the tenant_id. The PAP answers a call whose path is in
// refuse with that status, a check with false, and everything else with 200.
func runSequenceCasesAgainst(t *testing.T, refuse map[string]int, f caseFile) []string {
	t.Helper()
	var mu sync.Mutex
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Method+" "+r.URL.Path+" "+r.URL.Query().Get("tenant_id"))
		if status, ok := refuse[r.URL.Path]; ok {
			w.WriteHeader(status)
		}
		if r.URL.Path == "/access/v1/check/resource" {
			_, _ = w.Write([]byte("false"))
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	_, _, sequence, err := caseFileCases(f)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ACBaseURL: srv.URL, TenantID: "stand", Profile: "legacy"}
	s := &ParitySuite{
		cfg:        cfg,
		tokens:     &TokenFactory{cfg: cfg, cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}},
		comparator: &GoldenComparator{goldenRoot: t.TempDir()},
	}
	s.SetS(s)
	t.Run("run", func(t *testing.T) {
		s.SetT(t)
		s.runSequenceCases(sequence)
	})
	if s.cfg.TenantID != "stand" {
		t.Errorf("tenant after the cases = %q, want the stand's tenant back", s.cfg.TenantID)
	}
	mu.Lock()
	defer mu.Unlock()
	return sent
}

// sequenceFile holds one case in tenant t whose write step is followed by a
// read, a decision in the case's tenant, and a later step; onRefusal is the
// write step's.
func sequenceFile(onRefusal string) caseFile {
	return caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: []stepSpec{
		{Name: "write", Op: "write-domain-policies", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`),
			OnRefusal: onRefusal, Observe: []string{"status", "error-class", "read:read-domain-pips", "decide:here"},
			Requests: []requestSpec{{Name: "here", Subject: "m2m"}}},
		{Name: "after", Op: "write-domain-pips", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`)},
	}}, {ID: "next", Steps: []stepSpec{{Name: "read", Op: "read-config-sets"}}}}}
}

func TestRunSequenceCases(t *testing.T) {
	const policies = "/access/v1/simplifiedPolicies/domainPolicies/D"
	cases := []struct {
		name      string
		onRefusal string
		refuse    map[string]int
		want      []string
	}{
		{"an accepted write is observed in order, in the case's tenant",
			"", nil,
			[]string{"PUT " + policies + " t", "GET /access/v1/simplifiedPolicies/domainPIPs/D t", "POST /access/v1/check/resource t",
				"PUT /access/v1/simplifiedPolicies/domainPIPs/D t", "GET /access/v3/config/policySets stand"}},
		{"a refused write ends its case and the next case runs",
			"", map[string]int{policies: http.StatusBadRequest},
			[]string{"PUT " + policies + " t", "GET /access/v3/config/policySets stand"}},
		{"a refused write with onRefusal continue goes on",
			"continue", map[string]int{policies: http.StatusBadRequest},
			[]string{"PUT " + policies + " t", "GET /access/v1/simplifiedPolicies/domainPIPs/D t", "POST /access/v1/check/resource t",
				"PUT /access/v1/simplifiedPolicies/domainPIPs/D t", "GET /access/v3/config/policySets stand"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runSequenceCasesAgainst(t, tc.refuse, sequenceFile(tc.onRefusal))
			if diff := cmp.Diff(append(tc.want, clearsIn("t")...), got); diff != "" {
				t.Errorf("requests mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// stepTenantFile holds one case in tenant t whose middle step runs in tenant u:
// its write, its read, a decision with no tenantId, and a decision that names
// t. The steps before and after it run in t, and the next case in the stand's
// tenant. onRefusal is the middle step's.
func stepTenantFile(onRefusal string) caseFile {
	return caseFile{Cases: []caseSpec{{ID: "c", Tenant: stringOf("t"), Steps: []stepSpec{
		{Name: "before", Op: "write-domain-pips", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`)},
		{Name: "elsewhere", Op: "write-domain-policies", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`),
			Tenant: stringOf("u"), OnRefusal: onRefusal,
			Observe:  []string{"status", "read-raw:read-domain-pips", "decide:there", "decide:home"},
			Requests: []requestSpec{{Name: "there", Subject: "m2m"}, {Name: "home", Subject: "m2m", TenantID: stringOf("t")}}},
		{Name: "after", Op: "write-domain-pips", Args: map[string]any{"domain": "D"}, Body: json.RawMessage(`[]`)},
	}}, {ID: "next", Steps: []stepSpec{{Name: "read", Op: "read-config-sets"}}}}}
}

func TestRunSequenceCases_AStepRunsInItsOwnTenant(t *testing.T) {
	const (
		pips     = "/access/v1/simplifiedPolicies/domainPIPs/D"
		policies = "/access/v1/simplifiedPolicies/domainPolicies/D"
	)
	cases := []struct {
		name      string
		onRefusal string
		refuse    map[string]int
		want      []string
	}{
		{"the step's calls go to its tenant and the case's tenant comes back after it",
			"", nil,
			[]string{"PUT " + pips + " t", "PUT " + policies + " u", "GET " + pips + " u", "POST /access/v1/check/resource u",
				"POST /access/v1/check/resource t", "PUT " + pips + " t", "GET /access/v3/config/policySets stand"}},
		{"a refusal in the step's tenant ends the case and the next case runs in the stand's tenant",
			"", map[string]int{policies: http.StatusBadRequest},
			[]string{"PUT " + pips + " t", "PUT " + policies + " u", "GET /access/v3/config/policySets stand"}},
		{"a refusal in the step's tenant with onRefusal continue goes on there and the next step runs in the case's tenant",
			"continue", map[string]int{policies: http.StatusBadRequest},
			[]string{"PUT " + pips + " t", "PUT " + policies + " u", "GET " + pips + " u", "POST /access/v1/check/resource u",
				"POST /access/v1/check/resource t", "PUT " + pips + " t", "GET /access/v3/config/policySets stand"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runSequenceCasesAgainst(t, tc.refuse, stepTenantFile(tc.onRefusal))
			if diff := cmp.Diff(append(tc.want, clearsIn("t", "u")...), got); diff != "" {
				t.Errorf("requests mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// clearsIn returns the requests, as runSequenceCasesAgainst lists them, that
// clear the customizations and the policy sets of each of tenants and empty
// its domain D when the last case ends.
func clearsIn(tenants ...string) []string {
	var requests []string
	for _, tenant := range tenants {
		for _, path := range []string{"/access/v1/config/customization/clear", "/access/v1/pip/customization/clear"} {
			requests = append(requests, "POST "+path+" "+tenant, "POST "+path+" "+tenant)
		}
		requests = append(requests, "POST /access/v1/config/clear "+tenant,
			"PUT /access/v1/simplifiedPolicies/domainPolicies/D "+tenant,
			"PUT /access/v1/simplifiedPolicies/domainPIPs/D "+tenant)
	}
	return requests
}

// When the last case ends, the runner clears the customizations and the
// policy sets of each tenant a case or a step ran in: round48/papstate-must.json
// archives a set in its case's tenant and uploads an empty list under its
// externalId, which deletes nothing. It sends nothing to the stand's tenant.
func TestSequenceCleanup_ClearsTheTenantsOfTheCasesAndNotTheStands(t *testing.T) {
	f, err := readCaseFile("round48/papstate-must.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _, sequence, err := caseFileCases(f)
	if err != nil {
		t.Fatal(err)
	}
	want := papCall{method: http.MethodPost, path: "/access/v1/config/clear",
		query: url.Values{"tenant_id": {"parity-p48-state-002"}}}
	got := sequenceCleanup(sequence, "default")
	if !slices.ContainsFunc(got, func(c papCall) bool { return cmp.Equal(want, c, cmp.AllowUnexported(papCall{})) }) {
		t.Errorf("sequenceCleanup holds no %v", want)
	}
	for _, c := range got {
		if c.query.Get("tenant_id") == "default" {
			t.Errorf("sequenceCleanup sends %s %s to the stand's tenant", c.method, c.path)
		}
	}
}

// A customize step is the step customizeStepCall builds, observing its status
// and then each of its requests in order, and going on after a refusal, as the
// runner sent it before steps existed. Every customize step of every case file
// is checked, so a case file recorded with customize replays unchanged.
func TestCaseSteps_ACustomizeStepIsItsCallThenItsRequests(t *testing.T) {
	root := filepath.Join("testdata", "cases")
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		f, err := readCaseFile(name)
		if err != nil {
			return err
		}
		for _, c := range f.Cases {
			if len(c.Customize) == 0 {
				continue
			}
			rt := valueOr(c.ResourceType, f.ResourceTypePrefix+strings.ToUpper(strings.ReplaceAll(c.ID, "-", "_")))
			steps, err := caseSteps(c, rt)
			if err != nil {
				t.Errorf("%s: case %s: %v", name, c.ID, err)
				continue
			}
			for i, st := range c.Customize {
				n++
				call, golden := customizeStepCall(c.ID, c.RuleIDsOf, st, rt)
				var want []string
				want = append(want, "status")
				for _, r := range st.Requests {
					want = append(want, "decide "+r.Name)
				}
				var got []string
				for _, o := range steps[i].observe {
					if o.kind == "decide" {
						got = append(got, "decide "+o.request.name)
					} else {
						got = append(got, o.kind)
					}
				}
				if diff := cmp.Diff(call, *steps[i].call, cmp.AllowUnexported(papCall{})); diff != "" {
					t.Errorf("%s: case %s step %s: call mismatch (-customizeStepCall +caseSteps):\n%s", name, c.ID, st.Name, diff)
				}
				if steps[i].golden != golden || steps[i].stopOnRefusal || !cmp.Equal(want, got) {
					t.Errorf("%s: case %s step %s: golden %s, stop %v, observe %v; want %s, false, %v",
						name, c.ID, st.Name, Meta(steps[i].golden).GoldenDir, steps[i].stopOnRefusal, got, Meta(golden).GoldenDir, want)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no customize step under testdata/cases")
	}
	t.Logf("%d customize steps", n)
}

// A request classed by classifyBy is compared with its unclassified golden on
// the authz-agent profile when that golden is recorded, and with the golden of
// its order class otherwise: an order-dependent answer is accepted from legacy
// access-control only. regular/d2r46-d2cff13835/ry has that golden, and
// regular/o16-01/ry has only its classes.
func TestComparesWithTheUnclassifiedGolden(t *testing.T) {
	cases := []struct {
		profile, subCase string
		want             bool
	}{
		{"authz-agent", "regular/d2r46-d2cff13835/ry", true},
		{"legacy", "regular/d2r46-d2cff13835/ry", false},
		{"authz-agent", "regular/o16-01/ry", false},
	}
	for _, tc := range cases {
		s := &ParitySuite{cfg: Config{Profile: tc.profile}, comparator: NewGoldenComparator(Config{})}
		if got := s.comparesWithTheUnclassifiedGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, tc.subCase); got != tc.want {
			t.Errorf("%s %s: got %v, want %v", tc.profile, tc.subCase, got, tc.want)
		}
	}
}
