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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

const (
	domainPoliciesPath = "/access/v1/simplifiedPolicies/domainPolicies/" + isolatedCaseDomain
	domainPIPsPath     = "/access/v1/simplifiedPolicies/domainPIPs/" + isolatedCaseDomain
)

// runRegularCasesAgainst runs cases through runRegularCases against an
// in-process PAP and returns the method and path of every request it received,
// cleanups included. The PAP answers the n-th PUT to domainPoliciesPath or
// domainPIPsPath, counted from 1 over the whole run, with refuse[n] when that is
// set, a check with false, and everything else with 200. domainGoldens holds the
// declare-the-domain golden of each case that has one, so that subtest fails
// unless the runner records that status.
func runRegularCasesAgainst(t *testing.T, refuse map[int]int, domainGoldens map[string]int, cases ...regularCase) []string {
	t.Helper()
	var mu sync.Mutex
	var sent []string
	domainPUTs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case domainPoliciesPath, domainPIPsPath:
			domainPUTs++
			if status, ok := refuse[domainPUTs]; ok {
				w.WriteHeader(status)
			}
		case "/access/v1/check/resource":
			_, _ = w.Write([]byte("false"))
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	goldenRoot := t.TempDir()
	for id, status := range domainGoldens {
		golden := filepath.Join(goldenRoot, "load-simplified-policies-v1", "regular", id, "declare-the-domain.json")
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(fmt.Sprintf(`{"status": %d}`, status)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{ACBaseURL: srv.URL, TenantID: "t", Profile: "legacy"}
	s := &ParitySuite{
		cfg:        cfg,
		tokens:     &TokenFactory{cfg: cfg, cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}},
		comparator: &GoldenComparator{goldenRoot: goldenRoot},
	}
	s.SetS(s)
	t.Run("run", func(t *testing.T) {
		s.SetT(t)
		s.runRegularCases(cases)
	})
	mu.Lock()
	defer mu.Unlock()
	return sent
}

// caseWithSets returns a regular case with one upload of sets under
// parity-<id> and one M2M check request named read.
func caseWithSets(id string) regularCase {
	return regularCase{
		id:       id,
		uploads:  []regularUpload{{externalID: "parity-" + id, sets: []any{map[string]any{}}}},
		requests: []isolatedRequest{{name: "read", m2mOnly: true}},
	}
}

func TestRunRegularCases_ARefusedPIPUploadEndsTheCaseAfterItsGolden(t *testing.T) {
	c := caseWithSets("c")
	c.pips = []any{map[string]any{"name": "subject.x"}}
	c.cleanup = []papCall{{method: http.MethodDelete, path: "/access/v1/config/customization/policySet/s", query: url.Values{"level": {"PROJECT"}}}}
	c.steps = []regularStep{{name: "step", call: &papCall{method: http.MethodPost, path: "/access/v1/config/customization/import"}, golden: PSUITE_IMPORT_CUSTOMIZATION, observe: customizeObservations(nil)}}
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		// the cleanups of the test: the sets of the case, then the domain
		"DELETE /access/v1/policySets/externalId/parity-c",
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
	}
	got := runRegularCasesAgainst(t, map[int]int{2: http.StatusBadRequest}, map[string]int{"c": http.StatusBadRequest}, c)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the PIP upload refused mismatch (-want +got):\n%s", diff)
	}
}

// The upload of the simplified policies is the last of the three PUTs, and its
// status is the one recorded. The next case, which has no PIPs, runs in full and
// sends no domain upload of its own.
func TestRunRegularCases_ARefusedPolicyUploadEndsOnlyItsOwnCase(t *testing.T) {
	refused := caseWithSets("refused")
	refused.simplified = []any{map[string]any{"resourceType": "RT"}}
	next := caseWithSets("next")
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"PUT /access/v1/policySets/externalId/parity-next",
		"POST /access/v1/check/resource",
		// the cleanups of the test: the sets of both cases, then the domain
		"DELETE /access/v1/policySets/externalId/parity-refused",
		"DELETE /access/v1/policySets/externalId/parity-next",
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
	}
	got := runRegularCasesAgainst(t, map[int]int{3: http.StatusBadRequest}, map[string]int{"refused": http.StatusBadRequest}, refused, next)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the policy upload refused mismatch (-want +got):\n%s", diff)
	}
}

func TestRunRegularCases_AnAcceptedDomainUploadGoesOnToTheSetsRequestsAndSteps(t *testing.T) {
	c := caseWithSets("c")
	c.pips = []any{map[string]any{"name": "subject.x"}}
	c.cleanup = []papCall{{method: http.MethodDelete, path: "/access/v1/config/customization/policySet/s", query: url.Values{"level": {"PROJECT"}}}}
	c.steps = []regularStep{{
		name: "step", call: &papCall{method: http.MethodPost, path: "/access/v1/config/customization/import"},
		golden: PSUITE_IMPORT_CUSTOMIZATION, observe: customizeObservations([]isolatedRequest{{name: "read-after", m2mOnly: true}}),
	}}
	want := []string{
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
		"DELETE /access/v1/config/customization/policySet/s",
		"PUT /access/v1/policySets/externalId/parity-c",
		"POST /access/v1/check/resource",
		"POST /access/v1/config/customization/import",
		"POST /access/v1/check/resource",
		// the cleanups of the case, then of the test
		"DELETE /access/v1/config/customization/policySet/s",
		"DELETE /access/v1/policySets/externalId/parity-c",
		"PUT " + domainPoliciesPath,
		"PUT " + domainPIPsPath,
		"PUT " + domainPoliciesPath,
	}
	got := runRegularCasesAgainst(t, nil, map[string]int{"c": http.StatusOK}, c)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("requests with the domain upload accepted mismatch (-want +got):\n%s", diff)
	}
}
