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
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestExportFedOwnerDecisions checks how the agent treats an export that
// holds a form legacy access-control accepts and then fails every decision
// on: an iterate block legacy never evaluates (formNeverEvaluated), or a
// target or condition that reads a PIP the export does not declare
// (formUndeclaredPIP).
// The agent counts the policy set that holds the form as a source that
// fails every time, and nothing more: it accepts the export, its /health
// names the set, and it answers each decision legacy failed because of the
// form with 200 and nothing allowed.
//
// The exports come from the case files and the goldens: the regular cases
// whose upload legacy accepted (regularOwnerDecisionCases), and the points
// of part A whose raw reads hold the form (legacyOwnerDecisionCases). Each
// export is mounted with the canary set of part A, and a denied canary means
// the agent refused the export. Each of the three checks fails on its own.
// It runs only under PARITY_PROFILE=authz-agent-export
// (make parity-export-owner-decisions); PARITY_EXPORT_RUN selects the cases
// whose name it matches.
func TestExportFedOwnerDecisions(t *testing.T) {
	cfg := LoadConfig()
	if !isExportFedProfile(cfg.Profile) {
		t.Skipf("PARITY_PROFILE=%s; the export-fed agent runs under %s", cfg.Profile, exportFedProfile)
	}
	ecfg, err := LoadExportFedConfig()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := allOwnerDecisionCases(NewGoldenComparator(cfg).goldenRoot, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	s := &ParitySuite{cfg: cfg, tokens: NewTokenFactory(cfg), comparator: NewGoldenComparator(cfg),
		pipMock: NewPipController(cfg.PipMockControlURL), eaMock: NewPipController(cfg.EAMockControlURL),
		umMock: NewPipController(cfg.UMMockControlURL)}
	source := &stubExportSource{stub: NewPipController(ecfg.SourceControlURL), timeout: ecfg.PullTimeout, poll: 200 * time.Millisecond}
	ctx := context.Background()
	stand := cfg.TenantID
	ran := 0
	for i, oc := range cases {
		if ecfg.Run != nil && !ecfg.Run.MatchString(oc.name) {
			continue
		}
		ran++
		t.Run(oc.name, func(t *testing.T) {
			s.SetT(t)
			defer func() { s.cfg.TenantID = stand }()
			for _, c := range []*PipController{s.pipMock, s.eaMock, s.umMock} {
				if err := c.ResetPinnedRoutes(ctx); err != nil {
					t.Fatalf("reset the stubs: %v", err)
				}
			}
			s.pinRoutes(oc.pins)
			s.pinUserManagement(oc.userManagement)
			canary := legacyCanaryType(i + 1)
			ps, pips, err := legacyExportDocuments(legacyExportPoint{policySets: oc.policySets, pips: oc.pips}, canary)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Mount(ctx, ps, pips); err != nil {
				t.Fatalf("mount the export: %v", err)
			}
			for _, f := range oc.forms {
				t.Logf("form %s: %s, in set %s", f.kind, f.what, strings.Join(f.sets, " / "))
			}
			s.cfg.TenantID = valueOr(oc.tenant, stand)
			if !s.legacyCanaryAllowed(canary) {
				t.Errorf("the agent refused the export: the canary set %s is denied, so the agent kept its previous "+
					"snapshot; want the export accepted with the set as a failed source", canary)
			}
			status, body, err := agentHealth(ctx, cfg.ACBaseURL)
			if err != nil {
				t.Errorf("GET /health: %v", err)
			}
			for _, f := range oc.forms {
				if err == nil && !healthNames(body, f) {
					t.Errorf("/health answered %d and names none of the sets [%s] that hold %s: %s",
						status, strings.Join(f.sets, ", "), f.what, truncate(body, 500))
				}
			}
			for _, d := range oc.decisions {
				s.cfg.TenantID = d.tenant
				if d.tenant == "" {
					s.cfg.TenantID = stand
				}
				_, outcome := s.sendRequest(oc.resourceType, d.request, s.requestTokens(d.request))
				if problem := refusalProblem(outcome); problem != "" {
					t.Errorf("%s: legacy answered %d; want 200 with nothing allowed, got %s", d.path, d.status, problem)
				}
			}
		})
	}
	s.SetT(t)
	if ran == 0 {
		t.Error("no case ran: PARITY_EXPORT_RUN matched no case whose export holds a form legacy fails decisions on")
	}
}

// agentHealth returns the status and the body of GET <baseURL>/health.
func agentHealth(ctx context.Context, baseURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(baseURL, "/")+"/health", nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
