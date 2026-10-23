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
	"io/fs"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"authz-agent/test/parity/suite/model"
)

// TestExportFedLegacyAgent is part A of the export-fed profile: it feeds the
// agent the v3 exports legacy access-control held, as the raw reads of the
// sequence cases recorded them, and compares the agent's decisions with the
// legacy goldens recorded at the same point (legacyExportCases). Each point's
// export is mounted on the export source with a canary set beside it, and a
// check of the canary tells a loaded export from a failed pull. A golden
// fails when the agent's answer differs from it, unless the kind of its
// class (set-type for set-type:DEFAULT) is listed in
// acceptedExportDivergences and the answer allows nothing the golden denies,
// or the entry covers such an answer too (AllowsMore). It runs only under
// PARITY_PROFILE=authz-agent-export (make parity-export-legacy);
// PARITY_EXPORT_RUN selects the cases whose <file>/<case id> it matches.
func TestExportFedLegacyAgent(t *testing.T) {
	cfg := LoadConfig()
	if !isExportFedProfile(cfg.Profile) {
		t.Skipf("PARITY_PROFILE=%s; the export-fed agent runs under %s", cfg.Profile, exportFedProfile)
	}
	ecfg, err := LoadExportFedConfig()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := allLegacyExportCases(NewGoldenComparator(cfg).goldenRoot)
	if err != nil {
		t.Fatal(err)
	}
	s := &ParitySuite{cfg: cfg, tokens: NewTokenFactory(cfg), comparator: NewGoldenComparator(cfg),
		pipMock: NewPipController(cfg.PipMockControlURL), eaMock: NewPipController(cfg.EAMockControlURL),
		umMock: NewPipController(cfg.UMMockControlURL)}
	source := &stubExportSource{stub: NewPipController(ecfg.SourceControlURL), timeout: ecfg.PullTimeout, poll: 200 * time.Millisecond}
	ctx := context.Background()
	var all []legacyResult
	uncompared := map[string]string{}
	mounted := 0
	stand := cfg.TenantID
	for _, lc := range cases {
		name := lc.file + "/" + lc.id
		if ecfg.Run != nil && !ecfg.Run.MatchString(name) {
			continue
		}
		maps.Copy(uncompared, lc.uncompared)
		if len(lc.points) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s.SetT(t)
			defer func() { s.cfg.TenantID = stand }()
			for _, c := range []*PipController{s.pipMock, s.eaMock, s.umMock} {
				if err := c.ResetPinnedRoutes(ctx); err != nil {
					t.Fatalf("reset the stubs: %v", err)
				}
			}
			s.pinRoutes(lc.pins)
			s.pinUserManagement(lc.userManagement)
			for _, p := range lc.points {
				mounted++
				canary := legacyCanaryType(mounted)
				ps, pips, err := legacyExportDocuments(p, canary)
				if err != nil {
					t.Fatal(err)
				}
				if err := source.Mount(ctx, ps, pips); err != nil {
					t.Fatalf("mount the export of step %s: %v", p.step, err)
				}
				s.cfg.TenantID = lc.tenant
				loaded := s.legacyCanaryAllowed(canary)
				for _, d := range p.decisions {
					s.cfg.TenantID = d.tenant
					res := s.judgeLegacyDecision(lc, p, d, loaded)
					all = append(all, res)
					switch {
					case res.WrongAllow && res.Verdict == verdictDiffers:
						t.Errorf("WRONG ALLOW %s (class %s): %s", res.Path, res.Class, res.Detail)
					case res.Verdict == verdictDiffers:
						t.Errorf("%s (class %s): %s", res.Path, res.Class, res.Detail)
					case res.Verdict == verdictAccepted:
						t.Logf("ACCEPTED DIVERGENCE %s: %s", res.Path, res.Detail)
					case res.Verdict == verdictSkipped:
						t.Logf("SKIPPED %s: %s", res.Path, res.Detail)
					}
				}
			}
		})
	}
	s.SetT(t)
	t.Log("\n" + legacyExportReport(all, uncompared))
	if len(all) == 0 {
		t.Error("no golden compared: PARITY_EXPORT_RUN matched no case with a legacy export")
	}
}

// allLegacyExportCases reads every case file under testdata/cases and returns
// the cases of legacyExportCases, those whose every decision is uncompared
// included.
func allLegacyExportCases(goldenRoot string) ([]legacyExportCase, error) {
	names, err := caseFileNames()
	if err != nil {
		return nil, err
	}
	var out []legacyExportCase
	for _, name := range names {
		f, err := readCaseFile(name)
		if err != nil {
			return nil, err
		}
		cases, err := legacyExportCases(name, f, goldenRoot)
		if err != nil {
			return nil, err
		}
		out = append(out, cases...)
	}
	return out, nil
}

// caseFileNames returns the names of the case files under testdata/cases,
// relative to it and sorted, as readCaseFile takes them.
func caseFileNames() ([]string, error) {
	root := filepath.Join("testdata", "cases")
	var names []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		names = append(names, filepath.ToSlash(name))
		return nil
	})
	slices.Sort(names)
	return names, err
}

// legacyCanaryAllowed checks the canary type for parity-reader and reports
// whether the agent allows it, that is, whether it loaded the export mounted
// with that canary.
func (s *ParitySuite) legacyCanaryAllowed(canary string) bool {
	_, outcome := s.sendRequest(canary, isolatedRequest{name: "canary", operation: "READ"}, s.requestTokens(isolatedRequest{}))
	got, ok := outcome.(*model.CheckResourceOutcome)
	return ok && got.Status == http.StatusOK && got.Decision
}

// judgeLegacyDecision sends the decision d at point p of case lc and compares
// the answer with its golden, or with the recorded variants of its order
// class.
func (s *ParitySuite) judgeLegacyDecision(lc legacyExportCase, p legacyExportPoint, d legacyDecision, loaded bool) legacyResult {
	req := d.request
	res := legacyResult{exportResult: exportResult{Test: lc.file + "/" + lc.id, Path: d.path, Status: "legacy",
		Families: featureFamilies(p.features), Class: legacyClass(p, loaded)}, Features: p.features}
	s.pinRoutes(req.pins)
	s.pinUserManagement(req.userManagement)
	time.Sleep(req.pause)
	id, actual := s.sendRequest(lc.resourceType, req, s.requestTokens(req))
	paths := legacyGoldenPaths(s.comparator.goldenRoot, id, d.path)
	if len(paths) == 0 {
		res.Verdict, res.Detail = verdictSkipped, "no golden is recorded"
		return res
	}
	wants := make([]any, len(paths))
	var diffs []string
	for i, path := range paths {
		want, err := readGoldenTarget(s.comparator.goldenRoot, id, path)
		if err != nil {
			res.Verdict, res.Detail = verdictDiffers, err.Error()
			return res
		}
		wants[i] = want
		_, sub, _ := goldenRow(path)
		diff := sameOutcome(id, sub, want, actual)
		if diff == "" {
			res.Verdict = verdictMatch
			return res
		}
		diffs = append(diffs, diff)
	}
	res.Verdict, res.Detail = verdictDiffers, strings.Join(diffs, "\n")
	res.WrongAllow = grantsMore(actual, wants)
	if accepted, ok := acceptedLegacyDifference(res.Class, res.WrongAllow); ok {
		res.Verdict = verdictAccepted
		res.Detail = "class " + res.Class + ", decided in " + accepted.Decision + ": " + accepted.Reason
	}
	return res
}
