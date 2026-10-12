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
	"testing"
	"time"
)

// TestExportFedAgent replays the export bundle against an agent that pulls its
// configuration from the export source: for each recorded test function, the
// stub pins of its log, each export mounted before the decisions that follow
// it, and every compared golden. A golden fails when the agent's answer
// matches neither the golden nor, for an accepted class, the answer the bundle
// predicts. It runs only under PARITY_PROFILE=authz-agent-export, and needs the
// kind stand with the agent's AUTHZ_PAP_CLIENT_SOURCE_URL pointing at the
// export source (make parity-export).
func TestExportFedAgent(t *testing.T) {
	cfg := LoadConfig()
	if !isExportFedProfile(cfg.Profile) {
		t.Skipf("PARITY_PROFILE=%s; the export-fed agent runs under %s", cfg.Profile, exportFedProfile)
	}
	ecfg, err := LoadExportFedConfig()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readExportBundle(ecfg.BundleDir)
	if err != nil {
		t.Fatalf("read the export bundle: %v", err)
	}
	exports, err := openBundleExports(ecfg.BundleDir)
	if err != nil {
		t.Fatalf("read the export bundle: %v", err)
	}
	pip, ea := NewPipController(cfg.PipMockControlURL), NewPipController(cfg.EAMockControlURL)
	tokens := newLabelTokens(cfg)
	if err := checkKnownUser(tokens); err != nil {
		t.Fatal(err)
	}
	r := &exportReplayer{
		exports:   exports,
		baseURL:   cfg.ACBaseURL,
		source:    &stubExportSource{stub: NewPipController(ecfg.SourceControlURL), timeout: ecfg.PullTimeout, poll: 200 * time.Millisecond},
		stubs:     stubFor(pip, ea),
		tokens:    tokens.token,
		client:    defaultHTTPClient,
		goldenDir: NewGoldenComparator(cfg).goldenRoot,
	}
	ctx := context.Background()
	var all []exportResult
	for _, fn := range bundle.Functions {
		if ecfg.Run != nil && !ecfg.Run.MatchString(fn.Test) {
			continue
		}
		t.Run(fn.Test, func(t *testing.T) {
			for _, c := range []*PipController{pip, ea} {
				if err := c.ResetPinnedRoutes(ctx); err != nil {
					t.Fatalf("reset the stubs: %v", err)
				}
			}
			results, err := r.replay(ctx, fn)
			all = append(all, results...)
			if err != nil {
				t.Fatal(err)
			}
			for _, res := range results {
				switch res.Verdict {
				case verdictDiffers:
					t.Errorf("%s (class %s, export %s): %s", res.Path, res.Class, res.Status, res.Detail)
				case verdictAccepted:
					t.Logf("ACCEPTED DIVERGENCE %s: %s", res.Path, res.Detail)
				case verdictSkipped:
					t.Logf("SKIPPED %s: %s", res.Path, res.Detail)
				}
			}
		})
	}
	t.Log("\n" + exportReport(all))
	if problem := exportRunProblem(all); problem != "" {
		t.Error(problem)
	}
}
