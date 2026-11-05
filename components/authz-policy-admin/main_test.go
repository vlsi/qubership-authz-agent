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

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reported keeps the level and the text of every line a run wrote.
type reported struct{ lines []string }

func (r *reported) record(level, format string, args ...any) {
	r.lines = append(r.lines, level+": "+fmt.Sprintf(format, args...))
}

func (r *reported) Infof(format string, args ...any)  { r.record("info", format, args...) }
func (r *reported) Warnf(format string, args ...any)  { r.record("warn", format, args...) }
func (r *reported) Errorf(format string, args ...any) { r.record("error", format, args...) }

// contains reports whether any line at level holds substring.
func (r *reported) contains(level, substring string) bool {
	for _, line := range r.lines {
		if strings.HasPrefix(line, level+": ") && strings.Contains(line, substring) {
			return true
		}
	}
	return false
}

// records swaps the command's logger for the run of one test.
func records(t *testing.T) *reported {
	t.Helper()
	rec := &reported{}
	previous := logger
	logger = rec
	t.Cleanup(func() { logger = previous })
	return rec
}

// The stub takes policies from anyone who can reach it, so every start says
// so: whoever reads the log of a namespace it was installed in is the person
// who has to decide whether that is acceptable there. A start that keeps the
// policies in memory says that too, because the next restart serves nothing.
func TestBuild_ReportsWhatTheRunIs(t *testing.T) {
	// The directory carries a domain from an earlier run, which the start
	// names: a restart that silently served nothing would look the same in
	// the log as one that loaded everything.
	seeded := t.TempDir()
	if err := os.WriteFile(filepath.Join(seeded, policiesFilePrefix+"BSS.json"), []byte(bssPolicies), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	for name, dataDir := range map[string]string{"with a data directory": seeded, "with none": ""} {
		t.Run(name, func(t *testing.T) {
			rec := records(t)
			mux, addr, err := build(dataDir, "18090", defaultTenant)
			if err != nil {
				t.Fatalf("build(%q) = %v", dataDir, err)
			}
			assertServes(t, mux, addr)
			assertReportsTheRun(t, rec, dataDir)
		})
	}
}

// assertServes fails unless build returned routes and the address its port
// makes.
func assertServes(t *testing.T, mux *http.ServeMux, addr string) {
	t.Helper()
	if mux == nil {
		t.Fatal("build returned no routes")
	}
	if addr != "0.0.0.0:18090" {
		t.Errorf("build listens on %q, want 0.0.0.0:18090", addr)
	}
}

// assertReportsTheRun fails unless the start reported that the upload API is
// open, and where the policies are kept or that they are kept nowhere.
func assertReportsTheRun(t *testing.T, rec *reported, dataDir string) {
	t.Helper()
	if !rec.contains("warn", "unauthenticated") {
		t.Errorf("the run reported %v, want a warning that the API is unauthenticated", rec.lines)
	}
	if dataDir == "" {
		if !rec.contains("warn", "persistence disabled") {
			t.Errorf("the run reported %v, want a warning that nothing is persisted", rec.lines)
		}
		return
	}
	if !rec.contains("info", dataDir) {
		t.Errorf("the run reported %v, want the directory the policies are kept in", rec.lines)
	}
	if !rec.contains("info", "BSS") {
		t.Errorf("the run reported %v, want the domain it loaded from that directory", rec.lines)
	}
}

// A data directory the stub cannot write to is a failed start, not a run that
// drops every upload: build names the store and main exits on it.
func TestBuild_RefusesADataDirectoryItCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	records(t)
	dir := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, _, err := build(dir, "18090", defaultTenant)
	if err == nil {
		t.Fatal("build over an unwritable data directory = nil, want an error")
	}
	if !strings.Contains(err.Error(), "store") {
		t.Errorf("build reported %q, want an error naming the store", err)
	}
}

// The routes build serves are the stub's own: the export the agent pulls
// answers before anything has been uploaded.
func TestBuild_ServesTheExport(t *testing.T) {
	records(t)
	mux, _, err := build(t.TempDir(), "18090", defaultTenant)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rec := do(t, mux, http.MethodGet, "/access/v3/config/policySets", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /access/v3/config/policySets = %d, want 200", rec.Code)
	}
}

// The chart always sets the port, and `docker run` of this image without one
// has to keep working, so an unset and an empty variable both take the
// fallback.
func TestEnvOr(t *testing.T) {
	const key = "AUTHZ_POLICY_ADMIN_PORT"
	for name, set := range map[string]string{"a value": "19000", "an empty value": ""} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(key, set)
			want := set
			if set == "" {
				want = "18090"
			}
			if got := envOr(key, "18090"); got != want {
				t.Errorf("envOr(%q) = %q with the variable set to %q, want %q", key, got, set, want)
			}
		})
	}
	t.Run("the variable is not set", func(t *testing.T) {
		if got := envOr("AUTHZ_POLICY_ADMIN_PORT_UNSET", "18090"); got != "18090" {
			t.Errorf("envOr on an unset variable = %q, want the fallback 18090", got)
		}
	})
}
