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

package pull

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authz-agent/internal/pips"
)

// policySets is a v3 policy-sets response with one SIMPLIFIED policy set of
// one rule and one DEFAULT policy set, which the converter skips.
const policySets = `{
  "hash": "hash-ps-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "policySets": [
    {
      "policySetId": "ps-1", "name": "Test PS", "type": "SIMPLIFIED", "domain": "TestDomain", "status": "ACTIVE",
      "target": "resourceType == 'TestResource'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "default",
      "policies": [{
        "policyId": "pol-1", "target": "subject.roles CONTAINS 'ROLE_TEST'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
        "rules": [{"ruleId": "rule-1", "target": "operation == 'READ'", "condition": null, "effect": "ALLOW"}]
      }]
    },
    {
      "policySetId": "ps-default", "name": "Default type PS", "type": "DEFAULT", "domain": "OtherDomain", "status": "ACTIVE",
      "target": "resourceType == 'Other'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "default", "policies": []
    }
  ]
}`

// pipsResponse is a v3 PIPs response with one TOKEN PIP and one FILTERED
// PIP, which the converter skips.
const pipsResponse = `{
  "hash": "hash-pip-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "pips": [
    {"name": "subject.azp", "pipType": "TOKEN", "claim": "azp", "domain": "TestDomain", "tenantId": "default"},
    {"name": "subject.filtered", "pipType": "FILTERED", "domain": "TestDomain", "tenantId": "default"}
  ]
}`

type store struct {
	mu   sync.Mutex
	puts map[string][]any
}

func (s *store) Put(_ context.Context, path []string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.puts == nil {
		s.puts = map[string][]any{}
	}
	key := strings.Join(path, "/")
	s.puts[key] = append(s.puts[key], value)
	return nil
}

func (s *store) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts[path])
}

// last decodes the last document stored at path through JSON.
func (s *store) last(t *testing.T, path string) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.puts[path]
	if len(values) == 0 {
		t.Fatalf("nothing stored at %s", path)
	}
	raw, err := json.Marshal(values[len(values)-1])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

type tokens struct {
	token string
	// err, when set, is what Bearer returns instead of the token.
	err   error
	ready chan struct{}
}

func readyTokens(token string) *tokens {
	ready := make(chan struct{})
	close(ready)
	return &tokens{token: token, ready: ready}
}

func (t *tokens) Bearer() (string, error) { return t.token, t.err }
func (t *tokens) Ready() <-chan struct{}  { return t.ready }

type quiet struct{}

func (quiet) Debugf(string, ...any) {}
func (quiet) Infof(string, ...any)  {}
func (quiet) Warnf(string, ...any)  {}

// recorder keeps the level and the text of every line, for a test whose
// subject is what the puller reports rather than what it stores.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) record(level, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, level+": "+fmt.Sprintf(format, args...))
}

func (r *recorder) Debugf(format string, args ...any) { r.record("debug", format, args...) }
func (r *recorder) Infof(format string, args ...any)  { r.record("info", format, args...) }
func (r *recorder) Warnf(format string, args ...any)  { r.record("warn", format, args...) }

// updates returns the lines reported for a completed load, oldest first.
func (r *recorder) updates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, line := range r.lines {
		if strings.Contains(line, "policies: updated") {
			out = append(out, line)
		}
	}
	return out
}

// source serves the v3 responses and records the Authorization header of
// the last request.
func source(t *testing.T, status int) (*httptest.Server, *string) {
	t.Helper()
	var authorization string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want application/json", r.Header.Get("Accept"))
		}
		w.WriteHeader(status)
		switch r.URL.Path {
		case "/access/v3/config/policySets":
			_, _ = w.Write([]byte(policySets))
		case "/access/v3/config/pips":
			_, _ = w.Write([]byte(pipsResponse))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &authorization
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after 3s waiting for %s", what)
}

// TestRun_LoadsTheSource: the first pull fetches both documents with the
// bearer token, converts them, stores data.policies and data.pips, and
// reports the policies loaded with the conversion counts.
func TestRun_LoadsTheSource(t *testing.T) {
	srv, authorization := source(t, http.StatusOK)
	st := &store{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, st, readyTokens("tok"), quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "the first load", func() bool { return p.Status().PoliciesLoaded })
	status := p.Status()
	want := Conversion{PolicySets: 1, Rules: 1, Policies: 1}
	if status.Conversion == nil || *status.Conversion != want || status.FirstSuccessAt == "" || status.Reason != "" {
		t.Errorf("Status() = %+v, want conversion %+v with a first success time", status, want)
	}
	if *authorization != "Bearer tok" {
		t.Errorf("Authorization sent = %q, want Bearer tok", *authorization)
	}
	if st.count("policies") != 1 || st.count("pips") != 1 {
		t.Fatalf("stored %d policies and %d pips documents, want one each", st.count("policies"), st.count("pips"))
	}
	policies := st.last(t, "policies")
	if len(policies) == 0 {
		t.Errorf("data.policies = %v, want the normalized document", policies)
	}
	byName, _ := st.last(t, "pips")["byName"].(map[string]any)
	if _, ok := byName["subject.azp"]; !ok || len(byName) != 1 {
		t.Errorf("data.pips.byName = %v, want subject.azp alone", byName)
	}
}

// TestRun_ReportsTheFirstLoadAtInfoAndTheRestAtDebug: every tick loads the
// source again, changed or not, so the loads after the first one repeat what
// the first one said. Only the first is reported at info; at the default
// interval of 30 seconds the rest would be 2880 identical lines a day.
func TestRun_ReportsTheFirstLoadAtInfoAndTheRestAtDebug(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	rec := &recorder{}
	p := New(Config{SourceURL: srv.URL, Interval: 20 * time.Millisecond}, &store{}, nil, rec)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "three loads", func() bool { return len(rec.updates()) >= 3 })
	got := rec.updates()
	if !strings.HasPrefix(got[0], "info: ") {
		t.Errorf("the first load reported %q, want an info line", got[0])
	}
	for i, line := range got[1:] {
		if !strings.HasPrefix(line, "debug: ") {
			t.Errorf("load %d reported %q, want a debug line", i+2, line)
		}
	}
}

// TestPullOnce_KeepsTheDocumentsOnFailure: a source that fails leaves the
// store untouched and returns the error, and so does a source whose
// documents cannot be converted.
func TestPullOnce_KeepsTheDocumentsOnFailure(t *testing.T) {
	failing, _ := source(t, http.StatusInternalServerError)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policySets": "no"`))
	}))
	defer broken.Close()
	for name, url := range map[string]string{"an HTTP 500": failing.URL, "a body that is not JSON": broken.URL} {
		t.Run(name, func(t *testing.T) {
			st := &store{}
			p := New(Config{SourceURL: url, Interval: time.Hour}, st, nil, quiet{})
			if err := p.PullOnce(context.Background()); err == nil {
				t.Fatal("PullOnce() = nil, want an error")
			}
			if st.count("policies") != 0 || st.count("pips") != 0 || p.Status().PoliciesLoaded {
				t.Errorf("after the failure: %d policies, %d pips, status %+v; want nothing stored and not loaded", st.count("policies"), st.count("pips"), p.Status())
			}
		})
	}
}

// TestPull_KeepsTheLoadedPoliciesWhenALaterPullFails: once a pull has loaded
// the source, a pull that fails stores nothing, and the status that /health
// and /ready read stays as the successful pull set it.
func TestPull_KeepsTheLoadedPoliciesWhenALaterPullFails(t *testing.T) {
	healthy, _ := source(t, http.StatusOK)
	failing, _ := source(t, http.StatusInternalServerError)
	st := &store{}
	p := New(Config{SourceURL: healthy.URL, Interval: time.Hour}, st, nil, quiet{})
	p.pull(context.Background())
	loaded := p.Status()
	if !loaded.PoliciesLoaded || st.count("policies") != 1 || st.count("pips") != 1 {
		t.Fatalf("after the first pull: %d policies, %d pips, status %+v; want one of each stored and loaded", st.count("policies"), st.count("pips"), loaded)
	}

	p.cfg.SourceURL = failing.URL
	p.pull(context.Background())
	if got := p.Status(); !reflect.DeepEqual(got, loaded) {
		t.Errorf("Status() after the failed pull = %+v, want %+v", got, loaded)
	}
	if st.count("policies") != 1 || st.count("pips") != 1 {
		t.Errorf("after the failed pull: %d policies and %d pips documents stored, want the one of each from the first pull", st.count("policies"), st.count("pips"))
	}
}

// TestPullOnce_SendsNothingWithoutACurrentToken: a token source that has no
// current token, such as one whose token expired after a failed refresh,
// fails the pull before any request, with the source's error.
func TestPullOnce_SendsNothingWithoutACurrentToken(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()
	expired := readyTokens("old")
	expired.err = errors.New("m2m token: expired at 2026-11-04T12:00:00Z")
	st := &store{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, st, expired, quiet{})

	err := p.PullOnce(context.Background())

	if err == nil || !strings.Contains(err.Error(), "no token to present: m2m token: expired") {
		t.Errorf("PullOnce() = %v, want the error of the token source", err)
	}
	if n := requests.Load(); n != 0 || st.count("policies") != 0 {
		t.Errorf("requests at the source = %d, policies stored = %d; want 0 and 0", n, st.count("policies"))
	}
}

// TestPullOnce_WithoutTokens: with no token source the fetch carries no
// Authorization header.
func TestPullOnce_WithoutTokens(t *testing.T) {
	srv, authorization := source(t, http.StatusOK)
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, &store{}, nil, quiet{})
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v", err)
	}
	if *authorization != "" {
		t.Errorf("Authorization sent = %q, want none", *authorization)
	}
}

// TestRun_Disabled: without a source, or with a zero interval, the status
// reports the policies as loaded with the reason, so readiness does not wait.
func TestRun_Disabled(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		reason string
	}{
		{"no source", Config{Interval: time.Second}, "pull disabled: source URL empty"},
		{"a zero interval", Config{SourceURL: "http://source", Interval: 0}, "pull disabled: interval is 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &store{}
			p := New(tc.cfg, st, nil, quiet{})
			p.Run(context.Background())
			if status := p.Status(); !status.PoliciesLoaded || status.Reason != tc.reason {
				t.Errorf("Status() = %+v, want loaded with reason %q", status, tc.reason)
			}
			if st.count("policies") != 0 {
				t.Errorf("stored %d policies documents, want none", st.count("policies"))
			}
		})
	}
}

// TestLoad_PinsTheEntitlements: the entitlements PIP of the deployment is
// added to the PIP document as it is stored.
func TestLoad_PinsTheEntitlements(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	st := &store{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Entitlements: &pips.EntitlementsConfig{URL: "http://entitlements:8080", HTTPTimeoutSeconds: 2, HTTPRetries: 3}}, st, nil, quiet{})
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce() = %v", err)
	}
	remote, _ := st.last(t, "pips")["remote"].(map[string]any)
	entitlements, _ := remote["entitlements"].(map[string]any)
	if !reflect.DeepEqual(entitlements["url"], "http://entitlements:8080") {
		t.Errorf("data.pips.remote.entitlements = %v, want the pinned URL", entitlements)
	}
}
