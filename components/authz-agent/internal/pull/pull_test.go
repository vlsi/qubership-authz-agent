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
)

// policySets is a v3 policy-sets response; the puller hands it on as sent.
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

// pipsResponse is a v3 PIPs response; the puller hands it on as sent.
const pipsResponse = `{
  "hash": "hash-pip-v1",
  "lastModificationTimestamp": "2026-01-01T00:00:00",
  "pips": [
    {"name": "subject.azp", "pipType": "TOKEN", "claim": "azp", "domain": "TestDomain", "tenantId": "default"},
    {"name": "subject.filtered", "pipType": "FILTERED", "domain": "TestDomain", "tenantId": "default"}
  ]
}`

// loader records the documents of every load; err, when set, is what
// every load returns.
type loader struct {
	mu    sync.Mutex
	loads [][2]string
	err   error
}

func (l *loader) LoadSnapshots(_ context.Context, policySets, pips []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loads = append(l.loads, [2]string{string(policySets), string(pips)})
	return l.err
}

func (l *loader) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.loads)
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
// bearer token, hands them to the snapshots as the source sent them, and
// reports the policies loaded.
func TestRun_LoadsTheSource(t *testing.T) {
	srv, authorization := source(t, http.StatusOK)
	snaps := &loader{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Snapshots: snaps}, readyTokens("tok"), quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "the first load", func() bool { return p.Status().PoliciesLoaded })
	if status := p.Status(); status.FirstSuccessAt == "" || status.Reason != "" {
		t.Errorf("Status() = %+v, want a first success time and no reason", status)
	}
	if *authorization != "Bearer tok" {
		t.Errorf("Authorization sent = %q, want Bearer tok", *authorization)
	}
	snaps.mu.Lock()
	defer snaps.mu.Unlock()
	if len(snaps.loads) == 0 || snaps.loads[0] != [2]string{policySets, pipsResponse} {
		t.Errorf("loads = %q, want the two documents as sent", snaps.loads)
	}
}

// TestRun_ReportsTheFirstLoadAtInfoAndTheRestAtDebug: every tick loads the
// source again, changed or not, so the loads after the first one repeat what
// the first one said. Only the first is reported at info; at the default
// interval of 30 seconds the rest would be 2880 identical lines a day.
func TestRun_ReportsTheFirstLoadAtInfoAndTheRestAtDebug(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	rec := &recorder{}
	p := New(Config{SourceURL: srv.URL, Interval: 20 * time.Millisecond}, nil, rec)
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

// TestPullOnce_LoadsNothingOnFailure: a source that fails hands nothing to
// the snapshots and returns the error.
func TestPullOnce_LoadsNothingOnFailure(t *testing.T) {
	failing, _ := source(t, http.StatusInternalServerError)
	snaps := &loader{}
	p := New(Config{SourceURL: failing.URL, Interval: time.Hour, Snapshots: snaps}, nil, quiet{})
	if err := p.PullOnce(context.Background()); err == nil {
		t.Fatal("PullOnce() = nil, want an error")
	}
	if snaps.count() != 0 || p.Status().PoliciesLoaded {
		t.Errorf("after the failure: %d loads, status %+v; want none and not loaded", snaps.count(), p.Status())
	}
}

// TestPull_KeepsTheLoadedPoliciesWhenALaterPullFails: once a pull has loaded
// the source, a pull that fails loads nothing, and the status that /health
// and /ready read stays as the successful pull set it.
func TestPull_KeepsTheLoadedPoliciesWhenALaterPullFails(t *testing.T) {
	healthy, _ := source(t, http.StatusOK)
	failing, _ := source(t, http.StatusInternalServerError)
	snaps := &loader{}
	p := New(Config{SourceURL: healthy.URL, Interval: time.Hour, Snapshots: snaps}, nil, quiet{})
	p.pull(context.Background())
	loaded := p.Status()
	if !loaded.PoliciesLoaded || snaps.count() != 1 {
		t.Fatalf("after the first pull: %d loads, status %+v; want one load and loaded", snaps.count(), loaded)
	}

	p.cfg.SourceURL = failing.URL
	p.pull(context.Background())
	if got := p.Status(); !reflect.DeepEqual(got, loaded) {
		t.Errorf("Status() after the failed pull = %+v, want %+v", got, loaded)
	}
	if snaps.count() != 1 {
		t.Errorf("loads after the failed pull = %d, want the one from the first pull", snaps.count())
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
	snaps := &loader{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Snapshots: snaps}, expired, quiet{})

	err := p.PullOnce(context.Background())

	if err == nil || !strings.Contains(err.Error(), "no token to present: m2m token: expired") {
		t.Errorf("PullOnce() = %v, want the error of the token source", err)
	}
	if n := requests.Load(); n != 0 || snaps.count() != 0 {
		t.Errorf("requests at the source = %d, loads = %d; want 0 and 0", n, snaps.count())
	}
}

// TestPullOnce_WithoutTokens: with no token source the fetch carries no
// Authorization header.
func TestPullOnce_WithoutTokens(t *testing.T) {
	srv, authorization := source(t, http.StatusOK)
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour}, nil, quiet{})
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
			snaps := &loader{}
			tc.cfg.Snapshots = snaps
			p := New(tc.cfg, nil, quiet{})
			p.Run(context.Background())
			if status := p.Status(); !status.PoliciesLoaded || status.Reason != tc.reason {
				t.Errorf("Status() = %+v, want loaded with reason %q", status, tc.reason)
			}
			if snaps.count() != 0 {
				t.Errorf("loads = %d, want none", snaps.count())
			}
		})
	}
}

// TestPullOnce_ReportsAFailedLoad: documents the snapshots cannot read fail
// the pull with the snapshots' error, and the policies are not loaded.
func TestPullOnce_ReportsAFailedLoad(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	snaps := &loader{err: errors.New("the export names no tenant")}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Snapshots: snaps}, nil, quiet{})
	p.pull(context.Background())

	err := p.PullOnce(context.Background())

	if err == nil || !strings.Contains(err.Error(), "load snapshots: the export names no tenant") {
		t.Errorf("PullOnce() = %v, want the error of the snapshots", err)
	}
	if p.Status().PoliciesLoaded {
		t.Errorf("Status() = %+v, want not loaded", p.Status())
	}
}

// refusal is an error of a load that published part of the tenants.
type refusal string

func (e refusal) Error() string { return string(e) }
func (refusal) Partial() bool   { return true }

// TestPull_APartialLoadMarksThePoliciesLoaded: a load that refused a tenant
// and published the others releases readiness, and PullOnce still returns
// the refusal to its caller.
func TestPull_APartialLoadMarksThePoliciesLoaded(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	snaps := &loader{err: refusal("tenant a: candidate snapshot refused")}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Snapshots: snaps}, nil, quiet{})

	p.pull(context.Background())

	if !p.Status().PoliciesLoaded {
		t.Errorf("Status() after a partial load = %+v, want loaded", p.Status())
	}
	var partial PartialLoad
	if err := p.PullOnce(context.Background()); !errors.As(err, &partial) {
		t.Errorf("PullOnce() = %v, want the partial load of the snapshots", err)
	}
}

// TestPull_ReportsARefusalWhenItChanges: a refusal is reported at warn on
// the pull where it first appears or its text changes, not on every pull
// that repeats it, and the pull that ends it is reported at info.
func TestPull_ReportsARefusalWhenItChanges(t *testing.T) {
	srv, _ := source(t, http.StatusOK)
	snaps := &loader{}
	rec := &recorder{}
	p := New(Config{SourceURL: srv.URL, Interval: time.Hour, Snapshots: snaps}, nil, rec)
	for _, err := range []error{
		refusal("tenant a: refused"),
		refusal("tenant a: refused"),
		errors.New("source unreachable"),
		refusal("tenant a: refused"),
		refusal("tenant a: refused; tenant b: refused"),
		nil,
		nil,
	} {
		snaps.mu.Lock()
		snaps.err = err
		snaps.mu.Unlock()
		p.pull(context.Background())
	}

	var got []string
	for _, line := range rec.lines {
		if !strings.Contains(line, "policies: updated") && !strings.Contains(line, "pull failed") {
			got = append(got, line)
		}
	}
	want := []string{
		"warn: policies: pulled from " + srv.URL + ", and some tenants are not updated: load snapshots: tenant a: refused",
		"warn: policies: pulled from " + srv.URL + ", and some tenants are not updated: load snapshots: tenant a: refused; tenant b: refused",
		"info: policies: pulled from " + srv.URL + ", and every tenant is updated",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
