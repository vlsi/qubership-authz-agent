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
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// tenantManager answers the lookup of the display name acme with answers
// in turn, the last one from then on, and counts the lookups.
func tenantManager(t *testing.T, answers ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if r.URL.Path != tenantLookupPath || r.URL.Query().Get("dns") != "acme" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		a := answers[min(i, len(answers)-1)]
		if a == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(a + "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// The default tenant is its display name until tenant-manager resolves it,
// which Run retries until it does.
func TestDefaultTenant_IsResolvedOnceTenantManagerAnswers(t *testing.T) {
	srv, lookups := tenantManager(t, "", "0b9e-acme")
	d := newDefaultTenant("acme", srv.URL+"/")
	if got := d.Get(); got != "acme" {
		t.Fatalf("Get before Run = %q, want the display name acme", got)
	}

	d.Run(context.Background(), time.Millisecond)

	if got := d.Get(); got != "0b9e-acme" || lookups.Load() != 2 {
		t.Errorf("Get after Run = %q after %d lookups, want 0b9e-acme after 2", got, lookups.Load())
	}
}

// An answer that is not a tenant ID leaves the display name in place.
func TestDefaultTenant_RefusesAnAnswerThatIsNotAnID(t *testing.T) {
	srv, _ := tenantManager(t, `{"id": "x"}`)
	d := newDefaultTenant("acme", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	d.Run(ctx, time.Millisecond)

	if got := d.Get(); got != "acme" {
		t.Errorf("Get = %q, want the display name acme", got)
	}
}

// Without a tenant-manager URL the display name is the ID.
func TestDefaultTenant_WithoutTenantManagerKeepsTheName(t *testing.T) {
	d := newDefaultTenant("acme", " ")
	d.Run(context.Background(), time.Millisecond)
	if got := d.Get(); got != "acme" {
		t.Errorf("Get = %q, want acme", got)
	}
}
