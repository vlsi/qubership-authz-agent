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

package snapshot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

var table *spectables.Table

func tab(t *testing.T) *spectables.Table {
	t.Helper()
	if table == nil {
		var err error
		if table, err = regogen.DefaultTable(); err != nil {
			t.Fatalf("DefaultTable: %v", err)
		}
	}
	return table
}

// set is a policy set of tenant whose one rule allows the operation read on
// the resource type doc where condition holds.
func set(tenant, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": %[2]q, "effect": "ALLOW", "tenantId": %[1]q}]}]}`, tenant, condition)
}

func load(t *testing.T, r *Registry, pips string, sets ...string) LoadSummary {
	t.Helper()
	sum, err := r.Load(context.Background(), []byte(`{"policySets": [`+strings.Join(sets, ",")+`]}`),
		[]byte(`{"pips": [`+pips+`]}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return sum
}

// readDoc is a request of the user u1 to read a doc whose member a is a.
func readDoc(t *testing.T, tenant, a string, items int) Request {
	t.Helper()
	return readDocAs(t, "u1", tenant, a, items)
}

// readDocAs is readDoc of the user sub.
func readDocAs(t *testing.T, sub, tenant, a string, items int) Request {
	t.Helper()
	claims, err := jsonvalue.Decode([]byte(`{"sub": "` + sub + `", "preferred_username": "alice",
		"realm_access": {"roles": ["R"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Tenant: tenant, Claims: claims.(*jsonvalue.Object), Headers: map[string]string{}}
	for range items {
		req.Items = append(req.Items, regogen.Body{Operation: "read", ResourceType: "doc",
			Resource: mustObject(t, `{"a": "`+a+`"}`), HasResource: true})
	}
	return req
}

func mustObject(t *testing.T, s string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func decide(t *testing.T, r *Registry, req Request) []Result {
	t.Helper()
	got, err := r.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide(%s): %v", req.Tenant, err)
	}
	return got
}

func tenantHealth(r *Registry, tenant string) (TenantHealth, bool) {
	for _, th := range r.Health().Tenants {
		if th.Tenant == tenant {
			return th, true
		}
	}
	return TenantHealth{}, false
}

// A tenant is decided by the sets that carry its tenantId alone: a set of
// tenant a that allows every doc allows nothing in tenant b, and a tenant
// the export does not name denies with the reason that names it.
func TestEachTenantIsDecidedByItsOwnPolicies(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", "resource.a == 'x'"))

	for _, tc := range []struct {
		tenant, a string
		want      Result
	}{
		{"a", "y", Result{Allowed: true}},
		{"b", "y", Result{Reason: ReasonDenied}},
		{"b", "x", Result{Allowed: true}},
		{"c", "x", Result{Reason: "no policies are published for tenant c"}},
	} {
		if got := decide(t, r, readDoc(t, tc.tenant, tc.a, 1)); got[0] != tc.want {
			t.Errorf("Decide(tenant %s, a=%s) = %+v, want %+v", tc.tenant, tc.a, got[0], tc.want)
		}
	}
}

// broken is a condition the agent's parser refuses, which rejects the
// candidate of its tenant as a whole.
const broken = "resource.a =="

// A tenant whose new candidate is refused keeps answering from its previous
// snapshot and names the refusal in its health, while another tenant of the
// same load is published.
func TestARefusedCandidateKeepsThePreviousSnapshot(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", "resource.a == 'x'"))
	sum := load(t, r, ``, set("a", broken), set("b", "true"))

	if sum.Rejected != 1 || sum.Generated != 1 {
		t.Errorf("Load summary = %+v, want 1 refused and 1 generated", sum)
	}
	if got := decide(t, r, readDoc(t, "a", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant a) = %+v, want allowed by the previous snapshot", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant b) = %+v, want allowed by the new snapshot", got[0])
	}
	th, _ := tenantHealth(r, "a")
	if !th.Ready || th.Rejected == nil || th.Rejected.Stage != "unsupported" || len(th.Rejected.Forms) == 0 {
		t.Errorf("health of a = %+v, want ready with a refusal at stage unsupported naming the form", th)
	}
}

// On its first load a refused tenant has no snapshot: it is not ready and
// denies every request, and the other tenants are served.
func TestATenantRefusedOnItsFirstLoadIsNotServed(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", broken), set("b", "true"))

	if got := decide(t, r, readDoc(t, "a", "y", 1)); got[0].Allowed || got[0].Reason != "no policies are published for tenant a" {
		t.Errorf("Decide(tenant a) = %+v, want denied as unpublished", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide(tenant b) = %+v, want allowed", got[0])
	}
	if th, _ := tenantHealth(r, "a"); th.Ready || th.Rejected == nil {
		t.Errorf("health of a = %+v, want not ready with the refusal", th)
	}
}

// A load in which a tenant's tree is unchanged keeps the tenant's snapshot
// as it was, and an unchanged refused tree is neither generated nor counted
// as refused again.
func TestAnUnchangedTreeIsNotGeneratedAgain(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, ``, set("a", "true"), set("b", broken))
	before, _ := r.Snapshot("a")
	sum := load(t, r, ``, set("a", "true"), set("b", broken), set("c", "true"))

	if after, _ := r.Snapshot("a"); after != before {
		t.Errorf("snapshot of a after an unchanged load = %p, want the same %p", after, before)
	}
	if sum.Kept != 1 || sum.Generated != 1 || sum.Rejected != 0 {
		t.Errorf("Load summary = %+v, want a kept, c generated, and b not refused again", sum)
	}
}

// pipServer answers every call with body and counts the calls.
func pipServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func pipRegistry(t *testing.T) *Registry {
	t.Helper()
	return New(Config{HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
}

func generalPIP(url, cacheable string) string {
	return `{"tenantId": "a", "name": "subject.g", "pipType": "GENERAL", "url": "` + url +
		`", "httpMethod": "GET"` + cacheable + `}`
}

// The items of one bulk request share one call of the PIP, and the next
// decision request calls it again, though the PIP declares itself
// cacheable: no answer outlives its decision request.
func TestTheItemsOfABulkRequestShareOneCall(t *testing.T) {
	srv, calls := pipServer(t, http.StatusOK, `["x"]`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, `, "cacheable": true`), set("a", "subject.g == 'x'"))

	decide(t, r, readDoc(t, "a", "y", 5))
	if n := calls.Load(); n != 1 {
		t.Errorf("calls of the PIP for a bulk of 5 = %d, want 1", n)
	}
	decide(t, r, readDoc(t, "a", "y", 1))
	if n := calls.Load(); n != 2 {
		t.Errorf("calls of the PIP after the next request = %d, want 2", n)
	}
}

// A denial that rests on a source the agent cannot read names it.
func TestADenialOnAnUnreadSourceNamesIt(t *testing.T) {
	for _, tc := range []struct {
		name, pips, set, want string
	}{
		{"an undeclared PIP", ``, set("a", "subject.entitledResources == 'x'"),
			ReasonUnknown + ": subject.entitledResources"},
		{"entitlements without the service's URL", ``,
			set("a", "subject.entitledResources.of('doc').as('owner') CONTAINS resource.a"),
			ReasonUnknown + `: ["ent","doc",["owner"]]`},
		{"a permission scope without a PERMISSION_SCOPE PIP", ``, scopeSet("a"), ReasonUnknown + ": subject.permissionScope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(Config{}, tab(t), quiet{})
			load(t, r, tc.pips, tc.set)

			got := decide(t, r, readDoc(t, "a", "y", 1))

			if want := (Result{Reason: tc.want}); got[0] != want {
				t.Errorf("Decide = %+v, want %+v", got[0], want)
			}
		})
	}
}

// A denial that rests on a PIP whose call failed names the PIP.
func TestADenialOnAFailedPIPNamesIt(t *testing.T) {
	srv, _ := pipServer(t, http.StatusInternalServerError, `oops`)
	r := pipRegistry(t)
	load(t, r, generalPIP(srv.URL, ""), set("a", "subject.g == 'x'"))

	got := decide(t, r, readDoc(t, "a", "y", 1))

	if want := (Result{Reason: "PIP resolution failed: subject.g"}); got[0] != want {
		t.Errorf("Decide = %+v, want %+v", got[0], want)
	}
}

// scopeSet is a policy set of tenant that iterates over the permission
// scope and allows the operation read on a doc whose member a is a domain
// of the pass.
func scopeSet(tenant string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"iterate": {"foreach": "subject.permissionScope", "combiningAlgorithm": "DENY_UNLESS_PERMIT"},
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": "subject.permissionScope.domain CONTAINS resource.a", "effect": "ALLOW", "tenantId": %[1]q}]}]}`,
		tenant)
}

// A role the tenant's MAPPING PIP maps grants its permissions, which a
// condition on subject.permissions reads.
func TestTheMappingTablesGrantPermissions(t *testing.T) {
	r := New(Config{}, tab(t), quiet{})
	load(t, r, `{"tenantId": "a", "name": "subject.permissions", "pipType": "MAPPING",
		"customMapping": {"subject.roles": {"r": ["p1"]}}}`,
		set("a", "subject.permissions CONTAINS 'p1'"), set("b", "subject.permissions CONTAINS 'p1'"))

	if got := decide(t, r, readDoc(t, "a", "y", 1)); !got[0].Allowed {
		t.Errorf("Decide with the role R mapped to p1 = %+v, want allowed", got[0])
	}
	if got := decide(t, r, readDoc(t, "b", "y", 1)); got[0] != (Result{Reason: ReasonDenied}) {
		t.Errorf("Decide in a tenant without the mapping = %+v, want %+v", got[0], Result{Reason: ReasonDenied})
	}
}

// countingServer answers every POST of path with body, any other request
// with 404, and counts the requests.
func countingServer(t *testing.T, path, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// The items of a bulk request share one call of the entitlements service.
func TestTheEntitlementsServiceIsCalledOncePerRequest(t *testing.T) {
	srv, calls := countingServer(t, "/api/v3/user-entitlements/user/u1", `{"entitlements": [{"resourceType": "doc",
		"references": [{"name": "owner", "resources": [{"resourceId": "y"}]}]}]}`)
	r := New(Config{Entitlements: srv.URL, HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
	load(t, r, ``, set("a", "subject.entitledResources.of('doc').as('owner') CONTAINS resource.a"))

	got := decide(t, r, readDoc(t, "a", "y", 3))

	if !got[0].Allowed || !got[2].Allowed {
		t.Errorf("Decide of the entitled doc y = %+v, want every item allowed", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("calls of the entitlements service = %d, want 1", n)
	}
	if got := decide(t, r, readDoc(t, "a", "z", 1)); got[0].Allowed {
		t.Errorf("Decide of the doc z the service does not grant = %+v, want denied", got[0])
	}
}

// The items of a bulk request share one read of the permission scope, at
// the url of the tenant's PERMISSION_SCOPE PIP.
func TestThePermissionScopeIsReadOncePerRequest(t *testing.T) {
	srv, calls := countingServer(t, "/api/v1/permission-scope/user/u1/policies",
		`{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": [{"id": "y"}]}]}]}]}`)
	r := New(Config{HTTP: &regobuiltins.HTTP{Client: &http.Client{},
		Token: func() (string, error) { return "own", nil }}}, tab(t), quiet{})
	load(t, r, `{"tenantId": "a", "name": "subject.permissionScope", "pipType": "PERMISSION_SCOPE", "url": "`+srv.URL+`"}`,
		scopeSet("a"))

	got := decide(t, r, readDoc(t, "a", "y", 2))

	if !got[0].Allowed || !got[1].Allowed {
		t.Errorf("Decide of the doc y in the scope = %+v, want every item allowed", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("reads of the permission scope = %d, want 1", n)
	}
	if got := decide(t, r, readDoc(t, "a", "z", 1)); got[0].Allowed {
		t.Errorf("Decide of the doc z outside the scope = %+v, want denied", got[0])
	}
}
