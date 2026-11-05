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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	policiesPath = "/access/v1/simplifiedPolicies/domainPolicies/"
	pipsPath     = "/access/v1/simplifiedPolicies/domainPIPs/"
)

const bssPolicies = `[
  {"component":"BSS","resourceType":"Invoice","operation":"READ","roles":["ROLE_ADMIN"]}
]`

const ossPolicies = `[
  {"component":"OSS","resourceType":"Ticket","operation":"UPDATE","roles":["ROLE_ENGINEER"]}
]`

func newTestServer(t *testing.T, dataDir string) *http.ServeMux {
	t.Helper()
	return newTestServerWithDefaultTenantID(t, dataDir, defaultTenant)
}

// newTestServerWithDefaultTenantID is newTestServer whose export gives the
// default tenant the tenantId defaultTenantID.
func newTestServerWithDefaultTenantID(t *testing.T, dataDir, defaultTenantID string) *http.ServeMux {
	t.Helper()
	st, err := newStore(dataDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	mux := http.NewServeMux()
	(&server{st: st, defaultTenantID: defaultTenantID}).routes(mux)
	return mux
}

func do(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doWithTenantHeader(t, mux, method, path, body, "")
}

// doWithTenantHeader sends the request with the Tenant header set to tenant,
// or with no Tenant header when tenant is empty.
func doWithTenantHeader(t *testing.T, mux *http.ServeMux, method, path, body, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test")
	if tenant != "" {
		req.Header.Set("Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// Uploading one domain must not disturb another. This is the whole reason the
// store is keyed by the domain from the request path rather than holding one flat
// list: access-control scopes `PUT .../domainPolicies/BSS` to BSS, and the export
// the agent pulls is the union.
func TestDomainsAreIndependentAndExportIsTheUnion(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies); rec.Code != http.StatusOK {
		t.Fatalf("BSS upload: got %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, mux, http.MethodPut, policiesPath+"OSS", ossPolicies); rec.Code != http.StatusOK {
		t.Fatalf("OSS upload: got %d, body %s", rec.Code, rec.Body.String())
	}

	// Each domain still reads back its own content.
	for domain, want := range map[string]string{"BSS": "Invoice", "OSS": "Ticket"} {
		rec := do(t, mux, http.MethodGet, policiesPath+domain, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d", domain, rec.Code)
		}
		var items []simplifiedPolicy
		decode(t, rec.Body.Bytes(), &items)
		if len(items) != 1 || items[0].ResourceType != want {
			t.Errorf("GET %s returned %+v, want one policy on %s", domain, items, want)
		}
	}

	// The v3 export carries both, so the agent applies both.
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	domains := map[string]bool{}
	for _, ps := range resp.PolicySets {
		domains[ps.Domain] = true
	}
	if !domains["BSS"] || !domains["OSS"] {
		t.Errorf("v3 export covers %v, want both BSS and OSS", domains)
	}
}

// An unknown domain reads as an empty collection, which is what access-control
// answers for a domain nobody has uploaded yet.
func TestUnknownDomainReadsEmpty(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	rec := do(t, mux, http.MethodGet, policiesPath+"NOPE", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var items []simplifiedPolicy
	decode(t, rec.Body.Bytes(), &items)
	if len(items) != 0 {
		t.Errorf("got %d policies for an unused domain, want 0", len(items))
	}
}

// A restart must serve exactly the same policies under exactly the same hash:
// the puller caches the hash it applied, so a hash that changed for no reason
// costs a needless re-push, and a hash that repeated over different data would
// hide a real change.
func TestStoreReloadsPersistedDomainsWithSameHash(t *testing.T) {
	dir := t.TempDir()

	first := newTestServer(t, dir)
	do(t, first, http.MethodPut, policiesPath+"BSS", bssPolicies)
	do(t, first, http.MethodPut, policiesPath+"OSS", ossPolicies)
	do(t, first, http.MethodPut, pipsPath+"BSS", `[{"name":"tenant","pipType":"TOKEN","claim":"tenant_id"}]`)
	before := hashOf(t, first)

	second := newTestServer(t, dir)
	if got := hashOf(t, second); got != before {
		t.Errorf("hash changed across restart: %q → %q", before, got)
	}
	var resp v3PolicySetsResponse
	decode(t, do(t, second, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 2 {
		t.Errorf("reloaded %d policy sets, want 2 (one per domain)", len(resp.PolicySets))
	}

	raw, err := os.ReadFile(filepath.Join(dir, policiesFilePrefix+"BSS.json"))
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if string(raw) != bssPolicies {
		t.Errorf("persisted file is not the uploaded body verbatim:\n%s", raw)
	}
}

// The hash identifies content, not upload count: re-uploading the same policies
// formatted differently must not make the puller re-apply them.
func TestHashIsContentBased(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	original := hashOf(t, mux)

	reformatted := `[{"operation":"READ","roles":["ROLE_ADMIN"],"resourceType":"Invoice","component":"BSS"}]`
	do(t, mux, http.MethodPut, policiesPath+"BSS", reformatted)
	if got := hashOf(t, mux); got != original {
		t.Errorf("hash changed on a semantically identical upload: %q → %q", original, got)
	}

	changed := `[{"component":"BSS","resourceType":"Invoice","operation":"UPDATE","roles":["ROLE_ADMIN"]}]`
	do(t, mux, http.MethodPut, policiesPath+"BSS", changed)
	if got := hashOf(t, mux); got == original {
		t.Errorf("hash unchanged after the policies changed: %q", got)
	}
}

// Policies and PIPs carry independent hashes, so a PIP upload does not make the
// puller believe the policy set changed.
func TestPolicyAndPIPHashesAreIndependent(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	policiesHash := hashOf(t, mux)

	do(t, mux, http.MethodPut, pipsPath+"BSS", `[{"name":"tenant","pipType":"TOKEN","claim":"tenant_id"}]`)
	if got := hashOf(t, mux); got != policiesHash {
		t.Errorf("policy hash moved on a PIP upload: %q → %q", policiesHash, got)
	}

	var pipsResp v3PIPsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/pips", "").Body.Bytes(), &pipsResp)
	if pipsResp.Hash == policiesHash {
		t.Error("PIP and policy hashes are identical; they must be computed per collection")
	}
}

// An upload that cannot be persisted must be reported as a failure and must
// leave the served content untouched — a 200 whose data disappears on the next
// restart is the failure mode this ordering exists to prevent.
func TestFailedPersistKeepsPreviousContent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	mux := newTestServer(t, dir)
	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	before := hashOf(t, mux)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", `[]`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 when the data dir is read-only", rec.Code)
	}
	if got := hashOf(t, mux); got != before {
		t.Errorf("served content changed despite the failed write: %q → %q", before, got)
	}
	// A brand-new domain must not linger in memory either.
	if rec := do(t, mux, http.MethodPut, policiesPath+"FRESH", ossPolicies); rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d for a new domain, want 500", rec.Code)
	}
	var items []simplifiedPolicy
	decode(t, do(t, mux, http.MethodGet, policiesPath+"FRESH", "").Body.Bytes(), &items)
	if len(items) != 0 {
		t.Errorf("failed upload of a new domain left %d policies behind", len(items))
	}
}

// The PIP upload owes the same promise as the policy upload: a write that
// does not reach disk is a failure, and what the agent pulls is what the last
// upload that did reach disk left.
func TestFailedPIPPersistKeepsPreviousContent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	mux := newTestServer(t, dir)
	do(t, mux, http.MethodPut, pipsPath+"BSS", `[{"name":"tenant","pipType":"TOKEN","claim":"tenant_id"}]`)
	before := hashOf(t, mux)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if rec := do(t, mux, http.MethodPut, pipsPath+"BSS", `[]`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT of PIPs onto a read-only data dir = %d, want 500", rec.Code)
	}
	if got := hashOf(t, mux); got != before {
		t.Errorf("served content changed despite the failed write: %q -> %q", before, got)
	}
}

func TestNewStoreRejectsUnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := newStore(dir); err == nil {
		t.Fatal("newStore accepted a read-only data dir; the Pod must fail fast instead")
	}
}

// A SIGKILL between CreateTemp and Rename leaves a temp file behind. On a small
// PVC these would accumulate for the lifetime of the volume.
func TestNewStoreSweepsStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".acstub-deadbeef.json")
	if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}
	if _, err := newStore(dir); err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file survived startup: %v", err)
	}
}

// Malformed persisted data must not take the container down, and must not take
// the other domains with it: the file stays as evidence and its domain is empty.
func TestMalformedDomainFileSkipsOnlyThatDomain(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, policiesFilePrefix+"BROKEN.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, policiesFilePrefix+"BSS.json"), []byte(bssPolicies), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	mux := newTestServer(t, dir)
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 1 || resp.PolicySets[0].Domain != "BSS" {
		t.Errorf("got %+v, want only the BSS policy set", resp.PolicySets)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Errorf("malformed file was removed; it should be kept as evidence: %v", err)
	}
}

// seedUnreadable puts a directory where each kind of file belongs, so that
// reading one returns an error that is not "no such file", the absent case.
func seedUnreadable(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{policiesFilePrefix + "DIR.json", pipsFilePrefix + "DIR.json", stateFileName} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatalf("seed directory: %v", err)
		}
	}
}

// seedUnparsable writes content no JSON decoder accepts.
func seedUnparsable(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{pipsFilePrefix + "BROKEN.json", stateFileName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{not json"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
	}
}

// seedNotADomain writes a file whose name holds something the domain pattern
// refuses.
func seedNotADomain(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, policiesFilePrefix+"not a domain.json"), []byte(bssPolicies), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
}

// assertOnlyBSSSurvived fails unless the export and the status name the one
// domain the store could read.
func assertOnlyBSSSurvived(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 1 || resp.PolicySets[0].Domain != "BSS" {
		t.Errorf("the export holds %+v, want only the BSS policy set the store could read", resp.PolicySets)
	}
	var status struct {
		Revision int      `json:"revision"`
		Domains  []string `json:"domains"`
	}
	decode(t, do(t, mux, http.MethodGet, "/authz-policy-admin/hash", "").Body.Bytes(), &status)
	if status.Revision != 0 {
		t.Errorf("revision = %d, want 0: no state the store could read", status.Revision)
	}
	if len(status.Domains) != 1 || status.Domains[0] != "BSS" {
		t.Errorf("domains = %v, want BSS alone", status.Domains)
	}
}

// A restart reads whatever the volume holds, which is the last run's files
// plus anything an operator put there by hand. Each kind of unusable file is
// reported and skipped, and the domains the store can read still load: a stub
// that refused to start over one bad file would take the namespace's whole
// policy surface with it.
func TestUnusableFilesInTheDataDirectoryAreSkipped(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"a file the store cannot read":     seedUnreadable,
		"a file the store cannot parse":    seedUnparsable,
		"a file name that is not a domain": seedNotADomain,
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seed(t, dir)
			if err := os.WriteFile(filepath.Join(dir, policiesFilePrefix+"BSS.json"), []byte(bssPolicies), 0o644); err != nil {
				t.Fatalf("seed file: %v", err)
			}
			assertOnlyBSSSurvived(t, newTestServer(t, dir))
		})
	}
}

// The domain lands in a file name, so anything that could escape the data
// directory is refused rather than sanitised into a different domain.
func TestInvalidDomainIsRejected(t *testing.T) {
	mux := newTestServer(t, t.TempDir())

	// Reach the handler and fail validation.
	for _, domain := range []string{"has%20space", "sub%2Fdir", "quote%27", strings.Repeat("x", 65)} {
		rec := do(t, mux, http.MethodPut, policiesPath+domain, bssPolicies)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("domain %q: got %d, want 400", domain, rec.Code)
		}
	}

	// `.` and `..` never reach the handler: net/http cleans the path first and
	// answers a redirect. Either way no file is written for them.
	for _, domain := range []string{".", ".."} {
		rec := do(t, mux, http.MethodPut, policiesPath+domain, bssPolicies)
		if rec.Code == http.StatusOK {
			t.Errorf("domain %q was accepted (%d)", domain, rec.Code)
		}
	}
}

// access-control serves POST / PATCH / DELETE on the PIP path. This stub does
// not, and says so with 405 and an Allow header instead of a silent 404.
func TestUnsupportedMethodsAnswer405(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, pipsPath + "BSS"},
		{http.MethodPatch, pipsPath + "BSS"},
		{http.MethodDelete, pipsPath + "BSS"},
		{http.MethodPost, policiesPath + "BSS"},
	} {
		rec := do(t, mux, tc.method, tc.path, `[]`)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want 405", tc.method, tc.path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, PUT" {
			t.Errorf("%s %s: Allow header %q, want \"GET, PUT\"", tc.method, tc.path, allow)
		}
	}
}

// The v3 export is the agent's entry point and must keep rejecting an anonymous
// caller, because the real access-control does.
func TestV3ExportRequiresAuthorizationHeader(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	for _, p := range []string{"/access/v3/config/policySets", "/access/v3/config/pips"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without Authorization: got %d, want 401", p, rec.Code)
		}
	}
}

// In-memory mode (no AUTHZ_POLICY_ADMIN_DATA_DIR) is what the Compose test stacks run:
// uploads must work with no data directory at all.
func TestInMemoryModeServesUploads(t *testing.T) {
	mux := newTestServer(t, "")
	if rec := do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies); rec.Code != http.StatusOK {
		t.Fatalf("upload: got %d, body %s", rec.Code, rec.Body.String())
	}
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	if len(resp.PolicySets) != 1 {
		t.Errorf("got %d policy sets, want 1", len(resp.PolicySets))
	}
}

// The health probe reports the domains it holds, which is the first thing anyone
// debugging "my policies did not arrive" wants to see.
func TestHashEndpointListsDomains(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	do(t, mux, http.MethodPut, policiesPath+"BSS", bssPolicies)
	do(t, mux, http.MethodPut, pipsPath+"OSS", `[]`)
	do(t, mux, http.MethodPut, pipsPath+"support?tenant_id=tenant-a", `[]`)

	var status struct {
		Domains []string `json:"domains"`
		Hash    string   `json:"hash"`
	}
	decode(t, do(t, mux, http.MethodGet, "/authz-policy-admin/hash", "").Body.Bytes(), &status)
	if fmt.Sprint(status.Domains) != "[BSS OSS tenant-a/support]" {
		t.Errorf("domains %v, want [BSS OSS tenant-a/support]", status.Domains)
	}
	if status.Hash == "" {
		t.Error("hash is empty")
	}
}

// The agent rejects an export whose policySets is null, so an empty store has
// to export an empty array.
func TestEmptyStoreExportsEmptyArrays(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	for _, tc := range []struct{ path, field string }{
		{"/access/v3/config/policySets", "policySets"},
		{"/access/v3/config/pips", "pips"},
	} {
		var resp map[string]json.RawMessage
		decode(t, do(t, mux, http.MethodGet, tc.path, "").Body.Bytes(), &resp)
		if got := string(resp[tc.field]); got != "[]" {
			t.Errorf("GET %s: %s = %s, want []", tc.path, tc.field, got)
		}
	}
}

// Each tenant holds its own collection for a domain, and the export stamps
// every policy set and PIP with the tenant that uploaded it. The tenant is the
// tenant_id query parameter, else the Tenant header, else "default".
func TestTenantsKeepSeparateCollectionsOfOneDomain(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	uploads := []struct {
		name, query, header, resourceType string
	}{
		{name: "default", resourceType: "Invoice"},
		{name: "query", query: "?tenant_id=tenant-a", resourceType: "Ticket"},
		{name: "header", header: "tenant-b", resourceType: "Order"},
		{name: "query over header", query: "?tenant_id=tenant-c", header: "tenant-b-ignored", resourceType: "Quote"},
	}
	for _, u := range uploads {
		body := `[{"component":"billing","resourceType":"` + u.resourceType + `","operation":"READ","roles":["ROLE_ADMIN"]}]`
		if rec := doWithTenantHeader(t, mux, http.MethodPut, policiesPath+"billing"+u.query, body, u.header); rec.Code != http.StatusOK {
			t.Fatalf("%s policy upload: got %d, body %s", u.name, rec.Code, rec.Body.String())
		}
		pip := `[{"name":"subject.org","pipType":"TOKEN","claim":"` + u.resourceType + `"}]`
		if rec := doWithTenantHeader(t, mux, http.MethodPut, pipsPath+"billing"+u.query, pip, u.header); rec.Code != http.StatusOK {
			t.Fatalf("%s PIP upload: got %d, body %s", u.name, rec.Code, rec.Body.String())
		}
	}

	for _, tc := range []struct{ query, header, want string }{
		{"", "", "Invoice"},
		{"?tenant_id=tenant-a", "", "Ticket"},
		{"", "tenant-b", "Order"},
		{"?tenant_id=tenant-c", "", "Quote"},
		{"", "tenant-b-ignored", ""},
	} {
		var items []simplifiedPolicy
		decode(t, doWithTenantHeader(t, mux, http.MethodGet, policiesPath+"billing"+tc.query, "", tc.header).Body.Bytes(), &items)
		var got []string
		for _, p := range items {
			got = append(got, p.ResourceType)
		}
		if want := tc.want; fmt.Sprint(got) != fmt.Sprint(strings.Fields(want)) {
			t.Errorf("GET billing%s with Tenant %q: resource types %v, want [%s]", tc.query, tc.header, got, want)
		}
	}

	var sets v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &sets)
	gotSets := map[string]string{}
	for _, ps := range sets.PolicySets {
		gotSets[ps.TenantID] = ps.Target
	}
	wantSets := map[string]string{
		"default":  "resourceType == 'Invoice'",
		"tenant-a": "resourceType == 'Ticket'",
		"tenant-b": "resourceType == 'Order'",
		"tenant-c": "resourceType == 'Quote'",
	}
	if fmt.Sprint(gotSets) != fmt.Sprint(wantSets) {
		t.Errorf("policy set targets by tenantId = %v, want %v", gotSets, wantSets)
	}

	var pips v3PIPsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/pips", "").Body.Bytes(), &pips)
	gotPIPs := map[string]string{}
	for _, p := range pips.PIPs {
		gotPIPs[p.TenantID] = p.Claim
	}
	wantPIPs := map[string]string{"default": "Invoice", "tenant-a": "Ticket", "tenant-b": "Order", "tenant-c": "Quote"}
	if fmt.Sprint(gotPIPs) != fmt.Sprint(wantPIPs) {
		t.Errorf("PIP claims by tenantId = %v, want %v", gotPIPs, wantPIPs)
	}
}

// A collection of a tenant other than the default one survives a restart under
// that tenant, and the default tenant keeps the file name it had before
// uploads were kept per tenant.
func TestStoreReloadsTenantCollections(t *testing.T) {
	dir := t.TempDir()
	first := newTestServer(t, dir)
	do(t, first, http.MethodPut, policiesPath+"billing", `[{"component":"billing","resourceType":"Invoice","operation":"READ","roles":["ROLE_ADMIN"]}]`)
	do(t, first, http.MethodPut, policiesPath+"support?tenant_id=tenant-a", `[{"component":"support","resourceType":"Ticket","operation":"UPDATE","roles":["ROLE_ENGINEER"]}]`)
	before := hashOf(t, first)

	for _, name := range []string{policiesFilePrefix + "billing.json", policiesFilePrefix + "tenant-a@support.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("data file %s: %v", name, err)
		}
	}

	second := newTestServer(t, dir)
	if got := hashOf(t, second); got != before {
		t.Errorf("hash changed across restart: %q → %q", before, got)
	}
	var resp v3PolicySetsResponse
	decode(t, do(t, second, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	got := map[string]string{}
	for _, ps := range resp.PolicySets {
		got[ps.Domain] = ps.TenantID
	}
	if want := map[string]string{"billing": "default", "support": "tenant-a"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("reloaded tenantId by domain = %v, want %v", got, want)
	}
}

// The export gives the default tenant the configured tenantId, which a
// stand sets to the ID tenant-manager resolves the default tenant to, and
// leaves the tenant an upload named as it is.
func TestTheDefaultTenantIsExportedUnderItsConfiguredID(t *testing.T) {
	mux := newTestServerWithDefaultTenantID(t, t.TempDir(), "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b")
	do(t, mux, http.MethodPut, policiesPath+"billing", `[{"component":"billing","resourceType":"Invoice","operation":"READ","roles":["ROLE_ADMIN"]}]`)
	do(t, mux, http.MethodPut, policiesPath+"billing?tenant_id=tenant-a", `[{"component":"billing","resourceType":"Ticket","operation":"READ","roles":["ROLE_ADMIN"]}]`)
	do(t, mux, http.MethodPut, pipsPath+"billing", `[{"name":"subject.org","pipType":"TOKEN","claim":"org"}]`)

	var sets v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &sets)
	got := map[string]string{}
	for _, ps := range sets.PolicySets {
		got[ps.TenantID] = ps.Target
	}
	want := map[string]string{"6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b": "resourceType == 'Invoice'", "tenant-a": "resourceType == 'Ticket'"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("policy set targets by tenantId = %v, want %v", got, want)
	}
	var pips v3PIPsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/pips", "").Body.Bytes(), &pips)
	if len(pips.PIPs) != 1 || pips.PIPs[0].TenantID != "6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b" {
		t.Errorf("PIPs = %+v, want one PIP of tenantId 6f1c2a9e-3b4d-4e8f-9a1b-2c3d4e5f6a7b", pips.PIPs)
	}
}

// A tenant names a data file, so a tenant that is not a legal name is
// refused with 400 and writes nothing.
func TestInvalidTenantIsRejected(t *testing.T) {
	dir := t.TempDir()
	mux := newTestServer(t, dir)
	for _, tc := range []struct{ name, query, header string }{
		{"a path in the query", "?tenant_id=..%2Fx", ""},
		{"an @ in the header", "", "a@b"},
	} {
		rec := doWithTenantHeader(t, mux, http.MethodPut, policiesPath+"billing"+tc.query, `[]`, tc.header)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", tc.name, rec.Code)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(files) != 0 {
		t.Errorf("data files after the refused uploads = %v, want none", files)
	}
}

func hashOf(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	var resp v3PolicySetsResponse
	decode(t, do(t, mux, http.MethodGet, "/access/v3/config/policySets", "").Body.Bytes(), &resp)
	return resp.Hash
}

func decode(t *testing.T, raw []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode response: %v (%s)", err, raw)
	}
}
