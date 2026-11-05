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
	"io"
	"net/http"
	"sync"
	"time"
)

// maxBodyBytes caps an upload.
const maxBodyBytes = 10 << 20

// server wires the HTTP surface to the store.
//
// The paths are access-control's own, prefix included: this stub stands in for
// access-control, so the endpoints it supports have to be reachable at the URLs
// access-control serves them at (authz-agent-ADR-0073). Nothing here is
// authenticated, which is why the stub is limited to development and test
// namespaces.
type server struct {
	st *store
	// defaultTenantID is the tenantId of the default tenant in the export.
	defaultTenantID string
	// requireDeclaredPIPs refuses a policy whose condition reads a PIP that
	// the tenant has not declared yet, as access-control does.
	requireDeclaredPIPs bool
	// uploads serializes the uploads, so that the checks of one read what the
	// tenant declared before it and no other upload commits in between.
	uploads sync.Mutex
}

func (s *server) routes(mux *http.ServeMux) {
	// Simplified-policy API — access-control's northbound config surface.
	// GET and PUT are what this stub supports; access-control also serves
	// POST / PATCH / DELETE on the PIP path, and those answer 405 here rather
	// than pretending to work.
	mux.HandleFunc("GET /access/v1/simplifiedPolicies/domainPolicies/{domainName}", s.handleGetDomainPolicies)
	mux.HandleFunc("PUT /access/v1/simplifiedPolicies/domainPolicies/{domainName}", s.handlePutDomainPolicies)
	mux.HandleFunc("/access/v1/simplifiedPolicies/domainPolicies/{domainName}", methodNotAllowed("GET, PUT"))
	mux.HandleFunc("GET /access/v1/simplifiedPolicies/domainPIPs/{domainName}", s.handleGetDomainPIPs)
	mux.HandleFunc("PUT /access/v1/simplifiedPolicies/domainPIPs/{domainName}", s.handlePutDomainPIPs)
	mux.HandleFunc("/access/v1/simplifiedPolicies/domainPIPs/{domainName}", methodNotAllowed("GET, PUT"))

	// v3 config export — what the agent's PolicyPuller reads. Serves the union
	// of every domain.
	mux.HandleFunc("GET /access/v3/config/policySets", s.handleV3PolicySets)
	mux.HandleFunc("GET /access/v3/config/pips", s.handleV3PIPs)

	// The one stub-specific route left: the container health probe. It carries
	// no policy content.
	mux.HandleFunc("GET /authz-policy-admin/hash", s.handleHash)

	mux.HandleFunc("/", handleNotFound)
}

// ── Simplified-policy API ─────────────────────────────────────────────────────

func (s *server) handleGetDomainPolicies(w http.ResponseWriter, r *http.Request) {
	tenant, domain, ok := requestScope(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.st.DomainPolicies(tenant, domain))
}

func (s *server) handlePutDomainPolicies(w http.ResponseWriter, r *http.Request) {
	tenant, domain, ok := requestScope(w, r)
	if !ok {
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	s.uploads.Lock()
	defer s.uploads.Unlock()
	objects, err := decodeUpload(raw)
	if err == nil {
		var declared map[string]bool
		if s.requireDeclaredPIPs {
			declared = s.st.TenantPIPNames(tenant)
		}
		if why := validatePolicies(objects, declared); why != nil {
			writeJSON(w, why.status, map[string]string{"error": why.reason})
			return
		}
		raw, err = coerceTexts(raw, objects, policyTexts, false)
	}
	var items []simplifiedPolicy
	if err == nil {
		err = json.Unmarshal(raw, &items)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.st.SetDomainPolicies(tenant, domain, items, raw); err != nil {
		// The upload did not reach disk, so it is not committed in memory
		// either. Telling the caller beats a 200 that quietly evaporates on
		// the next restart.
		logger.Errorf("policy upload of tenant %q for domain %q rejected: %v", tenant, domain, err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	policiesHash, _, revision := s.st.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated", "domain": domain, "count": len(items),
		"hash": policiesHash, "revision": revision,
	})
}

func (s *server) handleGetDomainPIPs(w http.ResponseWriter, r *http.Request) {
	tenant, domain, ok := requestScope(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.st.DomainPIPs(tenant, domain))
}

func (s *server) handlePutDomainPIPs(w http.ResponseWriter, r *http.Request) {
	tenant, domain, ok := requestScope(w, r)
	if !ok {
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	s.uploads.Lock()
	defer s.uploads.Unlock()
	objects, err := decodeUpload(raw)
	if err == nil {
		trimmed := trimPIPEnums(objects)
		if why := validatePIPs(objects, domain, s.st.TenantPIPs(tenant)); why != nil {
			writeJSON(w, why.status, map[string]string{"error": why.reason})
			return
		}
		raw, err = coerceTexts(raw, objects, pipTexts, trimmed)
	}
	var items []simplifiedPIP
	if err == nil {
		err = json.Unmarshal(raw, &items)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.st.SetDomainPIPs(tenant, domain, items, raw); err != nil {
		logger.Errorf("PIP upload of tenant %q for domain %q rejected: %v", tenant, domain, err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_, pipsHash, revision := s.st.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated", "domain": domain, "count": len(items),
		"hash": pipsHash, "revision": revision,
	})
}

// ── v3 config export ──────────────────────────────────────────────────────────

func (s *server) handleV3PolicySets(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
		return
	}
	policies, hash := s.st.Policies()
	writeJSON(w, http.StatusOK, v3PolicySetsResponse{
		Hash:                      hash,
		LastModificationTimestamp: timestamp(),
		PolicySets:                toV3PolicySets(policies, s.defaultTenantID),
	})
}

func (s *server) handleV3PIPs(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
		return
	}
	pips, hash := s.st.PIPs()
	writeJSON(w, http.StatusOK, v3PIPsResponse{
		Hash:                      hash,
		LastModificationTimestamp: timestamp(),
		PIPs:                      toV3PIPs(pips, s.defaultTenantID),
	})
}

// ── Health ────────────────────────────────────────────────────────────────────

func (s *server) handleHash(w http.ResponseWriter, r *http.Request) {
	policiesHash, pipsHash, revision := s.st.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		// `hash` is kept for callers written against the single-counter version
		// of this stub (the Compose health checks).
		"hash":         policiesHash,
		"policiesHash": policiesHash,
		"pipsHash":     pipsHash,
		"revision":     revision,
		"domains":      s.st.Domains(),
	})
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		http.Error(w, fmt.Sprintf(`{"error":"method not allowed, supported: %s"}`, allow), http.StatusMethodNotAllowed)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// pathDomain extracts and validates `{domainName}`. The value ends up in a file
// name, so anything outside the allowed character set is refused instead of
// being sanitised into a different domain than the caller named.
func pathDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	domain := r.PathValue("domainName")
	if !validDomain(domain) {
		http.Error(w, `{"error":"invalid domain name: allowed characters are letters, digits, dot, underscore and dash"}`, http.StatusBadRequest)
		return "", false
	}
	return domain, true
}

// requestScope returns the tenant and the domain of a simplified-API request.
// The tenant is the tenant_id query parameter, else the Tenant header, else
// the default tenant, the order access-control reads them in.
func requestScope(w http.ResponseWriter, r *http.Request) (tenant, domain string, ok bool) {
	domain, ok = pathDomain(w, r)
	if !ok {
		return "", "", false
	}
	tenant = r.URL.Query().Get("tenant_id")
	if tenant == "" {
		tenant = r.Header.Get("Tenant")
	}
	if tenant == "" {
		tenant = defaultTenant
	}
	if !validDomain(tenant) {
		http.Error(w, `{"error":"invalid tenant: allowed characters are letters, digits, dot, underscore and dash"}`, http.StatusBadRequest)
		return "", "", false
	}
	return tenant, domain, true
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return nil, false
	}
	return raw, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000")
}
