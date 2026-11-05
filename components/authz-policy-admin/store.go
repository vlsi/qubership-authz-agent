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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// File layout under the data directory. Policies and PIPs are stored per domain,
// under the domain name taken from the request path, because that is how
// access-control scopes them: `PUT .../domainPolicies/BSS` must not disturb what
// was uploaded for OSS. Each file holds the raw bytes of the last successful
// upload for its domain, so `cat policies-BSS.json` in a running Pod returns
// exactly what the caller sent, and a restart re-parses it through the same code
// path as the original request.
// unreadableFile reports a file the store found and could not read, which
// leaves the domain it holds out of what the stub serves.
const unreadableFile = "cannot read %s: %v"

const (
	policiesFilePrefix = "policies-"
	pipsFilePrefix     = "pips-"
	stateFileName      = "state.json"
	tempFilePattern    = ".acstub-*.json"
)

// domainPattern is what may appear as `{domainName}` in a request path. It is
// deliberately narrow: the domain becomes part of a file name, so anything that
// could escape the data directory or collide with another domain's file is
// rejected rather than sanitised into something the caller did not ask for.
var domainPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validDomain(domain string) bool {
	return domainPattern.MatchString(domain) && domain != "." && domain != ".."
}

// defaultTenant is the tenant of an upload that names none, and of a data file
// written before uploads were kept per tenant.
const defaultTenant = "default"

// scopeKey is the key of the collection that one tenant uploaded for one
// domain: the domain for the default tenant, tenant/domain for another.
// access-control keeps the collections of two tenants apart, so a PUT for a
// domain replaces only what the same tenant uploaded for it. Neither a tenant
// nor a domain may contain the slash.
func scopeKey(tenant, domain string) string {
	if tenant == defaultTenant {
		return domain
	}
	return tenant + "/" + domain
}

// scopeFileName is the data file of a collection: <prefix><domain>.json for
// the default tenant, <prefix><tenant>@<domain>.json for another.
func scopeFileName(prefix, tenant, domain string) string {
	if tenant == defaultTenant {
		return prefix + domain + ".json"
	}
	return prefix + tenant + "@" + domain + ".json"
}

// persistedState is diagnostic metadata written next to the data files. Only
// `revision` is read back at startup; both hashes are always recomputed from
// the data files, so losing or corrupting this file cannot change what the
// stub serves.
type persistedState struct {
	SchemaVersion int    `json:"schemaVersion"`
	Revision      int    `json:"revision"`
	PoliciesHash  string `json:"policiesHash"`
	PIPsHash      string `json:"pipsHash"`
	UpdatedAt     string `json:"updatedAt"`
}

// store holds the simplified policies and PIPs the stub serves, keyed by domain,
// and — when a data directory is configured — mirrors them to local disk so they
// survive a container restart.
//
// The v3 export API serves the union of all domains, in sorted domain order, and
// the hashes are content hashes of exactly that union: the PolicyPuller consumes
// the union and re-fetches whenever the hash it applied differs. A content hash
// means "the data changed", not "someone called PUT again", and it is what makes
// persistence safe — a restart rebuilds the same hash from the same bytes,
// instead of a write counter that would restart at zero on a freshly provisioned
// volume and could collide with a hash a running agent has already applied.
type store struct {
	dataDir string // empty = in-memory only

	mu           sync.RWMutex
	policies     map[string][]simplifiedPolicy
	pips         map[string][]simplifiedPIP
	policiesHash string
	pipsHash     string
	revision     int
}

// newStore builds a store and, when dataDir is non-empty, prepares the
// directory and loads any previously persisted content.
//
// A configured but unusable directory is fatal to the caller (an error is
// returned): a stub that answers 200 to every upload and then loses the data on
// the next reschedule is worse than a Pod that fails to start with the
// directory and uid named in its logs.
func newStore(dataDir string) (*store, error) {
	s := &store{
		dataDir:  dataDir,
		policies: map[string][]simplifiedPolicy{},
		pips:     map[string][]simplifiedPIP{},
	}

	if dataDir == "" {
		s.rehashLocked()
		return s, nil
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir %s (running as uid %d): %w", dataDir, os.Getuid(), err)
	}
	if err := probeWritable(dataDir); err != nil {
		return nil, fmt.Errorf("data dir %s is not writable (running as uid %d): %w", dataDir, os.Getuid(), err)
	}
	// A SIGKILL between CreateTemp and Rename leaves a temp file behind. Sweep
	// them at startup so they cannot accumulate on a small volume.
	sweepTempFiles(dataDir)

	s.loadFromDisk()
	return s, nil
}

// loadFromDisk restores every domain file and the revision counter. A malformed
// file is logged and skipped — it is deliberately left in place as evidence, and
// the next successful upload for that domain overwrites it.
func (s *store) loadFromDisk() {
	for _, f := range globDomainFiles(s.dataDir, policiesFilePrefix) {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			logger.Errorf(unreadableFile, f.path, err)
			continue
		}
		var items []simplifiedPolicy
		if err := json.Unmarshal(raw, &items); err != nil {
			logger.Errorf("%s is malformed, skipping domain %q: %v", f.path, f.domain, err)
			continue
		}
		s.policies[scopeKey(f.tenant, f.domain)] = withPolicyTenant(normalizePolicies(items), f.tenant)
		logger.Infof("loaded %d policies of tenant %q for domain %q from %s", len(items), f.tenant, f.domain, f.path)
	}
	for _, f := range globDomainFiles(s.dataDir, pipsFilePrefix) {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			logger.Errorf(unreadableFile, f.path, err)
			continue
		}
		var items []simplifiedPIP
		if err := json.Unmarshal(raw, &items); err != nil {
			logger.Errorf("%s is malformed, skipping domain %q: %v", f.path, f.domain, err)
			continue
		}
		s.pips[scopeKey(f.tenant, f.domain)] = withPIPTenant(normalizePIPs(items), f.tenant)
		logger.Infof("loaded %d PIPs of tenant %q for domain %q from %s", len(items), f.tenant, f.domain, f.path)
	}
	if raw, ok := readIfPresent(s.dataDir, stateFileName); ok {
		var st persistedState
		if err := json.Unmarshal(raw, &st); err != nil {
			logger.Errorf("%s is malformed, restarting revision at 0: %v", stateFileName, err)
		} else {
			s.revision = st.Revision
		}
	}
	s.rehashLocked()
}

// SetDomainPolicies replaces the policy collection that tenant uploaded for
// domain. raw is the request body, stored verbatim.
func (s *store) SetDomainPolicies(tenant, domain string, items []simplifiedPolicy, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := scopeKey(tenant, domain)
	previous, existed := s.policies[key]
	s.policies[key] = withPolicyTenant(normalizePolicies(items), tenant)
	if err := s.commitLocked(scopeFileName(policiesFilePrefix, tenant, domain), raw); err != nil {
		if existed {
			s.policies[key] = previous
		} else {
			delete(s.policies, key)
		}
		s.rehashLocked()
		return err
	}
	return nil
}

// SetDomainPIPs replaces the PIP collection that tenant uploaded for domain.
func (s *store) SetDomainPIPs(tenant, domain string, items []simplifiedPIP, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := scopeKey(tenant, domain)
	previous, existed := s.pips[key]
	s.pips[key] = withPIPTenant(normalizePIPs(items), tenant)
	if err := s.commitLocked(scopeFileName(pipsFilePrefix, tenant, domain), raw); err != nil {
		if existed {
			s.pips[key] = previous
		} else {
			delete(s.pips, key)
		}
		s.rehashLocked()
		return err
	}
	return nil
}

// commitLocked persists one domain file plus the state file and recomputes the
// hashes. The caller has already applied the change in memory and rolls it back
// if this returns an error, so a caller that was told 200 is a caller whose data
// is on disk.
//
// The write happens while the lock is held so two concurrent uploads cannot
// interleave their renames, and so a reader never observes a state that was not
// persisted.
func (s *store) commitLocked(fileName string, raw []byte) error {
	s.rehashLocked()
	s.revision++
	if s.dataDir == "" {
		return nil
	}
	if err := writeFileAtomic(filepath.Join(s.dataDir, fileName), raw); err != nil {
		s.revision--
		return fmt.Errorf("persist %s: %w", fileName, err)
	}
	state, err := json.Marshal(persistedState{
		SchemaVersion: 1,
		Revision:      s.revision,
		PoliciesHash:  s.policiesHash,
		PIPsHash:      s.pipsHash,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		s.revision--
		return fmt.Errorf("marshal %s: %w", stateFileName, err)
	}
	if err := writeFileAtomic(filepath.Join(s.dataDir, stateFileName), state); err != nil {
		s.revision--
		return fmt.Errorf("persist %s: %w", stateFileName, err)
	}
	return nil
}

// DomainPolicies returns the policies tenant uploaded for domain; an unknown
// domain reads as empty, the same answer access-control gives for a domain
// nobody has uploaded yet.
func (s *store) DomainPolicies(tenant, domain string) []simplifiedPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizePolicies(s.policies[scopeKey(tenant, domain)])
}

func (s *store) DomainPIPs(tenant, domain string) []simplifiedPIP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizePIPs(s.pips[scopeKey(tenant, domain)])
}

// Policies returns the union of every domain's policies and its content hash.
// This is what the v3 export API serves and what the PolicyPuller applies.
func (s *store) Policies() ([]simplifiedPolicy, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mergedPoliciesLocked(), s.policiesHash
}

func (s *store) PIPs() ([]simplifiedPIP, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mergedPIPsLocked(), s.pipsHash
}

// Status returns both hashes and the revision counter (logs and humans only —
// the revision never feeds a hash).
func (s *store) Status() (policiesHash, pipsHash string, revision int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policiesHash, s.pipsHash, s.revision
}

// Domains lists the domains that have any content, as tenant/domain for a
// tenant other than the default one, for the startup log.
func (s *store) Domains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	for d := range s.policies {
		seen[d] = true
	}
	for d := range s.pips {
		seen[d] = true
	}
	return sortedKeys(seen)
}

// ── Merging and hashing ───────────────────────────────────────────────────────

// mergedPoliciesLocked flattens the per-tenant, per-domain map in sorted key
// order.
// Deterministic order matters twice over: the hash is computed from this view, so
// map iteration order would make it flap, and a stable export keeps the OPA data
// document stable across pulls that changed nothing.
func (s *store) mergedPoliciesLocked() []simplifiedPolicy {
	out := []simplifiedPolicy{}
	for _, d := range sortedKeysOfPolicies(s.policies) {
		out = append(out, s.policies[d]...)
	}
	return out
}

func (s *store) mergedPIPsLocked() []simplifiedPIP {
	out := []simplifiedPIP{}
	for _, d := range sortedKeysOfPIPs(s.pips) {
		out = append(out, s.pips[d]...)
	}
	return out
}

// rehashLocked hashes each collection under its key: the tenant of an item is
// not part of its JSON, and moving a collection to another tenant changes the
// export.
func (s *store) rehashLocked() {
	s.policiesHash = hashItems(s.policies)
	s.pipsHash = hashItems(s.pips)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// hashItems returns a short content hash of a collection. Hashing the
// re-marshalled value rather than the request body means the same policies
// uploaded with different whitespace or key order produce the same hash.
//
// A marshalling failure yields a blank hash, which PolicyPuller treats as
// "always changed" — it re-fetches instead of caching a wrong identity.
func hashItems(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		logger.Errorf("hashing failed, serving a blank hash: %v", err)
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

func withPolicyTenant(items []simplifiedPolicy, tenant string) []simplifiedPolicy {
	for i := range items {
		items[i].Tenant = tenant
	}
	return items
}

func withPIPTenant(items []simplifiedPIP, tenant string) []simplifiedPIP {
	for i := range items {
		items[i].Tenant = tenant
	}
	return items
}

// normalizePolicies guarantees a non-nil slice so an empty upload and a missing
// file hash identically (`[]`, not `null`).
func normalizePolicies(items []simplifiedPolicy) []simplifiedPolicy {
	if items == nil {
		return []simplifiedPolicy{}
	}
	return items
}

func normalizePIPs(items []simplifiedPIP) []simplifiedPIP {
	if items == nil {
		return []simplifiedPIP{}
	}
	return items
}

type domainFile struct {
	tenant string
	domain string
	path   string
}

// globDomainFiles finds `<prefix><tenant>@<domain>.json` files and recovers the
// tenant and the domain from the name; a name without @ is a file of the
// default tenant. Files whose recovered tenant or domain is not legal are
// ignored and logged: they cannot have been written by this stub.
func globDomainFiles(dir, prefix string) []domainFile {
	matches, err := filepath.Glob(filepath.Join(dir, prefix+"*.json"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	out := make([]domainFile, 0, len(matches))
	for _, m := range matches {
		name := filepath.Base(m)
		tenant, domain, found := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json"), "@")
		if !found {
			tenant, domain = defaultTenant, tenant
		}
		if !validDomain(tenant) || !validDomain(domain) {
			logger.Warnf("ignoring %s: %q@%q is not a valid tenant and domain", m, tenant, domain)
			continue
		}
		out = append(out, domainFile{tenant: tenant, domain: domain, path: m})
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOfPolicies(m map[string][]simplifiedPolicy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOfPIPs(m map[string][]simplifiedPIP) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func readIfPresent(dir, name string) ([]byte, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Errorf(unreadableFile, filepath.Join(dir, name), err)
		}
		return nil, false
	}
	return raw, true
}

// probeWritable verifies the process can actually create files in dir. MkdirAll
// succeeding says nothing about an existing directory owned by another uid,
// which is exactly what happens when a storage provisioner ignores fsGroup.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func sweepTempFiles(dir string) {
	matches, err := filepath.Glob(filepath.Join(dir, tempFilePattern))
	if err != nil {
		return
	}
	for _, m := range matches {
		if err := os.Remove(m); err == nil {
			logger.Infof("removed stale temp file %s", m)
		}
	}
}

// writeFileAtomic writes content to path through a temp file and a rename, so a
// reader (or a crash) never sees a half-written file. Mirrors the helper in
// components/pap-client/internal/policyadmin/policy_puller.go; duplicated rather than shared
// because the stub image deliberately links no internal packages.
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
