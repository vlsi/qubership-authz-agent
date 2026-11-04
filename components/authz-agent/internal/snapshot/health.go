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
	"maps"
	"slices"
	"time"

	"authz-agent/internal/regogen"
)

// Health is the state of the registry as /health reports it.
type Health struct {
	// LoadedAt is the time of the last completed load, empty before one.
	LoadedAt string `json:"loadedAt,omitempty"`
	// Tenants holds every tenant the last export named, by tenant ID order.
	Tenants []TenantHealth `json:"tenants"`
	// Orphans lists the elements of the export that name no tenant.
	Orphans []string `json:"orphans,omitempty"`
}

// TenantHealth is the state of one tenant. Ready is set while the tenant has
// a published snapshot, which Decide answers from; a tenant that is not
// ready denies every request.
type TenantHealth struct {
	Tenant      string `json:"tenant"`
	Ready       bool   `json:"ready"`
	Snapshot    string `json:"snapshot,omitempty"`
	PublishedAt string `json:"publishedAt,omitempty"`
	// Failures lists the parts of the published snapshot that answer as a
	// permanently failed source: a set the legacy service never evaluates,
	// a PIP the tenant does not declare, and the like. The rest of the
	// tenant is served.
	Failures []Failure `json:"failures,omitempty"`
	// Rejected is the refusal of the tenant's latest candidate, nil when
	// the published snapshot is the latest candidate.
	Rejected *Rejection `json:"rejected,omitempty"`
	// Dropped lists what the tenant's tree leaves out of the export, one
	// line per element.
	Dropped []string `json:"dropped,omitempty"`
}

// Failure is a part of a tenant that answers as a failed source.
type Failure struct {
	Set    string `json:"set,omitempty"`
	PIP    string `json:"pip,omitempty"`
	Reason string `json:"reason"`
}

// Rejection says why a tenant's candidate was not published. Stage is
// export (the tenant's elements cannot be read), unsupported (the tenant
// has a form the agent cannot execute; Forms lists them), generate, or
// compile.
type Rejection struct {
	At     string `json:"at"`
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Forms  []Form `json:"forms,omitempty"`
}

// Form is one form of a rejected candidate the agent cannot execute.
type Form struct {
	Where string `json:"where"`
	Form  string `json:"form"`
	Text  string `json:"text"`
}

// Health returns the state of every tenant of the last load.
func (r *Registry) Health() Health {
	s := r.cur.Load()
	h := Health{Tenants: []TenantHealth{}, Orphans: s.orphans}
	if !s.loadedAt.IsZero() {
		h.LoadedAt = s.loadedAt.UTC().Format(time.RFC3339)
	}
	for _, t := range slices.Sorted(maps.Keys(s.tenants)) {
		h.Tenants = append(h.Tenants, s.tenants[t])
	}
	return h
}

func failuresOf(m *regogen.Module) []Failure {
	var out []Failure
	for _, f := range m.Failures {
		out = append(out, Failure{Set: f.Set, PIP: f.PIP, Reason: f.Reason})
	}
	return out
}
