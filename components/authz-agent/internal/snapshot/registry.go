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

// Package snapshot holds the compiled policies of every tenant and answers
// check requests with them. A [Registry] turns the policy source's v3 export
// into one generated Rego module per tenant ([regogen.Generate]), compiles
// it, and publishes it for that tenant alone; [Registry.Decide] projects a
// request onto the tenant's module and evaluates it.
//
// The tenants of one export never share policies or PIP declarations: each
// tenant's tree comes from the elements that carry its tenantId. A tenant
// whose candidate cannot be generated or compiled keeps its previous
// snapshot, and the others are published regardless.
package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

// Logger receives the diagnostics of a load.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Config tunes a Registry.
type Config struct {
	// HTTP is how nc.http.send reaches the PIPs; nil fails every call, so
	// that a PIP the module calls reads as a failed source.
	HTTP *regobuiltins.HTTP
	// Workers bounds the tenants generated and compiled at once during a
	// load; zero or less takes a quarter of the CPUs, at least one, so that
	// a load leaves the rest to the decisions served meanwhile.
	Workers int
	// BulkWorkers bounds the items of one bulk request evaluated at once;
	// zero or less means 4.
	BulkWorkers int
	// Entitlements is the base URL of the entitlements service, which
	// subject.entitledResources calls; empty fails every such operand.
	Entitlements string
	// FilterFirstApproximation is [regogen.Options.FirstApproximation].
	FilterFirstApproximation bool
}

// Snapshot is the compiled module of one tenant.
type Snapshot struct {
	Tenant string
	// Hash identifies the module text and the decision text; tenants with
	// equal text share the compiled queries.
	Hash        string
	Module *regogen.Module
	// Filter is the module that answers check/filter.
	Filter      *regogen.Module
	PublishedAt time.Time
	// treeKey identifies the tenant's tree, so that a load whose tree is
	// unchanged keeps the snapshot without generating it again.
	treeKey string
	q       *queries
}

// queries are the prepared queries of one module text.
type queries struct {
	allow, maybe, filter rego.PreparedEvalQuery
	compile              time.Duration
}

// state is what one load publishes: the snapshots and the health of every
// tenant the export names.
type state struct {
	snapshots map[string]*Snapshot
	tenants   map[string]TenantHealth
	orphans   []string
	// refused holds the tree key of each tenant's refused candidate, so
	// that an unchanged tree is not generated, refused, and reported again.
	refused   map[string]string
	loadedAt  time.Time
	sourceKey string
}

// Registry holds the published snapshot of each tenant. Decide is safe for
// concurrent use with itself and with Load; loads are serialized.
type Registry struct {
	cfg Config
	tab *spectables.Table
	opt regogen.Options
	log Logger

	load sync.Mutex
	cur  atomic.Pointer[state]
}

// New returns a registry with no tenant; tab is the specification table the
// generator reads.
func New(cfg Config, tab *spectables.Table, log Logger) *Registry {
	if cfg.Workers <= 0 {
		cfg.Workers = max(1, runtime.NumCPU()/4)
	}
	if cfg.BulkWorkers <= 0 {
		cfg.BulkWorkers = 4
	}
	opt := regogen.DefaultOptions()
	opt.Groups, opt.Decision = true, true
	opt.FirstApproximation = cfg.FilterFirstApproximation
	r := &Registry{cfg: cfg, tab: tab, opt: opt, log: log}
	r.cur.Store(&state{snapshots: map[string]*Snapshot{}, tenants: map[string]TenantHealth{}})
	return r
}

// Snapshot returns the published snapshot of tenant, and false when the
// tenant has none.
func (r *Registry) Snapshot(tenant string) (*Snapshot, bool) {
	s, ok := r.cur.Load().snapshots[tenant]
	return s, ok
}

// Loaded reports whether a load has completed.
func (r *Registry) Loaded() bool { return !r.cur.Load().loadedAt.IsZero() }

// LoadSummary counts what one load did.
type LoadSummary struct {
	Tenants   int
	Generated int
	Compiled  int
	Kept      int
	Rejected  int
	Removed   int
	Duration  time.Duration
	// Refused lists, by tenant ID order, every tenant whose latest
	// candidate is refused, including one refused by an earlier load whose
	// tree has not changed since.
	Refused []TenantRefusal
}

// TenantRefusal is a tenant whose latest candidate is refused.
type TenantRefusal struct {
	Tenant string
	// Served is set when the tenant keeps a previous snapshot, and clear
	// when the tenant has none and denies every request.
	Served bool
	Stage  string
	Reason string
}

// RefusedError is the error of [Registry.LoadSnapshots] after a load that
// published every tenant except the ones it names.
type RefusedError struct {
	// Tenants is [LoadSummary.Refused], never empty.
	Tenants []TenantRefusal
}

func (e *RefusedError) Error() string {
	var b strings.Builder
	for i, t := range e.Tenants {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "tenant %s: candidate snapshot refused, %s: %s: %s", t.Tenant, keepsWhat(t.Served), t.Stage, t.Reason)
	}
	return b.String()
}

// Partial reports that the load published the tenants e does not name.
func (e *RefusedError) Partial() bool { return true }

// Load builds a candidate snapshot of every tenant in the documents of
// GET /access/v3/config/policySets and GET /access/v3/config/pips, and
// publishes each tenant whose candidate compiles. A tenant whose tree is
// unchanged since the last load keeps its snapshot. A tenant whose
// candidate is rejected or fails keeps its previous snapshot and reports
// why in [Registry.Health] and [LoadSummary.Refused]; on the first load it
// has none and is not served. A tenant the documents no longer name is
// removed.
//
// Load returns an error, and publishes nothing, only when a document is
// not a JSON object of the expected shape.
func (r *Registry) Load(ctx context.Context, policySets, pips []byte) (LoadSummary, error) {
	r.load.Lock()
	defer r.load.Unlock()
	start := time.Now()
	prev := r.cur.Load()
	h := sha256.New()
	h.Write(policySets)
	h.Write([]byte{0})
	h.Write(pips)
	sourceKey := hex.EncodeToString(h.Sum(nil))
	if sourceKey == prev.sourceKey {
		next := *prev
		next.loadedAt = time.Now()
		r.cur.Store(&next)
		return LoadSummary{Tenants: len(prev.tenants), Kept: len(prev.snapshots), Duration: time.Since(start),
			Refused: refusalsOf(prev.tenants)}, nil
	}
	exp, err := policyir.FromRegular(policySets, pips)
	if err != nil {
		return LoadSummary{}, err
	}
	next := &state{
		snapshots: map[string]*Snapshot{},
		tenants:   map[string]TenantHealth{},
		refused:   map[string]string{},
		loadedAt:  time.Now(),
		sourceKey: sourceKey,
	}
	for _, o := range exp.Orphans {
		next.orphans = append(next.orphans, o.Error())
	}
	names := slices.Sorted(maps.Keys(exp.Trees))
	for t := range exp.Failed {
		if _, ok := exp.Trees[t]; !ok {
			names = append(names, t)
		}
	}
	slices.Sort(names)

	var sum LoadSummary
	sum.Tenants = len(names)
	// a compiled module text is shared by every tenant whose candidate has
	// the same text, in this load and from the previous one
	shared := map[string]*queries{}
	for _, s := range prev.snapshots {
		shared[s.Hash] = s.q
	}
	var sharedMu sync.Mutex
	results := make([]build, len(names))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range r.cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = r.build(ctx, names[i], exp, prev, shared, &sharedMu)
			}
		}()
	}
	for i := range names {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	for i, t := range names {
		b := results[i]
		old, hadOld := prev.snapshots[t]
		th := b.health
		th.Tenant = t
		th.Dropped = exp.Dropped[t]
		switch {
		case b.snap != nil:
			next.snapshots[t] = b.snap
			if b.kept {
				sum.Kept++
			} else {
				sum.Generated++
				if b.compiled {
					sum.Compiled++
				}
			}
		case hadOld:
			// the candidate is refused, and the tenant keeps what it had
			next.snapshots[t] = old
			if !b.repeat {
				sum.Rejected++
			}
		case !b.repeat:
			sum.Rejected++
		}
		if s, ok := next.snapshots[t]; ok {
			th.Ready = true
			th.Snapshot = s.Hash[:16]
			th.PublishedAt = s.PublishedAt.UTC().Format(time.RFC3339)
			th.Failures = failuresOf(s.Module)
		}
		if b.refusedTree != "" {
			next.refused[t] = b.refusedTree
		}
		next.tenants[t] = th
	}
	for t := range prev.snapshots {
		if _, ok := next.tenants[t]; !ok {
			sum.Removed++
		}
	}
	r.cur.Store(next)
	sum.Duration = time.Since(start)
	sum.Refused = refusalsOf(next.tenants)
	return sum, nil
}

// refusalsOf returns the tenants of tenants whose latest candidate is
// refused, by tenant ID order.
func refusalsOf(tenants map[string]TenantHealth) []TenantRefusal {
	var out []TenantRefusal
	for _, t := range slices.Sorted(maps.Keys(tenants)) {
		if th := tenants[t]; th.Rejected != nil {
			out = append(out, TenantRefusal{Tenant: t, Served: th.Ready, Stage: th.Rejected.Stage, Reason: th.Rejected.Reason})
		}
	}
	return out
}

func keepsWhat(hadOld bool) string {
	if hadOld {
		return "the previous snapshot stays"
	}
	return "the tenant is not served"
}

// build is the outcome of one tenant's candidate.
type build struct {
	snap     *Snapshot
	kept     bool
	compiled bool
	health   TenantHealth
	// refusedTree is the tree key of a refused candidate, and repeat is set
	// when the previous load refused the same tree.
	refusedTree string
	repeat      bool
}

// build generates and compiles the candidate of tenant t, or keeps its
// snapshot from prev where the tree is unchanged.
func (r *Registry) build(ctx context.Context, t string, exp *policyir.Export, prev *state,
	shared map[string]*queries, mu *sync.Mutex) build {
	var b build
	tree, ok := exp.Trees[t]
	if !ok {
		reason := exp.Failed[t].Error()
		b.refusedTree = "export: " + reason
		if prev.refused[t] == b.refusedTree {
			b.health.Rejected, b.repeat = prev.tenants[t].Rejected, true
			return b
		}
		b.health.Rejected = &Rejection{At: now(), Stage: "export", Reason: reason}
		return b
	}
	sum := sha256.Sum256([]byte(tree.Dump()))
	treeKey := hex.EncodeToString(sum[:])
	if old, ok := prev.snapshots[t]; ok && old.treeKey == treeKey {
		b.snap, b.kept = old, true
		return b
	}
	if prev.refused[t] == treeKey {
		// a refusal of the same tree stays visible until the tree changes
		b.health.Rejected, b.refusedTree, b.repeat = prev.tenants[t].Rejected, treeKey, true
		return b
	}
	b.refusedTree = treeKey
	m, err := regogen.Generate(tree, r.tab, r.opt)
	if err != nil {
		rej := &Rejection{At: now(), Stage: "generate", Reason: err.Error()}
		var re *regogen.RejectedError
		if errors.As(err, &re) {
			rej.Stage = "unsupported"
			for _, x := range re.Rejections {
				rej.Forms = append(rej.Forms, Form{Where: x.Where, Form: string(x.Form), Text: x.Text})
			}
		}
		b.health.Rejected = rej
		return b
	}
	fopt := r.opt
	fopt.Package += "_filter"
	f, err := regogen.GenerateFilter(tree, r.tab, fopt)
	if err != nil {
		b.health.Rejected = &Rejection{At: now(), Stage: "generate", Reason: "the filter: " + err.Error()}
		return b
	}
	hs := sha256.Sum256([]byte(m.Text + "\x00" + m.DecisionText + "\x00" + f.Text))
	hash := hex.EncodeToString(hs[:])
	mu.Lock()
	q, ok := shared[hash]
	mu.Unlock()
	if !ok {
		q, err = r.compile(ctx, m, f)
		if err != nil {
			b.health.Rejected = &Rejection{At: now(), Stage: "compile", Reason: err.Error()}
			return b
		}
		b.compiled = true
		mu.Lock()
		shared[hash] = q
		mu.Unlock()
	}
	b.refusedTree = ""
	b.snap = &Snapshot{Tenant: t, Hash: hash, Module: m, Filter: f, PublishedAt: time.Now(), treeKey: treeKey, q: q}
	return b
}

// compile prepares the queries allow and maybe of m and the statuses of
// the filter f.
func (r *Registry) compile(ctx context.Context, m, f *regogen.Module) (*queries, error) {
	start := time.Now()
	allow, err := rego.New(append([]func(*rego.Rego){
		rego.Query("data." + r.opt.Package + ".allow"),
		rego.Module("tenant.rego", m.Text),
	}, regogen.Builtins()...)...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile the module: %w", err)
	}
	maybe, err := rego.New(append([]func(*rego.Rego){
		rego.Query("data." + r.opt.Package + "_decision.maybe"),
		rego.Module("decision.rego", m.DecisionText),
	}, regogen.Builtins()...)...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile the decision module: %w", err)
	}
	filter, err := rego.New(append([]func(*rego.Rego){
		rego.Query(regogen.FilterQuery(r.opt.Package + "_filter")),
		rego.Module("filter.rego", f.Text),
	}, regogen.Builtins()...)...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile the filter module: %w", err)
	}
	return &queries{allow: allow, maybe: maybe, filter: filter, compile: time.Since(start)}, nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// LoadSnapshots is [Registry.Load] for package pull: it reports a load that
// changed a tenant at info. After a load that published the other tenants,
// it returns a [*RefusedError] naming every tenant whose latest candidate is
// refused, so a caller that asked for this load learns that its documents
// are not served in full.
func (r *Registry) LoadSnapshots(ctx context.Context, policySets, pips []byte) error {
	sum, err := r.Load(ctx, policySets, pips)
	if err != nil {
		return err
	}
	if sum.Generated+sum.Rejected+sum.Removed > 0 {
		r.log.Infof("policies: snapshots of %d tenants: %d generated (%d compiled), %d kept, %d refused, %d removed in %s",
			sum.Tenants, sum.Generated, sum.Compiled, sum.Kept, sum.Rejected, sum.Removed, sum.Duration.Round(time.Millisecond))
	}
	if len(sum.Refused) > 0 {
		return &RefusedError{Tenants: sum.Refused}
	}
	return nil
}
