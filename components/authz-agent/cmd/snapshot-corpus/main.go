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

// Snapshot-corpus runs the corpus of the specification through the decision
// path of the service: each bundle is loaded into a registry of its own
// ([snapshot.Registry.Load]) and each of its requests is decided from the
// claims, the headers, and the body it carries ([snapshot.Registry.Decide]).
//
// A request is compared with the answer of the agent profile unless its
// module reads a GENERAL or FILTERED PIP, whose answers the bundle does not
// carry. The calls of the entitlements service and of the permission scope
// are answered with the status and the body the bundle recorded for their
// path, and any other call with 200 and a null body. A request in a tenant
// the export does not name is compared too: the service denies it. Disagreements are counted in mismatch, requests
// not compared in skipped; regogen-corpus -resolve -service checks those.
// A tenant whose candidate the registry rejects is counted in rejected.
//
// It prints the time of a load per tenant, the live heap of the largest
// tenant's snapshot, the time of Decide for one item, for a bulk of 50
// items in one goroutine and of 1000 items in a pool of 4, and the time of
// Decide while the largest tenant is loaded again and again beside it.
//
//	snapshot-corpus -bundles bundles.jsonl
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

type bundle struct {
	Key        string          `json:"key"`
	Tenant     string          `json:"tenant"`
	PolicySets json.RawMessage `json:"policySets"`
	PIPs       json.RawMessage `json:"pips"`
	Requests   []request       `json:"requests"`
}

type request struct {
	ID        string            `json:"id"`
	Body      *string           `json:"body"`
	Claims    *string           `json:"claims"`
	Anonymous bool              `json:"anonymous"`
	Headers   map[string]string `json:"headers"`
	Agent     bool              `json:"agent"`
	// HTTP is the status and the body, or null for none, the specification's
	// services answered a POST of each path with.
	HTTP map[string][2]json.RawMessage `json:"http"`
}

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

// nullPIP answers every call of a PIP with 200 and a null body at once, so
// that the time of a decision is the agent's own.
type nullPIP struct{}

func (nullPIP) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader("null")), Request: r}, nil
}

// replay answers a POST of a path the current request recorded with the
// recorded status and body, and any other call as nullPIP does.
type replay struct {
	paths atomic.Pointer[map[string][2]json.RawMessage]
}

func (t *replay) RoundTrip(r *http.Request) (*http.Response, error) {
	var a [2]json.RawMessage
	ok := false
	if paths := t.paths.Load(); paths != nil {
		a, ok = (*paths)[r.URL.Path]
	}
	if !ok || r.Method != http.MethodPost {
		return nullPIP{}.RoundTrip(r)
	}
	var status int
	if err := json.Unmarshal(a[0], &status); err != nil {
		return nil, fmt.Errorf("recorded status of %s: %w", r.URL.Path, err)
	}
	var body *string
	if err := json.Unmarshal(a[1], &body); err != nil {
		return nil, fmt.Errorf("recorded body of %s: %w", r.URL.Path, err)
	}
	text := ""
	if body != nil {
		text = *body
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Request: r,
		Body: io.NopCloser(strings.NewReader(text))}, nil
}

// replayEntitlements is the URL of the entitlements service the requests of
// the bundles recorded the answers of.
const replayEntitlements = "http://entitlements.replay"

func newRegistry(tab *spectables.Table, bulkWorkers int, tr http.RoundTripper) *snapshot.Registry {
	return snapshot.New(snapshot.Config{BulkWorkers: bulkWorkers, Entitlements: replayEntitlements,
		HTTP: &regobuiltins.HTTP{Client: &http.Client{Transport: tr},
			Token: func() (string, error) { return "own", nil }}}, tab, quiet{})
}

// toRequest is the decision request of q in tenant with the bodies given.
func toRequest(q request, tenant string, bodies ...regogen.Body) (snapshot.Request, error) {
	req := snapshot.Request{Tenant: tenant, Anonymous: q.Anonymous, Headers: map[string]string{}, Items: bodies}
	for k, v := range q.Headers {
		req.Headers[strings.ToLower(k)] = v
	}
	if q.Claims != nil {
		c, err := jsonvalue.Decode([]byte(*q.Claims))
		if err != nil {
			return req, fmt.Errorf("claims: %w", err)
		}
		req.Claims, _ = c.(*jsonvalue.Object)
	}
	return req, nil
}

func body(q request) (regogen.Body, error) {
	if q.Body == nil {
		return regogen.Body{}, fmt.Errorf("%s: the bundle carries no body", q.ID)
	}
	return regogen.ReadBody([]byte(*q.Body))
}

// comparable reports whether m reads only sources whose answers the bundle
// carries.
func comparable(m *regogen.Module) bool {
	for _, r := range m.Refs {
		switch r.Kind {
		case spectables.KindPIPGeneral, spectables.KindPIPFiltered:
			return false
		}
	}
	return true
}

type outcome struct {
	key                         string
	requests, compared, skipped int
	mismatch, errors            []string
	loadMs                      float64
	clauses                     int
	decideUs                    []float64
	rejected                    string
}

func run(b bundle, tab *spectables.Table, reps int) outcome {
	o := outcome{key: b.Key, requests: len(b.Requests)}
	tr := &replay{}
	r := newRegistry(tab, 1, tr)
	t0 := time.Now()
	sum, err := r.Load(context.Background(), b.PolicySets, b.PIPs)
	o.loadMs = float64(time.Since(t0).Microseconds()) / 1000
	if err != nil {
		o.rejected = "load: " + err.Error()
		return o
	}
	// a tenant the export does not name has no snapshot and denies
	cmp := true
	if s, ok := r.Snapshot(b.Tenant); ok {
		o.clauses = s.Module.Stats.Clauses
		cmp = comparable(s.Module)
	} else if sum.Rejected > 0 {
		for _, th := range r.Health().Tenants {
			if th.Tenant == b.Tenant && th.Rejected != nil {
				o.rejected = th.Rejected.Stage + ": " + th.Rejected.Reason
			}
		}
		return o
	}
	for _, q := range b.Requests {
		bd, err := body(q)
		if err != nil {
			o.errors = append(o.errors, err.Error())
			continue
		}
		req, err := toRequest(q, b.Tenant, bd)
		if err != nil {
			o.errors = append(o.errors, q.ID+": "+err.Error())
			continue
		}
		tr.paths.Store(&q.HTTP)
		best := -1.0
		var got []snapshot.Result
		for range reps {
			t := time.Now()
			got, err = r.Decide(context.Background(), req)
			us := float64(time.Since(t).Nanoseconds()) / 1000
			if err != nil {
				break
			}
			if best < 0 || us < best {
				best = us
			}
		}
		if err != nil {
			o.errors = append(o.errors, q.ID+": "+err.Error())
			continue
		}
		o.decideUs = append(o.decideUs, best)
		if !cmp {
			o.skipped++
			continue
		}
		o.compared++
		if got[0].Allowed != q.Agent {
			o.mismatch = append(o.mismatch, fmt.Sprintf("%s: agent %v, service %v (%s)", q.ID, q.Agent, got[0].Allowed, got[0].Reason))
		}
	}
	return o
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	ys := slices.Clone(xs)
	slices.Sort(ys)
	i := int(p*float64(len(ys))+0.5) - 1
	return ys[max(0, min(i, len(ys)-1))]
}

func q(xs []float64) map[string]float64 {
	return map[string]float64{"n": float64(len(xs)), "p50": pct(xs, .5), "p90": pct(xs, .9), "p99": pct(xs, .99), "max": pct(xs, 1)}
}

// bulk times Decide of n items of the subject of b's first request, the
// bodies of b's requests in turn, with workers evaluating them.
func bulk(b bundle, tab *spectables.Table, n, workers, reps int) ([]float64, error) {
	r := newRegistry(tab, workers, nullPIP{})
	if _, err := r.Load(context.Background(), b.PolicySets, b.PIPs); err != nil {
		return nil, err
	}
	var bodies []regogen.Body
	for len(bodies) < n {
		for _, q := range b.Requests {
			bd, err := body(q)
			if err != nil {
				return nil, err
			}
			if len(bodies) < n {
				bodies = append(bodies, bd)
			}
		}
	}
	req, err := toRequest(b.Requests[0], b.Tenant, bodies...)
	if err != nil {
		return nil, err
	}
	var out []float64
	for range reps {
		t := time.Now()
		if _, err := r.Decide(context.Background(), req); err != nil {
			return nil, err
		}
		out = append(out, float64(time.Since(t).Nanoseconds())/1000)
	}
	return out, nil
}

// underLoad times Decide of the requests of probe, one item each, while
// another goroutine loads big into registries of its own, if load is set.
func underLoad(probe, big bundle, tab *spectables.Table, rounds int, load bool) ([]float64, error) {
	r := newRegistry(tab, 1, nullPIP{})
	if _, err := r.Load(context.Background(), probe.PolicySets, probe.PIPs); err != nil {
		return nil, err
	}
	var reqs []snapshot.Request
	for _, q := range probe.Requests {
		bd, err := body(q)
		if err != nil {
			return nil, err
		}
		req, err := toRequest(q, probe.Tenant, bd)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, req)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	if load {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_, _ = newRegistry(tab, 1, nullPIP{}).Load(context.Background(), big.PolicySets, big.PIPs)
			}
		}()
	}
	var out []float64
	for range rounds {
		for _, req := range reqs {
			t := time.Now()
			if _, err := r.Decide(context.Background(), req); err != nil {
				stop.Store(true)
				wg.Wait()
				return nil, err
			}
			out = append(out, float64(time.Since(t).Nanoseconds())/1000)
		}
	}
	stop.Store(true)
	wg.Wait()
	return out, nil
}

// liveHeap is the heap the snapshot of b holds once loaded, in MB.
func liveHeap(b bundle, tab *spectables.Table) float64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := newRegistry(tab, 1, nullPIP{})
	_, _ = r.Load(context.Background(), b.PolicySets, b.PIPs)
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(r)
	return float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)) / (1 << 20)
}

func main() {
	path := flag.String("bundles", "", "bundles.jsonl")
	workers := flag.Int("workers", runtime.NumCPU()/2, "bundles in parallel")
	reps := flag.Int("reps", 3, "decisions per request; the fastest counts")
	limit := flag.Int("limit", 0, "bundles to read, 0 for all")
	perf := flag.Bool("perf", true, "measure bulk, the live heap, and Decide during a load")
	flag.Parse()
	tab, err := regogen.DefaultTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()
	var bundles []bundle
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<30)
	for sc.Scan() {
		var b bundle
		if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		bundles = append(bundles, b)
		if *limit > 0 && len(bundles) >= *limit {
			break
		}
	}
	t0 := time.Now()
	jobs := make(chan bundle)
	results := make(chan outcome)
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				results <- run(b, tab, *reps)
			}
		}()
	}
	go func() {
		for _, b := range bundles {
			jobs <- b
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	counts := map[string]int{}
	rejected := map[string]int{}
	var loads, decides []float64
	var examples []string
	largest, maxClauses := "", -1
	for o := range results {
		counts["bundles"]++
		counts["requests"] += o.requests
		if o.rejected != "" {
			counts["rejected"]++
			counts["requests_rejected"] += o.requests
			msg := o.rejected
			if len(msg) > 120 {
				msg = msg[:120]
			}
			rejected[msg]++
			continue
		}
		counts["compared"] += o.compared
		counts["skipped"] += o.skipped
		counts["mismatch"] += len(o.mismatch)
		counts["errors"] += len(o.errors)
		for _, e := range append(o.mismatch, o.errors...) {
			if len(examples) < 20 {
				examples = append(examples, o.key+" "+e)
			}
		}
		loads = append(loads, o.loadMs)
		decides = append(decides, o.decideUs...)
		if o.clauses > maxClauses && o.requests > 0 {
			largest, maxClauses = o.key, o.clauses
		}
	}
	report := map[string]any{"counts": counts, "rejected": rejected, "examples": examples,
		"load_ms": q(loads), "decide_us": q(decides), "seconds": time.Since(t0).Seconds()}
	if *perf && largest != "" {
		var big, probe bundle
		for _, b := range bundles {
			if b.Key == largest {
				big = b
			}
			if len(b.Requests) > len(probe.Requests) && len(b.Requests) <= 2000 {
				probe = b
			}
		}
		report["largest"] = map[string]any{"key": big.Key, "clauses": maxClauses, "live_heap_mb": liveHeap(big, tab)}
		if xs, err := bulk(big, tab, 50, 1, 50); err == nil {
			report["bulk50_one_goroutine_us"] = q(xs)
		} else {
			report["bulk50_error"] = err.Error()
		}
		if xs, err := bulk(big, tab, 1000, 4, 20); err == nil {
			report["bulk1000_pool4_us"] = q(xs)
		} else {
			report["bulk1000_error"] = err.Error()
		}
		quietXs, err1 := underLoad(probe, big, tab, 5, false)
		busyXs, err2 := underLoad(probe, big, tab, 5, true)
		if err1 == nil && err2 == nil {
			report["during_load"] = map[string]any{"probe": probe.Key, "requests": len(probe.Requests),
				"without_us": q(quietXs), "with_us": q(busyXs)}
		} else {
			report["during_load_error"] = fmt.Sprint(err1, err2)
		}
	}
	s, _ := json.MarshalIndent(report, "", " ")
	fmt.Println(string(s))
}
