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

// Filter-corpus runs the check/filter requests the specification recorded
// through the filter of the service: each bundle is loaded into a registry
// of its own ([snapshot.Registry.Load]) and each request is answered by
// [snapshot.Registry.Filter]. Every call of a PIP, the entitlements service,
// or the permission scope is answered with the status and the body the
// bundle recorded for its path, and any other call with 200 and a null body.
//
// Each answer is compared, as JSON, with the answer of the agent profile in
// the order class read. A request the agent profile answers with a status
// other than 200, or that names a user, is not compared. Every request is
// written to -out with both answers, for the classification of the
// differences.
//
//	filter-corpus -bundles filter-bundles.jsonl -out answers.jsonl
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
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
)

type bundle struct {
	Key        string          `json:"key"`
	Tenant     string          `json:"tenant"`
	PolicySets json.RawMessage `json:"policySets"`
	PIPs       json.RawMessage `json:"pips"`
	Requests   []request       `json:"requests"`
}

type answer struct {
	Status int             `json:"status"`
	Result json.RawMessage `json:"result"`
}

type request struct {
	ID        string            `json:"id"`
	Query     map[string]any    `json:"query"`
	UserID    any               `json:"userId"`
	Claims    *string           `json:"claims"`
	Anonymous bool              `json:"anonymous"`
	Headers   map[string]string `json:"headers"`
	HTTP      map[string][2]any `json:"http"`
	Agent     map[string]answer `json:"agent"`
	Legacy    map[string]answer `json:"legacy"`
}

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

// replay answers a call of a path the current request recorded with the
// recorded status and body, a path only other requests recorded with the
// first answer recorded for it, and any other call with 200 and a null body.
type replay struct {
	paths atomic.Pointer[map[string][2]any]
	known map[string][2]any
}

func (t *replay) RoundTrip(r *http.Request) (*http.Response, error) {
	status, text := 200, "null"
	if paths := t.paths.Load(); paths != nil {
		a, ok := (*paths)[r.URL.Path]
		if !ok {
			a, ok = t.known[r.URL.Path]
		}
		if ok {
			n, _ := a[0].(float64)
			status = int(n)
			text = ""
			if s, ok := a[1].(string); ok {
				text = s
			}
		}
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Request: r,
		Body: io.NopCloser(strings.NewReader(text))}, nil
}

// record is one line of -out.
type record struct {
	ID      string          `json:"id"`
	Bundle  string          `json:"bundle"`
	Verdict string          `json:"verdict"`
	Query   map[string]any  `json:"query"`
	Service json.RawMessage `json:"service,omitempty"`
	Agent   json.RawMessage `json:"agent,omitempty"`
	Legacy  json.RawMessage `json:"legacy,omitempty"`
	// Check is whether a check of the same request on a resource without
	// attributes is allowed, with -check.
	Check *bool  `json:"check,omitempty"`
	Error string `json:"error,omitempty"`
}

func main() {
	bundles := flag.String("bundles", "", "the bundles of filter requests, one JSON object per line")
	out := flag.String("out", "", "where to write every request with its answers")
	approx := flag.Bool("approx", false, "the first approximation: a denied predicate empties the allowed rows")
	check := flag.Bool("check", false, "also check each request on a resource without attributes")
	flag.Parse()
	tab, err := regogen.DefaultTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	f, err := os.Open(*bundles)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer func() { _ = f.Close() }()
	w := io.Discard
	if *out != "" {
		of, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer func() {
			if err := of.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}()
		w = of
	}
	known, err := knownPaths(*bundles)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	enc := json.NewEncoder(w)
	counts := map[string]int{}
	var total, checkTotal time.Duration
	answered, checked := 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		var b bundle
		if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		tr := &replay{known: known}
		r := snapshot.New(snapshot.Config{Entitlements: "http://entitlements.replay", FilterFirstApproximation: *approx,
			HTTP: &regobuiltins.HTTP{Client: &http.Client{Transport: tr},
				Token: func() (string, error) { return "own", nil }}}, tab, quiet{})
		if _, err := r.Load(context.Background(), b.PolicySets, b.PIPs); err != nil {
			for _, q := range b.Requests {
				counts["load error"]++
				_ = enc.Encode(record{ID: q.ID, Bundle: b.Key, Verdict: "load error", Error: err.Error()})
			}
			continue
		}
		for _, q := range b.Requests {
			rec := record{ID: q.ID, Bundle: b.Key, Query: q.Query}
			rec.Agent = q.Agent["read"].Result
			rec.Legacy = q.Legacy["read"].Result
			req, err := toRequest(q, b.Tenant)
			if err != nil {
				rec.Verdict, rec.Error = "error", err.Error()
			} else {
				tr.paths.Store(&q.HTTP)
				t := time.Now()
				a, err := r.Filter(context.Background(), req)
				total += time.Since(t)
				answered++
				if err != nil {
					rec.Verdict, rec.Error = "error", err.Error()
				} else {
					rec.Service, _ = json.Marshal(a)
					rec.Verdict = verdict(q, rec.Service)
				}
				if *check {
					op := "READ"
					if req.Operation != nil && *req.Operation != "" {
						op = *req.Operation
					}
					t := time.Now()
					res, err := r.Decide(context.Background(), snapshot.Request{Tenant: req.Tenant, Claims: req.Claims,
						Anonymous: req.Anonymous, Headers: req.Headers, Items: []regogen.Body{{Operation: op,
							ResourceType: req.ResourceType, Resource: jsonvalue.NewObject(), HasResource: true}}})
					checkTotal += time.Since(t)
					checked++
					if err == nil && len(res) == 1 {
						rec.Check = &res[0].Allowed
					}
				}
			}
			counts[rec.Verdict]++
			_ = enc.Encode(rec)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("%v\n", counts)
	if answered > 0 {
		fmt.Printf("mean filter time: %.1f us over %d requests\n", float64(total.Microseconds())/float64(answered), answered)
	}
	if checked > 0 {
		fmt.Printf("mean check time: %.1f us over %d requests\n", float64(checkTotal.Microseconds())/float64(checked), checked)
	}
}

func verdict(q request, got json.RawMessage) string {
	ag := q.Agent["read"]
	switch {
	case q.UserID != nil:
		return "not compared: userId"
	case ag.Status != 200:
		return fmt.Sprintf("not compared: agent status %d", ag.Status)
	case sameJSON(got, ag.Result):
		return "match"
	case sameJSON(got, q.Agent["skip"].Result):
		return "match skip"
	}
	return "mismatch"
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func toRequest(q request, tenant string) (snapshot.FilterRequest, error) {
	req := snapshot.FilterRequest{Tenant: tenant, Anonymous: q.Anonymous, Headers: map[string]string{}}
	if t, ok := q.Query["tenant_id"].(string); ok && t != "" {
		req.Tenant = t
	}
	req.ResourceType, _ = q.Query["resourceType"].(string)
	if op, ok := q.Query["operation"].(string); ok {
		req.Operation = &op
	}
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

// knownPaths returns the first answer the bundles in file recorded for each
// path.
func knownPaths(file string) (map[string][2]any, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string][2]any{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		var b bundle
		if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
			return nil, err
		}
		for _, q := range b.Requests {
			for p, a := range q.HTTP {
				if _, ok := out[p]; !ok {
					out[p] = a
				}
			}
		}
	}
	return out, sc.Err()
}
