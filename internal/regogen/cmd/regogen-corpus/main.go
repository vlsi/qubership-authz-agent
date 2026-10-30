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

// Regogen-corpus checks the Rego generator against recorded decisions.
//
// It reads bundles, one JSON object per line: a tenant's v3 export (policySets,
// pips), and its check/resource requests with the operand values the
// specification resolved and the decision of the specification's profile
// agent. For each bundle it converts the export with policyir.FromRegular,
// generates a module, compiles it, evaluates every request, and compares the
// decision. It prints a summary as JSON and writes every disagreement, failed
// generation, and timing to the -out file.
//
//	regogen-corpus -bundles bundles.jsonl -out results.jsonl [-workers 4] [-reps 3] [-flat=false] [-groups]
//	               [-budget 16] [-decision] [-limit N] [-only key,...] [-dump DIR] [-explain]
//
// With -decision the decision module is compiled beside the module of allow,
// and a denied request also evaluates its maybe; the summary gives the
// decision module's clauses and compilation, the time of a denial (allow and
// maybe), and the count of denials that maybe makes unknown. The bundles carry
// no oracle answer for that split.
//
// A request carries the resolved values of its operands and, where the bundle
// has it, the resource document, which a lazily read resource path reads.
//
// A request whose projection or evaluation fails is counted in proj_errors,
// not as a disagreement.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
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
	ID       string                        `json:"id"`
	Op       *string                       `json:"op"`
	RT       *string                       `json:"rt"`
	Roles    []string                      `json:"roles"`
	M2M      bool                          `json:"m2m"`
	Vals     map[string][3]json.RawMessage `json:"vals"`
	Scope    json.RawMessage               `json:"scope"`
	Resource *string                       `json:"resource"`
	Agent    bool                          `json:"agent"`
	Legacy   map[string]any                `json:"legacy"`
}

type result struct {
	Key        string   `json:"key"`
	Error      string   `json:"error,omitempty"`
	Stage      string   `json:"stage,omitempty"`
	Requests   int      `json:"requests"`
	Mismatch   []string `json:"mismatch,omitempty"`
	ProjErrors []string `json:"projErrors,omitempty"`
	GenMs      float64  `json:"genMs"`
	CompileMs  float64  `json:"compileMs"`
	// DecisionCompileMs and DenyUs are the compilation of the decision
	// module and the evaluation of each denied request, allow and maybe;
	// EvalUs times allow alone.
	DecisionCompileMs float64        `json:"decisionCompileMs,omitempty"`
	DenyUs            []float64      `json:"denyUs,omitempty"`
	Unknown           int            `json:"unknown,omitempty"`
	EvalUs            []float64      `json:"evalUs,omitempty"`
	GroupsUs          []float64      `json:"groupsUs,omitempty"`
	Stats             regogen.Stats  `json:"stats"`
	Groups            int            `json:"groups"`
	NoTemplate        map[string]int `json:"noTemplate,omitempty"`
}

type ctxKey struct{}

var explain bool

var pipDecl = &ast.Builtin{Name: "nc.pip", Decl: types.NewFunction(types.Args(types.S), types.A)}

func stubs() []func(*rego.Rego) {
	pip := rego.Function1(&rego.Function{Name: pipDecl.Name, Decl: pipDecl.Decl},
		func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			in := bctx.Context.Value(ctxKey{}).(*regogen.Input)
			t, ok := in.PIPRecord(string(a.Value.(ast.String)))
			if !ok {
				return nil, fmt.Errorf("nc.pip: no record %v", a)
			}
			return t, nil
		})
	return append(regogen.Builtins(), pip)
}

func toRequest(q request) (regogen.Request, error) {
	r := regogen.Request{Roles: q.Roles, M2M: q.M2M}
	if q.Op != nil {
		r.Operation = *q.Op
	}
	if q.RT != nil {
		r.ResourceType = *q.RT
	}
	var err error
	if r.Values, err = resolvedValues(q.Vals); err != nil {
		return r, err
	}
	if q.Resource != nil {
		if r.Resource, err = jsonvalue.Decode([]byte(*q.Resource)); err != nil {
			return r, fmt.Errorf("resource: %w", err)
		}
	}
	// scope is "ERROR", null for a tenant without iterate, or the passes
	var failed string
	if json.Unmarshal(q.Scope, &failed) == nil && failed == "ERROR" {
		r.Scope = &regogen.Scope{Failed: true}
	} else if len(q.Scope) > 0 && string(q.Scope) != "null" {
		var passes []map[string][3]json.RawMessage
		if err := json.Unmarshal(q.Scope, &passes); err != nil {
			return r, fmt.Errorf("scope: %w", err)
		}
		r.Scope = &regogen.Scope{Passes: []map[string]regogen.Resolved{}}
		for _, p := range passes {
			vals, err := resolvedValues(p)
			if err != nil {
				return r, err
			}
			r.Scope.Passes = append(r.Scope.Passes, vals)
		}
	}
	return r, nil
}

// resolvedValues reads the resolved values of a bundle, by operand key.
func resolvedValues(vals map[string][3]json.RawMessage) (map[string]regogen.Resolved, error) {
	out := map[string]regogen.Resolved{}
	for k, v := range vals {
		var parts []any
		if err := json.Unmarshal([]byte(k), &parts); err != nil {
			return nil, err
		}
		key, _ := json.Marshal(parts)
		var st string
		if err := json.Unmarshal(v[0], &st); err != nil {
			return nil, err
		}
		res := regogen.Resolved{State: spectables.State(st)}
		var hl bool
		_ = json.Unmarshal(v[2], &hl)
		res.HeaderList = hl
		var text *string
		if err := json.Unmarshal(v[1], &text); err != nil {
			return nil, err
		}
		if text != nil {
			val, err := jsonvalue.Decode([]byte(*text))
			if err != nil {
				return nil, fmt.Errorf("value of %s: %w", k, err)
			}
			res.Value = val
		}
		out[string(key)] = res
	}
	return out, nil
}

func run(b bundle, tab *spectables.Table, opt regogen.Options, reps int, dumpDir string) result {
	res := result{Key: b.Key, Requests: len(b.Requests)}
	exp, err := policyir.FromRegular(b.PolicySets, b.PIPs)
	if err != nil {
		res.Stage, res.Error = "export", err.Error()
		return res
	}
	if explain {
		fmt.Fprintf(os.Stderr, "trees %v failed %v orphans %v dropped %v\n", slices.Collect(maps.Keys(exp.Trees)),
			exp.Failed, exp.Orphans, exp.Dropped)
	}
	tree, ok := exp.Trees[b.Tenant]
	if !ok {
		if e, failed := exp.Failed[b.Tenant]; failed {
			res.Stage, res.Error = "export", e.Error()
		} else if len(b.Requests) > 0 {
			// a tenant without elements: an empty tree
			tree, _ = policyir.NewTree(nil, nil, nil)
		}
		if tree == nil {
			return res
		}
	}
	t0 := time.Now()
	m, err := regogen.Generate(tree, tab, opt)
	res.GenMs = float64(time.Since(t0).Microseconds()) / 1000
	if err != nil {
		res.Stage, res.Error = "generate", err.Error()
		if m != nil {
			res.NoTemplate = m.Stats.NoTemplate
		}
		return res
	}
	res.Stats = m.Stats
	res.Groups = len(m.Groups)
	res.NoTemplate = m.Stats.NoTemplate
	if explain {
		fmt.Fprintln(os.Stderr, tree.Dump())
		fmt.Fprintln(os.Stderr, m.Text)
	}
	if dumpDir != "" {
		_ = os.WriteFile(dumpDir+"/"+strings.ReplaceAll(b.Key, "/", "_")+".rego", []byte(m.Text), 0o644)
	}
	t0 = time.Now()
	opts := append([]func(*rego.Rego){rego.Query("data." + opt.Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, stubs()...)
	pq, err := rego.New(opts...).PrepareForEval(context.Background())
	res.CompileMs = float64(time.Since(t0).Microseconds()) / 1000
	if err != nil {
		res.Stage, res.Error = "compile", err.Error()
		return res
	}
	// a denial evaluates maybe of the decision module, compiled beside
	var pqd rego.PreparedEvalQuery
	if opt.Decision {
		t0 = time.Now()
		opts := append([]func(*rego.Rego){rego.Query("data." + opt.Package + "_decision.maybe"),
			rego.Module("decision.rego", m.DecisionText)}, stubs()...)
		if pqd, err = rego.New(opts...).PrepareForEval(context.Background()); err != nil {
			res.Stage, res.Error = "compile decision", err.Error()
			return res
		}
		res.DecisionCompileMs = float64(time.Since(t0).Microseconds()) / 1000
	}
	for _, q := range b.Requests {
		rq, err := toRequest(q)
		if err != nil {
			res.ProjErrors = append(res.ProjErrors, q.ID+": "+err.Error())
			continue
		}
		g0 := time.Now()
		in, err := regogen.Project(m, rq)
		gUs := float64(time.Since(g0).Nanoseconds()) / 1000
		if err != nil {
			res.ProjErrors = append(res.ProjErrors, q.ID+": "+err.Error())
			continue
		}
		v := in.Value()
		ctx := in.Context(context.WithValue(context.Background(), ctxKey{}, in))
		best, bestDeny := -1.0, -1.0
		var got, maybe bool
		for i := 0; i < reps; i++ {
			e0 := time.Now()
			rs, err := pq.Eval(ctx, rego.EvalParsedInput(v))
			us := float64(time.Since(e0).Nanoseconds()) / 1000
			deny := us
			if err == nil {
				got = len(rs) == 1 && rs[0].Expressions[0].Value == true
				if !got && opt.Decision {
					rs, err = pqd.Eval(ctx, rego.EvalParsedInput(v))
					maybe = len(rs) == 1 && rs[0].Expressions[0].Value == true
					deny = float64(time.Since(e0).Nanoseconds()) / 1000
				}
			}
			if err != nil {
				res.ProjErrors = append(res.ProjErrors, q.ID+": eval: "+err.Error())
				best = -2
				break
			}
			if best < 0 || us < best {
				best = us
			}
			if bestDeny < 0 || deny < bestDeny {
				bestDeny = deny
			}
		}
		if best == -2 {
			continue
		}
		if !got && opt.Decision {
			res.DenyUs = append(res.DenyUs, bestDeny)
			if maybe {
				res.Unknown++
			}
		}
		res.EvalUs = append(res.EvalUs, best)
		res.GroupsUs = append(res.GroupsUs, gUs)
		if got != q.Agent {
			res.Mismatch = append(res.Mismatch, fmt.Sprintf("%s: agent %v, module %v", q.ID, q.Agent, got))
		}
	}
	return res
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	i := int(p * float64(len(s)-1))
	return s[i]
}

func main() {
	path := flag.String("bundles", "", "bundles.jsonl")
	out := flag.String("out", "", "results.jsonl")
	workers := flag.Int("workers", runtime.NumCPU()/2, "bundles in parallel")
	reps := flag.Int("reps", 3, "evaluations per request; the fastest counts")
	flat := flag.Bool("flat", true, "inline positive flags")
	groups := flag.Bool("groups", false, "subject groups")
	limit := flag.Int("limit", 0, "bundles to read, 0 for all")
	only := flag.String("only", "", "comma-separated bundle keys")
	dump := flag.String("dump", "", "directory to write modules to")
	budget := flag.Int("budget", 16, "product limit")
	decision := flag.Bool("decision", false, "evaluate decision == \"permit\" instead of allow")
	flag.BoolVar(&explain, "explain", false, "print the export's tenants, the tree, and the module to stderr")
	flag.Parse()

	t0 := time.Now()
	tab, err := regogen.DefaultTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	loadMs := time.Since(t0).Milliseconds()
	opt := regogen.DefaultOptions()
	opt.Flat, opt.Groups, opt.ProductLimit, opt.Decision = *flat, *groups, *budget, *decision

	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<30)
	jobs := make(chan bundle)
	results := make(chan result)
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				results <- run(b, tab, opt, *reps, *dump)
			}
		}()
	}
	go func() {
		keys := map[string]bool{}
		for _, k := range strings.Split(*only, ",") {
			if k != "" {
				keys[k] = true
			}
		}
		n := 0
		for sc.Scan() {
			var b bundle
			if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if len(keys) > 0 && !keys[b.Key] {
				continue
			}
			jobs <- b
			n++
			if *limit > 0 && n >= *limit {
				break
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	w, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = w.Close() }()
	enc := json.NewEncoder(w)
	var evals, groupUs, compiles, denies, dcompiles []float64
	sum := map[string]int{}
	noTpl := map[string]int{}
	errClasses := map[string]int{}
	var clauses []float64
	for r := range results {
		_ = enc.Encode(r)
		sum["bundles"]++
		sum["requests"] += r.Requests
		if r.Error != "" {
			sum["failed_"+r.Stage]++
			sum["requests_not_generated"] += r.Requests
			msg := r.Error
			if i := strings.LastIndex(msg, ": "); i >= 0 && r.Stage == "generate" {
				msg = msg[i+2:]
			}
			if len(msg) > 120 {
				msg = msg[:120]
			}
			errClasses[r.Stage+": "+msg]++
			for k, v := range r.NoTemplate {
				noTpl[k] += v
			}
			continue
		}
		sum["mismatch"] += len(r.Mismatch)
		sum["proj_errors"] += len(r.ProjErrors)
		sum["evaluated"] += len(r.EvalUs)
		sum["clauses"] += r.Stats.Clauses
		sum["allow_clauses"] += r.Stats.AllowClauses
		sum["unguarded_allow"] += r.Stats.UnguardedAllow
		sum["groups"] += r.Groups
		sum["access_copies"] += r.Stats.AccessCopies
		sum["iterates"] += r.Stats.Iterates
		sum["materialized"] += r.Stats.Materialized
		sum["lookups"] += r.Stats.Lookups
		if r.Stats.Clauses > sum["max_clauses"] {
			sum["max_clauses"] = r.Stats.Clauses
		}
		clauses = append(clauses, float64(r.Stats.Clauses))
		sum["decision_clauses"] += r.Stats.DecisionClauses
		sum["max_decision_clauses"] = max(sum["max_decision_clauses"], r.Stats.DecisionClauses)
		sum["unknown"] += r.Unknown
		denies = append(denies, r.DenyUs...)
		if r.DecisionCompileMs > 0 {
			dcompiles = append(dcompiles, r.DecisionCompileMs)
		}
		evals = append(evals, r.EvalUs...)
		groupUs = append(groupUs, r.GroupsUs...)
		compiles = append(compiles, r.CompileMs)
	}
	q := func(xs []float64) map[string]float64 {
		return map[string]float64{"p50": pct(xs, .5), "p90": pct(xs, .9), "p99": pct(xs, .99), "max": pct(xs, 1)}
	}
	s, _ := json.MarshalIndent(map[string]any{
		"counts": sum, "table_load_ms": loadMs, "spec_tag": tab.SpecTag(),
		"eval_us": q(evals), "project_us": q(groupUs), "compile_ms": q(compiles), "clauses": q(clauses),
		"deny_eval_us": q(denies), "decision_compile_ms": q(dcompiles),
		"errors": errClasses, "no_template": noTpl, "seconds": time.Since(t0).Seconds(),
	}, "", " ")
	fmt.Println(string(s))
}
