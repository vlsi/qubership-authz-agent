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
//	               [-budget 16] [-decision] [-resolve] [-limit N] [-only key,...] [-dump DIR] [-explain]
//
// With -decision the decision module is compiled beside the module of allow,
// and a denied request also evaluates its maybe; the summary gives the
// decision module's clauses and compilation, the time of a denial (allow and
// maybe), and the count of denials that maybe makes unknown. The bundles carry
// no oracle answer for that split.
//
// A request carries the resolved values of its operands and, where the bundle
// has it, the body of the request, which gives the operation, the resource
// type, and the resource document that a lazily read resource path reads.
//
// With -resolve the module evaluates the values the projection resolves from
// the body of the request ([regogen.Module.Resolve]) and, where the bundle
// carries them, from the claims of the subject's token ([regogen.SubjectOf])
// in place of the specification's. Every record of the input, the subject's
// roles, and subject.isM2M are compared with what the specification's values
// give; each difference is counted in record_mismatch and listed in the
// output file. The input of the request as the one item of a bulk request
// ([regogen.NewBulk]) is compared with the request's own, and a difference
// is counted in bulk_mismatch. The bundle must carry the body.
//
// A GENERAL or FILTERED PIP calls nc.http.send, whose transport replays the
// value the specification resolved for the PIP ([regogen.ReplayTransport]):
// the request the projection builds is not checked, the reading of the
// response and the calls the agent does not make are. A value no response
// gives, two PIPs whose calls are one HTTP request with different values
// recorded, and a url Go does not parse are counted in replay_errors, and the
// request is not compared.
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
	"net/http"
	"os"
	"reflect"
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
	ID       string                        `json:"id"`
	Op       *string                       `json:"op"`
	RT       *string                       `json:"rt"`
	Roles    []string                      `json:"roles"`
	M2M      bool                          `json:"m2m"`
	Vals     map[string][3]json.RawMessage `json:"vals"`
	Scope    json.RawMessage               `json:"scope"`
	Resource *string                       `json:"resource"`
	Body     *string                       `json:"body"`
	// Claims and Anonymous are the claims of the subject's token and
	// whether the request is anonymous, which the subject is read from.
	Claims    *string        `json:"claims"`
	Anonymous bool           `json:"anonymous"`
	Agent     bool           `json:"agent"`
	Legacy    map[string]any `json:"legacy"`
}

type result struct {
	Key        string   `json:"key"`
	Error      string   `json:"error,omitempty"`
	Stage      string   `json:"stage,omitempty"`
	Requests   int      `json:"requests"`
	Mismatch   []string `json:"mismatch,omitempty"`
	ProjErrors []string `json:"projErrors,omitempty"`
	// ReplayErrors lists the values of GENERAL and FILTERED PIPs that no
	// response of a call gives, the calls of two PIPs that are one request
	// with different values recorded, and the urls Go does not parse; their
	// requests are not compared.
	ReplayErrors []string `json:"replayErrors,omitempty"`
	// RecordMismatch lists, with -resolve, each reference whose record the
	// projection's values give differently from the specification's.
	RecordMismatch []string  `json:"recordMismatch,omitempty"`
	ResolveUs      []float64 `json:"resolveUs,omitempty"`
	// BulkMismatch lists, with -resolve, each request whose input as an item
	// of a bulk request differs from its own; BulkUs and ItemUs are the
	// projection of the shared part and of the item, its input value
	// included.
	BulkMismatch []string  `json:"bulkMismatch,omitempty"`
	BulkUs       []float64 `json:"bulkUs,omitempty"`
	ItemUs       []float64 `json:"itemUs,omitempty"`
	GenMs        float64   `json:"genMs"`
	CompileMs    float64   `json:"compileMs"`
	// DecisionCompileMs and DenyUs are the compilation of the decision
	// module and the evaluation of each denied request, allow and maybe;
	// EvalUs times allow alone.
	DecisionCompileMs float64   `json:"decisionCompileMs,omitempty"`
	DenyUs            []float64 `json:"denyUs,omitempty"`
	Unknown           int       `json:"unknown,omitempty"`
	EvalUs            []float64 `json:"evalUs,omitempty"`
	// GroupsUs times Project, the subject groups included, and
	// EvalGroupsUs the subject groups alone.
	GroupsUs     []float64      `json:"groupsUs,omitempty"`
	EvalGroupsUs []float64      `json:"evalGroupsUs,omitempty"`
	Stats        regogen.Stats  `json:"stats"`
	Groups       int            `json:"groups"`
	NoTemplate   map[string]int `json:"noTemplate,omitempty"`
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

// toRequest reads the request q of the tenant's bundle for module m. A value
// of the subject that the request of a PIP of m reads and q does not carry
// is ABSENT: the replay of the PIP's call answers by its request, which q
// does not record either.
func toRequest(q request, tenant string, m *regogen.Module) (regogen.Request, error) {
	r := regogen.Request{Roles: q.Roles, M2M: q.M2M, Tenant: tenant, Anonymous: q.Anonymous}
	var err error
	if q.Claims != nil {
		c, err := jsonvalue.Decode([]byte(*q.Claims))
		if err != nil {
			return r, fmt.Errorf("claims: %w", err)
		}
		r.Claims, _ = c.(*jsonvalue.Object)
	}
	if q.Body != nil {
		if r.Body, err = regogen.ReadBody([]byte(*q.Body)); err != nil {
			return r, fmt.Errorf("body: %w", err)
		}
	} else {
		// a bundle without the body: the operation and the resource type the
		// specification read from it
		if q.Op != nil {
			r.Body.Operation = *q.Op
		}
		if q.RT != nil {
			r.Body.ResourceType = *q.RT
		}
		if q.Resource != nil {
			r.Body.HasResource = true
			if r.Body.Resource, err = jsonvalue.Decode([]byte(*q.Resource)); err != nil {
				return r, fmt.Errorf("resource: %w", err)
			}
		}
	}
	if r.Values, err = resolvedValues(q.Vals); err != nil {
		return r, err
	}
	for _, k := range m.Placeholders() {
		if _, ok := r.Values[k]; !ok {
			r.Values[k] = regogen.Resolved{State: spectables.StateAbsent}
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

// resolution is what resolveRequest found for one request.
type resolution struct {
	in *regogen.Input
	// diff lists the records that differ from the specification's, and
	// bulk is set when the input as an item of a bulk request differs.
	diff                      []string
	bulk                      bool
	resolveUs, bulkUs, itemUs float64
}

// resolveRequest replaces the values of rq that the projection resolves
// itself, the subject's where q carries the claims, and projects rq. It
// compares the records with those of in, the input the specification's
// values give, and the input of rq as the one item of a bulk request with
// rq's own.
func resolveRequest(m *regogen.Module, q request, rq *regogen.Request, in *regogen.Input) (resolution, error) {
	var res resolution
	var claims *jsonvalue.Object
	if q.Claims != nil {
		c, err := jsonvalue.Decode([]byte(*q.Claims))
		if err != nil {
			return res, fmt.Errorf("claims: %w", err)
		}
		var ok bool
		if claims, ok = c.(*jsonvalue.Object); !ok {
			return res, fmt.Errorf("claims: not an object")
		}
	}
	rq.Values = maps.Clone(rq.Values)
	t0 := time.Now()
	m.Resolve(rq.Body, rq.Values)
	if claims != nil {
		regogen.SubjectOf(claims, q.Anonymous, regogen.DefaultSubjectRules).Apply(rq)
	}
	res.resolveUs = float64(time.Since(t0).Nanoseconds()) / 1000
	got, err := regogen.Project(m, *rq)
	if err != nil {
		return res, err
	}
	res.in = got
	if !slices.Equal(in.SRoles, got.SRoles) {
		res.diff = append(res.diff, fmt.Sprintf("sroles: spec %q, projection %q", in.SRoles, got.SRoles))
	}
	if in.M2M != got.M2M {
		res.diff = append(res.diff, fmt.Sprintf("m2m: spec %v, projection %v", in.M2M, got.M2M))
	}
	for _, r := range m.Refs {
		want, okW := in.Records[r.ID]
		have, okH := got.Records[r.ID]
		if okW != okH || !reflect.DeepEqual(want, have) {
			w, _ := json.Marshal(want)
			h, _ := json.Marshal(have)
			res.diff = append(res.diff, fmt.Sprintf("%s: spec %s, projection %s", r.ID, w, h))
		}
	}
	shared := *rq
	shared.Body = regogen.Body{}
	t0 = time.Now()
	bulk, err := regogen.NewBulk(m, shared)
	res.bulkUs = float64(time.Since(t0).Nanoseconds()) / 1000
	if err != nil {
		return res, fmt.Errorf("bulk: %w", err)
	}
	t0 = time.Now()
	item := bulk.Item(rq.Body).Value()
	res.itemUs = float64(time.Since(t0).Nanoseconds()) / 1000
	res.bulk = item.Compare(got.Value()) != 0
	return res, nil
}

func run(b bundle, tab *spectables.Table, opt regogen.Options, reps int, dumpDir string, resolve bool) result {
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
		rq, err := toRequest(q, b.Tenant, m)
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
		g0 = time.Now()
		regogen.EvalGroups(m, in)
		res.EvalGroupsUs = append(res.EvalGroupsUs, float64(time.Since(g0).Nanoseconds())/1000)
		if resolve {
			if q.Body == nil {
				res.ProjErrors = append(res.ProjErrors, q.ID+": -resolve: the bundle carries no body")
				continue
			}
			r, err := resolveRequest(m, q, &rq, in)
			if err != nil {
				res.ProjErrors = append(res.ProjErrors, q.ID+": resolve: "+err.Error())
				continue
			}
			res.ResolveUs = append(res.ResolveUs, r.resolveUs)
			res.BulkUs = append(res.BulkUs, r.bulkUs)
			res.ItemUs = append(res.ItemUs, r.itemUs)
			for _, d := range r.diff {
				res.RecordMismatch = append(res.RecordMismatch, q.ID+": "+d)
			}
			if r.bulk {
				res.BulkMismatch = append(res.BulkMismatch, q.ID)
			}
			in = r.in
		}
		v := in.Value()
		tr, errs := regogen.ReplayTransport(in)
		for _, e := range errs {
			res.ReplayErrors = append(res.ReplayErrors, q.ID+": "+e.Error())
		}
		if len(errs) > 0 {
			// the replay answers a call otherwise than the recording did
			continue
		}
		h := &regobuiltins.HTTP{Client: &http.Client{Transport: tr}, Token: func() (string, error) { return "own", nil }}
		ctx := in.Context(context.WithValue(h.Context(context.Background()), ctxKey{}, in))
		best, bestDeny := -1.0, -1.0
		var got, maybe bool
		for i := 0; i < reps; i++ {
			e0 := time.Now()
			// each evaluation is a decision request of its own, with its own calls
			cctx := regobuiltins.WithCalls(ctx)
			rs, err := pq.Eval(cctx, rego.EvalParsedInput(v))
			us := float64(time.Since(e0).Nanoseconds()) / 1000
			deny := us
			if err == nil {
				got = len(rs) == 1 && rs[0].Expressions[0].Value == true
				if !got && opt.Decision {
					rs, err = pqd.Eval(cctx, rego.EvalParsedInput(v))
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
	resolve := flag.Bool("resolve", false, "resolve the resource operands from the body and compare the records")
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
				results <- run(b, tab, opt, *reps, *dump, *resolve)
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
	var evals, groupUs, compiles, denies, dcompiles, resolveUs, bulkUs, itemUs, evalGroupsUs []float64
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
		sum["replay_errors"] += len(r.ReplayErrors)
		sum["record_mismatch"] += len(r.RecordMismatch)
		resolveUs = append(resolveUs, r.ResolveUs...)
		sum["bulk_mismatch"] += len(r.BulkMismatch)
		bulkUs = append(bulkUs, r.BulkUs...)
		itemUs = append(itemUs, r.ItemUs...)
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
		evalGroupsUs = append(evalGroupsUs, r.EvalGroupsUs...)
		compiles = append(compiles, r.CompileMs)
	}
	q := func(xs []float64) map[string]float64 {
		return map[string]float64{"p50": pct(xs, .5), "p90": pct(xs, .9), "p99": pct(xs, .99), "max": pct(xs, 1)}
	}
	s, _ := json.MarshalIndent(map[string]any{
		"counts": sum, "table_load_ms": loadMs, "spec_tag": tab.SpecTag(),
		"eval_us": q(evals), "project_us": q(groupUs), "groups_us": q(evalGroupsUs), "resolve_us": q(resolveUs),
		"bulk_us": q(bulkUs), "item_us": q(itemUs), "compile_ms": q(compiles), "clauses": q(clauses),
		"deny_eval_us": q(denies), "decision_compile_ms": q(dcompiles),
		"errors": errClasses, "no_template": noTpl, "seconds": time.Since(t0).Seconds(),
	}, "", " ")
	fmt.Println(string(s))
}
