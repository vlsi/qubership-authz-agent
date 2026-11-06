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

//go:build unix

package regogen

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/policyir"
)

// scalingCondition reads two resource lists with every operator that builds
// a token of a list element: CONTAINS and CONTAINS ANY build the element
// tokens, == the text keys, and IS SUBSET the subset tokens.
const scalingCondition = "resource.a CONTAINS 'x' OR resource.a == resource.b OR " +
	"resource.a IS SUBSET resource.b OR resource.a CONTAINS ANY resource.b"

// The bytes and the time one request takes, from reading its body to
// evaluating allow and, for a denial, maybe, grow linearly in the size of its
// resource along every shape the decoder accepts, under each operator that
// reads a list. A request is untrusted input, so a cost that grows faster
// lets a small body take the memory or the CPU of the process. Each operator
// gets lists it reads to the end: no element of a matches 'z', only the last
// elements of a and b differ, and a and b share no element.
func TestRequestCostIsLinearInTheResource(t *testing.T) {
	for _, op := range []struct {
		condition string
		// a and b are the JSON of resource.a and resource.b, given the
		// elements of size n whose leaves are x or y.
		a, b func(elems func(leaf string) string) string
		want bool
	}{
		{"resource.a CONTAINS 'z'",
			func(e func(string) string) string { return "[" + e("x") + "]" },
			func(e func(string) string) string { return "[" + e("y") + "]" }, false},
		{"resource.a == resource.b",
			func(e func(string) string) string { return "[" + e("x") + `, "p"]` },
			func(e func(string) string) string { return "[" + e("x") + `, "q"]` }, false},
		{"resource.a IS SUBSET resource.b",
			func(e func(string) string) string { return "[" + e("x") + `, "p"]` },
			func(e func(string) string) string { return "[" + e("x") + `, "q"]` }, false},
		{"resource.a CONTAINS ANY resource.b",
			func(e func(string) string) string { return "[" + e("x") + "]" },
			func(e func(string) string) string { return "[" + e("y") + "]" }, false},
		// a path builds its records when OPA evaluates the module
		{"resource.a[0] CONTAINS ANY resource.b[0]",
			func(e func(string) string) string { return "[[" + e("x") + "]]" },
			func(e func(string) string) string { return "[[" + e("y") + "]]" }, false},
		{"resource.a[0] IS SUBSET resource.b[0]",
			func(e func(string) string) string { return "[[" + e("x") + `, "p"]]` },
			func(e func(string) string) string { return "[[" + e("x") + `, "q"]]` }, false},
	} {
		m, allow, maybe := scalingModule(t, op.condition)
		for _, shape := range []struct {
			axis string
			max  int
			// elems is the JSON of the elements of a list at size n.
			elems func(n int, leaf string) string
		}{
			// jsonvalue.Decode refuses a body nested deeper than
			// jsonvalue.MaxDepth, 10000
			{"nesting depth of a list", 8192, func(n int, leaf string) string {
				return strings.Repeat("[", n) + `"` + leaf + `"` + strings.Repeat("]", n)
			}},
			{"nesting depth of an object in a list", 8192, func(n int, leaf string) string {
				return strings.Repeat(`{"k":`, n) + `"` + leaf + `"` + strings.Repeat("}", n)
			}},
			{"length of a list", 8192, func(n int, leaf string) string {
				elems := make([]string, n)
				for i := range elems {
					elems[i] = fmt.Sprintf(`"%s%d"`, leaf, i)
				}
				return strings.Join(elems, ",")
			}},
			// a path allocates about 16 KB per index, an object of a and one
			// of b, so 8192 objects would exceed the budget of a request
			{"length of a list of objects", 4096, func(n int, leaf string) string {
				elems := make([]string, n)
				for i := range elems {
					elems[i] = fmt.Sprintf(`{"k": "%s%d"}`, leaf, i)
				}
				return strings.Join(elems, ",")
			}},
			{"length of a string", 65536, func(n int, leaf string) string {
				return `"` + strings.Repeat(leaf, n) + `"`
			}},
		} {
			t.Run(op.condition+"/"+shape.axis, func(t *testing.T) {
				checkGrowth(t, shape.max, 3, requestBudget, true, func(n int) func() {
					elems := func(leaf string) string { return shape.elems(n, leaf) }
					body := []byte(`{"operation": "read", "type": "doc", "resource": {"a": ` + op.a(elems) +
						`, "b": ` + op.b(elems) + `}}`)
					return func() {
						if got := evalBody(t, m, allow, maybe, body); got != op.want {
							t.Fatalf("allow at size %d = %v, want %v", n, got, op.want)
						}
					}
				})
			})
		}
	}
}

// The bytes and the time one request takes grow linearly in the length of
// the subject's lists under each operator that compares two of them. With
// subject groups Go evaluates such an atom before Eval, so a long list in
// the subject's token reaches that code. Each operator gets lists it reads to
// the end: only their last elements differ under IS SUBSET, and they share no
// element under CONTAINS ANY.
func TestRequestCostIsLinearInTheSubjectLists(t *testing.T) {
	for _, op := range []struct {
		condition, a, b string
	}{
		{"subject.roles IS SUBSET subject.scopes", "x%d", "x%d"},
		{"subject.roles CONTAINS ANY subject.scopes", "x%d", "y%d"},
	} {
		t.Run(op.condition, func(t *testing.T) {
			m, allow, maybe := scalingModule(t, op.condition)
			if len(m.Groups) == 0 {
				t.Fatalf("the module of %s has no subject group", op.condition)
			}
			checkGrowth(t, 8192, 3, requestBudget, true, func(n int) func() {
				list := func(format, last string) string {
					elems := make([]string, n, n+1)
					for i := range elems {
						elems[i] = fmt.Sprintf(`"`+format+`"`, i)
					}
					return "[" + strings.Join(append(elems, last), ",") + "]"
				}
				a, b := resolved(t, "VALUE", list(op.a, `"p"`)), resolved(t, "VALUE", list(op.b, `"q"`))
				return func() {
					req := Request{Body: Body{Operation: "read", ResourceType: "doc"}, Values: map[string]Resolved{}}
					m.Resolve(req.Body, req.Values)
					req.Values[`["subj","roles"]`], req.Values[`["subj","scopes"]`] = a, b
					if evalRequest(t, m, allow, maybe, req) {
						t.Fatalf("allow at size %d = true, want false", n)
					}
				}
			})
		})
	}
}

// The bytes and the time one bulk request takes grow linearly in the number
// of its items.
func TestBulkCostIsLinearInItsItems(t *testing.T) {
	m, pq, _ := scalingModule(t, scalingCondition)
	var shared Request
	SubjectOf(claimsOf(t, serviceClaims), false, DefaultSubjectRules).Apply(&shared)
	checkGrowth(t, 1024, 3, requestBudget, true, func(n int) func() {
		bodies := make([][]byte, n)
		for i := range bodies {
			bodies[i] = []byte(fmt.Sprintf(`{"operation": "read", "type": "doc",
				"resource": {"a": ["v%d", "x"], "b": ["v%d"]}}`, i, i))
		}
		return func() {
			bulk, err := NewBulk(m, shared)
			if err != nil {
				t.Fatalf("NewBulk: %v", err)
			}
			for _, data := range bodies {
				b, err := ReadBody(data)
				if err != nil {
					t.Fatalf("ReadBody(%s): %v", data, err)
				}
				in := bulk.Item(b)
				if _, err := pq.Eval(in.Context(context.Background()), rego.EvalParsedInput(in.Value())); err != nil {
					t.Fatalf("Eval: %v", err)
				}
			}
		}
	})
}

// moduleSettings are the modules a tenant's policies compile to: the module
// the agent generates, with subject groups and the decision module
// (agentOptions); the same without groups, for the code only that setting
// reaches; and the filter module.
var moduleSettings = []struct {
	name           string
	filter, groups bool
}{
	{"agent module", false, true},
	{"module without groups", false, false},
	{"filter module", true, false},
}

// The bytes that reading a tenant's policies, generating its modules, and
// preparing their queries in OPA allocate grow linearly in the number of
// policy sets, of policies, regular or simplified, and of rules. Policies are
// trusted and compile time is no requirement, so this guard keeps a site of a
// few thousand policies loading rather than bounding a request.
func TestModuleCostIsLinearInThePolicies(t *testing.T) {
	table(t)
	rule := func(i int) string {
		return fmt.Sprintf("resource.a == 'v%d' AND subject.roles CONTAINS 'r%d'", i, i)
	}
	for _, tc := range []struct {
		axis string
		sets func(n int) string
	}{
		{"number of policy sets", func(n int) string { return policySets(n, 1, 1, false, rule) }},
		{"number of policies", func(n int) string { return policySets(1, n, 1, false, rule) }},
		{"number of rules in a policy", func(n int) string { return policySets(1, 1, n, false, rule) }},
		{"number of simplified policies", func(n int) string {
			return policySets(1, n, 1, true, func(i int) string { return fmt.Sprintf("resource.a == 'v%d'", i) })
		}},
	} {
		for _, ms := range moduleSettings {
			t.Run(tc.axis+"/"+ms.name, func(t *testing.T) {
				checkGrowth(t, 1024, 1, moduleBudget, false, func(n int) func() {
					sets := tc.sets(n)
					return func() { compileSets(t, sets, ms.filter, ms.groups) }
				})
			})
		}
	}
}

// The bytes that generating one condition's modules and preparing their
// queries allocate grow linearly in the number of atoms an OR or
// an AND joins. AND multiplies the true rails of its atoms and OR their false
// rails, and the rail of each != atom has several clauses, one per state and
// class of the operand, so each product builds clauses that grow with every
// atom. Subject atoms run on the agent module only, which moves them into
// subject groups: in the other modules they reach Rego, where OPA's
// reorderBodyForSafety grows faster than linear in the atoms an OR joins.
func TestModuleCostIsLinearInTheWidthOfACondition(t *testing.T) {
	table(t)
	for _, tc := range []struct {
		axis, op  string
		atom      func(i int) string
		agentOnly bool
	}{
		{"resource atoms joined by OR", " OR ", func(i int) string { return fmt.Sprintf("resource.a != 'v%d'", i) }, false},
		{"resource atoms joined by AND", " AND ", func(i int) string { return fmt.Sprintf("resource.a != 'v%d'", i) }, false},
		{"subject atoms joined by OR", " OR ", func(i int) string { return fmt.Sprintf("subject.roles CONTAINS 'r%d'", i) }, true},
		{"subject atoms joined by AND", " AND ", func(i int) string { return fmt.Sprintf("subject.roles CONTAINS 'r%d'", i) }, true},
	} {
		for _, ms := range moduleSettings {
			if tc.agentOnly && ms.name != "agent module" {
				continue
			}
			t.Run(tc.axis+"/"+ms.name, func(t *testing.T) {
				checkGrowth(t, 2048, 1, moduleBudget, false, func(n int) func() {
					atoms := make([]string, n)
					for i := range atoms {
						atoms[i] = tc.atom(i)
					}
					sets := policySets(1, 1, 1, false, func(int) string { return strings.Join(atoms, tc.op) })
					return func() { compileSets(t, sets, ms.filter, ms.groups) }
				})
			})
		}
	}
}

const (
	// byteRatio bounds the growth of the bytes per doubling of the size: linear
	// bytes double, and quadratic ones grow four times.
	byteRatio = 3.0
	// byteSlack is added to the bound of each doubling, so that the few
	// kilobytes by which a run differs from the next fail no step whose
	// bytes are still that few.
	byteSlack = 16 << 10
	// timeRatio bounds the growth of the CPU time per quadrupling of the
	// size: linear time grows four times, and quadratic time sixteen. Time
	// varies more from run to run than bytes, so it is compared over two
	// doublings.
	timeRatio = 8.0
	// timeSlack is added to the bound of each quadrupling, so that a pause of
	// the runner fails no step whose CPU time is still that short.
	timeSlack = 10 * time.Millisecond
	// requestBudget is the most bytes one request may allocate, 128 MiB
	// (134217728 bytes): twice what the largest request here allocates.
	requestBudget = 128 << 20
	// moduleBudget is the most bytes one compilation may allocate, 1 GiB
	// (1073741824 bytes). The decision module about doubles the bytes of a
	// module, so 1024 policies take about 700 MB.
	moduleBudget = 1 << 30
)

// cost is what an act takes: the bytes it allocates and the CPU time the
// process spends while it runs.
type cost struct {
	bytes uint64
	time  time.Duration
}

// checkGrowth measures the cost of the act of size n for n = 8, 16, and so on
// while n <= maxN, less the cost of size 1, and fails at the first size whose
// bytes exceed budget, or grow over the bytes of half that size more than
// byteRatio times plus byteSlack, or, when timed, whose time grows over the
// time of a quarter that size more than timeRatio times plus timeSlack. The
// time of compiling a module varies up to 14 times from run to run under
// -cover, so only a request is timed. The doublings start small and the test
// stops at the first failure, so a cost that grows exponentially fails at a
// size the machine can still afford. act builds the input of size n and
// returns the act, so that building the input is not measured. Each size
// counts the fewest bytes and the least CPU time of runs runs.
func checkGrowth(t *testing.T, maxN, runs int, budget uint64, timed bool, act func(n int) func()) {
	t.Helper()
	// the first run fills the caches of OPA and of the tables
	act(1)()
	base := measure(act(1), runs)
	costs := map[int]cost{}
	for n := 8; n <= maxN; n *= 2 {
		c := measure(act(n), runs)
		if c.bytes > budget {
			t.Fatalf("size %d allocates %d bytes, over the budget of %d", n, c.bytes, budget)
		}
		c.bytes -= min(c.bytes, base.bytes)
		c.time -= min(c.time, base.time)
		costs[n] = c
		if p, ok := costs[n/2]; ok && p.bytes > 0 {
			if limit := uint64(byteRatio*float64(p.bytes)) + byteSlack; c.bytes > limit {
				t.Fatalf("size %d allocates %d bytes over size 1, while size %d allocates %d: %.2f times for twice the size, want at most %.1f",
					n, c.bytes, n/2, p.bytes, float64(c.bytes)/float64(p.bytes), byteRatio)
			}
		}
		if q, ok := costs[n/4]; ok && timed {
			if limit := time.Duration(timeRatio*float64(q.time)) + timeSlack; c.time > limit {
				t.Fatalf("size %d takes %v of CPU over size 1, while size %d takes %v: %.2f times for four times the size, want at most %.1f",
					n, c.time, n/4, q.time, float64(c.time)/float64(q.time), timeRatio)
			}
		}
		t.Logf("size %d: %d bytes and %v of CPU over size 1", n, c.bytes, c.time)
	}
}

// measure returns the fewest bytes the act allocates and the least CPU time
// the process spends on it in runs runs. When go test ./... runs other
// packages' tests beside this one, CPU time grows far less than wall time. The
// test must not run in parallel with another, since both counts are of the
// whole process.
func measure(act func(), runs int) cost {
	least := cost{math.MaxUint64, math.MaxInt64}
	for range runs {
		// sync.Pool keeps its victim through one cycle, so two leave every
		// run with the same pools
		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := cpuTime()
		act()
		elapsed := cpuTime() - start
		runtime.ReadMemStats(&after)
		least = cost{min(least.bytes, after.TotalAlloc-before.TotalAlloc), min(least.time, elapsed)}
	}
	return least
}

// scalingModule generates the module of tenantWithSet with the condition and
// agentOptions, and prepares its allow and its maybe in OPA.
func scalingModule(t *testing.T, condition string) (m *Module, allow, maybe rego.PreparedEvalQuery) {
	t.Helper()
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", condition), table(t), agentOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	allow, maybe = prepareModule(t, m)
	return m, allow, maybe
}

// prepareModule prepares the allow of the module, and the maybe of its
// decision module, as the agent does.
func prepareModule(t *testing.T, m *Module) (allow, maybe rego.PreparedEvalQuery) {
	t.Helper()
	pkg := agentOptions().Package
	return prepare(t, "data."+pkg+".allow", m.Text), prepare(t, "data."+pkg+"_decision.maybe", m.DecisionText)
}

func prepare(t *testing.T, query, text string) rego.PreparedEvalQuery {
	t.Helper()
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query(query), rego.Module("gen.rego", text)},
		Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval(%s): %v", query, err)
	}
	return pq
}

// evalBody reads the body of a check/resource request and evaluates it with
// evalRequest.
func evalBody(t *testing.T, m *Module, allow, maybe rego.PreparedEvalQuery, body []byte) bool {
	t.Helper()
	b, err := ReadBody(body)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	req := Request{Body: b, Values: map[string]Resolved{}}
	m.Resolve(b, req.Values)
	return evalRequest(t, m, allow, maybe, req)
}

// evalRequest projects the request, subject groups included, and evaluates
// allow and, for a denial, maybe, as the agent does; it returns allow.
func evalRequest(t *testing.T, m *Module, allow, maybe rego.PreparedEvalQuery, req Request) bool {
	t.Helper()
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	ctx, v := in.Context(context.Background()), in.Value()
	rs, err := allow.Eval(ctx, rego.EvalParsedInput(v))
	if err != nil {
		t.Fatalf("Eval allow: %v", err)
	}
	if len(rs) == 1 && rs[0].Expressions[0].Value == true {
		return true
	}
	if _, err := maybe.Eval(ctx, rego.EvalParsedInput(v)); err != nil {
		t.Fatalf("Eval maybe: %v", err)
	}
	return false
}

// compileSets reads the policy sets of tenant t1, generates its module with
// agentOptions, groups on or off, and prepares its queries, or with filter
// generates and prepares its filter module.
func compileSets(t *testing.T, sets string, filter, groups bool) {
	t.Helper()
	exp, err := policyir.FromRegular([]byte(sets), []byte(`{"pips": []}`))
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	tree, ok := exp.Trees["t1"]
	if !ok {
		t.Fatalf("FromRegular: no tree of t1; failed %v, dropped %v", exp.Failed, exp.Dropped)
	}
	opt := agentOptions()
	if filter {
		m, err := GenerateFilter(tree, table(t), opt)
		if err != nil {
			t.Fatalf("GenerateFilter: %v", err)
		}
		prepare(t, FilterQuery(opt.Package), m.Text)
		return
	}
	opt.Groups = groups
	m, err := Generate(tree, table(t), opt)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	prepareModule(t, m)
}

// policySets returns the policy sets of tenant t1: the given number of
// sets, regular or of type SIMPLIFIED, each with the given number of
// policies of the given number of rules. The rule numbered i, counted across
// the sets and policies from 0, has the condition condition(i); in a
// SIMPLIFIED set it also has the target of role ri.
func policySets(sets, policies, rules int, simplified bool, condition func(i int) string) string {
	kind, policyTarget := "", "true"
	if simplified {
		kind, policyTarget = `"type": "SIMPLIFIED", `, "operation == 'read'"
	}
	ss := make([]string, sets)
	for s := range ss {
		ps := make([]string, policies)
		for p := range ps {
			rs := make([]string, rules)
			for r := range rs {
				i := (s*policies+p)*rules + r
				target := "operation == 'read'"
				if simplified {
					target = fmt.Sprintf("subject.roles CONTAINS ANY 'r%d'", i)
				}
				rs[r] = fmt.Sprintf(`{"ruleId": "r%d", "target": %q, "condition": %q,
					"effect": "ALLOW", "tenantId": "t1"}`, i, target, condition(i))
			}
			ps[p] = fmt.Sprintf(`{"policyId": "p%d_%d", "target": %q, "combiningAlgorithm": "DENY_UNLESS_PERMIT",
				"tenantId": "t1", "rules": [%s]}`, s, p, policyTarget, strings.Join(rs, ","))
		}
		ss[s] = fmt.Sprintf(`{"policySetId": "s%d", "name": "s%d", "status": "ACTIVE", %s
			"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "t1",
			"policies": [%s]}`, s, s, kind, strings.Join(ps, ","))
	}
	return `{"policySets": [` + strings.Join(ss, ",") + `]}`
}

// cpuTime returns the user and system CPU time the process has spent.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
