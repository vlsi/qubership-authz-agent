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

package regogen

// check/filter answers which rows of a resource type the subject may read,
// as predicates over the row. The request has no resource, so every
// comparison that reads the resource is unknown, and the rest of a target or
// a condition is computed as for check/resource. The module of the filter
// computes only that: for each target and condition the tree holds, whether it
// is true, false, or unknown on this request. Go then walks the tree with
// those statuses, combines the rules' predicates by the algorithms
// (filteralg.go), and renders the answer in the dialects (filtertext.go).
//
// A status is a key in one of the sets the module returns:
//
//	t    the keys of the targets and conditions that are true
//	f    the keys of the three-valued ones that are false
//	tp   [key, i]: true in pass i of an iterate
//	fp   [key, i]: false in pass i
//
// A key is in t only where the targets of its ancestors are true as well,
// which lets the rule index of OPA skip the subtrees of other resource types.
// Go reads a status only below ancestors whose targets are true. A two-valued
// status that is not in t is false; a three-valued one in neither set is
// unknown.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// status is how Go reads one target or condition from the answer of the
// module of the filter.
type status struct {
	// key is the key of the status in the sets of the module; empty for a
	// constant, whose value is konst.
	key   string
	konst bool
	// three is set when the status may be unknown.
	three bool
	// pass is set for a status inside an iterate, which the module answers
	// per pass.
	pass bool
	// refs are the references the condition reads, which tell a failed source
	// from the resource where the status is unknown.
	refs []*Ref
}

// fnode is a node of the tree as the algebra of the filter walks it.
type fnode struct {
	kind nodeKind
	alg  policyir.Algorithm
	tgt  status
	kids []*fnode

	// a rule
	cond   status
	effect string
	preds  policyir.Predicates
	ruleID string

	// a simplified group: one part per operation, each a top-level node
	simp []fsimp

	// setID names the set of an iterate, which prefixes the keys of the
	// custom predicates of its passes.
	setID string
}

// fsimp is a simplified policy: match is its resource type, operation, and
// roles, cond its condition.
type fsimp struct {
	match, cond status
	op          string
	id          string
	preds       policyir.Predicates
}

// filterPlan is the tree of the filter in the order of the export.
type filterPlan struct {
	tops []*fnode
	// approx is [Options.FirstApproximation].
	approx bool
}

// GenerateFilter translates the policy tree of a tenant into the module that
// check/filter evaluates, as [Generate] does for check/resource. Its package
// is opt.Package; its rule st holds the statuses this file describes.
// [Options.Groups] and [Options.Decision] do not apply to it.
func GenerateFilter(tree *policyir.Tree, tab *spectables.Table, opt Options) (*Module, error) {
	opt.Groups, opt.Decision = false, false
	g, err := newGen(tree, tab, opt)
	if err != nil {
		return &Module{Stats: g.stats}, err
	}
	g.filter = true
	fg := &filterGen{g: g, t: map[string]dnf{}, f: map[string]dnf{}}
	plan := &filterPlan{approx: opt.FirstApproximation}
	ids, seen := map[string]string{}, map[string]int{}
	label := func(id string) (string, error) {
		seen[id]++
		l := setLabel(id)
		if k := seen[id]; k > 1 {
			l = fmt.Sprintf("%s_dup%d", l, k)
		}
		if other, ok := ids[l]; ok && other != id {
			return "", fmt.Errorf("policy sets %q and %q share the label %s", other, id, l)
		}
		ids[l] = id
		return l, nil
	}
	for _, sg := range tree.Simplified {
		l, err := label(sg.ID)
		if err != nil {
			return nil, err
		}
		n, err := g.simplified(sg, l)
		if err != nil {
			return &Module{Stats: g.stats}, err
		}
		plan.tops = append(plan.tops, fg.simplified(n, sg)...)
	}
	for _, s := range tree.Sets {
		l, err := label(s.ID)
		if err != nil {
			return nil, err
		}
		n, err := g.set(s, l, "")
		if err != nil {
			return &Module{Stats: g.stats}, err
		}
		plan.tops = append(plan.tops, fg.set(n, s, dnfTrue))
	}
	if err := g.decisions(); err != nil {
		return nil, err
	}
	if g.collision != nil {
		return &Module{Stats: g.stats}, g.collision
	}
	m := g.newModule()
	m.Text = fg.module(opt.Package)
	markEmitted(g.refList, m.Text)
	g.stats.Bytes = len(m.Text)
	m.Stats = g.stats
	m.filter = plan
	return m, nil
}

// filterGen collects the clauses of each status: t and f by key, in order.
type filterGen struct {
	g     *gen
	t, f  map[string]dnf
	order []string
	// pass marks the keys answered per pass.
	pass map[string]bool
}

// status records the clauses where condition c, under the ancestors' targets
// prefix, is true and, for a three-valued one, false.
func (fg *filterGen) status(key string, prefix dnf, c *cond) status {
	if c.isTrue != nil {
		return status{konst: *c.isTrue && !prefix.isFalse()}
	}
	g := fg.g
	s := status{key: key, three: c.three, pass: g.pass, refs: c.refs}
	fg.order = append(fg.order, key)
	fg.t[key] = g.product(prefix, c.T())
	if c.three {
		fg.f[key] = g.product(prefix, c.F())
	}
	if g.pass {
		if fg.pass == nil {
			fg.pass = map[string]bool{}
		}
		fg.pass[key] = true
	}
	return s
}

// dnfStatus records d, a two-valued disjunction, as a status.
func (fg *filterGen) dnfStatus(key string, d dnf) status {
	switch {
	case d.isTrue():
		return status{konst: true}
	case d.isFalse():
		return status{}
	}
	fg.order = append(fg.order, key)
	fg.t[key] = d
	return status{key: key}
}

// simplified returns the nodes of simplified group n, translated from sg: one
// per operation, in the order the operations first appear.
func (fg *filterGen) simplified(n *node, sg *policyir.SimplifiedGroup) []*fnode {
	var out []*fnode
	parts := map[string]*fnode{}
	for i, k := range n.simp {
		p := sg.Policies[i]
		alts := dnf{}
		for _, r := range k.roles {
			alts = append(alts, conj(k.match, r))
		}
		alts = union(alts)
		fs := fsimp{op: p.Operation, id: p.ID, preds: p.Predicates,
			match: fg.dnfStatus(fmt.Sprintf("%s.m%d", n.id, i), alts),
			cond:  fg.status(fmt.Sprintf("%s.c%d", n.id, i), alts, k.c)}
		part, ok := parts[p.Operation]
		if !ok {
			part = &fnode{kind: kindSimplified}
			parts[p.Operation] = part
			out = append(out, part)
		}
		part.simp = append(part.simp, fs)
	}
	return out
}

// set returns the node of set n, translated from s, under the ancestors'
// targets prefix.
func (fg *filterGen) set(n *node, s *policyir.PolicySet, prefix dnf) *fnode {
	g := fg.g
	f := &fnode{kind: n.kind, alg: n.alg, setID: s.ID, tgt: fg.status(n.id+".t", prefix, n.tgt)}
	switch n.kind {
	case kindUnknown:
		return f
	case kindIterate:
		inner := g.product(prefix, n.tgt.T())
		saved := g.pass
		g.pass = true
		f.kids = []*fnode{fg.setKids(n.kids[0], s, inner)}
		g.pass = saved
		return f
	}
	inner := g.product(prefix, n.tgt.T())
	for i, k := range n.kids {
		if i < len(s.Policies) {
			f.kids = append(f.kids, fg.policy(k, s.Policies[i], inner))
		} else {
			f.kids = append(f.kids, fg.set(k, s.Sets[i-len(s.Policies)], inner))
		}
	}
	return f
}

// setKids returns the node of the set n that one pass of an iterate
// evaluates, translated from s.
func (fg *filterGen) setKids(n *node, s *policyir.PolicySet, prefix dnf) *fnode {
	f := &fnode{kind: kindSet, alg: n.alg, setID: s.ID, tgt: status{konst: true}}
	for i, k := range n.kids {
		if i < len(s.Policies) {
			f.kids = append(f.kids, fg.policy(k, s.Policies[i], prefix))
		} else {
			f.kids = append(f.kids, fg.set(k, s.Sets[i-len(s.Policies)], prefix))
		}
	}
	return f
}

// policy returns the node of policy n, translated from p.
func (fg *filterGen) policy(n *node, p *policyir.Policy, prefix dnf) *fnode {
	f := &fnode{kind: kindPolicy, alg: n.alg, tgt: fg.status(n.id+".t", prefix, n.tgt)}
	inner := fg.g.product(prefix, n.tgt.T())
	for j, k := range n.kids {
		r := p.Rules[j]
		f.kids = append(f.kids, &fnode{kind: kindRule, effect: k.effect, preds: r.Predicates, ruleID: r.ID,
			tgt: fg.status(k.id+".t", inner, k.tgt), cond: fg.status(k.id+".c", inner, k.cond)})
	}
	return f
}

// module writes the text of the module of the filter in package pkg.
func (fg *filterGen) module(pkg string) string {
	g := fg.g
	var b strings.Builder
	b.WriteString("package " + pkg + "\n\n")
	b.WriteString("st := {\"t\": t, \"f\": f, \"tp\": tp, \"fp\": fp}\n\n")
	for _, set := range []string{"t", "f", "tp", "fp"} {
		b.WriteString(set + " contains \"\" if false\n")
	}
	var clauses dnf
	write := func(set, key string, d dnf, pass bool) {
		head := fmt.Sprintf("%s contains %q", set, key)
		if pass {
			head = fmt.Sprintf("%sp contains [%q, i]", set, key)
		}
		for _, c := range d {
			clauses = append(clauses, c)
			b.WriteString("\n" + head + " if {\n")
			if pass {
				v := "_"
				if readsPass(dnf{c}) {
					v = "p"
				}
				b.WriteString("\tsome i, " + v + " in input.ps\n")
			}
			es := slices.Clone(c)
			slices.SortStableFunc(es, func(a, b expr) int { return a.cls - b.cls })
			for _, e := range es {
				b.WriteString("\t" + e.text + "\n")
			}
			if len(es) == 0 && !pass {
				b.WriteString("\ttrue\n")
			}
			b.WriteString("}\n")
		}
	}
	for _, key := range fg.order {
		write("t", key, fg.t[key], fg.pass[key])
		if d, ok := fg.f[key]; ok {
			write("f", key, d, fg.pass[key])
		}
	}
	all := union(clauses)
	cm := &commenter{g: g, b: &b, printed: map[string]bool{}}
	used := g.used(all)
	g.stats.Rules = len(used)
	g.stats.Clauses = len(all) + g.writeRules(&b, cm, used)
	return b.String()
}

// FilterQuery is the query of the module of the filter in package pkg,
// whose one value [ReadStatuses] reads.
func FilterQuery(pkg string) string { return "data." + pkg + ".st" }

// Statuses are the statuses the module of the filter answered.
type Statuses struct {
	t, f   map[string]bool
	tp, fp map[passKey]bool
}

type passKey struct {
	key  string
	pass int
}

// ReadStatuses reads the value of [FilterQuery] as the evaluation returns
// it: an object of four sets, of keys and of [key, pass] pairs.
func ReadStatuses(v any) (*Statuses, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("filter statuses: %T is not an object", v)
	}
	st := &Statuses{t: map[string]bool{}, f: map[string]bool{}, tp: map[passKey]bool{}, fp: map[passKey]bool{}}
	for name, set := range map[string]map[string]bool{"t": st.t, "f": st.f} {
		l, ok := o[name].([]any)
		if !ok {
			return nil, fmt.Errorf("filter statuses: %s is not a set", name)
		}
		for _, k := range l {
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("filter statuses: %s holds %v", name, k)
			}
			set[key] = true
		}
	}
	for name, set := range map[string]map[passKey]bool{"tp": st.tp, "fp": st.fp} {
		l, ok := o[name].([]any)
		if !ok {
			return nil, fmt.Errorf("filter statuses: %s is not a set", name)
		}
		for _, e := range l {
			p, ok := e.([]any)
			if !ok || len(p) != 2 {
				return nil, fmt.Errorf("filter statuses: %s holds %v", name, e)
			}
			key, ok := p[0].(string)
			if !ok {
				return nil, fmt.Errorf("filter statuses: %s holds %v", name, e)
			}
			i, err := passIndex(p[1])
			if err != nil {
				return nil, fmt.Errorf("filter statuses: %s holds %v: %w", name, e, err)
			}
			set[passKey{key, i}] = true
		}
	}
	return st, nil
}

func passIndex(v any) (int, error) {
	switch x := v.(type) {
	case interface{ Int64() (int64, error) }:
		n, err := x.Int64()
		return int(n), err
	case float64:
		return int(x), nil
	case int:
		return x, nil
	}
	return 0, fmt.Errorf("%T is not a pass index", v)
}

// Filter returns the answer of check/filter for req from st, the statuses
// the module of [GenerateFilter] answered for the projection of req. ctx
// carries the calls of the request ([regobuiltins.WithCalls]), which a
// GENERAL PIP of a placeholder shares with the module. The error is a
// defect of the module, not a denial.
func (m *Module) Filter(ctx context.Context, st *Statuses, req *Request) (FilterAnswer, error) {
	if m.filter == nil {
		return FilterAnswer{}, errors.New("the module answers check/resource, not check/filter")
	}
	e := &filterEval{m: m, ctx: ctx, req: req, st: st, failed: failedSources(ctx), approx: m.filter.approx,
		sub: &substituter{m: m, ctx: ctx, req: req, general: map[string]sourceValue{}}}
	a, err := e.top(m.filter)
	if errors.Is(err, errDenyAll) {
		return FilterAnswer{Result: FilterDeny}, nil
	}
	if err != nil {
		return FilterAnswer{}, err
	}
	return filterAnswer(a), nil
}
