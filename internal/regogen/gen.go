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

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// Options switch the parts of the generator that the plan measures separately.
// The zero value is not the default; use [DefaultOptions].
type Options struct {
	// Package is the Rego package of the module; the decision is
	// data.<Package>.allow.
	Package string
	// Flat inlines a positive flag of a child into its parent, so that an
	// ALLOW rule under neutral ancestors becomes one clause of allow. Without
	// it every node's flag is a rule of its own.
	Flat bool
	// ProductLimit is the budget of a product of two disjunctions: a larger
	// product moves one factor into a helper rule.
	ProductLimit int
	// RefFanout is the most clauses a reference to a node's rule is copied
	// into; a larger product moves the other factor into a helper rule.
	RefFanout int
	// AliasClauses is the most clauses of a rule that other clauses reference
	// directly; a larger rule gets a one-clause alias.
	AliasClauses int
	// Groups moves the subject-only part of each condition into a subject
	// group that Go evaluates before Eval.
	Groups bool
	// AccessDepth is the deepest nesting of subject allowed/denied that a copy
	// of the tree answers; deeper, the leaf is a constant.
	AccessDepth int
	// Report fills [Module.Report].
	Report bool
}

// DefaultOptions returns the settings the measurements of the prototype chose:
// flat clauses, a product limit of 16, at most 8 clauses per rule reference
// or rule, and access copies to depth 5. Subject groups are off.
func DefaultOptions() Options {
	return Options{Package: "gen", Flat: true, ProductLimit: 16, RefFanout: 8, AliasClauses: 8, AccessDepth: 5}
}

// Module is a generated module and what Go needs to evaluate it.
type Module struct {
	// Text is the Rego source.
	Text string
	// Refs are the operands the module reads, in the order they were
	// assigned.
	Refs []*Ref
	// IterateSets lists the IDs of the iterate sets the module reads through
	// the stub nc.node.
	IterateSets []string
	// Groups are the subject groups of the module, by ID.
	Groups map[string]Group
	// Stats counts what the generator produced.
	Stats Stats
	// Report holds the [LeafReport] of every comparison, when
	// [Options.Report] is set.
	Report []LeafReport

	ixOnce sync.Once
	ix     *groupIndex
}

// Stats counts what the generator produced.
type Stats struct {
	Leaves, ThreeValuedConds, Lookups               int
	Clauses, AllowClauses, UnguardedAllow, Rules    int
	Materialized, AccessCopies, IterateStubs, Bytes int
	NoTemplate                                      map[string]int
}

type nodeKind int

const (
	kindRule nodeKind = iota
	kindPolicy
	kindSet
	kindSimplified
	kindUnknown // a set the agent evaluates to [deny, permit] under its target
	kindStub    // an iterate set, answered by nc.node
)

type node struct {
	kind   nodeKind
	id     string
	alg    policyir.Algorithm
	tgt    *cond
	kids   []*node
	cond   *cond
	effect string // ALLOW, DENY, NA
	simp   []simpKid
	setID  string
}

type simpKid struct {
	match clause
	roles dnf
	c     *cond
}

type gen struct {
	tab   *spectables.Table
	tree  *policyir.Tree
	opt   Options
	nodes spectables.Nodes

	refs    map[string]*Ref
	refList []*Ref
	nextRef int

	rules     map[string]dnf
	order     []string
	memo      map[string]string
	counters  map[string]int
	anyBodies map[string]dnf
	condMemo  map[string]*cond

	fixedOp    *string
	fixedDepth int
	decNames   map[string]string
	decRoots   map[string]*node
	decOrder   []string

	groups   map[string]Group
	groupIDs map[string]string

	iterate []string
	stats   Stats

	where  whereNow
	report []LeafReport
}

// Generate translates the policy tree of a tenant into one Rego module that
// answers check/resource as the profile agent of the specification does. The
// leaves come from the agent profile of tab. An error names the first form the
// generator cannot translate, and the module carries the statistics gathered
// up to it.
func Generate(tree *policyir.Tree, tab *spectables.Table, opt Options) (*Module, error) {
	g := &gen{tab: tab, tree: tree, opt: opt, refs: map[string]*Ref{}, rules: map[string]dnf{},
		memo: map[string]string{}, counters: map[string]int{}, anyBodies: map[string]dnf{},
		condMemo: map[string]*cond{}, decNames: map[string]string{}, decRoots: map[string]*node{},
		groups: map[string]Group{}, groupIDs: map[string]string{}}
	g.stats.NoTemplate = map[string]int{}
	nodes, ok := tab.Nodes(spectables.ProfileAgent)
	if !ok {
		return nil, fmt.Errorf("the export of schema version %d carries no node rules for profile %s",
			tab.SchemaVersion(), spectables.ProfileAgent)
	}
	g.nodes = nodes
	tops, err := g.tops()
	if err != nil {
		return &Module{Stats: g.stats}, err
	}
	for _, name := range g.decOrder {
		root := g.decRoots[name]
		for _, f := range []string{"loP", "loD", "hiP", "hiD"} {
			body, err := g.flagBody(root, f[:2], f[2:])
			if err != nil {
				return nil, err
			}
			g.rule(name+"_"+f, body)
		}
	}
	allow := dnfFalse
	for _, t := range tops {
		d, err := g.flag(t, "lo", "P")
		if err != nil {
			return nil, err
		}
		allow = union(allow, d)
	}
	m := &Module{Refs: g.refList, IterateSets: g.iterate, Groups: g.groups, Report: g.report}
	m.Text = g.module(allow)
	g.stats.Bytes = len(m.Text)
	g.stats.AllowClauses = len(allow)
	for _, c := range allow {
		if !guarded(dnf{c}) {
			g.stats.UnguardedAllow++
		}
	}
	m.Stats = g.stats
	return m, nil
}

func (g *gen) fresh(p string) string {
	g.counters[p]++
	return fmt.Sprintf("%s%d", p, g.counters[p])
}

// -- tree -------------------------------------------------------------------

func (g *gen) tops() ([]*node, error) {
	var tops []*node
	for _, sg := range g.tree.Simplified {
		n, err := g.simplified(sg)
		if err != nil {
			return nil, err
		}
		if n != nil {
			tops = append(tops, n)
		}
	}
	for _, s := range g.tree.Sets {
		n, err := g.set(s)
		if err != nil {
			return nil, err
		}
		tops = append(tops, n)
	}
	return tops, nil
}

func (g *gen) fold(s string) string {
	l, _ := literal(policyir.String{Value: s})
	return l.key
}

func (g *gen) simplified(sg *policyir.SimplifiedGroup) (*node, error) {
	n := &node{kind: kindSimplified, id: g.fresh("n")}
	saved := g.where
	defer func() { g.where = saved }()
	for _, p := range sg.Policies {
		g.where = whereNow{set: sg.ID, policy: p.ID}
		var m clause
		if sg.ResourceType != "ALL" {
			if _, err := g.ref(policyir.ResourceType{}, spectables.KindResourceType, false); err != nil {
				return nil, err
			}
			m = conj(m, clause{{cls: clsIndexEq, text: "input.k.rt == " + lit(g.fold(sg.ResourceType))}})
		}
		op := p.Operation
		if g.fixedOp != nil {
			if op != "ALL" && g.fold(op) != g.fold(*g.fixedOp) {
				continue
			}
		} else if op != "ALL" {
			if _, err := g.ref(policyir.Operation{}, spectables.KindOperation, false); err != nil {
				return nil, err
			}
			m = conj(m, clause{{cls: clsIndexEq, text: "input.k.op == " + lit(g.fold(op))}})
		}
		var roles dnf
		for _, r := range p.Roles {
			roles = append(roles, clause{{cls: clsIndexIn, text: lit(g.fold(r)) + " in input.sroles",
				test: &test{kind: "has", ref: "sroles", val: g.fold(r)}}})
		}
		roles = union(roles)
		// a simplified policy without a condition grants by its operation and
		// roles: the specification evaluates no condition for it, so the
		// profile's absent expression does not apply
		c := g.constCond(true)
		if p.Condition != nil {
			var err error
			if c, err = g.cond(p.Condition, spectables.PlaceSimplified, ""); err != nil {
				return nil, err
			}
		}
		n.simp = append(n.simp, simpKid{match: m, roles: roles, c: c})
	}
	if len(n.simp) == 0 && g.fixedOp != nil {
		return nil, nil
	}
	return n, nil
}

// alg returns the algorithm of a node, the profile's absent algorithm when
// the node names none.
func (g *gen) alg(a policyir.Algorithm) policyir.Algorithm {
	if a == policyir.AlgorithmAbsent {
		return policyir.Algorithm(g.nodes.AbsentAlgorithm)
	}
	return a
}

// effect returns what a rule's effect counts as: ALLOW, DENY, or NA, by the
// profile's effects for any effect other than ALLOW and DENY.
func (g *gen) effect(e policyir.Effect) (string, error) {
	name := string(e)
	if e == policyir.EffectAbsent {
		name = g.nodes.AbsentEffect
	}
	switch name {
	case "ALLOW", "DENY":
		return name, nil
	}
	o, ok := g.nodes.Effects[name]
	if !ok {
		o = g.nodes.Effects["other"]
	}
	switch o {
	case spectables.NodePermit:
		return "ALLOW", nil
	case spectables.NodeDeny:
		return "DENY", nil
	case spectables.NodeNotApplicable:
		return "NA", nil
	}
	return "", fmt.Errorf("effect %q has node outcome %q", e, o)
}

func (g *gen) set(s *policyir.PolicySet) (*node, error) {
	if s.Isolated != "" {
		return nil, fmt.Errorf("set %s is isolated: %s", s.ID, s.Isolated)
	}
	id := g.fresh("n")
	saved := g.where
	defer func() { g.where = saved }()
	g.where = whereNow{set: s.ID}
	tgt, err := g.cond(s.Target, spectables.PlaceSetTarget, "")
	if err != nil {
		return nil, err
	}
	if s.AlwaysFails != "" {
		return &node{kind: kindUnknown, id: id, tgt: tgt}, nil
	}
	if s.Iterate != nil {
		g.stats.IterateStubs++
		if !slices.Contains(g.iterate, s.ID) {
			g.iterate = append(g.iterate, s.ID)
		}
		return &node{kind: kindStub, id: id, setID: s.ID}, nil
	}
	n := &node{kind: kindSet, id: id, alg: g.alg(s.Algorithm), tgt: tgt}
	for _, p := range s.Policies {
		k, err := g.policy(p)
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, k)
	}
	for _, c := range s.Sets {
		k, err := g.set(c)
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, k)
	}
	return n, nil
}

func (g *gen) policy(p *policyir.Policy) (*node, error) {
	set := g.where.set
	g.where = whereNow{set: set, policy: p.ID}
	tgt, err := g.cond(p.Target, spectables.PlacePolicyTarget, "")
	if err != nil {
		return nil, err
	}
	n := &node{kind: kindPolicy, id: g.fresh("n"), alg: g.alg(p.Algorithm), tgt: tgt}
	for _, r := range p.Rules {
		g.where = whereNow{set: set, policy: p.ID, rule: r.ID}
		rt, err := g.cond(r.Target, spectables.PlaceRuleTarget, "")
		if err != nil {
			return nil, err
		}
		eff, err := g.effect(r.Effect)
		if err != nil {
			return nil, err
		}
		rc, err := g.cond(r.Condition, spectables.PlaceRuleCondition, r.Effect)
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, &node{kind: kindRule, id: g.fresh("n"), tgt: rt, cond: rc, effect: eff})
	}
	return n, nil
}

// -- conditions ---------------------------------------------------------------

// cond is a condition with its rails. groups holds the leaves of each
// disjunct.
type cond struct {
	g      *gen
	isTrue *bool
	groups [][]leafRails
	three  bool
	t, f   dnf
	done   bool
}

func (g *gen) constCond(v bool) *cond { return &cond{g: g, isTrue: &v} }

func (g *gen) cond(c *policyir.Condition, place spectables.Place, effect policyir.Effect) (*cond, error) {
	if c == nil {
		return g.constCond(g.nodes.AbsentExpression == spectables.OutcomeT), nil
	}
	fixed := ""
	if g.fixedOp != nil {
		fixed = fmt.Sprintf("%s/%d", *g.fixedOp, g.fixedDepth)
	}
	k := fmt.Sprintf("%p|%s|%s|%s", c, place, effect, fixed)
	if cc, ok := g.condMemo[k]; ok {
		return cc, nil
	}
	// The leaf's context carries the effect as the rule writes it, which is
	// what a leaf reads, not what the effect counts as at the node: only a
	// written DENY is DENY, an absent effect reads as ALLOW.
	ctx := spectables.Context{Place: place, Effect: spectables.EffectAllow, Disjunction: c.HasOr()}
	if effect == policyir.EffectDeny {
		ctx.Effect = spectables.EffectDeny
	}
	cc := &cond{g: g}
	g.where.place = place
	for _, d := range c.Disjuncts {
		var leaves []leafRails
		for _, a := range d {
			l, err := g.leaf(a, ctx)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", policyir.FormatCondition(c), err)
			}
			g.stats.Leaves++
			cc.three = cc.three || l.threeValued
			leaves = append(leaves, l)
		}
		cc.groups = append(cc.groups, leaves)
	}
	if cc.three {
		g.stats.ThreeValuedConds++
	}
	g.condMemo[k] = cc
	return cc, nil
}

func (g *gen) leaf(a policyir.Atom, ctx spectables.Context) (leafRails, error) {
	switch a := a.(type) {
	case policyir.Const:
		if a.Value {
			return leafRails{t: dnfTrue, f: dnfFalse}, nil
		}
		return leafRails{t: dnfFalse, f: dnfTrue}, nil
	case policyir.IsM2M:
		t := &test{kind: "m2m", val: "true"}
		f := &test{kind: "m2m", val: "false"}
		return leafRails{t: dnf{{{cls: clsIndexEq, text: "input.m2m == true", test: t}}},
			f: dnf{{{cls: clsIndexEq, text: "input.m2m == false", test: f}}}, subjectOnly: true}, nil
	case policyir.Access:
		return g.access(a)
	case policyir.Compare:
		return g.compare(a, ctx)
	case policyir.Unsupported:
		return leafRails{}, fmt.Errorf("unsupported %s: %s", a.Form, a.Text)
	}
	return leafRails{}, fmt.Errorf("atom %T", a)
}

// access translates subject allowed/denied 'OP' on resource: the interval of
// the decision for operation OP one level deeper, from a copy of the tree
// where the operation is the constant OP.
func (g *gen) access(a policyir.Access) (leafRails, error) {
	depth := g.fixedDepth + 1
	if depth > g.opt.AccessDepth {
		// past the depth legacy evaluates: allowed is false, denied is
		// denied_without_decision, which is true
		if a.Denied {
			return leafRails{t: dnfTrue, f: dnfFalse}, nil
		}
		return leafRails{t: dnfFalse, f: dnfTrue}, nil
	}
	key := fmt.Sprintf("%s/%d", g.fold(a.Operation), depth)
	name, ok := g.decNames[key]
	if !ok {
		name = fmt.Sprintf("dec%d", len(g.decNames)+1)
		g.decNames[key] = name
		g.decOrder = append(g.decOrder, name)
		savedOp, savedDepth := g.fixedOp, g.fixedDepth
		op := a.Operation
		g.fixedOp, g.fixedDepth = &op, depth
		tops, err := g.tops()
		g.fixedOp, g.fixedDepth = savedOp, savedDepth
		if err != nil {
			return leafRails{}, err
		}
		g.decRoots[name] = &node{kind: kindSet, id: g.fresh("n"), alg: policyir.AlgorithmPermitOverrides,
			tgt: g.constCond(true), kids: tops}
		g.stats.AccessCopies++
	}
	ref := func(r string, neg bool) dnf {
		t := r
		if neg {
			t = "not " + r
		}
		return dnf{{{cls: clsCheck, text: t, rule: r}}}
	}
	if !a.Denied {
		return leafRails{t: ref(name+"_loP", false), f: ref(name+"_hiP", true), threeValued: true}, nil
	}
	// denied: deny is true, permit false, and not applicable is
	// denied_without_decision, true
	return leafRails{t: ref(name+"_hiP", true), f: ref(name+"_loP", false), threeValued: true}, nil
}

// T is the true rail: a clause per disjunct, the product of its leaves' true
// rails.
func (c *cond) T() dnf {
	if c.isTrue != nil {
		if *c.isTrue {
			return dnfTrue
		}
		return dnfFalse
	}
	if !c.done {
		c.build()
	}
	return c.t
}

// F is the false rail: the product over disjuncts of the union of their
// leaves' false rails.
func (c *cond) F() dnf {
	if c.isTrue != nil {
		if *c.isTrue {
			return dnfFalse
		}
		return dnfTrue
	}
	if !c.done {
		c.build()
	}
	return c.f
}

func (c *cond) build() {
	c.done = true
	g := c.g
	c.t = dnfFalse
	for _, grp := range c.groups {
		if g.opt.Groups {
			c.t = union(c.t, g.groupedT(grp, nil))
			continue
		}
		d := dnfTrue
		for _, l := range grp {
			d = g.product(d, l.t)
		}
		c.t = union(c.t, d)
	}
	c.f = dnfTrue
	for _, grp := range c.groups {
		alt := dnfFalse
		if g.opt.Groups {
			alt = g.groupedF(grp)
		} else {
			for _, l := range grp {
				alt = union(alt, l.f)
			}
		}
		c.f = g.product(c.f, alt)
	}
}

func (c *cond) notF() dnf {
	if !c.three {
		return c.T()
	}
	return c.g.refRule(c.F(), "c", true)
}

func (c *cond) U() dnf {
	if c.isTrue != nil || !c.three {
		return dnfFalse
	}
	return prod(c.g.refRule(c.T(), "c", true), c.g.refRule(c.F(), "c", true), true)
}

// -- rules --------------------------------------------------------------------

func (g *gen) rule(name string, body dnf) string {
	if _, ok := g.rules[name]; !ok {
		g.rules[name] = union(body)
		g.order = append(g.order, name)
	}
	return name
}

// refRule returns a one-clause disjunction that reads a rule with these
// clauses, or its negation.
func (g *gen) refRule(d dnf, prefix string, negate bool) dnf {
	switch {
	case d.isTrue() && negate, d.isFalse() && !negate:
		return dnfFalse
	case d.isTrue(), d.isFalse():
		return dnfTrue
	}
	k := prefix + "|" + d.key()
	name, ok := g.memo[k]
	if !ok {
		name = g.rule(g.fresh(prefix), d)
		g.memo[k] = name
	}
	text := name
	if negate {
		text = "not " + name
	}
	return dnf{{{cls: clsCheck, text: text, rule: name}}}
}

// product is a × b. Over the budget one factor becomes a helper rule; the
// factor that stays inline is the one whose every clause has an indexed
// expression, so the clause keeps a guard. A factor that references a node's
// rule is not copied into more than RefFanout clauses: the compiler of OPA
// walks the dependency graph from every clause anew, so a reference repeated
// in N clauses costs N walks of the node's subtree.
func (g *gen) product(a, b dnf) dnf {
	for _, p := range [][2]dnf{{a, b}, {b, a}} {
		x, y := p[0], p[1]
		if len(y) > g.opt.RefFanout && refsNodeRule(x) {
			g.stats.Materialized++
			return prod(x, g.refRule(y, "m", false), true)
		}
	}
	if len(a) > 1 && len(b) > 1 && len(a)*len(b) > g.opt.ProductLimit {
		g.stats.Materialized++
		ga, gb := guarded(a), guarded(b)
		if ga && !gb || ga == gb && len(b) > len(a) {
			b = g.refRule(b, "m", false)
		} else {
			a = g.refRule(a, "m", false)
		}
	}
	return prod(a, b, true)
}

// -- flags --------------------------------------------------------------------

// flag returns the clauses that hold exactly when bound b (lo, hi) of node n
// is x (P permit, D deny).
func (g *gen) flag(n *node, b, x string) (dnf, error) {
	if !g.opt.Flat && n.kind != kindRule {
		body, err := g.flagBody(n, b, x)
		if err != nil {
			return nil, err
		}
		return g.refRule(body, n.id+"_"+b+x+"_", false), nil
	}
	return g.flagBody(n, b, x)
}

func (g *gen) flagBody(n *node, b, x string) (dnf, error) {
	switch n.kind {
	case kindRule:
		t, c := n.tgt, n.cond
		switch n.effect {
		case "ALLOW":
			if x == "P" {
				if b == "lo" {
					return g.product(t.T(), c.T()), nil
				}
				return g.product(t.T(), c.notF()), nil
			}
			return t.U(), nil
		case "DENY":
			if x == "D" {
				if b == "lo" {
					return union(t.U(), g.product(t.T(), c.notF())), nil
				}
				return union(t.U(), g.product(t.T(), c.T())), nil
			}
			return dnfFalse, nil
		}
		if x == "D" {
			return t.U(), nil
		}
		return dnfFalse, nil
	case kindSimplified:
		if x == "D" {
			return dnfFalse, nil
		}
		out := dnfFalse
		for _, k := range n.simp {
			var body dnf
			if g.opt.Groups {
				if b == "lo" || !k.c.three {
					body = k.c.tWithSubject(k.roles)
				} else {
					body = g.product(g.group(k.roles), k.c.notF())
				}
				out = union(out, g.product(dnf{k.match}, body))
				continue
			}
			alts := dnf{}
			for _, r := range k.roles {
				alts = append(alts, conj(k.match, r))
			}
			if b == "lo" {
				body = k.c.T()
			} else {
				body = k.c.notF()
			}
			out = union(out, g.product(alts, body))
		}
		return out, nil
	case kindStub:
		return dnf{{{cls: clsBuiltin, text: fmt.Sprintf("nc.node(%s).%s == %q", lit(n.setID), b, x)}}}, nil
	case kindUnknown:
		// [deny, permit] under a true target, [deny, deny] under an
		// undefined one
		switch b + x {
		case "loD":
			return union(n.tgt.U(), n.tgt.T()), nil
		case "hiP":
			return n.tgt.T(), nil
		case "hiD":
			return n.tgt.U(), nil
		}
		return dnfFalse, nil
	}
	inner, err := g.inner(n, b, x)
	if err != nil {
		return nil, err
	}
	if !g.opt.Flat {
		inner = g.refRule(inner, n.id+"_in_"+b+x+"_", false)
	}
	if x == "P" {
		return g.product(n.tgt.T(), inner), nil
	}
	return union(n.tgt.U(), g.product(n.tgt.T(), inner)), nil
}

// anyKid returns the clauses of "some child of n has bound b equal to x",
// inlined when positive in the flat form, or a reference to its rule.
func (g *gen) anyKid(n *node, b, x string, negate bool) (dnf, error) {
	name := n.id + "_any_" + b + x
	if _, ok := g.anyBodies[name]; !ok {
		body := dnfFalse
		for _, k := range n.kids {
			d, err := g.flag(k, b, x)
			if err != nil {
				return nil, err
			}
			body = union(body, d)
		}
		g.rule(name, body)
		g.anyBodies[name] = body
	}
	body := g.anyBodies[name]
	ref := dnf{{{cls: clsCheck, text: name, rule: name}}}
	if negate {
		if body.isFalse() {
			return dnfTrue, nil
		}
		return dnf{{{cls: clsCheck, text: "not " + name, rule: name}}}, nil
	}
	if g.opt.Flat {
		return body, nil
	}
	if body.isFalse() {
		return dnfFalse, nil
	}
	return ref, nil
}

func (g *gen) inner(n *node, b, x string) (dnf, error) {
	row, ok := g.nodes.Algorithms[string(n.alg)]
	if !ok {
		return nil, fmt.Errorf("algorithm %q is not in the export's node rules", n.alg)
	}
	flag := map[spectables.NodeOutcome]string{spectables.NodePermit: "P", spectables.NodeDeny: "D",
		spectables.NodeNotApplicable: "N"}
	table := map[combo]string{{true, false}: flag[row.Permit], {false, true}: flag[row.Deny],
		{true, true}: flag[row.Both], {false, false}: flag[row.None]}
	want := map[combo]bool{}
	for c, o := range table {
		if o == x {
			want[c] = true
		}
	}
	out := dnfFalse
	for _, lits := range minimize(want) {
		d := dnfTrue
		for _, l := range lits {
			k, err := g.anyKid(n, b, l.v, !l.pos)
			if err != nil {
				return nil, err
			}
			d = g.product(d, k)
		}
		out = union(out, d)
	}
	return out, nil
}

type literalVar struct {
	v   string
	pos bool
}

// combo is whether some child permits and whether some child denies.
type combo struct{ p, d bool }

// minimize writes the combinations in want as disjuncts of literals.
func minimize(want map[combo]bool) [][]literalVar {
	w := maps.Clone(want)
	if len(w) == 4 {
		return [][]literalVar{{}}
	}
	if len(w) == 0 {
		return nil
	}
	all := []combo{{true, false}, {false, true}, {true, true}, {false, false}}
	var out [][]literalVar
	for _, v := range []string{"P", "D"} {
		for _, pos := range []bool{true, false} {
			var cover []combo
			for _, c := range all {
				if v == "P" && c.p == pos || v == "D" && c.d == pos {
					cover = append(cover, c)
				}
			}
			if !slices.ContainsFunc(cover, func(c combo) bool { return !w[c] }) {
				out = append(out, []literalVar{{v, pos}})
				for _, c := range cover {
					delete(w, c)
				}
			}
		}
	}
	for _, c := range all {
		if w[c] {
			out = append(out, []literalVar{{"P", c.p}, {"D", c.d}})
		}
	}
	return out
}

// -- text ---------------------------------------------------------------------

func (g *gen) used(allow dnf) map[string]bool {
	seen := map[string]bool{}
	var todo []string
	add := func(d dnf) {
		for _, c := range d {
			for _, e := range c {
				if e.rule != "" {
					todo = append(todo, e.rule)
				}
			}
		}
	}
	add(allow)
	for len(todo) > 0 {
		n := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[n] {
			continue
		}
		if _, ok := g.rules[n]; !ok {
			continue
		}
		seen[n] = true
		add(g.rules[n])
	}
	return seen
}

func clauseText(name string, c clause) string {
	if len(c) == 0 {
		return name + " := true\n"
	}
	es := slices.Clone(c)
	slices.SortStableFunc(es, func(a, b expr) int { return a.cls - b.cls })
	var b strings.Builder
	b.WriteString(name + " if {\n")
	for _, e := range es {
		b.WriteString("\t" + e.text + "\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (g *gen) module(allow dnf) string {
	var b strings.Builder
	b.WriteString("package " + g.opt.Package + "\n\ndefault allow := false\n\n")
	for _, c := range allow {
		b.WriteString(clauseText("allow", c))
	}
	g.stats.Clauses = len(allow)
	used := g.used(allow)
	g.stats.Rules = len(used)
	for _, name := range g.order {
		if !used[name] {
			continue
		}
		body := g.rules[name]
		b.WriteString("\n")
		if len(body) == 0 {
			b.WriteString("default " + name + " := false\n")
			continue
		}
		target := name
		if len(body) > g.opt.AliasClauses {
			// A reference to a rule adds an edge per clause to the compiler's
			// dependency graph, so a rule of many clauses referenced from many
			// clauses costs their product: the references go to an alias.
			b.WriteString(clauseText(name, clause{{text: name + "__body"}}))
			target = name + "__body"
			g.stats.Clauses++
		}
		for _, c := range body {
			b.WriteString(clauseText(target, c))
		}
		g.stats.Clauses += len(body)
	}
	return b.String()
}
