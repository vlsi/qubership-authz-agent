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
	"errors"
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
	// Package is the Rego package of the module; data.<Package>.allow is
	// whether the request is allowed. [Options.Decision] adds a second module
	// in the package <Package>_decision.
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
	// Decision fills [Module.DecisionText], a second module that a denial
	// evaluates, so that the module of allow keeps its size. Its package is
	// <Package>_decision, and it holds allow, maybe, and decision. maybe
	// holds where the hi bound of some top-level node is permit. decision is
	// permit where allow holds; unknown where it does not but maybe does, so
	// the denial depends on a value or a source the agent could not read, a
	// permanent failure of [Module.Failures] included (the root's lo and hi
	// bounds differ); deny otherwise.
	Decision bool
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
	// Iterates is set when the module reads the passes of an iterate over
	// subject.permissionScope, which [Project] takes from [Request.Scope].
	Iterates bool
	// DecisionText is the decision module, empty without
	// [Options.Decision].
	DecisionText string
	// Groups are the subject groups of the module, by ID.
	Groups map[string]Group
	// Stats counts what the generator produced.
	Stats Stats
	// Report holds the [LeafReport] of every comparison, when
	// [Options.Report] is set.
	Report []LeafReport
	// Failures lists the parts of the tenant the module reads as a permanent
	// failure of their source, in the order the generator met them.
	Failures []Failure

	ixOnce sync.Once
	ix     *groupIndex
}

// Stats counts what the generator produced. Clauses, AllowClauses,
// UnguardedAllow, Rules, and Bytes describe [Module.Text], the module of
// allow.
type Stats struct {
	Leaves, ThreeValuedConds, Lookups            int
	Clauses, AllowClauses, UnguardedAllow, Rules int
	Materialized, AccessCopies, Iterates, Bytes  int
	// DecisionClauses counts the clauses of [Module.DecisionText].
	DecisionClauses int
	NoTemplate      map[string]int
}

type nodeKind int

const (
	kindRule nodeKind = iota
	kindPolicy
	kindSet
	kindSimplified
	kindUnknown // a set the agent evaluates to [deny, permit] under its target
	kindIterate // an iterate set: its only kid is the set evaluated in one pass
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
	// vars maps the [Ref.Var] of each reference to its ID.
	vars map[string]string

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
	// copyPrefix starts the node IDs of the copy of the tree a decision for
	// another operation reads: the decision's name and _; empty in the tree
	// itself.
	copyPrefix string
	// light holds the rules that are not a node's or a product's: condition
	// rails and decisions for another operation.
	light map[string]bool

	groups   map[string]Group
	groupIDs map[string]string

	// sources holds what the comments say of each node, by label; shared
	// holds the rules several nodes may read, and ruleAtoms the comparisons
	// their clauses came from.
	sources   map[string]nodeSource
	shared    map[string]bool
	ruleAtoms map[string][]string

	stats Stats
	// pass is set while the generator translates the subtree of an iterate
	// set, whose rules are functions of the pass p.
	pass bool
	// params holds the rules that are functions of the pass.
	params map[string]bool

	where    whereNow
	report   []LeafReport
	failures []Failure

	uncertainMemo map[*node]bool
}

// Generate translates the policy tree of a tenant into one Rego module that
// answers check/resource as the profile agent of the specification does. The
// leaves come from the agent profile of tab. A tree with a form the agent
// cannot execute gives a [*RejectedError]; any other error is a defect of the
// export or the generator. With an error, the module carries only the
// statistics gathered up to it. A part of the tree that fails as a source does
// generates, and [Module.Failures] lists it.
func Generate(tree *policyir.Tree, tab *spectables.Table, opt Options) (*Module, error) {
	g := &gen{tab: tab, tree: tree, opt: opt, refs: map[string]*Ref{}, vars: map[string]string{}, rules: map[string]dnf{},
		memo: map[string]string{}, counters: map[string]int{}, anyBodies: map[string]dnf{},
		condMemo: map[string]*cond{}, decNames: map[string]string{}, decRoots: map[string]*node{},
		groups: map[string]Group{}, groupIDs: map[string]string{}, params: map[string]bool{}, uncertainMemo: map[*node]bool{},
		sources: map[string]nodeSource{}, shared: map[string]bool{}, ruleAtoms: map[string][]string{}, light: map[string]bool{}}
	g.stats.NoTemplate = map[string]int{}
	if fs := tree.Unsupported(); len(fs) > 0 {
		rej := &RejectedError{}
		for _, f := range fs {
			rej.Rejections = append(rej.Rejections, Rejection{Where: f.Where, Form: f.Form, Text: f.Text})
		}
		return &Module{Stats: g.stats}, rej
	}
	nodes, ok := tab.Nodes(spectables.ProfileAgent)
	if !ok {
		return nil, fmt.Errorf("the leaf-outcome tables carry no node rules for profile %s", spectables.ProfileAgent)
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
			g.light[g.rule(name+"_"+f, body)] = true
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
	maybe := dnfFalse
	if g.opt.Decision {
		for _, t := range tops {
			d, err := g.flag(t, "hi", "P")
			if err != nil {
				return nil, err
			}
			maybe = union(maybe, d)
		}
	}
	m := &Module{Refs: g.refList, Iterates: g.stats.Iterates > 0, Groups: g.groups, Report: g.report,
		Failures: g.failures}
	if g.opt.Decision {
		m.DecisionText, g.stats.DecisionClauses = g.module(g.opt.Package+"_decision", allow, maybe, true)
	}
	m.Text, g.stats.Clauses = g.module(g.opt.Package, allow, nil, false)
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

// nodeID returns the ID of the node with label, which starts the names of its
// rules.
func (g *gen) nodeID(label string) string { return g.copyPrefix + label }

func (g *gen) tops() ([]*node, error) {
	var tops []*node
	// ids maps a label to the ID it was given to; seen counts the sets of
	// each ID, as a tenant may hold several under one ID
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
	for _, sg := range g.tree.Simplified {
		l, err := label(sg.ID)
		if err != nil {
			return nil, err
		}
		n, err := g.simplified(sg, l)
		if err != nil {
			return nil, err
		}
		if n != nil {
			tops = append(tops, n)
		}
	}
	for _, s := range g.tree.Sets {
		l, err := label(s.ID)
		if err != nil {
			return nil, err
		}
		n, err := g.set(s, l, "")
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

// simplified translates a simplified group whose node has label.
func (g *gen) simplified(sg *policyir.SimplifiedGroup, label string) (*node, error) {
	n := &node{kind: kindSimplified, id: g.nodeID(label)}
	saved := g.where
	defer func() { g.where = saved }()
	g.source(label, "", fmt.Sprintf("simplified %q %q, resourceType %q", sg.ID, commentLine(sg.Name), sg.ResourceType))
	for i, p := range sg.Policies {
		pl := fmt.Sprintf("%s_p%d", label, i+1)
		g.where = whereNow{set: sg.ID, policy: p.ID, label: pl}
		g.source(pl, label, fmt.Sprintf("simplified policy %q, operation %q, roles %q", p.ID, p.Operation, p.Roles),
			"condition: "+condText(p.Condition))
		simpSrc := func(atom string) *exprSrc { return &exprSrc{node: pl, atom: atom} }
		var m clause
		if sg.ResourceType != "ALL" {
			r, err := g.ref(policyir.ResourceType{}, spectables.KindResourceType, false)
			if err != nil {
				return nil, err
			}
			m = conj(m, clause{{cls: clsIndexEq, text: "input.k" + refIndex(r.ID) + " == " + lit(g.fold(sg.ResourceType)),
				src: simpSrc("resourceType == " + lit(sg.ResourceType))}})
		}
		op := p.Operation
		if g.fixedOp != nil {
			if op != "ALL" && g.fold(op) != g.fold(*g.fixedOp) {
				continue
			}
		} else if op != "ALL" {
			r, err := g.ref(policyir.Operation{}, spectables.KindOperation, false)
			if err != nil {
				return nil, err
			}
			m = conj(m, clause{{cls: clsIndexEq, text: "input.k" + refIndex(r.ID) + " == " + lit(g.fold(op)),
				src: simpSrc("operation == " + lit(op))}})
		}
		var roles dnf
		for _, r := range p.Roles {
			roles = append(roles, clause{{cls: clsIndexIn, text: lit(g.fold(r)) + " in input.sroles",
				test: &test{kind: "has", ref: "sroles", val: g.fold(r)}, src: simpSrc("role " + lit(r))}})
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

// set translates a policy set whose node has label, under the node parent,
// empty for a top-level set.
func (g *gen) set(s *policyir.PolicySet, label, parent string) (*node, error) {
	id := g.nodeID(label)
	saved := g.where
	defer func() { g.where = saved }()
	g.where = whereNow{set: s.ID, label: label}
	g.source(label, parent, fmt.Sprintf("set %q %q, %s", s.ID, commentLine(s.Name), s.Algorithm),
		"target: "+condText(s.Target))
	tgt, err := g.cond(s.Target, spectables.PlaceSetTarget, "")
	if err != nil {
		return nil, err
	}
	if s.AlwaysFails != "" || s.Isolated != "" {
		reason := s.AlwaysFails
		if s.Isolated != "" {
			reason = "isolated: " + s.Isolated
		}
		g.fail(Failure{Set: s.ID, Reason: reason})
		return &node{kind: kindUnknown, id: id, tgt: tgt}, nil
	}
	n := &node{kind: kindSet, id: id, alg: g.alg(s.Algorithm), tgt: tgt}
	if s.Iterate != nil {
		// The set is evaluated once per pass under the set's algorithm, and
		// the passes combine by the iterate's: the set's node is the one kid
		// of the iterate's node, and its subtree reads the pass.
		g.stats.Iterates++
		saved := g.pass
		g.pass = true
		defer func() { g.pass = saved }()
		n.tgt = g.constCond(true)
		n.id = id + "_each"
		it := &node{kind: kindIterate, id: id, alg: g.alg(s.Iterate.Algorithm), tgt: tgt, kids: []*node{n}}
		if err := g.setKids(n, s, label); err != nil {
			return nil, err
		}
		return it, nil
	}
	if err := g.setKids(n, s, label); err != nil {
		return nil, err
	}
	return n, nil
}

// setKids translates the policies and the nested sets of s, whose node has
// label, into the kids of n.
func (g *gen) setKids(n *node, s *policyir.PolicySet, label string) error {
	for i, p := range s.Policies {
		k, err := g.policy(p, fmt.Sprintf("%s_p%d", label, i+1), label)
		if err != nil {
			return err
		}
		n.kids = append(n.kids, k)
	}
	for i, c := range s.Sets {
		k, err := g.set(c, fmt.Sprintf("%s_s%d", label, i+1), label)
		if err != nil {
			return err
		}
		n.kids = append(n.kids, k)
	}
	return nil
}

// policy translates a policy whose node has label, under the set parent.
func (g *gen) policy(p *policyir.Policy, label, parent string) (*node, error) {
	set := g.where.set
	g.where = whereNow{set: set, policy: p.ID, label: label}
	g.source(label, parent, fmt.Sprintf("policy %q %q, %s", p.ID, commentLine(p.Name), p.Algorithm),
		"target: "+condText(p.Target))
	tgt, err := g.cond(p.Target, spectables.PlacePolicyTarget, "")
	if err != nil {
		return nil, err
	}
	n := &node{kind: kindPolicy, id: g.nodeID(label), alg: g.alg(p.Algorithm), tgt: tgt}
	for j, r := range p.Rules {
		rl := fmt.Sprintf("%s_r%d", label, j+1)
		g.where = whereNow{set: set, policy: p.ID, rule: r.ID, label: rl}
		g.source(rl, label, fmt.Sprintf("rule %q %q, %s", r.ID, commentLine(r.Name), r.Effect),
			"target: "+condText(r.Target), "condition: "+condText(r.Condition))
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
		n.kids = append(n.kids, &node{kind: kindRule, id: g.nodeID(rl), tgt: rt, cond: rc, effect: eff})
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
	k := fmt.Sprintf("%p|%s|%s|%s|%t", c, place, effect, fixed, g.pass)
	if cc, ok := g.condMemo[k]; ok {
		return cc, nil
	}
	// The leaf's context carries the effect as the rule writes it, which is
	// what a leaf reads, not what the effect counts as at the node: only a
	// written DENY is DENY, an absent effect reads as ALLOW.
	ctx := spectables.Context{Place: place, Effect: spectables.EffectAllow, Disjunction: c.HasOr(), InIterate: g.pass}
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
				if rej := (*RejectedError)(nil); errors.As(err, &rej) {
					return nil, err
				}
				if gp := (*gapError)(nil); errors.As(err, &gp) {
					return nil, &RejectedError{Rejections: []Rejection{{Where: g.whereText(), Form: gp.form,
						Text: fmt.Sprintf("%s: %v", policyir.FormatCondition(c), err)}}}
				}
				return nil, fmt.Errorf("%s: %w", policyir.FormatCondition(c), err)
			}
			src := &exprSrc{node: g.where.label, atom: atomText(a)}
			l.t, l.f = stamp(l.t, src), stamp(l.f, src)
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
		if g.pass {
			// legacy reads the decision for the operation in the current
			// pass, which needs a copy of the tree per pass
			return leafRails{}, gap(FormGenerator, fmt.Errorf("subject allowed or denied inside iterate"))
		}
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
		name = fmt.Sprintf("dec_%s_%d", escapeID(g.fold(a.Operation)), depth)
		g.decNames[key] = name
		g.decOrder = append(g.decOrder, name)
		savedOp, savedDepth, savedCopy := g.fixedOp, g.fixedDepth, g.copyPrefix
		op := a.Operation
		g.fixedOp, g.fixedDepth, g.copyPrefix = &op, depth, name+"_"
		tops, err := g.tops()
		g.fixedOp, g.fixedDepth, g.copyPrefix = savedOp, savedDepth, savedCopy
		if err != nil {
			return leafRails{}, err
		}
		g.decRoots[name] = &node{kind: kindSet, id: name, alg: policyir.AlgorithmPermitOverrides,
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
	// a decision that reads no unknown value has hi equal to lo, so the leaf
	// is two-valued and reads lo alone
	hi, three := name+"_hiP", g.uncertain(g.decRoots[name])
	if !three {
		hi = name + "_loP"
	}
	if !a.Denied {
		return leafRails{t: ref(name+"_loP", false), f: ref(hi, true), threeValued: three}, nil
	}
	// denied: deny is true, permit false, and not applicable is
	// denied_without_decision, true
	return leafRails{t: ref(hi, true), f: ref(name+"_loP", false), threeValued: three}, nil
}

// uncertain reports whether the lo and hi bounds of n can differ: a rule
// condition at or below n is three-valued, or n or a node below it fails as a
// source or iterates over a permission scope that may fail. A three-valued
// target does not split the bounds, as an undefined target makes its node
// deny on both.
func (g *gen) uncertain(n *node) bool {
	if u, ok := g.uncertainMemo[n]; ok {
		return u
	}
	u := false
	switch n.kind {
	case kindUnknown, kindIterate:
		u = true
	case kindRule:
		u = n.cond.three
	case kindSimplified:
		u = slices.ContainsFunc(n.simp, func(k simpKid) bool { return k.c.three })
	default:
		u = slices.ContainsFunc(n.kids, g.uncertain)
	}
	g.uncertainMemo[n] = u
	return u
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
		if g.pass {
			g.params[name] = true
		}
	}
	return name
}

// call is the text that reads rule name: name, or name(p) for a function of
// the pass.
func (g *gen) call(name string) string {
	if g.params[name] {
		return name + "(p)"
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
	k := fmt.Sprintf("%s|%t|%s", prefix, g.pass, d.key())
	name, ok := g.memo[k]
	if !ok {
		name = g.rule(g.fresh(prefix), d)
		g.memo[k] = name
		if prefix == "c" {
			g.light[name] = true
		}
	}
	if prefix == "m" || prefix == "c" {
		// several nodes read the rule: its comment names the comparisons
		// of every reader, in an order no reader decides
		g.shared[name] = true
		for _, a := range atoms(d) {
			if !slices.Contains(g.ruleAtoms[name], a) {
				g.ruleAtoms[name] = append(g.ruleAtoms[name], a)
			}
		}
		slices.Sort(g.ruleAtoms[name])
	}
	text := g.call(name)
	if negate {
		text = "not " + text
	}
	return dnf{{{cls: clsCheck, text: text, rule: name, src: &exprSrc{nodes: dnfNodes(d)}}}}
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
		if len(y) > g.opt.RefFanout && g.refsNodeRule(x) {
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
// is x (P permit, D deny). The hi bound of a node no unknown value reaches
// (uncertain) is its lo bound, and reads the same clauses.
func (g *gen) flag(n *node, b, x string) (dnf, error) {
	if b == "hi" && !g.uncertain(n) {
		return g.flag(n, "lo", x)
	}
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
	case kindIterate:
		return g.iterateFlag(n, b, x)
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
// inlined when positive in the flat form, or a reference to its rule; for an
// iterate node, whose children are its passes, always a reference (anyPass).
func (g *gen) anyKid(n *node, b, x string, negate bool) (dnf, error) {
	if n.kind == kindIterate {
		return g.anyPass(n, b, x, negate)
	}
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
	ref := dnf{{{cls: clsCheck, text: g.call(name), rule: name}}}
	if negate {
		if body.isFalse() {
			return dnfTrue, nil
		}
		return dnf{{{cls: clsCheck, text: "not " + g.call(name), rule: name}}}, nil
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

// decisionText is the rule decision, as [Options.Decision] describes it.
// Only a denial whose bounds differ is unknown: a failed value in a target
// makes its node deny on both bounds, and the denial is deny.
const decisionText = `
decision := "permit" if {
	allow
} else := "unknown" if {
	maybe
} else := "deny"
`

// readsPass reports whether a clause of d reads the pass p.
func readsPass(d dnf) bool {
	for _, c := range d {
		for _, e := range c {
			if strings.Contains(e.text, "p.") || strings.Contains(e.text, "(p)") {
				return true
			}
		}
	}
	return false
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
		b.WriteString("\t" + e.text)
		if c := lineComment(e); c != "" {
			b.WriteString(" # " + commentLine(c))
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// module writes the text of a module in package pkg and returns it with its
// number of clauses: allow and the rules it reads, and with decision also the
// rules maybe and decision and what maybe reads.
func (g *gen) module(pkg string, allow, maybe dnf, decision bool) (string, int) {
	var b strings.Builder
	b.WriteString("package " + pkg + "\n\n" + legend + "\ndefault allow := false\n\n")
	cm := &commenter{g: g, b: &b, printed: map[string]bool{}}
	for _, c := range allow {
		cm.clause(c)
		b.WriteString(clauseText("allow", c))
	}
	clauses := len(allow)
	if decision {
		b.WriteString(decisionText)
		b.WriteString("\ndefault maybe := false\n\n")
		cm.last = ""
		for _, c := range maybe {
			cm.clause(c)
			b.WriteString(clauseText("maybe", c))
		}
		clauses += len(maybe)
	}
	used := g.used(union(allow, maybe))
	if !decision {
		g.stats.Rules = len(used)
	}
	for _, name := range g.order {
		if !used[name] {
			continue
		}
		body := g.rules[name]
		// a function of the pass has the head name(p); its default and a
		// body that holds always do not read p
		head, any, of := name, name, func(n string) string { return n }
		if g.params[name] {
			head, any, of = name+"(p)", name+"(_)", func(n string) string { return n + "(p)" }
			if !readsPass(body) && len(body) <= g.opt.AliasClauses {
				// a strict compiler refuses an argument the body never reads;
				// an alias passes p on, so it keeps it
				head = any
			}
		}
		b.WriteString("\n")
		cm.last = ""
		if g.shared[name] {
			for _, a := range g.ruleAtoms[name] {
				b.WriteString("# " + commentLine(a) + "\n")
			}
		}
		if len(body) == 0 {
			b.WriteString("default " + any + " := false\n")
			continue
		}
		target := head
		if len(body) > g.opt.AliasClauses {
			// A reference to a rule adds an edge per clause to the compiler's
			// dependency graph, so a rule of many clauses referenced from many
			// clauses costs their product: the references go to an alias.
			b.WriteString(clauseText(head, clause{{text: of(name + "__body")}}))
			target = of(name + "__body")
			clauses++
		}
		for _, c := range body {
			if !g.shared[name] {
				cm.clause(c)
			}
			if len(c) == 0 && g.params[name] {
				b.WriteString(clauseText(strings.TrimSuffix(target, "(p)")+"(_)", c))
				continue
			}
			b.WriteString(clauseText(target, c))
		}
		clauses += len(body)
	}
	return b.String(), clauses
}
