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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// The filter returns the rows that a check of each row would allow, where a
// rule's predicate stands for its condition on the row. A node on a row
// permits, denies, or does not apply, so it is described by two sets of rows:
// those it allows (A) and those it denies (D). An algorithm combines the pairs
// of its children:
//
//	DENY_OVERRIDES      A = ∪A ∖ ∪D   D = ∪D
//	PERMIT_OVERRIDES    A = ∪A        D = ∪D ∖ ∪A
//	DENY_UNLESS_PERMIT  A = ∪A        D = all rows ∖ ∪A
//	PERMIT_UNLESS_DENY  A = all ∖ ∪D  D = ∪D
//
// The answer is A of the root, the union of the top-level nodes' A: empty is
// DENY, all rows ALLOW, anything else USE_FILTER_CONDITION with its text.
//
// A set the agent cannot write as a predicate shrinks A and never grows it,
// so the filter never returns a row the check would deny. D may grow for the
// same reason: a D the agent cannot write is unknown, and subtracting it
// leaves A empty.

// rowKind is what a set of rows is.
type rowKind int

const (
	rowsNone    rowKind = iota
	rowsAll             // every row
	rowsSome            // the rows of any of groups
	rowsNot             // every row but those of any of groups
	rowsUnknown         // rows the agent cannot name
)

// rows is a set of rows. groups are the predicates of rowsSome and rowsNot,
// joined by OR, each rendered as one group of the answer.
type rows struct {
	kind   rowKind
	groups []*fexpr
}

// pair is what a node gives on the rows: those it allows and those it denies.
type pair struct{ a, d rows }

var (
	none    = rows{}
	allRows = rows{kind: rowsAll}
)

// errDenyAll ends the evaluation: the whole filter is DENY, as legacy answers
// when a source a rule needs fails.
var errDenyAll = errors.New("filter: deny all")

// unionRows is the union of xs. Every row but those of g, joined with the
// rows of h or with every row but those of h, stays every row but some:
// (all ∖ g) ∪ h = all ∖ (g ∖ h) and (all ∖ g) ∪ (all ∖ h) = all ∖ (g ∩ h).
func unionRows(xs ...rows) rows {
	out := none
	for _, x := range xs {
		switch {
		case x.kind == rowsNone:
		case out.kind == rowsAll || x.kind == rowsAll:
			out = allRows
		case out.kind == rowsUnknown || x.kind == rowsUnknown:
			out = rows{kind: rowsUnknown}
		case out.kind == rowsNone:
			out = rows{kind: x.kind, groups: slices.Clone(x.groups)}
		case out.kind == x.kind && out.kind == rowsSome:
			out.groups = distinct(append(out.groups, x.groups...))
		case out.kind == x.kind && groupsKey(out.groups) == groupsKey(x.groups):
			// every row but g, twice
		case out.kind == x.kind:
			out = rows{kind: rowsNot, groups: []*fexpr{andOf([]*fexpr{groupOf(out.groups), groupOf(x.groups)})}}
		default:
			not, some := out, x
			if not.kind != rowsNot {
				not, some = x, out
			}
			parts := []*fexpr{groupOf(not.groups)}
			for _, g := range some.groups {
				parts = append(parts, negate(g))
			}
			out = rows{kind: rowsNot, groups: []*fexpr{andOf(parts)}}
		}
	}
	return out
}

// filterEval holds what one evaluation of the filter reads.
type filterEval struct {
	m      *Module
	ctx    context.Context
	req    *Request
	st     *Statuses
	failed map[string]bool
	// approx is the first approximation of the plan: a node's A loses every
	// row once any of its children denies a row it can name.
	approx bool
	sub    *substituter
}

// tri is a three-valued status: true, false, or unknown; err marks an
// unknown that rests on a failed source rather than on the resource.
type tri struct {
	v   int8 // 1 true, 0 false, -1 unknown
	err bool
}

func (e *filterEval) status(s status, pass int) tri {
	if s.key == "" {
		if s.konst {
			return tri{v: 1}
		}
		return tri{}
	}
	var t, f bool
	if s.pass {
		t, f = e.st.tp[passKey{s.key, pass}], e.st.fp[passKey{s.key, pass}]
	} else {
		t, f = e.st.t[s.key], e.st.f[s.key]
	}
	switch {
	case t:
		return tri{v: 1}
	case f || !s.three:
		return tri{}
	}
	return tri{v: -1, err: e.sourceFailed(s, pass)}
}

// scopeOutside stands in the references of a status for a read of
// subject.permissionScope outside a pass of iterate, which fails the decision
// as a failed source does.
var scopeOutside = &Ref{Key: "subject.permissionScope"}

// sourceFailed reports whether a reference of s reads a source that failed
// on this request.
func (e *filterEval) sourceFailed(s status, pass int) bool {
	for _, r := range s.refs {
		switch {
		case r == scopeOutside:
			return true
		case r.pip != nil:
			if e.failed[r.pip.Name] {
				return true
			}
		case r.ent != nil:
			if e.failed[entitlementsPIP] {
				return true
			}
		case r.Pass:
			if e.req.Scope != nil && pass >= 0 && pass < len(e.req.Scope.Passes) &&
				e.req.Scope.Passes[pass][r.Key].State == spectables.StateError {
				return true
			}
		}
		if v, ok := e.req.Values[r.Key]; ok && v.State == spectables.StateError {
			return true
		}
	}
	return false
}

// and is a ∧ b by Kleene.
func and(a, b tri) tri {
	switch {
	case a.v == 0 || b.v == 0:
		return tri{}
	case a.v == 1 && b.v == 1:
		return tri{v: 1}
	}
	return tri{v: -1, err: a.v == -1 && a.err || b.v == -1 && b.err}
}

// top returns A of the root.
func (e *filterEval) top(plan *filterPlan) (rows, error) {
	var as []rows
	for _, n := range plan.tops {
		var p pair
		var err error
		if n.kind == kindSimplified {
			p, err = e.simplified(n)
		} else {
			p, err = e.node(n, -1, "")
		}
		if err != nil {
			return none, err
		}
		as = append(as, p.a)
	}
	return unionRows(as...), nil
}

// simplified evaluates the policies of one operation of a simplified group.
func (e *filterEval) simplified(n *fnode) (pair, error) {
	var terms []*fexpr
	for _, s := range n.simp {
		if e.status(s.match, -1).v != 1 {
			continue
		}
		c := e.status(s.cond, -1)
		if hasPredicate(s.preds) {
			if c.v == 0 || c.v == -1 && c.err {
				continue
			}
			t, err := e.sub.term(s.preds, s.id, -1)
			if err != nil {
				return pair{}, err
			}
			terms = append(terms, t)
			continue
		}
		switch {
		case c.v == 1:
			return pair{a: allRows}, nil
		case c.v == -1 && c.err:
			return pair{}, errDenyAll
		}
	}
	if len(terms) == 0 {
		return pair{}, nil
	}
	return pair{a: rows{kind: rowsSome, groups: []*fexpr{orOf(terms)}}}, nil
}

// node evaluates a set, an iterate, or a policy in pass (-1 outside an
// iterate). prefix starts the custom keys of the rules of a policy that a
// pass evaluates.
func (e *filterEval) node(n *fnode, pass int, prefix string) (pair, error) {
	if e.status(n.tgt, pass).v != 1 {
		// a target over the resource or a failed source leaves the node out,
		// as legacy does
		return pair{}, nil
	}
	switch n.kind {
	case kindUnknown:
		return pair{d: rows{kind: rowsUnknown}}, nil
	case kindPolicy:
		return e.policy(n, pass, prefix)
	case kindIterate:
		return e.iterate(n)
	}
	kids := make([]pair, 0, len(n.kids))
	for _, k := range n.kids {
		kp := ""
		if k.kind == kindPolicy {
			kp = prefix
		}
		p, err := e.node(k, pass, kp)
		if err != nil {
			return pair{}, err
		}
		kids = append(kids, p)
	}
	return e.combine(n.alg, kids), nil
}

// iterate evaluates the set of iterate n once per pass of the subject's
// permission scope and combines the passes by the iterate's algorithm. The
// groups of the passes form one group of the answer.
func (e *filterEval) iterate(n *fnode) (pair, error) {
	sc := e.req.Scope
	if sc == nil || sc.Failed {
		return pair{d: rows{kind: rowsUnknown}}, nil
	}
	each := n.kids[0]
	passes := make([]pair, 0, len(sc.Passes))
	for i := range sc.Passes {
		p, err := e.node(each, i, fmt.Sprintf("%s_%d_", each.setID, i))
		if err != nil {
			return pair{}, err
		}
		if p.a.kind == rowsSome && len(p.a.groups) > 1 {
			p.a.groups = []*fexpr{{kind: "grp", parts: p.a.groups}}
		}
		passes = append(passes, p)
	}
	out := e.combine(n.alg, passes)
	if out.a.kind == rowsSome && len(out.a.groups) > 1 {
		out.a.groups = []*fexpr{{kind: "grp", parts: out.a.groups}}
	}
	return out, nil
}

// policy evaluates the rules of policy n. The allowed predicates of a policy
// form one group of the answer.
func (e *filterEval) policy(n *fnode, pass int, prefix string) (pair, error) {
	var allow, deny []*fexpr
	allowAll, denyAll, denyUnknown := false, false, false
	for _, r := range n.kids {
		t := e.status(r.tgt, pass)
		if t.v == 0 || t.v == -1 && t.err {
			continue
		}
		if r.effect != "ALLOW" && r.effect != "DENY" {
			continue
		}
		c := and(t, e.status(r.cond, pass))
		if hasPredicate(r.preds) {
			if c.v == 0 || c.v == -1 && c.err && r.effect == "ALLOW" {
				continue
			}
			term, err := e.sub.term(r.preds, prefix+r.ruleID, pass)
			if err != nil {
				return pair{}, err
			}
			if r.effect == "ALLOW" {
				allow = append(allow, term)
			} else {
				deny = append(deny, term)
			}
			continue
		}
		switch {
		case c.v == 1 && r.effect == "ALLOW":
			allowAll = true
		case c.v == 1:
			denyAll = true
		case c.v == -1 && c.err:
			return pair{}, errDenyAll
		case c.v == -1 && r.effect == "DENY":
			denyUnknown = true
		}
	}
	a := none
	switch {
	case allowAll:
		a = allRows
	case len(allow) > 0:
		a = rows{kind: rowsSome, groups: []*fexpr{orOf(allow)}}
	}
	d := none
	switch {
	case denyAll:
		d = allRows
	case denyUnknown:
		d = rows{kind: rowsUnknown}
	case len(deny) > 0:
		d = rows{kind: rowsSome, groups: deny}
	}
	return e.combine(n.alg, []pair{{a: a}, {d: d}}), nil
}

// combine applies algorithm alg to the pairs of the children.
func (e *filterEval) combine(alg policyir.Algorithm, kids []pair) pair {
	as, ds := make([]rows, len(kids)), make([]rows, len(kids))
	for i, k := range kids {
		as[i], ds[i] = k.a, k.d
	}
	A, D := unionRows(as...), unionRows(ds...)
	switch alg {
	case policyir.AlgorithmDenyOverrides:
		return pair{a: e.subtract(A, D), d: D}
	case policyir.AlgorithmPermitOverrides:
		if A.kind == rowsAll {
			return pair{a: A}
		}
		// D ∖ A may stay D: a D that grows only shrinks the A of an ancestor
		return pair{a: A, d: D}
	case policyir.AlgorithmDenyUnlessPermit:
		return pair{a: A, d: complement(A)}
	case policyir.AlgorithmPermitUnlessDeny:
		return pair{a: e.subtract(allRows, D), d: D}
	}
	return pair{a: A, d: D}
}

// complement is every row but those of x.
func complement(x rows) rows {
	switch x.kind {
	case rowsNone:
		return allRows
	case rowsAll:
		return none
	case rowsSome:
		return rows{kind: rowsNot, groups: x.groups}
	case rowsNot:
		return rows{kind: rowsSome, groups: x.groups}
	}
	return rows{kind: rowsUnknown}
}

// subtract is a ∖ d, or what of it the predicates can write: an unknown d,
// or any d under the first approximation, leaves nothing.
func (e *filterEval) subtract(a, d rows) rows {
	switch {
	case d.kind == rowsNone || a.kind == rowsNone:
		return a
	case d.kind == rowsAll || d.kind == rowsUnknown || e.approx:
		return none
	}
	var parts []*fexpr
	if a.kind == rowsSome {
		parts = append(parts, groupOf(a.groups))
	}
	if d.kind == rowsNot {
		// a ∖ (all ∖ g) = a ∩ g
		parts = append(parts, groupOf(d.groups))
	} else {
		for _, g := range d.groups {
			parts = append(parts, negate(g))
		}
	}
	if len(parts) == 1 {
		return rows{kind: rowsSome, groups: parts}
	}
	return rows{kind: rowsSome, groups: []*fexpr{andOf(parts)}}
}

// groupOf is the groups gs as one operand of an AND: the group alone, a
// predicate wrapped in a group of one so that it keeps its parentheses, or
// a group of groups.
func groupOf(gs []*fexpr) *fexpr {
	if len(gs) > 1 {
		return &fexpr{kind: "grp", parts: gs}
	}
	if gs[0].kind == "leaf" {
		return &fexpr{kind: "or", parts: gs}
	}
	return gs[0]
}

// failedSources returns the PIPs whose calls failed in ctx, by name.
func failedSources(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	for _, n := range regobuiltins.FailedPIPs(ctx) {
		out[n] = true
	}
	return out
}

func groupsKey(gs []*fexpr) string {
	keys := make([]string, len(gs))
	for i, g := range gs {
		keys[i] = g.key()
	}
	return strings.Join(keys, "\x02")
}
