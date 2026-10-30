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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

var errUndeclared = errors.New("the PIP is not declared")

// leafRails are the two rails of a leaf: the clauses where it is true and the
// clauses where it is false. A request on neither rail leaves the leaf
// undefined; threeValued is set when such a request exists.
type leafRails struct {
	t, f        dnf
	threeValued bool
	// subjectOnly is set when every expression reads only the subject's
	// projected attributes, so that the leaf can join a subject group.
	subjectOnly bool
}

type point struct {
	st spectables.State
	cl spectables.Class
}

func (p point) spec(k spectables.Kind) spectables.Point {
	return spectables.Point{Kind: k, State: p.st, Class: p.cl}
}

// points lists the (state, class) pairs the side can be in at this leaf.
func (s *side) points() []point {
	switch {
	case s.lit != nil:
		return []point{{spectables.StateValue, s.lit.class}}
	case s.isPattern():
		return []point{{spectables.StateValue, spectables.ClassString}}
	case s.fixed != "":
		return []point{{s.fixed, ""}}
	}
	var out []point
	for _, st := range s.ref.domain.States {
		if st != spectables.StateValue {
			out = append(out, point{st, ""})
			continue
		}
		for _, cl := range s.ref.domain.Classes {
			out = append(out, point{st, cl})
		}
	}
	return out
}

// field is the expression that reads one field of the side's value record.
func (s *side) field(f string) string {
	if s.ref.Network {
		return "p_" + s.ref.ID + "." + f
	}
	return "input." + f + "." + s.ref.ID
}

// bind is the clause that binds a network PIP's record, empty for any other
// side.
func (s *side) bind() clause {
	if s.ref == nil || !s.ref.Network {
		return nil
	}
	return clause{{cls: clsBuiltin, text: fmt.Sprintf("p_%s := nc.pip(%q)", s.ref.ID, s.ref.ID)}}
}

// cls is the class of a check of the side: after the binding for a network PIP.
func (s *side) cls(c int) int {
	if s.ref != nil && s.ref.Network {
		return clsAfterBuilt
	}
	return c
}

// at is the clause that holds exactly when the side is at the point; empty
// when the side has no other point.
func (s *side) at(p point) clause {
	if s.ref == nil || len(s.points()) == 1 {
		return nil
	}
	if p.st != spectables.StateValue {
		return conj(s.bind(), clause{{cls: s.cls(clsCheck), text: fmt.Sprintf("%s == %q", s.field("s"), p.st),
			fact: fact{ref: s.ref.ID, field: 's', val: string(p.st)},
			test: refTest(s, &test{kind: "state", val: string(p.st)})}})
	}
	return conj(s.bind(), clause{{cls: s.cls(clsCheck), text: fmt.Sprintf("%s == %q", s.field("t"), p.cl),
		fact: fact{ref: s.ref.ID, field: 't', val: string(p.cl)}, test: refTest(s, &test{kind: "cls", val: string(p.cl)})}})
}

// compare builds the rails of a comparison from the specification's cells.
// Every point of the operands' domains gets the outcome of its cell: a constant
// becomes a clause of the operands' states, and a cell whose outcome depends on
// the values becomes the template of the operator. A cell that is unsupported,
// a bad request, or value-dependent without a template is a generation error.
func (g *gen) compare(c policyir.Compare, ctx spectables.Context) (leafRails, error) {
	L, err := g.side(c.Left)
	if err != nil {
		if errors.Is(err, errUndeclared) {
			return leafRails{threeValued: true}, nil
		}
		return leafRails{}, err
	}
	var R *side
	if c.Right != nil {
		if R, err = g.side(c.Right); err != nil {
			if errors.Is(err, errUndeclared) {
				return leafRails{threeValued: true}, nil
			}
			return leafRails{}, err
		}
	}
	op := spectables.Operator(c.Op)
	lps := L.points()
	rps := []point{{}}
	if R != nil {
		rps = R.points()
	}
	cells := make([][]spectables.Cell, len(lps))
	for i, lp := range lps {
		cells[i] = make([]spectables.Cell, len(rps))
		for j, rp := range rps {
			key := spectables.Key{Op: op, Left: lp.spec(L.kind), Context: ctx}
			if R != nil {
				key.Right = rp.spec(R.kind)
			}
			cell, err := g.tab.Lookup(spectables.ProfileAgent, key)
			if err != nil {
				return leafRails{}, err
			}
			switch cell.Outcome {
			case spectables.OutcomeUnsupported, spectables.OutcomeBadRequest:
				return leafRails{}, fmt.Errorf("%s(%s %v, %s %v) at %s: the specification answers %s", op,
					L.kind, lp, kindOf(R), rps[j], ctx.Place, cell.Outcome)
			}
			cells[i][j] = cell
		}
	}
	g.stats.Lookups += len(lps) * len(rps)

	var rails leafRails
	add := func(o spectables.Outcome, c clause) {
		switch o {
		case spectables.OutcomeT:
			rails.t = union(rails.t, dnf{c})
		case spectables.OutcomeF:
			rails.f = union(rails.f, dnf{c})
		case spectables.OutcomeU:
			rails.threeValued = true
		}
	}
	constant := func(cs []spectables.Cell) (spectables.Outcome, bool) {
		o := cs[0].Outcome
		for _, c := range cs {
			if c.Outcome != o || o == spectables.OutcomeByValue {
				return "", false
			}
		}
		return o, true
	}
	coveredL := make([]bool, len(lps))
	coveredR := make([]bool, len(rps))
	for j := range rps {
		col := make([]spectables.Cell, len(lps))
		for i := range lps {
			col[i] = cells[i][j]
		}
		if o, ok := constant(col); ok && R != nil && R.ref != nil {
			coveredR[j] = true
			add(o, R.at(rps[j]))
		}
	}
	for i := range lps {
		if o, ok := constant(cells[i]); ok {
			coveredL[i] = true
			add(o, L.at(lps[i]))
		}
	}
	for i, lp := range lps {
		if coveredL[i] {
			continue
		}
		for j, rp := range rps {
			if coveredR[j] {
				continue
			}
			cell := cells[i][j]
			if cell.Outcome != spectables.OutcomeByValue {
				add(cell.Outcome, conj(L.at(lp), rightAt(R, rp)))
				continue
			}
			if err := g.byValue(&rails, op, L, R, cells, lps, rps, i, j); err != nil {
				return leafRails{}, err
			}
		}
	}
	rails.subjectOnly = sideSubjectOnly(L) && (R == nil || sideSubjectOnly(R))
	return rails, nil
}

func rightAt(R *side, p point) clause {
	if R == nil {
		return nil
	}
	return R.at(p)
}

// byValue adds the template rows of the value-dependent cell (i, j). A true
// row leaves out the class check of a side when the template applies, with the
// same true row, to every class whose record has the fields the row reads:
// then the fields themselves select the classes, and the index sees the bare
// equality. A false row keeps the checks, because its negations also hold
// where the fields are missing.
func (g *gen) byValue(rails *leafRails, op spectables.Operator, L, R *side, cells [][]spectables.Cell,
	lps, rps []point, i, j int) error {
	lp, rp := lps[i], rps[j]
	cell := cells[i][j]
	// A one-element GENERAL list of null, a boolean, or an object
	// (SINGLE_ODD) is a list that may hold a null element to the collection
	// operators: the templates of class xn, whose guard reads the record's n0.
	odd := func(p point) point {
		if p.st == spectables.StateSingleOdd {
			return point{spectables.StateValue, spectables.ClassNullElement}
		}
		return p
	}
	oddL, oddR := lp.st == spectables.StateSingleOdd, rp.st == spectables.StateSingleOdd
	lp, rp = odd(lp), odd(rp)
	if oddL != oddR && (lp.st != spectables.StateValue || R != nil && rp.st != spectables.StateValue) {
		// the other side has no value, so only a null element of the odd
		// list decides: it fails the PIP (undefined), and any other element
		// gives the cell's one remaining outcome
		oddSide := L
		if oddR {
			oddSide = R
		}
		var rest []spectables.Outcome
		for _, o := range cell.Outcomes {
			if o != spectables.OutcomeU {
				rest = append(rest, o)
			}
		}
		if len(rest) != 1 || !slices.Contains(cell.Outcomes, spectables.OutcomeU) {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) odd", op, L.kind, lps[i].st, kindOf(R), rps[j].st)]++
			return fmt.Errorf("%s: value-dependent cell in state %s × %s has no template", op, lps[i].st, rps[j].st)
		}
		if r, ok := uncovered(cell.ValueRule, spectables.RuleSingleOdd, spectables.RuleNullElementEnds); ok {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lps[i].st, kindOf(R), rps[j].st, r)]++
			return fmt.Errorf("%s: value rule %s of a SINGLE_ODD cell has no template", op, r)
		}
		g2 := conj(oddSide.bind(), clause{{cls: oddSide.cls(clsCheck), text: "not " + oddSide.field("n0"),
			fact: vfact(oddSide), test: refTest(oddSide, &test{kind: "non0"})}})
		c := conj(L.at(lps[i]), rightAt(R, rps[j]), g2)
		if rest[0] == spectables.OutcomeT {
			rails.t = union(rails.t, dnf{c})
		} else {
			rails.f = union(rails.f, dnf{c})
		}
		rails.threeValued = true
		return nil
	}
	if (op == spectables.OpEQ || op == spectables.OpNE) && lp.st == spectables.StateValue &&
		lp.cl == spectables.ClassString && L.ref != nil && R != nil && rp.st != spectables.StateValue &&
		len(cell.ValueRule) == 1 && cell.ValueRule[0] == spectables.RuleEq {
		// a right operand in a special state whose cell evaluates the values
		// is read as an empty list, and a string equals it by the text []
		eq := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field("k") + ` == "[]"`, fact: vfact(L)}})
		ne := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field("k") + ` != "[]"`, fact: vfact(L)}})
		if op == spectables.OpNE {
			eq, ne = ne, eq
		}
		at := conj(L.at(lps[i]), rightAt(R, rps[j]))
		rails.t = union(rails.t, prod(dnf{at}, dnf{eq}, true))
		rails.f = union(rails.f, prod(dnf{at}, dnf{ne}, true))
		return nil
	}
	if lp.st != spectables.StateValue || R != nil && rp.st != spectables.StateValue {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s)", op, L.kind, lp.st, kindOf(R), rp.st)]++
		return fmt.Errorf("%s(%s %s, %s %s): value-dependent cell in a state other than VALUE has no template", op,
			L.kind, lp.st, kindOf(R), rp.st)
	}
	if L.ref == nil && L.lit != nil && R != nil && R.ref == nil {
		// both values known at generation: a copy of the tree for one
		// operation compares the operation with a literal
		v, ok := constCompare(op, L, R)
		if _, bad := uncovered(cell.ValueRule, spectables.RuleEq, spectables.RuleInAny, spectables.RuleMatch); bad {
			ok = false
		}
		if !ok {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s, %s) of two literals", op, L.kind, R.kind)]++
			return fmt.Errorf("%s(%s, %s): no constant template", op, L.kind, R.kind)
		}
		if v {
			rails.t = union(rails.t, dnfTrue)
		} else {
			rails.f = union(rails.f, dnfTrue)
		}
		return nil
	}
	tp, ok := template(op, L, R, lp.cl, rp.cl)
	if ok && slices.Contains(cell.ValueRule, spectables.RuleRightListScalarOps) {
		if err := g.rightListScalarOps(&tp, R, rp); err != nil {
			g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lp.cl, kindOf(R), rp.cl,
				spectables.RuleRightListScalarOps)]++
			return fmt.Errorf("%s(%s %s, %s %s): %w", op, L.kind, lp.cl, kindOf(R), rp.cl, err)
		}
	}
	if ok && slices.Contains(cell.Outcomes, spectables.OutcomeU) && !tp.undefined {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) with U", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return fmt.Errorf("%s: value-dependent cell with an undefined outcome has no template", op)
	}
	if ok && tp.undefined && !slices.Contains(cell.Outcomes, spectables.OutcomeU) {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) without U", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return fmt.Errorf("%s: the template leaves a value undefined where the cell has no undefined outcome", op)
	}
	if tp.undefined {
		rails.threeValued = true
	}
	if oddL || oddR {
		// the template's expressions read the odd list in its own state, not
		// in VALUE
		tp.t, tp.f = withoutValueFacts(tp.t, L, oddL, R, oddR), withoutValueFacts(tp.f, L, oddL, R, oddR)
	}
	if !ok {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s)", op, L.kind, lp.cl, kindOf(R), rp.cl)]++
		return fmt.Errorf("%s(%s %s, %s %s): no template for a value-dependent cell", op, L.kind, lp.cl,
			kindOf(R), rp.cl)
	}
	have := slices.Collect(maps.Keys(tp.rules))
	if oddL || oddR {
		have = append(have, spectables.RuleSingleOdd)
	}
	if r, bad := uncovered(cell.ValueRule, have...); bad {
		g.stats.NoTemplate[fmt.Sprintf("%s(%s %s, %s %s) rule %s", op, L.kind, lp.cl, kindOf(R), rp.cl, r)]++
		return fmt.Errorf("%s(%s %s, %s %s): value rule %s has no template", op, L.kind, lp.cl, kindOf(R), rp.cl, r)
	}
	// same reports whether the template's true rows are the same at every
	// point of s whose record carries the fields they read, with the other
	// side at its point. A SINGLE_ODD record carries ks too, so a row that
	// reads ks keeps its check where the domain has that state.
	same := func(s *side, isLeft bool) bool {
		if s == nil || s.ref == nil {
			return true
		}
		fields := tp.fields[s]
		if len(fields) == 0 || fields["guard"] ||
			fields["ks"] && slices.Contains(s.ref.domain.States, spectables.StateSingleOdd) {
			return false
		}
		classes := tp.fieldClasses(s)
		if len(classes) == 0 {
			return false
		}
		want := tp.t.key()
		for _, cl := range classes {
			var c spectables.Cell
			lc, rc := lp.cl, rp.cl
			if isLeft {
				idx := slices.Index(lps, point{spectables.StateValue, cl})
				if idx < 0 {
					return false
				}
				c, lc = cells[idx][j], cl
			} else {
				idx := slices.Index(rps, point{spectables.StateValue, cl})
				if idx < 0 {
					return false
				}
				c, rc = cells[i][idx], cl
			}
			if c.Outcome != spectables.OutcomeByValue {
				return false
			}
			other, ok := template(op, L, R, lc, rc)
			if !ok || other.t.key() != want {
				return false
			}
		}
		return true
	}
	// At most one side drops its check: with both dropped, a row would also
	// hold at the pairs where both sides moved, which no check above covers.
	gl, gr := L.at(lps[i]), rightAt(R, rps[j])
	tl, tr := gl, gr
	if !oddL && same(L, true) {
		tl = L.bind()
	} else if R != nil && !oddR && same(R, false) {
		tr = R.bind()
	}
	rails.t = union(rails.t, prod(dnf{conj(tl, tr)}, tp.t, true))
	rails.f = union(rails.f, prod(dnf{conj(gl, gr)}, tp.f, true))
	return nil
}

func kindOf(s *side) spectables.Kind {
	if s == nil {
		return "-"
	}
	return s.kind
}

// sideSubjectOnly reports whether a side reads only what Go projects from the
// subject before Eval: a literal, or a subject attribute that is not a network
// PIP.
func sideSubjectOnly(s *side) bool {
	if s.ref == nil {
		return s.fixed == ""
	}
	if s.ref.Network {
		return false
	}
	switch s.ref.Kind {
	case spectables.KindSubjID, spectables.KindSubjName, spectables.KindSubjType, spectables.KindSubjRoles,
		spectables.KindSubjScopes, spectables.KindSubjPermissions, spectables.KindPIPToken,
		spectables.KindPIPHeader, spectables.KindPIPMapping:
		return true
	}
	return false
}

// constCompare compares two values known at generation, and returns false as
// its second result for an operator it does not evaluate.
func constCompare(op spectables.Operator, L, R *side) (bool, bool) {
	if pos, ok := negated[op]; ok {
		v, ok := constCompare(pos, L, R)
		return !v, ok
	}
	switch op {
	case spectables.OpEQ:
		if isScalar(L.lit.class) && isScalar(R.lit.class) {
			return L.lit.key == R.lit.key, true
		}
	case spectables.OpIn:
		if isScalar(L.lit.class) {
			return slices.Contains(R.lit.keys, L.lit.key), true
		}
	case spectables.OpMatch:
		if R.isPattern() && L.lit.class == spectables.ClassString {
			rx, err := matchRegex(R.pattern)
			if err != nil {
				return false, false
			}
			return regexp.MustCompile(rx).MatchString(L.lit.raw), true
		}
	}
	return false, false
}

// withoutValueFacts drops the requirement of state VALUE that template
// expressions put on an odd side.
func withoutValueFacts(d dnf, L *side, oddL bool, R *side, oddR bool) dnf {
	out := make(dnf, len(d))
	for i, c := range d {
		nc := make(clause, len(c))
		for j, e := range c {
			if e.fact.field == 'v' && (oddL && L.ref != nil && e.fact.ref == L.ref.ID ||
				oddR && R != nil && R.ref != nil && e.fact.ref == R.ref.ID) {
				e.fact = fact{}
			}
			nc[j] = e
		}
		out[i] = nc
	}
	return out
}

// uncovered returns the first rule of the cell that have does not list, and
// whether there is one.
func uncovered(rules []spectables.ValueRule, have ...spectables.ValueRule) (spectables.ValueRule, bool) {
	for _, r := range rules {
		if !slices.Contains(have, r) {
			return r, true
		}
	}
	return "", false
}

// rightListScalarOps adds the rule right_list_scalar_ops to the template of a
// cell that names it: a list of two or more values on the right answers with
// the profile's setting right_list_scalar_ops before the values are compared,
// for the negated operators too, and a shorter list compares as the template
// says. A cell of CONTAINS with a list attribute on the right has no base
// template, so it fails generation before this is reached.
func (g *gen) rightListScalarOps(tp *tpl, R *side, rp point) error {
	if R == nil || R.ref == nil || !isListClass(rp.cl) {
		return fmt.Errorf("value rule %s needs a list attribute on the right", spectables.RuleRightListScalarOps)
	}
	raw, ok := g.tab.Knob(spectables.ProfileAgent, "right_list_scalar_ops")
	if !ok {
		return fmt.Errorf("the export carries no knob right_list_scalar_ops")
	}
	var knob string
	if err := json.Unmarshal(raw, &knob); err != nil {
		return fmt.Errorf("knob right_list_scalar_ops: %w", err)
	}
	// the setting holds a legacy outcome; the agent ends no rule and fails
	// no decision there (an end is false, an error unknown)
	outcome, ok := map[string]spectables.Outcome{"T": spectables.OutcomeT, "F": spectables.OutcomeF,
		"ABORT": spectables.OutcomeF, "ERR": spectables.OutcomeU}[knob]
	if !ok {
		return fmt.Errorf("knob right_list_scalar_ops is %q, not an outcome", knob)
	}
	long := conj(R.bind(), clause{{cls: R.cls(clsCheck), text: R.field("ln") + " > 1", fact: vfact(R)}})
	short := conj(R.bind(), clause{{cls: R.cls(clsCheck), text: R.field("ln") + " <= 1", fact: vfact(R)}})
	tp.t = prod(dnf{short}, tp.t, true)
	tp.f = prod(dnf{short}, tp.f, true)
	switch outcome {
	case spectables.OutcomeT:
		tp.t = union(tp.t, dnf{long})
	case spectables.OutcomeF:
		tp.f = union(tp.f, dnf{long})
	default:
		tp.undefined = true
	}
	if tp.fields[R] == nil {
		tp.fields[R] = map[string]bool{}
	}
	tp.fields[R]["ln"] = true
	tp.rules[spectables.RuleRightListScalarOps] = true
	return nil
}
