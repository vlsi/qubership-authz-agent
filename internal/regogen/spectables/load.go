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

package spectables

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// SchemaVersion is the version of the export format the exporter writes.
const SchemaVersion = 2

// schemaVersion1 is the format before value rules, the split of class x, and
// nodes. [Load] still reads it, because the generator embeds an export of
// that version until the exporter writes version 2.
const schemaVersion1 = 1

// maxProblems bounds how many problems an error from [Load] spells out.
const maxProblems = 20

var (
	// ErrInvalid reports an export that violates the format: malformed JSON, a
	// field or knob the format does not define, a value outside its
	// enumeration, or two cells that answer the same question.
	ErrInvalid = errors.New("invalid specification export")
	// ErrIncomplete reports a well-formed export that leaves a required question
	// unanswered: a missing profile, knob, or kind domain, or a combination of
	// operator and operand kinds with a point no cell covers.
	ErrIncomplete = errors.New("incomplete specification export")
	// ErrNotCovered reports a [Key] that no cell of the table answers.
	ErrNotCovered = errors.New("no cell for the key")
)

// Table is a loaded and validated export. It is safe for concurrent use.
type Table struct {
	version  int
	specTag  string
	profiles map[Profile]*profileTable
}

type profileTable struct {
	knobs   map[string]json.RawMessage
	domains map[Kind]Domain
	cells   map[combo][]cellJSON
	nodes   *Nodes
}

// combo is one combination of operator and operand kinds; right is empty for a
// unary operator.
type combo struct {
	op          Operator
	left, right Kind
}

func (c combo) String() string {
	if c.right == "" {
		return fmt.Sprintf("%s(%s)", c.op, c.left)
	}
	return fmt.Sprintf("%s(%s, %s)", c.op, c.left, c.right)
}

type exportJSON struct {
	SchemaVersion int                      `json:"schema_version"`
	SpecTag       string                   `json:"spec_tag"`
	Profiles      map[Profile]*profileJSON `json:"profiles"`
}

type profileJSON struct {
	Knobs map[string]json.RawMessage `json:"knobs"`
	Kinds map[Kind]Domain            `json:"kinds"`
	Nodes *Nodes                     `json:"nodes,omitempty"`
	Cells []cellJSON                 `json:"cells"`
}

type sideJSON struct {
	Kind  Kind  `json:"kind"`
	State State `json:"state,omitempty"`
	Class Class `json:"class,omitempty"`
}

type cellJSON struct {
	Op          Operator    `json:"op"`
	Left        *sideJSON   `json:"left"`
	Right       *sideJSON   `json:"right,omitempty"`
	Place       Place       `json:"place,omitempty"`
	Effect      Effect      `json:"effect,omitempty"`
	Disjunction *bool       `json:"disjunction,omitempty"`
	InIterate   *bool       `json:"in_iterate,omitempty"`
	Outcome     Outcome     `json:"outcome"`
	Outcomes    []Outcome   `json:"outcomes,omitempty"`
	ValueRule   []ValueRule `json:"value_rule,omitempty"`
}

// Load reads an export and validates it. The error wraps [ErrInvalid] when the
// document violates the format and [ErrIncomplete] when it leaves a required
// question unanswered; its text names up to 20 of the problems found.
func Load(r io.Reader) (*Table, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var doc exportJSON
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: data after the export document", ErrInvalid)
	}
	if doc.SchemaVersion != SchemaVersion && doc.SchemaVersion != schemaVersion1 {
		return nil, fmt.Errorf("%w: schema_version is %d, want %d (or %d, the format before value rules)", ErrInvalid,
			doc.SchemaVersion, SchemaVersion, schemaVersion1)
	}
	if doc.SpecTag == "" {
		return nil, fmt.Errorf("%w: spec_tag is empty", ErrInvalid)
	}

	var invalid, incomplete problems
	t := &Table{version: doc.SchemaVersion, specTag: doc.SpecTag, profiles: map[Profile]*profileTable{}}
	for p := range doc.Profiles {
		if !known(Profiles, p) {
			invalid.add("unknown profile %q", p)
		}
	}
	for _, p := range Profiles {
		pj := doc.Profiles[p]
		if pj == nil {
			incomplete.add("profile %s is missing", p)
			continue
		}
		pt := buildProfile(p, doc.SchemaVersion, pj, &invalid, &incomplete)
		t.profiles[p] = pt
	}
	if err := invalid.err(ErrInvalid); err != nil {
		return nil, err
	}
	for _, p := range Profiles {
		if pt := t.profiles[p]; pt != nil {
			checkCoverage(p, pt, &invalid, &incomplete)
		}
	}
	if err := invalid.err(ErrInvalid); err != nil {
		return nil, err
	}
	if err := incomplete.err(ErrIncomplete); err != nil {
		return nil, err
	}
	return t, nil
}

// SpecTag returns the tag of the specification commit the export was computed
// from.
func (t *Table) SpecTag() string { return t.specTag }

// SchemaVersion returns the format version of the export: [SchemaVersion], or
// 1 for the format before value rules and nodes.
func (t *Table) SchemaVersion() int { return t.version }

// Nodes returns how the profile combines the outcomes of nodes, and false for
// an unknown profile or an export of schema version 1, which carries none.
func (t *Table) Nodes(p Profile) (Nodes, bool) {
	pt := t.profiles[p]
	if pt == nil || pt.nodes == nil {
		return Nodes{}, false
	}
	return *pt.nodes, true
}

// Knob returns the raw JSON value of a specification setting in the profile,
// and false when the export does not carry it.
func (t *Table) Knob(p Profile, name string) (json.RawMessage, bool) {
	pt := t.profiles[p]
	if pt == nil {
		return nil, false
	}
	v, ok := pt.knobs[name]
	return v, ok
}

// Domain returns the states and classes an operand of the kind can have in the
// profile, and false for an unknown profile or kind.
func (t *Table) Domain(p Profile, k Kind) (Domain, bool) {
	pt := t.profiles[p]
	if pt == nil {
		return Domain{}, false
	}
	d, ok := pt.domains[k]
	return d, ok
}

// Lookup returns the cell of the profile that answers the key. The error wraps
// [ErrNotCovered] when no cell does: the profile, an enumerated value, or a
// point is outside the table, or Right is set for a unary operator or unset for
// a binary one.
func (t *Table) Lookup(p Profile, k Key) (Cell, error) {
	pt := t.profiles[p]
	if pt == nil {
		return Cell{}, fmt.Errorf("%w: unknown profile %q", ErrNotCovered, p)
	}
	c := combo{op: k.Op, left: k.Left.Kind, right: k.Right.Kind}
	if k.Op.Unary() && k.Right != (Point{}) {
		return Cell{}, fmt.Errorf("%w: %s takes no right operand", ErrNotCovered, k.Op)
	}
	if !known(Places, k.Context.Place) || !known(Effects, k.Context.Effect) ||
		!pt.inDomain(k.Left) || !k.Op.Unary() && !pt.inDomain(k.Right) {
		return Cell{}, fmt.Errorf("%w: %s, %s is outside the domains", ErrNotCovered, c,
			describePoint(k.Left, k.Right, k.Context, c.right != ""))
	}
	for i := range pt.cells[c] {
		cj := &pt.cells[c][i]
		if cj.matchesContext(k.Context) && cj.Left.matches(k.Left) && (cj.Right == nil || cj.Right.matches(k.Right)) {
			return Cell{Outcome: cj.Outcome, Outcomes: slices.Clone(cj.Outcomes), ValueRule: slices.Clone(cj.ValueRule)}, nil
		}
	}
	return Cell{}, fmt.Errorf("%w: %s, %s", ErrNotCovered, c, describePoint(k.Left, k.Right, k.Context, c.right != ""))
}

// inDomain reports whether the point is one of the (state, class) pairs its
// kind's domain lists.
func (pt *profileTable) inDomain(p Point) bool {
	d, ok := pt.domains[p.Kind]
	if !ok || !slices.Contains(d.States, p.State) {
		return false
	}
	if p.State == StateValue {
		return slices.Contains(d.Classes, p.Class)
	}
	return p.Class == ""
}

func buildProfile(p Profile, version int, pj *profileJSON, invalid, incomplete *problems) *profileTable {
	pt := &profileTable{knobs: pj.Knobs, domains: map[Kind]Domain{}, cells: map[combo][]cellJSON{}, nodes: pj.Nodes}
	classes := Classes
	if version == schemaVersion1 {
		classes = classesV1
		if pj.Nodes != nil {
			invalid.add("%s: nodes is set in schema version 1", p)
		}
	} else if pj.Nodes == nil {
		incomplete.add("%s: nodes is missing", p)
	} else {
		checkNodes(p, pj.Nodes, invalid, incomplete)
	}
	for _, name := range RequiredKnobs {
		if _, ok := pj.Knobs[name]; !ok {
			incomplete.add("%s: knob %s is missing", p, name)
		}
	}
	for name := range pj.Knobs {
		if !slices.Contains(RequiredKnobs, name) {
			invalid.add("%s: unknown knob %q", p, name)
		}
	}
	for k, d := range pj.Kinds {
		if !known(Kinds, k) {
			invalid.add("%s: unknown operand kind %q", p, k)
			continue
		}
		checkDomain(p, k, d, classes, invalid)
		pt.domains[k] = d
	}
	for _, k := range Kinds {
		if _, ok := pj.Kinds[k]; !ok {
			incomplete.add("%s: operand kind %s has no domain", p, k)
		}
	}
	for i := range pj.Cells {
		cj := pj.Cells[i]
		if checkCell(p, version, i, &cj, pt.domains, invalid) {
			c := combo{op: cj.Op, left: cj.Left.Kind}
			if cj.Right != nil {
				c.right = cj.Right.Kind
			}
			pt.cells[c] = append(pt.cells[c], cj)
		}
	}
	return pt
}

func checkDomain(p Profile, k Kind, d Domain, classes []Class, invalid *problems) {
	if len(d.States) == 0 {
		invalid.add("%s: operand kind %s has no states", p, k)
	}
	for i, s := range d.States {
		if !known(States, s) || slices.Contains(d.States[:i], s) {
			invalid.add("%s: operand kind %s: state %q is unknown or repeated", p, k, s)
		}
	}
	for i, c := range d.Classes {
		if !known(classes, c) || slices.Contains(d.Classes[:i], c) {
			invalid.add("%s: operand kind %s: class %q is unknown or repeated", p, k, c)
		}
	}
	if slices.Contains(d.States, StateValue) != (len(d.Classes) > 0) {
		invalid.add("%s: operand kind %s lists classes without state VALUE, or state VALUE without classes", p, k)
	}
}

// checkCell reports whether the cell is well-formed, and records each problem.
func checkCell(p Profile, version, i int, cj *cellJSON, domains map[Kind]Domain, invalid *problems) bool {
	before := len(invalid.list) + invalid.extra
	where := fmt.Sprintf("%s: cell %d", p, i)
	if !known(Operators, cj.Op) {
		invalid.add("%s: unknown operator %q", where, cj.Op)
		return false
	}
	if cj.Left == nil {
		invalid.add("%s: %s has no left side", where, cj.Op)
		return false
	}
	if !admitsLeft(cj.Left.Kind) || !known(Kinds, cj.Left.Kind) {
		invalid.add("%s: %s does not take kind %q on the left", where, cj.Op, cj.Left.Kind)
	} else {
		checkSide(where, "left", cj.Left, domains, invalid)
	}
	switch {
	case cj.Op.Unary() && cj.Right != nil:
		invalid.add("%s: %s takes no right side", where, cj.Op)
	case !cj.Op.Unary() && cj.Right == nil:
		invalid.add("%s: %s has no right side", where, cj.Op)
	case cj.Right != nil && (!admitsRight(cj.Op, cj.Right.Kind) || !known(Kinds, cj.Right.Kind)):
		invalid.add("%s: %s does not take kind %q on the right", where, cj.Op, cj.Right.Kind)
	case cj.Right != nil:
		checkSide(where, "right", cj.Right, domains, invalid)
	}
	if cj.Place != "" && !known(Places, cj.Place) {
		invalid.add("%s: unknown place %q", where, cj.Place)
	}
	if cj.Effect != "" && !known(Effects, cj.Effect) {
		invalid.add("%s: unknown effect %q", where, cj.Effect)
	}
	allowed, _ := Outcomes(p)
	switch {
	case !known(allowed, cj.Outcome):
		invalid.add("%s: outcome %q is not an outcome of profile %s", where, cj.Outcome, p)
	case cj.Outcome == OutcomeByValue:
		checkValueOutcomes(where, p, cj.Outcomes, invalid)
	case len(cj.Outcomes) > 0:
		invalid.add("%s: outcomes is set for outcome %s; only by_value lists outcomes", where, cj.Outcome)
	}
	switch {
	case version == schemaVersion1 && cj.ValueRule != nil:
		invalid.add("%s: value_rule is set in schema version 1", where)
	case version == schemaVersion1:
	case cj.Outcome == OutcomeByValue:
		checkValueRule(where, cj.ValueRule, invalid)
	case cj.ValueRule != nil:
		invalid.add("%s: value_rule is set for outcome %s; only by_value names a value rule", where, cj.Outcome)
	}
	return len(invalid.list)+invalid.extra == before
}

func checkSide(where, side string, s *sideJSON, domains map[Kind]Domain, invalid *problems) {
	d, ok := domains[s.Kind]
	if !ok {
		return // reported as a missing domain
	}
	if s.State != "" && !slices.Contains(d.States, s.State) {
		invalid.add("%s: %s state %q is not in the domain of %s", where, side, s.State, s.Kind)
	}
	if s.Class != "" {
		if s.State != StateValue {
			invalid.add("%s: %s class %q is set without state VALUE", where, side, s.Class)
		} else if !slices.Contains(d.Classes, s.Class) {
			invalid.add("%s: %s class %q is not in the domain of %s", where, side, s.Class, s.Kind)
		}
	}
}

func checkValueOutcomes(where string, p Profile, outs []Outcome, invalid *problems) {
	allowed := valueOutcomes(p)
	for i, o := range outs {
		if !known(allowed, o) || slices.Contains(outs[:i], o) {
			invalid.add("%s: by_value outcome %q is not an outcome of profile %s, or is repeated", where, o, p)
		}
	}
	if len(outs) < 2 {
		invalid.add("%s: by_value lists %d outcomes, want at least 2", where, len(outs))
	}
}

// checkValueRule records a by_value cell whose value_rule is missing, holds a
// rule the generator does not know, or is not sorted without repeats.
func checkValueRule(where string, rules []ValueRule, invalid *problems) {
	if len(rules) == 0 {
		invalid.add("%s: by_value has no value_rule", where)
		return
	}
	for _, r := range rules {
		if !known(ValueRules, r) {
			invalid.add("%s: unknown value rule %q", where, r)
		}
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1] >= rules[i] {
			invalid.add("%s: value_rule %q is not sorted, or repeats a rule", where, rules)
			break
		}
	}
}

// checkNodes records an unknown or missing algorithm, rule effect, or node
// outcome of the profile's nodes.
func checkNodes(p Profile, n *Nodes, invalid, incomplete *problems) {
	where := fmt.Sprintf("%s: nodes", p)
	outcome := func(what string, o NodeOutcome) {
		switch {
		case o == "":
			incomplete.add("%s: %s is missing", where, what)
		case !known(NodeOutcomes, o):
			invalid.add("%s: %s has unknown node outcome %q", where, what, o)
		}
	}
	missing := func(what, v string) bool {
		if v == "" {
			incomplete.add("%s: %s is missing", where, what)
		}
		return v == ""
	}
	for name, c := range n.Algorithms {
		if !known(Algorithms, name) {
			invalid.add("%s: unknown algorithm %q", where, name)
			continue
		}
		outcome(name+".permit", c.Permit)
		outcome(name+".deny", c.Deny)
		outcome(name+".both", c.Both)
		outcome(name+".none", c.None)
	}
	for _, name := range Algorithms {
		if _, ok := n.Algorithms[name]; !ok {
			incomplete.add("%s: algorithm %s is missing", where, name)
		}
	}
	if !missing("absent_algorithm", n.AbsentAlgorithm) && !known(Algorithms, n.AbsentAlgorithm) {
		invalid.add("%s: absent_algorithm %q is not an algorithm", where, n.AbsentAlgorithm)
	}
	for name, o := range n.Effects {
		if !known(RuleEffects, name) {
			invalid.add("%s: unknown rule effect %q", where, name)
			continue
		}
		outcome("effects."+name, o)
	}
	for _, name := range RuleEffects {
		if _, ok := n.Effects[name]; !ok {
			incomplete.add("%s: rule effect %s is missing", where, name)
		}
	}
	if !missing("absent_effect", n.AbsentEffect) && !known(AbsentEffects, n.AbsentEffect) {
		invalid.add("%s: absent_effect %q is not one of %q", where, n.AbsentEffect, AbsentEffects)
	}
	if !missing("absent_expression", string(n.AbsentExpression)) &&
		n.AbsentExpression != OutcomeT && n.AbsentExpression != OutcomeF {
		invalid.add("%s: absent_expression %q is not T or F", where, n.AbsentExpression)
	}
}

// checkCoverage records, for every combination the profile must answer, each
// point of its grid that no cell covers or that two cells cover.
func checkCoverage(p Profile, pt *profileTable, invalid, incomplete *problems) {
	contexts := allContexts()
	var counts []uint8
	for _, op := range Operators {
		for _, lk := range Kinds {
			if !admitsLeft(lk) {
				continue
			}
			rights := []Kind{""}
			if !op.Unary() {
				rights = rights[:0]
				for _, rk := range Kinds {
					if admitsRight(op, rk) {
						rights = append(rights, rk)
					}
				}
			}
			for _, rk := range rights {
				c := combo{op: op, left: lk, right: rk}
				cells := pt.cells[c]
				if len(cells) == 0 {
					incomplete.add("%s: %s has no cells", p, c)
					continue
				}
				lps := points(lk, pt.domains[lk])
				rps := []Point{{}}
				if rk != "" {
					rps = points(rk, pt.domains[rk])
				}
				n := len(contexts) * len(lps) * len(rps)
				counts = slices.Grow(counts[:0], n)[:n]
				clear(counts)
				for i := range cells {
					cells[i].mark(counts, contexts, lps, rps)
				}
				reportGrid(p, c, counts, contexts, lps, rps, invalid, incomplete)
			}
		}
	}
}

func (cj *cellJSON) mark(counts []uint8, contexts []Context, lps, rps []Point) {
	for ci, ctx := range contexts {
		if !cj.matchesContext(ctx) {
			continue
		}
		for li, lp := range lps {
			if !cj.Left.matches(lp) {
				continue
			}
			for ri, rp := range rps {
				if cj.Right != nil && !cj.Right.matches(rp) {
					continue
				}
				i := (ci*len(lps)+li)*len(rps) + ri
				if counts[i] < 2 {
					counts[i]++
				}
			}
		}
	}
}

// reportGrid records the first hole and the first overlap of one combination's
// grid, with the number of points of each.
func reportGrid(p Profile, c combo, counts []uint8, contexts []Context, lps, rps []Point, invalid, incomplete *problems) {
	var holes, overlaps int
	var firstHole, firstOverlap int
	for i, n := range counts {
		switch n {
		case 0:
			if holes == 0 {
				firstHole = i
			}
			holes++
		case 2:
			if overlaps == 0 {
				firstOverlap = i
			}
			overlaps++
		}
	}
	at := func(i int) string {
		ri := i % len(rps)
		li := i / len(rps) % len(lps)
		ci := i / len(rps) / len(lps)
		return describePoint(lps[li], rps[ri], contexts[ci], c.right != "")
	}
	if holes > 0 {
		incomplete.add("%s: %s: no cell covers %d points, the first at %s", p, c, holes, at(firstHole))
	}
	if overlaps > 0 {
		invalid.add("%s: %s: several cells cover %d points, the first at %s", p, c, overlaps, at(firstOverlap))
	}
}

func describePoint(l, r Point, ctx Context, binary bool) string {
	var b strings.Builder
	b.WriteString("left " + describeSide(l))
	if binary {
		b.WriteString(", right " + describeSide(r))
	}
	fmt.Fprintf(&b, ", place %s, effect %s, disjunction %t, in_iterate %t",
		ctx.Place, ctx.Effect, ctx.Disjunction, ctx.InIterate)
	return b.String()
}

func describeSide(pt Point) string {
	if pt.Class != "" {
		return string(pt.State) + "/" + string(pt.Class)
	}
	return string(pt.State)
}

// points lists the (state, class) pairs of a domain, VALUE once per class.
func points(k Kind, d Domain) []Point {
	var ps []Point
	for _, s := range d.States {
		if s != StateValue {
			ps = append(ps, Point{Kind: k, State: s})
			continue
		}
		for _, c := range d.Classes {
			ps = append(ps, Point{Kind: k, State: s, Class: c})
		}
	}
	return ps
}

func allContexts() []Context {
	var cs []Context
	for _, pl := range Places {
		for _, ef := range Effects {
			for _, dis := range []bool{false, true} {
				for _, it := range []bool{false, true} {
					cs = append(cs, Context{Place: pl, Effect: ef, Disjunction: dis, InIterate: it})
				}
			}
		}
	}
	return cs
}

func (s *sideJSON) matches(pt Point) bool {
	return s.Kind == pt.Kind &&
		(s.State == "" || s.State == pt.State) &&
		(s.Class == "" || s.Class == pt.Class)
}

func (cj *cellJSON) matchesContext(ctx Context) bool {
	return (cj.Place == "" || cj.Place == ctx.Place) &&
		(cj.Effect == "" || cj.Effect == ctx.Effect) &&
		(cj.Disjunction == nil || *cj.Disjunction == ctx.Disjunction) &&
		(cj.InIterate == nil || *cj.InIterate == ctx.InIterate)
}

// problems collects the messages of one error, keeping the first maxProblems.
type problems struct {
	list  []string
	extra int
}

func (ps *problems) add(format string, args ...any) {
	if len(ps.list) < maxProblems {
		ps.list = append(ps.list, fmt.Sprintf(format, args...))
		return
	}
	ps.extra++
}

func (ps *problems) err(sentinel error) error {
	if len(ps.list) == 0 {
		return nil
	}
	msg := strings.Join(ps.list, "; ")
	if ps.extra > 0 {
		msg += fmt.Sprintf("; and %d more", ps.extra)
	}
	return fmt.Errorf("%w: %s", sentinel, msg)
}
