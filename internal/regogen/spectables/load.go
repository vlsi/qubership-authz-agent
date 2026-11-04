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
	"maps"
	"slices"
	"strings"
)

// SchemaVersion is the version of the table format [Load] reads.
const SchemaVersion = 4

// maxProblems bounds how many problems an error from [Load] spells out.
const maxProblems = 20

var (
	// ErrInvalid reports a table that violates its format: malformed JSON, a
	// field or knob the format does not define, a value outside its
	// enumeration, or two lines that answer the same question.
	ErrInvalid = errors.New("invalid specification export")
	// ErrIncomplete reports a well-formed table that leaves a required
	// question unanswered: a missing knob or kind domain, or a combination of
	// operator and operand kinds with a context no line covers.
	ErrIncomplete = errors.New("incomplete specification export")
	// ErrNotCovered reports a [Key] that no cell of the table answers.
	ErrNotCovered = errors.New("no cell for the key")
)

// Table is a loaded and validated table of the agent profile. It is safe for
// concurrent use.
type Table struct {
	specTag string
	knobs   map[string]json.RawMessage
	domains map[Kind]Domain
	points  map[Kind][]Point
	nodes   Nodes
	// results holds every distinct cell the lines refer to, in the agent
	// profile's outcomes once Load has applied the leaf map.
	results []Cell
	lines   map[combo][]line
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

// line is one parsed entry of cells: the contexts it covers and, for each pair
// of a left point and a right point of its combination, an index into
// Table.results. The grid is left-major: the pair (li, ri) is at li*m+ri, where
// m is the number of right points, 1 for a unary operator.
type line struct {
	ctx  contextFilter
	grid []int
}

// contextFilter holds the qualifiers of a line; an unset one matches every
// value of its dimension.
type contextFilter struct {
	place       Place
	effect      Effect
	disjunction *bool
	inIterate   *bool
}

type tableJSON struct {
	SchemaVersion int                        `json:"schema_version"`
	SpecTag       string                     `json:"spec_tag"`
	Negates       map[Operator]Operator      `json:"negates"`
	Knobs         map[string]json.RawMessage `json:"knobs"`
	Kinds         map[Kind]Domain            `json:"kinds"`
	Nodes         *Nodes                     `json:"nodes"`
	Leaf          map[Outcome]Outcome        `json:"leaf"`
	Aliases       map[Kind]Kind              `json:"aliases"`
	Codes         map[string]Cell            `json:"codes"`
	Cells         []string                   `json:"cells"`
}

// Load reads a table and validates it. The error wraps [ErrInvalid] when the
// document violates the format and [ErrIncomplete] when it leaves a required
// question unanswered; its text names up to 20 of the problems found.
func Load(r io.Reader) (*Table, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var doc tableJSON
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: data after the table document", ErrInvalid)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version is %d, want %d", ErrInvalid, doc.SchemaVersion, SchemaVersion)
	}
	if doc.SpecTag == "" {
		return nil, fmt.Errorf("%w: spec_tag is empty", ErrInvalid)
	}

	var invalid, incomplete problems
	if !maps.Equal(doc.Negates, Negations) {
		invalid.add("negates is %v, want %v", doc.Negates, Negations)
	}
	t := &Table{specTag: doc.SpecTag, knobs: doc.Knobs, domains: map[Kind]Domain{}, points: map[Kind][]Point{},
		lines: map[combo][]line{}}
	if doc.Nodes == nil {
		incomplete.add("nodes is missing")
	} else {
		checkNodes(doc.Nodes, &invalid, &incomplete)
		t.nodes = *doc.Nodes
	}
	for _, name := range RequiredKnobs {
		if _, ok := doc.Knobs[name]; !ok {
			incomplete.add("knob %s is missing", name)
		}
	}
	for name := range doc.Knobs {
		if !slices.Contains(RequiredKnobs, name) {
			invalid.add("unknown knob %q", name)
		}
	}
	for k, d := range doc.Kinds {
		if !known(Kinds, k) {
			invalid.add("unknown operand kind %q", k)
			continue
		}
		checkDomain(k, d, &invalid)
		t.domains[k] = d
		t.points[k] = points(k, d)
	}
	for _, k := range Kinds {
		if _, ok := doc.Kinds[k]; !ok {
			incomplete.add("operand kind %s has no domain", k)
		}
	}
	checkLeaf(doc.Leaf, &invalid)
	checkAliases(doc.Aliases, t.domains, &invalid)
	codes := t.readCodes(doc.Codes, &invalid)
	for i, s := range doc.Cells {
		t.readLine(i, s, codes, &invalid)
	}
	if err := invalid.err(ErrInvalid); err != nil {
		return nil, err
	}
	t.derive(doc.Aliases)
	t.applyLeaf(doc.Leaf)
	t.checkCoverage(&invalid, &incomplete)
	if err := invalid.err(ErrInvalid); err != nil {
		return nil, err
	}
	if err := incomplete.err(ErrIncomplete); err != nil {
		return nil, err
	}
	return t, nil
}

// SpecTag returns the tag of the specification commit the table was computed
// from.
func (t *Table) SpecTag() string { return t.specTag }

// Nodes returns how the agent profile combines the outcomes of nodes.
func (t *Table) Nodes() Nodes { return t.nodes }

// Knob returns the raw JSON value of a specification setting, and false when
// the table does not carry it.
func (t *Table) Knob(name string) (json.RawMessage, bool) {
	v, ok := t.knobs[name]
	return v, ok
}

// Domain returns the states and classes an operand of the kind can have, and
// false for an unknown kind.
func (t *Table) Domain(k Kind) (Domain, bool) {
	d, ok := t.domains[k]
	return d, ok
}

// Lookup returns the cell that answers the key. The error wraps
// [ErrNotCovered] when no cell does: an enumerated value or a point is outside
// the table, or Right is set for a unary operator or unset for a binary one.
func (t *Table) Lookup(k Key) (Cell, error) {
	c := combo{op: k.Op, left: k.Left.Kind, right: k.Right.Kind}
	if k.Op.Unary() && k.Right != (Point{}) {
		return Cell{}, fmt.Errorf("%w: %s takes no right operand", ErrNotCovered, k.Op)
	}
	li := slices.Index(t.points[k.Left.Kind], k.Left)
	ri, m := 0, 1
	if !k.Op.Unary() {
		ri, m = slices.Index(t.points[k.Right.Kind], k.Right), len(t.points[k.Right.Kind])
	}
	if !known(Places, k.Context.Place) || !known(Effects, k.Context.Effect) || li < 0 || ri < 0 {
		return Cell{}, fmt.Errorf("%w: %s, %s is outside the domains", ErrNotCovered, c,
			describePoint(k.Left, k.Right, k.Context, c.right != ""))
	}
	for _, l := range t.lines[c] {
		if l.ctx.matches(k.Context) {
			r := t.results[l.grid[li*m+ri]]
			return Cell{Outcome: r.Outcome, Outcomes: slices.Clone(r.Outcomes), ValueRule: slices.Clone(r.ValueRule)}, nil
		}
	}
	return Cell{}, fmt.Errorf("%w: %s, %s", ErrNotCovered, c, describePoint(k.Left, k.Right, k.Context, c.right != ""))
}

// readCodes appends each valid entry of codes to t.results, in the order of
// the codes, and returns the index of each code's result.
func (t *Table) readCodes(codes map[string]Cell, invalid *problems) map[byte]int {
	index := map[byte]int{}
	for _, code := range slices.Sorted(maps.Keys(codes)) {
		where := fmt.Sprintf("code %q", code)
		if len(code) != 1 || !isCode(code[0]) {
			invalid.add("%s is not one ASCII letter or digit", where)
			continue
		}
		r := codes[code]
		if checkResult(where, r, invalid) {
			index[code[0]] = len(t.results)
			t.results = append(t.results, r)
		}
	}
	return index
}

func isCode(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// readLine parses entry i of cells into a line of its combination, and records
// each problem.
func (t *Table) readLine(i int, s string, codes map[byte]int, invalid *problems) {
	where := fmt.Sprintf("cells[%d]", i)
	f := strings.Fields(s)
	if len(f) < 3 {
		invalid.add("%s: %q has no operator, kind, or grid", where, s)
		return
	}
	c := combo{op: Operator(f[0]), left: Kind(f[1])}
	rest := f[2:]
	switch {
	case !known(Operators, c.op):
		invalid.add("%s: unknown operator %q", where, c.op)
		return
	case !admitsLeft(c.left) || !known(Kinds, c.left):
		invalid.add("%s: %s does not take kind %q on the left", where, c.op, c.left)
		return
	case c.op.Unary() && known(Kinds, Kind(rest[0])):
		invalid.add("%s: %s takes no right side", where, c.op)
		return
	case !c.op.Unary():
		c.right, rest = Kind(rest[0]), rest[1:]
		if !admitsRight(c.op, c.right) || !known(Kinds, c.right) {
			invalid.add("%s: %s does not take kind %q on the right", where, c.op, c.right)
			return
		}
	}
	where += " " + c.String()
	var l line
	for len(rest) > 0 && strings.Contains(rest[0], "=") {
		if !l.ctx.set(rest[0]) {
			invalid.add("%s: qualifier %q is unknown or repeated", where, rest[0])
			return
		}
		rest = rest[1:]
	}
	lps, ok := t.points[c.left]
	m := 1
	if c.right != "" {
		var rps []Point
		rps, ok = t.points[c.right]
		m = len(rps)
	}
	if !ok {
		return // reported as a missing domain
	}
	grid, problem := readGrid(rest, len(lps), m, codes)
	if problem != "" {
		invalid.add("%s: %s", where, problem)
		return
	}
	l.grid = grid
	t.lines[c] = append(t.lines[c], l)
}

// readGrid expands the rows of a line into its grid of n left points and m
// right points. It accepts one row for every left point, or one row for all of
// them; and in a row, one code for every right point, or one code for all of
// them. It returns a description of the first problem, or "".
func readGrid(rows []string, n, m int, codes map[byte]int) ([]int, string) {
	if len(rows) != 1 && len(rows) != n {
		return nil, fmt.Sprintf("has %d rows, want %d or 1", len(rows), n)
	}
	grid := make([]int, 0, n*m)
	for li := range n {
		row := rows[0]
		if len(rows) == n {
			row = rows[li]
		}
		if len(row) != 1 && len(row) != m {
			return nil, fmt.Sprintf("row %q has %d codes, want %d or 1", row, len(row), m)
		}
		for ri := range m {
			code := row[0]
			if len(row) == m {
				code = row[ri]
			}
			r, ok := codes[code]
			if !ok {
				return nil, fmt.Sprintf("row %q names code %q, which codes does not define", row, string(code))
			}
			grid = append(grid, r)
		}
	}
	return grid, ""
}

// set records a qualifier of the form name=value, and reports false for an
// unknown name or value or a name set before.
func (f *contextFilter) set(q string) bool {
	name, value, _ := strings.Cut(q, "=")
	flag := func(p **bool) bool {
		if *p != nil || value != "true" && value != "false" {
			return false
		}
		b := value == "true"
		*p = &b
		return true
	}
	switch name {
	case "place":
		if f.place != "" || !known(Places, Place(value)) {
			return false
		}
		f.place = Place(value)
	case "effect":
		if f.effect != "" || !known(Effects, Effect(value)) {
			return false
		}
		f.effect = Effect(value)
	case "disjunction":
		return flag(&f.disjunction)
	case "in_iterate":
		return flag(&f.inIterate)
	default:
		return false
	}
	return true
}

func (f contextFilter) matches(ctx Context) bool {
	return (f.place == "" || f.place == ctx.Place) &&
		(f.effect == "" || f.effect == ctx.Effect) &&
		(f.disjunction == nil || *f.disjunction == ctx.Disjunction) &&
		(f.inIterate == nil || *f.inIterate == ctx.InIterate)
}

// checkLeaf records a leaf map that does not take every outcome of legacy the
// agent profile lacks to an outcome the profile has, or maps anything else.
func checkLeaf(leaf map[Outcome]Outcome, invalid *problems) {
	legacy, _ := Outcomes(ProfileLegacy)
	own, _ := Outcomes(ProfileAgent)
	for from, to := range leaf {
		if !known(legacy, from) || known(own, from) || !known(valueOutcomes(ProfileAgent), to) {
			invalid.add("leaf maps %q to %q; it maps each outcome of legacy the agent profile lacks to T, F, or U",
				from, to)
		}
	}
	for _, o := range legacy {
		if _, ok := leaf[o]; !ok && !known(own, o) {
			invalid.add("leaf does not map %s, which the agent profile lacks", o)
		}
	}
}

// checkAliases records an alias whose kind or representative is unknown or
// takes no side, that names itself or another alias, or whose domain is not
// its representative's.
func checkAliases(aliases map[Kind]Kind, domains map[Kind]Domain, invalid *problems) {
	for a, r := range aliases {
		switch {
		case !known(Kinds, a) || !known(Kinds, r) || !admitsLeft(a) || !admitsLeft(r):
			invalid.add("alias %q of %q names an unknown kind or the pattern", a, r)
		case aliases[r] != "": // an alias of itself names an alias too
			invalid.add("alias %s names %s, which is itself or another alias", a, r)
		case !slices.Equal(domains[a].States, domains[r].States) || !slices.Equal(domains[a].Classes, domains[r].Classes):
			invalid.add("alias %s has another domain than its representative %s", a, r)
		}
	}
}

// derive gives each combination without lines of its own the lines of its
// source: the combination over the representatives of its kinds when that one
// has lines of its own; else, for a negated operator, its positive operator's
// lines, mirrored; else the combination over the representatives. A
// combination whose source has no lines stays without them, and checkCoverage
// reports it. An alias has its representative's domain, so a grid of the
// source indexes the points of the derived combination unchanged.
func (t *Table) derive(aliases map[Kind]Kind) {
	own := map[combo]bool{}
	for c := range t.lines {
		own[c] = true
	}
	rep := func(k Kind) Kind {
		if r, ok := aliases[k]; ok {
			return r
		}
		return k
	}
	mirrored := map[int]int{}
	mirror := func(lines []line) []line {
		out := make([]line, len(lines))
		for i, l := range lines {
			grid := make([]int, len(l.grid))
			for j, r := range l.grid {
				grid[j] = t.mirrorResult(r, mirrored)
			}
			out[i] = line{ctx: l.ctx, grid: grid}
		}
		return out
	}
	var linesOf func(c combo) []line
	linesOf = func(c combo) []line {
		if lines, ok := t.lines[c]; ok {
			return lines
		}
		r := combo{op: c.op, left: rep(c.left), right: rep(c.right)}
		var out []line
		switch pos, negated := Negations[c.op]; {
		case r != c && own[r]:
			out = t.lines[r]
		case negated:
			out = mirror(linesOf(combo{op: pos, left: c.left, right: c.right}))
		case r != c:
			out = linesOf(r)
		}
		if len(out) > 0 {
			t.lines[c] = out
		}
		return out
	}
	for _, c := range combos() {
		linesOf(c)
	}
}

// mirrorResult returns the index of the mirror of result i, appending it to
// t.results when no result equals it: T and F swap, and a by_value cell lists
// the mirrored outcomes in the order of valueOutcomes.
func (t *Table) mirrorResult(i int, memo map[int]int) int {
	if m, ok := memo[i]; ok {
		return m
	}
	r := t.results[i]
	m := Cell{Outcome: mirrorOutcome(r.Outcome), ValueRule: r.ValueRule}
	if r.Outcomes != nil {
		m.Outcomes = []Outcome{}
		for _, o := range valueOutcomes(ProfileLegacy) {
			if slices.ContainsFunc(r.Outcomes, func(x Outcome) bool { return mirrorOutcome(x) == o }) {
				m.Outcomes = append(m.Outcomes, o)
			}
		}
	}
	j := slices.IndexFunc(t.results, func(x Cell) bool { return sameCell(x, m) })
	if j < 0 {
		j = len(t.results)
		t.results = append(t.results, m)
	}
	memo[i] = j
	return j
}

func sameCell(a, b Cell) bool {
	return a.Outcome == b.Outcome && slices.Equal(a.Outcomes, b.Outcomes) && slices.Equal(a.ValueRule, b.ValueRule)
}

func mirrorOutcome(o Outcome) Outcome {
	switch o {
	case OutcomeT:
		return OutcomeF
	case OutcomeF:
		return OutcomeT
	default:
		return o
	}
}

// applyLeaf maps the outcome of every result through the leaf map. A by_value
// result whose outcomes map to one becomes a result of that outcome.
func (t *Table) applyLeaf(leaf map[Outcome]Outcome) {
	if len(leaf) == 0 {
		return
	}
	mapped := func(o Outcome) Outcome {
		if to, ok := leaf[o]; ok {
			return to
		}
		return o
	}
	for i, r := range t.results {
		r.Outcome = mapped(r.Outcome)
		if r.Outcome == OutcomeByValue {
			var outs []Outcome
			for _, o := range r.Outcomes {
				if m := mapped(o); !slices.Contains(outs, m) {
					outs = append(outs, m)
				}
			}
			r.Outcomes = outs
			if len(outs) == 1 {
				r.Outcome, r.Outcomes, r.ValueRule = outs[0], nil, nil
			}
		}
		t.results[i] = r
	}
}

func checkDomain(k Kind, d Domain, invalid *problems) {
	if len(d.States) == 0 {
		invalid.add("operand kind %s has no states", k)
	}
	for i, s := range d.States {
		if !known(States, s) || slices.Contains(d.States[:i], s) {
			invalid.add("operand kind %s: state %q is unknown or repeated", k, s)
		}
	}
	for i, c := range d.Classes {
		if !known(Classes, c) || slices.Contains(d.Classes[:i], c) {
			invalid.add("operand kind %s: class %q is unknown or repeated", k, c)
		}
	}
	if slices.Contains(d.States, StateValue) != (len(d.Classes) > 0) {
		invalid.add("operand kind %s lists classes without state VALUE, or state VALUE without classes", k)
	}
}

// checkResult reports whether the cell is a valid result in legacy's
// outcomes, and records each problem. The leaf map rewrites the outcomes
// after loading.
func checkResult(where string, r Cell, invalid *problems) bool {
	before := len(invalid.list) + invalid.extra
	allowed, _ := Outcomes(ProfileLegacy)
	switch {
	case !known(allowed, r.Outcome):
		invalid.add("%s: outcome %q is not an outcome of profile %s", where, r.Outcome, ProfileLegacy)
	case r.Outcome == OutcomeByValue:
		checkValueOutcomes(where, ProfileLegacy, r.Outcomes, invalid)
	case len(r.Outcomes) > 0:
		invalid.add("%s: outcomes is set for outcome %s; only by_value lists outcomes", where, r.Outcome)
	}
	switch {
	case r.Outcome == OutcomeByValue:
		checkValueRule(where, r.ValueRule, invalid)
	case r.ValueRule != nil:
		invalid.add("%s: value_rule is set for outcome %s; only by_value names a value rule", where, r.Outcome)
	}
	return len(invalid.list)+invalid.extra == before
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
// outcome of the nodes.
func checkNodes(n *Nodes, invalid, incomplete *problems) {
	const where = "nodes"
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

// checkCoverage records, for every combination the table must answer, each
// context that no line of the combination covers or that two lines cover. A
// line covers every point of its combination, so the contexts are all that
// can leave a point uncovered or covered twice.
func (t *Table) checkCoverage(invalid, incomplete *problems) {
	for _, c := range combos() {
		lines := t.lines[c]
		if len(lines) == 0 {
			incomplete.add("%s has no cells", c)
			continue
		}
		var holes, overlaps int
		var firstHole, firstOverlap Context
		for _, ctx := range allContexts() {
			n := 0
			for _, l := range lines {
				if l.ctx.matches(ctx) {
					n++
				}
			}
			switch {
			case n == 0 && holes == 0:
				firstHole = ctx
				fallthrough
			case n == 0:
				holes++
			case n > 1 && overlaps == 0:
				firstOverlap = ctx
				fallthrough
			case n > 1:
				overlaps++
			}
		}
		if holes > 0 {
			incomplete.add("%s: no line covers %d contexts, the first at %s", c, holes, describeContext(firstHole))
		}
		if overlaps > 0 {
			invalid.add("%s: several lines cover %d contexts, the first at %s", c, overlaps,
				describeContext(firstOverlap))
		}
	}
}

// combos lists every combination of operator and operand kinds a table must
// answer.
func combos() []combo {
	var out []combo
	for _, op := range Operators {
		for _, lk := range Kinds {
			if !admitsLeft(lk) {
				continue
			}
			if op.Unary() {
				out = append(out, combo{op: op, left: lk})
				continue
			}
			for _, rk := range Kinds {
				if admitsRight(op, rk) {
					out = append(out, combo{op: op, left: lk, right: rk})
				}
			}
		}
	}
	return out
}

func describePoint(l, r Point, ctx Context, binary bool) string {
	var b strings.Builder
	b.WriteString("left " + describeSide(l))
	if binary {
		b.WriteString(", right " + describeSide(r))
	}
	b.WriteString(", " + describeContext(ctx))
	return b.String()
}

func describeContext(ctx Context) string {
	return fmt.Sprintf("place %s, effect %s, disjunction %t, in_iterate %t",
		ctx.Place, ctx.Effect, ctx.Disjunction, ctx.InIterate)
}

func describeSide(pt Point) string {
	if pt.Class != "" {
		return string(pt.State) + "/" + string(pt.Class)
	}
	return string(pt.State)
}

// points lists the (state, class) pairs of a domain in the order a line's grid
// indexes them: the states in the order the domain lists them, with VALUE
// once per class, in the order the domain lists the classes.
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
