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
	"maps"
	"slices"
	"strings"
	"sync"

	"authz-agent/internal/jsonvalue"
)

// test is one expression of a subject-only clause, in the form the group
// evaluator runs over the projected input. Each kind answers as the Rego
// expression it stands for: a positive test fails on a missing field and a
// negated one passes.
type test struct {
	kind string // a case of test.holds
	ref  string // sroles for the roles a simplified policy matches
	val  string
	set  []string // a literal's keys; for IS SUBSET, the tokens of a literal on the right; for clsin, the classes
	ref2 string
	// field and field2 name the list of the record of ref and of ref2 that
	// has, nothas, none, overlap, and disjoint read: ks when empty, or ea or
	// eb.
	field, field2 string
	// num is the literal number rel compares with.
	num *jsonvalue.Decimal
	// sets are the tokens of the elements of a literal on the left of IS
	// SUBSET.
	sets [][]string
	// ri and ri2 number ref and ref2 among the references of the module's
	// groups, -1 for none and for sroles, and slot numbers the list of ref
	// that field names (listSlot). groupIndex sets them for the tests of the
	// factors it holds.
	ri, ri2, slot int
}

// Group is a subject group: a conjunction of factors, each a disjunction of
// clauses of tests. The module reads it as "g_<hash>" in input.g, where
// <hash> is the first 12 hex digits of the SHA-256 of its factors.
type Group struct {
	Factors [][][]*test
	// factorIDs numbers each factor among the factors of the module's
	// groups, so that groups share a factor by its number.
	factorIDs []int
}

// subjectClauses returns the tests of every clause of d, and false when an
// expression has none.
func subjectClauses(d dnf) ([][]*test, bool) {
	out := make([][]*test, 0, len(d))
	for _, c := range d {
		ts := make([]*test, 0, len(c))
		for _, e := range c {
			if e.test == nil {
				return nil, false
			}
			ts = append(ts, e.test)
		}
		out = append(out, ts)
	}
	return out, true
}

// group returns a one-clause disjunction that reads the subject group of the
// conjunction of the factors. The factors stay apart: their product is what
// the group saves the module.
func (g *gen) group(factors ...dnf) dnf {
	type f struct {
		key string
		d   dnf
	}
	var fs []f
	for _, d := range factors {
		if d.isFalse() {
			return dnfFalse
		}
		if slices.ContainsFunc(d, func(c clause) bool { return len(c) == 0 }) {
			continue
		}
		k := d.key()
		if !slices.ContainsFunc(fs, func(x f) bool { return x.key == k }) {
			fs = append(fs, f{k, d})
		}
	}
	if len(fs) == 0 {
		return dnfTrue
	}
	slices.SortFunc(fs, func(a, b f) int { return strings.Compare(a.key, b.key) })
	keys := make([]string, len(fs))
	for i, x := range fs {
		keys[i] = x.key
	}
	key := strings.Join(keys, "\x02")
	id, ok := g.groupIDs[key]
	if !ok {
		id = g.hashed("g", key)
		g.groupIDs[key] = id
		var grp Group
		for _, x := range fs {
			cs, ok := subjectClauses(x.d)
			if !ok {
				panic("regogen: a group factor holds an expression without a test")
			}
			grp.Factors = append(grp.Factors, cs)
			fid, ok := g.factorIDs[x.key]
			if !ok {
				fid = len(g.factorIDs)
				g.factorIDs[x.key] = fid
			}
			grp.factorIDs = append(grp.factorIDs, fid)
		}
		g.groups[id] = grp
	}
	var as []string
	var all dnf
	for _, x := range fs {
		as = append(as, atoms(x.d)...)
		all = append(all, x.d...)
	}
	slices.Sort(as)
	return dnf{{{cls: clsIndexIn, text: lit(id) + " in input.g", cell: "group: " + strings.Join(slices.Compact(as), "; "),
		src: &exprSrc{nodes: dnfNodes(all)}}}}
}

func (l leafRails) grouped() bool {
	if !l.subjectOnly {
		return false
	}
	_, okT := subjectClauses(l.t)
	_, okF := subjectClauses(l.f)
	return okT && okF
}

// groupedT is the true rail of one disjunct with its subject-only leaves, and
// subj, in one group.
func (g *gen) groupedT(grp []leafRails, subj dnf) dnf {
	x := dnfTrue
	factors := []dnf{}
	if subj != nil {
		factors = append(factors, subj)
	}
	for _, l := range grp {
		if l.grouped() {
			factors = append(factors, l.t)
		} else {
			x = g.product(x, l.t)
		}
	}
	return g.product(g.group(factors...), x)
}

// groupedF is the union of the false rails of one disjunct's leaves, the
// subject-only ones in one group.
func (g *gen) groupedF(grp []leafRails) dnf {
	subj := dnfFalse
	out := dnfFalse
	any := false
	for _, l := range grp {
		if l.grouped() {
			subj = union(subj, l.f)
			any = true
		} else {
			out = union(out, l.f)
		}
	}
	if any {
		out = union(g.group(subj), out)
	}
	return out
}

// tWithSubject is the true rail where subj, a subject-only condition, joins
// the group of every disjunct.
func (c *cond) tWithSubject(subj dnf) dnf {
	if c.isTrue != nil {
		if *c.isTrue {
			return c.g.group(subj)
		}
		return dnfFalse
	}
	out := dnfFalse
	for _, grp := range c.groups {
		out = union(out, c.g.groupedT(grp, subj))
	}
	return out
}

// EvalGroups returns the IDs of the module's groups the input satisfies.
func EvalGroups(m *Module, in *Input) []string {
	ix := m.groupIndex()
	e := ix.pool.Get().(*groupEval)
	defer e.release(ix)
	e.in, e.ix = in, ix
	out := []string{}
	try := func(gs []int) {
		for _, g := range gs {
			if !e.seen[g] {
				e.seen[g] = true
				if e.groupHolds(ix.groups[g]) {
					out = append(out, ix.ids[g])
				}
			}
		}
	}
	try(ix.always)
	for _, r := range in.SRoles {
		try(ix.byKey["has\x00sroles\x00"+r])
	}
	for id, rec := range in.Records {
		for _, k := range rec.KS {
			try(ix.byKey["has\x00"+id+"\x00"+k])
		}
		if rec.K != nil {
			try(ix.byKey["eq\x00"+id+"\x00"+*rec.K])
		}
	}
	slices.Sort(out)
	return out
}

// groupIndex files each group under the keys of one factor that every
// satisfying input has: a factor whose every clause requires a key among a
// list's keys (has) or a scalar's key (eq). A group without such a factor is
// tried for every input.
//
// A factor that several groups share is held once, so one evaluation answers
// it for all of them, and a reference the tests read is numbered, so a test
// reads its record from a slice rather than from [Input.Records].
//
// A factor of more than maxPlainClauses clauses, each of which requires a key
// among a list's keys, is keyed: its clauses are filed under their keys too,
// and an evaluation tries only the clauses filed under the keys the input
// has.
type groupIndex struct {
	ids    []string
	groups [][]int // the factors of each group, as indexes into factors
	// factors holds the clauses of each distinct factor.
	factors [][][]*test
	byKey   map[string][]int
	always  []int
	// refs lists the references the tests read; test.ri and test.ri2 index
	// it.
	refs []string
	// slots holds the slots of clauseKey that the clauses of a keyed factor
	// require keys in, and nil for any other factor; clauses files the
	// clauses of keyed factors under their keys, and sources names where an
	// input's keys of each slot are.
	slots   [][]int
	clauses map[clauseKey][]factorClause
	sources []keySource
	pool    sync.Pool
}

// maxPlainClauses is the number of clauses up to which a factor is cheaper to
// evaluate clause by clause than through the keys of the input.
const maxPlainClauses = 4

// clauseKey is a key a clause requires among the keys of the list in slot
// (listSlot).
type clauseKey struct {
	slot int
	val  string
}

type factorClause struct{ f, c int }

// keySource names where the input's list in one slot is.
type keySource struct {
	slot, ri int
	field    string
}

// key returns the clauseKey of a test that requires a key among a list's
// keys, and false for any other test.
func (t *test) key() (clauseKey, bool) {
	if t.kind == "has" {
		return clauseKey{t.slot, t.val}, true
	}
	return clauseKey{}, false
}

func (m *Module) groupIndex() *groupIndex {
	m.ixOnce.Do(func() {
		ix := &groupIndex{byKey: map[string][]int{}, clauses: map[clauseKey][]factorClause{}}
		ix.ids = slices.Sorted(maps.Keys(m.Groups))
		factorIDs := map[int]int{}
		refIDs := map[string]int{}
		refID := func(ref string) int {
			if ref == "" || ref == "sroles" {
				return -1
			}
			i, ok := refIDs[ref]
			if !ok {
				i = len(ix.refs)
				refIDs[ref] = i
				ix.refs = append(ix.refs, ref)
			}
			return i
		}
		for g, id := range ix.ids {
			grp := m.Groups[id]
			fs := make([]int, len(grp.Factors))
			for i, f := range grp.Factors {
				fi, ok := factorIDs[grp.factorIDs[i]]
				if !ok {
					fi = len(ix.factors)
					factorIDs[grp.factorIDs[i]] = fi
					ix.factors = append(ix.factors, f)
					var keys []clauseKey
					var slots []int
					for _, c := range f {
						for _, t := range c {
							t.ri, t.ri2 = refID(t.ref), refID(t.ref2)
							t.slot = listSlot(t.ri, t.field)
						}
						for _, t := range c {
							if k, ok := t.key(); ok {
								keys = append(keys, k)
								if !slices.Contains(slots, k.slot) {
									slots = append(slots, k.slot)
								}
								if !slices.ContainsFunc(ix.sources, func(s keySource) bool { return s.slot == k.slot }) {
									ix.sources = append(ix.sources, keySource{k.slot, t.ri, t.field})
								}
								break
							}
						}
					}
					if len(f) <= maxPlainClauses || len(keys) < len(f) {
						slots = nil
					}
					ix.slots = append(ix.slots, slots)
					for c, k := range keys {
						if slots != nil {
							ix.clauses[k] = append(ix.clauses[k], factorClause{fi, c})
						}
					}
				}
				fs[i] = fi
			}
			ix.groups = append(ix.groups, fs)
			var best []string
			for _, f := range grp.Factors {
				var keys []string
				ok := true
				for _, c := range f {
					k := ""
					for _, t := range c {
						if t.kind == "has" && t.field == "" || t.kind == "eq" {
							k = t.kind + "\x00" + t.ref + "\x00" + t.val
							break
						}
					}
					if k == "" {
						ok = false
						break
					}
					keys = append(keys, k)
				}
				if ok && (best == nil || len(keys) < len(best)) {
					best = keys
				}
			}
			if best == nil {
				ix.always = append(ix.always, g)
				continue
			}
			for _, k := range slices.Compact(slices.Sorted(slices.Values(best))) {
				ix.byKey[k] = append(ix.byKey[k], g)
			}
		}
		ix.pool.New = func() any {
			return &groupEval{seen: make([]bool, len(ix.ids)), factors: make([]int8, len(ix.factors)),
				recs: make([]Record, len(ix.refs)), loaded: make([]int8, len(ix.refs)),
				sets: make([]map[string]struct{}, 3*len(ix.refs)+1), cands: make([][]int, len(ix.factors))}
		}
		m.ix = ix
	})
	return m.ix
}

// groupEval holds what one call of [EvalGroups] has learned about its input:
// the groups it tried, the answer of each factor it evaluated, and the
// record of each reference it read.
type groupEval struct {
	in      *Input
	ix      *groupIndex
	seen    []bool
	factors []int8 // 0 not evaluated, 1 holds, 2 does not
	recs    []Record
	loaded  []int8 // 0 not read, 1 in recs, 2 absent from the input
	// sets holds, as a set, each long list a test has looked a key up in,
	// by listSlot.
	sets []map[string]struct{}
	// cands holds the clauses of each keyed factor filed under a key the
	// input has, in the slots filed lists; touched lists the factors with
	// any.
	cands   [][]int
	filed   []int
	touched []int
}

// file adds to cands the clauses filed under the input's keys of slot, once
// per slot.
func (e *groupEval) file(slot int) {
	if slices.Contains(e.filed, slot) {
		return
	}
	e.filed = append(e.filed, slot)
	add := func(v string) {
		for _, fc := range e.ix.clauses[clauseKey{slot, v}] {
			if len(e.cands[fc.f]) == 0 {
				e.touched = append(e.touched, fc.f)
			}
			e.cands[fc.f] = append(e.cands[fc.f], fc.c)
		}
	}
	s := e.ix.sources[slices.IndexFunc(e.ix.sources, func(s keySource) bool { return s.slot == slot })]
	var ks []string
	if s.ri < 0 {
		ks = e.in.SRoles
	} else if r, ok := e.rec(s.ri); ok {
		ks = r.list(s.field)
	}
	for _, v := range ks {
		add(v)
	}
}

func (e *groupEval) release(ix *groupIndex) {
	e.in, e.ix = nil, nil
	clear(e.seen)
	clear(e.factors)
	clear(e.recs)
	clear(e.loaded)
	clear(e.sets)
	for _, f := range e.touched {
		e.cands[f] = e.cands[f][:0]
	}
	e.filed, e.touched = e.filed[:0], e.touched[:0]
	ix.pool.Put(e)
}

// rec returns the record of the reference i, and false where the input has
// none.
func (e *groupEval) rec(i int) (*Record, bool) {
	switch e.loaded[i] {
	case 0:
		r, ok := e.in.Records[e.ix.refs[i]]
		if !ok {
			e.loaded[i] = 2
			return nil, false
		}
		e.recs[i], e.loaded[i] = r, 1
	case 2:
		return nil, false
	}
	return &e.recs[i], true
}

// contains reports whether ks, the list in the slot listSlot names, holds k.
// A list longer than eight keys is looked up in a set that the first lookup
// builds.
func (e *groupEval) contains(slot int, ks []string, k string) bool {
	if len(ks) <= 8 {
		return slices.Contains(ks, k)
	}
	set := e.sets[slot]
	if set == nil {
		set = make(map[string]struct{}, len(ks))
		for _, x := range ks {
			set[x] = struct{}{}
		}
		e.sets[slot] = set
	}
	_, ok := set[k]
	return ok
}

// listSlot numbers the list a test reads: the field of the record of ri, or
// the subject's roles.
func listSlot(ri int, field string) int {
	switch {
	case ri < 0:
		return 0
	case field == "ea":
		return 3*ri + 2
	case field == "eb":
		return 3*ri + 3
	}
	return 3*ri + 1
}

func (e *groupEval) groupHolds(fs []int) bool {
	for _, f := range fs {
		if !e.factorHolds(f) {
			return false
		}
	}
	return true
}

func (e *groupEval) factorHolds(f int) bool {
	if a := e.factors[f]; a != 0 {
		return a == 1
	}
	var ok bool
	if slots := e.ix.slots[f]; slots != nil {
		for _, s := range slots {
			e.file(s)
		}
		ok = slices.ContainsFunc(e.cands[f], func(c int) bool { return e.clauseHolds(e.ix.factors[f][c]) })
	} else {
		ok = slices.ContainsFunc(e.ix.factors[f], e.clauseHolds)
	}
	e.factors[f] = 2
	if ok {
		e.factors[f] = 1
	}
	return ok
}

func (e *groupEval) clauseHolds(c []*test) bool {
	for _, t := range c {
		if !t.holds(e) {
			return false
		}
	}
	return true
}

func (t *test) holds(e *groupEval) bool {
	if t.kind == "m2m" {
		return e.in.M2M == (t.val == "true")
	}
	if t.kind == "noop" {
		return true
	}
	var ks []string
	var k *string
	var st, cl string
	var n0 bool
	var num *jsonvalue.Decimal
	if t.ref == "sroles" {
		ks = e.in.SRoles
	} else if r, ok := e.rec(t.ri); ok {
		ks, k, st, cl, n0, num = r.list(t.field), r.K, r.S, r.T, r.N0, r.N
	}
	in2 := func() ([]string, *string) {
		if r, ok := e.rec(t.ri2); ok {
			return r.list(t.field2), r.K
		}
		return nil, nil
	}
	switch t.kind {
	case "has":
		return e.contains(t.slot, ks, t.val)
	case "nothas":
		return !e.contains(t.slot, ks, t.val)
	case "eq":
		return k != nil && *k == t.val
	case "ne":
		return k != nil && *k != t.val
	case "in":
		return k != nil && slices.Contains(t.set, *k)
	case "notin":
		return k == nil || !slices.Contains(t.set, *k)
	case "none":
		return ks != nil && !slices.ContainsFunc(t.set, func(x string) bool { return e.contains(t.slot, ks, x) })
	case "non0":
		return !n0
	case "rel":
		return relHolds(t.val, num, t.num)
	case "relref":
		var n2 *jsonvalue.Decimal
		if r, ok := e.rec(t.ri2); ok {
			n2 = r.N
		}
		return relHolds(t.val, num, n2)
	case "nonum":
		return num == nil
	case "subset", "unmatched", "nonempty", "emptyleft":
		return t.subsetHolds(e)
	case "state":
		return st == t.val
	case "cls":
		return cl == t.val
	case "clsin":
		return slices.Contains(t.set, cl)
	case "eqref", "neref", "inref", "notinref":
		ks2, k2 := in2()
		switch t.kind {
		case "eqref":
			return k != nil && k2 != nil && *k == *k2
		case "neref":
			return k != nil && k2 != nil && *k != *k2
		case "inref":
			return k != nil && ks2 != nil && slices.Contains(ks2, *k)
		default:
			return k == nil || ks2 == nil || !slices.Contains(ks2, *k)
		}
	case "overlap":
		ks2, _ := in2()
		return ks != nil && ks2 != nil && slices.ContainsFunc(ks, func(x string) bool { return slices.Contains(ks2, x) })
	case "disjoint":
		ks2, _ := in2()
		return ks != nil && !(ks2 != nil && slices.ContainsFunc(ks, func(x string) bool { return slices.Contains(ks2, x) }))
	}
	panic("unknown test " + t.kind)
}

// list returns the list field f of the record: ks when f is empty, or ea or
// eb.
func (r Record) list(f string) []string {
	switch f {
	case "ea":
		return r.EA
	case "eb":
		return r.EB
	}
	return r.KS
}
