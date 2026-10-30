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
	set  []string // a literal's keys; for IS SUBSET, the tokens of a literal on the right
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
}

// Group is a subject group: a conjunction of factors, each a disjunction of
// clauses of tests. The module reads it as "gN" in input.g.
type Group struct {
	Factors [][][]*test
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
		id = fmt.Sprintf("g%d", len(g.groupIDs)+1)
		g.groupIDs[key] = id
		var grp Group
		for _, x := range fs {
			cs, ok := subjectClauses(x.d)
			if !ok {
				panic("regogen: a group factor holds an expression without a test")
			}
			grp.Factors = append(grp.Factors, cs)
		}
		g.groups[id] = grp
	}
	return dnf{{{cls: clsIndexIn, text: lit(id) + " in input.g"}}}
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
	seen := map[string]bool{}
	out := []string{}
	try := func(ids []string) {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				if m.Groups[id].holds(in) {
					out = append(out, id)
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
type groupIndex struct {
	byKey  map[string][]string
	always []string
}

func (m *Module) groupIndex() *groupIndex {
	m.ixOnce.Do(func() {
		ix := &groupIndex{byKey: map[string][]string{}}
		ids := slices.Sorted(maps.Keys(m.Groups))
		for _, id := range ids {
			var best []string
			for _, f := range m.Groups[id].Factors {
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
				ix.always = append(ix.always, id)
				continue
			}
			for _, k := range slices.Compact(slices.Sorted(slices.Values(best))) {
				ix.byKey[k] = append(ix.byKey[k], id)
			}
		}
		m.ix = ix
	})
	return m.ix
}

func (grp Group) holds(in *Input) bool {
	for _, f := range grp.Factors {
		ok := false
		for _, c := range f {
			if clauseHolds(c, in) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func clauseHolds(c []*test, in *Input) bool {
	for _, t := range c {
		if !t.holds(in) {
			return false
		}
	}
	return true
}

func (t *test) holds(in *Input) bool {
	if t.kind == "m2m" {
		return in.M2M == (t.val == "true")
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
		ks = in.SRoles
	} else {
		r, ok := in.Records[t.ref]
		if ok {
			ks, k, st, cl, n0, num = r.list(t.field), r.K, r.S, r.T, r.N0, r.N
		}
	}
	in2 := func() ([]string, *string) {
		r := in.Records[t.ref2]
		return r.list(t.field2), r.K
	}
	switch t.kind {
	case "has":
		return slices.Contains(ks, t.val)
	case "nothas":
		return !slices.Contains(ks, t.val)
	case "eq":
		return k != nil && *k == t.val
	case "ne":
		return k != nil && *k != t.val
	case "in":
		return k != nil && slices.Contains(t.set, *k)
	case "notin":
		return k == nil || !slices.Contains(t.set, *k)
	case "none":
		return ks != nil && !slices.ContainsFunc(ks, func(x string) bool { return slices.Contains(t.set, x) })
	case "non0":
		return !n0
	case "rel":
		return relHolds(t.val, num, t.num)
	case "relref":
		return relHolds(t.val, num, in.Records[t.ref2].N)
	case "nonum":
		return num == nil
	case "subset", "unmatched", "nonempty", "emptyleft":
		return t.subsetHolds(in)
	case "state":
		return st == t.val
	case "cls":
		return cl == t.val
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
