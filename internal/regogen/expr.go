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
	"slices"
	"strings"
)

// Expression classes. A clause writes its expressions in this order, because
// OPA evaluates a body in the order written: the equalities and memberships
// the rule index uses first, the network last.
const (
	clsIndexEq    = 0 // an equality the rule index of OPA uses
	clsIndexIn    = 1 // a membership the rule index of OPA uses
	clsCheck      = 2 // a check after the index, or a reference to a rule
	clsBuiltin    = 3 // a call of a built-in function
	clsAfterBuilt = 4 // a check of a value a built-in function returned
)

// expr is one expression of a clause body.
type expr struct {
	cls  int
	text string
	// fact records what the expression requires of one reference, so that a
	// product can drop a clause that requires two states of it.
	fact fact
	// test is the expression as a subject-group test, or nil when the group
	// evaluator does not know it.
	test *test
	// rule names the rule the expression references, or is empty.
	rule string
}

// fact is the requirement an expression puts on a reference: a state, a class
// (which implies the state VALUE), or any value at all (state VALUE).
type fact struct {
	ref   string
	field byte // 's' state, 't' class, 'v' a value; 0 for no fact
	val   string
}

// clause is a conjunction of expressions without repeats.
type clause []expr

// dnf is a disjunction of clauses. The empty dnf is false; a dnf holding one
// empty clause is true.
type dnf []clause

var (
	dnfTrue  = dnf{clause{}}
	dnfFalse = dnf{}
)

func (c clause) key() string {
	texts := make([]string, len(c))
	for i, e := range c {
		texts[i] = e.text
	}
	slices.Sort(texts)
	return strings.Join(texts, "\x00")
}

func (d dnf) key() string {
	keys := make([]string, len(d))
	for i, c := range d {
		keys[i] = c.key()
	}
	return strings.Join(keys, "\x01")
}

func (d dnf) isTrue() bool  { return len(d) == 1 && len(d[0]) == 0 }
func (d dnf) isFalse() bool { return len(d) == 0 }

// conj joins clauses, keeping the first of repeated expressions.
func conj(parts ...clause) clause {
	var out clause
	for _, p := range parts {
		for _, e := range p {
			if !slices.ContainsFunc(out, func(x expr) bool { return x.text == e.text }) {
				out = append(out, e)
			}
		}
	}
	return out
}

// union joins disjunctions, dropping repeated clauses.
func union(ds ...dnf) dnf {
	out := dnf{}
	seen := map[string]bool{}
	for _, d := range ds {
		for _, c := range d {
			k := c.key()
			if !seen[k] {
				seen[k] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// prod is a × b without the clauses that cannot hold.
func prod(a, b dnf, prune bool) dnf {
	out := make(dnf, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			c := conj(x, y)
			if !prune || consistent(c) {
				out = append(out, c)
			}
		}
	}
	return union(out)
}

// consistent reports whether a clause can hold: one state and one class per
// reference, and a value only in the state VALUE. A product of two leaves over
// one reference often asks for two states at once; such a clause never holds
// and only costs the compiler.
func consistent(c clause) bool {
	type slot struct {
		ref   string
		field byte
	}
	seen := map[slot]string{}
	set := func(ref string, field byte, v string) bool {
		k := slot{ref, field}
		if old, ok := seen[k]; ok {
			return old == v
		}
		seen[k] = v
		return true
	}
	for _, e := range c {
		f := e.fact
		switch f.field {
		case 's':
			if !set(f.ref, 's', f.val) {
				return false
			}
		case 't':
			if !set(f.ref, 's', "VALUE") || !set(f.ref, 't', f.val) {
				return false
			}
		case 'v':
			if !set(f.ref, 's', "VALUE") {
				return false
			}
		}
	}
	return true
}

// guarded reports whether every clause has an expression the index uses.
func guarded(d dnf) bool {
	for _, c := range d {
		if !slices.ContainsFunc(c, func(e expr) bool { return e.cls <= clsIndexIn }) {
			return false
		}
	}
	return true
}

// refsNodeRule reports whether a clause of d references the rule of a node or
// a materialized rule.
func refsNodeRule(d dnf) bool {
	for _, c := range d {
		for _, e := range c {
			if e.rule != "" && (strings.HasPrefix(e.rule, "n") || strings.HasPrefix(e.rule, "m")) {
				return true
			}
		}
	}
	return false
}
