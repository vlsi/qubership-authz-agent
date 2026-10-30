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
	"fmt"
	"regexp"
	"slices"
	"strings"

	"authz-agent/internal/regogen/spectables"
)

// tpl is the template of a value-dependent cell: the true and the false rows
// of the comparison of two values, and the record fields the true rows read of
// each side.
type tpl struct {
	t, f   dnf
	fields map[*side]map[string]bool
	// undefined is set when a value leaves the comparison on neither rail.
	undefined bool
	// rules are the value rules the template implements; a cell that names
	// another rule is not this template's.
	rules map[spectables.ValueRule]bool
}

// fieldClasses lists the classes of the domain of s whose record carries
// every field the true rows read of s, as [record] writes them.
func (t tpl) fieldClasses(s *side) []spectables.Class {
	var out []spectables.Class
	for _, cl := range s.ref.domain.Classes {
		ok := true
		for f := range t.fields[s] {
			if !fieldOf(f, cl) {
				ok = false
			}
		}
		if ok {
			out = append(out, cl)
		}
	}
	return out
}

// fieldOf reports whether [record] writes field f for a value of class cl:
// k for s and n; ks for every class but z; raw and the segments for s; tk and
// o for the lists and the object. Any other field, such as n0, keeps the check
// of the class.
func fieldOf(f string, cl spectables.Class) bool {
	switch f {
	case "k":
		return cl == spectables.ClassString || cl == spectables.ClassScalar
	case "ks":
		return cl != spectables.ClassNull
	case "raw", "seg":
		return cl == spectables.ClassString
	case "tk", "o":
		return cl == spectables.ClassList || cl == spectables.ClassHeaderList || isStructure(cl)
	}
	return false
}

// isStructureOrList reports whether cl is a list or an object.
func isStructureOrList(cl spectables.Class) bool {
	return isListClass(cl) || cl == spectables.ClassObject
}

// isListClass reports whether cl is a list.
func isListClass(cl spectables.Class) bool {
	return cl == spectables.ClassList || cl == spectables.ClassHeaderList || cl == spectables.ClassNullElement ||
		cl == spectables.ClassNested
}

// isStructure reports whether cl is a list with a null, a list or object
// element, or an object.
func isStructure(cl spectables.Class) bool {
	return cl == spectables.ClassNullElement || cl == spectables.ClassNested || cl == spectables.ClassObject
}

func lit(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func setLit(keys []string) string {
	if len(keys) == 0 {
		return "set()"
	}
	ks := slices.Clone(keys)
	slices.Sort(ks)
	ks = slices.Compact(ks)
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = lit(k)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

type tb struct {
	fields map[*side]map[string]bool
}

func (b *tb) use(s *side, f string) {
	if s.ref == nil {
		return
	}
	if b.fields[s] == nil {
		b.fields[s] = map[string]bool{}
	}
	b.fields[s][f] = true
}

// k is the key of a scalar side, as a literal or a field.
func (b *tb) k(s *side) string {
	if s.ref == nil {
		return lit(s.lit.key)
	}
	b.use(s, "k")
	return s.field("k")
}

func (b *tb) ks(s *side) string {
	if s.ref == nil {
		return setLit(s.lit.keys)
	}
	b.use(s, "ks")
	return s.field("ks")
}

func vfact(s *side) fact {
	if s.ref == nil {
		return fact{}
	}
	return fact{ref: s.ref.ID, field: 'v'}
}

func isScalar(c spectables.Class) bool {
	return c == spectables.ClassString || c == spectables.ClassScalar
}

func isRes(k spectables.Kind) bool {
	return k == spectables.KindResource || k == spectables.KindResPath || k == spectables.KindResNested ||
		k == spectables.KindResJSONPath
}

// negated maps an operator to the one it negates within the value-by-value
// case.
var negated = map[spectables.Operator]spectables.Operator{
	spectables.OpNE: spectables.OpEQ, spectables.OpNotIn: spectables.OpIn,
	spectables.OpNotContains: spectables.OpContains, spectables.OpNotContainsAny: spectables.OpContainsAny,
	spectables.OpNotMatch: spectables.OpMatch,
}

// template returns the rows of a comparison between a value of class cl on the
// left and one of class cr on the right, and false when no template covers the
// pair. The cells say where a template applies, and the templates say how
// the values decide.
func template(op spectables.Operator, L, R *side, cl, cr spectables.Class) (tpl, bool) {
	if _, ok := negated[op]; ok {
		return valueTemplate(op, L, R, cl, cr)
	}
	// A list with a null element (class xn, or a SINGLE_ODD list read as one)
	// ends the rule on one side of a collection operator: the right of IN, the
	// left of CONTAINS, and the left of CONTAINS ANY when the right has none.
	// The agent reads the end as undefined, so both rails require that side to
	// hold no null element; elsewhere the null element has no key and the
	// list compares as any other.
	var ends *side
	switch op {
	case spectables.OpIn:
		if cr == spectables.ClassNullElement {
			ends = R
		}
	case spectables.OpContains:
		if cl == spectables.ClassNullElement {
			ends = L
		}
	case spectables.OpContainsAny:
		if cl == spectables.ClassNullElement {
			// With nulls on both sides the guard leaves the leaf undefined,
			// where the specification compares the values: an open
			// departure.
			ends = L
		}
	}
	t, ok := valueTemplate(op, L, R, cl, cr)
	if !ok || ends == nil || ends.ref == nil {
		return t, ok
	}
	g := conj(ends.bind(), clause{{cls: ends.cls(clsCheck), text: "not " + ends.field("n0"), fact: vfact(ends),
		test: refTest(ends, &test{kind: "non0"})}})
	t.t = prod(dnf{g}, t.t, true)
	t.f = prod(dnf{g}, t.f, true)
	if t.fields[ends] == nil {
		t.fields[ends] = map[string]bool{}
	}
	t.fields[ends]["n0"] = true
	t.undefined = true
	t.rules[spectables.RuleNullElementEnds] = true
	return t, true
}

func valueTemplate(op spectables.Operator, L, R *side, cl, cr spectables.Class) (tpl, bool) {
	if pos, ok := negated[op]; ok {
		t, ok := template(pos, L, R, cl, cr)
		if !ok {
			return tpl{}, false
		}
		// the true rows of the negation are the false rows of the operator,
		// which carry their own checks; the fields its true rows read are
		// the fields those checks read
		fields := map[*side]map[string]bool{}
		for _, s := range []*side{L, R} {
			if s != nil && s.ref != nil {
				fields[s] = map[string]bool{"guard": true}
			}
		}
		return tpl{t: t.f, f: t.t, fields: fields, undefined: t.undefined, rules: t.rules}, true
	}
	if R == nil {
		return tpl{}, false
	}
	b := &tb{fields: map[*side]map[string]bool{}}
	out := func(rule spectables.ValueRule, t, f dnf) (tpl, bool) {
		return tpl{t: t, f: f, fields: b.fields, rules: map[spectables.ValueRule]bool{rule: true}}, true
	}
	lref, rref := L.ref != nil, R.ref != nil
	net := lref && L.ref.Network || rref && R.ref.Network
	if op == spectables.OpEQ && (isStructureOrList(cl) && cr == spectables.ClassString && lref ||
		cl == spectables.ClassString && isStructureOrList(cr) && rref) {
		// a list or an object equals a string by its Java text under
		// equalsIgnoreCase: value_op reaches it for a list on the left
		// (structure_text_left), eq for every other order (eq)
		structure, text := L, R
		if !isStructureOrList(cl) {
			structure, text = R, L
		}
		b.use(structure, "tk")
		bind := conj(L.bind(), R.bind())
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		t := conj(bind, clause{{cls: c, text: structure.field("tk") + " == " + b.k(text), fact: vfact(structure)}})
		f := conj(bind, clause{{cls: c, text: structure.field("tk") + " != " + b.k(text), fact: vfact(structure)}})
		tp, _ := out(spectables.RuleEq, dnf{t}, dnf{f})
		tp.rules[spectables.RuleStructureTextLeft] = true
		return tp, true
	}
	if op == spectables.OpContains && cl == spectables.ClassObject && cr == spectables.ClassString && lref {
		// an object on the left of CONTAINS equals a string by its Java text
		b.use(L, "tk")
		bind := conj(L.bind(), R.bind())
		c := L.cls(clsCheck)
		if net {
			c = clsAfterBuilt
		}
		t := conj(bind, clause{{cls: c, text: L.field("tk") + " == " + b.k(R), fact: vfact(L)}})
		f := conj(bind, clause{{cls: c, text: L.field("tk") + " != " + b.k(R), fact: vfact(L)}})
		return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
	}
	if op == spectables.OpIn && lref && !rref && (isListClass(cl) || cl == spectables.ClassObject) {
		// a list or an object on the left of IN is in a literal list holding
		// its Java text
		b.use(L, "tk")
		keys := R.lit.keys
		t := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: L.field("tk") + " in " + setLit(keys), fact: vfact(L)}})
		f := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: "not " + L.field("tk") + " in " + setLit(keys),
			fact: vfact(L)}})
		return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
	}
	if (op == spectables.OpIn || op == spectables.OpContains || op == spectables.OpEQ) &&
		cl == spectables.ClassObject && cr == spectables.ClassObject && lref && rref {
		// two objects are equal by their members: the same keys, each value
		// of the same JSON type and equal, a list inside in order
		b.use(L, "o")
		b.use(R, "o")
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		bind := conj(L.bind(), R.bind())
		t := conj(bind, clause{{cls: c, text: L.field("o") + " == " + R.field("o"), fact: vfact(L)}})
		f := conj(bind, clause{{cls: c, text: L.field("o") + " != " + R.field("o"), fact: vfact(L)}})
		// IN and CONTAINS reach the comparison through object_eq, == through
		// eq
		tp, _ := out(spectables.RuleObjectEq, dnf{t}, dnf{f})
		tp.rules[spectables.RuleEq] = true
		return tp, true
	}
	switch op {
	case spectables.OpMatch:
		if cl != spectables.ClassString || !R.isPattern() || !lref {
			return tpl{}, false
		}
		rx, err := matchRegex(R.pattern)
		if err != nil {
			return tpl{}, false
		}
		b.use(L, "raw")
		call := expr{cls: L.cls(clsCheck), text: fmt.Sprintf("regex.match(%s, %s)", lit(rx), L.field("raw")),
			fact: vfact(L)}
		t := conj(L.bind(), clause{call})
		if !L.ref.Network {
			if guards := segmentGuards(R.pattern, L.ref.ID); len(guards) > 0 {
				L.ref.Segments = true
				t = conj(guards, t)
			}
		}
		f := conj(L.bind(), clause{{cls: L.cls(clsCheck),
			text: fmt.Sprintf("not regex.match(%s, %s)", lit(rx), L.field("raw")), fact: vfact(L)}})
		return out(spectables.RuleMatch, dnf{t}, dnf{f})
	case spectables.OpEQ:
		if cl == spectables.ClassNullElement && cr == spectables.ClassList && lref && rref {
			// a list with a null element never equals a list of scalars
			b.use(L, "ks")
			return out(spectables.RuleListEq, dnfFalse, dnf{conj(L.bind(), R.bind())})
		}
		listOrNested := func(c spectables.Class) bool {
			return c == spectables.ClassList || c == spectables.ClassNested
		}
		if listOrNested(cl) && listOrNested(cr) && lref && rref {
			// two lists are equal as sets of typed elements, a number by its
			// text and a string with its case
			b.use(L, "o")
			b.use(R, "o")
			c := clsCheck
			if net {
				c = clsAfterBuilt
			}
			bind := conj(L.bind(), R.bind())
			t := conj(bind, clause{{cls: c, text: L.field("o") + " == " + R.field("o"), fact: vfact(L)}})
			f := conj(bind, clause{{cls: c, text: L.field("o") + " != " + R.field("o"), fact: vfact(L)}})
			return out(spectables.RuleListEq, dnf{t}, dnf{f})
		}
		if !isScalar(cl) || !isScalar(cr) || !lref && !rref {
			return tpl{}, false
		}
		cls := clsIndexEq
		if lref && rref {
			cls = clsCheck
		}
		if net {
			cls = clsAfterBuilt
		}
		bind := conj(L.bind(), R.bind())
		t := conj(bind, clause{{cls: cls, text: b.k(L) + " == " + b.k(R), fact: vfact(L), test: scalarTest("eq", L, R)}})
		fc := cls
		if fc == clsIndexEq {
			fc = clsCheck
		}
		f := conj(bind, clause{{cls: fc, text: b.k(L) + " != " + b.k(R), fact: vfact(L), test: scalarTest("ne", L, R)}})
		return out(spectables.RuleEq, dnf{t}, dnf{f})
	case spectables.OpIn:
		if (cl == spectables.ClassList || isStructure(cl)) && lref && rref {
			// a list or an object on the left is in the right when a string
			// there equals its Java text
			b.use(L, "tk")
			c := clsCheck
			if net {
				c = clsAfterBuilt
			}
			bind := conj(L.bind(), R.bind())
			t := conj(bind, clause{{cls: c, text: L.field("tk") + " in " + b.ks(R), fact: vfact(L)}})
			f := conj(bind, clause{{cls: c, text: "not " + L.field("tk") + " in " + b.ks(R), fact: vfact(L)}})
			return out(spectables.RuleStructureTextLeft, dnf{t}, dnf{f})
		}
		rightOK := isScalar(cr) || cr == spectables.ClassList || cr == spectables.ClassHeaderList ||
			isStructure(cr) && rref
		if !isScalar(cl) || !rightOK {
			return tpl{}, false
		}
		if !lref {
			if !rref {
				return tpl{}, false
			}
			t := conj(R.bind(), clause{{cls: R.cls(clsIndexIn), text: b.k(L) + " in " + b.ks(R), fact: vfact(R),
				test: refTest(R, &test{kind: "has", val: L.lit.key})}})
			f := conj(R.bind(), clause{{cls: R.cls(clsCheck), text: "not " + b.k(L) + " in " + b.ks(R),
				fact: vfact(R), test: refTest(R, &test{kind: "nothas", val: L.lit.key})}})
			return out(spectables.RuleInAny, dnf{t}, dnf{f})
		}
		if !rref {
			keys := R.lit.keys
			var t clause
			if len(keys) == 1 {
				t = conj(L.bind(), clause{{cls: L.cls(clsIndexEq), text: b.k(L) + " == " + lit(keys[0]), fact: vfact(L),
					test: refTest(L, &test{kind: "eq", val: keys[0]})}})
			} else {
				t = conj(L.bind(), clause{{cls: L.cls(clsIndexIn), text: b.k(L) + " in " + setLit(keys), fact: vfact(L),
					test: refTest(L, &test{kind: "in", set: keys})}})
			}
			f := conj(L.bind(), clause{{cls: L.cls(clsCheck), text: "not " + b.k(L) + " in " + setLit(keys),
				fact: vfact(L), test: refTest(L, &test{kind: "notin", set: keys})}})
			return out(spectables.RuleInAny, dnf{t}, dnf{f})
		}
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		bind := conj(L.bind(), R.bind())
		t := conj(bind, clause{{cls: c, text: b.k(L) + " in " + b.ks(R), fact: vfact(L), test: pairTest("inref", L, R)}})
		f := conj(bind, clause{{cls: c, text: "not " + b.k(L) + " in " + b.ks(R), fact: vfact(L),
			test: pairTest("notinref", L, R)}})
		return out(spectables.RuleInAny, dnf{t}, dnf{f})
	case spectables.OpContains, spectables.OpContainsAny:
		listy := func(c spectables.Class) bool {
			return isScalar(c) || c == spectables.ClassList || c == spectables.ClassHeaderList || isStructure(c)
		}
		if op == spectables.OpContains && rref && isRes(R.kind) && cr == spectables.ClassList {
			// a resource attribute on the right is one value, and no element
			// equals a list (right_attribute_one_value,
			// contains_right_attribute_list_false)
			b.use(L, "ks")
			return out(spectables.RuleContainsRightAttributeList, dnfFalse, dnf{conj(L.bind(), R.bind())})
		}
		if op == spectables.OpContains && rref {
			// a list of several values on the right of CONTAINS is not
			// compared element-wise: only a scalar on the right
			if !isScalar(cr) || !listy(cl) {
				return tpl{}, false
			}
		}
		if !listy(cl) || !listy(cr) {
			return tpl{}, false
		}
		if !lref {
			if !rref {
				return tpl{}, false
			}
			var ts dnf
			for _, k := range L.lit.keys {
				ts = append(ts, conj(R.bind(), clause{{cls: R.cls(clsIndexIn), text: lit(k) + " in " + b.ks(R),
					fact: vfact(R), test: refTest(R, &test{kind: "has", val: k})}}))
			}
			f := conj(R.bind(), clause{{cls: R.cls(clsCheck), fact: vfact(R),
				test: refTest(R, &test{kind: "none", set: L.lit.keys}),
				text: fmt.Sprintf("every x in %s { not x in %s }", b.ks(R), setLit(L.lit.keys))}})
			return out(spectables.RuleContainsAny, union(ts), dnf{f})
		}
		if !rref {
			var ts dnf
			for _, k := range R.lit.keys {
				ts = append(ts, conj(L.bind(), clause{{cls: L.cls(clsIndexIn), text: lit(k) + " in " + b.ks(L),
					fact: vfact(L), test: refTest(L, &test{kind: "has", val: k})}}))
			}
			f := conj(L.bind(), clause{{cls: L.cls(clsCheck), fact: vfact(L),
				test: refTest(L, &test{kind: "none", set: R.lit.keys}),
				text: fmt.Sprintf("every x in %s { not x in %s }", b.ks(L), setLit(R.lit.keys))}})
			return out(spectables.RuleContainsAny, union(ts), dnf{f})
		}
		c := clsCheck
		if net {
			c = clsAfterBuilt
		}
		v := "x_" + L.ref.ID + "_" + R.ref.ID
		bind := conj(L.bind(), R.bind())
		t := conj(bind, clause{{cls: c, text: fmt.Sprintf("some %s in %s", v, b.ks(L)), fact: vfact(L),
			test: pairTest("overlap", L, R)},
			{cls: c, text: fmt.Sprintf("%s in %s", v, b.ks(R)), fact: vfact(R), test: pairTest("noop", L, R)}})
		f := conj(bind, clause{{cls: c, fact: vfact(L), test: pairTest("disjoint", L, R),
			text: fmt.Sprintf("every %s in %s { not %s in %s }", v, b.ks(L), v, b.ks(R))}})
		return out(spectables.RuleContainsAny, dnf{t}, dnf{f})
	}
	return tpl{}, false
}

// matchRegex is the regular expression of a MATCH pattern: ** any characters, * and ? characters other than
// /, () one or more such characters, . any character, and every other
// character as itself in a regular expression, so a metacharacter keeps its
// meaning; anchored at both ends.
func matchRegex(pattern string) (string, error) {
	const any = `[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]`
	const noSlash = `[A-Za-z0-9\-._~:?#\[\]@!$&'()*+,;=%]`
	var b strings.Builder
	for i := 0; i < len(pattern); {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(any + "*")
			i += 2
		case pattern[i] == '*':
			b.WriteString(noSlash + "*")
			i++
		case strings.HasPrefix(pattern[i:], "()"):
			b.WriteString(noSlash + "+")
			i += 2
		case pattern[i] == '?':
			b.WriteString(noSlash)
			i++
		default:
			b.WriteByte(pattern[i])
			i++
		}
	}
	rx := "^(?:" + b.String() + ")$"
	if _, err := regexp.Compile(rx); err != nil {
		return "", err
	}
	return rx, nil
}

// segmentGuards are equalities a value must satisfy to match the pattern: its
// literal path segments, counted from the start up to the first segment that
// can span a slash and from the end after the last one, and the number of
// segments when no segment can. The index of OPA uses each of them.
func segmentGuards(pattern, ref string) clause {
	const most = 3
	isMeta := func(s string) bool { return strings.ContainsAny(s, `*?().[]{}+^$|\`) }
	breaks := func(s string) bool { return strings.Contains(s, "**") || strings.Contains(s, ".") }
	if strings.ContainsAny(pattern, `[]{}+^$|\`) {
		return nil
	}
	segs := strings.Split(pattern, "/")
	first, last := -1, -1
	for i, s := range segs {
		if breaks(s) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	var out clause
	if first < 0 {
		out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.nseg.%s == %d", ref, len(segs))})
	}
	head := segs
	if first >= 0 {
		head = segs[:first]
	}
	n := 0
	for i := len(head) - 1; i >= 0 && n < most; i-- {
		if head[i] != "" && !isMeta(head[i]) {
			out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.seg.%s[%d] == %s", ref, i, lit(head[i]))})
			n++
		}
	}
	if last >= 0 {
		tail := segs[last+1:]
		for j := 0; j < len(tail) && len(out) < most+1; j++ {
			x := tail[len(tail)-1-j]
			if x != "" && !isMeta(x) {
				out = append(out, expr{cls: clsIndexEq, text: fmt.Sprintf("input.eseg.%s[%d] == %s", ref, j, lit(x))})
			}
		}
	}
	return out
}

// refTest returns t for the reference of s, or nil when the group evaluator
// cannot read s: a literal or a network PIP.
func refTest(s *side, t *test) *test {
	if s.ref == nil || s.ref.Network {
		return nil
	}
	t.ref = s.ref.ID
	return t
}

// scalarTest is the test of an equality (eq) or inequality (ne) of two keys.
func scalarTest(kind string, L, R *side) *test {
	switch {
	case L.ref != nil && R.ref != nil:
		return pairTest(kind+"ref", L, R)
	case L.ref != nil:
		return refTest(L, &test{kind: kind, val: R.lit.key})
	default:
		return refTest(R, &test{kind: kind, val: L.lit.key})
	}
}

// pairTest is a test over two references.
func pairTest(kind string, L, R *side) *test {
	if L.ref == nil || R.ref == nil || L.ref.Network || R.ref.Network {
		return nil
	}
	return &test{kind: kind, ref: L.ref.ID, ref2: R.ref.ID}
}
