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
	"slices"
	"strconv"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regogen/spectables"
)

// IS SUBSET holds when the left value, read as a list, has at least one
// element and each of its elements equals an element of the right value, read
// as a list. Two elements are equal as == compares them, with case, except
// that a string never equals a boolean on the right, an object on the right
// equals nothing, and a resource attribute or a PIP on the right is one value
// whose elements other than strings equal nothing (rule subset).
//
// The projection writes each left element as its tokens (subsetLeft) and the
// right value as the tokens of all its elements (subsetRight), so that two
// elements are equal exactly when the tokens of the left one meet those of the
// right one. A token is a prefix and a text:
//
//	t:  a scalar by its text, which a number, a string, and a boolean on the
//	    left share; on the right also a list by its Java text, which a string
//	    on the left equals
//	b:  a boolean, which on the right only a boolean on the left meets
//	s:  a list or an object on the left by its Java text, which a string on the
//	    right equals
//	l:  a list by its elements in order, each by its own token
//	o:  an object by its members

// numberText returns the text a number compares by under ==: for a number of
// the input, its digits when it is an integer and Double.toString otherwise;
// the BigDecimal text of a number literal; the text as written of an item of
// a literal list.
type numberText func(jsonvalue.Number) string

// subsetLeft returns the tokens of each element of v read as a list.
func subsetLeft(v jsonvalue.Value, num numberText) [][]string {
	out := [][]string{}
	for _, e := range asList(v) {
		var ts []string
		switch e := e.(type) {
		case nil:
		case bool:
			ts = []string{"t:" + strconv.FormatBool(e), "b:" + strconv.FormatBool(e)}
		case []jsonvalue.Value, *jsonvalue.Object:
			ts = []string{"s:" + structureText(e)}
			if t, ok := caseToken(e, num); ok {
				ts = append(ts, t)
			}
		default:
			ts = []string{"t:" + scalarText(e, num)}
		}
		out = append(out, ts)
	}
	return out
}

// subsetRight returns the tokens of the elements of v read as a list; with
// oneValue, those of its strings only.
func subsetRight(v jsonvalue.Value, num numberText, oneValue bool) []string {
	out := []string{}
	for _, e := range asList(v) {
		switch e := e.(type) {
		case string:
			out = append(out, "t:"+e, "s:"+e)
		case nil, *jsonvalue.Object:
		default:
			if oneValue {
				continue
			}
			switch e := e.(type) {
			case bool:
				out = append(out, "b:"+strconv.FormatBool(e))
			case []jsonvalue.Value:
				out = append(out, "t:"+structureText(e))
				if t, ok := caseToken(e, num); ok {
					out = append(out, t)
				}
			default:
				out = append(out, "t:"+scalarText(e, num))
			}
		}
	}
	return out
}

func asList(v jsonvalue.Value) []jsonvalue.Value {
	if l, ok := v.([]jsonvalue.Value); ok {
		return l
	}
	return []jsonvalue.Value{v}
}

func scalarText(e jsonvalue.Value, num numberText) string {
	switch e := e.(type) {
	case string:
		return e
	case jsonvalue.Number:
		return num(e)
	case bool:
		return strconv.FormatBool(e)
	}
	panic(fmt.Sprintf("regogen: %T is not a scalar", e))
}

// caseToken is the token of a list or an object as an element of a list: a
// list by the tokens of its elements in order, a scalar by its text with case,
// an object by its members. A list that holds null equals nothing and has no
// token.
func caseToken(e jsonvalue.Value, num numberText) (string, bool) {
	switch e := e.(type) {
	case nil:
		return "", false
	case *jsonvalue.Object:
		return "o:" + *legacyvalue.Of(e).Structure, true
	case []jsonvalue.Value:
		parts := make([]string, len(e))
		for i, x := range e {
			t, ok := caseToken(x, num)
			if !ok {
				return "", false
			}
			parts[i] = t
		}
		b, err := json.Marshal(parts)
		if err != nil {
			panic(err)
		}
		return "l:" + string(b), true
	}
	return "t:" + scalarText(e, num), true
}

// inputNumberText is the text a number of the input compares by.
func inputNumberText(n jsonvalue.Number) string { return legacyvalue.NumberText(n) }

// literalNumberText is the text a number literal compares by: its BigDecimal
// text, so 5.0 stays 5.0 and 1e3 is 1E+3.
func literalNumberText(n jsonvalue.Number) string {
	if t, ok := jsonvalue.BigDecimalText(string(n)); ok {
		return t
	}
	return string(n)
}

// listNumberText is the text an item of a literal list compares by: as written.
func listNumberText(n jsonvalue.Number) string { return string(n) }

// subsetOneValue reports whether an operand of kind k on the right of IS
// SUBSET is one value: a resource attribute or a PIP.
func subsetOneValue(k spectables.Kind) bool {
	return isRes(k) || strings.HasPrefix(string(k), "pip:")
}

// subsetTemplate is the template of IS SUBSET over any two values.
func subsetTemplate(L, R *side, b *tb) (tpl, bool) {
	var la, rb string
	if L.ref != nil {
		L.ref.Subset = true
		b.use(L, "sa")
		la = L.field("sa")
	} else {
		la = setsLit(L.lit.sa)
	}
	if R.ref != nil {
		R.ref.Subset = true
		b.use(R, "sb")
		rb = R.field("sb")
	} else {
		rb = setLit(R.lit.sb)
	}
	c := clsCheck
	if L.ref != nil && L.ref.Network || R.ref != nil && R.ref.Network {
		c = clsAfterBuilt
	}
	ref := L
	if L.ref == nil {
		ref = R
	}
	bind := conj(L.bind(), R.bind())
	row := func(kind, text string) clause {
		return conj(bind, clause{{cls: c, text: text, fact: vfact(ref), test: subsetTest(L, R, kind)}})
	}
	// every element of the left has a token on the right; a comprehension
	// keeps the element variable local, so two such rows can share a clause
	t := row("subset", fmt.Sprintf("every e in %s { some x in e; x in %s }", la, rb))
	f := dnf{row("unmatched", fmt.Sprintf("count([e | some e in %s; every x in e { not x in %s }]) > 0", la, rb))}
	if L.ref != nil {
		// an empty list on the left is a subset of nothing
		t = conj(row("nonempty", fmt.Sprintf("count(%s) > 0", la)), t)
		f = append(f, row("emptyleft", fmt.Sprintf("count(%s) == 0", la)))
	}
	return tpl{t: dnf{t}, f: f, fields: b.fields, rules: map[spectables.ValueRule]bool{spectables.RuleSubset: true}},
		true
}

// setsLit is the Rego text of a list of lists of strings.
func setsLit(sets [][]string) string {
	parts := make([]string, len(sets))
	for i, s := range sets {
		items := make([]string, len(s))
		for j, x := range s {
			items[j] = lit(x)
		}
		parts[i] = "[" + strings.Join(items, ", ") + "]"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// subsetTest is the group test of a row of IS SUBSET: subset and unmatched
// (some left element equals no right one) over both sides, nonempty and
// emptyleft over the left one; nil when a side is a network PIP.
func subsetTest(L, R *side, kind string) *test {
	for _, s := range []*side{L, R} {
		if s.ref != nil && s.ref.Network {
			return nil
		}
	}
	t := &test{kind: kind}
	if L.ref != nil {
		t.ref = L.ref.ID
	} else {
		t.sets = L.lit.sa
	}
	if R.ref != nil {
		t.ref2 = R.ref.ID
	} else {
		t.set = R.lit.sb
	}
	return t
}

// subsetHolds answers a test of subsetTest as its Rego row does: a missing
// field fails it.
func (t *test) subsetHolds(in *Input) bool {
	la, okL := t.sets, t.sets != nil
	if t.ref != "" {
		r, ok := in.Records[t.ref]
		la, okL = r.SA, ok && r.SA != nil
	}
	if !okL {
		return false
	}
	switch t.kind {
	case "nonempty":
		return len(la) > 0
	case "emptyleft":
		return len(la) == 0
	}
	rb, okR := t.set, t.set != nil
	if t.ref2 != "" {
		r, ok := in.Records[t.ref2]
		rb, okR = r.SB, ok && r.SB != nil
	}
	if !okR {
		return false
	}
	unmatched := func(e []string) bool {
		return !slices.ContainsFunc(e, func(x string) bool { return slices.Contains(rb, x) })
	}
	if t.kind == "subset" {
		return !slices.ContainsFunc(la, unmatched)
	}
	return slices.ContainsFunc(la, unmatched)
}
