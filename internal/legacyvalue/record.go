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

package legacyvalue

import (
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
)

// State is the state an operand resolves to.
type State string

// The states. [Of] gives a value one of StateValue, StateNullElement,
// StateNull, and StateEmptyColl; the others depend on how the value was read,
// such as a path that selected nothing, and the caller sets them with
// [WithState].
const (
	StateValue State = "VALUE"
	// StateNullElement is the state of a list that holds null among its
	// elements. Its record is the record of a VALUE list, and the state lets
	// generated code tell it apart with one comparison.
	StateNullElement State = "NULL_ELEMENT"
	StateAbsent      State = "ABSENT"
	StateNull        State = "NULL"
	StatePIPEmpty    State = "PIP_EMPTY"
	StateEmptyColl   State = "EMPTY_COLL"
	StateEmptySel    State = "EMPTY_SEL"
	StateIndexOOB    State = "INDEX_OOB"
	StatePIPNull     State = "PIP_NULL"
	StateError       State = "ERROR"
)

// Class is the class of a value in state VALUE or NULL_ELEMENT, which decides
// how a comparison treats it.
type Class string

// The classes.
const (
	// ClassString is a string.
	ClassString Class = "s"
	// ClassScalar is a number or a boolean.
	ClassScalar Class = "n"
	// ClassList is a list whose elements are strings, numbers, or booleans.
	ClassList Class = "l"
	// ClassOther is any other value: an object, and a list that holds null, a
	// list, or an object.
	ClassOther Class = "x"
)

// Type is the JSON type of a value in state VALUE or NULL_ELEMENT.
type Type string

// The types.
const (
	TypeString  Type = "string"
	TypeNumber  Type = "number"
	TypeBoolean Type = "boolean"
	TypeArray   Type = "array"
	TypeObject  Type = "object"
)

// Record is what generated Rego reads of an operand instead of its raw JSON.
// Every field but State is set only where the value has it; a record in any
// state other than VALUE and NULL_ELEMENT carries State alone.
//
// [Record.Term] writes the record as a Rego object; each field comment starts
// with the key it has there.
type Record struct {
	// s: the state.
	State State
	// t: the class.
	Class Class
	// j: the JSON type.
	Type Type
	// k: the key two values are equal by under equalsIgnoreCase. For a
	// scalar it is [Fold] of the text the legacy service compares the value
	// by, so the number 5 and the string "5" share a key, and so do true and
	// "TRUE". For a list or an object it is Fold of its Java [Text], which a
	// string equals it by. Generated code compares a number with a number or
	// a string by Number instead, and the two are unequal unless both have
	// one; two numbers that both lack one, such as 1e400, compare by k
	// (ADR-0083).
	Key *string
	// ck: the key with case, the same text before [Fold].
	CaseKey *string
	// ks: the keys of the elements that are not null, for a list; the record's
	// own Key for any other value, which a collection operator reads as a list
	// of one. A number element compares with a number or a string by the
	// Number of its record in e instead.
	Keys []string
	// o: for a list or an object, the key two lists or two objects are equal
	// by: object members in key order, keys and strings with their case, and
	// each value typed, so {"a": 1} and {"a": "1"} have two keys, and so do
	// ["X"] and ["x"]. The list that [Of] reads is a set, as legacy reads a
	// list operand into a java.util.HashSet: its key lists the keys of its
	// elements sorted and without repeats, so [1, 2], [2, 1], and [1, 2, 2]
	// share one. A list inside an element or a member keeps its order. A
	// number is keyed by its Number, or by its [NumberText] where it has none,
	// so {"a": 1}, {"a": 1.0}, and {"a": 1e0} share one (ADR-0083).
	Structure *string
	// n or nl: the number new BigDecimal(ck) reads, set for a number and for
	// a string that BigDecimal reads; <, <=, >, and >= compare it, and so does
	// == between a number and a number or a string. A fraction or an exponent
	// has the value of its Double, so 1e-400 is 0, and 1e400, whose ck is
	// Infinity, has none. It is normalized, so two equal numbers have the same
	// Number. [Record.Term] decides between n and nl.
	Number *jsonvalue.Decimal
	// e: the records of the elements of a list, null elements included. An
	// element record has no e of its own: a list nested in an element compares
	// by the o and the ks of the element record. So the records of a value
	// hold its text a fixed number of times, however deep its lists nest.
	Elements []Record
}

// WithState returns the record of an operand in state s, which carries no
// value. s must not be StateValue or StateNullElement; [Of] builds those.
func WithState(s State) Record {
	return Record{State: s}
}

// Parts names the fields of the record of a list that [OfParts] builds.
type Parts uint8

// The parts of the record of a list.
const (
	// PartKey is k and ck.
	PartKey Parts = 1 << iota
	// PartKeys is ks.
	PartKeys
	// PartStructure is o.
	PartStructure
	// PartElements is e.
	PartElements
	// AllParts is every part, the record [Of] returns.
	AllParts = PartKey | PartKeys | PartStructure | PartElements
)

// Of returns the record of v as the operand's value: state NULL for nil,
// EMPTY_COLL for an empty list, NULL_ELEMENT for a list that holds nil, and
// VALUE otherwise. Of panics if v is not a [jsonvalue.Value].
func Of(v jsonvalue.Value) Record {
	return OfParts(v, AllParts)
}

// OfParts returns the record [Of] returns, with only the parts p of a
// non-empty list; the state and the class of a list, and the record of any
// other value, are whole.
func OfParts(v jsonvalue.Value, p Parts) Record {
	if l, ok := v.([]jsonvalue.Value); ok && len(l) > 0 {
		return listWithElements(l, p)
	}
	return of(v, false)
}

// of returns the record of v, and leaves out e when elements is false.
func of(v jsonvalue.Value, elements bool) Record {
	switch x := v.(type) {
	case nil:
		return Record{State: StateNull}
	case string:
		return scalar(TypeString, ClassString, x)
	case jsonvalue.Number:
		return scalar(TypeNumber, ClassScalar, NumberText(x))
	case bool:
		return scalar(TypeBoolean, ClassScalar, Text(x))
	case []jsonvalue.Value:
		return listRecord(x, elements)
	case *jsonvalue.Object:
		ck := Text(x)
		k := Fold(ck)
		sk := structureKey(x)
		return Record{State: StateValue, Class: ClassOther, Type: TypeObject, Key: &k, CaseKey: &ck,
			Keys: []string{k}, Structure: &sk}
	}
	panic("legacyvalue: not a Value")
}

func scalar(t Type, c Class, text string) Record {
	k := Fold(text)
	r := Record{State: StateValue, Class: c, Type: t, Key: &k, CaseKey: &text, Keys: []string{k}}
	if d, ok := jsonvalue.ParseBigDecimal(text); ok {
		r.Number = &d
	}
	return r
}

func listRecord(list []jsonvalue.Value, elements bool) Record {
	if len(list) == 0 {
		return Record{State: StateEmptyColl}
	}
	if elements {
		return listWithElements(list, AllParts)
	}
	ck := Text(list)
	k := Fold(ck)
	sk := structureKey(list)
	r := Record{State: StateValue, Class: ClassList, Type: TypeArray, Key: &k, CaseKey: &ck,
		Keys: []string{}, Structure: &sk}
	for _, e := range list {
		if !classify(&r, e) {
			r.Keys = append(r.Keys, Fold(Text(e)))
		}
	}
	return r
}

// listWithElements returns the record of a non-empty list with the parts p,
// e among them where p has PartElements. It builds
// the list's ck, k, and ks from the records of its elements, which hold the
// same texts, instead of reading the elements again, and its o as the key of
// a set. The element records
// come from of(e, false), which reads each element directly: joining at every
// level would copy each byte once per level of nesting.
func listWithElements(list []jsonvalue.Value, p Parts) Record {
	r := Record{State: StateValue, Class: ClassList, Type: TypeArray}
	if p&PartKeys != 0 {
		r.Keys = []string{}
	}
	if p&PartElements != 0 {
		r.Elements = make([]Record, len(list))
	}
	var ck, k strings.Builder
	ck.WriteByte('[')
	k.WriteByte('[')
	var elementKeys []string
	if p&PartStructure != 0 {
		elementKeys = make([]string, len(list))
	}
	for i, e := range list {
		null := classify(&r, e)
		if p&^PartStructure == 0 {
			// o alone reads the element, not its record
			if elementKeys != nil {
				elementKeys[i] = structureKey(e)
			}
			continue
		}
		er := of(e, false)
		if r.Elements != nil {
			r.Elements[i] = er
		}
		// A null element and an empty list have a record without ck or o.
		var text, ek string
		if er.Key != nil {
			text, ek = *er.CaseKey, *er.Key
		} else {
			text = Text(e)
			ek = Fold(text)
		}
		if p&PartKey != 0 {
			if i > 0 {
				ck.WriteString(", ")
				k.WriteString(", ")
			}
			ck.WriteString(text)
			k.WriteString(ek)
		}
		if elementKeys != nil {
			if er.Structure != nil {
				elementKeys[i] = *er.Structure
			} else {
				elementKeys[i] = structureKey(e)
			}
		}
		if !null && r.Keys != nil {
			r.Keys = append(r.Keys, ek)
		}
	}
	if p&PartKey != 0 {
		ck.WriteByte(']')
		k.WriteByte(']')
		cks, ks := ck.String(), k.String()
		r.CaseKey, r.Key = &cks, &ks
	}
	if elementKeys != nil {
		slices.Sort(elementKeys)
		elementKeys = slices.Compact(elementKeys)
		os := "[" + strings.Join(elementKeys, ",") + "]"
		r.Structure = &os
	}
	return r
}

// classify updates the state and the class of the list record r for its
// element e, and reports whether e is null, which has no key in ks.
func classify(r *Record, e jsonvalue.Value) bool {
	switch e.(type) {
	case nil:
		r.State = StateNullElement
		r.Class = ClassOther
		return true
	case string, jsonvalue.Number, bool:
	default:
		r.Class = ClassOther
	}
	return false
}

// Term returns the record as a Rego object with the keys s, t, j, k, ck, ks, o,
// n, nl, and e, leaving out every field the record does not set. A record
// with a Number carries exactly one of n and nl. n, a Rego number with the
// text of [jsonvalue.Decimal.String], is written for a
// [jsonvalue.Decimal.Short] number, which Rego's own operators compare
// exactly. Any other number is written as nl: true and no n, and generated
// code compares the record with nc.decimal.compare, which reads the number
// from ck. OPA's own comparison panics on an exponent of ten million or more
// and takes milliseconds well below that.
func (r Record) Term() *ast.Term {
	obj := ast.NewObjectWithCapacity(8)
	obj.Insert(keyTerms.s, constTerm(string(r.State)))
	if r.Class != "" {
		obj.Insert(keyTerms.t, constTerm(string(r.Class)))
		obj.Insert(keyTerms.j, constTerm(string(r.Type)))
	}
	var k *ast.Term
	if r.Key != nil {
		k = ast.StringTerm(*r.Key)
		ck := k
		if *r.CaseKey != *r.Key {
			ck = ast.StringTerm(*r.CaseKey)
		}
		obj.Insert(keyTerms.k, k)
		obj.Insert(keyTerms.ck, ck)
	}
	if r.Keys != nil {
		keys := make([]*ast.Term, len(r.Keys))
		for i, key := range r.Keys {
			if k != nil && key == *r.Key {
				keys[i] = k
			} else {
				keys[i] = ast.StringTerm(key)
			}
		}
		obj.Insert(keyTerms.ks, ast.ArrayTerm(keys...))
	}
	if r.Structure != nil {
		obj.Insert(keyTerms.o, ast.StringTerm(*r.Structure))
	}
	if r.Number != nil {
		if r.Number.Short() {
			obj.Insert(keyTerms.n, ast.NewTerm(ast.Number(r.Number.String())))
		} else {
			obj.Insert(keyTerms.nl, ast.InternedTerm(true))
		}
	}
	if r.Elements != nil {
		elems := make([]*ast.Term, len(r.Elements))
		for i, e := range r.Elements {
			elems[i] = e.Term()
		}
		obj.Insert(keyTerms.e, ast.ArrayTerm(elems...))
	}
	return ast.NewTerm(obj)
}

// keyTerms holds the keys of the object [Record.Term] writes. A query reads
// the terms and does not change them, so every record shares them.
var keyTerms = struct{ s, t, j, k, ck, ks, o, n, nl, e *ast.Term }{
	ast.StringTerm("s"), ast.StringTerm("t"), ast.StringTerm("j"), ast.StringTerm("k"), ast.StringTerm("ck"),
	ast.StringTerm("ks"), ast.StringTerm("o"), ast.StringTerm("n"), ast.StringTerm("nl"), ast.StringTerm("e"),
}

// constTerms holds a term for each state, class, and type.
var constTerms = func() map[string]*ast.Term {
	m := map[string]*ast.Term{}
	for _, v := range []string{
		string(StateValue), string(StateNullElement), string(StateAbsent), string(StateNull),
		string(StatePIPEmpty), string(StateEmptyColl), string(StateEmptySel), string(StateIndexOOB),
		string(StatePIPNull), string(StateError),
		string(ClassString), string(ClassScalar), string(ClassList), string(ClassOther),
		string(TypeString), string(TypeNumber), string(TypeBoolean), string(TypeArray), string(TypeObject),
	} {
		m[v] = ast.StringTerm(v)
	}
	return m
}()

// constTerm returns the term of a state, a class, or a type.
func constTerm(v string) *ast.Term {
	if t, ok := constTerms[v]; ok {
		return t
	}
	return ast.StringTerm(v)
}

// structureKey returns a text of v in which every object lists its members in
// key order, a string is quoted with its case, and a number is unquoted as its
// Number prints it, or as [NumberText] where it has none, so a number and a string
// of the same digits differ.
func structureKey(v jsonvalue.Value) string {
	var b strings.Builder
	writeStructureKey(&b, v)
	return b.String()
}

func writeStructureKey(b *strings.Builder, v jsonvalue.Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case jsonvalue.Number:
		if d, ok := jsonvalue.ParseBigDecimal(NumberText(x)); ok {
			b.WriteString(d.String())
		} else {
			b.WriteString(NumberText(x))
		}
	case string:
		writeQuoted(b, x)
	case []jsonvalue.Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeStructureKey(b, e)
		}
		b.WriteByte(']')
	case *jsonvalue.Object:
		keys := slices.Sorted(slices.Values(x.Keys()))
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeQuoted(b, k)
			b.WriteByte(':')
			e, _ := x.Get(k)
			writeStructureKey(b, e)
		}
		b.WriteByte('}')
	}
}

// writeQuoted writes s as strconv.Quote does. A string of printable ASCII
// without a quote or a backslash, which Quote only surrounds with quotes, is
// written without escaping it.
func writeQuoted(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' || c > '~' || c == '"' || c == '\\' {
			var buf [64]byte
			b.Write(strconv.AppendQuote(buf[:0], s))
			return
		}
	}
	b.WriteByte('"')
	b.WriteString(s)
	b.WriteByte('"')
}
