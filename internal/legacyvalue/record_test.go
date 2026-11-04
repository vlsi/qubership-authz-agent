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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
)

func mustDecode(t *testing.T, doc string) jsonvalue.Value {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(doc))
	if err != nil {
		t.Fatalf("Decode(%s): %v", doc, err)
	}
	return v
}

// The keys and the number of a scalar come from its Java text. == compares the
// folded text; <, and == where one side is a number, compare the number
// BigDecimal reads from that text.
func TestOf_ScalarCarriesTheTextsEachOperatorComparesBy(t *testing.T) {
	type want struct {
		class   Class
		typ     Type
		key     string
		caseKey string
		number  string // Decimal.String, or "" for none
		long    bool
	}
	tests := []struct {
		name string
		doc  string
		want want
	}{
		{"a string folds to lower case", `"ABC"`, want{ClassString, TypeString, "abc", "ABC", "", false}},
		{"a string whose scale BigDecimal refuses is no number", `"1.1e-2147483647"`, want{ClassString, TypeString, "1.1e-2147483647", "1.1e-2147483647", "", false}},
		{"a string at the largest scale BigDecimal accepts is a number", `"1e-2147483647"`, want{ClassString, TypeString, "1e-2147483647", "1e-2147483647", "1e-2147483647", true}},
		{"sharp s has no one-character upper case and stays", `"Straße"`, want{ClassString, TypeString, "straße", "Straße", "", false}},
		{"dotted capital I folds to i", `"İ"`, want{ClassString, TypeString, "i", "İ", "", false}},
		{"long s folds through its upper case to s", `"ſ"`, want{ClassString, TypeString, "s", "ſ", "", false}},
		{"final sigma folds through its upper case to sigma", `"ς"`, want{ClassString, TypeString, "σ", "ς", "", false}},
		{"a letter outside the BMP folds as one code point", `"𐐀"`, want{ClassString, TypeString, "𐐨", "𐐀", "", false}},
		{"a string of digits reads as a number", `"5"`, want{ClassString, TypeString, "5", "5", "5", false}},
		{"a string with a plus sign reads as a number", `"+5"`, want{ClassString, TypeString, "+5", "+5", "5", false}},
		{"a string with no integer digits reads as a number", `".5"`, want{ClassString, TypeString, ".5", ".5", "0.5", false}},
		{"a string with a trailing point reads as a number", `"5."`, want{ClassString, TypeString, "5.", "5.", "5", false}},
		{"a string of Arabic-Indic digits reads as a number", `"٣"`, want{ClassString, TypeString, "٣", "٣", "3", false}},
		{"a string beyond the double range keeps its exact value", `"1e400"`, want{ClassString, TypeString, "1e400", "1e400", "1e400", true}},
		{"a string with a leading space is not a number", `" 5"`, want{ClassString, TypeString, " 5", " 5", "", false}},
		{"a string with an underscore is not a number", `"5_0"`, want{ClassString, TypeString, "5_0", "5_0", "", false}},
		{"the string NaN is not a number", `"NaN"`, want{ClassString, TypeString, "nan", "NaN", "", false}},
		{"the string Infinity is not a number", `"Infinity"`, want{ClassString, TypeString, "infinity", "Infinity", "", false}},
		{"an integer prints as its digits", `5`, want{ClassScalar, TypeNumber, "5", "5", "5", false}},
		{"minus zero integer prints as 0", `-0`, want{ClassScalar, TypeNumber, "0", "0", "0", false}},
		{"a fraction prints as Double.toString", `5.0`, want{ClassScalar, TypeNumber, "5.0", "5.0", "5", false}},
		{"minus zero fraction keeps its sign in the text only", `-0.0`, want{ClassScalar, TypeNumber, "-0.0", "-0.0", "0", false}},
		{"an exponent prints as a fraction", `1e2`, want{ClassScalar, TypeNumber, "100.0", "100.0", "100", false}},
		{"a small magnitude prints with an exponent", `1.5e-4`, want{ClassScalar, TypeNumber, "1.5e-4", "1.5E-4", "0.00015", false}},
		{"ten million prints with an exponent", `1e7`, want{ClassScalar, TypeNumber, "1.0e7", "1.0E7", "10000000", false}},
		{"just under ten million prints plain", `9999999.0`, want{ClassScalar, TypeNumber, "9999999.0", "9999999.0", "9999999", false}},
		{"an underflow reads as the zero of its Double", `1e-400`, want{ClassScalar, TypeNumber, "0.0", "0.0", "0", false}},
		{"a negative underflow prints as minus zero and reads as zero", `-1e-400`, want{ClassScalar, TypeNumber, "-0.0", "-0.0", "0", false}},
		{"an overflow prints as Infinity and has no number", `1e400`, want{ClassScalar, TypeNumber, "infinity", "Infinity", "", false}},
		{"a long integer keeps every digit", `123456789012345678901234567890`, want{ClassScalar, TypeNumber, "123456789012345678901234567890", "123456789012345678901234567890", "1.2345678901234567890123456789e29", true}},
		{"a long fraction reads as the nearest double", `12345678901234567.5`, want{ClassScalar, TypeNumber, "1.2345678901234568e16", "1.2345678901234568E16", "12345678901234568", true}},
		{"digits beyond a double read as the double", `0.300000000000000010`, want{ClassScalar, TypeNumber, "0.3", "0.3", "0.3", false}},
		{"true has a key and no number", `true`, want{ClassScalar, TypeBoolean, "true", "true", "", false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Of(mustDecode(t, tt.doc))
			var got want
			got.class, got.typ = r.Class, r.Type
			if r.Key != nil {
				got.key, got.caseKey = *r.Key, *r.CaseKey
			}
			if r.Number != nil {
				got.number, got.long = r.Number.String(), !r.Number.Short()
			}
			if r.State != StateValue {
				t.Errorf("Of(%s).State = %s, want VALUE", tt.doc, r.State)
			}
			if got != tt.want {
				t.Errorf("Of(%s) = %+v, want %+v", tt.doc, got, tt.want)
			}
			if !reflect.DeepEqual(r.Keys, []string{got.key}) {
				t.Errorf("Of(%s).Keys = %q, want [%q]", tt.doc, r.Keys, got.key)
			}
		})
	}
}

func TestOf_StateOfAValueWithoutAKey(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want State
	}{
		{"null", `null`, StateNull},
		{"an empty list", `[]`, StateEmptyColl},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Of(mustDecode(t, tt.doc))
			if !reflect.DeepEqual(got, Record{State: tt.want}) {
				t.Errorf("Of(%s) = %+v, want a record of state %s alone", tt.doc, got, tt.want)
			}
		})
	}
}

// A structure has the key of its Java text, which a string equals it by, and a
// list also has the keys of its elements that are not null.
func TestOf_StructureCarriesItsJavaTextAndTheKeysOfItsElements(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		state   State
		class   Class
		caseKey string
		keys    []string
	}{
		{"a list of scalars", `[1, "A", true]`, StateValue, ClassList, "[1, A, true]", []string{"1", "a", "true"}},
		{"a list that holds null", `[null, "A"]`, StateNullElement, ClassOther, "[null, A]", []string{"a"}},
		{"a list that holds a list", `[[1], "x"]`, StateValue, ClassOther, "[[1], x]", []string{"[1]", "x"}},
		{"a list that holds an empty object", `[{}]`, StateValue, ClassOther, "[{}]", []string{"{}"}},
		{"a list that holds an empty list", `[[], "x"]`, StateValue, ClassOther, "[[], x]", []string{"[]", "x"}},
		{"an object in document order", `{"b": 1, "A": [2, "X"]}`, StateValue, ClassOther, "{b=1, A=[2, X]}", []string{"{b=1, a=[2, x]}"}},
		{"an empty object", `{}`, StateValue, ClassOther, "{}", []string{"{}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Of(mustDecode(t, tt.doc))
			if r.State != tt.state || r.Class != tt.class {
				t.Errorf("Of(%s) state, class = %s, %s, want %s, %s", tt.doc, r.State, r.Class, tt.state, tt.class)
			}
			if r.CaseKey == nil {
				t.Fatalf("Of(%s) has no case key, want %q", tt.doc, tt.caseKey)
			}
			if *r.CaseKey != tt.caseKey || *r.Key != Fold(tt.caseKey) {
				t.Errorf("Of(%s) keys = %q, %q, want %q and its fold", tt.doc, *r.Key, *r.CaseKey, tt.caseKey)
			}
			if !reflect.DeepEqual(r.Keys, tt.keys) {
				t.Errorf("Of(%s).Keys = %q, want %q", tt.doc, r.Keys, tt.keys)
			}
			if r.Number != nil {
				t.Errorf("Of(%s) has the number %s, want none", tt.doc, r.Number)
			}
		})
	}
}

func TestOf_ListCarriesARecordPerElementIncludingNull(t *testing.T) {
	r := Of(mustDecode(t, `[null, "a", []]`))
	var got []State
	for _, e := range r.Elements {
		got = append(got, e.State)
	}
	want := []State{StateNull, StateValue, StateEmptyColl}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("states of the element records = %v, want %v", got, want)
	}
}

func TestRecord_TermWritesTheShortKeys(t *testing.T) {
	tests := []struct {
		name string
		rec  Record
		want string
	}{
		{"a long number", Of(jsonvalue.Number("12345678901234567.5")),
			`{"s": "VALUE", "t": "n", "j": "number", "k": "1.2345678901234568e16", "ck": "1.2345678901234568E16", "ks": ["1.2345678901234568e16"], "nl": true}`},
		{"a short number", Of(jsonvalue.Number("12.50")),
			`{"s": "VALUE", "t": "n", "j": "number", "k": "12.5", "ck": "12.5", "ks": ["12.5"], "n": 12.5}`},
		{"a list that holds null", Of([]jsonvalue.Value{nil, true}),
			`{"s": "NULL_ELEMENT", "t": "x", "j": "array", "k": "[null, true]", "ck": "[null, true]", "ks": ["true"], "o": "[null,true]", "e": [{"s": "NULL"}, {"s": "VALUE", "t": "n", "j": "boolean", "k": "true", "ck": "true", "ks": ["true"]}]}`},
		{"a special state", WithState(StateIndexOOB), `{"s": "INDEX_OOB"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := ast.MustParseTerm(tt.want)
			if got := tt.rec.Term(); !got.Equal(want) {
				t.Errorf("Term() = %v, want %v", got, want)
			}
		})
	}
}

// Two lists or two objects with the same Java text, such as {a=1} or [x],
// differ when an element or a member differs in type or case. Two lists agree
// whatever the order and the repeats of their elements, as two sets do, while
// a list inside an element or a member keeps its order. Two objects agree
// whatever the order of their members, and two numbers agree when their
// values do, as ADR-0083 decides.
func TestOf_StructureKeyKeepsTypesAndCase(t *testing.T) {
	structure := func(doc string) string {
		t.Helper()
		r := Of(mustDecode(t, doc))
		if r.Structure == nil {
			t.Fatalf("Of(%s) has no structure key", doc)
		}
		return *r.Structure
	}
	distinct := []string{
		`{"a": 1}`, `{"a": "1"}`, `{"a": 2}`, `{"a": true}`, `{"a": "true"}`,
		`{"a": 1e400}`, `{"a": -1e400}`, `{"a": "Infinity"}`,
		`{"a": "x"}`, `{"a": "X"}`, `{"A": "x"}`, `{"a": [1]}`, `{"a": {"b": 1}}`, `{"a": {"b": "1"}}`,
		`{"a": [1, 2]}`, `{"a": [2, 1]}`,
		`[1]`, `["1"]`, `[1, "1"]`, `["x"]`, `["X"]`, `[1, 2]`, `[[1]]`, `[[1, 2]]`, `[[2, 1]]`, `[null]`, `["null"]`,
	}
	seen := map[string]string{}
	for _, doc := range distinct {
		k := structure(doc)
		if other, ok := seen[k]; ok {
			t.Errorf("Of(%s) and Of(%s) share the structure key %q", doc, other, k)
		}
		seen[k] = doc
	}
	same := [][2]string{
		{`{"b": 1, "a": {"d": 2, "c": 3}}`, `{"a": {"c": 3, "d": 2}, "b": 1}`},
		{`{"a": 1}`, `{"a": 1.0}`},
		{`{"a": 1.0}`, `{"a": 1.00}`},
		{`{"a": 100}`, `{"a": 1e2}`},
		{`{"a": 0.0}`, `{"a": -0.0}`},
		{`{"a": 0.1}`, `{"a": 0.10000000000000000001}`},
		{`{"a": [1]}`, `{"a": [1.0]}`},
		{`{"a": 1e400}`, `{"a": 1e500}`},
		{`[1]`, `[1.0]`},
		{`[1, 2]`, `[2, 1]`},
		{`[1, 2]`, `[2, 1, 2]`},
		{`[1]`, `[1, 1.0]`},
		{`[[1, 2], [3]]`, `[[3], [1, 2]]`},
		{`[null, null, 1]`, `[1, null]`},
		{`[[1, {"b": 2}]]`, `[[1.0, {"b": 2e0}]]`},
	}
	for _, p := range same {
		if a, b := structure(p[0]), structure(p[1]); a != b {
			t.Errorf("structure keys of %s and %s = %q, %q, want them equal", p[0], p[1], a, b)
		}
	}
}

func TestOf_StructureKeyIsSetForListsAndObjects(t *testing.T) {
	r := Of(mustDecode(t, `[{"a": 1}, "x", [2]]`))
	want := []string{`["x",[2],{"a":1}]`, `{"a":1}`, "", "[2]"}
	got := []string{structureOf(r)}
	for _, e := range r.Elements {
		got = append(got, structureOf(e))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("structure keys of the list and its elements = %q, want %q", got, want)
	}
}

func structureOf(r Record) string {
	if r.Structure == nil {
		return ""
	}
	return *r.Structure
}

// A list nested in an element is read through the o and the ks of the element
// record, which has no e of its own.
func TestOf_ElementRecordsHaveNoElements(t *testing.T) {
	r := Of(mustDecode(t, `[[1, [2]], "x"]`))
	nested := r.Elements[0]
	if nested.Elements != nil {
		t.Errorf("the record of the element [1, [2]] has the elements %+v, want none", nested.Elements)
	}
	if got, want := structureOf(nested), "[1,[2]]"; got != want {
		t.Errorf("structure key of the element [1, [2]] = %q, want %q", got, want)
	}
	if want := []string{"1", "[2]"}; !reflect.DeepEqual(nested.Keys, want) {
		t.Errorf("keys of the element [1, [2]] = %q, want %q", nested.Keys, want)
	}
}

// Each list used to carry the text of every list nested in it, so a list
// nested 1000 deep held about 1000 copies of its text, and building its record
// took 0.1 s for a 15 KB document.
func TestOf_RecordsOfADeepListHoldItsTextAFewTimes(t *testing.T) {
	const depth = 1000
	doc := strings.Repeat(`["abc",`, depth) + "1" + strings.Repeat("]", depth)
	held := textHeld(Of(mustDecode(t, doc)))
	if limit := 10 * len(doc); held > limit {
		t.Errorf("records of a list nested %d deep hold %d bytes of text, want at most %d, ten times the %d-byte document", depth, held, limit, len(doc))
	}
}

// textHeld returns the bytes of text r and the records of its elements hold.
func textHeld(r Record) int {
	n := 0
	for _, s := range []*string{r.Key, r.CaseKey, r.Structure} {
		if s != nil {
			n += len(*s)
		}
	}
	for _, k := range r.Keys {
		n += len(k)
	}
	for _, e := range r.Elements {
		n += textHeld(e)
	}
	return n
}

// A list's record with e builds ck, k, and ks from the records of its
// elements; they equal the texts the record without e reads from the list
// itself, for each kind of element whose record lacks one of them. The two
// records differ in o alone: the list that Of reads has the key of a set.
func TestOf_ListTextsFromElementRecordsMatchTheList(t *testing.T) {
	tests := []struct{ doc, set string }{
		{`[null, 1]`, `[1,null]`},
		{`[[], "a"]`, `["a",[]]`},
		{`[[1, [2, null]], {"B": [], "a": "Ä"}]`, `[[1,[2,null]],{"B":[],"a":"Ä"}]`},
		{`["Straße", "İ", "ABC", "x\"y"]`, `["ABC","Straße","x\"y","İ"]`},
		{`[1.50, 1e400, -0, true]`, `[0,1.5,Infinity,true]`},
	}
	for _, tt := range tests {
		v := mustDecode(t, tt.doc)
		got, want := Of(v), of(v, false)
		if o := structureOf(got); o != tt.set {
			t.Errorf("structure key of Of(%s) = %q, want %q", tt.doc, o, tt.set)
		}
		got.Elements, got.Structure, want.Structure = nil, nil, nil
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Of(%s) without e and o = %s, want %s", tt.doc, recordText(got), recordText(want))
		}
	}
}

// recordText returns the fields of r that hold text, for a failure message.
func recordText(r Record) string {
	deref := func(s *string) string {
		if s == nil {
			return "<nil>"
		}
		return *s
	}
	n := "<nil>"
	if r.Number != nil {
		n = r.Number.String()
	}
	return fmt.Sprintf("{s: %s, t: %s, j: %s, k: %q, ck: %q, ks: %q, o: %q, n: %s}",
		r.State, r.Class, r.Type, deref(r.Key), deref(r.CaseKey), r.Keys, deref(r.Structure), n)
}

// writeQuoted writes what strconv.Quote returns, on both sides of the plain
// ASCII it writes without escaping: the edges of printable ASCII, a quote, a
// backslash, a control character, DEL, and a letter beyond ASCII.
func TestWriteQuotedQuotesAsStrconv(t *testing.T) {
	for _, s := range []string{"", "plain", " ", "~", "a\"b", `c\d`, "x\x01", "tab\t", "\x7f", "é", "a\xffb"} {
		var b strings.Builder
		writeQuoted(&b, s)
		if got, want := b.String(), strconv.Quote(s); got != want {
			t.Errorf("writeQuoted(%q) = %s, want %s", s, got, want)
		}
	}
}

// The record OfParts builds with some of the parts of a list is the record of
// Of with the other parts left out, null elements, nested lists, and objects
// included.
func TestOfPartsLeavesOutTheOtherParts(t *testing.T) {
	docs := []string{`["Straße", "x\"y", 1.50, true]`, `[null, "a", [2, null], {"B": []}]`, `[1, 1, "1"]`, `[]`,
		`"a"`, `{"a": [1]}`}
	for _, doc := range docs {
		v := mustDecode(t, doc)
		whole := Of(v)
		for p := Parts(0); p <= AllParts; p++ {
			want := whole
			if _, ok := v.([]jsonvalue.Value); ok {
				if p&PartKey == 0 {
					want.Key, want.CaseKey = nil, nil
				}
				if p&PartKeys == 0 {
					want.Keys = nil
				}
				if p&PartStructure == 0 {
					want.Structure = nil
				}
				if p&PartElements == 0 {
					want.Elements = nil
				}
			}
			if got := OfParts(v, p); !reflect.DeepEqual(got, want) {
				t.Errorf("OfParts(%s, %04b) = %s, want %s", doc, p, recordText(got), recordText(want))
			}
		}
	}
}
