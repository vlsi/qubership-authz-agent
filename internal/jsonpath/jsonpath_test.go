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

package jsonpath

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"authz-agent/internal/jsonvalue"
)

// doc is the document every case of TestSelect reads.
const doc = `{"a": {"b": [1, 2, 3], "c": null, "e": {}},
	"list": [{"k": "v", "n": 5}, {"k": "w", "n": 7.5, "t": [1, "x"]}, {"n": "5", "f": true}, {"k": "V", "n": 1e400}],
	"s": "héllo", "num": 5, "o": {"p": {"q": 1}, "r": 2},
	"user-id": "u1", "roles": ["r0", "r1"], "byNumber": {"1": "one"}}`

// text writes v as compact JSON with numbers as written, so that a case
// states the selected value as one literal.
func text(v jsonvalue.Value) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case jsonvalue.Number:
		return string(x)
	case string:
		return strconv.Quote(x)
	case []jsonvalue.Value:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = text(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *jsonvalue.Object:
		parts := make([]string, x.Len())
		for i, k := range x.Keys() {
			m, _ := x.Get(k)
			parts[i] = strconv.Quote(k) + ":" + text(m)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "<unknown>"
}

// selectCase is a path applied to a document and what it selects. want is the
// selected value for KindOne and KindMany, and empty for the other kinds.
type selectCase struct {
	name, doc, path string
	kind            Kind
	want            string
}

// sharedCases apply each path to doc.
var sharedCases = func() []selectCase {
	cases := []struct {
		name, path string
		kind       Kind
		want       string
	}{
		{"member", `.a.b`, KindOne, `[1,2,3]`},
		{"member of a missing root key", `.x.y`, KindMissing, ``},
		{"member of null", `.a.c.d`, KindNullParent, ``},
		{"member of an empty object", `.a.e.d`, KindNullParent, ``},
		{"member of a list", `.a.b.d`, KindMissing, ``},
		{"member of a scalar", `.num.x`, KindMissing, ``},
		{"bracket key after a step", `.a['b']`, KindOne, `[1,2,3]`},
		{"bracket key with a dot after a step", `.o['p.q']`, KindMissing, ``},
		{"bracket key first", `['a']`, KindBracket, ``},
		{"hyphenated key", `.user-id`, KindOne, `"u1"`},
		{"digits after a dot select an object member", `.byNumber.1`, KindOne, `"one"`},
		{"digits after a dot over a list are a missing member", `.roles.1`, KindMissing, ``},
		{"index", `.a.b[0]`, KindOne, `1`},
		{"negative index", `.a.b[-1]`, KindOne, `3`},
		{"index past the end", `.a.b[3]`, KindIndexOutOfBounds, ``},
		{"negative index past the start", `.a.b[-4]`, KindIndexOutOfBounds, ``},
		{"index of an object", `.a[0]`, KindMissing, ``},
		{"index in Arabic-Indic digits", `.a.b[٢]`, KindOne, `3`},
		{"index list", `.a.b[0,2]`, KindMany, `[1,3]`},
		{"index list with an index out of range", `.a.b[0, 5]`, KindMany, `[1]`},
		{"slice", `.a.b[1:]`, KindMany, `[2,3]`},
		{"slice with negative bounds", `.a.b[-2:-1]`, KindMany, `[2]`},
		{"slice past the end", `.a.b[1:10]`, KindMany, `[2,3]`},
		{"empty slice", `.a.b[2:1]`, KindMany, `[]`},
		{"slice of an object", `.a[0:1]`, KindMissing, ``},
		{"index list of null", `.a.c[0,1]`, KindMissing, ``},
		{"star over a list", `.a.b[*]`, KindMany, `[1,2,3]`},
		{"star over an object", `.o[*]`, KindMany, `[{"q":1},2]`},
		{"star over a scalar", `.num[*]`, KindMany, `[]`},
		{"star after star over objects", `.o[*][*]`, KindMany, `[1]`},
		{"star after star over lists", `.list[*][*]`, KindMany, `["v",5,"w",7.5,[1,"x"],"5",true,"V",1e400]`},
		{"deep scan", `..k`, KindMany, `["v","w","V"]`},
		{"deep scan over nested objects", `..q`, KindMany, `[1]`},
		{"deep scan of a hyphenated key", `..user-id`, KindMany, `["u1"]`},
		{"deep scan of a missing key", `..zz`, KindMany, `[]`},
		{"index after many", `.list[*].t[1]`, KindMany, `["x"]`},
		{"index after many skips a scalar", `.list[*].n[0]`, KindMany, `[]`},
		{"member after many skips the elements without it", `.list[*].k`, KindMany, `["v","w","V"]`},
		{"filter equal to a string", `.list[?(@.k == 'v')].n`, KindMany, `[5]`},
		{"filter equal is case-sensitive", `.list[?(@.k == 'V')].n`, KindMany, `[1e400]`},
		{"filter not equal selects an element without the key", `.list[?(@.k != 'v')].n`, KindMany, `[7.5,"5",1e400]`},
		{"filter number equals a string as a decimal", `.list[?(@.n == '5.0')].n`, KindMany, `[5]`},
		{"filter string equals a number as written", `.list[?(@.n == 5)].n`, KindMany, `[5,"5"]`},
		{"filter string does not equal a number written otherwise", `.list[?(@.n == 5.0)].n`, KindMany, `[5]`},
		{"filter greater than", `.list[?(@.n > 6)].n`, KindMany, `[7.5,1e400]`},
		{"filter less than or equal", `.list[?(@.n <= 7.5)].n`, KindMany, `[5,7.5]`},
		{"filter negative number literal", `.list[?(@.n > -1)].k`, KindMany, `["v","w","V"]`},
		{"filter number beyond double compares as a decimal", `.list[?(@.n > 10)].k`, KindMany, `["V"]`},
		{"filter beyond double equals the same number written out", `.list[?(@.n == 1` + strings.Repeat("0", 400) + `)].k`, KindMany, `["V"]`},
		{"filter boolean", `.list[?(@.f == true)].n`, KindMany, `["5"]`},
		{"filter boolean against a string", `.list[?(@.f != 'true')].n`, KindMany, `[5,7.5,"5",1e400]`},
		{"filter number ordered against a string", `.list[?(@.n < '9')].k`, KindMany, `[]`},
		{"filter string ordering", `.list[?(@.k < 'w')].k`, KindMany, `["v","V"]`},
		{"filter existence", `.list[?(@.t)].k`, KindMany, `["w"]`},
		{"filter in", `.list[?(@.k in ['v', 'x'])].n`, KindMany, `[5]`},
		{"filter in matches a number by its text", `.list[?(@.n in ['5', '7.5'])].k`, KindMany, `["v","w"]`},
		{"filter nin selects an element without the key", `.list[?(@.k nin ['v'])].n`, KindMany, `[7.5,"5",1e400]`},
		{"filter subsetof", `.list[?(@.t subsetof ['1', 'x'])].k`, KindMany, `["w"]`},
		{"filter anyof", `.list[?(@.t anyof ['x'])].k`, KindMany, `["w"]`},
		{"filter noneof", `.list[?(@.t noneof ['y'])].k`, KindMany, `["w"]`},
		{"filter size of a string", `.list[?(@.k size 1)].n`, KindMany, `[5,7.5,1e400]`},
		{"filter size of a list", `.list[?(@.t size 2)].k`, KindMany, `["w"]`},
		{"filter size of a number", `.list[?(@.n size 1)].k`, KindMany, `[]`},
		{"filter empty false", `.list[?(@.k empty false)].n`, KindMany, `[5,7.5,1e400]`},
		{"filter regex", `.list[?(@.k =~ /v|w/)].n`, KindMany, `[5,7.5]`},
		{"filter regex ignoring case", `.list[?(@.k =~ /v/i)].n`, KindMany, `[5,1e400]`},
		{"filter regex over a number", `.list[?(@.n =~ /7\..*/)].k`, KindMany, `["w"]`},
		{"filter and", `.list[?(@.k == 'v' && @.n == 5)].n`, KindMany, `[5]`},
		{"filter or", `.list[?(@.k == 'w' || @.f == true)].n`, KindMany, `[7.5,"5"]`},
		{"filter or binds looser than and", `.list[?(@.k == 'w' || @.k == 'v' && @.n == 7.5)].k`, KindMany, `["w"]`},
		{"filter nested", `.list[?(@.t[?(@ == 'x')])].k`, KindMany, `["w"]`},
		{"filter over one object tests the object", `.o[?(@.r == 2)].r`, KindMany, `[2]`},
		{"filter over one object that fails", `.o[?(@.r == 3)]`, KindMany, `[]`},
		{"filter on the element itself", `.a.b[?(@ >= 2)]`, KindMany, `[2,3]`},
		{"filter over a single number selects nothing, as Jayway refuses it", `.num[?(@ == 5)]`, KindMissing, ``},
		{"length of a list", `.a.b.length()`, KindOne, `3`},
		{"length of an object", `.o.length()`, KindOne, `2`},
		{"length of a number is null", `.num.length()`, KindOne, `null`},
		{"length of null is null", `.a.c.length()`, KindOne, `null`},
		{"length of a boolean is null", `.list[2].f.length()`, KindOne, `null`},
		{"length after many is the length of each value", `.a.b[*].length()`, KindMany, `[null,null,null]`},
		{"length of a missing member", `.x.length()`, KindMissing, ``},
		{"min", `.a.b.min()`, KindOne, `1.0`},
		{"max", `.a.b.max()`, KindOne, `3.0`},
		{"sum", `.a.b.sum()`, KindOne, `6.0`},
		{"avg", `.a.b.avg()`, KindOne, `2.0`},
		{"sum of a list with no number", `.list.sum()`, KindMissing, ``},
		{"sum of an object", `.o.sum()`, KindMissing, ``},
		{"first", `.a.b.first()`, KindOne, `1`},
		{"last", `.a.b.last()`, KindOne, `3`},
		{"first of an object", `.o.first()`, KindMissing, ``},
		{"keys of an object", `.o.keys()`, KindOne, `"[p, r]"`},
		{"keys of a list is null", `.a.b.keys()`, KindOne, `null`},
		{"keys of a string is null", `.s.keys()`, KindOne, `null`},
		{"min after many", `.list[*].n.min()`, KindMissing, ``},
	}
	out := make([]selectCase, len(cases))
	for i, c := range cases {
		out[i] = selectCase{name: c.name, doc: doc, path: c.path, kind: c.kind, want: c.want}
	}
	return out
}()

// ownDocumentCases each state their own document.
var ownDocumentCases = []selectCase{
	{"a key of the empty document is missing", `{}`, `.x`, KindMissing, ``},
	{"a key of the null document is missing", `null`, `.x`, KindMissing, ``},
	{"a key of an empty member is a null parent", `{"a": {}}`, `.a.x`, KindNullParent, ``},
	{"a duplicate key keeps its first position", `{"a": 1, "b": 2, "a": 3}`, `[*]`, KindMany, `[3,2]`},
	{"star over the document", `[{"id": 1}, {"id": 2}]`, `[*].id`, KindMany, `[1,2]`},
	{"index of the document", `[{"id": 1}, {"id": 2}]`, `[1].id`, KindOne, `2`},
	{"filter over the document", `[{"id": 1}, {"id": 2}]`, `[?(@.id > 1)].id`, KindMany, `[2]`},
	{"filter after a star tests each object the star selected", `[{"k": "a"}, {"k": "b"}]`, `[*][?(@.k == 'a')]`, KindMany, `[{"k":"a"}]`},
	{"regex dot does not match a carriage return", `{"a": [{"k": "a\rb"}]}`, `.a[?(@.k =~ /a.b/)].k`, KindMany, `[]`},
	{"filter with a hyphenated key", `{"a": [{"x-y": 1}, {"x-y": 2}]}`, `.a[?(@.x-y == 2)]`, KindMany, `[{"x-y":2}]`},
	{"empty true", `{"a": [{"k": ""}, {"k": "x"}]}`, `.a[?(@.k empty true)].k`, KindMany, `[""]`},
	{"in over an element without the key", `{"a": [{"j": 1}]}`, `.a[?(@.k in ['v'])].j`, KindMany, `[]`},
	{"in compares a number with a quoted item by value", `{"a": [{"k": 5.0}]}`, `.a[?(@.k in ['5'])].k`, KindMany, `[5.0]`},
	{"subsetof of an empty list holds", `{"a": [{"k": []}]}`, `.a[?(@.k subsetof ['x'])].k`, KindMany, `[[]]`},
	{"filter equal to null is false", `{"a": [{"k": null}]}`, `.a[?(@.k == 'null')].k`, KindMany, `[]`},
	{"filter not equal to a list", `{"a": [{"k": [1]}]}`, `.a[?(@.k != 1)].k`, KindMany, `[[1]]`},
	{"regex over a boolean matches its text", `{"a": [{"k": true}]}`, `.a[?(@.k =~ /tr.e/)].k`, KindMany, `[true]`},
	{"regex must match the whole text", `{"a": [{"k": "vw"}, {"k": "v"}]}`, `.a[?(@.k =~ /v/)].k`, KindMany, `["v"]`},
	{"regex does not match a missing member", `{"a": [{"j": 1}, {"k": ""}]}`, `.a[?(@.k =~ /x?/)]`, KindMany, `[{"k":""}]`},
	{"regex does not match null", `{"a": [{"k": null}]}`, `.a[?(@.k =~ /x?/)]`, KindMany, `[]`},
	{"regex over null does not match", `{"a": [{"k": null}]}`, `.a[?(@.k =~ /null/)].k`, KindMany, `[]`},
	{"regex end of text escape", `{"a": [{"k": "ab"}]}`, `.a[?(@.k =~ /ab\Z/)].k`, KindMany, `["ab"]`},
	{"regex hex escape", `{"a": [{"k": "A"}]}`, `.a[?(@.k =~ /\x41/)].k`, KindMany, `["A"]`},
	{"nested filter over an object member the inner filter rejects", `{"a": [{"t": {"u": 1}}]}`, `.a[?(@.t[?(@.u == 2)])]`, KindMany, `[]`},
	{"min of mixed elements skips the non-numbers", `{"a": ["x", 3, null, 2.5]}`, `.a.min()`, KindOne, `2.5`},
	{"max of an integer prints as a double", `{"a": [10000000]}`, `.a.max()`, KindOne, `1.0E7`},
	{"min of zeros", `{"a": [0, -0.0]}`, `.a.min()`, KindOne, `0.0`},
	{"min of minus zero has no sign", `{"a": [-0.0]}`, `.a.min()`, KindOne, `0.0`},
	{"min of an integer minus zero has no sign", `{"a": [-0]}`, `.a.min()`, KindOne, `0.0`},
	{"sum over the double range is infinite", `{"a": [1e400, 1]}`, `.a.sum()`, KindOne, `Infinity`},
	{"avg of an empty list is missing", `{"a": []}`, `.a.avg()`, KindMissing, ``},
	{"first of an empty list is missing", `{"a": []}`, `.a.first()`, KindMissing, ``},
	{"last of null element", `{"a": [1, null]}`, `.a.last()`, KindOne, `null`},
	{"deep scan lists a member before the members inside it", `{"a": {"k": {"k": 1}}}`, `..k`, KindMany, `[{"k":1},1]`},
	{"key with punctuation", `{"a:b$~@!&|": 1}`, `.a:b$~@!&|`, KindOne, `1`},
	{"key with a star after its first character", `{"v*": 1}`, `.v*`, KindOne, `1`},
	{"filter does not order booleans", `{"a": [{"f": true}, {"f": false}]}`, `.a[?(@.f > false)].f`, KindMany, `[]`},
	{"slice with an open start", `{"a": [1, 2, 3]}`, `.a[:2]`, KindMany, `[1,2]`},
	{"keys of a list of objects", `{"a": [{"k": 1}]}`, `.a.keys()`, KindOne, `null`},
	{"keys keep document order", `{"o": {"z": 1, "a": 2}}`, `.o.keys()`, KindOne, `"[z, a]"`},
}

// checkSelect runs each case as a subtest.
func checkSelect(t *testing.T, cases []selectCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root, err := jsonvalue.Decode([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Decode(%s): %v", tt.doc, err)
			}
			p, err := Compile(tt.path)
			if err != nil {
				t.Fatalf("Compile(%s): %v", tt.path, err)
			}
			r := p.Select(root)
			got := ""
			if r.Kind == KindOne || r.Kind == KindMany {
				got = text(r.Value)
			}
			if r.Kind != tt.kind || got != tt.want {
				t.Errorf("Select(%s) = %s %s, want %s %s", tt.path, r.Kind, got, tt.kind, tt.want)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	checkSelect(t, sharedCases)
}

func TestSelect_OwnDocument(t *testing.T) {
	checkSelect(t, ownDocumentCases)
}

// jaywayCases follow Jayway JsonPath where its answer does not depend on how
// the legacy service hands it the document. Each expected value is what
// Jayway 2.9.0 and 2.10.0 answered; where Jayway throws, the path selects
// nothing.
var jaywayCases = []selectCase{
	{"dot before a star", `[{"id": 1}, {"id": 2}]`, `.[*].id`, KindMany, `[1,2]`},
	{"dot before a star after a key", `{"a": [{"id": 1}]}`, `.a.[*].id`, KindMany, `[1]`},
	{"dot before a bracket key", `{"a": {"k": 1}}`, `.a.['k']`, KindOne, `1`},
	{"dot before a bracket key first", `{"k": 1}`, `.['k']`, KindOne, `1`},
	{"dot before an index", `{"a": [7]}`, `.a.[0]`, KindOne, `7`},
	{"dot before a filter", `{"a": [{"k": 1}]}`, `.a.[?(@.k == 1)]`, KindMany, `[{"k":1}]`},
	{"equal to null selects only null", `{"a": [{"g": null, "n": 1}, {"h": 1, "n": 2}, {"g": [], "n": 3}]}`, `.a[?(@.g == null)].n`, KindMany, `[1]`},
	{"not equal to null selects a missing member", `{"a": [{"g": null, "n": 1}, {"n": 2}, {"g": 0, "n": 3}]}`, `.a[?(@.g != null)].n`, KindMany, `[2,3]`},
	{"null orders nothing", `{"a": [{"g": 1}]}`, `.a[?(@.g < null)]`, KindMany, `[]`},
	{"a string equals a number literal as BigDecimal prints it", `{"a": [{"k": "10"}, {"k": "010"}, {"k": 10}]}`, `.a[?(@.k == 010)]`, KindMany, `[{"k":"10"},{"k":10}]`},
	{"a string equals a number literal with its scale", `{"a": [{"k": "5"}, {"k": "5.0"}]}`, `.a[?(@.k == 5.0)]`, KindMany, `[{"k":"5.0"}]`},
	{"a string equals minus zero as 0", `{"a": [{"k": "0"}, {"k": "-0"}]}`, `.a[?(@.k == -0)]`, KindMany, `[{"k":"0"}]`},
	{"a number is in a list by value", `{"a": [{"k": 5}]}`, `.a[?(@.k in ['5.0'])].k`, KindMany, `[5]`},
	{"subsetof compares numbers by value", `{"a": [{"k": [5.0, 1]}]}`, `.a[?(@.k subsetof ['5', '1'])]`, KindMany, `[{"k":[5.0,1]}]`},
	{"nin selects a null member", `{"a": [{"k": null}]}`, `.a[?(@.k nin ['x'])]`, KindMany, `[{"k":null}]`},
	{"in rejects a list member", `{"a": [{"k": ["x"]}]}`, `.a[?(@.k in ['x'])]`, KindMany, `[]`},
	{"regex matches a number as BigDecimal prints it", `{"a": [{"k": 1e7}]}`, `.a[?(@.k =~ /1E\+7/)]`, KindMany, `[{"k":1e7}]`},
	{"regex matches a small number in scientific notation", `{"a": [{"k": 0.0000001}]}`, `.a[?(@.k =~ /1E-7/)]`, KindMany, `[{"k":0.0000001}]`},
	{"regex matches a number with its scale", `{"a": [{"k": 5.0}]}`, `.a[?(@.k =~ /5\.0/)]`, KindMany, `[{"k":5.0}]`},
	{"regex matches a list where one element matches", `{"a": [{"k": ["x", "ab"]}]}`, `.a[?(@.k =~ /a.*/)]`, KindMany, `[{"k":["x","ab"]}]`},
	{"regex does not match an object", `{"a": [{"k": {"x": 1}}]}`, `.a[?(@.k =~ /.*/)]`, KindMany, `[]`},
	{"regex dot does not match a line separator", `{"a": [{"k": "a b"}]}`, `.a[?(@.k =~ /a.b/)]`, KindMany, `[]`},
	{"regex vertical whitespace matches a form feed", `{"a": [{"k": "\f"}]}`, `.a[?(@.k =~ /\v/)]`, KindMany, `[{"k":"\f"}]`},
	{"regex end anchor before closing parentheses", `{"a": [{"k": "ab"}]}`, `.a[?(@.k =~ /(a(b$))/)]`, KindMany, `[{"k":"ab"}]`},
	{"regex named group", `{"a": [{"k": "ab"}]}`, `.a[?(@.k =~ /(?<x>a)b/)]`, KindMany, `[{"k":"ab"}]`},
	{"regex repetition", `{"a": [{"k": "aa"}, {"k": "a"}]}`, `.a[?(@.k =~ /a{2,}/)].k`, KindMany, `["aa"]`},
	{"regex negated digit inside brackets", `{"a": [{"k": "x"}, {"k": "1"}]}`, `.a[?(@.k =~ /[\D]/)].k`, KindMany, `["x"]`},
	{"star after a filter gives the members of each object", `{"a": [{"k": "a", "v": 1}, {"k": "b", "v": 2}]}`, `.a[?(@.k == 'a')][*]`, KindMany, `["a",1]`},
	{"star after a deep scan gives the members of each object", `{"o": {"x": {"p": 1, "q": 2}}}`, `..x[*]`, KindMany, `[1,2]`},
	{"star after an index list gives the members of each object", `{"a": [{"p": 1}, {"q": 2}]}`, `.a[0,1][*]`, KindMany, `[1,2]`},
	{"filter after a star skips a number", `{"a": [{"k": "a"}, 5, [{"k": "a", "in": 1}]]}`, `.a[*][?(@.k == 'a')]`, KindMany, `[{"k":"a"},{"k":"a","in":1}]`},
	{"deep scan gives a member before the members inside its siblings", `{"o": {"a": {"k": 1}, "k": 2}}`, `..k`, KindMany, `[2,1]`},
	{"nested filter selects a member the inner filter selects something in", `{"a": [{"id": 1, "t": [{"p": 1}]}, {"id": 2, "t": []}, {"id": 3, "t": "s"}, {"id": 4}, {"id": 5, "t": {"p": 1}}, {"id": 6, "t": [{"p": 20}]}]}`, `.a[?(@.t[?(@.p > 10)])].id`, KindMany, `[6]`},
	{"nested filter tests an object member itself", `{"a": [{"id": 1, "t": {"p": 1}}, {"id": 2, "t": {"p": 20}}]}`, `.a[?(@.t[?(@.p > 10)])].id`, KindMany, `[2]`},
	{"size of a string counts UTF-16 code units", `{"a": [{"k": "😀"}]}`, `.a[?(@.k size 2)]`, KindMany, `[{"k":"😀"}]`},
	{"size of an object is not tested", `{"a": [{"k": {"x": 1, "y": 2}}]}`, `.a[?(@.k size 2)]`, KindMany, `[]`},
	{"empty over an object tests its members", `{"a": [{"k": {}}, {"k": []}, {"k": {"x": 1}}]}`, `.a[?(@.k empty true)]`, KindMany, `[{"k":{}},{"k":[]}]`},
	{"slice from before the start", `{"a": [1, 2, 3]}`, `.a[-10:]`, KindMany, `[1,2,3]`},
	{"slice to a negative end", `{"a": [1, 2, 3]}`, `.a[:-1]`, KindMany, `[1,2]`},
	{"slice from a negative start to a positive end", `{"a": [1, 2, 3, 4, 5]}`, `.a[-4:1]`, KindMany, `[]`},
	{"slice to a negative end counts it from the end", `{"a": [1, 2, 3]}`, `.a[1:-1]`, KindMany, `[2]`},
	{"slice from a negative start counts it from the end", `{"a": [1, 2, 3]}`, `.a[-2:3]`, KindMany, `[2,3]`},
	{"last after a star drops an empty list element", `{"l": [[], [1]]}`, `.l[*].last()`, KindMany, `[1]`},
	{"slice from before the start to a positive end", `{"a": [1, 2, 3]}`, `.a[-10:2]`, KindMany, `[1,2]`},
	{"slice from a positive start to a negative end", `{"a": [1, 2, 3, 4, 5]}`, `.a[3:-2]`, KindMany, `[]`},
	{"index list skips an index past the end", `{"a": [1, 2, 3]}`, `.a[-1,5,0]`, KindMany, `[3,1]`},
	{"keys of a number is null", `{"n": 5}`, `.n.keys()`, KindOne, `null`},
	{"first of a string selects nothing, as Jayway throws", `{"a": "xy"}`, `.a.first()`, KindMissing, ``},
	{"min of strings selects nothing, as Jayway throws", `{"a": ["1", "2"]}`, `.a.min()`, KindMissing, ``},
	{"min after a star over lists", `{"l": [[1, 2], [3]]}`, `.l[*].min()`, KindMany, `[1.0,3.0]`},
	{"sum after a star over lists", `{"l": [[1, 2], [3]]}`, `.l[*].sum()`, KindMany, `[3.0,3.0]`},
	{"first after a star over lists", `{"l": [[1, 2], [3]]}`, `.l[*].first()`, KindMany, `[1,3]`},
	{"length after a star over lists", `{"l": [[1, 2], [3]]}`, `.l[*].length()`, KindMany, `[2,1]`},
	{"keys after a star over objects", `{"l": [{"x": 1}]}`, `.l[*].keys()`, KindMany, `["[x]"]`},
	{"first after a star drops an empty list element", `{"l": [[], [1]]}`, `.l[*].first()`, KindMany, `[1]`},
	{"first after a key under a list element drops an empty list", `{"l": [{"x": []}]}`, `.l[*].x.first()`, KindMany, `[]`},
	{"first after a star drops an empty object member", `{"o": {"x": [], "y": [1]}}`, `.o[*].first()`, KindMany, `[1]`},
	{"min after a star over scalars selects nothing, as Jayway throws", `{"l": [1, 2]}`, `.l[*].min()`, KindMissing, ``},
	{"last of one element", `{"a": [5]}`, `.a.last()`, KindOne, `5`},
	{"last of an empty list selects nothing, as Jayway throws", `{"a": []}`, `.a.last()`, KindMissing, ``},
	{"last after a star with a one-element list", `{"l": [[1], [2, 3]]}`, `.l[*].last()`, KindMany, `[1,3]`},
	{"regex over a list skips an object element", `{"a": [{"k": ["zz", {"x": 1}]}]}`, `.a[?(@.k =~ /z+/)]`, KindMany, `[{"k":["zz",{"x":1}]}]`},
	{"subsetof over a list holding an object is false", `{"a": [{"k": [{"x": 1}]}]}`, `.a[?(@.k subsetof ['x'])]`, KindMany, `[]`},
	{"strings order by UTF-16 code units", `{"a": [{"k": "😀"}]}`, `.a[?(@.k < '～')].k`, KindMany, `["😀"]`},
	{"several spaces around an operator", `{"a": [{"k": "x"}]}`, `.a[?(@.k  ==  'x')].k`, KindMany, `["x"]`},
	{"regex range with escaped endpoints", `{"a": [{"k": "Q"}]}`, `.a[?(@.k =~ /[\x41-\x5a]/)].k`, KindMany, `["Q"]`},
	{"regex range across non-letters with the flag i", `{"a": [{"k": "z"}, {"k": "A"}, {"k": "b"}]}`, `.a[?(@.k =~ /[Z-a]/i)].k`, KindMany, `["z","A"]`},
	{"regex negated class with the flag i", `{"a": [{"k": "A"}, {"k": "b"}]}`, `.a[?(@.k =~ /[^a]/i)].k`, KindMany, `["b"]`},
	{"regex dot does not match a next-line character", `{"a": [{"k": "a\u0085b"}]}`, `.a[?(@.k =~ /a.b/)]`, KindMany, `[]`},
	{"a bracket key is unescaped", `{"x": {"a\nb": 1, "a\\nb": 2}}`, `.x['a\nb']`, KindOne, `1`},
	{"a bracket key reads a unicode escape", `{"x": {"A": 1}}`, `.x['\u0041']`, KindOne, `1`},
	{"a quoted literal is unescaped", `{"a": [{"r": "a\nb"}, {"r": "a\\nb"}]}`, `.a[?(@.r == 'a\nb')].r`, KindMany, `["a\nb"]`},
	{"a quoted literal reads a unicode escape", `{"a": [{"r": "A"}]}`, `.a[?(@.r == '\u0041')].r`, KindMany, `["A"]`},
	{"a quoted literal keeps an escaped backslash as one", `{"a": [{"r": "a\\b"}]}`, `.a[?(@.r == 'a\\b')].r`, KindMany, `["a\\b"]`},
	{"a quoted literal with a digit outside the Basic Multilingual Plane is no number", `{"a": [{"n": 1}]}`, `.a[?(@.n == '𝟙')]`, KindMany, `[]`},
	{"a list item that looks like a path is text", `{"a": [{"r": "$"}, {"r": "@"}]}`, `.a[?(@.r in ['$', '@'])].r`, KindMany, `["$","@"]`},
	{"a list item that looks like JSON is text", `{"a": [{"r": "{}"}]}`, `.a[?(@.r in ['{}'])].r`, KindMany, `["{}"]`},
	{"a list item is unescaped once", `{"a": [{"r": "a\\nb"}, {"r": "a\nb"}]}`, `.a[?(@.r in ['a\\nb'])].r`, KindMany, `["a\\nb"]`},
	{"a list item keeps double quotes", `{"a": [{"r": "x"}]}`, `.a[?(@.r in ['"x"'])].r`, KindMany, `[]`},
	{"max of negative numbers", `{"a": [-1, -2]}`, `.a.max()`, KindOne, `-1.0`},
	{"max of zero", `{"a": [0]}`, `.a.max()`, KindOne, `0.0`},
	{"max of a negative infinity", `{"a": [-1e400, -1]}`, `.a.max()`, KindOne, `-1.0`},
	{"min of an infinity", `{"a": [1e400]}`, `.a.min()`, KindOne, `Infinity`},
	{"a deep scan over a null document selects nothing, as Jayway refuses it", `null`, `..k`, KindMissing, ``},
	{"keys of a null document selects nothing, as Jayway refuses it", `null`, `.keys()`, KindMissing, ``},
	{"star over a null document selects nothing, as Jayway refuses it", `null`, `[*]`, KindMissing, ``},
	{"length of a null document selects nothing, as Jayway refuses it", `null`, `.length()`, KindMissing, ``},
	{"regex reads a list element that looks like a path as text", `{"a": [{"k": ["$"]}]}`, `.a[?(@.k =~ /\$/)]`, KindMany, `[{"k":["$"]}]`},
	{"regex reads a list element that looks like a longer path as text", `{"a": [{"k": ["$.x"]}]}`, `.a[?(@.k =~ /.*x/)]`, KindMany, `[{"k":["$.x"]}]`},
	{"regex reads a list element that looks like JSON as text", `{"a": [{"k": ["[1]"]}]}`, `.a[?(@.k =~ /\[1\]/)]`, KindMany, `[{"k":["[1]"]}]`},
	{"regex reads a list element that only starts like a filter path as text", `{"a": [{"k": ["@x"]}]}`, `.a[?(@.k =~ /@x/)]`, KindMany, `[{"k":["@x"]}]`},
	{"regex reads a list element that ends in a dot as text", `{"a": [{"k": ["$."]}]}`, `.a[?(@.k =~ /\$\./)]`, KindMany, `[{"k":["$."]}]`},
	{"regex reads a list element as written", `{"a": [{"k": ["a\\nb"]}]}`, `.a[?(@.k =~ /a\nb/)]`, KindMany, `[]`},
	{"anyof reads a list element with its quotes", `{"a": [{"k": ["'x'"]}]}`, `.a[?(@.k anyof ['x'])]`, KindMany, `[]`},
	{"anyof compares a list element that looks like a path as text", `{"a": [{"k": ["$"]}]}`, `.a[?(@.k anyof ['$'])]`, KindMany, `[{"k":["$"]}]`},
	{"regex vertical whitespace that starts a range is one char", `{"a": [{"k": "-"}, {"k": "\n"}, {"k": "\u000b"}, {"k": "\f"}]}`, `.a[?(@.k =~ /[\v-\r]/)].k`, KindMany, `["\v","\f"]`},
	{"regex vertical whitespace that ends a range is one char", `{"a": [{"k": "\u0001"}, {"k": "\n"}, {"k": "\u000b"}, {"k": "\f"}]}`, `.a[?(@.k =~ /[\x01-\v]/)].k`, KindMany, `["\x01","\n","\v"]`},
	{"regex escaped slash inside brackets", `{"a": [{"k": "/"}]}`, `.a[?(@.k =~ /[\/]/)].k`, KindMany, `["/"]`},
	{"regex vertical whitespace before a closing dash is one char", `{"a": [{"k": "-"}, {"k": "\n"}, {"k": "\u000b"}]}`, `.a[?(@.k =~ /[\v-]/)].k`, KindMany, `["-","\v"]`},
	{"filter over a single null selects nothing, as Jayway refuses it", `{"a": null}`, `.a[?(@ == 5)]`, KindMissing, ``},
}

func TestSelect_FollowsJayway(t *testing.T) {
	checkSelect(t, jaywayCases)
}

// lengthOfStringCases take .length() of a string, which Jayway counts only for
// a list and an object.
var lengthOfStringCases = []selectCase{
	{"length of a string is null", `{"s": "héllo"}`, `.s.length()`, KindOne, `null`},
	{"length of an empty string is null", `{"s": ""}`, `.s.length()`, KindOne, `null`},
}

func TestSelect_LengthOfAStringIsNull(t *testing.T) {
	checkSelect(t, lengthOfStringCases)
}

// intRangeCases take an index at the edge of Java's int range, beyond which
// Jayway does not compile the path (TestSelect_APathJaywayDoesNotCompileSelectsNothing).
var intRangeCases = []selectCase{
	{"the largest int index is past the end", `{"a": [1]}`, `.a[2147483647]`, KindIndexOutOfBounds, ``},
	{"the smallest int index is before the start", `{"a": [1]}`, `.a[-2147483648]`, KindIndexOutOfBounds, ``},
}

func TestSelect_AnIndexInTheIntRangeCompiles(t *testing.T) {
	checkSelect(t, intRangeCases)
}

// A path Jayway does not compile, which the legacy service reads as an
// absent attribute, compiles and selects nothing on any document, even one
// where the same path with a valid index or bound selects values: [:], an
// index or a bound beyond the int range, and a digit outside the Basic
// Multilingual Plane in an index, a bound, a number literal, or a size.
func TestSelect_APathJaywayDoesNotCompileSelectsNothing(t *testing.T) {
	const doc = `{"a": [{"n": 1, "k": [1]}, {"n": 2, "k": [1]}]}`
	root, err := jsonvalue.Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, control string }{
		{"a slice without bounds", `.a[:]`, `.a[0:]`},
		{"an index beyond the int range", `.a[2147483648]`, `.a[1]`},
		{"an index below the int range", `.a[-2147483649]`, `.a[-1]`},
		{"an index list beyond the int range", `.a[0,2147483648]`, `.a[0,1]`},
		{"a slice bound beyond the int range", `.a[0:2147483648]`, `.a[0:2]`},
		{"an index with a digit outside the Basic Multilingual Plane", `.a[𝟙]`, `.a[1]`},
		{"a slice with a digit outside the Basic Multilingual Plane", `.a[𝟙:]`, `.a[1:]`},
		{"an index list with a digit outside the Basic Multilingual Plane", `.a[0,𝟙]`, `.a[0,1]`},
		{"a number literal with a digit outside the Basic Multilingual Plane", `.a[?(@.n == 𝟙)]`, `.a[?(@.n == 1)]`},
		{"a size with a digit outside the Basic Multilingual Plane", `.a[?(@.k size 𝟙)]`, `.a[?(@.k size 1)]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct {
				path    string
				missing bool
			}{{tc.path, true}, {tc.control, false}} {
				p, err := Compile(c.path)
				if err != nil {
					t.Fatalf("Compile(%s): %v", c.path, err)
				}
				if got := p.Select(root).Kind; (got == KindMissing) != c.missing {
					t.Errorf("Select(%s) over %s kind = %s, want missing: %v", c.path, doc, got, c.missing)
				}
			}
		})
	}
}

// asciiClassCases match \d, \w, and \s, which java.util.regex reads as ASCII
// classes, and its \s holds \x0B, which Go's does not.
var asciiClassCases = []selectCase{
	{"regex digit class matches an ASCII digit", `{"a": [{"k": "12"}]}`, `.a[?(@.k =~ /\d+/)].k`, KindMany, `["12"]`},
	{"regex digit class does not match an Arabic-Indic digit", `{"a": [{"k": "١٢"}]}`, `.a[?(@.k =~ /\d+/)].k`, KindMany, `[]`},
	{"regex word class does not match sharp s", `{"a": [{"k": "Straße"}]}`, `.a[?(@.k =~ /\w+/)].k`, KindMany, `[]`},
	{"regex word class inside brackets does not match e acute", `{"a": [{"k": "é-1"}]}`, `.a[?(@.k =~ /[\w-]+/)].k`, KindMany, `[]`},
	{"regex space class does not match a no-break space", `{"a": [{"k": "a b"}]}`, `.a[?(@.k =~ /a\sb/)].k`, KindMany, `[]`},
	{"regex space class matches a vertical tab", `{"a": [{"k": "a\u000bb"}]}`, `.a[?(@.k =~ /a\sb/)].k`, KindMany, `["a\vb"]`},
	{"regex negated space class", `{"a": [{"k": "a "}, {"k": "ab"}]}`, `.a[?(@.k =~ /\S+/)].k`, KindMany, `["ab"]`},
}

func TestSelect_RegexClassesAreASCII(t *testing.T) {
	checkSelect(t, asciiClassCases)
}

// asciiFoldCases match a pattern with the flag i, which java.util.regex reads
// as CASE_INSENSITIVE: ASCII letters fold, and no other letter does.
var asciiFoldCases = []selectCase{
	{"flag i folds an ASCII letter", `{"a": [{"k": "ABC"}]}`, `.a[?(@.k =~ /abc/i)].k`, KindMany, `["ABC"]`},
	{"flag i folds a range", `{"a": [{"k": "Q"}]}`, `.a[?(@.k =~ /[a-z]/i)].k`, KindMany, `["Q"]`},
	{"flag i does not fold e acute", `{"a": [{"k": "ÉCOLE"}]}`, `.a[?(@.k =~ /école/i)].k`, KindMany, `[]`},
	{"flag i does not fold the Kelvin sign", `{"a": [{"k": "K"}]}`, `.a[?(@.k =~ /k/i)].k`, KindMany, `[]`},
}

func TestSelect_RegexFlagIFoldsASCIIOnly(t *testing.T) {
	checkSelect(t, asciiFoldCases)
}

// exactNumberCases compare a document number with a number literal as exact
// decimals, a number beyond the double range included. Jayway does so where
// the document holds the number as a BigDecimal.
var exactNumberCases = []selectCase{
	{"beyond double greater", `{"a": [{"n": 1e400}]}`, `.a[?(@.n > 10)].n`, KindMany, `[1e400]`},
	{"beyond double negative", `{"a": [{"n": -1e400}]}`, `.a[?(@.n < -10)].n`, KindMany, `[-1e400]`},
	{"beyond double equal written out", `{"a": [{"n": 1e400}]}`, `.a[?(@.n == 1` + strings.Repeat("0", 400) + `)].n`, KindMany, `[1e400]`},
	{"seventeen digits", `{"a": [{"n": 0.30000000000000001}]}`, `.a[?(@.n > 0.3)].n`, KindMany, `[0.30000000000000001]`},
}

func TestSelect_FilterComparesNumbersExactly(t *testing.T) {
	checkSelect(t, exactNumberCases)
}

// sumCases add doubles from first to last, as Java does, so 0.1 + 0.2 + 0.3 is
// 0.6000000000000001; a compensated sum would give 0.6.
var sumCases = []selectCase{
	{"sum of fractions", `{"a": [0.1, 0.2, 0.3]}`, `.a.sum()`, KindOne, `0.6000000000000001`},
	{"avg of fractions", `{"a": [0.1, 0.2, 0.3]}`, `.a.avg()`, KindOne, `0.20000000000000004`},
}

func TestSelect_SumAndAvgAddFromFirstToLast(t *testing.T) {
	checkSelect(t, sumCases)
}

func TestCompile_RefusesAPathOutsideTheSubset(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"no leading step", `a.b`},
		{"wildcard member", `.a.*`},
		{"deep wildcard", `..*`},
		{"deep scan before a bracket", `..[*]`},
		{"bare word in brackets", `.a[abc]`},
		{"key list", `.a['b','c']`},
		{"space inside brackets", `.a[ 0 ]`},
		{"step after a function", `.a.length().b`},
		{"unknown function", `.a.size()`},
		{"slice with a step", `.a[0:2:1]`},
		{"unclosed filter", `.a[?(@.k)`},
		{"filter with no closing parenthesis and nothing inside", `.a[?(]`},
		{"filter with no closing parenthesis after a key", `.a[?(@.kk]`},
		{"filter with no closing parenthesis after a number", `.a[?(@.a == 10]`},
		{"unknown operator", `.a[?(@.k ~= 'v')]`},
		{"dangling or", `.a[?(@.k == 'v' ||)]`},
		{"double-quoted literal", `.a[?(@.k == "v")]`},
		{"exponent literal", `.a[?(@.k == 1e5)]`},
		{"root path in a filter", `.a[?(@.k == $.x)]`},
		{"negation in a filter", `.a[?(!@.k)]`},
		{"parentheses in a filter", `.a[?((@.k == 'v'))]`},
		{"and inside a nested filter", `.a[?(@.b[?(@.c == 1 && @.d == 2)])]`},
		{"or inside a quoted literal", `.a[?(@.k == 'a||b')]`},
		{"regex flag other than i", `.a[?(@.k =~ /x/m)]`},
		{"regex inline flag", `.a[?(@.k =~ /(?i)x/)]`},
		{"regex lookahead", `.a[?(@.k =~ /(?=x)/)]`},
		{"regex backreference", `.a[?(@.k =~ /(a)\1/)]`},
		{"regex possessive repetition", `.a[?(@.k =~ /a*+/)]`},
		{"regex word boundary", `.a[?(@.k =~ /\bx/)]`},
		{"regex non-boundary", `.a[?(@.k =~ /\Bx/)]`},
		{"regex Unicode property", `.a[?(@.k =~ /\p{L}/)]`},
		{"regex quoted text", `.a[?(@.k =~ /\Qx\E/)]`},
		{"regex escaped letter Java does not know", `.a[?(@.k =~ /\y/)]`},
		{"regex brace outside a repetition", `.a[?(@.k =~ /a{/)]`},
		{"regex repetition with no minimum", `.a[?(@.k =~ /a{,2}/)]`},
		{"regex end anchor before more pattern", `.a[?(@.k =~ /a$b/)]`},
		{"regex end of text before more pattern", `.a[?(@.k =~ /a\Zb/)]`},
		{"regex closing bracket first in brackets", `.a[?(@.k =~ /[]a]/)]`},
		{"regex negated space class inside brackets", `.a[?(@.k =~ /[\S]/)]`},
		{"regex hex escape with the flag i", `.a[?(@.k =~ /\x41/i)]`},
		{"regex reversed range", `.a[?(@.k =~ /[z-a]/)]`},
		{"regex unbalanced parentheses", `.a[?(@.k =~ /admin)|(b/)]`},
		{"regex unescaped slash", `.a[?(@.k =~ /a/b/)]`},
		{"regex unescaped slash inside brackets", `.a[?(@.k =~ /[/]/)]`},
		{"regex group name that starts with a digit", `.a[?(@.k =~ /(?<1a>x)/)]`},
		{"a function after a deep scan", `..k.min()`},
		{"a tab around an operator", ".a[?(@.k\t== 'x')]"},
		{"a tab at the start of a filter", ".a[?(\t@.k == 'x')]"},
		{"a no-break space around an operator", ".a[?(@.k\u00a0== 'x')]"},
		{"a quoted literal that ends in an escaped quote", `.a[?(@.k == 'x\')]`},
		{"a bracket key that ends in an escaped quote", `.x['k\']`},
		{"a quoted literal with an unreadable unicode escape", `.a[?(@.k == '\uZZZZ')]`},
		{"a quoted literal that unescapes to half a surrogate pair", `.a[?(@.k == '\uD800')]`},
		{"regex group name used twice", `.a[?(@.k =~ /(?<x>a)(?<x>b)/)]`},
		{"a list item with an unreadable unicode escape", `.a[?(@.k in ['\uZZZZ'])]`},
		{"a bracket key with an unreadable unicode escape", `.x['\uZZZZ']`},
		{"a bracket key that unescapes to half a surrogate pair", `.x['\uD800']`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile(tt.path); !errors.Is(err, ErrUnsupported) {
				t.Errorf("Compile(%s) error = %v, want ErrUnsupported", tt.path, err)
			}
		})
	}
}

// The filter splits at && before a pattern reaches javaPattern, so the
// intersection of two classes is checked on javaPattern itself.
func TestJavaPattern_RefusesAnIntersectionOfClasses(t *testing.T) {
	if got, err := javaPattern(`[a-c&&b]`, false); err == nil {
		t.Errorf("javaPattern([a-c&&b]) = %q, want an error", got)
	}
}

// namedGroups returns the groups (?<g0>x)(?<g1>x)... named g0 to g(n-1),
// followed by extra.
func namedGroups(n int, extra string) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "(?<g%d>x)", i)
	}
	return b.String() + extra
}

// A group name is refused where any earlier group of the pattern holds it,
// however many groups stand between the two.
func TestJavaPattern_GroupNames(t *testing.T) {
	t.Run("a thousand distinct names are accepted", func(t *testing.T) {
		pattern := namedGroups(1000, "")
		if got, err := javaPattern(pattern, false); err != nil || got != pattern {
			t.Errorf("javaPattern(namedGroups(1000, \"\")) = %.40q..., %v; want the pattern unchanged", got, err)
		}
	})
	t.Run("the first name used again after a thousand groups is refused", func(t *testing.T) {
		if got, err := javaPattern(namedGroups(1000, "(?<g0>y)"), false); err == nil {
			t.Errorf("javaPattern(namedGroups(1000, \"(?<g0>y)\")) = %.40q..., want an error", got)
		}
	})
}

// A path that starts with ['key'] never reaches Jayway, so a null document
// does not change its kind.
func TestSelect_LeadingBracketKeyOverANullDocument(t *testing.T) {
	checkSelect(t, []selectCase{{"bracket key first over null", `null`, `['a']`, KindBracket, ``}})
}

// nestedKeys returns {"key":{"key":...1...}} with depth objects.
func nestedKeys(depth int) string {
	return strings.Repeat(`{"key":`, depth) + "1" + strings.Repeat("}", depth)
}

// inLists returns inner wrapped in depth lists of one element.
func inLists(inner string, depth int) string {
	return strings.Repeat("[", depth) + inner + strings.Repeat("]", depth)
}

// joined returns n copies of item, separated by commas.
func joined(item string, n int) string {
	return strings.TrimSuffix(strings.Repeat(item+",", n), ",")
}

// binaryTree returns a tree of objects depth levels deep, each with an id and,
// above the last level, a list of two children.
func binaryTree(depth int) string {
	if depth == 1 {
		return `{"id":"leaf"}`
	}
	child := binaryTree(depth - 1)
	return `{"id":"node","children":[` + child + "," + child + "]}"
}

// twice12 is a path of twelve [0,0] steps, which selects the innermost value
// of inLists(v, 12) 4096 times.
var twice12 = strings.Repeat("[0,0]", 12)

// A path whose work outgrows its document stops with KindTooLarge, whether a
// step visits nested parts of the document or repeats the values an earlier
// step selected. A selection as large as the document, made of parts that do
// not overlap, is still selected. ..key over objects nested 9000 deep used to
// select every subtree, and writing the selection's record took tens of
// seconds.
func TestSelect_StopsAPathWhoseWorkOutgrowsTheDocument(t *testing.T) {
	numbers := "[" + joined("1", 10000) + "]"
	objects := `{"items":[` + joined(`{"a":1,"b":2,"c":3,"d":4,"name":"n"}`, 3000) + "]}"
	tests := []struct {
		name, doc, path string
		kind            Kind
		count           int
	}{
		{"..key over objects nested 30 deep", nestedKeys(30), "..key", KindMany, 30},
		{"..key over a list of 5000 objects", "[" + joined(`{"key":1}`, 5000) + "]", "..key", KindMany, 5000},
		{"four filters over 3000 objects", objects, ".items[?(@.a)][?(@.b)][?(@.c)][?(@.d)]", KindMany, 3000},
		{"sum() of a list selected once", inLists(numbers, 12), strings.Repeat("[0]", 12) + ".sum()", KindOne, 0},
		{"..children over a binary tree 7 levels deep", binaryTree(7), "..children", KindMany, 63},
		{"..children[*].id over a binary tree 12 levels deep", binaryTree(12), "..children[*].id", KindMany, 4094},
		{"..children over a binary tree 8 levels deep", binaryTree(8), "..children", KindTooLarge, 0},
		{"..key over objects nested 9000 deep", nestedKeys(9000), "..key", KindTooLarge, 0},
		{"..key..key..key over objects nested 200 deep", nestedKeys(200), "..key..key..key", KindTooLarge, 0},
		{"..key..absent over objects nested 3000 deep", nestedKeys(3000), "..key..absent", KindTooLarge, 0},
		{"[0,0] forty times over lists nested 40 deep", inLists("1", 40), strings.Repeat("[0,0]", 40), KindTooLarge, 0},
		{"a filter over a long member selected 4096 times", inLists(`{"s":"`+strings.Repeat("x", 10000)+`"}`, 12),
			twice12 + "[?(@.s =~ /y/)]", KindTooLarge, 0},
		{"sum() of a list selected 4096 times", inLists(numbers, 12), twice12 + ".sum()", KindTooLarge, 0},
		{"sum() of a long number selected 4096 times", inLists("["+strings.Repeat("1", 100000)+"]", 12),
			twice12 + ".sum()", KindTooLarge, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := jsonvalue.Decode([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			p, err := Compile(tt.path)
			if err != nil {
				t.Fatalf("Compile(%s): %v", tt.path, err)
			}
			r := p.Select(root)
			count := 0
			if list, ok := r.Value.([]jsonvalue.Value); ok {
				count = len(list)
			}
			if r.Kind != tt.kind || count != tt.count {
				t.Errorf("Select(%.40s) = %s of %d values, want %s of %d", tt.path, r.Kind, count, tt.kind, tt.count)
			}
		})
	}
}

// [*] and a slice stop before they copy the members of a value that an
// earlier step selected 4096 times, not after.
func TestSelect_StopsBeforeCopyingARepeatedValue(t *testing.T) {
	tests := []struct {
		name, leaf, last string
	}{
		{"[*] over a list", "[" + joined("1", 10000) + "]", "[*]"},
		{"a slice of a list", "[" + joined("1", 10000) + "]", "[0:]"},
		{"[*] over an object", "{" + memberList(10000) + "}", "[*]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := jsonvalue.Decode([]byte(inLists(tt.leaf, 12)))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			p, err := Compile(twice12 + tt.last)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			r := p.Select(root)
			runtime.ReadMemStats(&after)
			const maxAlloc = 64 << 20
			if alloc := after.TotalAlloc - before.TotalAlloc; r.Kind != KindTooLarge || alloc > maxAlloc {
				t.Errorf("Select of twelve [0,0] then %s = %s after allocating %d bytes, want %s within %d bytes",
					tt.last, r.Kind, alloc, KindTooLarge, maxAlloc)
			}
		})
	}
}

// memberList returns the members "m0":1 to "m<n-1>":1 of an object.
func memberList(n int) string {
	members := make([]string, n)
	for i := range members {
		members[i] = `"m` + strconv.Itoa(i) + `":1`
	}
	return strings.Join(members, ",")
}

// weight stops reading a value once its size exceeds the limit.
func TestWeight_StopsAtTheLimit(t *testing.T) {
	for _, doc := range []string{nestedKeys(9000), inLists("1", 9000)} {
		root, err := jsonvalue.Decode([]byte(doc))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if got := weight(root, 10); got <= 10 || got > 100 {
			t.Errorf("weight(%.20s..., 10) = %d, want above 10 and at most 100", doc, got)
		}
	}
}

// A size beyond the int range compiles, as Jayway compiles it, and no value
// has that size, so the filter selects nothing; a size in range is the
// control.
func TestSelect_ASizeBeyondTheIntRangeMatchesNothing(t *testing.T) {
	checkSelect(t, []selectCase{
		{"a size beyond the int range", `{"a": [{"k": [1]}]}`, `.a[?(@.k size 2147483648)]`, KindMany, `[]`},
		{"a size in the int range", `{"a": [{"k": [1]}]}`, `.a[?(@.k size 1)]`, KindMany, `[{"k":[1]}]`},
	})
}

// Jayway compiles a filter pattern that Go cannot match as java.util.regex
// does, so a later part of the path that Jayway does not compile still makes
// the path select nothing, in a later step or in a later part of the filter.
// Any other form outside the subset leaves it before a later part is read.
func TestCompile_AGoOnlyPatternDoesNotHideAFormJaywayDoesNotCompile(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		missing    bool
	}{
		{"a pattern with a lookahead alone", `.a[?(@.k =~ /(?=u)/)]`, false},
		{"a pattern with a lookahead before [:]", `.a[?(@.k =~ /(?=u)/)][:]`, true},
		{"a pattern with a lookahead before a number with a digit outside the BMP",
			`.a[?(@.k =~ /(?=u)/ && @.n == 𝟙)]`, true},
		{"a bare word in brackets before [:]", `.a[abc][:]`, false},
		{"an unknown operator before a number with a digit outside the BMP", `.a[?(@.k ~= 'v' && @.n == 𝟙)]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Compile(tc.path)
			if !tc.missing {
				if !errors.Is(err, ErrUnsupported) {
					t.Errorf("Compile(%s) error = %v, want ErrUnsupported", tc.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile(%s): %v", tc.path, err)
			}
			if got := p.Select(nil).Kind; got != KindMissing || !p.refused {
				t.Errorf("Compile(%s) refused = %v, Select kind %s; want a path that selects nothing", tc.path,
					p.refused, got)
			}
		})
	}
}
