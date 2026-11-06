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

package jsonvalue

import (
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// compact writes v as JSON without spaces, with every number as its text and
// object members in the order the Object holds them.
func compact(v Value) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case Number:
		return string(x)
	case string:
		return strconv.Quote(x)
	case []Value:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = compact(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *Object:
		parts := make([]string, x.Len())
		for i, k := range x.Keys() {
			m, _ := x.Get(k)
			parts[i] = strconv.Quote(k) + ":" + compact(m)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "<unknown>"
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"members keep document order", `{"z": 1, "a": {"y": 2, "b": {}}}`, `{"z":1,"a":{"y":2,"b":{}}}`},
		{"numbers keep their text", `[5, 5.0, 1.50, -0, 1e400, 1E+2]`, `[5,5.0,1.50,-0,1e400,1E+2]`},
		{"a duplicate key keeps the first position and the last value", `{"a": 1, "b": 2, "a": 3}`, `{"a":3,"b":2}`},
		{"scalars", `[null, true, false, "x"]`, `[null,true,false,"x"]`},
		{"an empty list", `[]`, `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := Decode([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Decode(%s): %v", tt.doc, err)
			}
			if got := compact(v); got != tt.want {
				t.Errorf("Decode(%s) = %s, want %s", tt.doc, got, tt.want)
			}
		})
	}
}

func TestDecode_RefusesInvalidDocuments(t *testing.T) {
	for _, doc := range []string{`1 2`, `{"a": 1`, `[1,]`, ``, `NaN`} {
		if v, err := Decode([]byte(doc)); err == nil {
			t.Errorf("Decode(%q) = %s, want an error", doc, compact(v))
		}
	}
}

// The limit is the decoder's own, so it holds on every toolchain: the
// json.Decoder.Token that Decode reads through has none before Go 1.27.
func TestDecode_RefusesNestingDeeperThanMaxDepth(t *testing.T) {
	doc := func(depth int) []byte {
		return []byte(`{"a": ` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`)
	}
	if _, err := Decode(doc(MaxDepth)); err != nil {
		t.Errorf("Decode of a document nested %d deep: %v", MaxDepth, err)
	}
	if _, err := Decode(doc(MaxDepth + 1)); err == nil {
		t.Errorf("Decode of a document nested %d deep: no error", MaxDepth+1)
	}
}

func TestFromAST_ObjectComesInSortedKeyOrder(t *testing.T) {
	v, err := FromAST(ast.MustParseTerm(`{"z": 1.50, "a": [null, "x", true]}`).Value)
	if err != nil {
		t.Fatalf("FromAST: %v", err)
	}
	if got, want := compact(v), `{"a":[null,"x",true],"z":1.50}`; got != want {
		t.Errorf("FromAST(...) = %s, want %s", got, want)
	}
}

func TestFromAST_RefusesAValueJSONDoesNotHave(t *testing.T) {
	for _, term := range []string{`{1, 2}`, `{1: "a"}`} {
		if v, err := FromAST(ast.MustParseTerm(term).Value); err == nil {
			t.Errorf("FromAST(%s) = %s, want an error", term, compact(v))
		}
	}
}
