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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Value is a JSON value: nil for null, bool, [Number], string, []Value, or
// *[Object].
type Value any

// Number is a JSON number kept as the text of the document, so that 5 and 5.0
// stay different values. A number computed from a document, such as a sum,
// may also be Infinity, -Infinity, or NaN, as Java's Double.toString prints
// them.
type Number string

// Object is a JSON object that keeps its members in document order.
type Object struct {
	keys   []string
	values map[string]Value
}

// NewObject returns an empty object.
func NewObject() *Object {
	return &Object{values: map[string]Value{}}
}

// Set gives key the value v. A key the object already holds keeps its
// position and takes the new value, as a duplicate key does in a decoded
// document.
func (o *Object) Set(key string, v Value) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = v
}

// Get returns the value of key and whether the object holds key.
func (o *Object) Get(key string) (Value, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Keys returns the keys in document order. The caller must not modify the
// returned slice.
func (o *Object) Keys() []string {
	return o.keys
}

// Len returns the number of members.
func (o *Object) Len() int {
	return len(o.keys)
}

// MaxDepth is the deepest nesting of lists and objects that [Decode] accepts,
// the limit encoding/json sets on Unmarshal.
const MaxDepth = 10000

// Decode parses one JSON document. Numbers keep their text and object members
// keep their order; of two members with the same key, the later value wins at
// the position of the earlier one. A document nested deeper than [MaxDepth] is
// refused.
func Decode(data []byte) (Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jsonvalue: data after the JSON value")
	}
	return v, nil
}

// decodeValue decodes the value whose first token comes next, inside depth
// lists and objects.
func decodeValue(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth == MaxDepth {
			return nil, fmt.Errorf("jsonvalue: nested deeper than %d", MaxDepth)
		}
		switch t {
		case '[':
			list := []Value{}
			for dec.More() {
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return list, err
		case '{':
			obj := NewObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj.Set(kt.(string), v)
			}
			_, err := dec.Token()
			return obj, err
		}
		return nil, fmt.Errorf("jsonvalue: unexpected delimiter %v", t)
	case json.Number:
		return Number(t), nil
	default:
		// nil, bool, and string
		return t, nil
	}
}

// FromAST converts an OPA value. Object members come in OPA's order, sorted by
// key, not in the order of the document the value was parsed from. FromAST
// returns an error for a set, which JSON does not have.
func FromAST(v ast.Value) (Value, error) {
	return FromASTKnown(v, nil)
}

// FromASTKnown converts an OPA value as [FromAST] does, except that an object
// or a list for which known returns true, at any depth, converts to the value
// known returns. known may be nil.
func FromASTKnown(v ast.Value, known func(ast.Value) (Value, bool)) (Value, error) {
	if known != nil {
		switch v.(type) {
		case *ast.Array, ast.Object:
			if j, ok := known(v); ok {
				return j, nil
			}
		}
	}
	switch x := v.(type) {
	case ast.Null:
		return nil, nil
	case ast.Boolean:
		return bool(x), nil
	case ast.Number:
		return Number(x), nil
	case ast.String:
		return string(x), nil
	case *ast.Array:
		list := make([]Value, 0, x.Len())
		for i := range x.Len() {
			e, err := FromASTKnown(x.Elem(i).Value, known)
			if err != nil {
				return nil, err
			}
			list = append(list, e)
		}
		return list, nil
	case ast.Object:
		obj := NewObject()
		for _, k := range x.Keys() {
			ks, ok := k.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("jsonvalue: object key %v is not a string", k)
			}
			e, err := FromASTKnown(x.Get(k).Value, known)
			if err != nil {
				return nil, err
			}
			obj.Set(string(ks), e)
		}
		return obj, nil
	}
	return nil, fmt.Errorf("jsonvalue: %v is not a JSON value", v)
}
