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

// Package regobuiltins provides the built-in functions that Rego generated
// from legacy policies calls where Rego cannot reproduce Java:
//
//   - nc.value(v) returns the value record of v, the object
//     [legacyvalue.Record.Term] describes. Generated code calls it for a
//     value that comes from a PIP response; Go builds the records of the
//     input before the query.
//   - nc.decimal.compare(a, b) returns -1, 0, or 1 as a is less than, equal
//     to, or greater than b, exactly. a and b are each a number literal or a
//     value record that has n or nl. Generated code calls it where a record
//     has nl, which it has instead of n for a number Rego cannot compare. An
//     object of the request with the keys n and ck has the shape of such a
//     record, so generated code passes only a record that nc.value,
//     nc.jsonpath, or Go built, never a raw value of the request.
//   - nc.jsonpath(doc, path) applies a path of the subset [jsonpath] accepts,
//     without the leading $, and returns {"sel": kind, "rec": record}, where
//     kind is a [jsonpath.Kind] and rec is present for three kinds: for one
//     and many it is the record of the selected value or of the list of
//     selected values, and for toolarge a record in state ERROR.
//
// Nothing is registered globally. A compiler takes [Capabilities], a query
// takes [Options], and an OPA test runner takes the same functions through the
// regotest subpackage.
//
// nc.value and nc.jsonpath read an object or a list that [Documents.Term]
// built as the JSON it was built from, also where Rego passes it inside a
// value of its own. They see any other object in OPA's order, sorted by key,
// so the Java text of an object with two or more members, [*] over an object,
// ..key, and keys() follow that order rather than the document's.
//
// A number has the Java type its text gives it: 1 is an Integer, and 1.0 and
// 1e2 are Doubles. OPA keeps the text of a number it reads from JSON or from a
// module, but writes a number it computes in its own form, so 1 + 0.0 reaches
// nc.value as the Integer 1.
//
// Each function returns an error for an argument of the wrong type, and
// nc.jsonpath for a path outside the subset. Under strict built-in errors the
// query then fails. Otherwise OPA leaves the call undefined, and with it the
// rule that makes the call, so a rule that negates that rule holds: with
// gt5 if nc.decimal.compare(nc.value(input.x), 5) > 0, a string x that
// BigDecimal refuses leaves gt5 undefined and makes allow if not gt5 true.
package regobuiltins

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
)

// Builtin is one built-in function: its declaration for the compiler and its
// implementation for a query.
type Builtin struct {
	Decl *ast.Builtin
	// Option registers the implementation on a query.
	Option func(*rego.Rego)
}

var record = types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))

// operand is an argument of nc.decimal.compare: a number or a value record.
var operand = types.NewAny(types.N, record)

var (
	valueDecl = &ast.Builtin{
		Name: "nc.value",
		Decl: types.NewFunction(types.Args(types.Named("v", types.A)), types.Named("record", record)),
	}
	compareDecl = &ast.Builtin{
		Name: "nc.decimal.compare",
		Decl: types.NewFunction(
			types.Args(types.Named("a", operand), types.Named("b", operand)),
			types.Named("result", types.N)),
	}
	jsonpathDecl = &ast.Builtin{
		Name: "nc.jsonpath",
		Decl: types.NewFunction(types.Args(types.Named("doc", types.A), types.Named("path", types.S)),
			types.Named("selection", record)),
	}
)

// All returns the built-in functions in a fixed order.
func All() []Builtin {
	return []Builtin{
		{valueDecl, rego.Function1(function(valueDecl), value)},
		{compareDecl, rego.Function2(function(compareDecl), compare)},
		{jsonpathDecl, rego.Function2(function(jsonpathDecl), selectPath)},
	}
}

func function(b *ast.Builtin) *rego.Function {
	return &rego.Function{Name: b.Name, Decl: b.Decl}
}

// Capabilities returns the capabilities of the linked OPA version with the
// built-in functions added, for a compiler that checks generated modules.
func Capabilities() *ast.Capabilities {
	c := ast.CapabilitiesForThisVersion()
	for _, b := range All() {
		c.Builtins = append(c.Builtins, b.Decl)
	}
	return c
}

// Options returns the options that register the implementations on a query.
func Options() []func(*rego.Rego) {
	all := All()
	opts := make([]func(*rego.Rego), len(all))
	for i, b := range all {
		opts[i] = b.Option
	}
	return opts
}

// Documents holds the JSON that terms of one query's input were built from.
// The zero value is not usable; call [NewDocuments].
//
// Pass the context [Documents.Context] returns to the query's Eval. Term must
// not run concurrently with itself or with the query.
type Documents struct {
	json map[ast.Value]jsonvalue.Value
}

// NewDocuments returns an empty Documents.
func NewDocuments() *Documents {
	return &Documents{json: map[ast.Value]jsonvalue.Value{}}
}

// Term returns the term of v. Where the term reaches the query in its input,
// as with [rego.EvalParsedInput], nc.value and nc.jsonpath read the term, and
// each object and list inside it, as v: members in v's order, numbers with v's
// text. Term returns an error if v, or a value inside it, is not one of the
// types a [jsonvalue.Value] holds, such as a float64 or a map[string]any.
func (d *Documents) Term(v jsonvalue.Value) (*ast.Term, error) {
	x, err := d.value(v)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(x), nil
}

func (d *Documents) value(v jsonvalue.Value) (ast.Value, error) {
	switch x := v.(type) {
	case nil:
		return ast.Null{}, nil
	case bool:
		return ast.Boolean(x), nil
	case jsonvalue.Number:
		return ast.Number(x), nil
	case string:
		return ast.String(x), nil
	case []jsonvalue.Value:
		terms := make([]*ast.Term, len(x))
		for i, e := range x {
			ev, err := d.value(e)
			if err != nil {
				return nil, err
			}
			terms[i] = ast.NewTerm(ev)
		}
		a := ast.NewArray(terms...)
		d.json[a] = x
		return a, nil
	case *jsonvalue.Object:
		items := make([][2]*ast.Term, 0, x.Len())
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			ev, err := d.value(e)
			if err != nil {
				return nil, err
			}
			items = append(items, ast.Item(ast.StringTerm(k), ast.NewTerm(ev)))
		}
		o := ast.NewObject(items...)
		d.json[o] = x
		return o, nil
	}
	return nil, fmt.Errorf("regobuiltins: %T is not a jsonvalue.Value", v)
}

type documentsKey struct{}

// Context returns a copy of ctx that carries d.
func (d *Documents) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, documentsKey{}, d)
}

// convertedKey keys the JSON of an object or a list in the query's built-in
// cache.
type convertedKey struct{ v ast.Value }

// JSONOf returns the JSON of the argument t of a built-in function, as nc.value
// and nc.jsonpath read it: an object or a list that a [Documents] in the
// query's context built as the JSON it was built from.
func JSONOf(bctx rego.BuiltinContext, t *ast.Term) (jsonvalue.Value, error) { return jsonOf(bctx, t) }

// CompilePath returns the compiled path s, as nc.jsonpath compiles and keeps
// it.
func CompilePath(s string) (*jsonpath.Path, error) { return compilePath(s) }

// jsonOf returns the JSON of t. An object or a list that a [Documents] in the
// query's context built, at any depth, is the JSON it was built from; any
// other object or list is converted once per query where the query has a
// built-in cache.
func jsonOf(bctx rego.BuiltinContext, t *ast.Term) (jsonvalue.Value, error) {
	var known func(ast.Value) (jsonvalue.Value, bool)
	if bctx.Context != nil {
		if d, ok := bctx.Context.Value(documentsKey{}).(*Documents); ok {
			known = func(v ast.Value) (jsonvalue.Value, bool) {
				j, ok := d.json[v]
				return j, ok
			}
		}
	}
	switch v := t.Value.(type) {
	case *ast.Array, ast.Object:
		if bctx.Cache == nil {
			return jsonvalue.FromASTKnown(v, known)
		}
		key := convertedKey{v}
		if j, ok := bctx.Cache.Get(key); ok {
			return j, nil
		}
		j, err := jsonvalue.FromASTKnown(v, known)
		if err != nil {
			return nil, err
		}
		bctx.Cache.Put(key, j)
		return j, nil
	}
	return jsonvalue.FromASTKnown(t.Value, known)
}

// maxPaths bounds the paths nc.jsonpath keeps compiled. Generated code passes
// a path as a literal, so one snapshot holds far fewer; the cache empties
// when it is full, so that paths of a replaced snapshot do not crowd out the
// current one.
const maxPaths = 4096

var paths = struct {
	sync.RWMutex
	m map[string]*jsonpath.Path
}{m: map[string]*jsonpath.Path{}}

// compilePath returns the compiled path s, from the cache where it holds s.
func compilePath(s string) (*jsonpath.Path, error) {
	paths.RLock()
	p, ok := paths.m[s]
	paths.RUnlock()
	if ok {
		return p, nil
	}
	p, err := jsonpath.Compile(s)
	if err != nil {
		return nil, err
	}
	paths.Lock()
	if len(paths.m) >= maxPaths {
		paths.m = map[string]*jsonpath.Path{}
	}
	paths.m[s] = p
	paths.Unlock()
	return p, nil
}

func value(bctx rego.BuiltinContext, v *ast.Term) (*ast.Term, error) {
	lv, err := jsonOf(bctx, v)
	if err != nil {
		return nil, err
	}
	return legacyvalue.Of(lv).Term(), nil
}

func compare(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
	x, err := decimalOf(a)
	if err != nil {
		return nil, err
	}
	y, err := decimalOf(b)
	if err != nil {
		return nil, err
	}
	return ast.InternedTerm(x.Compare(y)), nil
}

// decimalOf reads a number argument: a Rego number, or a value record that
// has n or nl, whose number is the one new BigDecimal reads from its ck. A
// string is refused: a string becomes a number only through its record.
func decimalOf(t *ast.Term) (jsonvalue.Decimal, error) {
	switch v := t.Value.(type) {
	case ast.Number:
		if d, ok := jsonvalue.ParseDecimal(string(v)); ok {
			return d, nil
		}
		return jsonvalue.Decimal{}, fmt.Errorf("%s is not a decimal number", v)
	case ast.Object:
		if v.Get(ast.InternedTerm("n")) == nil && v.Get(ast.InternedTerm("nl")) == nil {
			break
		}
		if ck := v.Get(ast.InternedTerm("ck")); ck != nil {
			if s, ok := ck.Value.(ast.String); ok {
				if d, ok := jsonvalue.ParseBigDecimal(string(s)); ok {
					return d, nil
				}
			}
		}
	}
	if _, ok := t.Value.(ast.Object); ok {
		return jsonvalue.Decimal{}, errors.New("the object is not the record of a number")
	}
	return jsonvalue.Decimal{}, fmt.Errorf("%v is neither a number nor the record of one", t)
}

func selectPath(bctx rego.BuiltinContext, doc, path *ast.Term) (*ast.Term, error) {
	ps, ok := path.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("path %v is not a string", path)
	}
	p, err := compilePath(string(ps))
	if err != nil {
		return nil, err
	}
	lv, err := jsonOf(bctx, doc)
	if err != nil {
		return nil, err
	}
	r := p.Select(lv)
	obj := ast.NewObject(ast.Item(ast.InternedTerm("sel"), ast.StringTerm(string(r.Kind))))
	switch r.Kind {
	case jsonpath.KindOne, jsonpath.KindMany:
		obj.Insert(ast.InternedTerm("rec"), legacyvalue.Of(r.Value).Term())
	case jsonpath.KindTooLarge:
		obj.Insert(ast.InternedTerm("rec"), legacyvalue.WithState(legacyvalue.StateError).Term())
	}
	return ast.NewTerm(obj), nil
}
