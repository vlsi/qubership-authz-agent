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
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// A resource path with brackets, .., *, ?, or a call (kind res:jsonpath) and
// without one dot at its end is read lazily: the clause that reads it binds the record that
// nc.resource_path(input.resource, path) returns, so a path only a few
// clauses reach is not evaluated for every request. Any other resource path is
// in the input before the query. The function has a name of its own because
// the record differs from the {sel, rec} of [regobuiltins]' nc.jsonpath: a
// module evaluated with that one in its place fails to compile.

// JSONPathDecl declares nc.resource_path as generated modules call it.
var JSONPathDecl = &ast.Builtin{
	Name: "nc.resource_path",
	Decl: types.NewFunction(types.Args(types.Named("doc", types.A), types.Named("path", types.S)),
		types.Named("record", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)))),
}

// Builtins returns the built-in functions a generated module calls but nc.pip:
// those of [regobuiltins], and nc.resource_path, which [JSONPathRecord]
// answers. One query calls it once per path.
func Builtins() []func(*rego.Rego) {
	return append(regobuiltins.Options(), rego.Function2(&rego.Function{Name: JSONPathDecl.Name,
		Decl: JSONPathDecl.Decl, Memoize: true},
		func(bctx rego.BuiltinContext, doc, path *ast.Term) (*ast.Term, error) {
			p, ok := path.Value.(ast.String)
			if !ok {
				return nil, errNotAPath
			}
			d, err := regobuiltins.JSONOf(bctx, doc)
			if err != nil {
				return nil, err
			}
			return JSONPathRecord(d, string(p))
		}))
}

// Capabilities returns the capabilities of [regobuiltins] with
// nc.resource_path added, for a compiler that checks generated modules.
func Capabilities() *ast.Capabilities {
	c := regobuiltins.Capabilities()
	c.Builtins = append(c.Builtins, JSONPathDecl)
	return c
}

type pathError string

func (e pathError) Error() string { return string(e) }

const errNotAPath = pathError("nc.resource_path: the path is not a string")

// jsonPathRef is the reference a record of nc.resource_path belongs to: a resource
// path, whose elements other than strings are one value on the right of IS
// SUBSET, and whose element tokens IS SUBSET may read.
var jsonPathRef = &Ref{Kind: spectables.KindResJSONPath, Subset: true}

// JSONPathRecord returns the value record of path over the resource doc, in
// the state the specification's resolve_resource gives the selection under
// the agent profile. doc is nil for a request without a resource or with a
// null one, and the record is then ABSENT, as it is for a document without
// the path, a path through null, and a path that starts with a bracket. An
// index past the end is INDEX_OOB; a path that selects several values and
// none is EMPTY_SEL; one value null is NULL and an empty list EMPTY_COLL. A
// selection the package stops as too large, which the specification does not
// have, is ERROR: the domain of a path without a dot at its end holds no
// ERROR (pathDomain), so every comparison over the record is undefined, as
// over a failed source.
func JSONPathRecord(doc jsonvalue.Value, path string) (*ast.Term, error) {
	p, err := regobuiltins.CompilePath(path)
	if err != nil {
		return nil, err
	}
	return jsonPathRecord(doc, p).term(), nil
}

func jsonPathRecord(doc jsonvalue.Value, p *jsonpath.Path) Record {
	if doc == nil {
		return record(jsonPathRef, Resolved{State: spectables.StateAbsent})
	}
	r := p.Select(doc)
	var v Resolved
	switch r.Kind {
	case jsonpath.KindMissing, jsonpath.KindNullParent, jsonpath.KindBracket:
		v = Resolved{State: spectables.StateAbsent}
	case jsonpath.KindIndexOutOfBounds:
		v = Resolved{State: spectables.StateIndexOOB}
	case jsonpath.KindMany:
		if l, ok := r.Value.([]jsonvalue.Value); ok && len(l) == 0 {
			v = Resolved{State: spectables.StateEmptySel}
		} else {
			v = Resolved{State: spectables.StateValue, Value: r.Value}
		}
	case jsonpath.KindOne:
		switch x := r.Value.(type) {
		case nil:
			v = Resolved{State: spectables.StateNull}
		case []jsonvalue.Value:
			if len(x) == 0 {
				v = Resolved{State: spectables.StateEmptyColl}
			} else {
				v = Resolved{State: spectables.StateValue, Value: x}
			}
		default:
			v = Resolved{State: spectables.StateValue, Value: x}
		}
	default:
		v = Resolved{State: spectables.StateError}
	}
	return record(jsonPathRef, v)
}
