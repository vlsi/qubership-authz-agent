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
	"net/url"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regogen/spectables"
)

// subject.entitledResources.of(<type>).as(<names>) is a function of the
// module, ent_<Var>, which a clause binds the operand's record from where it
// reads it, the way a GENERAL PIP's function is bound:
//
//	ent_<Var> := nc.ent.record(q, pip_send(q), {...}) if q := input.pq[<ID>]
//
// Go builds q before the query ([entCall]): the POST of the entitlements
// service for the subject, or {"s": "ERROR"} where the agent makes no call.
// Every operand of one subject sends the same request, which nc.http.send
// makes once per decision request. nc.ent.record reads the response as the
// specification's entitled does.

// entText returns the function of the entitlements operand of r.
func entText(r *Ref) string {
	as, _ := json.Marshal(r.ent.As)
	return fmt.Sprintf("ent_%s := nc.ent.record(q, pip_send(q), {\"read\": %d, \"seg\": %t, \"subset\": %t, "+
		"\"jp\": null, \"type\": %s, \"as\": %s}) if q := input.pq[%s]\n\n", r.Var, r.read, r.Segments, r.Subset,
		lit(r.ent.ResourceType), as, lit(r.ID))
}

// entitlementsPIP is the name a failed call of the entitlements service
// goes by in the reason of a denial.
const entitlementsPIP = "subject.entitledResources"

// entCall returns the q of an entitlements operand on req: a POST with the
// body {} to <req.Entitlements>/api/v3/user-entitlements/user/<subject.id>,
// or {"s": "ERROR"} without the service's URL or without a subject.id
// value.
func entCall(req *Request) *ast.Term {
	id := req.Values[keySubjID]
	if req.Entitlements == "" || id.State != spectables.StateValue {
		return stateCall(spectables.StateError)
	}
	text, ok := id.Value.(string)
	if !ok {
		text = legacyvalue.Text(id.Value)
	}
	u := strings.TrimRight(req.Entitlements, "/") + "/api/v3/user-entitlements/user/" + url.PathEscape(text)
	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("method"), ast.StringTerm("POST")),
		ast.Item(ast.StringTerm("url"), ast.StringTerm(u)),
		ast.Item(ast.StringTerm("headers"), ast.ObjectTerm()),
		ast.Item(ast.StringTerm("body"), ast.ObjectTerm()),
		ast.Item(ast.StringTerm("raise_error"), ast.BooleanTerm(false)),
		ast.Item(ast.StringTerm("pip"), ast.StringTerm(entitlementsPIP)))
}

// EntRecordDecl declares nc.ent.record as generated modules call it.
var EntRecordDecl = &ast.Builtin{
	Name: "nc.ent.record",
	Decl: types.NewFunction(types.Args(
		types.Named("q", types.A), types.Named("response", types.A), types.Named("opts", types.A)),
		types.Named("record", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)))),
}

func entRecordFunction() func(*rego.Rego) {
	return rego.Function3(&rego.Function{Name: EntRecordDecl.Name, Decl: EntRecordDecl.Decl},
		func(_ rego.BuiltinContext, q, resp, opts *ast.Term) (*ast.Term, error) {
			r, _, err := pipOptions(opts)
			if err != nil {
				return nil, err
			}
			o := opts.Value.(ast.Object)
			typ, ok := o.Get(ast.StringTerm("type")).Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("nc.ent.record: the type in %v is not a string", opts)
			}
			var as []string
			if err := ast.As(o.Get(ast.StringTerm("as")).Value, &as); err != nil {
				return nil, fmt.Errorf("nc.ent.record: the names in %v: %w", opts, err)
			}
			if s := q.Get(ast.StringTerm("s")); s != nil {
				st, ok := s.Value.(ast.String)
				if !ok {
					return nil, fmt.Errorf("nc.ent.record: the state %v is not a string", s)
				}
				return record(r, Resolved{State: spectables.State(st)}).term(), nil
			}
			return record(r, entResolve(resp, string(typ), as)).term(), nil
		})
}

// entResolve returns the value of subject.entitledResources.of(typ).as(as)
// that the entitlements service answered resp with: ERROR for a failed call
// or a status of 400 or more; otherwise the resourceId of each resource
// under a reference named in as of an entitlement whose resourceType equals
// typ ignoring case, each once in the order of the answer, or EMPTY_COLL
// for none. A body the specification cannot walk, such as a list where it
// reads an object, is ERROR: the legacy service fails on it.
func entResolve(resp *ast.Term, typ string, as []string) Resolved {
	errorState := Resolved{State: spectables.StateError}
	o, ok := resp.Value.(ast.Object)
	if !ok || o.Get(ast.StringTerm("error")) != nil {
		return errorState
	}
	status, _ := o.Get(ast.StringTerm("status_code")).Value.(ast.Number)
	if code, ok := status.Int(); !ok || code >= 400 || code <= 0 {
		return errorState
	}
	var body jsonvalue.Value
	if raw, ok := o.Get(ast.StringTerm("raw_body")).Value.(ast.String); ok && strings.TrimSpace(string(raw)) != "" {
		var err error
		if body, err = jsonvalue.Decode([]byte(raw)); err != nil {
			return errorState
		}
	}
	if !truthy(body) {
		return Resolved{State: spectables.StateEmptyColl}
	}
	root, ok := body.(*jsonvalue.Object)
	if !ok {
		return errorState
	}
	ents, ok := pyList(root, "entitlements")
	if !ok {
		return errorState
	}
	foldedType := legacyvalue.Fold(typ)
	var ids []jsonvalue.Value
	for _, e := range ents {
		ent, ok := e.(*jsonvalue.Object)
		if !ok {
			return errorState
		}
		rt, _ := ent.Get("resourceType")
		if legacyvalue.Fold(pyStr(rt)) != foldedType {
			continue
		}
		refs, ok := pyList(ent, "references")
		if !ok {
			return errorState
		}
		for _, x := range refs {
			ref, ok := x.(*jsonvalue.Object)
			if !ok {
				return errorState
			}
			name, _ := ref.Get("name")
			if s, ok := name.(string); !ok || !containsString(as, s) {
				continue
			}
			resources, ok := pyList(ref, "resources")
			if !ok {
				return errorState
			}
			for _, y := range resources {
				res, ok := y.(*jsonvalue.Object)
				if !ok {
					return errorState
				}
				id, _ := res.Get("resourceId")
				if !containsPy(ids, id) {
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return Resolved{State: spectables.StateEmptyColl}
	}
	return Resolved{State: spectables.StateValue, Value: ids}
}

// pyList returns the member key of o as Python's o.get(key) or [] reads
// it: no member and a member Python counts false give an empty list, and
// any other member that is not a list is not one (ok false).
func pyList(o *jsonvalue.Object, key string) ([]jsonvalue.Value, bool) {
	v, _ := o.Get(key)
	if !truthy(v) {
		return nil, true
	}
	l, ok := v.([]jsonvalue.Value)
	return l, ok
}

// truthy reports whether Python counts the JSON value v true: every value
// but null, false, a zero number, "", [], and {}.
func truthy(v jsonvalue.Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case jsonvalue.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return err != nil || f != 0
	case string:
		return x != ""
	case []jsonvalue.Value:
		return len(x) > 0
	case *jsonvalue.Object:
		return len(x.Keys()) > 0
	}
	return true
}

// pyStr returns Python's str of the JSON value v as the specification reads
// it: a string as itself, null as None, a boolean as True or False, a
// number as written, and a list or an object as its Java text.
func pyStr(v jsonvalue.Value) string {
	return roleText(v)
}

// containsPy reports whether list holds a value equal to v as Python's ==
// compares JSON values: numbers by value, true as 1 and false as 0, lists
// and objects member by member.
func containsPy(list []jsonvalue.Value, v jsonvalue.Value) bool {
	for _, e := range list {
		if pyEqual(e, v) {
			return true
		}
	}
	return false
}

func pyEqual(a, b jsonvalue.Value) bool {
	if na, ok := pyNumber(a); ok {
		nb, ok := pyNumber(b)
		return ok && na == nb
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []jsonvalue.Value:
		y, ok := b.([]jsonvalue.Value)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case *jsonvalue.Object:
		y, ok := b.(*jsonvalue.Object)
		if !ok || len(x.Keys()) != len(y.Keys()) {
			return false
		}
		for _, k := range x.Keys() {
			xv, _ := x.Get(k)
			yv, ok := y.Get(k)
			if !ok || !pyEqual(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

// pyNumber returns the value of a number or a boolean, which Python
// compares as the numbers 1 and 0.
func pyNumber(v jsonvalue.Value) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case jsonvalue.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return f, err == nil
	}
	return 0, false
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
