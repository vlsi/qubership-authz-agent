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
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// ScopePIP is the name a call of the permission scope service goes by in
// the reason of a denial.
const ScopePIP = "subject.permissionScope"

// ReadScope reads the permission scope the iterates of m run over for the
// subject of req: a POST with the body {} to the url of the tenant's first
// PERMISSION_SCOPE PIP followed by /api/v1/permission-scope/user/<id>/policies,
// sent by nc.http.send under the calls and the HTTP of ctx, so with the
// agent's token and once per decision request. Each policy of the answer
// is one pass, which reads the ids under each key of its scopeItems.
//
// The scope fails without a PERMISSION_SCOPE PIP, without a subject.id
// value, on a failed call, on a status of 400 or more other than 404, and on
// a body the specification cannot walk, such as no body or one without
// permissionScope; it is empty on 404 and on the body null. Read as the
// specification's _scope_call reads it under the agent profile:
// scope_without_pip=http500, scope_404_is_empty=true, scope_error_empty=none,
// scope_blank_body=json_null, scope_empty_list=empty,
// scope_scalar_values=http500, scope_value_trim=false, scope_cache=request,
// scope_missing_key=ABSENT, scope_empty_key=EMPTY_COLL.
func (m *Module) ReadScope(ctx context.Context, req *Request) *Scope {
	failed := &Scope{Failed: true}
	id := req.Values[keySubjID]
	if m.scopePIP == nil || id.State != spectables.StateValue {
		return failed
	}
	text, ok := id.Value.(string)
	if !ok {
		text = legacyvalue.Text(id.Value)
	}
	u := strings.TrimRight(m.scopePIP.URL, "/") + "/api/v1/permission-scope/user/" + url.PathEscape(text) + "/policies"
	q := ast.ObjectTerm(
		ast.Item(ast.StringTerm("method"), ast.StringTerm("POST")),
		ast.Item(ast.StringTerm("url"), ast.StringTerm(u)),
		ast.Item(ast.StringTerm("headers"), ast.ObjectTerm()),
		ast.Item(ast.StringTerm("body"), ast.ObjectTerm()),
		ast.Item(ast.StringTerm("raise_error"), ast.BooleanTerm(false)),
		ast.Item(ast.StringTerm("pip"), ast.StringTerm(ScopePIP)))
	resp, err := regobuiltins.Send(ctx, q)
	if err != nil {
		return failed
	}
	grants, ok := scopeAnswer(resp)
	if !ok {
		return failed
	}
	s := &Scope{Passes: make([]map[string]Resolved, 0, len(grants))}
	for _, g := range grants {
		pass := map[string]Resolved{}
		for _, r := range m.Refs {
			if !r.Pass {
				continue
			}
			vals, ok := g[scopeKey(r.Key)]
			switch {
			case !ok:
				pass[r.Key] = Resolved{State: spectables.StateAbsent}
			case len(vals) == 0:
				pass[r.Key] = Resolved{State: spectables.StateEmptyColl}
			default:
				pass[r.Key] = Resolved{State: spectables.StateValue, Value: vals}
			}
		}
		s.Passes = append(s.Passes, pass)
	}
	return s
}

// scopeKey returns the key of the permission scope a pass value with the
// operand key ["subj","permissionScope.<key>"] reads.
func scopeKey(key string) string {
	var parts []string
	if json.Unmarshal([]byte(key), &parts) != nil || len(parts) != 2 {
		return ""
	}
	return strings.TrimPrefix(parts[1], "permissionScope.")
}

// scopeAnswer returns the grants of the scope service's response resp, one
// per policy, each mapping a key to its values; false where the scope
// fails.
func scopeAnswer(resp *ast.Term) ([]map[string][]jsonvalue.Value, bool) {
	o, ok := resp.Value.(ast.Object)
	if !ok || o.Get(ast.StringTerm("error")) != nil {
		return nil, false
	}
	status, _ := o.Get(ast.StringTerm("status_code")).Value.(ast.Number)
	code, ok := status.Int()
	switch {
	case !ok || code <= 0:
		return nil, false
	case code == 404:
		return nil, true
	case code >= 400:
		return nil, false
	}
	raw, _ := o.Get(ast.StringTerm("raw_body")).Value.(ast.String)
	if strings.TrimSpace(string(raw)) == "" {
		// no body: the specification reads permissionScope of None
		return nil, false
	}
	body, err := jsonvalue.Decode([]byte(raw))
	if err != nil {
		return nil, false
	}
	if body == nil {
		return nil, true
	}
	var out []map[string][]jsonvalue.Value
	scope, ok := pyIndex(body, "permissionScope")
	if !ok {
		return nil, false
	}
	pss, ok := pyIter(scope)
	if !ok {
		return nil, false
	}
	for _, ps := range pss {
		pols, ok := pyIndex(ps, "policies")
		if !ok {
			return nil, false
		}
		polList, ok := pyIter(pols)
		if !ok {
			return nil, false
		}
		for _, pol := range polList {
			items, ok := pyIndex(pol, "scopeItems")
			if !ok {
				return nil, false
			}
			itemList, ok := pyIter(items)
			if !ok {
				return nil, false
			}
			a := map[string][]jsonvalue.Value{}
			for _, it := range itemList {
				item, ok := it.(*jsonvalue.Object)
				if !ok {
					return nil, false
				}
				k := firstTruthy(item, "key", "name", "scopeKey")
				var vals []jsonvalue.Value
				if v := firstTruthy(item, "values", "value"); v != nil {
					if vals, ok = pyIter(v); !ok {
						return nil, false
					}
				}
				ids := make([]jsonvalue.Value, 0, len(vals))
				for _, x := range vals {
					obj, ok := x.(*jsonvalue.Object)
					if !ok {
						return nil, false
					}
					id, ok := obj.Get("id")
					if !ok {
						return nil, false
					}
					ids = append(ids, id)
				}
				if s, ok := k.(string); ok {
					// a key that is not a string is no key a condition names
					a[s] = ids
				}
			}
			out = append(out, a)
		}
	}
	return out, true
}

// firstTruthy returns the first member of o among keys that Python counts
// true, nil for none.
func firstTruthy(o *jsonvalue.Object, keys ...string) jsonvalue.Value {
	for _, k := range keys {
		if v, _ := o.Get(k); truthy(v) {
			return v
		}
	}
	return nil
}

// pyIndex returns v[key] as Python reads it on a JSON value: false for a
// value that is not an object or has no such member.
func pyIndex(v jsonvalue.Value, key string) (jsonvalue.Value, bool) {
	o, ok := v.(*jsonvalue.Object)
	if !ok {
		return nil, false
	}
	return o.Get(key)
}

// pyIter returns the elements a Python for loop takes from v: the elements
// of a list, the member names of an object, and the characters of a string;
// false for a value a loop cannot take, such as null or a number.
func pyIter(v jsonvalue.Value) ([]jsonvalue.Value, bool) {
	switch x := v.(type) {
	case []jsonvalue.Value:
		return x, true
	case *jsonvalue.Object:
		out := make([]jsonvalue.Value, 0, len(x.Keys()))
		for _, k := range x.Keys() {
			out = append(out, k)
		}
		return out, true
	case string:
		out := make([]jsonvalue.Value, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, true
	}
	return nil, false
}
