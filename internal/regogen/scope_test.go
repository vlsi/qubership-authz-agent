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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
)

func TestScopeAnswer_ReadsOneGrantPerPolicy(t *testing.T) {
	ids := func(s ...string) []jsonvalue.Value {
		out := make([]jsonvalue.Value, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out
	}
	for _, tc := range []struct {
		name string
		resp *ast.Term
		want []map[string][]jsonvalue.Value
		ok   bool
	}{
		{"each policy one grant, keys by key, name, or scopeKey", entAnswer(200, `{"permissionScope": [
			{"policies": [{"scopeItems": [{"key": "domain", "values": [{"id": "d1"}, {"id": "d2"}]}]},
				{"scopeItems": [{"name": "region", "value": [{"id": "eu"}]}, {"scopeKey": "team", "values": []}]}]}]}`),
			[]map[string][]jsonvalue.Value{{"domain": ids("d1", "d2")}, {"region": ids("eu"), "team": {}}}, true},
		{"an empty list", entAnswer(200, `{"permissionScope": []}`), nil, true},
		{"the body null", entAnswer(200, `null`), nil, true},
		{"404", entAnswer(404, `{"error": "x"}`), nil, true},
		{"no body", entAnswer(200, ``), nil, false},
		{"permissionScope null", entAnswer(200, `{"permissionScope": null}`), nil, false},
		{"no permissionScope", entAnswer(200, `{}`), nil, false},
		{"a value that is not an object", entAnswer(200,
			`{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": ["d1"]}]}]}]}`), nil, false},
		{"a value without an id", entAnswer(200,
			`{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": [{"x": 1}]}]}]}]}`), nil, false},
		{"a status of 400 or more but 404", entAnswer(400, `{}`), nil, false},
		{"403", entAnswer(403, `{"permissionScope": []}`), nil, false},
		{"405", entAnswer(405, `{"permissionScope": []}`), nil, false},
		{"a status below 400", entAnswer(399, `{"permissionScope": []}`), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := scopeAnswer(tc.resp)
			if ok != tc.ok || ok && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("scopeAnswer = %v, %t; want %v, %t", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// scopeModule is the module of a tenant whose set iterates over the
// permission scope, with the PERMISSION_SCOPE PIP of url, or none for "".
func scopeModule(t *testing.T, url string) *Module {
	t.Helper()
	tree := iterateTree(t, "DENY_UNLESS_PERMIT", "subject.permissionScope.domain CONTAINS resource.domain")
	if url != "" {
		tree.PIPs = append(tree.PIPs, &policyir.PIP{Name: "subject.permissionScope", Type: policyir.PIPPermissionScope, URL: url})
	}
	m, err := Generate(tree, table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return m
}

// readScope reads the permission scope of the user u1 with the agent's
// token given by token.
func readScope(t *testing.T, m *Module, token func() (string, error)) *Scope {
	t.Helper()
	h := &regobuiltins.HTTP{Client: &http.Client{}, Token: token}
	req := Request{Values: map[string]Resolved{keySubjID: resolved(t, "VALUE", `"u1"`)}}
	return m.ReadScope(regobuiltins.WithCalls(h.Context(context.Background())), &req)
}

// The scope service is called with a POST under the url of the
// PERMISSION_SCOPE PIP and the agent's token, and each pass reads its
// grant's values of the key the condition names.
func TestReadScope_CallsTheServiceAndReadsAPassPerGrant(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = fmt.Sprintf("%s %s %s %s", r.Method, r.URL.Path, body, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"permissionScope": [{"policies": [{"scopeItems": [{"key": "domain", "values": [{"id": "d1"}]}]},
			{"scopeItems": [{"key": "other", "values": [{"id": "x"}]}]}]}]}`))
	}))
	t.Cleanup(srv.Close)

	s := readScope(t, scopeModule(t, srv.URL+"/scope/"), own)

	if want := `POST /scope/api/v1/permission-scope/user/u1/policies {} Bearer own`; got != want {
		t.Errorf("request = %q, want %q", got, want)
	}
	const domain = `["subj","permissionScope.domain"]`
	want := &Scope{Passes: []map[string]Resolved{{domain: resolved(t, "VALUE", `["d1"]`)},
		{domain: {State: "ABSENT"}}}}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("ReadScope = %+v, want %+v", s, want)
	}
}

// Without a PERMISSION_SCOPE PIP or the agent's token the scope is not
// read, and fails.
func TestReadScope_FailsWithoutAPIPOrAToken(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"permissionScope": []}`))
	}))
	t.Cleanup(srv.Close)

	if s := readScope(t, scopeModule(t, ""), own); !s.Failed {
		t.Errorf("without a PERMISSION_SCOPE PIP: %+v, want failed", s)
	}
	noToken := func() (string, error) { return "", errors.New("no token") }
	if s := readScope(t, scopeModule(t, srv.URL), noToken); !s.Failed {
		t.Errorf("without the agent's token: %+v, want failed", s)
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0", calls)
	}
	if s := readScope(t, scopeModule(t, srv.URL), own); s.Failed || len(s.Passes) != 0 || calls != 1 {
		t.Errorf("with the PIP and a token: %+v after %d calls, want no passes after 1", s, calls)
	}
}
