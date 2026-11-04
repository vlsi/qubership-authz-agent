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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/regobuiltins"
)

// entAnswer is a response of nc.http.send with status and the raw body.
func entAnswer(status int, body string) *ast.Term {
	return ast.ObjectTerm(ast.Item(ast.StringTerm("status_code"), ast.IntNumberTerm(status)),
		ast.Item(ast.StringTerm("raw_body"), ast.StringTerm(body)))
}

func TestEntResolve_ReadsTheIDsOfTheNamedReferences(t *testing.T) {
	const ordersAndInvoice = `{"entitlements": [
		{"resourceType": "ORDER", "references": [
			{"name": "owner", "resources": [{"resourceId": "o1"}, {"resourceId": "o2"}]},
			{"name": "viewer", "resources": [{"resourceId": "v1"}]}]},
		{"resourceType": "order", "references": [{"name": "owner", "resources": [{"resourceId": "o2"}, {"resourceId": "o3"}]}]},
		{"resourceType": "invoice", "references": [{"name": "owner", "resources": [{"resourceId": "i1"}]}]}]}`
	for _, tc := range []struct {
		name string
		resp *ast.Term
		want Resolved
	}{
		{"ids of the type ignoring case, each once in order", entAnswer(200, ordersAndInvoice), resolved(t, "VALUE", `["o1", "o2", "o3"]`)},
		{"no entitlement of the type", entAnswer(200, `{"entitlements": [{"resourceType": "invoice", "references": []}]}`),
			Resolved{State: "EMPTY_COLL"}},
		{"no entitlements", entAnswer(200, `{"entitlements": []}`), Resolved{State: "EMPTY_COLL"}},
		{"the body null", entAnswer(200, `null`), Resolved{State: "EMPTY_COLL"}},
		{"no body", entAnswer(200, ``), Resolved{State: "EMPTY_COLL"}},
		{"a malformed entitlement of another type is not read",
			entAnswer(200, `{"entitlements": [{"resourceType": "invoice", "references": "bad"}]}`), Resolved{State: "EMPTY_COLL"}},
		{"a malformed entitlement of the type", entAnswer(200, `{"entitlements": [{"resourceType": "order", "references": "bad"}]}`),
			Resolved{State: "ERROR"}},
		{"a body that is a list", entAnswer(200, `[{"resourceType": "order"}]`), Resolved{State: "ERROR"}},
		{"a body that is not JSON", entAnswer(200, `<html>`), Resolved{State: "ERROR"}},
		{"a status of 400 or more", entAnswer(400, ordersAndInvoice), Resolved{State: "ERROR"}},
		{"a status below 400", entAnswer(399, ordersAndInvoice), resolved(t, "VALUE", `["o1", "o2", "o3"]`)},
		{"a failed call", ast.ObjectTerm(ast.Item(ast.StringTerm("status_code"), ast.IntNumberTerm(0)),
			ast.Item(ast.StringTerm("error"), ast.ObjectTerm())), Resolved{State: "ERROR"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := entResolve(tc.resp, "order", []string{"owner"}); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("entResolve = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestEntCall_PostsForTheSubjectOrMakesNoCall(t *testing.T) {
	id := map[string]Resolved{keySubjID: resolved(t, "VALUE", `"u 1"`)}
	got := entCall(&Request{Entitlements: "http://ent/", Values: id})
	want := ast.MustParseTerm(`{"method": "POST", "url": "http://ent/api/v3/user-entitlements/user/u%201", "headers": {},
		"body": {}, "raise_error": false, "pip": "subject.entitledResources"}`)
	if !got.Equal(want) {
		t.Errorf("entCall = %v, want %v", got, want)
	}
	for _, req := range []Request{{Values: id}, {Entitlements: "http://ent", Values: map[string]Resolved{keySubjID: {State: "NULL"}}}} {
		if got := entCall(&req); !got.Equal(stateCall("ERROR")) {
			t.Errorf("entCall(%+v) = %v, want no call, ERROR", req, got)
		}
	}
}

// entServer is an entitlements service that grants the user u1 the order
// o1 and counts the calls and the tokens it was sent.
func entServer(t *testing.T) (*httptest.Server, func() (int, []string)) {
	t.Helper()
	var mu sync.Mutex
	var calls int
	var tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		calls++
		tokens = append(tokens, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/user-entitlements/user/u1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"entitlements": [{"resourceType": "order",
			"references": [{"name": "owner", "resources": [{"resourceId": "o1"}]}]}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() (int, []string) {
		mu.Lock()
		defer mu.Unlock()
		return calls, tokens
	}
}

// evalEntitled evaluates, with the agent's token given by token, whether
// the subject u1 may read the order resource id under a rule whose
// condition reads two operands of the entitlements service.
func evalEntitled(t *testing.T, url, id string, token func() (string, error)) bool {
	t.Helper()
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW",
		"subject.entitledResources.of('order').as('owner') CONTAINS resource.id AND "+
			"subject.entitledResources.of('order').as('owner','viewer') CONTAINS resource.id", ""),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := Request{Entitlements: url, Body: Body{Operation: "read", ResourceType: "doc", HasResource: true,
		Resource: mustDecode(t, `{"id": "`+id+`"}`)}, Values: map[string]Resolved{keySubjID: resolved(t, "VALUE", `"u1"`)}}
	m.Resolve(req.Body, req.Values)
	m.ResolveSubject(&req)
	in, err := Project(m, req)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + DefaultOptions().Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v\n%s", err, m.Text)
	}
	h := &regobuiltins.HTTP{Client: &http.Client{}, Token: token}
	ctx := in.Context(h.Context(regobuiltins.WithCalls(context.Background())))
	rs, err := pq.Eval(ctx, rego.EvalParsedInput(in.Value()))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	return len(rs) == 1 && rs[0].Expressions[0].Value == true
}

func own() (string, error) { return "own", nil }

// The module calls the entitlements service once for both operands, with
// the agent's own token, and allows the resource the service grants.
func TestTheModuleCallsTheEntitlementsService(t *testing.T) {
	srv, calls := entServer(t)
	if !evalEntitled(t, srv.URL, "o1", own) {
		t.Errorf("allow for the granted order o1 = false, want true")
	}
	if n, tokens := calls(); n != 1 || tokens[0] != "Bearer own" {
		t.Errorf("calls = %d with tokens %q, want 1 with Bearer own", n, tokens)
	}
	if evalEntitled(t, srv.URL, "o2", own) {
		t.Errorf("allow for the order o2 the service does not grant = true, want false")
	}
}

// Without the agent's token the call is not made, and the operand fails.
func TestTheEntitlementsServiceIsNotCalledWithoutAToken(t *testing.T) {
	srv, calls := entServer(t)
	if evalEntitled(t, srv.URL, "o1", func() (string, error) { return "", errors.New("no token") }) {
		t.Errorf("allow without the agent's token = true, want false")
	}
	if n, _ := calls(); n != 0 {
		t.Errorf("calls without the agent's token = %d, want 0", n)
	}
}
