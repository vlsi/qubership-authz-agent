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

package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/v1/topdown/builtins"

	"authz-agent/policies"
)

const testModule = `package t

import rego.v1

allow if input.x == 1

roles := data.policies.roles

when := time.now_ns()
`

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Options{Modules: map[string]string{"t.rego": testModule}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// TestEval_InputAndUndefined: a rule that holds evaluates to its value and an
// undefined document reports ok=false rather than an error.
func TestEval_InputAndUndefined(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	v, ok, err := e.Eval(ctx, []string{"t", "allow"}, map[string]any{"x": 1}, nil)
	if err != nil || !ok || v != true {
		t.Fatalf("allow with x=1: v=%v ok=%v err=%v", v, ok, err)
	}
	_, ok, err = e.Eval(ctx, []string{"t", "allow"}, map[string]any{"x": 2}, nil)
	if err != nil || ok {
		t.Fatalf("allow with x=2 must be undefined: ok=%v err=%v", ok, err)
	}
	_, ok, err = e.Eval(ctx, []string{"nothing", "here"}, nil, nil)
	if err != nil || ok {
		t.Fatalf("unknown document must be undefined: ok=%v err=%v", ok, err)
	}
}

// TestPut_DocumentsReachTheRules: a document written through Put is what the
// rules read, and a Put under a path that does not exist yet creates its
// parents.
func TestPut_DocumentsReachTheRules(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if err := e.Put(ctx, []string{"policies"}, map[string]any{"roles": []any{"a"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, ok, err := e.Eval(ctx, []string{"t", "roles"}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("roles after Put: ok=%v err=%v", ok, err)
	}
	if got := v.([]any); len(got) != 1 || got[0] != "a" {
		t.Fatalf("roles = %v, want [a]", got)
	}
	if err := e.Put(ctx, []string{"deep", "er", "doc"}, "x"); err != nil {
		t.Fatalf("Put with parents: %v", err)
	}
	if v, ok, err := e.Eval(ctx, []string{"deep", "er", "doc"}, nil, nil); err != nil || !ok || v != "x" {
		t.Fatalf("data.deep.er.doc after Put = %v ok=%v err=%v, want x", v, ok, err)
	}
}

// TestNDBuiltinCache_RecordsTimeNow: the cache handed to Eval collects the
// non-deterministic builtins the rules called, which the decision log
// carries so a decision can be replayed.
func TestNDBuiltinCache_RecordsTimeNow(t *testing.T) {
	e := newTestEngine(t)
	ndbc := builtins.NDBCache{}
	if _, ok, err := e.Eval(context.Background(), []string{"t", "when"}, nil, ndbc); err != nil || !ok {
		t.Fatalf("when: ok=%v err=%v", ok, err)
	}
	if _, ok := ndbc["time.now_ns"]; !ok {
		t.Fatalf("nd_builtin_cache lacks time.now_ns: %v", ndbc)
	}
}

// TestNew_RejectsBrokenPolicy: a module that does not compile fails New with
// the compiler's message rather than a nil engine.
func TestNew_RejectsBrokenPolicy(t *testing.T) {
	if _, err := New(Options{Modules: map[string]string{"bad.rego": "package bad\n\nx := undefined_fn()\n"}}); err == nil {
		t.Fatal("broken policy must fail New")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("no modules must fail New")
	}
}

// TestNew_EmbeddedProductPoliciesCompile: the policies the service ships
// compile on the library, and the admission document they define is what a
// check request reads first: a request without a token is refused.
func TestNew_EmbeddedProductPoliciesCompile(t *testing.T) {
	modules, err := policies.Modules()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Modules: modules})
	if err != nil {
		t.Fatalf("New with product policies: %v", err)
	}
	v, ok, err := e.Eval(context.Background(), []string{"authorize_internals", "admission"}, map[string]any{}, nil)
	if err != nil || !ok {
		t.Fatalf("data.authorize_internals.admission with an empty input: ok=%v err=%v", ok, err)
	}
	if want := map[string]any{"subjectError": "Authorization token is missing"}; !reflect.DeepEqual(v, want) {
		t.Errorf("data.authorize_internals.admission with an empty input = %v, want %v", v, want)
	}
}

// TestQuery_EscapesSegments: segments become bracketed string keys, so a
// dash or a quote in a document name cannot change the query.
func TestQuery_EscapesSegments(t *testing.T) {
	if got, want := Query([]string{"opa-lockdown-test", `a"b`}), `data["opa-lockdown-test"]["a\"b"]`; got != want {
		t.Fatalf("Query = %s, want %s", got, want)
	}
}
