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
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
)

// bulkCondition reads the subject in a group, resource paths read before the
// query and lazily, null, and the operation.
const bulkCondition = "subject.type == 'SERVICE' AND resource.a == 'x' OR resource.l[0] == 'x' OR null == 'x' " +
	"OR operation == 'WRITE'"

// checkBulk projects each body as an item of one Bulk over shared, one after
// another, so an item that kept a record of the item before it differs from
// its request alone. It checks that the item's input and allow are those of
// the request alone.
func checkBulk(t *testing.T, m *Module, shared Request, bodies ...string) {
	t.Helper()
	bulk, err := NewBulk(m, shared)
	if err != nil {
		t.Fatalf("NewBulk: %v", err)
	}
	for _, body := range bodies {
		b, err := ReadBody([]byte(body))
		if err != nil {
			t.Fatalf("ReadBody(%s): %v", body, err)
		}
		alone := shared
		alone.Body = b
		alone.Values = maps.Clone(shared.Values)
		if alone.Values == nil {
			alone.Values = map[string]Resolved{}
		}
		m.Resolve(b, alone.Values)
		want, err := Project(m, alone)
		if err != nil {
			t.Fatalf("Project(%s): %v", body, err)
		}
		item := bulk.Item(b)
		if got, want := item.Value(), want.Value(); got.Compare(want) != 0 {
			t.Errorf("Item(%s).Value() =\n%v\nwant\n%v", body, got, want)
		}
		if got, want := evalInput(t, m, item, "allow"), evalInput(t, m, want, "allow"); got != want {
			t.Errorf("allow of Item(%s) = %v, of the request alone %v", body, got, want)
		}
	}
}

func TestBulkItemIsTheInputOfItsRequestAlone(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", bulkCondition), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var shared Request
	SubjectOf(claimsOf(t, serviceClaims), false, DefaultSubjectRules).Apply(&shared)
	checkBulk(t, m, shared,
		`{"operation": "read", "type": "doc", "resource": {"a": "x", "null": 1}}`,
		`{"operation": "write", "resourceType": "doc"}`,
		`{"operation": "read", "type": "doc", "resource": {"l": ["x"]}}`,
		`{"resource": null}`)
}

// nc.pip reads a network PIP of an item from the shared records.
func TestBulkItemReadsANetworkPIP(t *testing.T) {
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.g == 'x' AND resource.a == 'y'",
		generalPIPs), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	shared := Request{Values: map[string]Resolved{`["subj","g"]`: resolved(t, "VALUE", `"x"`)}}
	checkBulk(t, m, shared,
		`{"operation": "read", "type": "doc", "resource": {"a": "y"}}`,
		`{"operation": "read", "type": "doc", "resource": {"a": "z"}}`)
}

// The passes of an iterate are shared, and each item compares them with its
// own resource.
func TestBulkItemIteratesTheSharedScope(t *testing.T) {
	m, err := Generate(iterateTree(t, "DENY_UNLESS_PERMIT", "subject.permissionScope.domain CONTAINS resource.domain"),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const domain = `["subj","permissionScope.domain"]`
	shared := Request{Scope: &Scope{Passes: []map[string]Resolved{{domain: resolved(t, "VALUE", `["x"]`)},
		{domain: resolved(t, "VALUE", `["d"]`)}}}}
	checkBulk(t, m, shared,
		`{"operation": "read", "type": "doc", "resource": {"domain": "d"}}`,
		`{"operation": "read", "type": "doc", "resource": {"domain": "y"}}`,
		`{"operation": "read", "type": "doc", "resource": {"domain": "x"}}`)
}

// The items of one Bulk are evaluated at once, as the agent's pool evaluates
// them; run with -race.
func TestBulkItemsEvaluateConcurrently(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", bulkCondition), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + DefaultOptions().Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("PrepareForEval: %v", err)
	}
	var shared Request
	SubjectOf(claimsOf(t, serviceClaims), false, DefaultSubjectRules).Apply(&shared)
	bulk, err := NewBulk(m, shared)
	if err != nil {
		t.Fatalf("NewBulk: %v", err)
	}
	// even items allow by resource.a, odd ones by resource.l[0]
	got := make([]bool, 40)
	var wg sync.WaitGroup
	for i := range got {
		wg.Go(func() {
			body := Body{Operation: "read", ResourceType: "doc", HasResource: true,
				Resource: object(t, fmt.Sprintf(`{"a": "v%d"}`, i))}
			if i%2 == 0 {
				body.Resource = object(t, `{"a": "x"}`)
			} else if i%4 == 1 {
				body.Resource = object(t, `{"l": ["x"]}`)
			}
			in := bulk.Item(body)
			rs, err := pq.Eval(in.Context(context.Background()), rego.EvalParsedInput(in.Value()))
			if err != nil {
				t.Errorf("Eval of item %d: %v", i, err)
				return
			}
			got[i] = len(rs) == 1 && rs[0].Expressions[0].Value == true
		})
	}
	wg.Wait()
	for i, allow := range got {
		if want := i%2 == 0 || i%4 == 1; allow != want {
			t.Errorf("allow of item %d = %v, want %v", i, allow, want)
		}
	}
}

func object(t testing.TB, text string) *jsonvalue.Object {
	t.Helper()
	return claimsOf(t, text)
}

func TestNewBulkFailsWithoutAValueOfTheSubject(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", bulkCondition), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := NewBulk(m, Request{}); err == nil {
		t.Errorf("NewBulk without subject.type: no error")
	}
}

// BenchmarkBulk50 is one bulk request of 50 items by a subject with 200
// roles: the shared projection, then each item's projection and allow.
func BenchmarkBulk50(b *testing.B) {
	m, err := Generate(tenantWithSet(b, "DENY_UNLESS_PERMIT", "ALLOW", bulkCondition), table(b), DefaultOptions())
	if err != nil {
		b.Fatalf("Generate: %v", err)
	}
	pq, err := rego.New(append([]func(*rego.Rego){rego.Query("data." + DefaultOptions().Package + ".allow"),
		rego.Module("gen.rego", m.Text)}, Builtins()...)...).PrepareForEval(context.Background())
	if err != nil {
		b.Fatalf("PrepareForEval: %v", err)
	}
	roles := make([]string, 200)
	for i := range roles {
		roles[i] = fmt.Sprintf("%q", fmt.Sprintf("PARITY_ROLE_%d", i))
	}
	claims := claimsOf(b, `{"sub": "u1", "preferred_username": "service-account-c", "scope": "openid profile",
		"realm_access": {"roles": [`+strings.Join(roles, ",")+`]}}`)
	bodies := make([]Body, 50)
	for i := range bodies {
		bodies[i], err = ReadBody([]byte(fmt.Sprintf(`{"operation": "read", "type": "doc",
			"resource": {"a": "v%d", "l": ["v%d", "x"], "id": %d}}`, i, i, i)))
		if err != nil {
			b.Fatalf("ReadBody: %v", err)
		}
	}
	b.ResetTimer()
	for b.Loop() {
		var shared Request
		SubjectOf(claims, false, DefaultSubjectRules).Apply(&shared)
		bulk, err := NewBulk(m, shared)
		if err != nil {
			b.Fatalf("NewBulk: %v", err)
		}
		for _, body := range bodies {
			in := bulk.Item(body)
			if _, err := pq.Eval(in.Context(context.Background()), rego.EvalParsedInput(in.Value())); err != nil {
				b.Fatalf("Eval: %v", err)
			}
		}
	}
}
