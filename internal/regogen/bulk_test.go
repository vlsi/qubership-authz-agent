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
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

// bulkCondition reads the subject in a group, resource paths read before the
// query and lazily, null, and the operation.
const bulkCondition = "subject.type == 'SERVICE' AND resource.a == 'x' OR resource.l[0] == 'x' OR null == 'x' " +
	"OR operation == 'WRITE'"

// The items are projected one after another from one Bulk, so an item that
// kept a record of the item before it differs from its request alone.
func TestBulkItemIsTheInputOfItsRequestAlone(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", bulkCondition), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	subject := SubjectOf(claimsOf(t, serviceClaims), false, DefaultSubjectRules)
	var shared Request
	subject.Apply(&shared)
	bulk, err := NewBulk(m, shared)
	if err != nil {
		t.Fatalf("NewBulk: %v", err)
	}
	for _, body := range []string{
		`{"operation": "read", "type": "doc", "resource": {"a": "x", "null": 1}}`,
		`{"operation": "write", "resourceType": "doc"}`,
		`{"operation": "read", "type": "doc", "resource": {"l": ["x"]}}`,
		`{"resource": null}`,
	} {
		b, err := ReadBody([]byte(body))
		if err != nil {
			t.Fatalf("ReadBody(%s): %v", body, err)
		}
		alone := Request{Body: b}
		subject.Apply(&alone)
		m.Resolve(b, alone.Values)
		want, err := Project(m, alone)
		if err != nil {
			t.Fatalf("Project(%s): %v", body, err)
		}
		if got, want := bulk.Item(b).Value(), want.Value(); got.Compare(want) != 0 {
			t.Errorf("Item(%s).Value() =\n%v\nwant\n%v", body, got, want)
		}
	}
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
