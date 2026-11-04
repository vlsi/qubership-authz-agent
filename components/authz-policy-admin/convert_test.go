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

package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"authz-agent/internal/policyir"
)

// The stub only earns its keep if what it serves is what the service reads
// back. The import of internal/policyir lives in a _test.go file on purpose:
// the shipped binary must not link the service's reader, otherwise the
// integration suites would compare the reader against itself, but the test
// may, and it is supposed to fail when the v3 wire shape changes.
func TestV3RoundTripThroughTheServiceReader(t *testing.T) {
	input := []simplifiedPolicy{
		{Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_ADMIN"}},
		{Component: "billing", ResourceType: "Invoice", Operation: "UPDATE", Roles: []any{"ROLE_ADMIN"}, Condition: "subject.tenantId == resource.tenantId"},
		{Component: "billing", ResourceType: "Invoice", Operation: "READ", Roles: []any{"ROLE_USER"}, RSQLPredicate: "ownerId==${subject.id}"},
		{Component: "billing", ResourceType: "Invoice", Operation: "LIST", Roles: []any{"ROLE_USER"}, Predicate: `Invoice.ownerId.eq("${subject.id}")`},
	}
	raw, err := json.Marshal(v3PolicySetsResponse{Hash: "deadbeef", PolicySets: toV3PolicySets(input)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	tree := readTree(t, raw, []byte(`{"pips": []}`), "billing")
	var got []string
	for _, set := range tree.Sets {
		for _, p := range set.Policies {
			for _, r := range p.Rules {
				got = append(got, format(p.Target)+" | "+format(r.Target)+" | "+format(r.Condition)+
					" | rsql="+r.Predicates.Text[policyir.DialectRSQL]+" | querydsl="+r.Predicates.Text[policyir.DialectQueryDSL])
			}
		}
	}
	slices.Sort(got)
	want := []string{
		`subject.roles CONTAINS "ROLE_ADMIN" | operation EQ "READ" |  | rsql= | querydsl=`,
		`subject.roles CONTAINS "ROLE_ADMIN" | operation EQ "UPDATE" | pip("subject.tenantId") EQ resource.tenantId | rsql= | querydsl=`,
		`subject.roles CONTAINS "ROLE_USER" | operation EQ "LIST" |  | rsql= | querydsl=Invoice.ownerId.eq("${subject.id}")`,
		`subject.roles CONTAINS "ROLE_USER" | operation EQ "READ" |  | rsql=ownerId==${subject.id} | querydsl=`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules read back =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// format is the condition c as the reader parsed it, "" for none.
func format(c *policyir.Condition) string {
	if c == nil {
		return ""
	}
	return policyir.FormatCondition(c)
}

func TestPIPRoundTripThroughTheServiceReader(t *testing.T) {
	input := []simplifiedPIP{
		{Name: "subject.tenant", PipType: "TOKEN", Claim: "tenant_id", Domain: "billing"},
		{Name: "subject.org", PipType: "HEADER", Header: "X-Org-Id", Domain: "billing"},
	}
	raw, err := json.Marshal(v3PIPsResponse{Hash: "deadbeef", PIPs: toV3PIPs(input)})
	if err != nil {
		t.Fatalf("marshal v3 envelope: %v", err)
	}

	tree := readTree(t, []byte(`{"policySets": []}`), raw, "billing")
	var got []string
	for _, p := range tree.PIPs {
		got = append(got, p.Name+" "+string(p.Type)+" "+p.Claim+p.Header)
	}
	want := []string{"subject.tenant TOKEN tenant_id", "subject.org HEADER X-Org-Id"}
	if !slices.Equal(got, want) {
		t.Errorf("PIPs read back = %q, want %q", got, want)
	}
}

// readTree reads the two documents as the service does and returns the tree
// of tenant, failing the test when the reader drops or fails anything.
func readTree(t *testing.T, policySets, pips []byte, tenant string) *policyir.Tree {
	t.Helper()
	export, err := policyir.FromRegular(policySets, pips)
	if err != nil {
		t.Fatalf("FromRegular: %v", err)
	}
	if len(export.Failed) != 0 || len(export.Orphans) != 0 || len(export.Dropped) != 0 {
		t.Fatalf("FromRegular failed %v, orphaned %v, dropped %v; want everything read", export.Failed, export.Orphans, export.Dropped)
	}
	tree := export.Trees[tenant]
	if tree == nil {
		t.Fatalf("FromRegular read tenants %v, want %s", export.Trees, tenant)
	}
	return tree
}

// TestRolesTarget_MultiRoleKeepsEveryRole pins the fidelity fix: the stub used
// to emit only the first role of a multi-role policy, so a multi-role defect
// was invisible to every test that runs against it. The round trip through the
// production converter is the assertion that matters.
func TestRolesTarget_MultiRoleKeepsEveryRole(t *testing.T) {
	got := rolesTarget("ROLE_A,ROLE_B,ROLE_C")
	want := "subject.roles CONTAINS ANY 'ROLE_A','ROLE_B','ROLE_C'"
	if got != want {
		t.Fatalf("rolesTarget: want %q got %q", want, got)
	}
}
