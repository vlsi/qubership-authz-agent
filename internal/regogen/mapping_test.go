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
	"reflect"
	"testing"

	"authz-agent/internal/jsonvalue"
)

const keyPermissions = `["subj","permissions"]`

// permissionsOf generates the module of a set whose condition reads
// subject.permissions, with the PIPs pips declared, and returns the value
// ResolveSubject gives it for a subject with claims and headers.
func permissionsOf(t *testing.T, pips, claims string, headers map[string]string) Resolved {
	t.Helper()
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.permissions CONTAINS 'p1'", pips),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := Request{Headers: headers, Claims: mustDecode(t, claims).(*jsonvalue.Object)}
	SubjectOf(req.Claims, false, DefaultSubjectRules).Apply(&req)
	if unread := m.ResolveSubject(&req); len(unread) != 0 {
		t.Errorf("ResolveSubject left %v unread, want none", unread)
	}
	return req.Values[keyPermissions]
}

func mapping(custom, product string) string {
	return `{"name": "subject.permissions", "pipType": "MAPPING", "customMapping": ` + custom +
		`, "productMapping": ` + product + `}`
}

func roles(list string) string { return `{"realm_access": {"roles": ` + list + `}}` }

func TestResolveSubject_ComputesPermissionsFromTheMappingTables(t *testing.T) {
	for _, tc := range []struct {
		name, pips, claims string
		headers            map[string]string
		want               Resolved
	}{
		{"a role grants its permissions, compared ignoring case",
			mapping(`{"subject.roles": {"admin": ["p1", "p2"], "viewer": ["p3"]}}`, `null`), roles(`["ADMIN"]`), nil,
			resolved(t, "VALUE", `["p1", "p2"]`)},
		{"a permission granted twice is listed once, in the order of the tables",
			mapping(`{"subject.roles": {"a": ["p1", "p2"], "b": ["p2", "p3"]}}`, `null`), roles(`["b", "a"]`), nil,
			resolved(t, "VALUE", `["p1", "p2", "p3"]`)},
		{"a HEADER PIP key",
			`{"name": "subject.region", "pipType": "HEADER", "header": "X-Region"}, ` +
				mapping(`{"subject.region": {"eu": ["p-eu"]}}`, `null`),
			roles(`["r"]`), map[string]string{"x-region": "eu"}, resolved(t, "VALUE", `["p-eu"]`)},
		{"a TOKEN PIP key",
			`{"name": "subject.dept", "pipType": "TOKEN", "claim": "dept"}, ` +
				mapping(`{"subject.dept": {"d1": ["p-d1"]}}`, `null`),
			`{"dept": "d1"}`, nil, resolved(t, "VALUE", `["p-d1"]`)},
		{"productMapping counts without a customMapping",
			mapping(`null`, `{"subject.roles": {"r": ["p-product"]}}`), roles(`["r"]`), nil,
			resolved(t, "VALUE", `["p-product"]`)},
		{"productMapping does not count beside an empty customMapping",
			mapping(`{}`, `{"subject.roles": {"r": ["p-product"]}}`), roles(`["r"]`), nil,
			Resolved{State: "EMPTY_COLL"}},
		{"a key naming an undeclared PIP grants nothing and fails nothing",
			mapping(`{"subject.nope": {"x": ["p-nope"]}, "subject.roles": {"r": ["p1"]}}`, `null`), roles(`["r"]`), nil,
			resolved(t, "VALUE", `["p1"]`)},
		{"no role the table names", mapping(`{"subject.roles": {"admin": ["p1"]}}`, `null`), roles(`["other"]`), nil,
			Resolved{State: "EMPTY_COLL"}},
		{"an empty role list grants nothing", mapping(`{"subject.roles": {"admin": ["p1"]}}`, `null`), roles(`[]`), nil,
			Resolved{State: "EMPTY_COLL"}},
		{"a role claim that is a string fails the whole value",
			mapping(`{"subject.roles": {"admin": ["p1"]}}`, `null`), roles(`"admin"`), nil, Resolved{State: "ERROR"}},
		{"productMapping does not count beside another PIP's customMapping",
			mapping(`{"subject.roles": {"r": ["p1"]}}`, `null`) + `, {"name": "subject.other", "pipType": "MAPPING", ` +
				`"customMapping": null, "productMapping": {"subject.roles": {"r": ["p-product"]}}}`,
			roles(`["r"]`), nil, resolved(t, "VALUE", `["p1"]`)},
		{"a customMapping that is a non-empty list grants nothing and turns productMapping off",
			mapping(`["x"]`, `{"subject.roles": {"r": ["p-product"]}}`), roles(`["r"]`), nil, Resolved{State: "EMPTY_COLL"}},
		{"a key naming a GENERAL PIP fails the whole value",
			`{"name": "subject.remote", "pipType": "GENERAL", "url": "http://pip"}, ` +
				mapping(`{"subject.remote": {"x": ["p-x"]}, "subject.roles": {"r": ["p1"]}}`, `null`),
			roles(`["r"]`), nil, Resolved{State: "ERROR"}},
		{"a key on the permission scope fails the whole value",
			mapping(`{"subject.permissionScope.domain": {"d": ["p-d"]}, "subject.roles": {"r": ["p1"]}}`, `null`),
			roles(`["r"]`), nil, Resolved{State: "ERROR"}},
		{"no MAPPING PIP", ``, roles(`["admin"]`), nil, Resolved{State: "ABSENT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := permissionsOf(t, tc.pips, tc.claims, tc.headers); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("subject.permissions = %+v, want %+v", got, tc.want)
			}
		})
	}
}
