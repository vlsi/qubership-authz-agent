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
	"slices"
	"testing"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// The expected values in this file are what the specification's agent profile
// reads from the same claims.

const (
	userClaims = `{"sub": "u1", "preferred_username": "alice", "scope": "openid profile",
		"realm_access": {"roles": ["r1", "R2"]}}`
	// a service account of a client without the scope that adds client_id
	serviceClaims = `{"sub": "generated-id", "preferred_username": "service-account-c", "azp": "c",
		"scope": "profile", "realm_access": {"roles": ["ROLE_M2M"]}}`
)

func claimsOf(t *testing.T, text string) *jsonvalue.Object {
	t.Helper()
	v, err := jsonvalue.Decode([]byte(text))
	if err != nil {
		t.Fatalf("jsonvalue.Decode(%s): %v", text, err)
	}
	return v.(*jsonvalue.Object)
}

func TestSubjectOfReadsTheMembersFromTheClaims(t *testing.T) {
	for _, tc := range []struct {
		name, claims string
		anonymous    bool
		member       string
		state        spectables.State
		value        string
	}{
		{"the id of a user", userClaims, false, "id", spectables.StateValue, `"u1"`},
		{"the name", userClaims, false, "name", spectables.StateValue, `"alice"`},
		{"the type of a user", userClaims, false, "type", spectables.StateValue, `"USER"`},
		{"the type of a service account", serviceClaims, false, "type", spectables.StateValue, `"SERVICE"`},
		{"the type of a user with level m2m", `{"preferred_username": "bob", "level": "M2M"}`, false, "type",
			spectables.StateValue, `"SERVICE"`},
		{"the type of a user with another level", `{"preferred_username": "bob", "level": "external"}`, false,
			"type", spectables.StateValue, `"USER"`},
		{"the type of an anonymous request", serviceClaims, true, "type", spectables.StateValue, `"ANONYMOUS"`},
		{"the service account", serviceClaims, false, "serviceAccount", spectables.StateNull, ""},
		{"the scopes", userClaims, false, "scopes", spectables.StateValue, `["openid","profile"]`},
		{"the roles", userClaims, false, "roles", spectables.StateValue, `["r1","R2"]`},
		{"an id claim that is a list", `{"sub": ["a", 1]}`, false, "id", spectables.StateValue, `"[a, 1]"`},
		{"an id claim that is a number", `{"sub": 5}`, false, "id", spectables.StateValue, `5`},
		{"no id claim", `{}`, false, "id", spectables.StateNull, ""},
		{"no name claim", `{}`, false, "name", spectables.StateNull, ""},
		{"scopes split at any white space", `{"scope": " a\tb\u001cc d "}`, false, "scopes",
			spectables.StateValue, `["a","b","c","d"]`},
		{"a blank scope claim", `{"scope": "  "}`, false, "scopes", spectables.StatePIPNull, ""},
		{"a scope claim that is a list", `{"scope": ["openid"]}`, false, "scopes", spectables.StatePIPNull, ""},
		{"roles that are a string", `{"realm_access": {"roles": "admin"}}`, false, "roles",
			spectables.StateError, ""},
		{"no role", `{"realm_access": {"roles": []}}`, false, "roles", spectables.StateAbsent, ""},
		{"no realm_access", `{}`, false, "roles", spectables.StateAbsent, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := SubjectOf(claimsOf(t, tc.claims), tc.anonymous, DefaultSubjectRules)
			got := s.Values[specKey("subj", tc.member)]
			value := ""
			if got.State == spectables.StateValue {
				value = jsonText(got.Value)
			}
			if got.State != tc.state || value != tc.value {
				t.Errorf("SubjectOf(%s, anonymous %v): %s = %s %s, want %s %s", tc.claims, tc.anonymous,
					tc.member, got.State, value, tc.state, tc.value)
			}
		})
	}
}

// subject.id of a service account and of an anonymous request depends on
// the knobs that the legacy service's answers have not settled; the claims
// of a service account lack client_id.
func TestSubjectOfReadsTheIDByTheRules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		rules     SubjectRules
		state     spectables.State
		value     string
	}{
		{"same", false, SubjectRules{ServiceIDSame, AnonymousIDToken}, spectables.StateValue, `"generated-id"`},
		{"client_id", false, SubjectRules{ServiceIDClientID, AnonymousIDToken}, spectables.StateNull, ""},
		{"azp", false, SubjectRules{ServiceIDAzp, AnonymousIDToken}, spectables.StateValue, `"c"`},
		{"client_id or empty", false, SubjectRules{ServiceIDClientIDEmpty, AnonymousIDToken},
			spectables.StateValue, `""`},
		{"anonymous as the token", true, SubjectRules{ServiceIDAzp, AnonymousIDToken}, spectables.StateValue,
			`"c"`},
		{"anonymous as sub", true, SubjectRules{ServiceIDAzp, AnonymousIDSub}, spectables.StateValue,
			`"generated-id"`},
		{"anonymous as null", true, SubjectRules{ServiceIDAzp, AnonymousIDNull}, spectables.StateNull, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SubjectOf(claimsOf(t, serviceClaims), tc.anonymous, tc.rules).Values[keySubjID]
			value := ""
			if got.State == spectables.StateValue {
				value = jsonText(got.Value)
			}
			if got.State != tc.state || value != tc.value {
				t.Errorf("SubjectOf(anonymous %v, %+v): id = %s %s, want %s %s", tc.anonymous, tc.rules,
					got.State, value, tc.state, tc.value)
			}
		})
	}
}

// subject.isM2M also holds for an anonymous request whose claim level is
// m2m, though its type is ANONYMOUS.
func TestSubjectOfReadsIsM2M(t *testing.T) {
	for _, tc := range []struct {
		name, claims string
		anonymous    bool
		want         bool
	}{
		{"a user", userClaims, false, false},
		{"a service account", serviceClaims, false, true},
		{"level m2m in upper case", `{"level": "M2M"}`, false, true},
		{"an anonymous service account", serviceClaims, true, false},
		{"an anonymous level m2m", `{"level": "m2m"}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SubjectOf(claimsOf(t, tc.claims), tc.anonymous, DefaultSubjectRules).M2M; got != tc.want {
				t.Errorf("SubjectOf(%s, anonymous %v).M2M = %v, want %v", tc.claims, tc.anonymous, got, tc.want)
			}
		})
	}
}

func TestSubjectOfReadsTheTextOfEachRole(t *testing.T) {
	s := SubjectOf(claimsOf(t, `{"realm_access": {"roles": ["a", 5, 1.5, true, null]}}`), false,
		DefaultSubjectRules)
	if want := []string{"a", "5", "1.5", "True", "None"}; !slices.Equal(s.Roles, want) {
		t.Errorf("SubjectOf().Roles = %q, want %q", s.Roles, want)
	}
}

// The module reads the subject that Apply puts into the request.
func TestSubjectApplyFeedsTheModule(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.type == 'SERVICE'"), table(t),
		DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, tc := range []struct {
		name, claims string
		want         bool
	}{
		{"a service account", serviceClaims, true},
		{"a user", userClaims, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Body: Body{Operation: "read", ResourceType: "doc"}}
			SubjectOf(claimsOf(t, tc.claims), false, DefaultSubjectRules).Apply(&req)
			if got := evalModule(t, m, req); got != tc.want {
				t.Errorf("allow = %v, want %v", got, tc.want)
			}
		})
	}
}
