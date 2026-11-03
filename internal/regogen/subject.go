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
	"strconv"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regogen/spectables"
)

// ServiceIDClaim names the claim subject.id of a service account reads.
type ServiceIDClaim string

// The readings of subject.id for a service account.
const (
	// ServiceIDSame reads the claim sub, as for a user.
	ServiceIDSame ServiceIDClaim = "same"
	// ServiceIDClientID reads the claim client_id.
	ServiceIDClientID ServiceIDClaim = "client_id"
	// ServiceIDAzp reads the claim azp.
	ServiceIDAzp ServiceIDClaim = "azp"
	// ServiceIDClientIDEmpty reads the claim client_id, and the empty
	// string where the token has none.
	ServiceIDClientIDEmpty ServiceIDClaim = "client_id_empty"
)

// AnonymousID names what subject.id of an anonymous request reads.
type AnonymousID string

// The readings of subject.id for an anonymous request.
const (
	// AnonymousIDToken reads the id of the token's subject, as for a request
	// that is not anonymous.
	AnonymousIDToken AnonymousID = "token"
	// AnonymousIDSub reads the claim sub, whatever the token's subject is.
	AnonymousIDSub AnonymousID = "sub"
	// AnonymousIDNull gives subject.id the state NULL.
	AnonymousIDNull AnonymousID = "NULL"
)

// SubjectRules holds the readings of the subject that the legacy service's
// answers have not settled yet; every other reading is fixed.
type SubjectRules struct {
	// ServiceID is the knob subject_id_service_claim of the specification.
	ServiceID ServiceIDClaim
	// AnonymousID is the knob anonymous_subject_id of the specification.
	AnonymousID AnonymousID
}

// DefaultSubjectRules are the readings of the specification's agent profile.
var DefaultSubjectRules = SubjectRules{ServiceID: ServiceIDSame, AnonymousID: AnonymousIDToken}

// serviceAccountPrefix starts the preferred_username of a service account.
const serviceAccountPrefix = "service-account-"

// The keys of the subject's members ([Ref.Key]).
var (
	keySubjID             = specKey("subj", "id")
	keySubjName           = specKey("subj", "name")
	keySubjType           = specKey("subj", "type")
	keySubjServiceAccount = specKey("subj", "serviceAccount")
	keySubjScopes         = specKey("subj", "scopes")
	keySubjRoles          = specKey("subj", "roles")
)

// Subject is the subject of a request as a module reads it.
type Subject struct {
	// Values holds the value of subject.id, name, type, serviceAccount,
	// scopes, and roles, by [Ref.Key].
	Values map[string]Resolved
	// Roles holds the text of each role, which a simplified policy matches.
	Roles []string
	// M2M is the value of subject.isM2M.
	M2M bool
}

// SubjectOf reads the subject from the claims of its token. anonymous is set
// for a request that names an anonymous subject; choosing the token and
// checking it are the caller's.
//
// subject.id reads the claim sub, of a service account the claim
// rules.ServiceID names, of an anonymous request what rules.AnonymousID
// names; subject.name reads preferred_username. A list in either claim is
// its Java text, and an absent claim is NULL. A service account is a subject
// whose preferred_username starts with service-account- or whose claim level
// is m2m in any case; subject.type is SERVICE for it, USER for any other
// subject, and ANONYMOUS for an anonymous request. subject.serviceAccount is
// NULL. subject.scopes splits the claim scope at white space, and is PIP_NULL
// where the claim is not a string or holds no scope. subject.roles reads
// realm_access.roles: a string there is ERROR, and an empty list, any other
// value, or no such member is ABSENT.
// subject.isM2M holds for a subject of type SERVICE and for one whose claim
// level is m2m in any case.
func SubjectOf(claims *jsonvalue.Object, anonymous bool, rules SubjectRules) Subject {
	if claims == nil {
		claims = jsonvalue.NewObject()
	}
	t := token{claims: claims}
	s := Subject{Values: make(map[string]Resolved, 6)}
	s.Values[keySubjID] = t.id(anonymous, rules)
	s.Values[keySubjName] = t.scalar("preferred_username")
	typ := "USER"
	switch {
	case anonymous:
		typ = "ANONYMOUS"
	case t.service():
		typ = "SERVICE"
	}
	s.Values[keySubjType] = Resolved{State: spectables.StateValue, Value: typ}
	s.Values[keySubjServiceAccount] = Resolved{State: spectables.StateNull}
	s.Values[keySubjScopes] = t.scopes()
	roles := t.roles()
	s.Values[keySubjRoles] = roles
	if l, ok := roles.Value.([]jsonvalue.Value); ok {
		for _, r := range l {
			s.Roles = append(s.Roles, roleText(r))
		}
	}
	s.M2M = typ == "SERVICE" || t.levelM2M()
	return s
}

// Apply sets in req the subject's values, its roles, and subject.isM2M.
func (s Subject) Apply(req *Request) {
	if req.Values == nil {
		req.Values = map[string]Resolved{}
	}
	for k, v := range s.Values {
		req.Values[k] = v
	}
	req.Roles, req.M2M = s.Roles, s.M2M
}

type token struct{ claims *jsonvalue.Object }

func (t token) id(anonymous bool, rules SubjectRules) Resolved {
	if anonymous {
		switch rules.AnonymousID {
		case AnonymousIDNull:
			return Resolved{State: spectables.StateNull}
		case AnonymousIDSub:
			return t.scalar("sub")
		}
	}
	if !t.service() {
		return t.scalar("sub")
	}
	switch rules.ServiceID {
	case ServiceIDClientID, ServiceIDAzp:
		return t.scalar(string(rules.ServiceID))
	case ServiceIDClientIDEmpty:
		if _, ok := t.claims.Get("client_id"); !ok {
			return Resolved{State: spectables.StateValue, Value: ""}
		}
		return t.scalar("client_id")
	}
	return t.scalar("sub")
}

// scalar reads a claim that subject.id or subject.name reads.
func (t token) scalar(claim string) Resolved {
	v, ok := t.claims.Get(claim)
	if !ok {
		return Resolved{State: spectables.StateNull}
	}
	if l, ok := v.([]jsonvalue.Value); ok {
		return Resolved{State: spectables.StateValue, Value: legacyvalue.Text(l)}
	}
	return Resolved{State: spectables.StateValue, Value: v}
}

func (t token) service() bool {
	user, _ := t.claims.Get("preferred_username")
	if s, ok := user.(string); ok && strings.HasPrefix(s, serviceAccountPrefix) {
		return true
	}
	return t.levelM2M()
}

// levelM2M reports whether the claim level is the string m2m in any case.
func (t token) levelM2M() bool {
	level, _ := t.claims.Get("level")
	s, ok := level.(string)
	return ok && strings.ToLower(s) == "m2m"
}

func (t token) scopes() Resolved {
	v, _ := t.claims.Get("scope")
	s, _ := v.(string)
	scopes := strings.FieldsFunc(s, isPySpace)
	if len(scopes) == 0 {
		return Resolved{State: spectables.StatePIPNull}
	}
	l := make([]jsonvalue.Value, len(scopes))
	for i, x := range scopes {
		l[i] = x
	}
	return Resolved{State: spectables.StateValue, Value: l}
}

// isPySpace reports the characters at which the specification splits the
// claim scope: those of Python's str.split, which are Go's white space and
// the separators U+001C to U+001F.
func isPySpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f,
		0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func (t token) roles() Resolved {
	ra, _ := t.claims.Get("realm_access")
	var v jsonvalue.Value
	if o, ok := ra.(*jsonvalue.Object); ok {
		v, _ = o.Get("roles")
	}
	switch v := v.(type) {
	case string:
		return Resolved{State: spectables.StateError}
	case []jsonvalue.Value:
		if len(v) > 0 {
			return Resolved{State: spectables.StateValue, Value: v}
		}
	}
	return Resolved{State: spectables.StateAbsent}
}

// roleText is the text of a role that a simplified policy matches: a string
// as itself, a number as written, true, false, and null as Python prints
// them (True, False, None), and a list or an object as its Java text.
func roleText(v jsonvalue.Value) string {
	switch v := v.(type) {
	case string:
		return v
	case jsonvalue.Number:
		return string(v)
	case bool:
		return strings.ToUpper(strconv.FormatBool(v)[:1]) + strconv.FormatBool(v)[1:]
	case nil:
		return "None"
	}
	return legacyvalue.Text(v)
}
