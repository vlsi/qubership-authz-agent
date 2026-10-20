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

package paritysuite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-agent/test/parity/suite/model"

	"github.com/google/go-cmp/cmp"
)

// The expected ids in these tests are the derivation derivedID documents,
// computed outside Go, and the expected wire forms follow the rules the README
// states under "Cases kept as data"; neither is output of the code under test.

func stringOf(v string) *string { return &v }

func boolOf(v bool) *bool { return &v }

func TestDerivedID_IsTheFirst16BytesOfTheSHA256OfThePath(t *testing.T) {
	if got, want := derivedID("c1", "set/outer"), "d82b5a69-4822-465d-d804-1c9317bcfe92"; got != want {
		t.Errorf(`derivedID("c1", "set/outer") = %s, want %s`, got, want)
	}
}

func TestCustomEntry_RenamesTheUploadMembersAndSendsTheRestAsWritten(t *testing.T) {
	entry := map[string]any{
		"key":       "outer",
		"algorithm": "DENY_OVERRIDES",
		"iterate":   map[string]any{"foreach": "subject.permissionScope", "algorithm": "PERMIT_OVERRIDES"},
		"target":    "resourceType == '{{resourceType}}'",
		"policies": []any{map[string]any{"key": "p", "rules": []any{map[string]any{
			"key": "r", "predicates": map[string]any{"rsqlPredicate": "a==b"}, "status": "INACTIVE",
		}}}},
		"sets": "x",
	}
	want := map[string]any{
		"policySetId":        "d82b5a69-4822-465d-d804-1c9317bcfe92",
		"combiningAlgorithm": "DENY_OVERRIDES",
		"iterate":            map[string]any{"foreach": "subject.permissionScope", "combiningAlgorithm": "PERMIT_OVERRIDES"},
		"target":             "resourceType == 'RT'",
		"policies": []any{map[string]any{"policyId": "e7852720-9add-579c-e70a-d2e16a6b9cbe", "rules": []any{map[string]any{
			"ruleId": "bdda613b-c5b4-68b9-be02-a936accd128e", "rsqlPredicate": "a==b", "status": "INACTIVE",
		}}}},
		"policySets": "x",
	}
	if diff := cmp.Diff(want, customEntry("c1", "c0", "set", entry, "RT")); diff != "" {
		t.Errorf(`customEntry("c1", ruleIDsOf "c0") mismatch (-want +got):\n%s`, diff)
	}
}

func TestCustomEntry_DerivesRuleIDsFromTheCaseWithoutRuleIDsOf(t *testing.T) {
	got := customEntry("c1", "", "rule", map[string]any{"key": "r"}, "RT")
	want := map[string]any{"ruleId": "15d6b792-eff3-7653-87a2-fa96a7209fb5"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf(`customEntry("c1", rule r) mismatch (-want +got):\n%s`, diff)
	}
}

func TestCustomEntry_SendsAnEntryThatIsNotAnObjectAsWritten(t *testing.T) {
	if got := customEntry("c1", "", "set", json.Number("5"), "RT"); got != json.Number("5") {
		t.Errorf(`customEntry("c1", 5) = %v, want 5`, got)
	}
}

// The cleanup deletes each level and set once, at a step's own level when it
// is PROJECT or CUSTOMER and at both otherwise, and skips an entry that is not
// an object, since it names no set. Each group is lower level first, also when
// a CUSTOMER step comes first, so the runner, which sends it backward, deletes
// at CUSTOMER first.
func TestCustomizationCleanup_DeletesEachSetAndPIPOnceAtTheLevelsOfItsSteps(t *testing.T) {
	steps := []customizeStep{
		{Name: "upper-level", Level: stringOf("CUSTOMER"), Sets: []any{map[string]any{"key": "outer"}}},
		{Name: "own-level", Level: stringOf("PROJECT"), Sets: []any{map[string]any{"key": "outer"}, json.Number("5")}},
		{Name: "other-level", Level: stringOf("PARITY_OTHER"), Sets: []any{map[string]any{"key": "outer"}},
			PIPs: []any{map[string]any{"name": "subject.{{resourceType}}"}}},
		{Name: "no-level", Level: stringOf("PROJECT"), OmitLevel: true, Sets: []any{map[string]any{"key": "outer"}}},
	}
	set := "/access/v1/config/customization/policySet/d82b5a69-4822-465d-d804-1c9317bcfe92"
	pip := "/access/v1/pip/customization/pip/subject.RT"
	want := []papCall{
		{method: http.MethodDelete, path: set, query: url.Values{"level": {"PROJECT"}, "recursive": {"true"}}},
		{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}, "recursive": {"true"}}},
		{method: http.MethodDelete, path: pip, query: url.Values{"level": {"PROJECT"}}},
		{method: http.MethodDelete, path: pip, query: url.Values{"level": {"CUSTOMER"}}},
	}
	if diff := cmp.Diff(want, customizationCleanup("c1", steps, "RT"), cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("customizationCleanup mismatch (-want +got):\n%s", diff)
	}
}

func TestCustomizeStepCall(t *testing.T) {
	set := "/access/v1/config/customization/policySet/d82b5a69-4822-465d-d804-1c9317bcfe92"
	cases := []struct {
		name       string
		step       customizeStep
		want       papCall
		wantGolden ParityEndpointID
	}{
		{"an import sends the entries Sets builds",
			customizeStep{Level: stringOf("CUSTOMER"), Sets: []any{map[string]any{"key": "outer"}}},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{"level": {"CUSTOMER"}},
				body: []any{map[string]any{"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92"}}},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"body replaces the entries Sets builds",
			customizeStep{Level: stringOf("CUSTOMER"), Sets: []any{map[string]any{"key": "outer"}}, Body: json.RawMessage(`{}`)},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{"level": {"CUSTOMER"}},
				body: json.RawMessage(`{}`)},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"omitLevel sends no level",
			customizeStep{Level: stringOf("CUSTOMER"), OmitLevel: true},
			papCall{method: http.MethodPost, path: "/access/v1/config/customization/import", query: url.Values{}, body: []any{}},
			PSUITE_IMPORT_CUSTOMIZATION},
		{"a PIP import sends the entries with the placeholders replaced",
			customizeStep{Level: stringOf("PROJECT"), PIPs: []any{map[string]any{"name": "subject.{{resourceType}}"}}},
			papCall{method: http.MethodPost, path: "/access/v1/pip/customization/import", query: url.Values{"level": {"PROJECT"}},
				body: []any{map[string]any{"name": "subject.RT"}}},
			PSUITE_IMPORT_PIP_CUSTOMIZATION},
		{"a delete without recursive sends no recursive",
			customizeStep{Level: stringOf("CUSTOMER"), Delete: &customizeDelete{Key: "outer"}},
			papCall{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}}},
			PSUITE_DELETE_CUSTOMIZATION},
		{"a delete with recursive false sends it",
			customizeStep{Level: stringOf("CUSTOMER"), Delete: &customizeDelete{Key: "outer", Recursive: boolOf(false)}},
			papCall{method: http.MethodDelete, path: set, query: url.Values{"level": {"CUSTOMER"}, "recursive": {"false"}}},
			PSUITE_DELETE_CUSTOMIZATION},
		{"pipBody is sent in place of the list, with the placeholders replaced",
			customizeStep{Level: stringOf("CUSTOMER"), PIPBody: json.RawMessage(`{"name":"subject.{{resourceType}}","cachePeriod":5}`)},
			papCall{method: http.MethodPost, path: "/access/v1/pip/customization/import", query: url.Values{"level": {"CUSTOMER"}},
				body: map[string]any{"name": "subject.RT", "cachePeriod": json.Number("5")}},
			PSUITE_IMPORT_PIP_CUSTOMIZATION},
		{"a PIP delete sends the PIP's name, and omitLevel no level",
			customizeStep{Level: stringOf("CUSTOMER"), OmitLevel: true, Delete: &customizeDelete{PIP: "subject.{{resourceType}}"}},
			papCall{method: http.MethodDelete, path: "/access/v1/pip/customization/pip/subject.RT", query: url.Values{}},
			PSUITE_DELETE_PIP_CUSTOMIZATION},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, golden := customizeStepCall("c1", "", tc.step, "RT")
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(papCall{})); diff != "" {
				t.Errorf("customizeStepCall mismatch (-want +got):\n%s", diff)
			}
			if golden != tc.wantGolden {
				t.Errorf("customizeStepCall golden = %s, want %s", Meta(golden).GoldenDir, Meta(tc.wantGolden).GoldenDir)
			}
		})
	}
}

// An item keeps a type it names, null included, and takes the case's
// resource type only where it names none.
func TestBulkItems_DefaultsOnlyAnAbsentType(t *testing.T) {
	items := []any{
		map[string]any{"id": "a", "resource": map[string]any{"id": "{{resourceType}}"}},
		map[string]any{"id": "b", "type": "OTHER"},
		map[string]any{"id": "c", "type": nil},
	}
	want := []any{
		map[string]any{"id": "a", "type": "RT", "resource": map[string]any{"id": "RT"}},
		map[string]any{"id": "b", "type": "OTHER"},
		map[string]any{"id": "c", "type": nil},
	}
	if diff := cmp.Diff(want, bulkItems(items, "RT")); diff != "" {
		t.Errorf("bulkItems mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeFields_ReplacesAddsAndNullsMembers(t *testing.T) {
	object := map[string]any{"status": "ACTIVE", "target": "true"}
	mergeFields(object, map[string]any{"status": nil, "target": "resourceType == '{{resourceTypeLowerCase}}'", "extra": true}, "RT")
	want := map[string]any{"status": nil, "target": "resourceType == 'rt'", "extra": true}
	if diff := cmp.Diff(want, object); diff != "" {
		t.Errorf("mergeFields mismatch (-want +got):\n%s", diff)
	}
}

// Only the first call on the route counts, and a header value is replaced by
// a label wherever it would put a token or the tenant into a golden.
func TestForwardedHeaders(t *testing.T) {
	sent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": "Bearer user-token"}
	calls := []PipStubCall{
		{Path: "/other", Headers: map[string]string{"x-a": "from another route"}},
		{Path: "/pip", Headers: map[string]string{
			"x-a":            "va",
			"authorization":  "Bearer m2m-token",
			"incoming-token": "bearer user-token",
			"x-copy":         "m2m-token",
			"x-auth-other":   "Bearer elsewhere",
			"tenant":         "default",
		}},
		{Path: "/pip", Headers: map[string]string{"x-b": "from the second call"}},
	}
	got := forwardedHeaders(calls, "/pip", []string{"X-A", "x-b", "authorization", "incoming-token", "x-copy", "tenant"}, sent, "default")
	want := map[string]any{
		"x-a":            "va",
		"x-b":            nil,
		"authorization":  "<m2m token>",
		"incoming-token": "<user token>",
		"x-copy":         "<m2m token>",
		"tenant":         "<tenant_id>",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

// A user-management-call golden lists every call in order, keeps the request
// target as sent, lists every header name, and holds the value only of the
// headers whose value repeats from run to run, a token or the tenant labeled.
func TestUserManagementCallOutcome(t *testing.T) {
	sent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": "Bearer user-token"}
	userID := "u 1"
	calls := []PipStubCall{
		{Method: "GET", Path: "/users/u 1", RequestURI: "/users/u%201?expand=roles", BodyRaw: "", Headers: map[string]string{
			"authorization": jwt(map[string]any{"preferred_username": "service-account-ac", "sub": "s",
				"iss": "http://idp.parity.svc/auth/realms/parity"}),
			"tenant":       "default",
			"accept":       "application/json",
			"x-request-id": "differs on every run",
		}},
		{Method: "POST", Path: "/users", RequestURI: "/users", BodyRaw: `{"id":"u 1"}`, Headers: map[string]string{
			"incoming-token": "Bearer user-token",
			"tenant":         "tenant-b",
			"content-type":   "application/json",
		}},
	}
	got := userManagementCallOutcome(calls, sent, "default", &userID)
	want := &model.UserManagementCallOutcome{Calls: []model.UserManagementCall{
		{Method: "GET", RequestURI: "/users/u%201?expand=roles",
			HeaderNames: []string{"accept", "authorization", "tenant", "x-request-id"},
			Headers: map[string]any{"accept": "application/json", "authorization": "<service account>",
				"authorization:issuer": "<idp>", "tenant": "<tenant_id>"}},
		{Method: "POST", RequestURI: "/users", Body: `{"id":"u 1"}`,
			HeaderNames: []string{"content-type", "incoming-token", "tenant"},
			Headers:     map[string]any{"content-type": "application/json", "incoming-token": "<user token>", "tenant": "tenant-b"}},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("userManagementCallOutcome mismatch (-want +got):\n%s", diff)
	}
}

// A request that made no call records an empty list, not null, so that the
// golden tells it from a log nobody read.
func TestUserManagementCallOutcome_NoCall(t *testing.T) {
	got, err := json.Marshal(userManagementCallOutcome(nil, map[string]string{}, "default", nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"calls":[]}` {
		t.Errorf("userManagementCallOutcome(no calls) = %s, want {\"calls\":[]}", got)
	}
}

func TestUserManagementTokenLabel(t *testing.T) {
	user := jwt(map[string]any{"sub": "sub-of-the-reader", "preferred_username": "parity-reader"})
	sent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": user}
	userID := "sub-asked-for"
	cases := []struct {
		name, value, want string
	}{
		{"the request's Authorization", "m2m-token", "<m2m token>"},
		{"the request's Incoming-Token", user, "<user token>"},
		{"a service account's token", jwt(map[string]any{"sub": "x", "preferred_username": "service-account-ac"}), "<service account>"},
		{"another token of the request's user", jwt(map[string]any{"sub": "sub-of-the-reader", "azp": "other"}), "<the request's user>"},
		{"a token of the user asked for", jwt(map[string]any{"sub": "sub-asked-for"}), "<the user asked for>"},
		{"a token of another user", jwt(map[string]any{"sub": "someone"}), "<another user>"},
		{"no JWT", "Basic dXNlcjpwYXNz", "<not a token>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := userManagementTokenLabel(tc.value, sent, &userID); got != tc.want {
				t.Errorf("userManagementTokenLabel(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestForwardedHeaders_LabelsAnotherTokenAndAnotherTenant(t *testing.T) {
	calls := []PipStubCall{{Path: "/pip", Headers: map[string]string{"authorization": "Bearer elsewhere", "tenant": "tenant-b"}}}
	got := forwardedHeaders(calls, "/pip", []string{"authorization", "tenant"}, map[string]string{"authorization": "Bearer m2m-token"}, "default")
	want := map[string]any{"authorization": "<other token>", "tenant": "<other>"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

// tokenIssuer classes a token by its claims: a kubernetes.io member marks a
// pod's projected service account token, an iss that names a Keycloak realm
// the stand's IdP, and any other JWT is <other>.
func TestTokenIssuer(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
	}{
		{"a pod's projected token", jwt(map[string]any{"iss": "https://kubernetes.default.svc.cluster.local",
			"kubernetes.io": map[string]any{"namespace": "parity"}}), "<kubernetes>"},
		{"a kubernetes.io member beside a realm issuer", jwt(map[string]any{"iss": "http://idp/auth/realms/parity",
			"kubernetes.io": map[string]any{}}), "<kubernetes>"},
		{"a realm of the IdP", jwt(map[string]any{"iss": "http://idp.parity.svc/auth/realms/parity"}), "<idp>"},
		{"another realm of the IdP", jwt(map[string]any{"iss": "https://idp.example/realms/parity-mt-b"}), "<idp>"},
		{"a path below a realm", jwt(map[string]any{"iss": "http://idp/auth/realms/parity/protocol"}), "<other>"},
		{"a realm without a name", jwt(map[string]any{"iss": "http://idp/auth/realms/"}), "<other>"},
		{"an issuer that is no realm", jwt(map[string]any{"iss": "https://issuer.example/oauth2"}), "<other>"},
		{"a JWT without iss", jwt(map[string]any{"sub": "s"}), "<other>"},
		{"no JWT", "Bearer opaque", "<not a token>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenIssuer(tc.value); got != tc.want {
				t.Errorf("tokenIssuer(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// The pseudo-header authorization:issuer records the issuer of the call's
// Authorization, and null when the call carried none.
func TestForwardedHeaders_ClassesTheIssuerOfTheToken(t *testing.T) {
	pod := jwt(map[string]any{"iss": "https://kubernetes.default.svc", "kubernetes.io": map[string]any{}})
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    any
	}{
		{"a call with a pod's token", map[string]string{"authorization": pod}, "<kubernetes>"},
		{"a call without Authorization", map[string]string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []PipStubCall{{Path: "/pip", Headers: tc.headers}}
			got := forwardedHeaders(calls, "/pip", []string{"Authorization:Issuer"}, map[string]string{}, "default")
			if diff := cmp.Diff(map[string]any{"authorization:issuer": tc.want}, got); diff != "" {
				t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// jwt returns a token whose payload holds claims, with a signature nothing
// checks, as the Authorization of a PIP call carries it.
func jwt(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return "Bearer e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// The pseudo-header authorization:subject records whose token the call
// carried by its claims: a service account by its preferred_username, the
// request's user by the sub of the Incoming-Token, any other subject as
// another user. The token itself never reaches the golden.
func TestForwardedHeaders_ClassesTheSubjectOfTheToken(t *testing.T) {
	incoming := jwt(map[string]any{"sub": "u-1", "preferred_username": "parity-reader"})
	sent := map[string]string{"authorization": jwt(map[string]any{"sub": "s-1", "preferred_username": "service-account-parity-m2m"}),
		"incoming-token": incoming}
	for _, tc := range []struct {
		name, authorization string
		want                any
	}{
		{"the service's own token", jwt(map[string]any{"sub": "s-2", "preferred_username": "service-account-access-control"}),
			"<service account>"},
		{"the request's M2M token", sent["authorization"], "<service account>"},
		{"the request's user token", incoming, "<the request's user>"},
		{"another token of the request's user", jwt(map[string]any{"sub": "u-1", "azp": "exchanged"}), "<the request's user>"},
		{"a token of another user", jwt(map[string]any{"sub": "u-2", "preferred_username": "parity-other"}), "<another user>"},
		{"no JWT", "Bearer opaque", "<not a token>"},
		{"a JWT without sub", jwt(map[string]any{"preferred_username": "parity-reader"}), "<not a token>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []PipStubCall{{Path: "/pip", Headers: map[string]string{"authorization": tc.authorization}}}
			got := forwardedHeaders(calls, "/pip", []string{"Authorization:Subject"}, sent, "default")
			if diff := cmp.Diff(map[string]any{"authorization:subject": tc.want}, got); diff != "" {
				t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
			}
		})
	}
	got := forwardedHeaders([]PipStubCall{{Path: "/pip", Headers: map[string]string{}}}, "/pip", []string{authorizationSubject}, sent, "default")
	if diff := cmp.Diff(map[string]any{"authorization:subject": nil}, got); diff != "" {
		t.Errorf("forwardedHeaders of a call without Authorization mismatch (-want +got):\n%s", diff)
	}
}

// A case names its subject as m2m or user:<username>, either one optionally
// followed by @<client> with a client of
// testdata/realm-clients/token-subject-clients.json; any
// other subject is a problem of the file.
func TestSubjectProblem_TakesOnlyTheSubjectsTheRunnerCanSend(t *testing.T) {
	for _, tc := range []struct {
		name, subject string
		refused       bool
	}{
		{"no subject", "", false},
		{"the M2M token", "m2m", false},
		{"a realm user", "user:parity-reader", false},
		{"a service account of a token-subject client", "m2m@parity-ts-bare", false},
		{"a user through a token-subject client", "user:parity-reader@parity-ts-arrays", false},
		{"a user without a name", "user:", true},
		{"a user without a name through a client", "user:@parity-ts-bare", true},
		{"another kind of subject", "admin", true},
		{"a client outside token-subject-clients.json", "m2m@parity-end-user", true},
		{"a user through a client outside token-subject-clients.json", "user:parity-reader@parity-m2m", true},
		{"a service account of a client that has none", "m2m@parity-ts-arrays", true},
		{"a service account without a client", "m2m@", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problem := subjectProblem(tc.subject)
			if (problem != "") != tc.refused {
				t.Errorf("subjectProblem(%q) = %q, want a problem: %v", tc.subject, problem, tc.refused)
			}
		})
	}
}

// The table of token-subject clients names the clients of the realm file, each
// with the service account the file gives it and the secret the file declares.
func TestTokenSubjectClients_MatchTheRealmFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/realm-clients/token-subject-clients.json")
	if err != nil {
		t.Fatal(err)
	}
	var clients []struct {
		ClientID               string `json:"clientId"`
		Secret                 string `json:"secret"`
		ServiceAccountsEnabled bool   `json:"serviceAccountsEnabled"`
	}
	if err := json.Unmarshal(raw, &clients); err != nil {
		t.Fatal(err)
	}
	inFile := map[string]bool{}
	for _, c := range clients {
		inFile[c.ClientID] = c.ServiceAccountsEnabled
		if c.Secret != tokenSubjectSecret {
			t.Errorf("client %s declares the secret %q, want tokenSubjectSecret %q", c.ClientID, c.Secret, tokenSubjectSecret)
		}
	}
	if diff := cmp.Diff(inFile, tokenSubjectClients); diff != "" {
		t.Errorf("tokenSubjectClients mismatch with the realm file (-file +table):\n%s", diff)
	}
}

// wellFormedCaseFile returns a file caseFileProblems accepts: a case without
// sets and a case with sets and one customize step, each with one request.
func wellFormedCaseFile() caseFile {
	return caseFile{
		Pins: map[string]PipStubResponse{"/pip": {StatusCode: http.StatusOK}},
		Cases: []caseSpec{
			{ID: "iso", Requests: []requestSpec{{Name: "read"}}},
			{ID: "reg", Sets: []setSpec{{Key: "outer"}}, Requests: []requestSpec{{Name: "read"}},
				Customize: []customizeStep{{Name: "step", Level: stringOf("CUSTOMER"),
					Sets: []any{map[string]any{"key": "outer"}}, Requests: []requestSpec{{Name: "after"}}}}},
		},
	}
}

// An entry that is not an object names no PIP, so the cleanup deletes only the
// PIPs the other entries name.
func TestCustomizationCleanup_SkipsAPIPEntryThatIsNotAnObject(t *testing.T) {
	steps := []customizeStep{{Name: "import", Level: stringOf("CUSTOMER"),
		PIPs: []any{"not an object", map[string]any{"name": "subject.a"}}}}
	want := []papCall{{method: http.MethodDelete, path: "/access/v1/pip/customization/pip/subject.a",
		query: url.Values{"level": {"CUSTOMER"}}}}
	if diff := cmp.Diff(want, customizationCleanup("c1", steps, "RT"), cmp.AllowUnexported(papCall{})); diff != "" {
		t.Errorf("customizationCleanup mismatch (-want +got):\n%s", diff)
	}
}

// pipBody names the PIPs it customizes as pips does, whether it holds one entry
// or a list of them, so the cleanup deletes those PIPs; a body that is neither
// names none.
func TestCustomizationCleanup_DeletesThePIPsPIPBodyNames(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"one entry", `{"name":"subject.a"}`, []string{"subject.a"}},
		{"a list", `[{"name":"subject.a"},"not an object",{"name":"subject.b"}]`, []string{"subject.a", "subject.b"}},
		{"a string", `"subject.a"`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps := []customizeStep{{Name: "import", Level: stringOf("CUSTOMER"), PIPBody: json.RawMessage(tc.body)}}
			var want []papCall
			for _, name := range tc.want {
				want = append(want, papCall{method: http.MethodDelete, path: "/access/v1/pip/customization/pip/" + name,
					query: url.Values{"level": {"CUSTOMER"}}})
			}
			if diff := cmp.Diff(want, customizationCleanup("c1", steps, "RT"), cmp.AllowUnexported(papCall{})); diff != "" {
				t.Errorf("customizationCleanup mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCaseFileProblems(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *caseFile)
		want   string
	}{
		{"a well-formed file", func(*caseFile) {}, ""},
		{"policy on a case with sets", func(f *caseFile) { f.Cases[1].Policy = map[string]any{} },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"customize on a case without sets", func(f *caseFile) { f.Cases[0].Customize = []customizeStep{} },
			"case iso sets customize"},
		{"status beside omitStatus", func(f *caseFile) { f.Cases[1].Sets[0].Status = "INACTIVE"; f.Cases[1].Sets[0].OmitStatus = true },
			"case reg set outer sets both status and omitStatus"},
		{"a step request named as a case request", func(f *caseFile) { f.Cases[1].Customize[0].Requests[0].Name = "read" },
			"case reg has two requests named read"},
		{"two steps with one name", func(f *caseFile) {
			f.Cases[1].Customize = append(f.Cases[1].Customize, customizeStep{Name: "step", OmitLevel: true})
		},
			`case reg has a customize step named "step"`},
		{"a step with no level", func(f *caseFile) { f.Cases[1].Customize[0].Level = nil },
			"case reg step step names no level"},
		{"a step with sets and pips", func(f *caseFile) { f.Cases[1].Customize[0].PIPs = []any{map[string]any{"name": "subject.a"}} },
			"case reg step step sets more than one of delete, pips or pipBody, and sets or body"},
		{"a PIP customization with no name", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPs = []any{map[string]any{"status": "INACTIVE"}}
		}, "imports a PIP customization map[status:INACTIVE] with no name"},
		{"a PIP customization entry that is not an object", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPs = []any{"not an object", map[string]any{"name": "subject.a"}}
		}, ""},
		{"omitFields in a customization entry", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "omitFields": []any{"target"}}}
		}, "case reg step step has a set entry with omitFields, which only an upload reads"},
		{"a nested entry with no key", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "policies": []any{map[string]any{}}}}
		}, "case reg step step has a policy entry with no key"},
		{"an iterate with no algorithm", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "iterate": map[string]any{"foreach": "x"}}}
		}, "has a set entry whose iterate is not an object with foreach and algorithm"},
		{"a case with no request", func(f *caseFile) { f.Cases[0].Requests = nil }, ""},
		{"omitOperation on a filter request", func(f *caseFile) {
			f.Cases[0].Requests[0].Filter = true
			f.Cases[0].Requests[0].OmitOperation = true
		}, ""},
		{"omitOperation on a check request", func(f *caseFile) { f.Cases[0].Requests[0].OmitOperation = true },
			"case iso request read sets omitOperation, which only a filter request"},
		{"omitOperation beside an operation", func(f *caseFile) {
			f.Cases[0].Requests[0].Filter = true
			f.Cases[0].Requests[0].Operation = "LIST"
			f.Cases[0].Requests[0].OmitOperation = true
		}, "case iso request read sets omitOperation, which only a filter request"},
		{"pipCalls of a case on a pinned route", func(f *caseFile) { f.Cases[1].PIPCalls = "/pip" }, ""},
		{"pipCalls of a case on a route the file does not pin", func(f *caseFile) { f.Cases[0].PIPCalls = "/other" },
			"case iso records the calls to /other, which nothing pins before it"},
		{"pipCalls of a case beside a request that clears the log", func(f *caseFile) {
			f.Cases[1].PIPCalls = "/pip"
			f.Cases[1].Requests[0].PIPCalls = "/pip"
		}, "case reg records the calls of the whole case, and its request read clears the call log"},
		{"classifyBy on a case without sets", func(f *caseFile) { f.Cases[0].Requests[0].ClassifyBy = "/pip" }, ""},
		{"classifyBy on a route the case pins", func(f *caseFile) {
			f.Cases[0].Pins = map[string]PipStubResponse{"/case": {StatusCode: http.StatusOK}}
			f.Cases[0].Requests[0].ClassifyBy = "/case"
		}, ""},
		{"readsRoutes of a request on a route the request pins", func(f *caseFile) {
			f.Cases[0].Requests[0].Pins = map[string]PipStubResponse{"/request": {StatusCode: http.StatusOK}}
			f.Cases[0].Requests[0].ReadsRoutes = []string{"/request"}
		}, ""},
		{"readsRoutes of a request on a route nothing pins", func(f *caseFile) {
			f.Cases[0].Requests[0].ReadsRoutes = []string{"/other"}
		}, "case iso request read expects calls to /other, which nothing pins before it"},
		{"pipCalls of a case beside a request with readsRoutes", func(f *caseFile) {
			f.Cases[1].PIPCalls = "/pip"
			f.Cases[1].Requests[0].ReadsRoutes = []string{"/pip"}
		}, "case reg records the calls of the whole case, and its request read clears the call log"},
		{"omitOperation beside emptyOperation", func(f *caseFile) {
			f.Cases[0].Requests[0].Filter = true
			f.Cases[0].Requests[0].EmptyOperation = true
			f.Cases[0].Requests[0].OmitOperation = true
		}, "case iso request read sets omitOperation, which only a filter request"},
		{"readsRoutes of a case on a route the case pins", func(f *caseFile) {
			f.Cases[0].Pins = map[string]PipStubResponse{"/case": {StatusCode: http.StatusOK}}
			f.Cases[0].ReadsRoutes = []string{"/case"}
		}, ""},
		{"readsRoutes of a case beside a request that clears the log", func(f *caseFile) {
			f.Cases[1].ReadsRoutes = []string{"/pip"}
			f.Cases[1].Requests[0].ClassifyBy = "/pip"
		}, "case reg expects calls over the whole case, and its request read clears the call log"},
		{"pipCalls of a case beside a step request that classifies", func(f *caseFile) {
			f.Cases[1].PIPCalls = "/pip"
			f.Cases[1].Customize[0].Requests[0].ClassifyBy = "/pip"
		}, "case reg records the calls of the whole case, and its request after clears the call log"},
		{"classifyBy on a route only a later request pins", func(f *caseFile) {
			f.Cases[1].Requests[0].ClassifyBy = "/later"
			f.Cases[1].Customize[0].Requests[0].Pins = map[string]PipStubResponse{"/later": {StatusCode: http.StatusOK}}
		}, "case reg request read is classified by /later, which nothing pins before it"},
		{"readsRoutes on a pinned route", func(f *caseFile) { f.Cases[0].ReadsRoutes = []string{"/pip"} }, ""},
		{"readsRoutes on a route the file does not pin", func(f *caseFile) { f.Cases[1].ReadsRoutes = []string{"/other"} },
			"case reg expects calls to /other, which nothing pins before it"},
		{"pipHeaders without pipCalls", func(f *caseFile) { f.Cases[0].Requests[0].PIPHeaders = []string{"tenant"} },
			"case iso request read sets pipHeaders without pipCalls"},
		{"pipHeaders with authorization:subject", func(f *caseFile) {
			f.Cases[0].Requests[0].PIPCalls = "/pip"
			f.Cases[0].Requests[0].PIPHeaders = []string{"Authorization:Subject", "tenant"}
		}, ""},
		{"pipHeaders with authorization:issuer", func(f *caseFile) {
			f.Cases[0].Requests[0].PIPCalls = "/pip"
			f.Cases[0].Requests[0].PIPHeaders = []string{"Authorization:Issuer"}
		}, ""},
		{"pipHeaders with another name holding a colon", func(f *caseFile) {
			f.Cases[0].Requests[0].PIPCalls = "/pip"
			f.Cases[0].Requests[0].PIPHeaders = []string{"authorization:claims"}
		}, `case iso request read names "authorization:claims" in pipHeaders, which no header has, and which is neither authorization:subject nor authorization:issuer`},
		{"emptyOperation beside operation", func(f *caseFile) {
			f.Cases[0].Requests[0].EmptyOperation = true
			f.Cases[0].Requests[0].Operation = "READ"
		}, "case iso request read sets both operation and emptyOperation"},
		{"a negative pause", func(f *caseFile) { f.Cases[0].Requests[0].PauseMs = -1 }, "case iso request read pauses for -1 ms"},
		{"user-management routes that are paths or the default route", func(f *caseFile) {
			f.UserManagement = map[string]PipStubResponse{DefaultRoute: {StatusCode: http.StatusNotFound}}
			f.Cases[0].UserManagement = map[string]PipStubResponse{"/users/u-1": {StatusCode: http.StatusOK}}
			f.Cases[0].Requests[0].UserManagement = map[string]PipStubResponse{DefaultRoute: {StatusCode: http.StatusOK}}
			f.Cases[0].Requests[0].UserManagementCalls = true
		}, ""},
		{"a user-management route of the file that is no path", func(f *caseFile) {
			f.UserManagement = map[string]PipStubResponse{"users": {StatusCode: http.StatusOK}}
		}, `the file pins the user-management route "users", which is neither * nor a path`},
		{"a user-management route of a case that is no path", func(f *caseFile) {
			f.Cases[1].UserManagement = map[string]PipStubResponse{"**": {StatusCode: http.StatusOK}}
		}, `case reg pins the user-management route "**", which is neither * nor a path`},
		{"a user-management route of a request that is no path", func(f *caseFile) {
			f.Cases[0].Requests[0].UserManagement = map[string]PipStubResponse{"": {StatusCode: http.StatusOK}}
		}, `case iso request read pins the user-management route "", which is neither * nor a path`},
		{"bulk beside bulkOperations", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{}
			f.Cases[0].Requests[0].BulkOperations = []any{}
		}, "case iso request read sets both bulk and bulkOperations"},
		{"bulk beside a resource", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{map[string]any{"id": "a"}}
			f.Cases[0].Requests[0].Resource = map[string]any{}
		}, "sets filter, resource, operation, type, emptyOperation, or classifyBy beside a bulk request"},
		{"a bulk item that is not an object", func(f *caseFile) { f.Cases[0].Requests[0].Bulk = []any{"a"} },
			"case iso request read has the bulk item a, which is not an object"},
		{"policyOmit on a case with sets", func(f *caseFile) { f.Cases[1].PolicyOmit = []string{"roles"} },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"policiesQuery on a case with sets", func(f *caseFile) { f.Cases[1].PoliciesQuery = "a=b" },
			"case reg sets roles, domain, policyOmit, policy, or policiesQuery"},
		{"a delete without a key", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].Delete = &customizeDelete{}
		}, "case reg step step deletes the customization of a set with no key"},
		{"a PIP delete", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].Delete = &customizeDelete{PIP: "subject.a"}
		}, ""},
		{"a delete of both a set and a PIP", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].Delete = &customizeDelete{Key: "outer", PIP: "subject.a"}
		}, "case reg step step deletes the customization of both a set and a PIP"},
		{"recursive on a PIP delete", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].Delete = &customizeDelete{PIP: "subject.a", Recursive: boolOf(true)}
		}, "case reg step step sets recursive on the delete of a PIP customization"},
		{"pipBody beside pips", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPs = []any{map[string]any{"name": "subject.a"}}
			f.Cases[1].Customize[0].PIPBody = json.RawMessage(`{"name":"subject.a"}`)
		}, "case reg step step sets both pips and pipBody"},
		{"pipBody beside sets", func(f *caseFile) { f.Cases[1].Customize[0].PIPBody = json.RawMessage(`{"name":"subject.a"}`) },
			"case reg step step sets more than one of delete, pips or pipBody, and sets or body"},
		{"a pipBody object with no name", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = nil
			f.Cases[1].Customize[0].PIPBody = json.RawMessage(`{"status":"INACTIVE"}`)
		}, "imports a PIP customization map[status:INACTIVE] with no name"},
		{"a step with no name", func(f *caseFile) { f.Cases[1].Customize[0].Name = "" },
			`case reg has a customize step named ""`},
		{"a bulkOperations item that is not an object", func(f *caseFile) { f.Cases[0].Requests[0].BulkOperations = []any{"a"} },
			"case iso request read has the bulk item a, which is not an object"},
		{"v2 beside bulk", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{}
			f.Cases[0].Requests[0].V2 = &v2Spec{}
		}, "case iso request read sets v2 beside bulk"},
		{"v2 bulkOperations of one type", func(f *caseFile) {
			f.Cases[0].Requests[0].BulkOperations = []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}
			f.Cases[0].Requests[0].V2 = &v2Spec{}
		}, ""},
		{"v2 bulkOperations of two types", func(f *caseFile) {
			f.Cases[0].Requests[0].BulkOperations = []any{map[string]any{"id": "a"}, map[string]any{"id": "b", "type": "T"}}
			f.Cases[0].Requests[0].V2 = &v2Spec{}
		}, "case iso request read sends bulkOperations through v2, but its items name 2 types"},
		{"v2 bulkOperations of the case's type, named and omitted", func(f *caseFile) {
			f.Cases[0].Requests[0].BulkOperations = []any{map[string]any{"id": "a"}, map[string]any{"id": "b", "type": "ISO"}}
			f.Cases[0].Requests[0].V2 = &v2Spec{}
		}, ""},
		{"a stand property", func(f *caseFile) {
			f.StandProperties = map[string]string{"access-control.obligations.merge.strategy": "weak"}
		}, ""},
		{"an unknown stand property", func(f *caseFile) { f.StandProperties = map[string]string{"access-control.other": "x"} },
			"names the stand property access-control.other"},
		{"a stand property value it cannot take", func(f *caseFile) {
			f.StandProperties = map[string]string{"access-control.obligations.enabled": "yes"}
		}, `sets the stand property access-control.obligations.enabled to "yes"`},
		{"emptyOperation beside bulk", func(f *caseFile) {
			f.Cases[0].Requests[0].Bulk = []any{}
			f.Cases[0].Requests[0].EmptyOperation = true
		}, "beside a bulk request"},
		{"predicates that are not an object", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "predicates": "a==b"}}
		}, "has a set entry whose predicates is not an object"},
		{"algorithm beside combiningAlgorithm", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer", "algorithm": "A", "combiningAlgorithm": "B"}}
		}, "has a set entry whose members algorithm and combiningAlgorithm write the same member combiningAlgorithm"},
		{"a predicate beside a member of the same name", func(f *caseFile) {
			f.Cases[1].Customize[0].Sets = []any{map[string]any{"key": "outer",
				"policies": []any{map[string]any{"key": "p", "rules": []any{map[string]any{
					"key": "r", "status": "ACTIVE", "predicates": map[string]any{"status": "INACTIVE"}}}}}}}
		}, "has a rule entry whose members predicates.status and status write the same member status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := wellFormedCaseFile()
			tc.change(&f)
			problems := caseFileProblems(f)
			if tc.want == "" {
				if len(problems) != 0 {
					t.Errorf("caseFileProblems = %q, want none", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], tc.want) {
				t.Errorf("caseFileProblems = %q, want one problem containing %q", problems, tc.want)
			}
		})
	}
}

// A header the case sets replaces the token header of the same name, so a
// forwarded value is labeled by the header the request carried, not by the
// token the suite minted.
func TestForwardedHeaders_LabelsByTheHeadersTheRequestSent(t *testing.T) {
	sent := sentHeaders(TokenBundle{M2M: "m2m-token", EndUser: "user-token"},
		PerCallOptions{CustomHeaders: map[string]string{"incoming-token": "Bearer case-token", "Authorization": "dropped"}})
	wantSent := map[string]string{"authorization": "Bearer m2m-token", "incoming-token": "Bearer case-token"}
	if diff := cmp.Diff(wantSent, sent); diff != "" {
		t.Errorf("sentHeaders mismatch (-want +got):\n%s", diff)
	}
	calls := []PipStubCall{{Path: "/pip", Headers: map[string]string{"x-fwd": "case-token", "x-minted": "user-token"}}}
	got := forwardedHeaders(calls, "/pip", []string{"x-fwd", "x-minted"}, sent, "default")
	want := map[string]any{"x-fwd": "<user token>", "x-minted": "user-token"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("forwardedHeaders mismatch (-want +got):\n%s", diff)
	}
}

// A rule's fields are merged after its predicates, so a field replaces a
// predicate of the same name.
func TestBuildSet_RuleFieldsReplaceAPredicate(t *testing.T) {
	set := setSpec{Key: "outer", Policies: []policySpec{{Key: "p", Rules: []ruleSpec{{
		Key: "r", Effect: "ALLOW",
		Predicates: map[string]any{"rsqlPredicate": "a==b"},
		Fields:     map[string]any{"rsqlPredicate": "c=={{resourceType}}", "status": nil},
	}}}}}
	rule := map[string]any{
		"ruleId": "15d6b792-eff3-7653-87a2-fa96a7209fb5", "name": "c1 r", "target": "", "condition": "", "effect": "ALLOW",
		"rsqlPredicate": "c==RT", "status": nil,
	}
	want := map[string]any{
		"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92", "name": "c1 outer", "status": "ACTIVE", "target": "",
		"policies": []any{map[string]any{
			"policyId": "e7852720-9add-579c-e70a-d2e16a6b9cbe", "name": "c1 p", "target": "", "rules": []any{rule},
		}},
		"policySets": []any{},
	}
	b := regularBuilder{caseID: "c1"}
	if diff := cmp.Diff(want, buildSet(b, b, set, "RT")); diff != "" {
		t.Errorf("buildSet mismatch (-want +got):\n%s", diff)
	}
}

// omitFields removes members after fields is merged, from a rule, a policy,
// and a set alike, so a member fields sets and omitFields names is not sent.
func TestBuildSet_OmitFieldsRemovesMembersAfterFields(t *testing.T) {
	set := setSpec{Key: "outer", OmitFields: []string{"target"}, Policies: []policySpec{{
		Key: "p", OmitFields: []string{"policyId"}, Rules: []ruleSpec{{
			Key: "r", Effect: "ALLOW", Fields: map[string]any{"effect": "DENY"}, OmitFields: []string{"effect", "ruleId"},
		}},
	}}}
	want := map[string]any{
		"policySetId": "d82b5a69-4822-465d-d804-1c9317bcfe92", "name": "c1 outer", "status": "ACTIVE",
		"policies": []any{map[string]any{
			"name": "c1 p", "target": "",
			"rules": []any{map[string]any{"name": "c1 r", "target": "", "condition": ""}},
		}},
		"policySets": []any{},
	}
	b := regularBuilder{caseID: "c1"}
	if diff := cmp.Diff(want, buildSet(b, b, set, "RT")); diff != "" {
		t.Errorf("buildSet mismatch (-want +got):\n%s", diff)
	}
}

// omitStatus removes the status the set would carry, and a status in fields,
// merged after it, puts one back.
func TestBuildSet_OmitStatus(t *testing.T) {
	cases := []struct {
		name       string
		fields     map[string]any
		wantStatus any
		wantSet    bool
	}{
		{"without fields the set has no status", nil, nil, false},
		{"a status in fields is sent", map[string]any{"status": "INACTIVE"}, "INACTIVE", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := regularBuilder{caseID: "c1"}
			got := buildSet(b, b, setSpec{Key: "outer", Status: "", OmitStatus: true, Fields: tc.fields}, "RT")
			status, set := got["status"]
			if set != tc.wantSet || status != tc.wantStatus {
				t.Errorf("buildSet(omitStatus, fields %v) status = %v (present %t), want %v (present %t)",
					tc.fields, status, set, tc.wantStatus, tc.wantSet)
			}
		})
	}
}

// recordedRequest is what testServer received in one request.
type recordedRequest struct {
	method, path, query, body string
}

// testServer answers every request with 200 and an empty JSON object, and
// records each request it received.
func testServer(t *testing.T) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var got []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recordedRequest{r.Method, r.URL.Path, r.URL.RawQuery, string(body)})
		mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestUploadIsolatedPoliciesWithQuery_ExtendsOnlyTheUploadOfThePolicies(t *testing.T) {
	srv, got := testServer(t)
	cfg := Config{ACBaseURL: srv.URL, TenantID: "t", Profile: "legacy"}
	tokens := &TokenFactory{cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}}
	if _, _, err := UploadIsolatedPoliciesWithQuery(context.Background(), cfg, tokens, "D", nil, []any{}, "applicableForFrontend=true"); err != nil {
		t.Fatal(err)
	}
	var queries []string
	for _, r := range *got {
		queries = append(queries, r.method+" "+r.path+"?"+r.query)
	}
	want := []string{
		"PUT /access/v1/simplifiedPolicies/domainPolicies/D?tenant_id=t",
		"PUT /access/v1/simplifiedPolicies/domainPIPs/D?tenant_id=t",
		"PUT /access/v1/simplifiedPolicies/domainPolicies/D?tenant_id=t&applicableForFrontend=true",
	}
	if diff := cmp.Diff(want, queries); diff != "" {
		t.Errorf("UploadIsolatedPoliciesWithQuery requests mismatch (-want +got):\n%s", diff)
	}
}

// UploadIsolatedPoliciesWithQuery returns the body of the PUT whose status it
// returns: the first one refused, which ends the upload, or else the last one.
func TestUploadIsolatedPoliciesWithQuery_ReturnsTheBodyOfTheReturnedStatus(t *testing.T) {
	cases := []struct {
		name       string
		refuse     string
		wantStatus int
		wantBody   string
		wantPuts   int
	}{
		{"the PIP declaration refused", "domainPIPs", http.StatusBadRequest, "refused domainPIPs", 2},
		{"the policies refused", "applicableForFrontend", http.StatusBadRequest, "refused applicableForFrontend", 3},
		{"nothing refused", "", http.StatusOK, "accepted 3", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			puts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				puts++
				if tc.refuse != "" && strings.Contains(r.URL.Path+"?"+r.URL.RawQuery, tc.refuse) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte("refused " + tc.refuse))
					return
				}
				_, _ = fmt.Fprintf(w, "accepted %d", puts)
			}))
			t.Cleanup(srv.Close)
			cfg := Config{ACBaseURL: srv.URL, TenantID: "t", Profile: "legacy"}
			tokens := &TokenFactory{cache: map[string]tokenEntry{"m2m": {accessToken: "m2m-token", expiresAt: time.Now().Add(time.Hour)}}}
			status, body, err := UploadIsolatedPoliciesWithQuery(context.Background(), cfg, tokens, "D", nil, []any{}, "applicableForFrontend=true")
			if err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus || string(body) != tc.wantBody || puts != tc.wantPuts {
				t.Errorf("UploadIsolatedPoliciesWithQuery = %d, %q after %d PUTs, want %d, %q after %d",
					status, body, puts, tc.wantStatus, tc.wantBody, tc.wantPuts)
			}
		})
	}
}

func TestEmptyOperation_WireForms(t *testing.T) {
	srv, got := testServer(t)
	cfg := Config{ACBaseURL: srv.URL, TenantID: "t"}
	ctx := context.Background()
	if _, _, _, err := HelperFilterV1Query(ctx, cfg, filterV1Query("RT", "LIST", true), TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperFilterV1Query(ctx, cfg, filterV1Query("RT", "LIST", false), TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperCheckResourceV1(ctx, cfg, model.CheckAccessRequest{Operation: checkOperation("UPDATE", true), Type: "RT"}, TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := HelperCheckResourceV1(ctx, cfg, model.CheckAccessRequest{Operation: checkOperation("", false), Type: "RT"}, TokenBundle{}, PerCallOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []recordedRequest{
		{"POST", "/access/v1/check/filter", "operation=&resourceType=RT&tenant_id=t", ""},
		{"POST", "/access/v1/check/filter", "operation=LIST&resourceType=RT&tenant_id=t", ""},
		{"POST", "/access/v1/check/resource", "tenant_id=t", `{"operation":"","type":"RT"}`},
		{"POST", "/access/v1/check/resource", "tenant_id=t", `{"operation":"READ","type":"RT"}`},
	}
	if diff := cmp.Diff(want, *got, cmp.AllowUnexported(recordedRequest{})); diff != "" {
		t.Errorf("requests mismatch (-want +got):\n%s", diff)
	}
}

// The algorithm of an iterate member is sent as the file writes it: a string
// as that string, and JSON null, or no algorithm at all, as null rather than
// as an empty string, which the PAP may read as another value.
func TestBuildSet_IterateAlgorithmIsSentAsWritten(t *testing.T) {
	cases := []struct {
		name, iterate, want string
	}{
		{"null", `{"foreach": "subject.permissionScope", "algorithm": null}`,
			`{"combiningAlgorithm":null,"foreach":"subject.permissionScope"}`},
		{"a name", `{"foreach": "subject.permissionScope", "algorithm": "DENY_OVERRIDES"}`,
			`{"combiningAlgorithm":"DENY_OVERRIDES","foreach":"subject.permissionScope"}`},
		{"an empty string", `{"foreach": "subject.permissionScope", "algorithm": ""}`,
			`{"combiningAlgorithm":"","foreach":"subject.permissionScope"}`},
		{"absent", `{"foreach": "subject.permissionScope"}`,
			`{"combiningAlgorithm":null,"foreach":"subject.permissionScope"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var set setSpec
			if err := json.Unmarshal([]byte(`{"key": "outer", "iterate": `+tc.iterate+`}`), &set); err != nil {
				t.Fatal(err)
			}
			b := regularBuilder{caseID: "c1"}
			got, err := json.Marshal(buildSet(b, b, set, "RT")["iterate"])
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("iterate %s is sent as %s, want %s", tc.iterate, got, tc.want)
			}
		})
	}
}
