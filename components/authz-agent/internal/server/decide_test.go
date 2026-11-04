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

package server

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// admissionStub stands in for the caller and token checks of the embedded
// policies: a request without a subject is refused with an authError, and
// a subject token Bearer expired is refused, and any other one is admitted
// with the claims of the user u1.
const admissionStub = `package authorize_internals

import rego.v1

admission := {"authError": {"status": 403, "message": "no subject"}} if input.subject == ""

admission := {"subjectError": "token expired"} if input.subject == "Bearer expired"

admission := {"tokenPayload": {"sub": "u1"}} if not input.subject in {"", "Bearer expired"}
`

type quietLoader struct{}

func (quietLoader) Infof(string, ...any) {}
func (quietLoader) Warnf(string, ...any) {}

// tenantSet is a set of tenant that allows the operation read on a doc
// where condition holds.
func tenantSet(tenant, condition string) string {
	return fmt.Sprintf(`{"policySetId": "s-%[1]s", "name": "s", "status": "ACTIVE", "tenantId": %[1]q,
		"target": "resourceType == 'doc'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"tenantId": %[1]q, "rules": [{"ruleId": "r", "target": "operation == 'read'",
				"condition": %[2]q, "effect": "ALLOW", "tenantId": %[1]q}]}]}`, tenant, condition)
}

// newDecideApp builds the public surface over a registry in which tenant a
// allows every read of a doc and tenant b none, with b the default tenant.
func newDecideApp(t *testing.T) *fiber.App {
	t.Helper()
	reg := registry(t, `{"policySets": [`+tenantSet("a", "true")+`,`+tenantSet("b", "false")+`]}`)
	return newPublicAppOver(t, map[string]string{"internals.rego": admissionStub}, nil,
		Options{Snapshots: reg, DefaultTenant: func() string { return "b" }})
}

func TestDecide_TheTenantComesFromTheQueryThenTheHeaderThenTheDefault(t *testing.T) {
	app := newDecideApp(t)
	const body = `{"type":"doc","operation":"read","resource":{}}`
	for _, tc := range []struct {
		name, query, header, want string
	}{
		{"the query parameter", "?tenant_id=a", "", "true"},
		{"the query parameter over the header", "?tenant_id=b", "a", "false"},
		{"the header", "", "a", "true"},
		{"a blank query parameter falls through to the header", "?tenant_id=%20", "a", "true"},
		{"the default tenant", "", "", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			for k, v := range admin {
				headers[k] = v
			}
			if tc.header != "" {
				headers["Tenant"] = tc.header
			}
			path := "/access/v1/check/resource" + tc.query
			code, got, _ := call(t, app, http.MethodPost, path, body, headers)
			if code != 200 || got != tc.want {
				t.Errorf("POST %s with Tenant %q = %d %s, want 200 %s", path, tc.header, code, got, tc.want)
			}
		})
	}
}

func TestDecide_ARefusedAdmissionAnswersWithItsAuthError(t *testing.T) {
	app := newDecideApp(t)
	code, got, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?tenant_id=a",
		`{"type":"doc","operation":"read"}`, nil)
	if code != 403 || got != `{"message":"no subject"}` {
		t.Errorf("POST without a subject = %d %s, want 403 {\"message\":\"no subject\"}", code, got)
	}
}

func TestDecide_BulkRoutesAnswerEachItem(t *testing.T) {
	app := newDecideApp(t)
	for _, tc := range []struct {
		name, path, body, want string
	}{
		{"bulk lists the allowed ids", "/access/v1/check/resource/bulk?tenant_id=a",
			`[{"id":"x","type":"doc","operation":"read"},{"id":"y","type":"doc","operation":"write"}]`, `["x"]`},
		{"bulk/operations groups the allowed ids by operation", "/access/v1/check/resource/bulk/operations?tenant_id=a",
			`[{"id":"x","type":"doc","operations":["read","write"]},{"id":"y","type":"doc","operations":["read"]}]`,
			`{"read":["x","y"],"write":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got, _ := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != 200 || got != tc.want {
				t.Errorf("POST %s = %d %s, want 200 %s", tc.path, code, got, tc.want)
			}
		})
	}
}

// A refused subject token denies every item, and no policy is asked: tenant
// a would allow the read.
func TestDecide_ARefusedSubjectTokenDeniesEveryItem(t *testing.T) {
	app := newDecideApp(t)
	headers := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer expired"}
	for _, tc := range []struct{ path, body, want string }{
		{"/access/v1/check/resource?tenant_id=a", `{"type":"doc","operation":"read"}`, "false"},
		{"/access/v1/check/resource/bulk/operations?tenant_id=a", `[{"id":"x","type":"doc","operations":["read"]}]`, `{"read":[]}`},
		{"/access/v1/check/filter?tenant_id=a&resourceType=doc&operation=read", "",
			`{"calculationResult":"DENY","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`},
	} {
		code, got, _ := call(t, app, http.MethodPost, tc.path, tc.body, headers)
		if code != 200 || got != tc.want {
			t.Errorf("POST %s with an expired subject token = %d %s, want 200 %s", tc.path, code, got, tc.want)
		}
	}
}
