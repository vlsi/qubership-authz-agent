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

//go:build integration

package runtimetest

func (s *RuntimeSuite) TestCheckResource() {
	s.Step("check_resource.order_read.rls_deny", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	// Incoming-Token is the preferred subject source on legacy
	// ingress. The thin client sends the M2M token in Authorization (for
	// admission) and the end-user token in Incoming-Token (for policy
	// evaluation). Here we send an expired end-user token in Incoming-Token
	// so subject validation fails and the canonical DENY path fires; the
	// Authorization (admission) token is valid, so this returns HTTP 200
	// with body "false" (not HTTP 401).
	s.Step("check_resource.incoming_token_used_for_subject", func() {
		h := map[string]string{
			"Content-Type":   "application/json",
			"Incoming-Token": "Bearer " + s.expiredOrderReaderToken,
			"Authorization":  "Bearer " + s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "admission via valid Authorization must pass; subject DENY is 200 not 401")
		s.Assert().Equal("false", bodyStr(b), "expired Incoming-Token subject must DENY")
	})

	s.Step("check_resource.expired_authorization.401", func() {
		h := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.expiredOrderReaderToken,
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, _ := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(401, code)
	})

	s.Step("check_resource.no_token.401", func() {
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource", jsonHeader(), body)
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
	})

	s.Step("check_resource.unknown_tenant_id.deny", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource?tenant_id=other-tenant", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	s.Step("check_resource.tenant_id_absent", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ",
			"resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
	})

	s.Step("check_resource.null_body.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.postRaw("/access/v1/check/resource", h, nil)
		s.Require().Equal(400, code)
		s.Assert().Equal("bad request", jsonObj(b)["message"])
	})

	s.Step("check_resource.boolean_response", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		v := bodyStr(b)
		s.Assert().True(v == "true" || v == "false", "response must be boolean string, got: %s", v)
	})

	// A missing required parameter is rejected with a field-specific
	// message. Envoy Lua now emits
	// "Missing required parameter: <field>" so the body substring
	// includes "parameter"/"type"/"operation" — matching the tolerance
	// set the parity suite's TestRow11ValidationMissingOperation uses.
	s.Step("check_resource.missing_fields.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"resource": map[string]interface{}{"id": "1"},
		}
		code, b := s.postRaw("/access/v1/check/resource", h, body)
		s.Require().Equal(400, code)
		msg, _ := jsonObj(b)["message"].(string)
		s.Assert().Contains(msg, "Missing required parameter",
			"expected field-specific validation message, got: %s", msg)
	})

	s.Step("check_resource.wrong_address.404", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resourc", h, body)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	// On legacy ingress the policy-evaluation subject comes from
	// Incoming-Token when present, with Authorization reserved for admission.
	// BULK_OPEN READ is allowed for ROLE_ADMINISTRATOR only; sending an
	// admin Authorization (admission) together with an order-reader
	// Incoming-Token (subject) must deny because the end-user subject lacks
	// the admin role. This proves the precedence ordering: Incoming-Token
	// overrides Authorization when both are present.
	s.Step("check_resource.incoming_token_precedence_over_authorization", func() {
		h := map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer " + s.validAdminToken,
			"Incoming-Token": "Bearer " + s.validOrderReaderToken,
		}
		body := map[string]interface{}{
			"type": "BULK_OPEN", "operation": "READ",
			"resource": map[string]interface{}{"id": "bulk-open-1"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b),
			"Incoming-Token (order-reader) must take precedence over Authorization (admin) for subject evaluation")
	})

	// An anonymous request (Authorization-Type: anonymous) is decided with
	// the claims of its Authorization token, as legacy decides it, so the
	// admin token's ROLE_ADMINISTRATOR allows BULK_OPEN READ. Admission
	// still requires a valid Authorization token.
	s.Step("check_resource.anonymous_subject_marker", func() {
		h := map[string]string{
			"Content-Type":       "application/json",
			"Authorization":      "Bearer " + s.validAdminToken,
			"Authorization-Type": "anonymous",
		}
		body := map[string]interface{}{
			"type": "BULK_OPEN", "operation": "READ",
			"resource": map[string]interface{}{"id": "bulk-open-anon"},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("true", bodyStr(b),
			"an anonymous request takes the roles of its Authorization token, so BULK_OPEN READ must ALLOW")
	})

	// The Incoming-Token header must never appear in
	// input.requestHeaders. We rely on HEADER PIP resolution to never see
	// the bearer string; a misconfigured HEADER PIP that tried to bind
	// subject.incomingToken would otherwise leak the raw token. This step
	// covers the negative path: sending an incoming-token header with a
	// well-known literal and then asserting the subsequent decision is
	// unchanged from the no-header baseline. (Direct header-leak inspection
	// would require decision-log scraping — we cover that in
	// tests/unit/policies/pip_resolution_test.rego.)
	s.Step("check_resource.incoming_token_stripped_from_header_pip", func() {
		baseline := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ",
			"resource": map[string]interface{}{"id": "atch-1"},
		}
		code1, b1 := s.post("/access/v1/check/resource", baseline, body)
		s.Require().Equal(200, code1)

		withIncoming := map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer " + s.validAdminToken,
			"Incoming-Token": "Bearer " + s.validAdminToken,
		}
		code2, b2 := s.post("/access/v1/check/resource", withIncoming, body)
		s.Require().Equal(200, code2)

		s.Assert().Equal(bodyStr(b1), bodyStr(b2),
			"incoming-token must not alter decision through HEADER PIP resolution")
	})

	// A token that is not a JWT fails admission, and the decision log names
	// the format as the reason.
	s.Step("check_resource.invalid_authorization.401", func() {
		h := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer not-a-jwt",
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
		authError, _ := s.loggedDecision(mark)["authError"].(map[string]interface{})
		s.Assert().Equal("Token is not a valid JWT", authError["reason"])
	})

	// The admission token has to carry the Bearer scheme: a valid token sent
	// without it fails admission, and the decision log names the scheme.
	s.Step("check_resource.authorization_without_bearer.401", func() {
		h := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
		authError, _ := s.loggedDecision(mark)["authError"].(map[string]interface{})
		s.Assert().Equal("Authorization scheme must be Bearer", authError["reason"])
	})

	// A subject token without the Bearer scheme fails authentication after
	// admission passed: the resource is denied with 200, and the decision log
	// names the scheme as the reason.
	s.Step("check_resource.incoming_token_without_bearer.deny", func() {
		h := map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer " + s.validAdminToken,
			"Incoming-Token": s.validAdminToken,
		}
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ", "resource": map[string]interface{}{},
		}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("false", bodyStr(b))
		s.Assert().Equal("Authorization scheme must be Bearer", firstLoggedResult(s.loggedDecision(mark))["reason"])
	})

	// The policy's condition and its ${subject.allowedCustomers} template
	// are filled from the GENERAL PIP the pip-stub answers: check/resource
	// allows a listed customer, and check/filter renders the list into the
	// rsql predicate. The step pins the stub's answer itself, because another
	// step may have pinned a different one.
	s.Step("check_resource.pip_value_substituted", func() {
		pin := `[{"path":"/api/v1/pip/allowed","responses":[{"statusCode":200,"body":["C1","C2","C3"]}]}]`
		pinCode, _ := s.doHTTPDirect("PUT", s.cfg.PIPStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"}, []byte(pin))
		s.Require().Equal(200, pinCode)
		body := map[string]interface{}{
			"type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "C1"},
		}
		code, b := s.post("/access/v1/check/resource", incomingTokenHeader(s.validAdminToken), body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("true", bodyStr(b))
		code, b = s.post("/access/v1/check/filter?resourceType=CUSTOMER&operation=READ",
			incomingTokenHeader(s.validAdminToken), map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		// PIP-resolved array elements are
		// JSON-quoted and comma-space-joined.
		s.Assert().Equal(`customerId=in=("C1", "C2", "C3")`, jsonObj(b)["rsqlFilterCondition"])
	})
}
