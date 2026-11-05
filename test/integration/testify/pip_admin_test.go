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

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func (s *RuntimeSuite) TestTokenPIPFilter() {
	s.Step("token_pip_filter.upload_token_pips", func() {
		pips := `[
			{"name":"subject.emailFromToken","pipType":"TOKEN","claim":"email"},
			{"name":"subject.deptFromToken","pipType":"TOKEN","claim":"department","defaultValue":"unknown"}
		]`
		err := UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
		s.Require().NoError(err, "pip stub upload failed")
		s.waitForACPull()
	})

	s.Step("token_pip_filter.positive_alias_in_filter", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=TOKEN_PIP_POSITIVE&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("USE_FILTER_CONDITION", j["calculationResult"])
		rsql, _ := j["rsqlFilterCondition"].(string)
		s.Assert().True(strings.HasPrefix(rsql, "ownerEmail=="),
			"rsqlFilterCondition must start with ownerEmail==, got: %s", rsql)
		s.Assert().NotContains(rsql, "${subject.",
			"TOKEN PIP alias must be substituted, got: %s", rsql)
		s.Assert().True(strings.Contains(rsql, "@"),
			"substituted email must contain @, got: %s", rsql)
	})

	s.Step("token_pip_filter.default_value_fallback", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=TOKEN_PIP_DEFAULT&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("USE_FILTER_CONDITION", j["calculationResult"])
		// D-AF-R (OQ-AF-6, 2026-04-15): scalar-string default value
		// is JSON-quoted in the rendered predicate.
		s.Assert().Equal(`dept=="unknown"`, j["rsqlFilterCondition"],
			"missing JWT claim must fall back to defaultValue")
	})
}

func (s *RuntimeSuite) TestPIPDenyReason() {
	pipStubInternal := s.cfg.PIPStubInternalURL

	s.Step("pip_deny.upload_broken_pip", func() {
		pips := fmt.Sprintf(`[
			{"name":"subject.brokenPip","url":"%s/nonexistent/path","requestAttributes":{"resourceType":"PIP_FAIL_TEST"}}
		]`, pipStubInternal)
		err := UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
		s.Require().NoError(err, "pip stub upload failed")
		s.waitForACPull()
	})

	s.Step("pip_deny.pip_failure_deny_reason", func() {
		body := map[string]interface{}{"type": "PIP_FAIL_TEST", "operation": "READ", "resource": map[string]interface{}{"ownerId": "X"}}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", incomingTokenHeader(s.validAdminToken), body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("false", bodyStr(b))
		reason, _ := firstLoggedResult(s.loggedDecision(mark))["reason"].(string)
		s.Assert().Contains(reason, "PIP resolution failed: brokenPip",
			"deny reason must mention PIP failure, got: %s", reason)
	})

	s.Step("pip_deny.missing_attr_deny_reason", func() {
		body := map[string]interface{}{"type": "ATTR_MISS_TEST", "operation": "READ", "resource": map[string]interface{}{"ownerId": "X"}}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", incomingTokenHeader(s.validAdminToken), body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("false", bodyStr(b))
		reason, _ := firstLoggedResult(s.loggedDecision(mark))["reason"].(string)
		s.Assert().Contains(reason, "subject attribute not found: nonExistentAttr",
			"deny reason must mention missing attr, got: %s", reason)
	})
}

func (s *RuntimeSuite) TestPIPGeneralActivation() {
	pipStubURL := s.cfg.PIPStubURL
	pipStubInternal := s.cfg.PIPStubInternalURL

	s.Step("pip_general.stub_reset", func() {
		code, _ := s.doHTTPDirect("POST", pipStubURL+"/pip-stub/reset", nil, nil)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.upload_pips_for_general", func() {
		pips := fmt.Sprintf(`[
			{"name":"subject.allowedCustomers","url":"%s/api/v1/pip/allowed","requestAttributes":{"resourceType":"Customer"}}
		]`, pipStubInternal)
		err := UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
		s.Require().NoError(err, "pip stub upload failed")
		s.waitForACPull()
	})

	s.Step("pip_general.active_pip_called", func() {
		code, _ := s.post(
			"/access/v1/check/filter?resourceType=CUSTOMER&operation=READ",
			incomingTokenHeader(s.validAdminToken),
			map[string]interface{}{},
		)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.stub_verify_active_called", func() {
		code, b := s.doHTTPDirect("GET", pipStubURL+"/pip-stub/calls", nil, nil)
		s.Require().Equal(200, code)

		var calls []map[string]interface{}
		s.Require().NoError(json.Unmarshal(b, &calls))

		found := false
		for _, c := range calls {
			path, _ := c["path"].(string)
			if strings.Contains(path, "/api/v1/pip/allowed") {
				found = true
				break
			}
		}
		s.Assert().True(found, "expected pip-stub to receive call to /api/v1/pip/allowed, calls: %v", calls)
	})

	s.Step("pip_general.stub_reset_after", func() {
		code, _ := s.doHTTPDirect("POST", pipStubURL+"/pip-stub/reset", nil, nil)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.inactive_pip_not_called", func() {
		code, _ := s.post(
			"/access/v1/check/filter?resourceType=DOCUMENT&operation=READ",
			incomingTokenHeader(s.validAdminToken),
			map[string]interface{}{},
		)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.stub_verify_inactive_not_called", func() {
		code, b := s.doHTTPDirect("GET", pipStubURL+"/pip-stub/calls", nil, nil)
		s.Require().Equal(200, code)

		var calls []map[string]interface{}
		s.Require().NoError(json.Unmarshal(b, &calls))

		for _, c := range calls {
			path, _ := c["path"].(string)
			if strings.Contains(path, "/api/v1/pip/allowed") {
				s.Fail("pip-stub should NOT have received /api/v1/pip/allowed for DOCUMENT/READ", "calls: %v", calls)
			}
		}
	})

	s.Step("pip_general.bulk_reset_calls", func() {
		code, _ := s.doHTTPDirect("POST", pipStubURL+"/pip-stub/reset", nil, nil)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.bulk_pin_allowed_subset", func() {
		payload := `[{"path":"/api/v1/pip/allowed","responses":[{"statusCode":200,"body":["cust-keep-1","cust-keep-3"]}]}]`
		code, _ := s.doHTTPDirect(
			"PUT",
			pipStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"},
			[]byte(payload),
		)
		s.Require().Equal(200, code)
	})

	s.Step("pip_general.bulk_pip_filters_resources", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "c1", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-keep-1"}},
			{"id": "c2", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-deny-2"}},
			{"id": "c3", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-keep-3"}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		result := jsonStrArr(b)
		sort.Strings(result)
		s.Assert().Equal([]string{"c1", "c3"}, result,
			"bulk RLS must filter via GENERAL PIP response, got: %v", result)
	})

	s.Step("pip_general.bulk_stub_verify_called", func() {
		code, b := s.doHTTPDirect("GET", pipStubURL+"/pip-stub/calls", nil, nil)
		s.Require().Equal(200, code)

		var calls []map[string]interface{}
		s.Require().NoError(json.Unmarshal(b, &calls))

		found := false
		for _, c := range calls {
			path, _ := c["path"].(string)
			if strings.Contains(path, "/api/v1/pip/allowed") {
				found = true
				break
			}
		}
		s.Assert().True(found, "bulk path must drive /api/v1/pip/allowed at least once, calls: %v", calls)
	})

	s.Step("pip_general.restore_default_stub", func() {
		// D-AF-W item 5d: restore the pip-stub default so subsequent
		// testify steps that rely on `["C1","C2","C3"]` (e.g.
		// `pip_general.active_pip_called`) do not inherit
		// this test's `cust-keep-*` pin.
		payload := `[{"path":"/api/v1/pip/allowed","responses":[{"statusCode":200,"body":["C1","C2","C3"]}]}]`
		code, _ := s.doHTTPDirect(
			"PUT",
			pipStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"},
			[]byte(payload),
		)
		s.Require().Equal(200, code)
	})
}

// TestPIPJsonPathExtraction exercises D-AF-U end-to-end: a GENERAL PIP with
// type=JSON + jsonPath walks a nested field out of the pip-stub response and
// feeds the leaf into the rendered RSQL predicate. Raw-body fallback (no
// type / type=TEXT) is already covered by TestPIPGeneralActivation.
func (s *RuntimeSuite) TestPIPJsonPathExtraction() {
	pipStubURL := s.cfg.PIPStubURL
	pipStubInternal := s.cfg.PIPStubInternalURL

	s.Step("pip_jsonpath.stub_reset", func() {
		code, _ := s.doHTTPDirect("POST", pipStubURL+"/pip-stub/reset", nil, nil)
		s.Require().Equal(200, code)
	})

	s.Step("pip_jsonpath.upload_json_pip", func() {
		pips := fmt.Sprintf(`[
			{"name":"subject.allowedCustomers","pipType":"GENERAL","type":"JSON","jsonPath":"$.ids","url":"%s/api/v1/pip/meta","httpMethod":"POST","requestAttributes":{"resourceType":"Customer"}}
		]`, pipStubInternal)
		err := UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
		s.Require().NoError(err, "pip stub upload failed")
		s.waitForACPull()
	})

	s.Step("pip_jsonpath.pin_json_response", func() {
		payload := `[{"path":"/api/v1/pip/meta","responses":[{"statusCode":200,"body":{"department":"finance","ids":["cust-json-1","cust-json-3"]}}]}]`
		code, _ := s.doHTTPDirect(
			"PUT",
			pipStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"},
			[]byte(payload),
		)
		s.Require().Equal(200, code)
	})

	s.Step("pip_jsonpath.bulk_extracts_ids_and_filters", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "c1", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-json-1"}},
			{"id": "c2", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-not-in-ids"}},
			{"id": "c3", "type": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "cust-json-3"}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		result := jsonStrArr(b)
		sort.Strings(result)
		s.Assert().Equal([]string{"c1", "c3"}, result,
			"jsonPath-extracted ids array must drive the bulk filter, got: %v", result)
	})

	s.Step("pip_jsonpath.restore_legacy_pip", func() {
		pips := fmt.Sprintf(`[
			{"name":"subject.allowedCustomers","url":"%s/api/v1/pip/allowed","requestAttributes":{"resourceType":"Customer"}}
		]`, pipStubInternal)
		err := UploadPIPsToACStub(s.cfg.ACStubURL, []byte(pips), s.currentRequestID())
		s.Require().NoError(err, "pip stub upload failed")
		s.waitForACPull()
	})

	s.Step("pip_jsonpath.restore_default_stub", func() {
		// D-AF-W item 5d: restore the pip-stub default `/api/v1/pip/allowed`
		// response so later tests that rely on `["C1","C2","C3"]`
		// (e.g. `pip_general.active_pip_called`) do not
		// inherit residual state from this test's `/api/v1/pip/meta`
		// pin. `/api/v1/pip/meta` stays pinned with the dict payload
		// because no later testify step depends on a different body
		// on that path.
		payload := `[{"path":"/api/v1/pip/allowed","responses":[{"statusCode":200,"body":["C1","C2","C3"]}]}]`
		code, _ := s.doHTTPDirect(
			"PUT",
			pipStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"},
			[]byte(payload),
		)
		s.Require().Equal(200, code)
	})
}
