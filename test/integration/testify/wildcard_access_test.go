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

import "os"

func (s *RuntimeSuite) TestWildcardAccess() {
	// Upload wildcard-enhanced policy fixture to the authz-policy-admin and wait for the
	// pull loop to apply it before running wildcard-specific assertions.
	s.Step("wildcard_access.upload_wildcard_policies", func() {
		policies, err := os.ReadFile("testdata/runtime-simplified-policies-wildcard.json")
		s.Require().NoError(err, "failed to read wildcard policy fixture")
		err = UploadPoliciesToACStub(s.cfg.ACStubURL, policies, s.currentRequestID())
		s.Require().NoError(err, "wildcard policy stub upload failed")
		s.waitForACPull()
	})

	// ── ALL/ALL: admin allows any resource/operation ────────────────────
	// wildcard_access.legacy.check_resource_all_all covers an unknown type.

	s.Step("wildcard_access.all_all.no_predicates", func() {
		h := incomingTokenHeader(s.validAdminToken)
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("ALLOW", jsonObj(b)["calculationResult"],
			"wildcard short-circuit must allow without a filter condition")
		_, hasPreds := firstLoggedResult(s.loggedDecision(mark))["predicates"]
		s.Assert().False(hasPreds, "wildcard short-circuit must not produce predicates")
	})

	s.Step("wildcard_access.all_all.no_deny_reason", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{"type": "WC_EXACT_ONLY", "operation": "READ", "resource": map[string]interface{}{}}
		mark := s.decisionLogMark()
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("true", bodyStr(b))
		_, hasReason := firstLoggedResult(s.loggedDecision(mark))["reason"]
		s.Assert().False(hasReason, "wildcard short-circuit must not produce reason")
	})

	// ── ALL/<operation>: order-reader READ on any resourceType ──────────
	// wildcard_access.legacy.check_filter_all_op covers the allowed READ.

	s.Step("wildcard_access.all_op.reader_delete_denied", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{"type": "UNKNOWN_TYPE", "operation": "DELETE", "resource": map[string]interface{}{}}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("false", bodyStr(b),
			"order-reader has ALL/READ wildcard but not ALL/DELETE")
	})

	// ── <resourceType>/ALL: order-reader any op on WC_RT_TARGET ────────

	s.Step("wildcard_access.rt_all.reader_any_op", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=WC_RT_TARGET&operation=DELETE", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("ALLOW", jsonObj(b)["calculationResult"],
			"wildcard resourceType short-circuit must allow without a filter condition")
	})

	s.Step("wildcard_access.rt_all.reader_other_rt_denied", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := map[string]interface{}{"type": "OTHER_TYPE", "operation": "DELETE", "resource": map[string]interface{}{}}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("false", bodyStr(b),
			"order-reader has WC_RT_TARGET/ALL but not OTHER_TYPE/ALL")
	})

	// ── Mixed: wildcard-matched + unmatched in same request ─────────────

	s.Step("wildcard_access.mixed.partial_wildcard", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := []map[string]interface{}{
			{"id": "wc-rt", "type": "WC_RT_TARGET", "operation": "DELETE", "resource": map[string]interface{}{}},
			{"id": "wc-op", "type": "INVOICE", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		ids := jsonStrArr(b)
		s.Assert().Contains(ids, "wc-rt", "WC_RT_TARGET/DELETE should be allowed via resourceType wildcard")
		s.Assert().Contains(ids, "wc-op", "INVOICE/READ should be allowed via operation wildcard (ALL/READ)")
	})

	// ── Legacy endpoints with wildcard-access ───────────────────────────

	s.Step("wildcard_access.legacy.check_resource_all_all", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type":      "UNKNOWN_TYPE",
			"operation": "DELETE",
			"resource":  map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		s.Assert().Equal("true", bodyStr(b),
			"admin with ALL/ALL wildcard must get boolean true from check/resource")
	})

	s.Step("wildcard_access.legacy.check_resource_bulk_all_all", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "wc-1", "type": "UNKNOWN_TYPE", "operation": "DELETE", "resource": map[string]interface{}{}},
			{"id": "wc-2", "type": "ANOTHER_TYPE", "operation": "CREATE", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		ids := jsonStrArr(b)
		s.Assert().Contains(ids, "wc-1", "ALL/ALL wildcard must allow wc-1")
		s.Assert().Contains(ids, "wc-2", "ALL/ALL wildcard must allow wc-2")
	})

	s.Step("wildcard_access.legacy.check_filter_all_op", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=UNKNOWN_TYPE&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("ALLOW", j["calculationResult"],
			"order-reader with ALL/READ wildcard must get ALLOW from check/filter")
	})

	// ── Restore original policies ───────────────────────────────────────

	s.Step("wildcard_access.restore_original_policies", func() {
		policies, err := os.ReadFile("testdata/runtime-simplified-policies.json")
		s.Require().NoError(err, "failed to read original policy fixture")
		err = UploadPoliciesToACStub(s.cfg.ACStubURL, policies, s.currentRequestID())
		s.Require().NoError(err, "original policy stub restore failed")
		s.waitForACPull()
	})
}
