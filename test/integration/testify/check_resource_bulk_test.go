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
	"fmt"
)

func (s *RuntimeSuite) TestCheckResourceBulk() {
	s.Step("check_resource_bulk.owner_mismatch.denied", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := []map[string]interface{}{
			{"id": "item-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{"ownerId": "no-match"}},
			{"id": "item-2", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{"ownerId": "also-no"}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("[]", bodyStr(b))
	})

	s.Step("check_resource_bulk.unknown_type.denied", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "denied-invoice", "type": "INVOICE", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("[]", bodyStr(b))
	})

	s.Step("check_resource_bulk.empty_array", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/resource/bulk", h, []interface{}{})
		s.Require().Equal(200, code)
		s.Assert().Equal("[]", bodyStr(b))
	})

	s.Step("check_resource_bulk.null_body.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.postRaw("/access/v1/check/resource/bulk", h, nil)
		s.Require().Equal(400, code)
		s.Assert().Equal("bad request", jsonObj(b)["message"])
	})

	s.Step("check_resource_bulk.response_is_array", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "item-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code)
		arr := jsonArr(b)
		s.Assert().NotNil(arr, "response must be a JSON array")
	})

	s.Step("check_resource_bulk.large_3000", func() {
		h := incomingTokenHeader(s.validAdminToken)
		items := make([]map[string]interface{}, 3000)
		for i := 1; i <= 3000; i++ {
			items[i-1] = map[string]interface{}{
				"id": fmt.Sprintf("bulk-%d", i), "type": "BULK_OPEN", "operation": "READ",
				"resource": map[string]interface{}{"id": fmt.Sprintf("bulk-open-%d", i)},
			}
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, items)
		s.Require().Equal(200, code)
		result := jsonStrArr(b)
		s.Require().Len(result, 3000)
		s.Assert().Equal("bulk-1", result[0])
		s.Assert().Equal("bulk-3000", result[2999])
	})

	s.Step("check_resource_bulk.no_token.401", func() {
		body := []map[string]interface{}{
			{"id": "item-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", jsonHeader(), body)
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
	})

	s.Step("check_resource_bulk.no_id_empty", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, _ := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(200, code)
	})

	// Parity catalogue row 10: field-specific message
	// "Missing required parameter: <field>" per the legacy
	// CheckRequestValidator.
	s.Step("check_resource_bulk.missing_type_op.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "item-1", "resource": map[string]interface{}{}},
		}
		code, b := s.postRaw("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(400, code)
		msg, _ := jsonObj(b)["message"].(string)
		s.Assert().Contains(msg, "Missing required parameter",
			"expected field-specific validation message, got: %s", msg)
	})

	// Parity catalogue row 11: CheckRequestValidator raises
	// NotUniqueResourcesIdsException when two bulk entries share the
	// same `id`. Envoy Lua now detects duplicates and returns
	// HTTP 400 with a body that names the unique-id invariant.
	s.Step("check_resource_bulk.duplicate_ids.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "dup-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
			{"id": "dup-1", "type": "ORDER", "operation": "DELETE", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk", h, body)
		s.Require().Equal(400, code)
		msg, _ := jsonObj(b)["message"].(string)
		s.Assert().Contains(msg, "Duplicate resource id",
			"expected duplicate-id validation message, got: %s", msg)
	})

	s.Step("check_resource_bulk.tenant_id_ignored", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		body := []map[string]interface{}{
			{"id": "item-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{"ownerId": "no-match"}},
		}
		code, b := s.post("/access/v1/check/resource/bulk?tenant_id=some-other-tenant", h, body)
		s.Require().Equal(200, code)
		s.Assert().Equal("[]", bodyStr(b))
	})

	s.Step("check_resource_bulk.wrong_address.404", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "item-1", "type": "ORDER", "operation": "READ", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bul", h, body)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})
}
