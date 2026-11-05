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

import "strings"

func (s *RuntimeSuite) TestCheckFilter() {
	s.Step("check_filter.calculation_result_present", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.unknown_type.deny", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		s.Assert().Equal("DENY", jsonObj(b)["calculationResult"])
	})

	// A denial carries its result and no filter text: legacy answers null in
	// each of the five condition fields.
	s.Step("check_filter.deny_all_fields", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		s.Assert().Equal("DENY", j["calculationResult"])
		for _, field := range []string{
			"filterCondition", "mongodbFilterCondition", "rsqlFilterCondition",
			"sqlFilterCondition", "customFilterCondition",
		} {
			v, ok := j[field]
			s.Assert().True(ok && v == nil, "field %s = %v (present %t), want JSON null", field, v, ok)
		}
	})

	s.Step("check_filter.known_resource.not_null", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ATTACHMENT&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.missing_operation", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ATTACHMENT", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.unknown_tenant_id.deny", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ&tenant_id=completely-different-tenant", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		s.Assert().Equal("DENY", jsonObj(b)["calculationResult"])
	})

	s.Step("check_filter.no_token.401", func() {
		code, b := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ", jsonHeader(), map[string]interface{}{})
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
	})

	s.Step("check_filter.missing_resource_type.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.postRaw("/access/v1/check/filter?operation=READ", h, map[string]interface{}{})
		s.Require().Equal(400, code)
		s.Assert().Equal("bad request", jsonObj(b)["message"])
	})

	// `filterCondition` is null on the simplified-policy path (legacy's
	// generic `predicate` template does not exist in simplified format).
	// Two-fragment RSQL
	// aggregation is flat comma-joined — legacy does not wrap each
	// item in parentheses.
	s.Step("check_filter.multi_frag.rsql_or_aggregation", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=MULTI_FRAG_ITEM&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("USE_FILTER_CONDITION", j["calculationResult"])
		rsql, _ := j["rsqlFilterCondition"].(string)
		s.Assert().Equal("dept==engineering,dept==management", rsql,
			"rsqlFilterCondition must be flat comma-joined, got: %s", rsql)
		s.Assert().Nil(j["filterCondition"],
			"filterCondition is null on the simplified-policy path, got: %v", j["filterCondition"])
	})

	s.Step("check_filter.wrong_address.404", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filte?resourceType=ORDER&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	// The rsql filter names the subject by the id in its token: the policy's
	// ${subject.id} template is substituted.
	s.Step("check_filter.predicate_subject_attr_substituted", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=PUBLIC_DOC&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("USE_FILTER_CONDITION", j["calculationResult"])
		rsql, _ := j["rsqlFilterCondition"].(string)
		s.Assert().True(strings.HasPrefix(rsql, "subjectId=="),
			"rsqlFilterCondition must start with subjectId==, got: %s", rsql)
		s.Assert().NotContains(rsql, "${subject.",
			"${subject.id} must be substituted, got: %s", rsql)
		s.Assert().Greater(len(rsql), len("subjectId=="),
			"the substituted id must not be empty, got: %s", rsql)
	})
}
