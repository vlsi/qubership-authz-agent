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

func (s *RuntimeSuite) TestRouteSecurity() {
	s.Step("route_security.authorize_hidden.404", func() {
		body := map[string]interface{}{
			"resources": []map[string]interface{}{{"resourceType": "ORDER", "operation": "READ"}},
			"subject":   "Bearer " + s.validAdminToken,
		}
		code, b := s.post("/authorize", jsonHeader(), body)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	// The agent serves the access-control check API and no decision route
	// of its own, so /access/v1/authorize is a path it does not know.
	s.Step("route_security.access_authorize_absent.404", func() {
		token := "Bearer " + s.validAdminToken
		body := map[string]interface{}{"input": map[string]interface{}{
			"authorizationToken": token,
			"subject":            token,
			"resources":          []map[string]interface{}{{"resourceType": "ORDER", "operation": "READ"}},
		}}
		code, b := s.post("/access/v1/authorize", jsonHeader(), body)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	s.Step("route_security.unknown_path.404", func() {
		code, b := s.get("/unknown/endpoint", nil)
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})

	// v2 surface implemented in Envoy.
	// /access/v2/check/resource lands via check_resource_v2.lua and
	// returns the {"decision": bool} wrapper shape the v2 thin client
	// expects. Admin token here has no policy granting ORDER READ so the
	// response is {"decision": false}.
	s.Step("route_security.v2_check_resource.implemented", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ORDER", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, b := s.post("/access/v2/check/resource?obligations=false", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		_, hasDecision := j["decision"].(bool)
		s.Assert().True(hasDecision, "response must include a boolean decision field; got %s", string(b))
	})

	// /access/v1/check/resource/bulk/operations and
	// /preview/v1/check/resource/bulk/operations are
	// Envoy routes backed by check_resource_bulk_operations.lua. The
	// historical route-security 404 assertion is replaced with a basic
	// positive-shape assertion against the admin token (which has no
	// policy granting ORDER READ, so the response is a valid map with
	// an empty "READ" array).
	s.Step("route_security.v1_bulk_operations.implemented", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := []map[string]interface{}{
			{"id": "some-id", "operations": []string{"READ"}, "type": "ORDER", "resource": map[string]interface{}{}},
		}
		code, b := s.post("/access/v1/check/resource/bulk/operations", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		decoded := jsonObj(b)
		_, hasRead := decoded["READ"]
		s.Assert().True(hasRead, "response must include a READ key; got %s", string(b))
	})

	// v2 bulk/operations implemented via
	// check_resource_bulk_operations_v2.lua — same canonical path as v1
	// bulk/operations but wrapped in `{"decision": {...}}` for the v2
	// response shape.
	s.Step("route_security.v2_bulk_operations.implemented", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ORDER",
			"entries": []map[string]interface{}{
				{"id": "some-id", "operations": []string{"READ"}, "resource": map[string]interface{}{}},
			},
		}
		code, b := s.post("/access/v2/check/resource/bulk/operations?obligations=false", h, body)
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		decision, hasDecision := j["decision"].(map[string]interface{})
		s.Assert().True(hasDecision, "response must include a decision map; got %s", string(b))
		_, hasRead := decision["READ"]
		s.Assert().True(hasRead, "response decision must include READ key; got %s", string(b))
	})

	// v2 check/filter reuses the v1 check_filter.lua
	// filter — the legacy wire shape is identical between v1 and v2 on
	// check/filter, and the v2 thin client only differs in the query
	// string (obligations=false) which Envoy does not read.
	s.Step("route_security.v2_check_filter.implemented", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v2/check/filter?resourceType=ORDER&operation=READ&obligations=false", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		_, hasCalc := j["calculationResult"].(string)
		s.Assert().True(hasCalc, "response must include calculationResult; got %s", string(b))
	})

	// /api-version is an Envoy-owned static handler returning the
	// legacy byte shape so the thin client's interceptor selection can pick
	// the relay (Incoming-Token) path. The response is served directly by
	// Envoy and never reaches OPA; it must be reachable without any
	// Authorization headers.
	s.Step("route_security.api_version.static", func() {
		code, b := s.get("/api-version", nil)
		s.Require().Equal(200, code)
		obj := jsonObj(b)
		specs, ok := obj["specs"].([]interface{})
		s.Require().True(ok, "body must have specs array: %s", bodyStr(b))
		s.Require().NotEmpty(specs, "specs array must not be empty")

		// Verify the legacy byte shape: integer major/minor/supportedMajors
		// (match legacy golden byte-for-byte). Row-0 of specs is
		// /access and its major must be an integer, not a string.
		first, ok := specs[0].(map[string]interface{})
		s.Require().True(ok, "specs[0] must be object")
		s.Assert().Equal("/access", first["specRootUrl"])
		_, majorIsNumber := first["major"].(float64)
		s.Assert().True(majorIsNumber, "specs[0].major must be a JSON number, got %T", first["major"])
	})
}
