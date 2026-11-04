# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package pip_request_args_test

import rego.v1

# m2m_token is a current token of the agent: without one no GENERAL PIP is called.
m2m_token := {"bearerToken": "test-token"}

# Test-plan §B (template expansion, shared jsonPath, general_pip_call, response
# extract/coerce/onMissing) and §F (extraction matrix + null-safety) for the
# GENERAL PIP request-args contract (authz-agent-ADR-0066..0069).

# Shared §F fixture body.
fixture := {
	"data": {"ids": [{"id": "C1"}, {"id": "C2"}], "count": 2, "flag": true, "note": null},
	"empty": [],
	"scalar": "x",
	"nested": {"a": [{"b": [{"c": 1}, {"c": 2}]}]},
}

# ── §F: shared jsonPath evaluator (positive) ─────────────────────────────

test_jsonpath_root if {
	data.pip.json_extract(fixture, "$") == fixture
}

test_jsonpath_scalar_number if {
	data.pip.json_extract(fixture, "$.data.count") == 2
}

test_jsonpath_scalar_bool if {
	data.pip.json_extract(fixture, "$.data.flag") == true
}

test_jsonpath_index if {
	data.pip.json_extract(fixture, "$.data.ids[0].id") == "C1"
}

test_jsonpath_wildcard if {
	data.pip.json_extract(fixture, "$.data.ids[*].id") == ["C1", "C2"]
}

test_jsonpath_nested_wildcard_flatten if {
	data.pip.json_extract(fixture, "$.nested.a[*].b[*].c") == [1, 2]
}

test_jsonpath_empty_wildcard if {
	data.pip.json_extract(fixture, "$.empty[*]") == []
}

test_jsonpath_null_value_present if {
	# a null value is a present value (null ≡ missing is applied at the response layer)
	data.pip.json_extract(fixture, "$.data.note") == null
}

# ── §F: null-safety negatives — each a miss, never a runtime error ───────

test_jsonpath_missing_intermediate if {
	not data.pip.json_extract(fixture, "$.data.missing.ids")
}

test_jsonpath_into_null if {
	not data.pip.json_extract(fixture, "$.data.note.x")
}

test_jsonpath_index_oob if {
	not data.pip.json_extract(fixture, "$.data.ids[9].id")
}

test_jsonpath_index_on_nonarray if {
	not data.pip.json_extract(fixture, "$.scalar[0]")
}

test_jsonpath_field_on_nonobject if {
	not data.pip.json_extract(fixture, "$.scalar.x")
}

test_jsonpath_wildcard_on_nonarray_is_empty if {
	# wildcard on a non-array yields [] (never a crash)
	data.pip.json_extract(fixture, "$.scalar[*]") == []
}

# ── §B/§F: coerce ────────────────────────────────────────────────────────

test_coerce_number if {
	data.pip.coerce_value(2, "number") == 2
}

test_coerce_bool if {
	data.pip.coerce_value(true, "bool") == true
}

test_coerce_string_from_number if {
	data.pip.coerce_value(2, "string") == "2"
}

test_coerce_string_array if {
	data.pip.coerce_value(["C1", "C2"], "string[]") == ["C1", "C2"]
}

test_coerce_number_array if {
	data.pip.coerce_value([1, 2], "number[]") == [1, 2]
}

test_coerce_mismatch_array_as_string if {
	not data.pip.coerce_value(["C1"], "string")
}

test_coerce_mismatch_scalar_as_number if {
	not data.pip.coerce_value("x", "number")
}

# ── §F: response_value extract + coerce + onMissing matrix ───────────────

resp := {"status_code": 200, "body": fixture}

test_response_extract_string_array if {
	cfg := {"alias": "a", "response": {"extract": "$.data.ids[*].id", "coerce": "string[]"}}
	data.pip.response_value(cfg, resp) == ["C1", "C2"]
}

test_response_extract_whole_body if {
	cfg := {"alias": "a"}
	data.pip.response_value(cfg, resp) == fixture
}

test_response_miss_onmissing_default if {
	cfg := {"alias": "a", "defaultValue": ["D"], "response": {"extract": "$.data.missing", "onMissing": "defaultValue"}}
	data.pip.response_value(cfg, resp) == ["D"]
}

test_response_miss_onmissing_empty if {
	cfg := {"alias": "a", "response": {"extract": "$.data.missing", "coerce": "string[]", "onMissing": "empty"}}
	data.pip.response_value(cfg, resp) == []
}

test_response_miss_onmissing_error_is_operand_fail if {
	cfg := {"alias": "a", "response": {"extract": "$.data.missing", "onMissing": "error"}}
	not data.pip.response_value(cfg, resp)
}

test_response_null_is_missing if {
	# $.data.note is null → treated as missing → onMissing
	cfg := {"alias": "a", "defaultValue": "D", "response": {"extract": "$.data.note", "onMissing": "defaultValue"}}
	data.pip.response_value(cfg, resp) == "D"
}

test_response_coerce_mismatch_routes_to_onmissing if {
	# $.data.ids (array) coerced as string → mismatch → onMissing default
	cfg := {"alias": "a", "defaultValue": "D", "response": {"extract": "$.data.ids", "coerce": "string", "onMissing": "defaultValue"}}
	data.pip.response_value(cfg, resp) == "D"
}

test_response_map_extract if {
	cfg := {"alias": "a", "response": {"extract": {"ids": "$.data.ids[*].id", "count": "$.data.count"}}}
	data.pip.response_value(cfg, resp) == {"ids": ["C1", "C2"], "count": 2}
}

test_response_map_per_entry_miss if {
	# one entry misses with per-entry onMissing:empty; sibling unaffected
	cfg := {"alias": "a", "response": {
		"extract": {"ids": {"path": "$.data.ids[*].id"}, "gone": {"path": "$.data.missing", "coerce": "string[]", "onMissing": "empty"}},
		"coerce": "string[]",
	}}
	got := data.pip.response_value(cfg, resp)
	got.ids == ["C1", "C2"]
	got.gone == []
}

test_response_non_json_body_is_operand_fail if {
	# a non-JSON string body with onMissing:error → operand fail, no runtime error
	cfg := {"alias": "a", "response": {"extract": "$.x", "onMissing": "error"}}
	not data.pip.response_value(cfg, {"status_code": 200, "body": "not-json"})
}

test_response_non_json_body_default if {
	cfg := {"alias": "a", "defaultValue": "D", "response": {"extract": "$.x", "onMissing": "defaultValue"}}
	data.pip.response_value(cfg, {"status_code": 200, "body": "not-json"}) == "D"
}

test_response_http_error_uses_default if {
	cfg := {"alias": "a", "defaultValue": [], "response": {"onMissing": "defaultValue"}}
	data.pip.response_value(cfg, {"status_code": 0, "body": null}) == []
}

test_response_http_error_no_default_is_fail if {
	cfg := {"alias": "a", "response": {"extract": "$.x", "onMissing": "error"}}
	not data.pip.response_value(cfg, {"status_code": 500, "body": null})
}

# Regression (review F-1): onMissing:empty must bind the empty value on an http
# error / non-200 / non-JSON body too — uniform with the 200 extract-miss path —
# not silently degrade to `error` (alias absent). Previously `empty` was dead on
# the soft-default path, which only handled `defaultValue`.
test_response_http_error_onmissing_empty_array if {
	cfg := {"alias": "a", "response": {"onMissing": "empty", "coerce": "string[]"}}
	data.pip.response_value(cfg, {"status_code": 503, "body": null}) == []
}

test_response_http_error_onmissing_empty_string if {
	cfg := {"alias": "a", "response": {"onMissing": "empty", "coerce": "string"}}
	data.pip.response_value(cfg, {"status_code": 503, "body": null}) == ""
}

test_response_non_json_body_onmissing_empty if {
	cfg := {"alias": "a", "response": {"extract": "$.x", "onMissing": "empty", "coerce": "string[]"}}
	data.pip.response_value(cfg, {"status_code": 200, "body": "not-json"}) == []
}

# ── §B: ${...} template expansion ────────────────────────────────────────

sub := {"id": "u1", "roles": [{"name": "r1"}, {"name": "r2"}]}

test_expand_whole_value_keeps_native_scalar if {
	data.pip.expand_string("${subject.id}", sub, {}) == "u1"
}

test_expand_whole_value_keeps_native_array if {
	data.pip.expand_string("${subject.roles[*].name}", sub, {}) == ["r1", "r2"]
}

test_expand_embedded_scalar_string if {
	data.pip.expand_string("id-${subject.id}", sub, {}) == "id-u1"
}

test_expand_embedded_nonscalar_is_operand_fail if {
	not data.pip.expand_string("x-${subject.roles[*].name}", sub, {})
}

test_expand_whole_value_absent_is_null if {
	data.pip.expand_string("${subject.absent}", sub, {}) == null
}

test_expand_embedded_absent_is_operand_fail if {
	not data.pip.expand_string("x-${subject.absent}", sub, {})
}

test_expand_resource_scope if {
	data.pip.expand_string("${resource.type}", sub, {"type": "Customer"}) == "Customer"
}

test_strip_crlf if {
	data.pip.strip_crlf("a\r\nb") == "ab"
}

# ── §B: build_pip_request (substitution into url/query/headers/body) ──────

test_build_request_substitutes_all if {
	cfg := {
		"url": "http://pip/allowed/${subject.id}",
		"httpMethod": "POST",
		"query": {"tenant": "${subject.id}"},
		"setHeaders": {"X-Trace": "${subject.id}"},
		"body": {"id": "${subject.id}", "roles": "${subject.roles[*].name}", "label": "customer-${subject.id}"},
		"timeoutSeconds": 7,
	}
	req := data.pip.build_pip_request(cfg, {}, sub) with data.m2m as m2m_token
	req.method == "POST"
	req.url == "http://pip/allowed/u1?tenant=u1"
	req.headers["x-trace"] == "u1"
	req.headers["content-type"] == "application/json" # object body auto CT (G9)
	req.timeout == "7s"
	req.body.id == "u1"
	req.body.roles == ["r1", "r2"] # whole-value keeps native array
	req.body.label == "customer-u1" # embedded → string
}

test_build_request_urlencodes_query if {
	cfg := {"url": "http://pip/x", "httpMethod": "GET", "query": {"q": "${subject.v}"}}
	req := data.pip.build_pip_request(cfg, {}, {"v": "a/b c"}) with data.m2m as m2m_token
	# value URL-encoded (no raw '/' or space)
	not contains(req.url, "a/b c")
	contains(req.url, "q=")
}

test_build_request_nonscalar_embedded_fails if {
	cfg := {"url": "http://pip/x-${subject.roles[*].name}", "httpMethod": "GET"}
	not data.pip.build_pip_request(cfg, {}, sub) with data.m2m as m2m_token
}

# Regression (review F-2): a whole-value placeholder that resolves to a non-scalar
# (array/object) in a QUERY value must fail the operand, not emit a URL-encoded
# stringification of the array. Parity with the header path.
test_expand_query_nonscalar_is_operand_fail if {
	not data.pip.expand_query({"roles": "${subject.roles[*].name}"}, sub, {})
}

test_build_request_nonscalar_query_fails if {
	cfg := {"url": "http://pip/x", "httpMethod": "GET", "query": {"roles": "${subject.roles[*].name}"}}
	not data.pip.build_pip_request(cfg, {}, sub) with data.m2m as m2m_token
}

# Regression (review F-4): a whole-value URL placeholder resolving to a non-string
# makes expand_url undefined (operand fail / substitution), not a malformed
# http.send url that only surfaces as status-0 http_error.
test_expand_url_wholevalue_nonstring_is_operand_fail if {
	not data.pip.expand_url("${subject.roles}", sub, {})
}

test_expand_url_wholevalue_string_ok if {
	data.pip.expand_url("${subject.home}", {"home": "http://h/x"}, {}) == "http://h/x"
}

# Regression: embedded body value with a JSON-special char is escaped correctly
# (object-level substitution), never a corrupted/silent-empty body.
test_build_body_escapes_special_chars if {
	cfg := {"url": "http://x", "httpMethod": "POST", "body": {"label": "customer-${subject.id}"}}
	req := data.pip.build_pip_request(cfg, {}, {"id": "a\"b"}) with data.m2m as m2m_token
	req.body.label == "customer-a\"b"
}

# Regression: a missing embedded body placeholder fails the operand (undefined),
# NOT a silent empty body.
test_build_body_missing_embedded_is_operand_fail if {
	cfg := {"url": "http://x", "httpMethod": "POST", "body": {"label": "customer-${subject.tenant}"}}
	not data.pip.build_pip_request(cfg, {}, {"id": "u1"}) with data.m2m as m2m_token
}

# Regression: no double-substitution — a resolved value that looks like a
# placeholder stays literal.
test_build_body_no_double_substitution if {
	body := data.pip.build_body({"body": {"note": "${subject.note}"}}, {"note": "${resource.id}"}, {"id": "r42"})
	body.note == "${resource.id}"
}

# Regression: url-path substituted values are URL-encoded (/ and space).
test_build_url_encodes_path_value if {
	cfg := {"url": "http://pip/user/${subject.id}/data", "httpMethod": "GET"}
	req := data.pip.build_pip_request(cfg, {}, {"id": "a/b c"}) with data.m2m as m2m_token
	req.url == "http://pip/user/a%2Fb+c/data"
}

# Regression: a real response body shaped like the miss sentinel is NOT treated
# as a miss (sentinel is a set, bodies are never sets).
test_response_sentinel_no_collision if {
	cfg := {"alias": "a", "response": {"extract": "$.weird"}}
	resp := {"status_code": 200, "body": {"weird": {"__pip_miss__": true}}}
	data.pip.response_value(cfg, resp) == {"__pip_miss__": true}
}

# ── §B/§G: general_pip_call injects x-request-id (wins over user header) ──

mock_echo(req) := req

test_general_pip_call_injects_request_id if {
	req := {"method": "POST", "url": "http://x", "headers": {"a": "b"}, "body": "", "timeout": "5s"}
	sent := data.pip.general_pip_call(req) with http.send as mock_echo with input as {"requestId": "R-123"}
	sent.headers["x-request-id"] == "R-123"
	sent.raise_error == false
}

test_general_pip_call_request_id_wins_over_user_header if {
	req := {"method": "POST", "url": "http://x", "headers": {"x-request-id": "spoofed"}, "body": "", "timeout": "5s"}
	sent := data.pip.general_pip_call(req) with http.send as mock_echo with input as {"requestId": "R-123"}
	sent.headers["x-request-id"] == "R-123"
}

test_general_pip_call_generates_stable_id_when_absent if {
	req := {"method": "GET", "url": "http://x", "headers": {}, "body": "", "timeout": "5s"}
	a := data.pip.general_pip_call(req) with http.send as mock_echo with input as {}
	b := data.pip.general_pip_call(req) with http.send as mock_echo with input as {}
	# a stable, non-empty id, identical across call sites within one evaluation
	a.headers["x-request-id"] != ""
	a.headers["x-request-id"] == b.headers["x-request-id"]
}

# ── §B: resolve_general_values end-to-end (mock http.send) ───────────────

test_resolve_general_end_to_end if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {"subject.allowedIds": {
			"name": "subject.allowedIds",
			"alias": "allowedIds",
			"url": "http://pip/allowed/${subject.id}",
			"httpMethod": "POST",
			"body": {"id": "${subject.id}"},
			"response": {"extract": "$.data.ids[*].id", "coerce": "string[]"},
		}}},
		"activation": {"generalByResourceTypeOperation": {"CUSTOMER": {"READ": ["subject.allowedIds"]}}},
	}
	mock := {"status_code": 200, "body": {"data": {"ids": [{"id": "C1"}, {"id": "C2"}]}}}
	result := data.pip.resolve_general_values("CUSTOMER", "READ", {}, {"id": "u1"}) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock
	result.allowedIds == ["C1", "C2"]
}

# NEW-2: hard-failure classification for deny-reason enrichment.
gpc(cfg_extra, mock) := failures if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {"subject.x": object.union({"name": "subject.x", "alias": "x", "url": "http://pip/x", "httpMethod": "POST"}, cfg_extra)}},
		"activation": {"generalByResourceTypeOperation": {"CUSTOMER": {"READ": ["subject.x"]}}},
	}
	failures := data.pip.general_pip_hard_failures("CUSTOMER", "READ", {}, {"id": "u1"}) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock
}

test_hard_failure_kind_response if {
	# 200 but onMissing:error extract miss → kind "response"
	gpc({"response": {"extract": "$.nope", "onMissing": "error"}}, {"status_code": 200, "body": {"a": 1}}) == {"x": "response"}
}

test_hard_failure_kind_http_error if {
	# non-200 with no default → kind "http_error"
	gpc({"response": {"extract": "$.a", "onMissing": "error"}}, {"status_code": 500, "body": null}) == {"x": "http_error"}
}

test_hard_failure_soft_default_not_recorded if {
	# soft default → alias present → NOT a hard failure
	gpc({"defaultValue": [], "response": {"extract": "$.nope", "onMissing": "defaultValue"}}, {"status_code": 200, "body": {"a": 1}}) == {}
}

test_hard_failure_soft_default_false_not_recorded if {
	# a boolean-false soft default is PRESENT, not a hard failure (regression:
	# `not general_pip_value` would have mis-fired on false).
	gpc({"defaultValue": false, "response": {"extract": "$.a", "onMissing": "defaultValue"}}, {"status_code": 500, "body": null}) == {}
}

test_hard_failure_kind_substitution if {
	# a non-scalar embedded url placeholder → request can't be built → "substitution"
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {"subject.x": {"name": "subject.x", "alias": "x", "url": "http://pip/${subject.roles[*].name}-x", "httpMethod": "POST"}}},
		"activation": {"generalByResourceTypeOperation": {"CUSTOMER": {"READ": ["subject.x"]}}},
	}
	data.pip.general_pip_hard_failures("CUSTOMER", "READ", {}, {"roles": [{"name": "a"}, {"name": "b"}]}) with data.pips as pip_config with data.m2m as m2m_token with http.send as {"status_code": 200, "body": {}} == {"x": "substitution"}
}

test_resolve_general_operand_fail_omits_alias if {
	# onMissing:error + extract miss → alias absent (operand-local fail)
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {"subject.x": {
			"name": "subject.x", "alias": "x",
			"url": "http://pip/x", "httpMethod": "POST",
			"response": {"extract": "$.nope", "onMissing": "error"},
		}}},
		"activation": {"generalByResourceTypeOperation": {"CUSTOMER": {"READ": ["subject.x"]}}},
	}
	mock := {"status_code": 200, "body": {"a": 1}}
	result := data.pip.resolve_general_values("CUSTOMER", "READ", {}, {"id": "u1"}) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock
	not result.x
}
