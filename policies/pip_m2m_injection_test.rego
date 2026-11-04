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

package pip_m2m_injection_test

import rego.v1

# ── helpers ──────────────────────────────────────────────────────────────────
#
# A minimal pip_config for a single GENERAL PIP with no explicit authorization.
# The PIP is always active (activation entry covers ALL resource types and ops).

general_pip_cfg(pip_name, url) := {
	"local": {"token": {}, "header": {}},
	"remote": {
		"general": {
			pip_name: {
				"name": pip_name,
				"alias": "testAlias",
				"url": url,
				"httpMethod": "GET",
			},
		},
	},
	"activation": {
		"generalByResourceTypeOperation": {
			"ALL": {"ALL": [pip_name]},
		},
	},
}

# ── Test: token present, PIP has no own authorization → injected ─────────────

test_m2m_header_injected_when_no_own_authorization if {
	# OPA mock: always returns a trivial JSON response.
	captured_headers := data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": "tok-abc123"}

	captured_headers["authorization"] == "Bearer tok-abc123"
}

# ── Test: token present, PIP has own authorization in setHeaders → not injected ─

test_m2m_header_not_injected_when_set_headers_supply_authorization if {
	captured_headers := data.pip.build_headers(
		{
			"url": "http://pip/data",
			"httpMethod": "GET",
			"setHeaders": {"Authorization": "Bearer own-token"},
		},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": "tok-abc123"}

	# setHeaders wins; M2M token must NOT appear.
	captured_headers["authorization"] == "Bearer own-token"
}

# ── Test: token present, PIP has own authorization in forwardHeaders → not injected ─

test_m2m_header_not_injected_when_forward_headers_supply_authorization if {
	captured_headers := data.pip.build_headers(
		{
			"url": "http://pip/data",
			"httpMethod": "GET",
			"forwardHeaders": ["Authorization"],
		},
		{"id": "user1"},
		{},
	) with input.requestHeaders as {"authorization": "Bearer forwarded-token"}
	  with data.m2m as {"bearerToken": "tok-abc123"}

	# forwardHeaders wins; M2M token must NOT replace it.
	captured_headers["authorization"] == "Bearer forwarded-token"
}

# ── Test: no current token → the PIP is not called ──────────────────────────

test_no_call_when_token_absent if {
	not data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {}
}

test_no_call_when_token_empty_string if {
	not data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": ""}
}

test_no_call_when_token_expired if {
	not data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": "tok-abc123", "expiresAtNs": time.now_ns() - 1}
}

test_m2m_header_injected_before_expiry if {
	h := data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": "tok-abc123", "expiresAtNs": time.now_ns() + 60000000000}

	h.authorization == "Bearer tok-abc123"
}

test_m2m_header_injected_without_known_expiry if {
	h := data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{"id": "user1"},
		{},
	) with data.m2m as {"bearerToken": "tok-abc123", "expiresAtNs": 0}

	h.authorization == "Bearer tok-abc123"
}

# A PIP whose own setHeaders carry an authorization is called without a token
# of the agent (ADR-0076).
test_own_authorization_called_without_token if {
	h := data.pip.build_headers(
		{
			"url": "http://pip/data",
			"httpMethod": "GET",
			"setHeaders": {"Authorization": "Bearer own-token"},
		},
		{"id": "user1"},
		{},
	) with data.m2m as {}

	h.authorization == "Bearer own-token"
}

# The deny reason names the missing token, not a substitution failure.
test_hard_failure_kind_no_token if {
	data.pip.hard_failure_kind(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{},
		{"id": "user1"},
	) == "no_token" with data.m2m as {"bearerToken": "tok", "expiresAtNs": time.now_ns() - 1}
}

# ── Test: m2m_bearer_token default is empty ───────────────────────────────────

test_m2m_bearer_token_defaults_to_empty if {
	data.pip.m2m_bearer_token == "" with data.m2m as {}
}

# ── Test: token updated → next build_headers call uses new value ──────────────

test_m2m_header_uses_updated_token if {
	# First value.
	h1 := data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{},
		{},
	) with data.m2m as {"bearerToken": "token-v1"}

	h1["authorization"] == "Bearer token-v1"

	# Simulate a token refresh by overriding data.pips.
	h2 := data.pip.build_headers(
		{"url": "http://pip/data", "httpMethod": "GET"},
		{},
		{},
	) with data.m2m as {"bearerToken": "token-v2"}

	h2["authorization"] == "Bearer token-v2"
}
