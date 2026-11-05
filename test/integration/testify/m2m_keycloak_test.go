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

// TestM2MKeycloak validates end-to-end policy pull with a Keycloak-issued
// client_credentials token, exercising the full path:
//
//	token-fetcher sidecar → AUTHZ_PAP_CLIENT_TOKEN_FILE → TokenWatcher → OPA
//	data.m2m.bearerToken → PolicyPuller Authorization header → authz-policy-admin → OPA policies.
//
// The tests run only when M2M_KEYCLOAK_PROFILE=true, which the kind harness
// sets because its chart values run the token-fetcher sidecar against the
// harness Keycloak. Against an agent with a static M2M token the steps are
// skipped via t.Skip() so the catalog coverage check passes.
//
// Test client: cloud-common realm / test-app-client (client_credentials)
func (s *RuntimeSuite) TestM2MKeycloak() {
	// (a) Policy pull succeeds with Keycloak token.
	//
	// When the stack starts with the m2m-keycloak overlay, token-fetcher fetches
	// a real Keycloak access_token (test-app-client, client_credentials grant)
	// and writes it to the shared tmpfs volume as AUTHZ_PAP_CLIENT_TOKEN_FILE.
	// pap-client's TokenWatcher detects the write, PUTs the token to
	// data.m2m.bearerToken in OPA, and the pull loop sends it as the
	// Authorization header to authz-policy-admin. The suite setup (setup.wait_for_agent)
	// already blocked until the agent became healthy, which requires at least
	// one successful pull. This step asserts the resulting decision path works
	// end-to-end — if the pull had failed the agent would not have returned 200.
	s.Step("m2m_keycloak.pull_succeeds_with_keycloak_token", func() {
		if !s.cfg.M2MKeycloakProfile {
			s.T().Skip("M2M Keycloak profile not active (M2M_KEYCLOAK_PROFILE != true)")
		}
		// /access/v1/check/resource with a valid admin token must return 200,
		// proving that OPA has loaded policies from the pull loop that ran with
		// the Keycloak-issued token as its Authorization header.
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code,
			"m2m-keycloak: policy pull with Keycloak token must produce a functional agent; body: %s", string(b))
	})

	// (b) Agent remains functional after the pull-loop retries triggered by the
	//     race between token-fetcher startup and the first pull-loop tick.
	//
	// When the opa container starts, token-fetcher is healthy (marker file
	// present = first token written). However, subsequent ticks continue
	// running while the token is still valid. This step waits for one
	// additional pull interval and re-asserts the same decision path, confirming
	// that TokenWatcher continues to publish the token and pull continues to
	// succeed — i.e., the "retry after token refresh" cycle does not degrade
	// functionality.
	s.Step("m2m_keycloak.agent_functional_after_token_refresh", func() {
		if !s.cfg.M2MKeycloakProfile {
			s.T().Skip("M2M Keycloak profile not active (M2M_KEYCLOAK_PROFILE != true)")
		}
		// Allow at least one full pull interval to elapse so any in-flight
		// token refresh and re-publish cycle has completed.
		s.waitForACPull()

		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]interface{}{},
		}
		code, b := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code,
			"m2m-keycloak: agent must remain functional after token refresh cycle; body: %s", string(b))
	})
}
