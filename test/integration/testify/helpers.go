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

package runtimetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// RuntimeConfig holds environment-driven parameters for the test suite.
type RuntimeConfig struct {
	BaseURL               string
	PIPStubURL            string
	PIPStubInternalURL    string
	KcBaseURL             string
	KcClientID            string
	KcClientSecret        string
	KcExpiredClientID     string
	KcExpiredClientSecret string
	KcOrderReaderUser     string
	KcAdminUser           string
	KcPassword            string
	KcTokenScope          string
	KcExpiredWaitSeconds  int
	// EntitlementsMockURL is the control URL of the second pip-stub instance
	// that serves the entitlements endpoint; the suite pins and resets it
	// there. The agent reaches the same stub through AUTHZ_ENTITLEMENTS_URL.
	EntitlementsMockURL string
	// authz-agent-ADR-0062 cross-transport contract: the same OPA Data
	// API envelope is exposed on both the Envoy mount
	// (`/access/v1/authorize`) and the OPA-direct mount
	// (`/v1/data/authorize`). OPADirectURL is the address of the latter, the
	// OPA port of the agent Service, so the suite can drive both transports
	// from the same process for parity assertions.
	OPADirectURL string
	// ACStubURL is the URL of the authz-policy-admin that serves the
	// access-control v3 config API to the PolicyPuller. The pap-client pull
	// loop (AUTHZ_PAP_CLIENT_SOURCE_URL) points at the same service; the suite
	// uploads simplified policies through this address.
	// Default: http://localhost:18090
	ACStubURL string
	// PullInterval is the PolicyPuller tick interval that the agent-under-test is
	// configured with (AUTHZ_PAP_CLIENT_PULL_INTERVAL). waitForACPull sleeps for this
	// duration plus a grace period so mid-test stub uploads are guaranteed to be
	// applied before follow-up assertions run.
	// Default: 2s (test stacks must set AUTHZ_PAP_CLIENT_PULL_INTERVAL=2 or shorter).
	PullInterval time.Duration
	// M2MKeycloakProfile is true when the agent under test fetches its M2M
	// token from Keycloak (M2M_KEYCLOAK_PROFILE=true), as the kind harness
	// configures it. When false, m2m_keycloak catalog steps are skipped.
	M2MKeycloakProfile bool
	// OPAAuthToken is the shared bearer token that pap-client sends to OPA on
	// write requests (PUT/PATCH /v1/data/**). Used by opa_lockdown tests that
	// verify authenticated writes are accepted (authz-agent-ADR-0077).
	// The kind harness reads it from the chart's Secret. Default:
	// "test-opa-auth-token".
	OPAAuthToken string
}

// LoadConfig builds RuntimeConfig from environment variables. The kind Job
// sets every address to a Service name (suite.env in
// test/k8s/test-stand-values.yaml). The defaults only keep the config
// well-formed: the suite runs inside the cluster, where every target is
// reachable by Service name.
func LoadConfig() RuntimeConfig {
	waitSec := 6
	if v := os.Getenv("KC_EXPIRED_WAIT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			waitSec = n
		}
	}
	pullInterval := 2 * time.Second
	if v := os.Getenv("AUTHZ_PAP_CLIENT_PULL_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pullInterval = time.Duration(n) * time.Second
		}
	}
	clientID := envOr("KC_CLIENT_ID", "authz-agent")
	clientSecret := envOr("KC_CLIENT_SECRET", "authz-agent-secret")
	return RuntimeConfig{
		BaseURL:               envOr("BASE_URL", "http://localhost:18080"),
		PIPStubURL:            envOr("PIP_STUB_URL", "http://localhost:19999"),
		PIPStubInternalURL:    envOr("PIP_STUB_INTERNAL_URL", "http://pip-stub:8090"),
		KcBaseURL:             envOr("KC_BASE_URL", "http://localhost:15556/auth/realms/authz-test"),
		KcClientID:            clientID,
		KcClientSecret:        clientSecret,
		KcExpiredClientID:     envOr("KC_EXPIRED_CLIENT_ID", "authz-agent-expired"),
		KcExpiredClientSecret: envOr("KC_EXPIRED_CLIENT_SECRET", "authz-agent-expired-secret"),
		KcOrderReaderUser:     envOr("KC_USERNAME", "order-reader"),
		KcAdminUser:           envOr("KC_ADMIN_USERNAME", "admin"),
		KcPassword:            envOr("KC_PASSWORD", "password"),
		KcTokenScope:          envOr("KC_TOKEN_SCOPE", "openid"),
		KcExpiredWaitSeconds:  waitSec,
		ACStubURL:             envOr("AUTHZ_POLICY_ADMIN_URL", "http://localhost:18090"),
		EntitlementsMockURL:   envOr("ENTITLEMENTS_MOCK_URL", "http://localhost:19998"),
		OPADirectURL:          envOr("OPA_DIRECT_URL", "http://localhost:18181"),
		PullInterval:          pullInterval,
		M2MKeycloakProfile:    os.Getenv("M2M_KEYCLOAK_PROFILE") == "true",
		OPAAuthToken:          envOr("OPA_AUTH_TOKEN", "test-opa-auth-token"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setRequestIDHeader(req *http.Request, requestID string) {
	if strings.TrimSpace(requestID) == "" {
		return
	}
	req.Header.Set("X-Request-Id", requestID)
}

// WaitForKeycloak polls Keycloak OIDC discovery until it responds with 200 or timeout.
func WaitForKeycloak(kcBaseURL string, timeout time.Duration, requestID string) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", kcBaseURL+"/.well-known/openid-configuration", nil)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		setRequestIDHeader(req, requestID)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("keycloak not ready at %s after %v", kcBaseURL, timeout)
}

// GetKeycloakToken issues an access_token from Keycloak using the password grant.
func GetKeycloakToken(kcBaseURL, clientID, clientSecret, scope, username, password, requestID string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("scope", scope)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequest("POST", kcBaseURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setRequestIDHeader(req, requestID)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak token request failed: %d %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token in keycloak response")
	}
	return token, nil
}

// WaitForAgent polls authz-agent check endpoint until it responds with 200 or timeout.
func WaitForAgent(baseURL, adminToken string, timeout time.Duration, requestID string) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	body := `{"type":"ATTACHMENT","operation":"READ","resource":{}}`

	for time.Now().Before(deadline) {
		req, err := http.NewRequest("POST",
			baseURL+"/access/v1/check/resource?tenant_id=default",
			strings.NewReader(body))
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		setRequestIDHeader(req, requestID)

		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("authz-agent not ready at %s after %v", baseURL, timeout)
}

// ACStubDomain is the simplified-policy domain this suite seeds into. The stub
// serves access-control's own per-domain paths, so an upload needs a domain; the
// v3 export the PolicyPuller reads is the union of all domains, so a single one
// is enough here.
const ACStubDomain = "RUNTIME"

// UploadPoliciesToACStub sends simplified policies to the authz-policy-admin on
// access-control's own upload path so the PolicyPuller can fetch them on its
// next tick.
// authzPolicyAdminURL is the host-published URL of the authz-policy-admin (e.g. http://localhost:18090).
func UploadPoliciesToACStub(authzPolicyAdminURL string, policies []byte, requestID string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("PUT", authzPolicyAdminURL+"/access/v1/simplifiedPolicies/domainPolicies/"+ACStubDomain, bytes.NewReader(policies))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setRequestIDHeader(req, requestID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authz-policy-admin policy upload failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

// UploadPIPsToACStub sends simplified PIPs to the authz-policy-admin on access-control's
// own upload path.
func UploadPIPsToACStub(authzPolicyAdminURL string, pips []byte, requestID string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("PUT", authzPolicyAdminURL+"/access/v1/simplifiedPolicies/domainPIPs/"+ACStubDomain, bytes.NewReader(pips))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setRequestIDHeader(req, requestID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authz-policy-admin PIP upload failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

// WaitForACStub polls the authz-policy-admin until it responds with 200 or timeout.
func WaitForACStub(authzPolicyAdminURL string, timeout time.Duration, requestID string) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", authzPolicyAdminURL+"/authz-policy-admin/hash", nil)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		setRequestIDHeader(req, requestID)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("authz-policy-admin not ready at %s after %v", authzPolicyAdminURL, timeout)
}

// DoHTTP executes an HTTP request and returns status code and body bytes.
func DoHTTP(method, rawURL string, headers map[string]string, body interface{}) (int, []byte, error) {
	code, b, _, _, err := DoHTTPFull(method, rawURL, headers, body)
	return code, b, err
}

// DoHTTPFull is like DoHTTP but additionally returns the marshalled
// request body bytes and the response headers. Used by suite wrappers
// that pipe the exchange through OpenAPI spec validation.
func DoHTTPFull(method, rawURL string, headers map[string]string, body interface{}) (int, []byte, []byte, http.Header, error) {
	var bodyBytes []byte
	if body != nil {
		switch v := body.(type) {
		case []byte:
			bodyBytes = v
		case string:
			bodyBytes = []byte(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return 0, nil, nil, nil, err
			}
			bodyBytes = b
		}
	}

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, bodyBytes, resp.Header.Clone(), err
	}
	return resp.StatusCode, respBody, bodyBytes, resp.Header.Clone(), nil
}
