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
	"regexp"
	"sort"
	"strings"
	"time"
)

// fullJWTPattern matches a complete JWT with or without a `Bearer ` prefix:
// header, payload and signature. `eyJ` is base64url for `{"`, the start of
// every JWT header. A logged token must have lost its signature.
var fullJWTPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

func (s *RuntimeSuite) TestDecisionLogs() {
	// Positive regression: GET /internal/v1/decision-logs with no
	// pap-client token header must succeed. Body may be empty when
	// the collector has not received any events yet; the assertion is
	// purely on the 200 status and on a parseable JSON-stream body when
	// non-empty.
	s.Step("decision_logs.download_no_token.200", func() {
		status, body := s.get("/internal/v1/decision-logs", nil)
		s.Require().Equal(200, status, "expected 200 without token, got %d body=%s", status, bodyStr(body))
		content := strings.TrimSpace(string(body))
		if content == "" {
			return
		}
		for i, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var obj map[string]any
			err := json.Unmarshal([]byte(line), &obj)
			s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)
		}
	})

	// Make a legacy check/resource request to seed a decision log entry with a known request ID.
	s.Step("decision_logs.legacy_path_header", func() {
		h := incomingTokenHeader(s.validAdminToken)
		body := map[string]interface{}{
			"type": "ATTACHMENT", "operation": "READ", "resource": map[string]interface{}{},
		}
		code, _ := s.post("/access/v1/check/resource", h, body)
		s.Require().Equal(200, code)
	})

	s.Step("decision_logs.content_is_ndjson", func() {
		// The agent's decision logger delivers events in batches at most a
		// second apart (the default FlushInterval), so an event of an earlier
		// step can appear only after this step starts. Retry until every
		// request ID in requiredRequestIDs is present or the deadline passes,
		// rather than stopping at the first non-empty download.
		requiredRequestIDs := []string{
			"setup.wait_for_agent",
			"check_resource.order_read.rls_deny",
			"check_resource_bulk.owner_mismatch.denied",
			"check_filter.calculation_result_present",
		}

		var content string
		var seenRequestIDs map[string]bool
		var logsByRequestID map[string]map[string]any
		authorizeEvents := 0

		deadline := time.Now().Add(35 * time.Second)
		for {
			status, responseBody := s.get("/internal/v1/decision-logs", nil)
			s.Require().Equal(200, status)
			content = strings.TrimSpace(string(responseBody))

			seenRequestIDs = map[string]bool{}
			logsByRequestID = map[string]map[string]any{}
			authorizeEvents = 0

			// Verify every non-empty line is valid JSON and index by x-request-id.
			for i, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var obj map[string]any
				err := json.Unmarshal([]byte(line), &obj)
				s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)

				if !decisionLogTargetsAuthorize(obj) {
					continue
				}

				authorizeEvents++
				requestIDs := decisionLogHeaderValues(obj, "x-request-id")
				s.Require().NotEmpty(requestIDs, "authorize decision log line %d must include x-request-id", i+1)
				for _, requestID := range requestIDs {
					_, knownStep := CatalogByName[requestID]
					s.Require().True(knownStep, "authorize decision log line %d contains unknown x-request-id %q", i+1, requestID)
					seenRequestIDs[requestID] = true
					logsByRequestID[requestID] = obj
				}
			}

			allPresent := true
			for _, requestID := range requiredRequestIDs {
				if !seenRequestIDs[requestID] {
					allPresent = false
					break
				}
			}
			if allPresent || time.Now().After(deadline) {
				break
			}
			time.Sleep(1 * time.Second)
		}

		s.Require().NotEmpty(content, "decision log file remained empty before timeout")
		s.Assert().NotRegexp(fullJWTPattern, content, "decision logs must not contain reusable full JWTs")

		s.Require().Greater(authorizeEvents, 0, "expected at least one authorize decision log event")
		for _, requestID := range requiredRequestIDs {
			s.Assert().True(seenRequestIDs[requestID], "expected authorize decision logs to include x-request-id %q", requestID)
		}

		// Assert x-authz-original-path for legacy route (/access/v1/check/resource).
		if legacyLog, ok := logsByRequestID["decision_logs.legacy_path_header"]; ok {
			originalPath := decisionLogSingleHeaderValue(legacyLog, "x-authz-original-path")
			s.Assert().Equal("/access/v1/check/resource", originalPath,
				"legacy check/resource decision log must have x-authz-original-path=/access/v1/check/resource, got %q", originalPath)

			// Legacy route OPA result must be canonical shape (not boolean/array/filter).
			s.Assert().True(decisionLogResultIsCanonical(legacyLog),
				"legacy check/resource decision log must have canonical OPA result shape (rlsIgnored + results), not legacy shape")
		}
	})
}

// TestZZDecisionLogsCatalogCoverage runs at the end of the suite (lexicographically)
// and verifies that all catalog steps that should reach OPA decisioning are persisted
// in decision logs with x-request-id equal to the step name.
func (s *RuntimeSuite) TestZZDecisionLogsCatalogCoverage() {
	s.Step("decision_logs.catalog_coverage", func() {
		expected := expectedDecisionLogStepNames(s.cfg)
		s.Require().NotEmpty(expected, "expected decision-log step set must not be empty")

		deadline := time.Now().Add(35 * time.Second)
		var missing []string

		for {
			status, body := s.get("/internal/v1/decision-logs", nil)
			s.Require().Equal(200, status)

			content := strings.TrimSpace(string(body))
			seen := map[string]bool{}
			logsByRequestID := map[string]map[string]any{}

			if content != "" {
				for i, line := range strings.Split(content, "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}

					var obj map[string]any
					err := json.Unmarshal([]byte(line), &obj)
					s.Require().NoError(err, "line %d is not valid JSON: %q", i+1, line)

					if !decisionLogTargetsAuthorize(obj) {
						continue
					}

					requestIDs := decisionLogHeaderValues(obj, "x-request-id")
					s.Require().NotEmpty(requestIDs,
						"authorize decision log line %d must include x-request-id", i+1)

					for _, requestID := range requestIDs {
						_, knownStep := CatalogByName[requestID]
						s.Require().True(knownStep,
							"authorize decision log line %d contains unknown x-request-id %q", i+1, requestID)
						seen[requestID] = true
						logsByRequestID[requestID] = obj
					}
				}
			}

			missing = missingExpectedDecisionLogSteps(expected, seen)
			if len(missing) == 0 {
				// Legacy path header must be preserved and result must stay canonical in OPA logs.
				legacyLog, ok := logsByRequestID["decision_logs.legacy_path_header"]
				s.Require().True(ok, "missing decision log for decision_logs.legacy_path_header")
				s.Assert().Equal("/access/v1/check/resource", decisionLogSingleHeaderValue(legacyLog, "x-authz-original-path"))
				s.Assert().True(decisionLogResultIsCanonical(legacyLog),
					"legacy route decision log must keep canonical result shape in OPA logs")

				return
			}

			if time.Now().After(deadline) {
				s.Failf("decision_logs.catalog_coverage",
					"missing %d expected decision-log request IDs: %v", len(missing), missing)
				return
			}

			time.Sleep(1 * time.Second)
		}
	})
}

func decisionLogTargetsAuthorize(obj map[string]any) bool {
	path, _ := obj["path"].(string)
	return strings.Contains(path, "authorize")
}

func decisionLogHeaderValues(obj map[string]any, headerName string) []string {
	requestContext, _ := obj["request_context"].(map[string]any)
	httpContext, _ := requestContext["http"].(map[string]any)
	headers, _ := httpContext["headers"].(map[string]any)
	rawValues, ok := headers[headerName]
	if !ok {
		return nil
	}

	switch typed := rawValues.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, value := range typed {
			if str, ok := value.(string); ok && str != "" {
				values = append(values, str)
			}
		}
		return values
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

// decisionLogSingleHeaderValue returns the first value of a header from a decision log entry.
func decisionLogSingleHeaderValue(obj map[string]any, headerName string) string {
	values := decisionLogHeaderValues(obj, headerName)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// decisionLogResultIsCanonical reports whether the event's result has the
// "rlsIgnored" and "results" keys of the authorize policy's canonical
// response, which an admitted request gets.
func decisionLogResultIsCanonical(obj map[string]any) bool {
	result, ok := obj["result"].(map[string]any)
	if !ok {
		return false
	}
	_, hasRlsIgnored := result["rlsIgnored"]
	_, hasResults := result["results"]
	return hasRlsIgnored && hasResults
}

// expectedDecisionLogStepNames returns the list of catalog step names that are
// expected to appear in OPA decision logs. Steps are excluded when:
//   - Their endpoint does not reach the OPA authorize path (e.g. setup, health).
//   - They are rejected before reaching OPA (e.g. 400 validation errors).
//   - They belong to a profile that is not active in this run:
//     m2m_keycloak.* steps are skipped when M2MKeycloakProfile is false, so no
//     decision log entries are produced for them. Including them in the expected
//     set would cause a spurious failure on every non-m2m run (Defect 4).
func expectedDecisionLogStepNames(cfg RuntimeConfig) []string {
	expected := make([]string, 0)

	for _, entry := range Catalog {
		if !catalogStepShouldReachOPA(entry) {
			continue
		}
		if catalogStepRejectedBeforeOPA(entry.Name) {
			continue
		}
		// m2m_keycloak steps are profile-gated: when M2M_KEYCLOAK_PROFILE is
		// not set they call t.Skip() and produce no decision logs.
		if !cfg.M2MKeycloakProfile && strings.HasPrefix(entry.Name, "m2m_keycloak.") {
			continue
		}
		expected = append(expected, entry.Name)
	}

	sort.Strings(expected)
	return expected
}

func catalogStepShouldReachOPA(entry StepEntry) bool {
	parts := strings.Fields(entry.Endpoint)
	if len(parts) < 2 {
		return false
	}

	method := parts[0]
	path := parts[1]
	if method != "POST" {
		return false
	}

	return path == "/access/v1/check/resource" ||
		path == "/access/v1/check/resource/bulk" ||
		path == "/access/v1/check/resource/bulk/operations" ||
		path == "/preview/v1/check/resource/bulk/operations" ||
		path == "/access/v1/check/filter" ||
		path == "/access/v2/check/resource" ||
		path == "/access/v2/check/resource/bulk/operations" ||
		path == "/preview/v2/check/resource/bulk/operations" ||
		path == "/access/v2/check/filter"
}

func catalogStepRejectedBeforeOPA(stepName string) bool {
	switch stepName {
	case "check_resource.null_body.400",
		"check_resource.missing_fields.400",
		"check_resource_bulk.null_body.400",
		"check_resource_bulk.missing_type_op.400",
		"check_resource_bulk.duplicate_ids.400",
		"check_filter.missing_resource_type.400":
		return true
	default:
		return false
	}
}

// stepDecisionLogEvents downloads the decision log and returns the events of
// the current step's requests, found by the step name each request carried as
// X-Request-Id, oldest first.
func (s *RuntimeSuite) stepDecisionLogEvents() []map[string]any {
	s.T().Helper()
	requestID := s.currentRequestID()
	status, body := s.get("/internal/v1/decision-logs", nil)
	s.Require().Equal(200, status, "decision-log download must succeed; body: %s", string(body))
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		for _, id := range decisionLogHeaderValues(event, "x-request-id") {
			if id == requestID {
				events = append(events, event)
			}
		}
	}
	return events
}

// decisionLogMark returns how many events the decision log holds for the
// current step before its request, so that loggedDecision returns the event
// of that request even when the suite runs again against the same install.
func (s *RuntimeSuite) decisionLogMark() int {
	s.T().Helper()
	return len(s.stepDecisionLogEvents())
}

// loggedDecision waits up to 40 seconds for the first decision-log event of
// the current step after mark, and returns the decision it recorded. No
// check-route answer carries the reason a resource was denied or the
// predicates it was given, so a test reads them here.
func (s *RuntimeSuite) loggedDecision(mark int) map[string]interface{} {
	s.T().Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		if events := s.stepDecisionLogEvents(); len(events) > mark {
			decision, _ := events[mark]["result"].(map[string]interface{})
			s.Require().NotNil(decision, "the decision-log event of %s carries no decision", s.currentRequestID())
			return decision
		}
		s.Require().True(time.Now().Before(deadline), "no new decision-log event for %s within 40s", s.currentRequestID())
		time.Sleep(500 * time.Millisecond)
	}
}

// firstLoggedResult returns the result of the first resource of a logged
// decision, or an empty map when the decision has none.
func firstLoggedResult(decision map[string]interface{}) map[string]interface{} {
	results, _ := decision["results"].([]interface{})
	if len(results) == 0 {
		return map[string]interface{}{}
	}
	first, _ := results[0].(map[string]interface{})
	return first
}

func missingExpectedDecisionLogSteps(expected []string, seen map[string]bool) []string {
	missing := make([]string, 0)
	for _, step := range expected {
		if !seen[step] {
			missing = append(missing, step)
		}
	}
	return missing
}
