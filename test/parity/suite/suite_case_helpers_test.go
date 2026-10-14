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

package paritysuite

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"time"

	"authz-agent/test/parity/suite/model"
)

func stringPtr(v string) *string { return &v }

func (s *ParitySuite) mustM2MToken() string {
	s.T().Helper()
	token, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	return token
}

func (s *ParitySuite) mustEndUserToken(profile UserProfile) string {
	s.T().Helper()
	token, err := s.tokens.EndUserToken(profile)
	s.Require().NoError(err)
	return token
}

func (s *ParitySuite) mustTokenBundle(profile UserProfile) TokenBundle {
	s.T().Helper()
	return TokenBundle{
		M2M:     s.mustM2MToken(),
		EndUser: s.mustEndUserToken(profile),
	}
}

func (s *ParitySuite) mustAnonymousTokenBundle() TokenBundle {
	s.T().Helper()
	return TokenBundle{
		M2M:       s.mustM2MToken(),
		Anonymous: true,
	}
}

// deletePolicySetsOnCleanup registers a cleanup that deletes the regular sets
// uploaded under each of externalIDs in the tenant of cfg, with
// [HelperDeletePolicySetsByExternalID]; an upload of an empty list would leave
// them on the stand. A regular set that names a PIP declaration no longer in
// the isolated domain makes the PAP refuse every check request on the stand
// with 400, so a test that uploads sets and empties the domain when it ends has
// to delete the sets first; cleanups run last registered first, so this one is
// registered after the domain's.
func (s *ParitySuite) deletePolicySetsOnCleanup(cfg Config, externalIDs ...string) {
	s.T().Helper()
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		for _, externalID := range externalIDs {
			status, _, err := HelperDeletePolicySetsByExternalID(ctx, cfg, m2m, externalID)
			if err != nil {
				s.T().Logf("delete the policy sets of %s: %v", externalID, err)
				continue
			}
			if status < http.StatusOK || status >= http.StatusMultipleChoices {
				s.T().Logf("delete the policy sets of %s: status %d", externalID, status)
			}
		}
	})
}

func (s *ParitySuite) requireGolden(id ParityEndpointID, subCase string, actual any) {
	s.T().Helper()
	if err := s.comparator.Compare(id, subCase, actual); err != nil {
		s.T().Errorf("%v", err)
	}
}

// requirePendingGolden is requireGolden for a case written before access-control
// answered it. With no golden recorded the case skips and prints the answer of the
// service under test, which is access-control when the golden is being captured;
// once the golden is committed it compares like any other case.
func (s *ParitySuite) requirePendingGolden(id ParityEndpointID, subCase string, actual any) {
	s.T().Helper()
	err := s.comparator.Compare(id, subCase, actual)
	if errors.Is(err, ErrGoldenNotRecorded) {
		answer, _ := json.Marshal(actual)
		s.T().Skipf("golden %s/%s is not recorded yet; the %s profile answered %s", Meta(id).GoldenDir, subCase, s.cfg.Profile, answer)
	}
	if err != nil {
		s.T().Errorf("%v", err)
	}
}

func (s *ParitySuite) runPendingCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decision)
}

// runRepeatedPendingCheckResourceV1Case sends the same request calls times. The
// answers have to agree with each other before the first one is compared with the
// golden, so an order-dependent answer shows up even while recording.
func (s *ParitySuite) runRepeatedPendingCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, calls int) {
	s.T().Helper()

	decisions := make([]bool, 0, calls)
	distinct := map[bool]struct{}{}
	for range calls {
		status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, PerCallOptions{})
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status)
		decisions = append(decisions, decision)
		distinct[decision] = struct{}{}
	}
	s.Require().Len(distinct, 1, "decisions over %d identical calls: %v", calls, decisions)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decisions[0])
}

// runPendingCheckResourceV1OutcomeCase records the HTTP status together with the
// decision, so a request access-control refuses is recorded rather than failed.
func (s *ParitySuite) runPendingCheckResourceV1OutcomeCase(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, subCase, &model.CheckResourceOutcome{Status: status, Decision: decision})
}

// runPendingFilterV1OutcomeCase is runPendingCheckResourceV1OutcomeCase for
// check/filter.
func (s *ParitySuite) runPendingFilterV1OutcomeCase(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.requirePendingGolden(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, subCase, &model.FilterOutcome{Status: status, Result: decoded})
}

func (s *ParitySuite) runPendingCheckResourceBulkV1Case(subCase string, body []model.CheckAccessRequestWithID, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, subCase, &decoded)
}

func (s *ParitySuite) runPendingFilterV1Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_6_CHECK_FILTER_V1, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decision)
}

func (s *ParitySuite) runCheckResourceV2Case(subCase string, body model.CheckResourceRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourceV2(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_7_CHECK_RESOURCE_V2, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkV1Case(subCase string, body []model.CheckAccessRequestWithID, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkOpsV1Case(subCase string, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesByOperationsV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, subCase, &decoded)
}

func (s *ParitySuite) runPreviewBulkOpsV1Case(subCase string, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperPreviewCheckResourcesByOperationsV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, subCase, &decoded)
}

func (s *ParitySuite) runFilterV1Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_6_CHECK_FILTER_V1, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkOpsV2Case(subCase string, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV2(context.Background(), s.cfg, body, tokens, opts, v2Flags{})
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, subCase, &decoded)
}

func (s *ParitySuite) runPreviewBulkOpsV2Case(subCase string, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperPreviewCheckResourcesV2(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, subCase, &decoded)
}

func (s *ParitySuite) runFilterV2Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV2(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_10_CHECK_FILTER_V2, subCase, &decoded)
}

func (s *ParitySuite) pinEntitlementsV3(userID string, refs map[string]map[string][]string) {
	s.T().Helper()

	ctx := context.Background()
	s.Require().NoError(s.pinEntitlementsAPIVersionV3(ctx))

	payload := buildDirectEntitlementsResponse(refs)
	err := s.eaMock.PinEntitlementsV3ForUser(ctx, userID, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       payload,
	})
	s.Require().NoError(err)
}

// pinEntitlementsAPIVersionV3 pins /api-version of entitlements-mock to major 3
// under /api. Without it access-control does not read the user-entitlements
// route that PinEntitlementsV3ForUser pins, and a decision that reads
// entitlements fails.
func (s *ParitySuite) pinEntitlementsAPIVersionV3(ctx context.Context) error {
	return s.eaMock.PinRoute(ctx, "/api-version", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: model.ApiVersionResponse{
			Specs: []model.ApiVersionSpec{{
				SpecRootUrl:     "/api",
				Major:           3,
				Minor:           0,
				SupportedMajors: []int{1, 2, 3},
			}},
		},
	})
}

func buildDirectEntitlementsResponse(refs map[string]map[string][]string) model.GetDirectUserEntitlementsResponse {
	resourceTypes := make([]string, 0, len(refs))
	for resourceType := range refs {
		resourceTypes = append(resourceTypes, resourceType)
	}
	sort.Strings(resourceTypes)

	entitlements := make([]model.Entitlement, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		names := make([]string, 0, len(refs[resourceType]))
		for name := range refs[resourceType] {
			names = append(names, name)
		}
		sort.Strings(names)

		references := make([]model.EntitlementReference, 0, len(names))
		for _, name := range names {
			ids := append([]string(nil), refs[resourceType][name]...)
			sort.Strings(ids)

			targets := make([]model.EntitlementTarget, 0, len(ids))
			for _, id := range ids {
				targets = append(targets, model.EntitlementTarget{ResourceID: id})
			}
			references = append(references, model.EntitlementReference{
				Name:      name,
				Resources: targets,
			})
		}
		entitlements = append(entitlements, model.Entitlement{
			ResourceType: resourceType,
			References:   references,
		})
	}

	return model.GetDirectUserEntitlementsResponse{
		Entitlements:          entitlements,
		Definitions:           []model.Definition{},
		DefinitionUpdatedWhen: "",
	}
}

// refusal is the Message of an outcome whose answer had status and body; see
// refusalMessage. It is nil unless the case file being run records error
// bodies.
func (s *ParitySuite) refusal(status int, body []byte) any {
	return refusalMessage(s.errorBodies, status, body)
}

// sendRegularRequest sends req against its own type, or resourceType when it
// names none, with the tokens requestTokens gives it, and returns the outcome
// with the endpoint its golden is filed under.
func (s *ParitySuite) sendRegularRequest(resourceType string, req isolatedRequest) (ParityEndpointID, any) {
	s.T().Helper()
	return s.sendRequest(resourceType, req, s.requestTokens(req))
}

// sendRequest is sendRegularRequest with the tokens given. A bulk request
// sends its items, whose type bulkItems already defaults to the case's.
func (s *ParitySuite) sendRequest(resourceType string, req isolatedRequest, tokens TokenBundle) (ParityEndpointID, any) {
	s.T().Helper()
	ctx := context.Background()
	opts := req.callOptions()
	switch {
	case req.v2:
		return s.sendV2Request(resourceType, req, tokens)
	case req.bulk != nil:
		status, raw, err := HelperPostV1(ctx, s.cfg, v1PathCheckResourceBulk, req.bulk, tokens, opts)
		s.Require().NoError(err)
		outcome := &model.CheckResourceBulkOutcome{Status: status, Message: s.refusal(status, raw)}
		if status == http.StatusOK {
			allowed := []string{}
			s.Require().NoError(decodeJSON(raw, &allowed), "decode the allowed ids of %s", raw)
			sort.Strings(allowed)
			outcome.Allowed = &allowed
		}
		return PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, outcome
	case req.bulkOperations != nil:
		status, raw, err := HelperPostV1(ctx, s.cfg, v1PathCheckResourceBulkOperations, req.bulkOperations, tokens, opts)
		s.Require().NoError(err)
		outcome := &model.CheckResourceBulkOperationsOutcome{Status: status, Message: s.refusal(status, raw)}
		if status == http.StatusOK {
			decision := map[string][]string{}
			s.Require().NoError(decodeJSON(raw, &decision), "decode the allowed ids by operation of %s", raw)
			for _, ids := range decision {
				sort.Strings(ids)
			}
			outcome.Decision = &decision
		}
		return PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, outcome
	case req.filter:
		query := filterV1Query(valueOr(req.typ, resourceType), req.filterOperation(), req.emptyOperation)
		status, decoded, raw, err := HelperFilterV1Query(ctx, s.cfg, query, tokens, opts)
		s.Require().NoError(err)
		return PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, &model.FilterOutcome{Status: status, Result: decoded, Message: s.refusal(status, raw)}
	}
	status, decision, raw, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: checkOperation(req.operation, req.emptyOperation), Type: valueOr(req.typ, resourceType), Resource: req.resource},
		tokens, opts)
	s.Require().NoError(err)
	return PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, &model.CheckResourceOutcome{Status: status, Decision: decision, Message: s.refusal(status, raw)}
}

// runRequest sends req against resourceType and compares its outcome with the
// golden subCase. With req.classifyBy the golden is filed under the order
// class the call log of that route shows. With req.pipCalls what the route
// received is recorded as the pip-call golden subCase beside the request's
// own; the call log is read before either golden is compared, since a golden
// not yet recorded skips the rest of the subtest. Either one, and
// req.readsRoutes, clear the call log before req.pause starts, and req.pins
// are pinned before that. With req.userManagementCalls what user-management-
// mock received is recorded as the user-management-call golden subCase, its
// call log cleared and req.userManagement pinned at the same points.
func (s *ParitySuite) runRequest(subCase, resourceType string, req isolatedRequest) {
	s.T().Helper()
	ctx := context.Background()
	s.pinRoutes(req.pins)
	s.pinUserManagement(req.userManagement)
	if req.classifyBy != "" || req.pipCalls != "" || len(req.readsRoutes) > 0 {
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
	}
	if req.userManagementCalls {
		s.Require().NoError(s.umMock.ResetCalls(ctx), "clear the user-management-mock call log")
	}
	time.Sleep(req.pause)
	tokens := s.requestTokens(req)
	id, outcome := s.sendRequest(resourceType, req, tokens)
	s.requireRoutesRead(req.readsRoutes)
	var umCalls *model.UserManagementCallOutcome
	if req.userManagementCalls {
		calls, err := s.umMock.GetCalls(ctx)
		s.Require().NoError(err, "read the user-management-mock call log")
		tenant := s.cfg.TenantID
		if req.tenantID != nil {
			tenant = *req.tenantID
		}
		umCalls = userManagementCallOutcome(calls, sentHeaders(tokens, req.callOptions()), tenant, req.userID)
	}
	switch {
	case req.classifyBy != "" && s.comparesWithTheUnclassifiedGolden(id, subCase):
		s.T().Logf("%s: the %s profile is compared with the unclassified golden", subCase, s.cfg.Profile)
	case req.classifyBy != "":
		read := s.pipCalls(req.classifyBy)
		s.T().Logf("%s: pip-mock received %d call(s) to %s", subCase, read, req.classifyBy)
		if read > 0 {
			subCase += "-when-the-pip-was-read"
		} else {
			subCase += "-when-the-pip-was-skipped"
		}
	case req.pipCalls != "":
		calls, err := s.pipMock.GetCalls(ctx)
		s.Require().NoError(err, "read the pip-mock call log for %s", req.pipCalls)
		pipCalls := s.pipCallOutcomeOf(calls, req.pipCalls)
		if len(req.pipHeaders) > 0 {
			tenant := s.cfg.TenantID
			if req.tenantID != nil {
				tenant = *req.tenantID
			}
			pipCalls.Headers = forwardedHeaders(calls, req.pipCalls, req.pipHeaders, sentHeaders(tokens, req.callOptions()), tenant)
		}
		s.Run("pip-calls", func() {
			s.requirePendingGolden(PSUITE_PIP_CALL, subCase, pipCalls)
		})
	}
	if umCalls != nil {
		s.Run("user-management-calls", func() {
			s.requirePendingGolden(PSUITE_USER_MANAGEMENT_CALL, subCase, umCalls)
		})
	}
	s.requirePendingGolden(id, subCase, outcome)
}

// comparesWithTheUnclassifiedGolden reports whether a request classed by
// classifyBy is compared with its golden subCase itself rather than with the
// golden of its order class: on the authz-agent profile, when that golden is
// recorded. An answer that depends on the order the stand evaluates in is
// accepted from legacy access-control only; the agent has to give the one
// answer that golden holds on every run. A request with no such golden keeps
// its order classes on both profiles.
func (s *ParitySuite) comparesWithTheUnclassifiedGolden(id ParityEndpointID, subCase string) bool {
	if !isAuthzAgentProfile(s.cfg.Profile) {
		return false
	}
	_, err := os.Stat(s.comparator.GoldenPath(id, subCase))
	return err == nil
}

// pipCalls counts the calls pip-mock received on route since its call log was
// last reset.
func (s *ParitySuite) pipCalls(route string) int {
	s.T().Helper()
	calls, err := s.pipMock.GetCalls(context.Background())
	s.Require().NoError(err, "read the pip-mock call log for %s", route)
	read := 0
	for _, call := range calls {
		if call.Path == route {
			read++
		}
	}
	return read
}

// pipCallOutcome reads the pip-mock call log for route into the golden shape
// PipCallOutcome.
func (s *ParitySuite) pipCallOutcome(route string) *model.PipCallOutcome {
	s.T().Helper()
	calls, err := s.pipMock.GetCalls(context.Background())
	s.Require().NoError(err, "read the pip-mock call log for %s", route)
	return s.pipCallOutcomeOf(calls, route)
}

// pipCallOutcomeOf is pipCallOutcome over a call log already read.
func (s *ParitySuite) pipCallOutcomeOf(calls []PipStubCall, route string) *model.PipCallOutcome {
	s.T().Helper()
	outcome := &model.PipCallOutcome{}
	for _, call := range calls {
		if call.Path != route {
			continue
		}
		outcome.Calls++
		if outcome.Calls > 1 {
			continue
		}
		body, isObject := call.Body.(map[string]any)
		if attributes, ok := body["requestAttributes"]; isObject && ok {
			outcome.RequestAttributes = attributes
			continue
		}
		raw := call.BodyRaw
		if raw == "" && call.Body != nil {
			encoded, err := json.Marshal(call.Body)
			s.Require().NoError(err)
			raw = string(encoded)
		}
		outcome.Body = raw
	}
	return outcome
}
