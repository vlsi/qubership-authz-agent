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
	"net/http"
	"slices"
	"time"

	"authz-agent/test/parity/suite/model"
)

// isolatedCaseDomain receives one case's PIPs and policy at a time. On the legacy
// profile a declaration the PAP refuses never reaches the seeded domain and cannot
// fail its upload. On the authz-agent profile authz-policy-admin serves the union
// of all domains, so a policy the agent cannot parse fails the agent's load until
// the next case replaces it; the requests of that case then see stale policies.
const isolatedCaseDomain = "PARITY_ISOLATED"

// isolatedCase is one policy uploaded alone, with the PIPs it references, and the
// requests sent against it once the upload is accepted. A PIP it references has to
// be declared in pips, since PIPs belong to a domain; X19 and X20 reference an
// undeclared one on purpose.
type isolatedCase struct {
	id           string
	resourceType string
	operation    string
	roles        []string
	condition    string
	rsql         string
	pips         []any
	requests     []isolatedRequest
	// domain is the domain the case uploads into, isolatedCaseDomain when
	// empty.
	domain string
	// policyOmit, policy, and policiesQuery change the upload of the policy;
	// see caseSpec. The resource type placeholders in policy are replaced when
	// it is merged.
	policyOmit    []string
	policy        map[string]any
	policiesQuery string
	// readsRoutes are the pip-mock routes that have to receive a call while
	// the case runs; see caseSpec.ReadsRoutes.
	readsRoutes []string
	// pipCalls is the pip-mock route whose calls over the whole case are
	// recorded as a pip-call golden; see caseSpec.PIPCalls.
	pipCalls string
	// pins are the pip-mock answers pinned when the case starts; see
	// caseSpec.Pins.
	pins map[string]PipStubResponse
	// userManagement are the user-management-mock answers pinned when the
	// case starts; see caseSpec.UserManagement.
	userManagement map[string]PipStubResponse
}

// isolatedRequest is a check/resource request against the case's policy, or a
// check/filter request when filter is set, or a bulk or bulk operations check
// when bulk or bulkOperations is set.
type isolatedRequest struct {
	name      string
	operation string
	typ       string
	resource  any
	headers   map[string]string
	filter    bool
	// omitOperation sends a filter request with no operation parameter at all,
	// where an empty operation would fall back to LIST.
	omitOperation bool
	// m2mOnly sends the service's M2M token alone, with no end-user token, so
	// the subject is the service account rather than parity-reader.
	m2mOnly bool
	// classifyBy is the pip-mock route whose call log files the golden of a
	// regular case's request under its order class; see requestSpec.ClassifyBy.
	classifyBy string
	// tenantID replaces the stand's tenant in the tenant_id query parameter
	// when non-nil; see requestSpec.TenantID.
	tenantID *string
	// pipCalls is the pip-mock route whose calls during the request are
	// recorded as a pip-call golden; see requestSpec.PIPCalls.
	pipCalls string
	// user names the parity realm user whose token the request carries in
	// place of parity-reader's, when not empty; see requestSpec.Subject.
	user string
	// userClaims holds the claim values user's token must carry; see
	// requestSpec.SubjectClaims.
	userClaims map[string]string
	// userID is the userId query parameter when non-nil; see
	// requestSpec.UserID.
	userID *string
	// emptyOperation sends the operation with an empty value; see
	// requestSpec.EmptyOperation.
	emptyOperation bool
	// pause is how long runRequest waits before sending the request.
	pause time.Duration
	// pins are the pip-mock answers pinned before the request; see
	// requestSpec.Pins.
	pins map[string]PipStubResponse
	// userManagement are the user-management-mock answers pinned before the
	// request; see requestSpec.UserManagement.
	userManagement map[string]PipStubResponse
	// userManagementCalls records what user-management-mock received while the
	// request ran; see requestSpec.UserManagementCalls.
	userManagementCalls bool
	// readsRoutes are the pip-mock routes that have to receive a call while
	// the request runs; see requestSpec.ReadsRoutes.
	readsRoutes []string
	// pipHeaders names the headers the pip-call golden of pipCalls records;
	// see forwardedHeaders.
	pipHeaders []string
	// bulk and bulkOperations, when non-nil, are the items of a
	// check/resource/bulk or a check/resource/bulk/operations request, in
	// place of the check or filter request.
	bulk           []any
	bulkOperations []any
	// v2 sends the check, the filter, or the bulk operations request through
	// its v2 endpoint with the obligations parameter obligations, none when
	// it is nil; see requestSpec.V2.
	v2          bool
	obligations *string
}

// callOptions returns the per-call options req is sent with: its headers, its
// tenant, and its userId.
func (r isolatedRequest) callOptions() PerCallOptions {
	return PerCallOptions{CustomHeaders: r.headers, TenantID: r.tenantID, UserID: r.userID}
}

// requestTokens returns the tokens req is sent with: parity-reader's bundle,
// the M2M token alone for an m2mOnly request, or the bundle of req.user. The
// token of req.user must carry req.userClaims, or the test fails before the
// request is sent.
func (s *ParitySuite) requestTokens(req isolatedRequest) TokenBundle {
	if req.m2mOnly {
		return TokenBundle{M2M: s.mustM2MToken()}
	}
	if req.user == "" {
		return s.mustTokenBundle(UserProfileReader)
	}
	token, err := s.tokens.EndUserTokenFor(req.user)
	s.Require().NoError(err, "token of the parity realm user %q", req.user)
	claims := s.decodeJWTClaims(token, req.user)
	for name, want := range req.userClaims {
		s.Require().Equal(want, claims[name], "claim %s in the token of %q", name, req.user)
	}
	return TokenBundle{M2M: s.mustM2MToken(), EndUser: token}
}

// runIsolatedCases uploads each case alone into isolatedCaseDomain, or into the
// domain the case names, and records the upload status and, when the PAP
// accepts the case, the status and the answer of every request. The upload
// status is a golden of its own, so a form the PAP refuses is a recorded result
// rather than a failed case. On the authz-agent profile the upload status is
// not compared (authz-policy-admin accepts anything) and the requests are.
//
// When it ends, it empties every domain its cases uploaded into.
func (s *ParitySuite) runIsolatedCases(cases []isolatedCase) {
	reader := []string{"ROLE_PARITY_READER"}

	ctx := context.Background()
	domains := []string{isolatedCaseDomain}
	for _, tc := range cases {
		if tc.domain != "" && !slices.Contains(domains, tc.domain) {
			domains = append(domains, tc.domain)
		}
	}
	s.T().Cleanup(func() {
		for _, domain := range domains {
			if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, domain, nil, nil); err != nil {
				s.T().Logf("empty domain %s: %v", domain, err)
			}
		}
	})
	for _, tc := range cases {
		s.Run(tc.id, func() {
			s.pinRoutes(tc.pins)
			s.pinUserManagement(tc.userManagement)
			s.resetCallsFor(append(slices.Clone(tc.readsRoutes), tc.pipCalls))
			policy := map[string]any{
				"component":             "PARITY",
				"reason":                tc.id,
				"resourceType":          tc.resourceType,
				"operation":             valueOr(tc.operation, "READ"),
				"roles":                 reader,
				"applicableForFrontend": false,
				"id":                    "00000000-0000-0000-0000-0000000f0001",
			}
			if tc.roles != nil {
				policy["roles"] = tc.roles
			}
			if tc.domain != "" {
				// a policy id another domain already holds would be refused for that id
				policy["id"] = regularBuilder{caseID: tc.id}.id("simplified/" + tc.domain)
			}
			if tc.condition != "" {
				policy["condition"] = tc.condition
			}
			if tc.rsql != "" {
				policy["rsqlPredicate"] = tc.rsql
			}
			for _, name := range tc.policyOmit {
				delete(policy, name)
			}
			mergeFields(policy, tc.policy, tc.resourceType)
			status, body, err := UploadIsolatedPoliciesWithQuery(ctx, s.cfg, s.tokens, valueOr(tc.domain, isolatedCaseDomain), tc.pips, []any{policy}, tc.policiesQuery)
			s.Require().NoError(err)

			if !isAuthzAgentProfile(s.cfg.Profile) {
				s.Run("upload", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+tc.id, &model.PolicyLoadOutcome{Status: status, Message: s.refusal(status, body)})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			for _, req := range tc.requests {
				s.Run(req.name, func() {
					s.runRequest("isolated/"+tc.id+"/"+req.name, tc.resourceType, req)
				})
			}
			s.recordCasePIPCalls("isolated/"+tc.id, tc.pipCalls)
			s.requireRoutesRead(tc.readsRoutes)
		})
	}
}

// filterOperation is the operation parameter of a filter request: LIST unless the
// request names one, and none at all when omitOperation is set.
func (r isolatedRequest) filterOperation() string {
	if r.omitOperation {
		return ""
	}
	return valueOr(r.operation, "LIST")
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
