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
	"cmp"
	"context"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// readerTarget is the policy target every regular case grants to parity-reader.
const readerTarget = "subject.roles CONTAINS 'ROLE_PARITY_READER'"

// regularCase uploads regular policy sets, and optionally the PIPs they reference
// and simplified policies for the same resource type, then sends requests against
// them.
type regularCase struct {
	id           string
	resourceType string
	// pips and simplified policies go into isolatedCaseDomain before the sets are
	// uploaded. PIPs belong to a domain and policy sets do not, so a set that
	// reads one declares it here.
	pips       []any
	simplified []any
	// uploads run in order; each replaces the sets of its own externalID.
	uploads  []regularUpload
	requests []isolatedRequest
	// steps run in order after requests, and only when every upload was
	// accepted.
	steps []regularStep
	// cleanup is sent in reverse order before the uploads and when the case
	// ends, whatever its outcome; see customizationCleanup.
	cleanup []papCall
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

// regularStep is one step of a case, as stepSpec describes it: call, the
// observations recorded after it in order, and whether a refused call ends the
// case. A customize step is a regularStep that observes its status and then
// sends its requests, and goes on after a refusal.
type regularStep struct {
	name string
	// call is nil for a read step, which sends no call of its own.
	call *papCall
	// golden is the endpoint the status observation is recorded under.
	golden        ParityEndpointID
	observe       []stepObservation
	stopOnRefusal bool
	// tenant, when not empty, replaces the case's tenant for every call of the
	// step; see stepSpec.Tenant.
	tenant string
}

// stepObservation is one observation of a step: status, error-class, read
// (the GET read), read-raw (the same GET, recorded whole), decide (the
// request), or pip-call (the calls route received since the step started).
// markers narrow the body of a read.
type stepObservation struct {
	kind    string
	read    papCall
	request isolatedRequest
	route   string
	markers []string
}

// customizeObservations are the observations of a customize step: its status,
// then each of its requests.
func customizeObservations(requests []isolatedRequest) []stepObservation {
	out := []stepObservation{{kind: "status"}}
	for _, r := range requests {
		out = append(out, stepObservation{kind: "decide", request: r})
	}
	return out
}

type regularUpload struct {
	externalID string
	sets       []any
}

func regularResourceType(caseID string) string {
	return "PARITY_SUITE_REG_" + strings.ToUpper(strings.ReplaceAll(caseID, "-", "_"))
}

// runRegularCases uploads the sets of each case and records the upload status and,
// once every upload was accepted, the status and the answer of every request. The
// upload status is a golden of its own, so a set the PAP refuses is a recorded
// result rather than a failed case, and the requests of a refused case are skipped
// because they would record a DENY the rules never produced.
//
// A case with PIPs or simplified policies first uploads them into the isolated
// domain and records that status as regular/<case>/declare-the-domain: the first
// of the three PUTs of [UploadIsolatedPolicies] that was not accepted, or else the
// last. When the PAP refused it, the case ends after that golden, before its
// customization cleanup, its sets, and its requests, since the sets would name PIPs
// that were never declared.
//
// When the test ends, the sets of every externalID the cases uploaded under are
// deleted and
// then the isolated domain is, in that order, so that no set outlives the PIP
// declarations it names. A set that does poisons the stand for every group that
// runs after it: access-control refuses every check request with 400, not only
// the ones the set's target matches.
func (s *ParitySuite) runRegularCases(cases []regularCase) {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	s.deletePolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, tc := range cases {
		s.Run(tc.id, func() {
			s.pinRoutes(tc.pins)
			s.pinUserManagement(tc.userManagement)
			s.resetCallsFor(append(slices.Clone(tc.readsRoutes), tc.pipCalls))
			if len(tc.pips) > 0 || len(tc.simplified) > 0 {
				status, body, err := UploadIsolatedPoliciesWithQuery(ctx, s.cfg, s.tokens, isolatedCaseDomain, tc.pips, tc.simplified, "")
				s.Require().NoError(err)
				s.Run("declare-the-domain", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "regular/"+tc.id+"/declare-the-domain", &model.PolicyLoadOutcome{Status: status, Message: s.refusal(status, body)})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			s.sendCustomizationCleanup(slices.Backward(tc.cleanup))
			if len(tc.cleanup) > 0 {
				s.T().Cleanup(func() { s.sendCustomizationCleanup(slices.Backward(tc.cleanup)) })
			}
			accepted := true
			for i, upload := range tc.uploads {
				status, body, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
				s.Require().NoError(err)
				s.Run(fmt.Sprintf("upload-%d", i+1), func() {
					s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, fmt.Sprintf("regular/%s/upload-%d", tc.id, i+1), &model.PolicyLoadOutcome{Status: status, Message: s.refusal(status, body)})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					accepted = false
				}
			}
			if !accepted {
				return
			}
			runRequests := func(requests []isolatedRequest) {
				for _, req := range requests {
					s.Run(req.name, func() {
						s.runRequest("regular/"+tc.id+"/"+req.name, tc.resourceType, req)
					})
				}
			}
			runRequests(tc.requests)
			var uploaded []any
			for _, upload := range tc.uploads {
				uploaded = append(uploaded, upload.sets)
			}
			if !s.runSteps("regular/"+tc.id, tc.resourceType, tc.steps, uploaded) {
				return
			}
			s.recordCasePIPCalls("regular/"+tc.id, tc.pipCalls)
			s.requireRoutesRead(tc.readsRoutes)
		})
	}
}

// runSteps runs steps in order and records what each observes under
// <kind>/<group>/<step>, where group is regular/<case> or sequence/<case>, and
// the requests of decide observations under the request's name. It reports
// false when a step with stopOnRefusal was refused: the step's status and
// error-class, which come first, are recorded, and nothing after them runs.
// A read and a raw read record their body with the ids the PAP generated for
// the elements the steps write without one masked (generatedIDs); uploaded
// holds the bodies the case sent before its steps, whose ids it wrote too.
// The answer to a write records the policy of a rule that a body of the case
// writes into more than one policy as duplicatingPolicy (duplicatedRules).
func (s *ParitySuite) runSteps(group, resourceType string, steps []regularStep, uploaded []any) bool {
	bodies := slices.Clone(uploaded)
	for _, step := range steps {
		if step.call != nil && step.call.body != nil {
			bodies = append(bodies, step.call.body)
		}
	}
	ids := caseGeneratedIDs(bodies)
	rules := caseDuplicatedRules(bodies)
	for _, step := range steps {
		if !s.runStep(group, resourceType, step, ids, rules) {
			return false
		}
	}
	return true
}

// runStep runs one step for runSteps, in the step's tenant when it names one,
// and reports false when the step was refused and stops its case. The tenant
// of the suite is the case's again when runStep returns, refused or not.
func (s *ParitySuite) runStep(group, resourceType string, step regularStep, ids generatedIDs, rules duplicatedRules) bool {
	ctx := context.Background()
	m2m := s.mustM2MToken()
	if step.tenant != "" {
		caseTenant := s.cfg.TenantID
		s.cfg.TenantID = step.tenant
		defer func() { s.cfg.TenantID = caseTenant }()
	}
	routes := []string{}
	for _, o := range step.observe {
		if o.kind == "pip-call" {
			routes = append(routes, o.route)
		}
	}
	s.resetCallsFor(routes)
	status, body := 0, []byte(nil)
	if step.call != nil {
		var err error
		status, body, err = HelperPAPCall(ctx, s.cfg, m2m, *step.call)
		s.Require().NoError(err)
		body = rules.mask(body)
	}
	refused := step.call != nil && (status < http.StatusOK || status >= http.StatusMultipleChoices)
	subCase := group + "/" + step.name
	for _, o := range step.observe {
		if refused && step.stopOnRefusal && o.kind != "status" && o.kind != "error-class" {
			break
		}
		switch o.kind {
		case "status":
			s.Run(step.name, func() {
				s.requirePendingGolden(step.golden, subCase, &model.PolicyLoadOutcome{Status: status, Message: s.refusal(status, body)})
			})
		case "error-class":
			s.Run(step.name+"-error-class", func() {
				s.requirePendingGolden(PSUITE_PAP_ERROR, subCase, errorOutcome(status, body))
			})
		case "read":
			readStatus, readBody, err := HelperPAPCall(ctx, s.cfg, m2m, o.read)
			s.Require().NoError(err)
			s.Run(step.name+"-read", func() {
				s.requirePendingGolden(PSUITE_PAP_READ, subCase, narrowStepRead(readStatus, ids.mask(readBody), o.markers))
			})
		case "read-raw":
			readStatus, readBody, err := HelperPAPCall(ctx, s.cfg, m2m, o.read)
			s.Require().NoError(err)
			s.Run(step.name+"-read-raw", func() {
				s.requirePendingGolden(PSUITE_PAP_READ_RAW, subCase, rawStepRead(readStatus, ids.mask(readBody), s.cfg.TenantID))
			})
		case "decide":
			s.Run(o.request.name, func() {
				s.runRequest(group+"/"+o.request.name, resourceType, o.request)
			})
		case "pip-call":
			outcome := s.pipCallOutcome(o.route)
			s.Run(step.name+"-pip-calls", func() {
				s.requirePendingGolden(PSUITE_PIP_CALL, subCase, outcome)
			})
		}
	}
	return !refused || !step.stopOnRefusal
}

// sequenceCase is a case with steps and no sets: it runs its steps alone, in
// tenant when that is not empty.
type sequenceCase struct {
	id           string
	resourceType string
	tenant       string
	pins         map[string]PipStubResponse
	// userManagement are the user-management-mock answers pinned when the
	// case starts; see caseSpec.UserManagement.
	userManagement map[string]PipStubResponse
	steps          []regularStep
}

// runSequenceCases runs each case's steps in the case's tenant, which every
// call of the case sends as tenant_id, a step's own tenant and the requests'
// own tenantId aside. A
// sequence case leaves behind what its steps leave behind: the suite empties
// nothing for it, so a case that writes ends with steps that undo the write.
// The one exception is what the cases leave in tenants other than the
// stand's: when the last case of the function ends, the suite clears the set
// and PIP customizations and the policy sets of every tenant a case or a step
// ran in, and empties each domain a step wrote simplified policies or PIPs to
// there. The PAP reads
// some of them for every tenant: a customization left over a set that no
// longer exists makes those reads answer 500, and a set or a PIP customization
// shows in the reads of the later functions' tenants. The goldens of the later
// cases of the same function were recorded with what the earlier ones left, so
// the suite clears nothing between cases; it clears so that a later function
// finds the stand as a fresh one.
func (s *ParitySuite) runSequenceCases(cases []sequenceCase) {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("a sequence of PAP operations asks access-control's PAP; authz-policy-admin answers no such sequence")
	}
	cleanup := sequenceCleanup(cases, s.cfg.TenantID)
	s.T().Cleanup(func() { s.sendCustomizationCleanup(slices.All(cleanup)) })
	for _, tc := range cases {
		s.Run(tc.id, func() {
			if tc.tenant != "" {
				stand := s.cfg.TenantID
				s.cfg.TenantID = tc.tenant
				// registered first, so it runs after every cleanup the steps register
				s.T().Cleanup(func() { s.cfg.TenantID = stand })
			}
			s.pinRoutes(tc.pins)
			s.pinUserManagement(tc.userManagement)
			s.runSteps("sequence/"+tc.id, tc.resourceType, tc.steps, nil)
		})
	}
}

// pinRoutes pins each route of pins to its answer, in the order of the route
// names.
func (s *ParitySuite) pinRoutes(pins map[string]PipStubResponse) {
	for _, route := range slices.Sorted(maps.Keys(pins)) {
		s.Require().NoErrorf(s.pipMock.PinRoute(context.Background(), route, pins[route]), "pin %s", route)
	}
}

// pinUserManagement pins each route of pins on user-management-mock, in the
// order of the route names, as pinRoutes does on pip-mock.
func (s *ParitySuite) pinUserManagement(pins map[string]PipStubResponse) {
	for _, route := range slices.Sorted(maps.Keys(pins)) {
		s.Require().NoErrorf(s.umMock.PinRoute(context.Background(), route, pins[route]), "pin %s on user-management-mock", route)
	}
}

// resetCallsFor clears the pip-mock call log when routes names a route, so
// that requireRoutesRead and recordCasePIPCalls count the calls of one case
// alone. An empty route names none.
func (s *ParitySuite) resetCallsFor(routes []string) {
	if slices.ContainsFunc(routes, func(route string) bool { return route != "" }) {
		s.Require().NoError(s.pipMock.ResetCalls(context.Background()), "clear the pip-mock call log")
	}
}

// recordCasePIPCalls compares what route received since resetCallsFor cleared
// the log with the pip-call golden subCase. An empty route records nothing.
func (s *ParitySuite) recordCasePIPCalls(subCase, route string) {
	if route == "" {
		return
	}
	outcome := s.pipCallOutcome(route)
	s.Run("the-pip-calls", func() {
		s.requirePendingGolden(PSUITE_PIP_CALL, subCase, outcome)
	})
}

// requireRoutesRead fails the test when a route of routes received no call
// since resetCallsFor cleared the log. It records no golden. The runners call it
// after a case's requests, so a case whose upload was refused skips it.
func (s *ParitySuite) requireRoutesRead(routes []string) {
	if len(routes) == 0 {
		return
	}
	s.Run("the-pips-were-read", func() {
		calls, err := s.pipMock.GetCalls(context.Background())
		s.Require().NoError(err, "read the pip-mock call log")
		read := map[string]int{}
		for _, call := range calls {
			read[call.Path]++
		}
		for _, route := range routes {
			s.Assert().Positive(read[route], "pip-mock calls to %s", route)
		}
	})
}

// sequenceCleanup returns the calls runSequenceCases sends when the last of
// cases ends: for each tenant other than stand that a case or a step ran in,
// in the order they first ran, the clear of its set and PIP customizations,
// the upper level first, the clear of its policy sets, whether a step
// uploaded them under an externalId or imported them, and an empty upload of
// the simplified policies and then of the PIPs of each domain a step of that
// tenant wrote either to.
func sequenceCleanup(cases []sequenceCase, stand string) []papCall {
	const (
		domainPoliciesPath = "/access/v1/simplifiedPolicies/domainPolicies/"
		domainPIPsPath     = "/access/v1/simplifiedPolicies/domainPIPs/"
	)
	var tenants []string
	domains := map[string][]string{}
	add := func(tenant string) {
		if tenant != "" && tenant != stand && !slices.Contains(tenants, tenant) {
			tenants = append(tenants, tenant)
		}
	}
	for _, tc := range cases {
		add(tc.tenant)
		for _, st := range tc.steps {
			tenant := cmp.Or(st.tenant, tc.tenant)
			add(st.tenant)
			if st.call == nil || st.call.method != http.MethodPut || tenant == "" || tenant == stand {
				continue
			}
			if path := st.call.path; strings.HasPrefix(path, domainPoliciesPath) || strings.HasPrefix(path, domainPIPsPath) {
				domain := strings.TrimPrefix(strings.TrimPrefix(path, domainPoliciesPath), domainPIPsPath)
				if !slices.Contains(domains[tenant], domain) {
					domains[tenant] = append(domains[tenant], domain)
				}
			}
		}
	}
	var calls []papCall
	for _, tenant := range tenants {
		for _, path := range []string{"/access/v1/config/customization/clear", "/access/v1/pip/customization/clear"} {
			for _, level := range []string{"CUSTOMER", "PROJECT"} {
				calls = append(calls, papCall{method: http.MethodPost, path: path,
					query: url.Values{"tenant_id": {tenant}, "level": {level}}})
			}
		}
		calls = append(calls, papCall{method: http.MethodPost, path: "/access/v1/config/clear", query: url.Values{"tenant_id": {tenant}}})
		for _, prefix := range []string{domainPoliciesPath, domainPIPsPath} {
			for _, domain := range domains[tenant] {
				calls = append(calls, papCall{method: http.MethodPut, path: prefix + domain,
					query: url.Values{"tenant_id": {tenant}}, body: []any{}})
			}
		}
	}
	return calls
}

// sendCustomizationCleanup sends each of calls and never fails the test. It
// logs a call that could not be sent or that the PAP answered with 5xx. A 4xx
// answer is not logged: before the upload the customization usually does not
// exist, and a refused delete of it is expected.
func (s *ParitySuite) sendCustomizationCleanup(calls iter.Seq2[int, papCall]) {
	ctx := context.Background()
	m2m := s.mustM2MToken()
	for _, call := range calls {
		status, _, err := HelperPAPCall(ctx, s.cfg, m2m, call)
		if err != nil {
			s.T().Logf("%s %s: %v", call.method, call.path, err)
		} else if status >= http.StatusInternalServerError {
			s.T().Logf("%s %s: status %d", call.method, call.path, status)
		}
	}
}

// regularExternalIDs lists the externalIDs the cases upload under, each once, in
// the order of their first upload.
func regularExternalIDs(cases []regularCase) []string {
	var ids []string
	seen := map[string]struct{}{}
	for _, tc := range cases {
		for _, upload := range tc.uploads {
			if _, dup := seen[upload.externalID]; dup {
				continue
			}
			seen[upload.externalID] = struct{}{}
			ids = append(ids, upload.externalID)
		}
	}
	return ids
}
