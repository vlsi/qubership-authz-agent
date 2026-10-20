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
	"fmt"
	"maps"
	"net/http"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// runCaseFile records the stand's version when the file asks for it, pins the
// file's routes and its entitlements answer, with the API version that answer
// needs, and runs its isolated cases, then its regular cases, then its sequence
// cases, each in the file's order. The goldens of a file of round 44 or later
// carry the body of each 400 or 409 answer beside its status.
func (s *ParitySuite) runCaseFile(name string) {
	f, err := readCaseFile(name)
	s.Require().NoError(err)
	s.errorBodies = recordsErrorBodies(name)
	defer func() { s.errorBodies = false }()
	s.scopeRead = s.scopeRead || readsPermissionScope(f)
	ctx := context.Background()
	for _, property := range slices.Sorted(maps.Keys(f.StandProperties)) {
		s.T().Logf("%s expects the stand to run with %s=%s", name, property, f.StandProperties[property])
	}
	if f.StandVersion {
		function := path.Base(s.T().Name())
		s.Run("api-version", func() {
			status, version, err := HelperApiVersion(ctx, s.cfg)
			s.Require().NoError(err)
			s.Require().Equal(http.StatusOK, status)
			s.requirePendingGolden(PSUITE_ROW_1_API_VERSION, function, &version)
		})
	}
	for route, response := range f.Pins {
		s.Require().NoErrorf(s.pipMock.PinRoute(ctx, route, response), "pin %s for %s", route, name)
	}
	for route, response := range f.UserManagement {
		s.Require().NoErrorf(s.umMock.PinRoute(ctx, route, response), "pin %s on user-management-mock for %s", route, name)
	}
	if f.Entitlements != nil {
		s.Require().NoErrorf(s.pinEntitlementsAPIVersionV3(ctx), "pin the entitlements API version of %s", name)
		s.Require().NoErrorf(s.eaMock.PinEntitlementsV3ForUser(ctx, parityReaderSubjectID, *f.Entitlements), "pin the entitlements of %s", name)
	}
	isolated, regular, sequence, err := caseFileCases(f)
	s.Require().NoErrorf(err, "build the cases of %s", name)
	if len(isolated) > 0 {
		s.runIsolatedCases(isolated)
	}
	if len(regular) > 0 {
		// runRegularCases skips the rest of the function on the authz-agent profile,
		// which loads simplified policies only.
		s.runRegularCases(regular)
	}
	if len(sequence) > 0 {
		s.runSequenceCases(sequence)
	}
}

// caseFileCases builds the cases of f in the form the runners take: its cases
// without sets and steps, its cases with sets, and its cases with steps and no
// sets, each in file order.
func caseFileCases(f caseFile) ([]isolatedCase, []regularCase, []sequenceCase, error) {
	var isolated []isolatedCase
	var regular []regularCase
	var sequence []sequenceCase
	for _, c := range f.Cases {
		rt := caseResourceType(f, c)
		steps, err := caseSteps(c, rt)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(c.Sets) == 0 && c.Steps != nil {
			sequence = append(sequence, sequenceCase{
				id: c.ID, resourceType: rt, tenant: caseTenant(c, f), pins: c.Pins, userManagement: c.UserManagement, steps: steps,
			})
			continue
		}
		var pips []any
		for _, key := range c.PIPs {
			pip, ok := f.PIPs[key]
			if !ok {
				return nil, nil, nil, fmt.Errorf("case %s names the PIP %q, which the file does not declare", c.ID, key)
			}
			pips = append(pips, pip)
		}
		requests := caseRequests(c.Requests, rt)
		if len(c.Sets) == 0 {
			isolated = append(isolated, isolatedCase{
				id: c.ID, resourceType: rt, domain: c.Domain, operation: c.Operation, roles: c.Roles,
				condition: resourceTypeReplacer(rt).Replace(c.Condition), pips: pips, requests: requests,
				policyOmit: c.PolicyOmit, policy: c.Policy, policiesQuery: c.PoliciesQuery,
				readsRoutes: c.ReadsRoutes, pipCalls: c.PIPCalls, pins: c.Pins, userManagement: c.UserManagement,
			})
			continue
		}
		b := regularBuilder{caseID: c.ID}
		ruleIDs := regularBuilder{caseID: valueOr(c.RuleIDsOf, c.ID)}
		sets := make([]any, 0, len(c.Sets))
		for _, set := range c.Sets {
			sets = append(sets, buildSet(b, ruleIDs, set, rt))
		}
		regular = append(regular, regularCase{
			id: c.ID, resourceType: rt, pips: pips,
			uploads:        []regularUpload{{externalID: "parity-" + c.ID, sets: sets}},
			requests:       requests,
			steps:          steps,
			cleanup:        customizationCleanup(c.ID, c.Customize, rt),
			readsRoutes:    c.ReadsRoutes,
			pipCalls:       c.PIPCalls,
			pins:           c.Pins,
			userManagement: c.UserManagement,
		})
	}
	return isolated, regular, sequence, nil
}

// caseTenant returns the tenant of the sequence case c of f: its own, else
// the file's, else "" for the stand's.
func caseTenant(c caseSpec, f caseFile) string {
	switch {
	case c.Tenant != nil:
		return *c.Tenant
	case f.Tenant != nil:
		return *f.Tenant
	}
	return ""
}

// caseSteps builds the steps of c, whose resource type is rt: its customize
// steps, or its steps. A customize step goes on after a refusal, as the runner
// has always sent it; a step stops unless it says continue.
func caseSteps(c caseSpec, rt string) ([]regularStep, error) {
	var steps []regularStep
	for _, st := range c.Customize {
		call, golden := customizeStepCall(c.ID, c.RuleIDsOf, st, rt)
		steps = append(steps, regularStep{name: st.Name, call: &call, golden: golden,
			observe: customizeObservations(caseRequests(st.Requests, rt))})
	}
	for _, st := range c.Steps {
		call, golden, err := stepCall(st, rt)
		if err != nil {
			return nil, fmt.Errorf("case %s step %s %w", c.ID, st.Name, err)
		}
		requests := map[string]isolatedRequest{}
		for _, r := range caseRequests(st.Requests, rt) {
			requests[r.name] = r
		}
		step := regularStep{name: st.Name, call: call, golden: golden, stopOnRefusal: st.OnRefusal != "continue"}
		if st.Tenant != nil {
			step.tenant = *st.Tenant
		}
		for _, text := range stepObserve(st, papOperations()[st.Op]) {
			o := parseObservation(text)
			obs := stepObservation{kind: o.kind}
			switch o.kind {
			case "read", "read-raw":
				read, err := readCall(o.arg, st.Args, rt)
				if err != nil {
					return nil, fmt.Errorf("case %s step %s %w", c.ID, st.Name, err)
				}
				obs.read, obs.markers = read, stepMarkers(c.ID, rt, st)
			case "decide":
				obs.request = requests[o.arg]
			case "pip-call":
				obs.route = o.arg
			}
			step.observe = append(step.observe, obs)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// caseRequests turns the requests of a case whose resource type is rt into the
// form the runners send.
func caseRequests(specs []requestSpec, rt string) []isolatedRequest {
	requests := make([]isolatedRequest, 0, len(specs))
	for _, r := range specs {
		req := isolatedRequest{
			name: r.Name, operation: r.Operation, typ: r.Type, resource: withResourceType(r.Resource, rt),
			headers: r.Headers, filter: r.Filter, m2mOnly: r.Subject == "m2m" || strings.HasPrefix(r.Subject, "m2m@"), classifyBy: r.ClassifyBy,
			tenantID: r.TenantID, pipCalls: r.PIPCalls, user: r.user(), client: r.client(),
			userClaims: r.SubjectClaims,
			userID:     r.UserID, emptyOperation: r.EmptyOperation, omitOperation: r.OmitOperation,
			pins: r.Pins, readsRoutes: r.ReadsRoutes, pipHeaders: r.PIPHeaders,
			userManagement: r.UserManagement, userManagementCalls: r.UserManagementCalls,
			pause: time.Duration(r.PauseMs) * time.Millisecond,
		}
		if r.Bulk != nil {
			req.bulk = bulkItems(r.Bulk, rt)
		}
		if r.BulkOperations != nil {
			req.bulkOperations = bulkItems(r.BulkOperations, rt)
		}
		if r.V2 != nil {
			req.v2, req.obligations = true, r.V2.Obligations
		}
		requests = append(requests, req)
	}
	return requests
}

// user returns the username of a "user:" subject, and "" for any other.
func (r requestSpec) user() string {
	who, _, _ := strings.Cut(r.Subject, "@")
	if name, ok := strings.CutPrefix(who, "user:"); ok {
		return name
	}
	return ""
}

// client returns the client a subject names after "@", and "" for a subject
// that names none.
func (r requestSpec) client() string {
	_, client, _ := strings.Cut(r.Subject, "@")
	return client
}

// A subject splits at "@" into the user the runner mints a token for and the
// client that issues it.
func TestRequestSpec_SplitsTheSubjectIntoUserAndClient(t *testing.T) {
	for _, tc := range []struct {
		subject, user, client string
	}{
		{"", "", ""},
		{"m2m", "", ""},
		{"user:parity-reader", "parity-reader", ""},
		{"m2m@parity-ts-bare", "", "parity-ts-bare"},
		{"user:parity-ts-many@parity-ts-arrays", "parity-ts-many", "parity-ts-arrays"},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			r := requestSpec{Subject: tc.subject}
			if got := r.user(); got != tc.user {
				t.Errorf("user() of %q = %q, want %q", tc.subject, got, tc.user)
			}
			if got := r.client(); got != tc.client {
				t.Errorf("client() of %q = %q, want %q", tc.subject, got, tc.client)
			}
		})
	}
}

// A case's resourceType replaces the resource type derived from the file's
// prefix and the case id, in the request type and in every {{resourceType}} of
// the condition or the set target; a case without it keeps the derived one.
func TestCaseFileCases_ResourceTypeReplacesTheDerivedOne(t *testing.T) {
	sets := []setSpec{{Key: "set", Target: "resourceType == '{{resourceType}}'"}}
	cases := []struct {
		name, resourceType, want string
	}{
		{"named", "PARITY_KEPT", "PARITY_KEPT"},
		{"derived", "", "PARITY_P_C_1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := caseFile{ResourceTypePrefix: "PARITY_P_", Cases: []caseSpec{
				{ID: "c-1", ResourceType: tc.resourceType, Condition: "resource.t == '{{resourceType}}'"},
				{ID: "c-1", ResourceType: tc.resourceType, Sets: sets},
			}}
			isolated, regular, _, err := caseFileCases(f)
			if err != nil {
				t.Fatal(err)
			}
			if isolated[0].resourceType != tc.want || isolated[0].condition != "resource.t == '"+tc.want+"'" {
				t.Errorf("isolated case: resource type %q, condition %q, want %q in both", isolated[0].resourceType, isolated[0].condition, tc.want)
			}
			target := regular[0].uploads[0].sets[0].(map[string]any)["target"]
			if regular[0].resourceType != tc.want || target != "resourceType == '"+tc.want+"'" {
				t.Errorf("regular case: resource type %q, set target %q, want %q in both", regular[0].resourceType, target, tc.want)
			}
		})
	}
}

// The userManagement pins and userManagementCalls of a case file reach the
// runner: a case's pins on the case, a request's pins and its call recording
// on the request, for a case without sets, one with sets, and a sequence case,
// whose step decides through the request.
func TestCaseFileCases_CarryTheUserManagementFields(t *testing.T) {
	casePins := map[string]PipStubResponse{DefaultRoute: {StatusCode: 404}}
	requestPins := map[string]PipStubResponse{"/users/u-1": {StatusCode: 200, Body: map[string]any{"id": "u-1"}}}
	request := []requestSpec{{Name: "read", UserManagement: requestPins, UserManagementCalls: true}}
	f := caseFile{ResourceTypePrefix: "PARITY_P_", Cases: []caseSpec{
		{ID: "iso", UserManagement: casePins, Requests: request},
		{ID: "reg", UserManagement: casePins, Sets: []setSpec{{Key: "set"}}, Requests: request},
		{ID: "seq", UserManagement: casePins, Steps: []stepSpec{
			{Name: "decide", Op: "read-config-sets", Observe: []string{"decide:read"}, Requests: request}}},
	}}
	isolated, regular, sequence, err := caseFileCases(f)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]map[string]PipStubResponse{
		"isolated": isolated[0].userManagement, "regular": regular[0].userManagement, "sequence": sequence[0].userManagement,
	} {
		if !reflect.DeepEqual(got, casePins) {
			t.Errorf("%s case: userManagement %v, want %v", name, got, casePins)
		}
	}
	for name, req := range map[string]isolatedRequest{"isolated": isolated[0].requests[0], "regular": regular[0].requests[0],
		"sequence step": sequence[0].steps[0].observe[0].request} {
		if !reflect.DeepEqual(req.userManagement, requestPins) || !req.userManagementCalls {
			t.Errorf("%s request: userManagement %v, userManagementCalls %v, want %v and true", name, req.userManagement, req.userManagementCalls, requestPins)
		}
	}
}
