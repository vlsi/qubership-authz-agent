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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/legacy"
	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen"
)

// tenantHeader names the tenant of a request that has no query parameter
// tenant_id.
const tenantHeader = "Tenant"

// decide answers a check/resource request, single or bulk, with the
// generated policies of the request's tenant and writes the response in the
// shape of the route. The embedded policies check the caller and the
// subject's token first: a refused admission token is answered with its
// authError, and a refused subject token denies every item with its reason.
// Without a registry every item is denied as in a tenant without policies.
func (s *Server) decide(c *fiber.Ctx, originalPath string, resources []legacy.Resource, shape func(result any) []byte) error {
	input, admission, answered := s.admit(c, originalPath, resources)
	if answered != nil {
		return answered()
	}
	ctx := c.UserContext()
	tenant := input["tenant"].(string)
	var results []snapshot.Result
	switch reason, refused := admission["subjectError"]; {
	case refused:
		results = make([]snapshot.Result, len(resources))
		for i := range results {
			results[i].Reason = fmt.Sprint(reason)
		}
	case s.opts.Snapshots == nil:
		results = make([]snapshot.Result, len(resources))
		for i := range results {
			results[i].Reason = fmt.Sprintf(snapshot.ReasonNoTenant, tenant)
		}
	default:
		req, err := snapshotRequest(tenant, input, admission["tokenPayload"], c.GetReqHeaders(), resources)
		if err != nil {
			s.opts.Log.DebugC(ctx, "legacy request rejected path=%s: %v", c.Path(), err)
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "bad request"})
		}
		if results, err = s.opts.Snapshots.Decide(ctx, req); err != nil {
			s.opts.Log.ErrorC(ctx, "decision failed tenant=%s: %v", tenant, err)
			return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
	result := legacyResult(resources, results)
	s.log(c, input, result)
	return sendJSON(c, http.StatusOK, shape(result))
}

// filter answers a check/filter request with the generated filter of the
// request's tenant, after the same checks of the caller and the subject's
// token as decide: a refused subject token, and a service without a
// registry, get DENY.
func (s *Server) filter(c *fiber.Ctx, originalPath string, r legacy.Resource) error {
	input, admission, answered := s.admit(c, originalPath, []legacy.Resource{r})
	if answered != nil {
		return answered()
	}
	ctx := c.UserContext()
	tenant := input["tenant"].(string)
	answer := regogen.FilterAnswer{Result: regogen.FilterDeny}
	if _, refused := admission["subjectError"]; !refused && s.opts.Snapshots != nil {
		req, err := filterRequest(tenant, input, admission["tokenPayload"], c.GetReqHeaders(), r)
		if err != nil {
			s.opts.Log.DebugC(ctx, "legacy request rejected path=%s: %v", c.Path(), err)
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "bad request"})
		}
		if answer, err = s.opts.Snapshots.Filter(ctx, req); err != nil {
			s.opts.Log.ErrorC(ctx, "filter failed tenant=%s: %v", tenant, err)
			return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
	body, err := json.Marshal(answer)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	s.log(c, input, result)
	return sendJSON(c, http.StatusOK, body)
}

// admit builds the input of the embedded policies for resources, with the
// tenant of the request, and evaluates their checks of the caller and the
// subject's token. answered is non-nil when the request is answered
// already: a refused admission token, with its authError, or a failed
// evaluation, with 500.
func (s *Server) admit(c *fiber.Ctx, originalPath string, resources []legacy.Resource) (input, admission map[string]any,
	answered func() error) {
	c.Request().Header.Set(originalPathHeader, originalPath)
	ctx := c.UserContext()
	input = legacy.Input(c.GetReqHeaders(), resources)
	admission, err := s.admission(ctx, input)
	if err != nil {
		s.opts.Log.ErrorC(ctx, "admission failed: %v", err)
		return nil, nil, func() error { return opaError(c, http.StatusInternalServerError, "internal_error", err.Error()) }
	}
	input["tenant"] = s.tenant(c)
	if raw, refused := admission["authError"]; refused {
		result := map[string]any{"authError": raw}
		s.log(c, input, result)
		status, body, _ := legacy.AuthError(result)
		return nil, nil, func() error { return sendJSON(c, status, body) }
	}
	return input, admission, nil
}

// log reports a decision at debug and records it, when decisions are
// logged, under the path the embedded policies log theirs. The debug line
// carries neither the input nor the result, which hold the caller's token
// and claims.
func (s *Server) log(c *fiber.Ctx, input map[string]any, result map[string]any) {
	id := ""
	if s.logs != nil && s.logs.Enabled() {
		id = decisionlog.NewDecisionID()
		s.logDecision(c, id, []string{"authorize"}, input, result, true)
	}
	s.opts.Log.DebugC(c.UserContext(), "decision path=authorize tenant=%v decisionId=%s", input["tenant"], id)
}

// admission evaluates the caller and subject checks of the embedded
// policies on input.
func (s *Server) admission(ctx context.Context, input map[string]any) (map[string]any, error) {
	v, defined, err := s.engine.Eval(ctx, []string{"authorize_internals", "admission"}, input, nil)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !defined || !ok {
		return nil, fmt.Errorf("the embedded policies gave no admission outcome")
	}
	return m, nil
}

// tenant is the tenant a request is decided in: the query parameter
// tenant_id, else the header Tenant, else the default tenant. A blank
// source is skipped.
func (s *Server) tenant(c *fiber.Ctx) string {
	if t := strings.TrimSpace(lastQuery(c, "tenant_id")); t != "" {
		return t
	}
	if t := strings.TrimSpace(c.Get(tenantHeader)); t != "" {
		return t
	}
	if s.opts.DefaultTenant != nil {
		return s.opts.DefaultTenant()
	}
	return ""
}

// snapshotRequest builds the request of the registry from the verified
// claims the subject is read from, which an anonymous request takes from
// its admission token, the request's headers, and the items as the request
// wrote them.
func snapshotRequest(tenant string, input map[string]any, payload any, headers map[string][]string,
	resources []legacy.Resource) (snapshot.Request, error) {
	claims, err := claimsOf(payload)
	if err != nil {
		return snapshot.Request{}, err
	}
	req := snapshot.Request{Tenant: tenant, Headers: lastValues(headers), Anonymous: input["subject"] == "",
		Claims: claims}
	for _, r := range resources {
		b, err := body(r.Raw)
		if err != nil {
			return req, err
		}
		req.Items = append(req.Items, b)
	}
	return req, nil
}

// filterRequest is snapshotRequest for check/filter: the resource type and
// the operation of r as the query sent them, an empty operation as none.
func filterRequest(tenant string, input map[string]any, payload any, headers map[string][]string,
	r legacy.Resource) (snapshot.FilterRequest, error) {
	claims, err := claimsOf(payload)
	if err != nil {
		return snapshot.FilterRequest{}, err
	}
	req := snapshot.FilterRequest{Tenant: tenant, Headers: lastValues(headers), Anonymous: input["subject"] == "",
		Claims: claims, ResourceType: fmt.Sprint(r.ResourceType)}
	if op := fmt.Sprint(r.Operation); op != "" {
		req.Operation = &op
	}
	return req, nil
}

// lastValues holds the last value of each header by lower-case name.
func lastValues(headers map[string][]string) map[string]string {
	out := map[string]string{}
	for k, values := range headers {
		if len(values) > 0 {
			out[strings.ToLower(k)] = values[len(values)-1]
		}
	}
	return out
}

// claimsOf is the token payload of the admission as claims, an empty
// object for a payload that is not one.
func claimsOf(payload any) (*jsonvalue.Object, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	v, err := jsonvalue.Decode(raw)
	if err != nil {
		return nil, err
	}
	claims, ok := v.(*jsonvalue.Object)
	if !ok {
		claims = jsonvalue.NewObject()
	}
	return claims, nil
}

// body is the projection's view of one resource; a field the request left
// out is null, and a resource it left out is absent.
func body(raw legacy.RawResource) (regogen.Body, error) {
	var b regogen.Body
	var err error
	if b.ResourceType, err = decode(raw.Type); err != nil {
		return b, err
	}
	if b.Operation, err = decode(raw.Operation); err != nil {
		return b, err
	}
	if len(raw.Resource) > 0 {
		b.HasResource = true
		if b.Resource, err = decode(raw.Resource); err != nil {
			return b, err
		}
	}
	return b, nil
}

func decode(raw json.RawMessage) (jsonvalue.Value, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return jsonvalue.Decode(raw)
}

// legacyResult is the decision in the shape the response builders of
// package legacy read: results with resourceType, operation, isAllowed, and
// the reason of a denial.
func legacyResult(resources []legacy.Resource, results []snapshot.Result) map[string]any {
	list := make([]any, len(results))
	for i, r := range results {
		item := map[string]any{
			"resourceType": resources[i].ResourceType,
			"operation":    resources[i].Operation,
			"isAllowed":    r.Allowed,
		}
		if !r.Allowed {
			item["reason"] = r.Reason
		}
		list[i] = item
	}
	return map[string]any{"rlsIgnored": false, "results": list}
}
