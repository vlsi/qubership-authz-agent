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
// Without a registry the request takes the path of check/filter.
func (s *Server) decide(c *fiber.Ctx, originalPath string, resources []legacy.Resource, shape func(result any) []byte) error {
	if s.opts.Snapshots == nil {
		return s.check(c, originalPath, resources, shape)
	}
	c.Request().Header.Set(originalPathHeader, originalPath)
	ctx := c.UserContext()
	headers := c.GetReqHeaders()
	input := legacy.Input(headers, resources)
	admission, err := s.admission(ctx, input)
	if err != nil {
		s.opts.Log.ErrorC(ctx, "admission failed: %v", err)
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if raw, refused := admission["authError"]; refused {
		result := map[string]any{"authError": raw}
		s.log(c, input, result)
		status, body, _ := legacy.AuthError(result)
		return sendJSON(c, status, body)
	}
	tenant := s.tenant(c)
	input["tenant"] = tenant
	var results []snapshot.Result
	if reason, refused := admission["subjectError"]; refused {
		results = make([]snapshot.Result, len(resources))
		for i := range results {
			results[i].Reason = fmt.Sprint(reason)
		}
	} else {
		req, err := snapshotRequest(tenant, input, admission["tokenPayload"], headers, resources)
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

// log records a decision of the generated policies, when decisions are
// logged, under the path the embedded policies log theirs.
func (s *Server) log(c *fiber.Ctx, input map[string]any, result map[string]any) {
	if s.logs != nil && s.logs.Enabled() {
		s.logDecision(c, decisionlog.NewDecisionID(), []string{"authorize"}, input, result, true, nil)
	}
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
	req := snapshot.Request{Tenant: tenant, Headers: map[string]string{}}
	for k, values := range headers {
		if len(values) > 0 {
			req.Headers[strings.ToLower(k)] = values[len(values)-1]
		}
	}
	req.Anonymous = input["subject"] == ""
	raw, err := json.Marshal(payload)
	if err != nil {
		return req, err
	}
	v, err := jsonvalue.Decode(raw)
	if err != nil {
		return req, err
	}
	claims, ok := v.(*jsonvalue.Object)
	if !ok {
		claims = jsonvalue.NewObject()
	}
	req.Claims = claims
	for _, r := range resources {
		b, err := body(r.Raw)
		if err != nil {
			return req, err
		}
		req.Items = append(req.Items, b)
	}
	return req, nil
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
