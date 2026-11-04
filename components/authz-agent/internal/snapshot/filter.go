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

package snapshot

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
)

// FilterRequest is one check/filter request: the tenant, the subject as
// [Request] holds it, the resource type, and the operation, nil where the
// request names none.
type FilterRequest struct {
	Tenant       string
	Claims       *jsonvalue.Object
	Anonymous    bool
	Headers      map[string]string
	ResourceType string
	Operation    *string
}

// Filter answers req with the snapshot of req.Tenant: the rows of
// req.ResourceType the subject may read with the operation, READ where the
// request names none. The operation ALL, and a tenant without a snapshot,
// give DENY. The error is a defect of the projection or the evaluation, not
// a denial.
func (r *Registry) Filter(ctx context.Context, req FilterRequest) (regogen.FilterAnswer, error) {
	deny := regogen.FilterAnswer{Result: regogen.FilterDeny}
	op := "READ"
	if req.Operation != nil && *req.Operation != "" {
		op = *req.Operation
	}
	s, ok := r.Snapshot(req.Tenant)
	if !ok || op == "ALL" {
		return deny, nil
	}
	m := s.Filter
	in := regogen.Request{Tenant: req.Tenant, Anonymous: req.Anonymous, Claims: req.Claims, Headers: req.Headers,
		Entitlements: r.cfg.Entitlements, Body: regogen.Body{Operation: op, ResourceType: req.ResourceType}}
	claims := req.Claims
	if claims == nil {
		claims = jsonvalue.NewObject()
	}
	regogen.SubjectOf(claims, req.Anonymous, regogen.DefaultSubjectRules).Apply(&in)
	m.ResolveSubject(&in)
	ctx = regobuiltins.WithCalls(ctx)
	if r.cfg.HTTP != nil {
		ctx = r.cfg.HTTP.Context(ctx)
	}
	if m.Iterates {
		in.Scope = m.ReadScope(ctx, &in)
	}
	p, err := regogen.Project(m, in)
	if err != nil {
		return deny, fmt.Errorf("tenant %s: project the filter request: %w", req.Tenant, err)
	}
	rs, err := s.q.filter.Eval(p.Context(ctx), rego.EvalParsedInput(p.Value()))
	if err != nil {
		return deny, fmt.Errorf("tenant %s: evaluate the filter: %w", req.Tenant, err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return deny, fmt.Errorf("tenant %s: the filter module answered %d results", req.Tenant, len(rs))
	}
	st, err := regogen.ReadStatuses(rs[0].Expressions[0].Value)
	if err != nil {
		return deny, fmt.Errorf("tenant %s: %w", req.Tenant, err)
	}
	a, err := m.Filter(ctx, st, &in)
	if err != nil {
		return deny, fmt.Errorf("tenant %s: %w", req.Tenant, err)
	}
	return a, nil
}
