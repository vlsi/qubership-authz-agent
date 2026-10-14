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

	"authz-agent/test/parity/suite/model"
)

// sendV2Request sends req, whose v2 is set, through the v2 endpoint of its
// kind with tokens, and returns the outcome with the endpoint its golden is
// filed under; see requestSpec.V2.
func (s *ParitySuite) sendV2Request(resourceType string, req isolatedRequest, tokens TokenBundle) (ParityEndpointID, any) {
	s.T().Helper()
	ctx := context.Background()
	opts := req.callOptions()
	switch {
	case req.bulkOperations != nil:
		body, err := v2BulkOperationsBody(req.bulkOperations, resourceType)
		s.Require().NoError(err)
		status, raw, err := HelperPostV2(ctx, s.cfg, v2PathCheckResourceBulkOperations, v2Query(nil, req.obligations), body, tokens, opts)
		s.Require().NoError(err)
		outcome, err := bulkOperationsV2Outcome(status, raw, s.refusal(status, raw))
		s.Require().NoError(err)
		return PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, outcome
	case req.filter:
		query := v2Query(filterV1Query(valueOr(req.typ, resourceType), req.filterOperation(), req.emptyOperation), req.obligations)
		status, raw, err := HelperPostV2(ctx, s.cfg, v2PathCheckFilter, query, nil, tokens, opts)
		s.Require().NoError(err)
		return PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, filterV2Outcome(status, raw, s.refusal(status, raw))
	}
	body := model.CheckResourceRequest{Operation: checkOperation(req.operation, req.emptyOperation), Type: valueOr(req.typ, resourceType), Resource: req.resource}
	status, raw, err := HelperPostV2(ctx, s.cfg, v2PathCheckResource, v2Query(nil, req.obligations), body, tokens, opts)
	s.Require().NoError(err)
	return PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, checkV2Outcome(status, raw, s.refusal(status, raw))
}
