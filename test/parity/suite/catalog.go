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

package paritysuite

import (
	"fmt"

	"authz-agent/test/parity/suite/model"
)

// ParityEndpointID enumerates the parity-contract Summary Table rows the Go
// helper layer implements directly. CLANG / AGG / SUB / ENT rows inherit the
// id of the parity-contract row they cite (check/resource → PSUITE_ROW_2,
// check/filter → PSUITE_ROW_6, etc.) — they do not get their own id because
// the row→Go-struct binding is the thing this enum drives.
type ParityEndpointID int

const (
	PSUITE_ROW_1_API_VERSION ParityEndpointID = iota + 1
	PSUITE_ROW_2_CHECK_RESOURCE_V1
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1
	PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1
	PSUITE_ROW_6_CHECK_FILTER_V1
	PSUITE_ROW_7_CHECK_RESOURCE_V2
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2
	PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2
	PSUITE_ROW_10_CHECK_FILTER_V2
	// PSUITE_LOAD_SIMPLIFIED_POLICIES is the PAP upload of simplified policies,
	// used by the cases that record whether access-control accepts a condition.
	PSUITE_LOAD_SIMPLIFIED_POLICIES
	// PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME is row 2 recorded with its HTTP
	// status, for requests access-control may refuse.
	PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME
	// PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME is row 6 recorded with its HTTP status.
	PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME
	// PSUITE_LOAD_POLICY_SETS is the PAP upload of regular policy sets.
	PSUITE_LOAD_POLICY_SETS
	// PSUITE_CONFIG_POLICY_SETS_V3 is the export of every policy set the PAP
	// holds, which the agent reads instead of the uploads.
	PSUITE_CONFIG_POLICY_SETS_V3
	// PSUITE_CONFIG_PIPS_V3 is the export of every PIP declaration the PAP holds.
	PSUITE_CONFIG_PIPS_V3
	// PSUITE_IMPORT_CUSTOMIZATION is the PAP import of policy customizations at
	// one level, which disable or replace an uploaded rule.
	PSUITE_IMPORT_CUSTOMIZATION
	// PSUITE_PIP_CALL is what pip-mock received from the service under test on
	// one PIP route over one request.
	PSUITE_PIP_CALL
	// PSUITE_PAP_READ is a GET the suite sends to the PAP outside the v3
	// export; the path is the case's.
	PSUITE_PAP_READ
	// PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME is row 3 recorded with its
	// HTTP status, for requests access-control may refuse.
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME
	// PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME is row 4 recorded
	// with its HTTP status.
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME
	// PSUITE_IMPORT_PIP_CUSTOMIZATION is the PAP import of PIP customizations
	// at one level.
	PSUITE_IMPORT_PIP_CUSTOMIZATION
	// PSUITE_DELETE_CUSTOMIZATION is the PAP delete of the customization of
	// one policy set at one level.
	PSUITE_DELETE_CUSTOMIZATION
	// PSUITE_DELETE_PIP_CUSTOMIZATION is the PAP delete of the customization
	// of one PIP at the level the call names.
	PSUITE_DELETE_PIP_CUSTOMIZATION
	// PSUITE_PAP_STATUS is the status of a case step that writes through a
	// PAP endpoint with no golden kind of its own; see testdata/pap-operations.json.
	PSUITE_PAP_STATUS
	// PSUITE_PAP_ERROR is the status and the error body of a case step's PAP
	// call, recorded when the step observes error-class; it is compared by
	// status, see compareOptionsFor.
	PSUITE_PAP_ERROR
	// PSUITE_PAP_READ_RAW is a case step's read recorded whole, when the step
	// observes read-raw:<op>.
	PSUITE_PAP_READ_RAW
	// PSUITE_USER_MANAGEMENT_CALL is what the User Management stub received
	// from the service under test over one request.
	PSUITE_USER_MANAGEMENT_CALL
	// PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME is row 7 sent by a case file with
	// its own obligations parameter, recorded with its HTTP status and the
	// obligations member of the answer.
	PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME
	// PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME is row 8 sent and
	// recorded as PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME is.
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME
	// PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME is row 10 sent and recorded as
	// PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME is.
	PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME
)

// RowMeta holds the canonical per-row metadata the GoldenComparator and
// record-mode writer use to pick the right golden-factory and the right
// cmp.Diff options.
type RowMeta struct {
	ID                ParityEndpointID
	Name              string
	HTTPMethod        string
	PathTmpl          string
	GoldenDir         string
	IgnoreObligations bool
	SortSlices        bool
}

// rowMetas is keyed by ParityEndpointID and populated from the parity
// contract's Summary Table. IgnoreObligations flips for v2 rows 7/8/9/10
// per D-E. SortSlices flips for rows 3/4/5/8/9 where the wire order is
// "LinkedHashSet-ordered but the client discards order" — the comparator
// therefore sorts before running cmp.Diff per D-M.
var rowMetas = map[ParityEndpointID]RowMeta{
	PSUITE_ROW_1_API_VERSION: {
		ID: PSUITE_ROW_1_API_VERSION, Name: "api-version", HTTPMethod: "GET",
		PathTmpl: "/api-version", GoldenDir: "api-version",
	},
	PSUITE_ROW_2_CHECK_RESOURCE_V1: {
		ID: PSUITE_ROW_2_CHECK_RESOURCE_V1, Name: "check-resource-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource", GoldenDir: "check-resource-v1",
	},
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1: {
		ID: PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, Name: "check-resource-bulk-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk", GoldenDir: "check-resource-bulk-v1",
		SortSlices: true,
	},
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1: {
		ID: PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, Name: "check-resource-bulk-operations-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v1",
		SortSlices: true,
	},
	PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1: {
		ID: PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, Name: "preview-bulk-operations-v1", HTTPMethod: "POST",
		PathTmpl: "/preview/v1/check/resource/bulk/operations", GoldenDir: "preview-bulk-operations-v1",
		SortSlices: true,
	},
	PSUITE_ROW_6_CHECK_FILTER_V1: {
		ID: PSUITE_ROW_6_CHECK_FILTER_V1, Name: "check-filter-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/filter", GoldenDir: "check-filter-v1",
	},
	PSUITE_ROW_7_CHECK_RESOURCE_V2: {
		ID: PSUITE_ROW_7_CHECK_RESOURCE_V2, Name: "check-resource-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource", GoldenDir: "check-resource-v2",
		IgnoreObligations: true,
	},
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2: {
		ID: PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, Name: "check-resource-bulk-operations-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v2",
		IgnoreObligations: true, SortSlices: true,
	},
	PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2: {
		ID: PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, Name: "preview-bulk-operations-v2", HTTPMethod: "POST",
		PathTmpl: "/preview/v2/check/resource/bulk/operations", GoldenDir: "preview-bulk-operations-v2",
		IgnoreObligations: true, SortSlices: true,
	},
	PSUITE_ROW_10_CHECK_FILTER_V2: {
		ID: PSUITE_ROW_10_CHECK_FILTER_V2, Name: "check-filter-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/filter", GoldenDir: "check-filter-v2",
		IgnoreObligations: true,
	},
	PSUITE_LOAD_SIMPLIFIED_POLICIES: {
		ID: PSUITE_LOAD_SIMPLIFIED_POLICIES, Name: "load-simplified-policies-v1", HTTPMethod: "PUT",
		PathTmpl: "/access/v1/simplifiedPolicies/domainPolicies/{domain}", GoldenDir: "load-simplified-policies-v1",
	},
	PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME: {
		ID: PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, Name: "check-resource-v1-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource", GoldenDir: "check-resource-v1-outcome",
	},
	PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME: {
		ID: PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, Name: "check-filter-v1-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/filter", GoldenDir: "check-filter-v1-outcome",
	},
	PSUITE_LOAD_POLICY_SETS: {
		ID: PSUITE_LOAD_POLICY_SETS, Name: "load-policy-sets-v1", HTTPMethod: "PUT",
		PathTmpl: "/access/v1/policySets/externalId/{externalId}", GoldenDir: "load-policy-sets-v1",
	},
	PSUITE_CONFIG_POLICY_SETS_V3: {
		ID: PSUITE_CONFIG_POLICY_SETS_V3, Name: "config-policy-sets-v3", HTTPMethod: "GET",
		PathTmpl: "/access/v3/config/policySets", GoldenDir: "config-policy-sets-v3",
	},
	PSUITE_CONFIG_PIPS_V3: {
		ID: PSUITE_CONFIG_PIPS_V3, Name: "config-pips-v3", HTTPMethod: "GET",
		PathTmpl: "/access/v3/config/pips", GoldenDir: "config-pips-v3",
	},
	PSUITE_IMPORT_CUSTOMIZATION: {
		ID: PSUITE_IMPORT_CUSTOMIZATION, Name: "import-customization-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/config/customization/import", GoldenDir: "import-customization-v1",
	},
	PSUITE_PIP_CALL: {
		ID: PSUITE_PIP_CALL, Name: "pip-call", HTTPMethod: "POST",
		PathTmpl: "/api/v1/pip", GoldenDir: "pip-call",
	},
	PSUITE_USER_MANAGEMENT_CALL: {
		ID: PSUITE_USER_MANAGEMENT_CALL, Name: "user-management-call", HTTPMethod: "GET",
		PathTmpl: "/", GoldenDir: "user-management-call",
	},
	PSUITE_PAP_READ: {
		ID: PSUITE_PAP_READ, Name: "pap-read", HTTPMethod: "GET",
		PathTmpl: "/access/v1", GoldenDir: "pap-read",
	},
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME: {
		ID: PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME, Name: "check-resource-bulk-v1-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk", GoldenDir: "check-resource-bulk-v1-outcome",
		SortSlices: true,
	},
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME: {
		ID: PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME, Name: "check-resource-bulk-operations-v1-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v1-outcome",
		SortSlices: true,
	},
	PSUITE_IMPORT_PIP_CUSTOMIZATION: {
		ID: PSUITE_IMPORT_PIP_CUSTOMIZATION, Name: "import-pip-customization-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/pip/customization/import", GoldenDir: "import-pip-customization-v1",
	},
	PSUITE_DELETE_CUSTOMIZATION: {
		ID: PSUITE_DELETE_CUSTOMIZATION, Name: "delete-customization-v1", HTTPMethod: "DELETE",
		PathTmpl: "/access/v1/config/customization/policySet/{policySetId}", GoldenDir: "delete-customization-v1",
	},
	PSUITE_DELETE_PIP_CUSTOMIZATION: {
		ID: PSUITE_DELETE_PIP_CUSTOMIZATION, Name: "delete-pip-customization-v1", HTTPMethod: "DELETE",
		PathTmpl: "/access/v1/pip/customization/pip/{name}", GoldenDir: "delete-pip-customization-v1",
	},
	PSUITE_PAP_STATUS: {
		ID: PSUITE_PAP_STATUS, Name: "pap-status-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1", GoldenDir: "pap-status-v1",
	},
	PSUITE_PAP_ERROR: {
		ID: PSUITE_PAP_ERROR, Name: "pap-error-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1", GoldenDir: "pap-error-v1",
	},
	PSUITE_PAP_READ_RAW: {
		ID: PSUITE_PAP_READ_RAW, Name: "pap-read-raw-v1", HTTPMethod: "GET",
		PathTmpl: "/access/v1", GoldenDir: "pap-read-raw-v1",
	},
	PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME: {
		ID: PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME, Name: "check-resource-v2-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource", GoldenDir: "check-resource-v2-outcome",
	},
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME: {
		ID: PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME, Name: "check-resource-bulk-operations-v2-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v2-outcome",
		SortSlices: true,
	},
	PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME: {
		ID: PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME, Name: "check-filter-v2-outcome", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/filter", GoldenDir: "check-filter-v2-outcome",
	},
}

// Meta returns a copy of the row metadata for the given id; panics on
// unknown id to fail fast in replay tests rather than silently falling
// through to a zero-value row.
func Meta(id ParityEndpointID) RowMeta {
	m, ok := rowMetas[id]
	if !ok {
		panic(fmt.Sprintf("paritysuite: unknown ParityEndpointID %d", int(id)))
	}
	return m
}

// NewGoldenTarget returns a fresh zero-value pointer that the
// GoldenComparator unmarshals both the golden JSON and the actual response
// into per D-M. CLANG / AGG / SUB / ENT rows reuse the row id they inherit
// from the parity-contract row they live on, so this map covers them
// transitively — no extra ids are needed.
func NewGoldenTarget(id ParityEndpointID) any {
	switch id {
	case PSUITE_ROW_1_API_VERSION:
		return &model.ApiVersionResponse{}
	case PSUITE_ROW_2_CHECK_RESOURCE_V1:
		var decision bool
		return &decision
	case PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1:
		return &[]string{}
	case PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1,
		PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1:
		return &map[string][]string{}
	case PSUITE_ROW_6_CHECK_FILTER_V1:
		return &model.OldFilterEvaluationResult{}
	case PSUITE_ROW_7_CHECK_RESOURCE_V2:
		return &model.CheckResourceResponse{}
	case PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2,
		PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2:
		return &model.CheckResourcesResponse{}
	case PSUITE_ROW_10_CHECK_FILTER_V2:
		return &model.FilterResponse{}
	case PSUITE_LOAD_SIMPLIFIED_POLICIES, PSUITE_LOAD_POLICY_SETS, PSUITE_IMPORT_CUSTOMIZATION,
		PSUITE_IMPORT_PIP_CUSTOMIZATION, PSUITE_DELETE_CUSTOMIZATION, PSUITE_DELETE_PIP_CUSTOMIZATION, PSUITE_PAP_STATUS:
		return &model.PolicyLoadOutcome{}
	case PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME:
		return &model.CheckResourceOutcome{}
	case PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME:
		return &model.FilterOutcome{}
	case PSUITE_CONFIG_POLICY_SETS_V3, PSUITE_CONFIG_PIPS_V3:
		return &model.ConfigExportOutcome{}
	case PSUITE_PIP_CALL:
		return &model.PipCallOutcome{}
	case PSUITE_USER_MANAGEMENT_CALL:
		return &model.UserManagementCallOutcome{}
	case PSUITE_PAP_READ:
		return &model.PapReadOutcome{}
	case PSUITE_PAP_ERROR:
		return &model.PapErrorOutcome{}
	case PSUITE_PAP_READ_RAW:
		return &model.PapReadRawOutcome{}
	case PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1_OUTCOME:
		return &model.CheckResourceBulkOutcome{}
	case PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1_OUTCOME:
		return &model.CheckResourceBulkOperationsOutcome{}
	case PSUITE_ROW_7_CHECK_RESOURCE_V2_OUTCOME:
		return &model.CheckResourceV2Outcome{}
	case PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2_OUTCOME:
		return &model.CheckResourceBulkOperationsV2Outcome{}
	case PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME:
		return &model.FilterV2Outcome{}
	}
	panic(fmt.Sprintf("paritysuite: no golden factory for ParityEndpointID %d", int(id)))
}
