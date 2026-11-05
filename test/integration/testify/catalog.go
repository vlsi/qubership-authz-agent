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

package runtimetest

// StepEntry describes a single named integration test step.
type StepEntry struct {
	Name       string
	Username   string
	Endpoint   string
	Resource   string
	Operation  string
	TokenRoles string
}

// Endpoints and a username that many entries of Catalog share, written once
// so every entry spells them the same way.
const (
	epCheckResource     = "POST /access/v1/check/resource"
	epCheckResourceBulk = "POST /access/v1/check/resource/bulk"
	epCheckFilter       = "POST /access/v1/check/filter"
	epUploadPIPs        = "PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}"
	userOrderReader     = "order-reader"
)

// Catalog is the machine-readable source of truth for all runtime integration test steps.
// Every executed step must reference a name from this catalog; the catalog also drives
// the committed human-readable table in tests/readme.md.
//
// Username convention: use the actual Keycloak username for steps that authenticate as a
// specific user; use "n/a" when no end-user identity exists (no token, service tokens,
// setup actions without user context).
var Catalog = []StepEntry{
	// ── setup ────────────────────────────────────────────────────────────
	{"setup.wait_for_keycloak", "n/a", "GET (Keycloak OIDC discovery)", "-", "-", "none"},
	{"setup.token_acquire_expired", "order-reader, admin", "POST (Keycloak /token)", "-", "-", "ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR"},
	{"setup.token_expiry_wait", "n/a", "-", "-", "-", "none"},
	{"setup.token_acquire_valid", "order-reader, admin", "POST (Keycloak /token)", "-", "-", "ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR"},
	{"setup.wait_for_authz_policy_admin", "n/a", "GET /authz-policy-admin/hash", "-", "-", "none"},
	{"setup.policy_upload", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},
	{"setup.pip_upload", "n/a", epUploadPIPs, "-", "-", "none"},
	{"setup.wait_for_agent", "admin", epCheckResource, "-", "-", "ROLE_ADMINISTRATOR"},

	// ── check_resource ───────────────────────────────────────────────────
	{"check_resource.order_read.rls_deny", userOrderReader, epCheckResource, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.incoming_token_used_for_subject", userOrderReader, epCheckResource, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.expired_authorization.401", userOrderReader, epCheckResource, "ATTACHMENT", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER (expired)"},
	{"check_resource.no_token.401", "n/a", epCheckResource, "ATTACHMENT", "READ", "none"},
	{"check_resource.unknown_tenant_id.deny", userOrderReader, epCheckResource, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.tenant_id_absent", userOrderReader, epCheckResource, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource.null_body.400", "admin", epCheckResource, "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource.boolean_response", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.missing_fields.400", "admin", epCheckResource, "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource.wrong_address.404", "admin", "POST /access/v1/check/resourc", "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.incoming_token_precedence_over_authorization", "admin+order-reader", epCheckResource, "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR (Authorization) / ROLE_ORDER_MANAGEMENT_RO_USER (Incoming-Token)"},
	{"check_resource.anonymous_subject_marker", "admin", epCheckResource, "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR (M2M) / anonymous (subject)"},
	{"check_resource.incoming_token_stripped_from_header_pip", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.invalid_authorization.401", "n/a", epCheckResource, "ATTACHMENT", "READ", "none (invalid)"},
	{"check_resource.authorization_without_bearer.401", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.incoming_token_without_bearer.deny", "admin", epCheckResource, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource.pip_value_substituted", "admin", epCheckResource, "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},

	// ── check_resource_bulk ──────────────────────────────────────────────
	{"check_resource_bulk.owner_mismatch.denied", userOrderReader, epCheckResourceBulk, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource_bulk.unknown_type.denied", "admin", epCheckResourceBulk, "INVOICE", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.empty_array", "admin", epCheckResourceBulk, "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.null_body.400", "admin", epCheckResourceBulk, "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.response_is_array", "admin", epCheckResourceBulk, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.large_3000", "admin", epCheckResourceBulk, "BULK_OPEN", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.no_token.401", "n/a", epCheckResourceBulk, "ORDER", "READ", "none"},
	{"check_resource_bulk.no_id_empty", "admin", epCheckResourceBulk, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.missing_type_op.400", "admin", epCheckResourceBulk, "-", "-", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.duplicate_ids.400", "admin", epCheckResourceBulk, "ORDER", "READ,DELETE", "ROLE_ADMINISTRATOR"},
	{"check_resource_bulk.unknown_tenant_id.denied", userOrderReader, epCheckResourceBulk, "ORDER", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_resource_bulk.wrong_address.404", "admin", "POST /access/v1/check/resource/bul", "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── check_filter ─────────────────────────────────────────────────────
	{"check_filter.calculation_result_present", "admin", epCheckFilter, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.unknown_type.deny", "admin", epCheckFilter, "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.deny_all_fields", "admin", epCheckFilter, "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.known_resource.not_null", userOrderReader, epCheckFilter, "ATTACHMENT", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_filter.missing_operation", userOrderReader, epCheckFilter, "ATTACHMENT", "-", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"check_filter.unknown_tenant_id.deny", "admin", epCheckFilter, "NONEXISTENT", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.no_token.401", "n/a", epCheckFilter, "ORDER", "READ", "none"},
	{"check_filter.missing_resource_type.400", "admin", epCheckFilter, "-", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.wrong_address.404", "admin", "POST /access/v1/check/filte", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"check_filter.predicate_subject_attr_substituted", "admin", epCheckFilter, "PUBLIC_DOC", "READ", "ROLE_ADMINISTRATOR"},

	// ── pip_general ─────────────────────────────────────────────────────
	{"pip_general.stub_reset", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.upload_pips_for_general", "n/a", epUploadPIPs, "CUSTOMER", "READ", "none"},
	{"pip_general.active_pip_called", "admin", epCheckFilter, "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.stub_verify_active_called", "n/a", "GET (pip-stub /calls)", "CUSTOMER", "READ", "none"},
	{"pip_general.stub_reset_after", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.inactive_pip_not_called", "admin", epCheckFilter, "DOCUMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.stub_verify_inactive_not_called", "n/a", "GET (pip-stub /calls)", "DOCUMENT", "READ", "none"},
	{"pip_general.bulk_reset_calls", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_general.bulk_pin_allowed_subset", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},
	{"pip_general.bulk_pip_filters_resources", "admin", epCheckResourceBulk, "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_general.bulk_stub_verify_called", "n/a", "GET (pip-stub /calls)", "CUSTOMER", "READ", "none"},
	{"pip_general.restore_default_stub", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},

	// ── pip_jsonpath ───────────────────────────────────────────────────
	{"pip_jsonpath.stub_reset", "n/a", "POST (pip-stub reset)", "-", "-", "none"},
	{"pip_jsonpath.upload_json_pip", "n/a", epUploadPIPs, "CUSTOMER", "READ", "none"},
	{"pip_jsonpath.pin_json_response", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},
	{"pip_jsonpath.bulk_extracts_ids_and_filters", "admin", epCheckResourceBulk, "CUSTOMER", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_jsonpath.restore_legacy_pip", "n/a", epUploadPIPs, "CUSTOMER", "READ", "none"},
	{"pip_jsonpath.restore_default_stub", "n/a", "PUT (pip-stub configure)", "-", "-", "none"},

	// ── rls_aggregation ──────────────────────────────────────────────────
	{"check_filter.multi_frag.rsql_or_aggregation", "admin", epCheckFilter, "MULTI_FRAG_ITEM", "READ", "ROLE_ADMINISTRATOR"},

	// ── token_pip_filter ────────────────────────────────────────────
	{"token_pip_filter.upload_token_pips", "n/a", epUploadPIPs, "TOKEN_PIP_POSITIVE,TOKEN_PIP_DEFAULT", "READ", "none"},
	{"token_pip_filter.positive_alias_in_filter", "admin", epCheckFilter, "TOKEN_PIP_POSITIVE", "READ", "ROLE_ADMINISTRATOR"},
	{"token_pip_filter.default_value_fallback", "admin", epCheckFilter, "TOKEN_PIP_DEFAULT", "READ", "ROLE_ADMINISTRATOR"},

	// ── pip_deny_reason ─────────────────────────────────────────────────
	{"pip_deny.upload_broken_pip", "n/a", epUploadPIPs, "PIP_FAIL_TEST", "READ", "none"},
	{"pip_deny.pip_failure_deny_reason", "admin", epCheckResource, "PIP_FAIL_TEST", "READ", "ROLE_ADMINISTRATOR"},
	{"pip_deny.missing_attr_deny_reason", "admin", epCheckResource, "ATTR_MISS_TEST", "READ", "ROLE_ADMINISTRATOR"},

	// ── health ───────────────────────────────────────────────────────────
	{"health.healthy_strict", "n/a", "GET /health", "-", "-", "none"},
	{"health.method_not_allowed", "n/a", "POST /health", "-", "-", "none"},
	{"health.regression.check_resource", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	// readiness: pap-client healthcheck --readiness must exit 0 after the
	// first successful policy pull (pull status latch written).

	// ── decision_logs ────────────────────────────────────────────────────
	{"decision_logs.download_no_token.200", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},
	{"decision_logs.content_is_ndjson", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},

	// ── entitlements ─────────────────────────────────────────────────────
	// Exercises the container-pinned entitlements PIP end-to-end: the test
	// pins a per-user response on the entitlements-mock stub, uploads an
	// ENT-flavoured policy via PUT /access/v1/simplifiedPolicies/domainPolicies/{domain} (pull loop), then drives
	// /access/v1/check/resource through Envoy + OPA to validate that the
	// ENT operand evaluates against the resolved bucket.
	{"entitlements.contains.allow_hit", "admin", epCheckResource, "ENT_CONTRACT", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.contains.deny_miss", "admin", epCheckResource, "ENT_CONTRACT", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.is_empty.allow_when_empty", "admin", epCheckResource, "ENT_EMPTY", "READ", "ROLE_ADMINISTRATOR"},
	{"entitlements.multi_as_union.allow", "admin", epCheckResource, "ENT_MULTI", "READ", "ROLE_ADMINISTRATOR"},
	{"decision_logs.catalog_coverage", "n/a", "GET /internal/v1/decision-logs", "-", "-", "none"},
	{"decision_logs.legacy_path_header", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── wildcard_access ─────────────────────────────────────────────────
	{"wildcard_access.upload_wildcard_policies", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},
	{"wildcard_access.all_all.no_predicates", "admin", epCheckFilter, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.all_all.no_deny_reason", "admin", epCheckResource, "WC_EXACT_ONLY", "READ", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.all_op.reader_delete_denied", userOrderReader, epCheckResource, "UNKNOWN_TYPE", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.rt_all.reader_any_op", userOrderReader, epCheckFilter, "WC_RT_TARGET", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.rt_all.reader_other_rt_denied", userOrderReader, epCheckResource, "OTHER_TYPE", "DELETE", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.mixed.partial_wildcard", userOrderReader, epCheckResourceBulk, "WC_RT_TARGET,INVOICE", "DELETE,READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.legacy.check_resource_all_all", "admin", epCheckResource, "UNKNOWN_TYPE", "DELETE", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.legacy.check_resource_bulk_all_all", "admin", epCheckResourceBulk, "UNKNOWN_TYPE", "DELETE", "ROLE_ADMINISTRATOR"},
	{"wildcard_access.legacy.check_filter_all_op", userOrderReader, epCheckFilter, "UNKNOWN_TYPE", "READ", "ROLE_ORDER_MANAGEMENT_RO_USER"},
	{"wildcard_access.restore_original_policies", "n/a", "PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}", "-", "-", "none"},

	// ── m2m_keycloak ────────────────────────────────────────────────────
	// These steps run only when M2M_KEYCLOAK_PROFILE=true, as the kind
	// harness sets it. Against an agent with a static M2M token they are
	// skipped — the step body calls t.Skip() so the catalog coverage check
	// still passes.
	{"m2m_keycloak.pull_succeeds_with_keycloak_token", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},
	{"m2m_keycloak.agent_functional_after_token_refresh", "admin", epCheckResource, "ATTACHMENT", "READ", "ROLE_ADMINISTRATOR"},

	// ── lockdown ────────────────────────────────────────────────────────
	// The store and the M2M token in it stay out of reach over HTTP: no
	// route reads or writes a document, and ?explain=full on a check route
	// gets the plain decision.
	{"lockdown.m2m_read_absent.404", "n/a", "GET /v1/data/m2m (internal port)", "-", "-", "none"},
	{"lockdown.store_write_absent.404", "n/a", "PUT /v1/data/lockdown-probe (internal port)", "-", "-", "none"},
	{"lockdown.check_explain_ignored.200", "admin", "POST /access/v1/check/resource (plain and with ?explain=full)", "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── tenant_realm ────────────────────────────────────────────────────
	// A tenant realm is named by an identifier; the agent learns it from the
	// tenant-manager emulator, which knows default and not unregistered.
	{"tenant_realm.resolved_realm_token_accepted", "admin (tenant default)", epCheckResource, "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"tenant_realm.unregistered_realm_token.401", "admin (tenant unregistered)", epCheckResource, "ORDER", "READ", "ROLE_ADMINISTRATOR"},

	// ── route_security ───────────────────────────────────────────────────
	{"route_security.authorize_hidden.404", "admin", "POST /authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.access_authorize_absent.404", "admin", "POST /access/v1/authorize", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.unknown_path.404", "n/a", "GET /unknown/endpoint", "-", "-", "none"},
	{"route_security.v2_check_resource.implemented", "admin", "POST /access/v2/check/resource", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v1_bulk_operations.implemented", "admin", "POST /access/v1/check/resource/bulk/operations", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v2_bulk_operations.implemented", "admin", "POST /access/v2/check/resource/bulk/operations", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.v2_check_filter.implemented", "admin", "POST /access/v2/check/filter", "ORDER", "READ", "ROLE_ADMINISTRATOR"},
	{"route_security.api_version.static", "n/a", "GET /api-version", "-", "-", "none"},
}

// CatalogByName provides O(1) lookup by step name.
var CatalogByName map[string]StepEntry

func init() {
	CatalogByName = make(map[string]StepEntry, len(Catalog))
	seen := make(map[string]bool, len(Catalog))
	for _, e := range Catalog {
		if seen[e.Name] {
			panic("duplicate step name in catalog: " + e.Name)
		}
		seen[e.Name] = true
		CatalogByName[e.Name] = e
	}
}
