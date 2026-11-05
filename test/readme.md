# Recommended Test Cases

## Purpose

This file defines the recommended regression test set for `authz-agent`.
It is aligned with the repository architecture and compatibility contract:

1. The agent serves the access-control check API, and every check route is answered with the decision of the
   `authorize` document.
2. Authorization semantics are two-stage: OLS first, RLS second when `ignoreRls=false`.
3. The check routes take bearer tokens in the `Authorization` and `Incoming-Token` headers, which OPA verifies.

## Priority Levels

- `P0`: required for every compatibility-affecting change and CI gate.
- `P1`: required when changing endpoint mappings, policy normalization, or auth handling.
- `P2`: scheduled regression or scale coverage.

## Runtime Integration Test Steps

This table is the committed source-of-truth for all Testify runtime integration steps.
Every step name below must exist in the Go catalog (`test/integration/testify/catalog.go`)
and every catalog entry must appear in this table. Validation tests enforce bidirectional parity.

| Step Name | Username | Endpoint | Resource | Operation | Token Roles |
| ----------- | ---------- | ---------- | ---------- | ----------- | ------------- |
| `setup.wait_for_keycloak` | n/a | `GET (Keycloak OIDC discovery)` | - | - | none |
| `setup.token_acquire_expired` | order-reader, admin | `POST (Keycloak /token)` | - | - | ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR |
| `setup.token_expiry_wait` | n/a | `-` | - | - | none |
| `setup.token_acquire_valid` | order-reader, admin | `POST (Keycloak /token)` | - | - | ROLE_ORDER_MANAGEMENT_RO_USER, ROLE_ADMINISTRATOR |
| `setup.wait_for_authz_policy_admin` | n/a | `GET /authz-policy-admin/hash` | - | - | none |
| `setup.policy_upload` | n/a | `PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}` | - | - | none |
| `setup.pip_upload` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | - | - | none |
| `setup.wait_for_agent` | admin | `POST /access/v1/check/resource` | - | - | ROLE_ADMINISTRATOR |
| `check_resource.order_read.rls_deny` | order-reader | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource.incoming_token_used_for_subject` | order-reader | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource.expired_authorization.401` | order-reader | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ORDER_MANAGEMENT_RO_USER (expired) |
| `check_resource.no_token.401` | n/a | `POST /access/v1/check/resource` | ATTACHMENT | READ | none |
| `check_resource.unknown_tenant_id.deny` | order-reader | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource.tenant_id_absent` | order-reader | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource.null_body.400` | admin | `POST /access/v1/check/resource` | - | - | ROLE_ADMINISTRATOR |
| `check_resource.boolean_response` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `check_resource.missing_fields.400` | admin | `POST /access/v1/check/resource` | - | - | ROLE_ADMINISTRATOR |
| `check_resource.wrong_address.404` | admin | `POST /access/v1/check/resourc` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `check_resource.incoming_token_precedence_over_authorization` | admin+order-reader | `POST /access/v1/check/resource` | BULK_OPEN | READ | ROLE_ADMINISTRATOR (Authorization) / ROLE_ORDER_MANAGEMENT_RO_USER (Incoming-Token) |
| `check_resource.anonymous_subject_marker` | admin | `POST /access/v1/check/resource` | BULK_OPEN | READ | ROLE_ADMINISTRATOR (M2M) / anonymous (subject) |
| `check_resource.incoming_token_stripped_from_header_pip` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `check_resource.invalid_authorization.401` | n/a | `POST /access/v1/check/resource` | ATTACHMENT | READ | none (invalid) |
| `check_resource.authorization_without_bearer.401` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `check_resource.incoming_token_without_bearer.deny` | admin | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_resource.pip_value_substituted` | admin | `POST /access/v1/check/resource` | CUSTOMER | READ | ROLE_ADMINISTRATOR |
| `check_resource_bulk.owner_mismatch.denied` | order-reader | `POST /access/v1/check/resource/bulk` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource_bulk.unknown_type.denied` | admin | `POST /access/v1/check/resource/bulk` | INVOICE | READ | ROLE_ADMINISTRATOR |
| `check_resource_bulk.empty_array` | admin | `POST /access/v1/check/resource/bulk` | - | - | ROLE_ADMINISTRATOR |
| `check_resource_bulk.null_body.400` | admin | `POST /access/v1/check/resource/bulk` | - | - | ROLE_ADMINISTRATOR |
| `check_resource_bulk.response_is_array` | admin | `POST /access/v1/check/resource/bulk` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_resource_bulk.large_3000` | admin | `POST /access/v1/check/resource/bulk` | BULK_OPEN | READ | ROLE_ADMINISTRATOR |
| `check_resource_bulk.no_token.401` | n/a | `POST /access/v1/check/resource/bulk` | ORDER | READ | none |
| `check_resource_bulk.no_id_empty` | admin | `POST /access/v1/check/resource/bulk` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_resource_bulk.missing_type_op.400` | admin | `POST /access/v1/check/resource/bulk` | - | - | ROLE_ADMINISTRATOR |
| `check_resource_bulk.duplicate_ids.400` | admin | `POST /access/v1/check/resource/bulk` | ORDER | READ,DELETE | ROLE_ADMINISTRATOR |
| `check_resource_bulk.unknown_tenant_id.denied` | order-reader | `POST /access/v1/check/resource/bulk` | ORDER | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_resource_bulk.wrong_address.404` | admin | `POST /access/v1/check/resource/bul` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_filter.calculation_result_present` | admin | `POST /access/v1/check/filter` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_filter.unknown_type.deny` | admin | `POST /access/v1/check/filter` | NONEXISTENT | READ | ROLE_ADMINISTRATOR |
| `check_filter.deny_all_fields` | admin | `POST /access/v1/check/filter` | NONEXISTENT | READ | ROLE_ADMINISTRATOR |
| `check_filter.known_resource.not_null` | order-reader | `POST /access/v1/check/filter` | ATTACHMENT | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_filter.missing_operation` | order-reader | `POST /access/v1/check/filter` | ATTACHMENT | - | ROLE_ORDER_MANAGEMENT_RO_USER |
| `check_filter.unknown_tenant_id.deny` | admin | `POST /access/v1/check/filter` | NONEXISTENT | READ | ROLE_ADMINISTRATOR |
| `check_filter.no_token.401` | n/a | `POST /access/v1/check/filter` | ORDER | READ | none |
| `check_filter.missing_resource_type.400` | admin | `POST /access/v1/check/filter` | - | READ | ROLE_ADMINISTRATOR |
| `check_filter.wrong_address.404` | admin | `POST /access/v1/check/filte` | ORDER | READ | ROLE_ADMINISTRATOR |
| `check_filter.predicate_subject_attr_substituted` | admin | `POST /access/v1/check/filter` | PUBLIC_DOC | READ | ROLE_ADMINISTRATOR |
| `pip_general.stub_reset` | n/a | `POST (pip-stub reset)` | - | - | none |
| `pip_general.upload_pips_for_general` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | CUSTOMER | READ | none |
| `pip_general.active_pip_called` | admin | `POST /access/v1/check/filter` | CUSTOMER | READ | ROLE_ADMINISTRATOR |
| `pip_general.stub_verify_active_called` | n/a | `GET (pip-stub /calls)` | CUSTOMER | READ | none |
| `pip_general.stub_reset_after` | n/a | `POST (pip-stub reset)` | - | - | none |
| `pip_general.inactive_pip_not_called` | admin | `POST /access/v1/check/filter` | DOCUMENT | READ | ROLE_ADMINISTRATOR |
| `pip_general.stub_verify_inactive_not_called` | n/a | `GET (pip-stub /calls)` | DOCUMENT | READ | none |
| `pip_general.bulk_reset_calls` | n/a | `POST (pip-stub reset)` | - | - | none |
| `pip_general.bulk_pin_allowed_subset` | n/a | `PUT (pip-stub configure)` | - | - | none |
| `pip_general.bulk_pip_filters_resources` | admin | `POST /access/v1/check/resource/bulk` | CUSTOMER | READ | ROLE_ADMINISTRATOR |
| `pip_general.bulk_stub_verify_called` | n/a | `GET (pip-stub /calls)` | CUSTOMER | READ | none |
| `pip_general.restore_default_stub` | n/a | `PUT (pip-stub configure)` | - | - | none |
| `pip_jsonpath.stub_reset` | n/a | `POST (pip-stub reset)` | - | - | none |
| `pip_jsonpath.upload_json_pip` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | CUSTOMER | READ | none |
| `pip_jsonpath.pin_json_response` | n/a | `PUT (pip-stub configure)` | - | - | none |
| `pip_jsonpath.bulk_extracts_ids_and_filters` | admin | `POST /access/v1/check/resource/bulk` | CUSTOMER | READ | ROLE_ADMINISTRATOR |
| `pip_jsonpath.restore_legacy_pip` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | CUSTOMER | READ | none |
| `pip_jsonpath.restore_default_stub` | n/a | `PUT (pip-stub configure)` | - | - | none |
| `check_filter.multi_frag.rsql_or_aggregation` | admin | `POST /access/v1/check/filter` | MULTI_FRAG_ITEM | READ | ROLE_ADMINISTRATOR |
| `token_pip_filter.upload_token_pips` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | TOKEN_PIP_POSITIVE,TOKEN_PIP_DEFAULT | READ | none |
| `token_pip_filter.positive_alias_in_filter` | admin | `POST /access/v1/check/filter` | TOKEN_PIP_POSITIVE | READ | ROLE_ADMINISTRATOR |
| `token_pip_filter.default_value_fallback` | admin | `POST /access/v1/check/filter` | TOKEN_PIP_DEFAULT | READ | ROLE_ADMINISTRATOR |
| `pip_deny.upload_broken_pip` | n/a | `PUT /access/v1/simplifiedPolicies/domainPIPs/{domain}` | PIP_FAIL_TEST | READ | none |
| `pip_deny.pip_failure_deny_reason` | admin | `POST /access/v1/check/resource` | PIP_FAIL_TEST | READ | ROLE_ADMINISTRATOR |
| `pip_deny.missing_attr_deny_reason` | admin | `POST /access/v1/check/resource` | ATTR_MISS_TEST | READ | ROLE_ADMINISTRATOR |
| `health.healthy_strict` | n/a | `GET /health` | - | - | none |
| `health.method_not_allowed` | n/a | `POST /health` | - | - | none |
| `health.regression.check_resource` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `decision_logs.download_no_token.200` | n/a | `GET /internal/v1/decision-logs` | - | - | none |
| `decision_logs.content_is_ndjson` | n/a | `GET /internal/v1/decision-logs` | - | - | none |
| `entitlements.contains.allow_hit` | admin | `POST /access/v1/check/resource` | ENT_CONTRACT | READ | ROLE_ADMINISTRATOR |
| `entitlements.contains.deny_miss` | admin | `POST /access/v1/check/resource` | ENT_CONTRACT | READ | ROLE_ADMINISTRATOR |
| `entitlements.is_empty.allow_when_empty` | admin | `POST /access/v1/check/resource` | ENT_EMPTY | READ | ROLE_ADMINISTRATOR |
| `entitlements.multi_as_union.allow` | admin | `POST /access/v1/check/resource` | ENT_MULTI | READ | ROLE_ADMINISTRATOR |
| `decision_logs.catalog_coverage` | n/a | `GET /internal/v1/decision-logs` | - | - | none |
| `decision_logs.legacy_path_header` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `wildcard_access.upload_wildcard_policies` | n/a | `PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}` | - | - | none |
| `wildcard_access.all_all.no_predicates` | admin | `POST /access/v1/check/filter` | ORDER | READ | ROLE_ADMINISTRATOR |
| `wildcard_access.all_all.no_deny_reason` | admin | `POST /access/v1/check/resource` | WC_EXACT_ONLY | READ | ROLE_ADMINISTRATOR |
| `wildcard_access.all_op.reader_delete_denied` | order-reader | `POST /access/v1/check/resource` | UNKNOWN_TYPE | DELETE | ROLE_ORDER_MANAGEMENT_RO_USER |
| `wildcard_access.rt_all.reader_any_op` | order-reader | `POST /access/v1/check/filter` | WC_RT_TARGET | DELETE | ROLE_ORDER_MANAGEMENT_RO_USER |
| `wildcard_access.rt_all.reader_other_rt_denied` | order-reader | `POST /access/v1/check/resource` | OTHER_TYPE | DELETE | ROLE_ORDER_MANAGEMENT_RO_USER |
| `wildcard_access.mixed.partial_wildcard` | order-reader | `POST /access/v1/check/resource/bulk` | WC_RT_TARGET,INVOICE | DELETE,READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `wildcard_access.legacy.check_resource_all_all` | admin | `POST /access/v1/check/resource` | UNKNOWN_TYPE | DELETE | ROLE_ADMINISTRATOR |
| `wildcard_access.legacy.check_resource_bulk_all_all` | admin | `POST /access/v1/check/resource/bulk` | UNKNOWN_TYPE | DELETE | ROLE_ADMINISTRATOR |
| `wildcard_access.legacy.check_filter_all_op` | order-reader | `POST /access/v1/check/filter` | UNKNOWN_TYPE | READ | ROLE_ORDER_MANAGEMENT_RO_USER |
| `wildcard_access.restore_original_policies` | n/a | `PUT /access/v1/simplifiedPolicies/domainPolicies/{domain}` | - | - | none |
| `m2m_keycloak.pull_succeeds_with_keycloak_token` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `m2m_keycloak.agent_functional_after_token_refresh` | admin | `POST /access/v1/check/resource` | ATTACHMENT | READ | ROLE_ADMINISTRATOR |
| `lockdown.m2m_read_absent.404` | n/a | `GET /v1/data/m2m (internal port)` | - | - | none |
| `lockdown.store_write_absent.404` | n/a | `PUT /v1/data/lockdown-probe (internal port)` | - | - | none |
| `lockdown.check_explain_ignored.200` | admin | `POST /access/v1/check/resource (plain and with ?explain=full)` | ORDER | READ | ROLE_ADMINISTRATOR |
| `tenant_realm.resolved_realm_token_accepted` | admin (tenant default) | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ADMINISTRATOR |
| `tenant_realm.unregistered_realm_token.401` | admin (tenant unregistered) | `POST /access/v1/check/resource` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.authorize_hidden.404` | admin | `POST /authorize` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.access_authorize_absent.404` | admin | `POST /access/v1/authorize` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.unknown_path.404` | n/a | `GET /unknown/endpoint` | - | - | none |
| `route_security.v2_check_resource.implemented` | admin | `POST /access/v2/check/resource` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.v1_bulk_operations.implemented` | admin | `POST /access/v1/check/resource/bulk/operations` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.v2_bulk_operations.implemented` | admin | `POST /access/v2/check/resource/bulk/operations` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.v2_check_filter.implemented` | admin | `POST /access/v2/check/filter` | ORDER | READ | ROLE_ADMINISTRATOR |
| `route_security.api_version.static` | n/a | `GET /api-version` | - | - | none |

## Recommended Suite Matrix

| Area | Priority | Recommended cases | Suggested location |
| --- | --- | --- | --- |
| Decision contract of the `authorize` document | `P0` | Request validation, `ignoreRls` omitted=`false` plus explicit `true` behavior, multi-resource order preservation, `ALLOW`/`DENY` mapping, `predicates[]` omission rules, auth failure mapping | `policies/authorize_contract_test.rego` |
| Policy language semantics | `P0` | Operator coverage, precedence, parentheses, JSONPath behavior, `has access`, normalized `conditionAst` evaluation, predicate passthrough | `policies/policy_language_contract_test.rego` |
| Token verification and subject normalization | `P0` | Valid token, expired token, wrong issuer, unknown `kid`, no roles, `realm_access.roles` only, non-realm claim ignored, service token, object-form `subject` rejection, anonymous compatibility mode | `policies/token_auth_contract_test.rego` |
| Legacy v1 endpoint mapping | `P0` | `/access/v1/check/resource`, `/access/v1/check/resource/bulk`, `/access/v1/check/filter` request mapping, response remapping, stable error shape, tenant pass-through ignored in decisioning | Rego contract tests plus runtime checks |
| Runtime auth compatibility | `P0` | Keycloak-issued token flow, OIDC discovery bootstrap, `Authorization` admission token and `Incoming-Token` subject token, admission `401` mapping, deterministic DENY reasons, policies pulled from the policy source | the kind harness under `test/k8s/` via `make e2e` |
| Public route wiring | `P1` | Per-route request and response translation, public non-exposure of `/authorize` and `/access/v1/authorize`, malformed body handling, query/header propagation | Runtime stack checks on kind (`test/k8s/`) |
| Simplified policy normalization | `P1` | OLS/RLS split, role-scoped RLS index, `conditionAst` usage, `condition=true` fallback, `predicate=true` fallback, explicit-role wildcard normalization for `ALL/ALL`, `ALL/<operation>`, and `<resourceType>/ALL`, unconditional-access short-circuit semantics for all wildcard buckets, unknown field preservation | New unit suite under `tests/unit/` |
| Deferred legacy v1 bulk operations and preview APIs | `Deferred` | Historical baseline only: `/access/v1/check/resource/bulk/operations` and `/preview/v1/check/resource/bulk/operations` are not implemented in the current repository snapshot and currently return `404`; no active implementation handover exists | Runtime `404` assertions only |
| Deferred legacy v2 APIs and `/api-version` | `Deferred` | Historical baseline only: `/access/v2/check/resource`, `/access/v2/check/resource/bulk/operations`, `/preview/v2/check/resource/bulk/operations`, `/access/v2/check/filter`, and `/api-version` are not implemented in the current repository snapshot and currently return `404`; no active implementation handover exists | Runtime `404` assertions only |
| Large-input and resilience checks | `P2` | Large bulk payloads, large simplified policy import, duplicate IDs, empty optional resource objects, startup failure when authn data is missing | Dedicated regression suite |

## Required Test Cases By Contract Area

### 1. Decision Contract of the `authorize` Document

- Single-resource `ALLOW` with omitted `ignoreRls` and `rlsIgnored=false`.
- Single-resource `ALLOW` with `ignoreRls=true`.
- Single-resource `ALLOW` with `ignoreRls=false` and returned `predicates[]`.
- OLS deny short-circuits RLS and returns `DENY`.
- OLS allow + RLS deny returns `DENY` when `ignoreRls=false`.
- OLS allow + RLS rule present returns RLS-aware result when `ignoreRls` is omitted.
- OLS allow + RLS rule present still returns OLS-only result when `ignoreRls=true`.
- Multi-resource response preserves request order.
- `rlsIgnored` reflects effective mode.
- `predicates` is omitted for `DENY`.
- `predicates` is omitted when `rlsIgnored=true`.
- Malformed payloads are rejected deterministically.

### 2. Legacy v1 Compatibility Endpoints

- `/access/v1/check/resource` maps to one resource of the decision input and returns JSON boolean.
- `/access/v1/check/resource/bulk` returns only allowed IDs and preserves input-to-output ID association.
- `/access/v1/check/filter` uses `calculationResult` and correct `filterCondition` behavior.
- `/access/v1/check/resource` returns `400` for null body and for missing required `type`/`operation` fields.
- `/access/v1/check/resource/bulk` returns `400` for null body and for entries without required `type`/`operation`.
- `/access/v1/check/filter` returns `400` when required query parameter `resourceType` is missing.
- Wrong-address variants of implemented compatibility endpoints return `404`.
- `tenant_id` is accepted but does not change the decision.
- `userId` compatibility path remains isolated and must be covered explicitly if a future handover activates it.
- Error responses keep the legacy-compatible `{ "message": "..." }` shape where required.

### 3. Deferred Legacy v1/v2 Bulk Operation APIs

- The historical baseline includes v1 bulk-operations/preview routes and v2 routes, but they are not implemented in the current repository snapshot.
- Current runtime behavior for these endpoints is `404`, and runtime route-security coverage asserts that absence explicitly.
- No active committed implementation handover currently exists for these deferred endpoints.

### 4. Authentication and Token Source

- The admission token is the `Authorization` header. The subject token is `Incoming-Token` when it is present, the
  `Authorization` token otherwise, and none when `Authorization-Type` is `anonymous`.
- Invalid `Authorization` token returns `401` with `message`.
- Valid `Authorization` + invalid subject token returns `200` with a denial, and the decision log records the `reason`.
- Missing token returns `401` unless anonymous mode is explicitly allowed.
- An object-form `subject` in the decision input is rejected.
- Authorization roles are derived only from `realm_access.roles`; non-realm claims like `groups`, `authorities`, direct `roles`, and `resource_access.*.roles` are ignored.

### 5. Policy Normalization and Simplified Policy Compatibility

- Policy with only `roles/resourceType/operation` normalizes to `condition=true` and `predicate=true`.
- Policy with predicate but no condition normalizes to `condition=true`.
- Policy with condition but no predicate still evaluates correctly through normalized RLS data.
- Multiple roles produce role-scoped RLS entries.
- Explicit-role wildcard policies `ALL/ALL`, `ALL/<operation>`, and `<resourceType>/ALL` remain supported through the dedicated wildcard access-role normalization path and produce unconditional access within their declared scope.
- Malformed simplified policy entries produce clear validation errors.
- Real sample fixtures (from the internal source repository) stay loadable.

### 6. Runtime and Deployment Wiring

- `make e2e-harness` and `make e2e-install` bring up Keycloak plus the agent from the Helm chart without
  pre-generated JWKS files.
- Runtime tests execute as a Job inside the cluster (Testify suite under `test/integration/testify/`).
- The agent pulls the policies and PIPs the suite uploads to the `authz-policy-admin` stub.
- OIDC discovery bootstrap populates runtime authn data before compatibility checks run.
- The public surface answers every supported check route with the decision of the `authorize` document.
- `/access/v1/check/resource/bulk` handles large payloads such as 3000 allowed IDs without restrictive RLS predicates.

## Minimum CI Gate

The minimum CI gate for compatibility-sensitive changes should run:

1. `test/scripts/test-opa.sh`
2. `test/scripts/test-chart-render.sh`
3. `make e2e` (the Testify suite on kind)
4. `make parity` (the parity replay on kind)

For running the runtime suite locally on a clean machine — prerequisites, the
images the stack needs, ports, target platform, and troubleshooting — see
[docs/local-integration-tests.md](../docs/local-integration-tests.md).

If deferred legacy endpoints are explicitly brought back into active scope in a future handover, the runtime gate should be expanded together with that implementation to cover:

1. `GET /api-version`
2. V1 bulk-operations and preview endpoints
3. V2 resource, bulk-operations, preview, and filter endpoints

## Current Gap Summary

The repository already has a solid baseline for:

- the decision contract of the `authorize` document;
- policy language coverage;
- token verification and subject normalization;
- runtime auth precedence checks for `/access/v1/check/resource`.

The main recommended additions are:

- dedicated simplified-policy normalization tests outside the current Rego contract suites;
- continued hardening of the already implemented surface as behavior evolves;
- deferred legacy endpoints only if a future handover explicitly brings them back into active implementation scope.
