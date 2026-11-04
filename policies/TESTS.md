# OPA Test Suites

## Purpose

This directory contains contract-focused tests for the Rego policies the agent embeds: the checks of the caller and
the subject's token.

## Suite Inventory

1. `admission_test.rego`
   - Validates `authorize_internals.admission`, the caller and subject checks the service runs before a decision:
     `authError` for a refused admission token, `subjectError` for a refused subject token, and `tokenPayload`
     otherwise.
2. `token_auth_contract_test.rego`
   - Validates authentication and subject normalization behavior for bearer-token inputs.
   - Covers:
     - valid token;
     - service token;
     - expired token;
     - wrong issuer;
     - unknown `kid`;
     - no roles;
     - object-form `subject` rejection;
     - anonymous compatibility mode;
     - `realm_access.roles`-only role derivation;
     - non-realm claims (`groups`, `authorities`, direct `roles`, `resource_access.*.roles`) ignored.
3. `token_taxonomy_test.rego`
   - Validates the admission outcome for each token failure class.
4. `make e2e`
   - Installs Keycloak plus `authz-agent` from the Helm chart on a kind cluster.
   - Executes the Testify integration suite as a Job inside the cluster.
   - Uploads simplified runtime policies to the authz-policy-admin during suite setup; the agent pulls them from there.
   - Covers the legacy check endpoints the agent implements.

The decisions of check/resource and check/filter come from the generated policies of package `internal/regogen`,
whose tests live in Go next to it.

## Subject Contract

All canonical authorize contract paths, including Rego policy suites, must provide `subject` as bearer token string.
Predecoded object-form `subject` is not part of the contract and must not be used as a test-only bypass.

## Token Auth Matrix

`token_auth_contract_test.rego` is expected to cover the following identity combinations:

| Area | Required combinations |
| --- | --- |
| Token validity | valid, expired, wrong issuer, unknown `kid` |
| Subject type | user token, service token, anonymous compatibility flow, `verifiedTokens` cache-hit fast path |
| Role cardinality | zero roles, single role |
| Role claim sources | `realm_access.roles` only; non-realm claims (`groups`, `authorities`, direct `roles`, `resource_access.*.roles`) verified as ignored |
| Rejection paths | object-form `subject` rejected even with internal flags |

## Runtime Coverage Matrix

`make e2e` plus the Testify suite are expected to keep the following runtime combinations covered:

| Area | Required combinations |
| --- | --- |
| Legacy check/resource | `Incoming-Token` precedence, `401` mapping, tenant invariance, null body => `400`, missing required fields => `400`, wrong address => `404` |
| Legacy check/resource/bulk | denied IDs, empty array, malformed entries, null body => `400`, missing required fields => `400`, tenant invariance, large payload of 3000 allowed IDs with non-restrictive RLS, wrong address => `404` |
| Legacy check/filter | `calculationResult`, deny/allow paths, tenant invariance, missing `resourceType` => `400`, wrong address => `404` |
| Public boundary | `/authorize` not exposed; not-yet-implemented legacy routes return `404` |
| Runner behavior | Suite runs as a Job inside the cluster, step-level PASS/FAIL reporting, catalog-validated coverage |

## Notes

1. `test/scripts/test-opa.sh` uses `policies/`; the runtime stack on kind loads the same policies through the chart's
   policy ConfigMap (`make copy-policies`) plus runtime-generated authn data.

## Token Toolkit for Tests

Use repository scripts to generate valid signed tokens for Rego/policy fixtures:

1. Generate provider key/JWKS material:

```bash
test/scripts/token-testkit/generate-rsa-jwks.sh
```

1. Generate a standard token fixture set:

```bash
test/scripts/token-testkit/generate-token-fixture-set.sh
```

1. Generate one-off token:

```bash
test/scripts/token-testkit/mint-jwt.sh --help
```

Default generation path is `/tmp/authz-token-testkit`.

To refresh the committed Rego fixtures used by the suites above:

```bash
test/scripts/token-testkit/refresh-rego-fixtures.sh
```

Runtime/integration auth checks intentionally do not use these repository fixture outputs; they request real tokens from the harness Keycloak during `make e2e`.
