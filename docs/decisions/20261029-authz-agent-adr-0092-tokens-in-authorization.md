# Accept any verified token in Authorization and limit a caller that is not M2M to its tenant

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, with the 503 for keys that cannot be loaded. On 2026-11-23
  the architect and the owner of the policy decision code agreed to drop the M2M modes of `M2M_AUTH_MODE` (R11, R15).
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes its statements on the decision log (R18, R19, R20): the agent emits it in process, with the
  event shape of the collector and the JWT signature redaction, and serves it through `GET /internal/v1/decision-logs`.
- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  verifies the tokens that this record accepts, and ADR-0091 R54, the result of the M2M test that R10 reads.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R1, the tenant that a caller that is not M2M is compared with, and ADR-0093 R22, the 503 that takes the
  place of the 403 of R4 before the default tenant is translated.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the checks of a Kubernetes token.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  ADR-0095 R2, the 503 for keys that cannot be loaded.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  ADR-0104 R22, which defines the identity-provider token and the Kubernetes token that R6, R7, R11, and R21 name.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  ADR-0105 R2, under which the chart writes the provider `kubernetes` in every installation.

## Context

A check route receives the caller's token in `Authorization` and, optionally, the user's token in `Incoming-Token`.

Services of an installation call each other with identity-provider tokens, and in some installations with Kubernetes
service account tokens. The platform's deployer passes `M2M_AUTH_MODE`, with the value `legacy`, `hybrid`, or `k8s`, to
every service of an installation, and the services that read it decide by it which kinds of token they accept.

Some callers send a user token in `Authorization`, and some services authenticate with client credentials and carry
neither the role `ROLE_M2M` nor a `level`. The parity goldens of #42 cover both: `caller-user-token`, `ts69-service`,
and `ts69-bare-service`.

## Decision

We will accept on the check routes any verified token in `Authorization`, of every kind and in every installation, and
limit a token that is not M2M to its own tenant.

### Terms

- **Check route**: `check/resource`, `check/resource/bulk/operations`, and `check/filter` under `/access/v1` and
  `/access/v2`, `check/resource/bulk` under `/access/v1`, and `check/resource/bulk/operations` under `/preview/v1` and
  `/preview/v2`.
- **M2M token**: a token that R6, R7, or R21 makes one.
- **Identity-provider token**, **Kubernetes token**: as ADR-0104 defines them.

### Rules

#### Requests

- **R1** (`handler`). `Authorization` is required on the check routes. A missing header gets 401 with `TOKEN_MISSING`,
  and a header that is not `Bearer` gets 401 with `TOKEN_SCHEME_INVALID`, both before policy evaluation.
- **R2** (`handler`). A token in `Authorization` that fails verification gets 401 before policy evaluation. The
  exception is `TOKEN_KEYS_UNAVAILABLE` of ADR-0091 R23, which gets the 503 of ADR-0095 R2.
- **R3** (`handler`). An M2M token in `Authorization` may name any tenant.
- **R4** (`handler`). A token in `Authorization` that is not M2M may reach only the tenant of its own non-empty
  `tenant-id` claim, or the default tenant when it has no such claim. Any other tenant gets 403 with
  `CALLER_TENANT_MISMATCH` before policy evaluation. The exception is a caller that ADR-0093 R22 refuses with 503
  before the agent translates the name of the default tenant.
- **R5** (`handler`). The comparison of R4 uses the tenant of the decision of ADR-0093 R1, so that an `Incoming-Token`
  cannot move the caller out of its tenant.

#### M2M tokens

- **R6** (`verify`). An identity-provider token is an M2M token when `realm_access.roles` holds `ROLE_M2M`, compared
  byte for byte.
- **R21** (`verify`). An identity-provider token is an M2M token when `level` is `m2m` or `key-manager`, compared
  without regard to case.
- **R7** (`verify`). A Kubernetes token is an M2M token.
- **R10** (`handler`, `policy`). Every reader of the M2M test, `subject.isM2M` among them, reads the result that the
  token verification returns under ADR-0091 R54.

#### Kinds of token

- **R11** (`handler`). A token in `Authorization` that passes verification is accepted whatever its kind: an
  identity-provider token or a Kubernetes token. R4 limits the tenants that a token that is not M2M may reach.
- **R15** (`startup`). The agent does not read `M2M_AUTH_MODE`. The tokens that the agent accepts, and whether it
  starts, are the same whether `M2M_AUTH_MODE` is unset or holds any value, with or without the chart.

#### Other routes

- **R17** (`handler`). No route requires an M2M token.
- **R18** (`handler`). The agent drops its decision log and with it `/internal/v1/decision-logs`, its one service route.
  [Issue #223](https://github.com/Netcracker/qubership-authz-agent/issues/223) tracks how decisions are read.
- **R19** (`handler`). A client of `/internal/v1/decision-logs` gets the 404 of any unknown path.
- **R20** (`chart`). `AUTHZ_DECISION_LOG_PATH`, `AUTHZ_DECISION_LOG_SIZE_LIMIT`, `AUTHZ_DECISION_LOG_FILE`,
  `AUTHZ_DECISION_LOG_URL`, `AUTHZ_DECISION_LOG_HEADERS`, and the emptyDir of the chart go away with the decision log.

### Justification

A check route needs a verified caller, not a caller of a particular kind (R11). The M2M test decides what a caller may
reach instead of whether it may call (R3, R4), so a service whose Keycloak client issues neither `ROLE_M2M` nor a
`level` keeps working and stays inside its own tenant. Reading the one result that the verification returns keeps the
check of a caller and the policies from disagreeing about one token (R10).

The project architect and the owner of the policy decision code dropped the M2M modes on 2026-11-23. The agent accepts
the same kinds of token in every installation, so a service moves from an identity-provider token to a Kubernetes token
with no change of the agent, and no setting of the agent has to agree with the mode of the other services (R11, R15).
The platform's deployer passes `M2M_AUTH_MODE` to every service, so the agent leaves it unread, and a value set for the
other services cannot stop the start of the agent (R15).

The goldens `caller-user-token`, `ts69-service`, and `ts69-bare-service` keep their answers. The goldens of #42 tell the
broad M2M test from `level` alone, and `ts72-service` and `ts72-role-m2m` tell `ROLE_M2M` from a service account.

### Alternatives considered

- **A1. Accept only M2M tokens in `Authorization`.** Rejected by R17: 28 goldens would change their answer, and a
  service without `ROLE_M2M` or `level` would stop working with no way to see that in the goldens.
- **A3. Compare the caller with the tenant the request names.** Rejected by R5: an `Incoming-Token` of another tenant
  would move the decision out of the caller's tenant, and a mismatch would get the refusal that ADR-0093 R9 does not
  make.
- **A4. Keep the M2M modes of `M2M_AUTH_MODE`: `legacy` accepts identity-provider tokens in `Authorization`, `hybrid`
  adds Kubernetes tokens, and `k8s` accepts only Kubernetes tokens and refuses the others with
  `TOKEN_KIND_NOT_ALLOWED`.** Rejected by R11 and R15: the architect and the owner of the policy decision code dropped
  the modes, and the tokens that the agent accepts would depend on a setting that the other services also read. This
  reverses the earlier R11 to R15 of this record, its A2, which kept identity-provider tokens out of `k8s`, and the
  answers of the owner of the policy decision code on an unknown mode and on the mode outside Kubernetes.

## Consequences

Negative:

- A client-credentials token without `ROLE_M2M` and without `level` is treated as a user token, so it reaches only its
  own or the default tenant.
- No setting refuses identity-provider tokens in `Authorization`, so the refusals of the agent no longer show which
  services still call with one, as `k8s` did (R11).
- Every installation that the chart deploys accepts Kubernetes tokens from the namespaces of the installation in
  `Authorization`, where `legacy`, the default mode, refused them (R11; ADR-0094 R17; ADR-0105 R2).
- Outside Kubernetes no API server serves the keys of a provider `kubernetes`, so a provider `kubernetes` there would
  keep the agent not ready (ADR-0104 R25; ADR-0091 R14), and the provider files hold none. No token is then a Kubernetes
  token, and a token that an API server signed is refused under ADR-0104 R21, unless a provider `identity-provider`
  names its issuer, which makes it an identity-provider token (ADR-0104 R22).
- The decisions of a request cannot be downloaded from the agent. Issue #223 tracks how they are read.
- Comparing with the tenant of the decision changes the answer of two requests that no golden covers:
  - A caller that is not M2M and has no `tenant-id`, such as a client-credentials token without `ROLE_M2M`, forwards the
    `Incoming-Token` of a user of tenant T. Without that header it is the golden `no-claim-names-no-tenant`, 200 in the
    default tenant. Here the tenant of the decision is T, so after the translation of the default tenant (ADR-0093 R22)
    the caller gets 403 `CALLER_TENANT_MISMATCH`.
  - A user of tenant A sends a token in `Authorization`, `tenant_id=B`, and an `Incoming-Token` with `tenant-id` A.
    Without that header it is the golden `claim-a-names-tenant-b`, 403. Here the decision is computed in A, with 200.

Follow-ups:

- When this record is accepted, the status of ADR-0080 names the statements it supersedes.
