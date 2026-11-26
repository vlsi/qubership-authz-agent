# Configure the two providers through the chart values

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records, agreed on 2026-11-19 and 2026-11-23. On 2026-11-23 the architect and the owner of the policy decision code
  also agreed to drop the M2M modes, so the chart writes both providers in every installation.
- The owner of the policy decision code (`vlsi`) reviews this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the Pod that stays not ready while keys do not arrive (ADR-0091 R19), and `IDENTITY_PROVIDER_URL`, which the agent
  does not read (ADR-0091 R78). This request deletes ADR-0091 R72 (now R3 of this record) and ADR-0091 R13 (now R13 of
  this record). It adds `AUTHZ_TRUSTED_PROVIDERS`, the list that A2 rejects, and `AUTHZ_JWKS_HTTP_TIMEOUT` to the
  settings that go away under ADR-0091 R64.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  the tokens of both kinds that `Authorization` accepts (ADR-0092 R11), and the M2M modes, which are dropped (ADR-0092
  R15). This request makes ADR-0092 cite R2 of this record where it cited ADR-0094 R30.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the terms Token for the API server and In-cluster address, the access to the keys of the API server (ADR-0094
  Context), the token for the API server, which never goes to a PIP (ADR-0094 R28), and the Pod without the default
  token of its service account (ADR-0094 R31). This request deletes ADR-0094 R30 (now R2 of this record) and the token
  part of ADR-0094 R2 (now R6 of this record), and makes ADR-0094 cite R2 of this record where it cited R30, and R6 of
  this record where it cited R2.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the provider files that the chart writes and their format (ADR-0104 R6), the providers and the two kinds of token
  (ADR-0104 R22), the source of a token and the tokens whose `iss` matches no provider (ADR-0104 R19, R21), the reading
  of the provider files only at start (ADR-0104 R5), the agent without a realm of its own (ADR-0104 R13), the required
  sources (ADR-0104 R25), the check of `aud` (ADR-0104 R26), the addresses that the token for the API server may go to
  (ADR-0104 R24, R28), and the warning on the issuer of the provider `kubernetes` (ADR-0104 R29). This request makes
  ADR-0104 cite R13 of this record where it cited ADR-0091 R13.

## Context

The values of the chart in `helm-templates/authz-agent` are what an operator of an installation sets. They carry
`IDENTITY_PROVIDER_URL`, the address of the platform's Keycloak without a realm, `http://identity-provider:8080` by
default, which serves each realm under the path `/auth/realms/` of that address. kubeadm gives the API server the issuer
`https://kubernetes.default.svc.cluster.local` unless the cluster configuration sets another one, and the API server
serves its keys only when its issuer is an https URL (`pkg/serviceaccount/openidmetadata.go` and `pkg/controlplane` of
Kubernetes).

## Decision

We will have the chart write both providers of ADR-0104 in every installation, and derive the provider
`identity-provider` from `IDENTITY_PROVIDER_URL` and the provider `kubernetes` from defaults, so that an operator sets
in the values only the part that differs in an installation, without repeating the rest of the provider.

### Terms

- **Provider file**, **provider `identity-provider`**, **provider `kubernetes`**, **identity-provider token**,
  **Kubernetes token**: as ADR-0104 defines them.
- **Token for the API server**, **in-cluster address**: as ADR-0094 defines them.
- **Values**: the values of the chart in `helm-templates/authz-agent`: its `values.yaml` and what an installation sets
  over it.

### Rules

- **R2** (`chart`). The chart writes the provider `identity-provider` and the provider `kubernetes` in every
  installation. The values change a provider only as R3, R5, R6, and R16 allow, and no value leaves either provider out
  or adds another one.
- **R3** (`chart`). A Keycloak that serves each realm under the path `/auth/realms/` of `IDENTITY_PROVIDER_URL`, and
  names that address in the `iss` of its tokens, needs no value for the provider `identity-provider` but
  `IDENTITY_PROVIDER_URL`: the chart derives the issuers of its realms and the address of their keys from that address.
  The values can override the issuers, the address of the keys, or both, and the chart derives the one that the values
  leave out. The provider trusts every realm of its Keycloak, and no value limits it to one realm.
- **R5** (`chart`). By default the provider `kubernetes` trusts the issuer
  `https://kubernetes.default.svc.cluster.local` and loads its keys from the API server at an in-cluster address. The
  values can override the issuer, the address of the keys, or both, and the one that the values leave out keeps its
  default.
- **R6** (`chart`). By default the chart gives the agent's Pod a token for the API server. The values can turn that
  token off, and the Pod then holds no token for the API server.
- **R13** (`chart`). An upgrade that changes a provider file restarts the agent's Pods, so a changed value takes effect
  without a manual restart.
- **R15** (`chart`). The chart writes the same check of `aud` in every installation, and no value changes it: the agent
  ignores the `aud` of an identity-provider token, and accepts a Kubernetes token only when its `aud` holds `netcracker`
  (ADR-0104 R26).
- **R16** (`chart`). By default the list of realms whose keys a Pod waits for before it becomes ready holds only
  `cloud-common`. The values can replace that list.

### Justification

`Authorization` accepts a verified token of either kind (ADR-0092 R11), and a token that the API server signs is a
Kubernetes token only where the provider files hold the provider `kubernetes` (ADR-0104 R22). The architect and the
owner of the policy decision code chose to accept Kubernetes tokens wherever the chart deploys the agent, so no value
leaves that provider out (R2).

An operator changes one part of a provider, and repeating the parts that stay would copy defaults into every
installation that changes anything. So each value overrides one part, and the chart keeps the rest (R3, R5). Deriving
the provider `identity-provider` from `IDENTITY_PROVIDER_URL` means that an installation whose Keycloak meets the
condition of R3 sets no value for the provider `identity-provider` but `IDENTITY_PROVIDER_URL`. A Keycloak whose tokens
name a public address in `iss` needs only the issuers, and its keys still load from the derived address. The platform's
Keycloak holds one realm per tenant, so the provider trusts every realm of it (R3).

The issuer of the API server differs between clusters. The default of R5 is the issuer that kubeadm gives (Context). An
API server whose issuer is an https URL serves its keys at an in-cluster address to any service account with a token for
the API server (ADR-0094 Context), so a managed cluster with another https issuer overrides only the issuer (R5).

A standard cluster refuses an anonymous request for its keys (ADR-0094 Context), and the agent's Pod holds no default
token of its service account (ADR-0094 R31), so by default the Pod holds a token for the API server. Turning it off is
for a cluster that serves its keys to an anonymous request: there no request needs the token, so the Pod does not hold
it (R6).

The platform's Keycloak has no audience mapper that names the services of an installation, so no `aud` of its tokens
marks a token for those services. Those services request their Kubernetes tokens with the audience `netcracker`
(ADR-0094 Context). Without the check of `aud` for Kubernetes tokens, the agent would also accept a token that the API
server issued for another audience, such as the default token of a Pod (R15).

The agent reads the provider files only at start (ADR-0104 R5), so a changed value takes effect only in a new container.
Without a restart, an upgrade that changes a value would succeed while every Pod keeps the providers it started with
(R13).

The default is `cloud-common`, the platform's realm for M2M clients, so that a Pod becomes ready only once it can verify
the tokens of those clients. The agent holds no realm name of its own (ADR-0104 R13), so the chart supplies this default
(R16).

### Alternatives considered

- **A2. Let the values hold a whole list of providers, as `AUTHZ_TRUSTED_PROVIDERS` does, that replaces the providers
  the chart writes.** Rejected by R2: an operator who changes one address would repeat every other part of both
  providers, and a mistake in the copy shows only when the agent starts (ADR-0104 R6).
- **A3. Let the values set the check of `aud`.** Rejected by R15: each provider has one check of `aud` that works in
  this stage. A later stage that checks the `aud` of identity-provider tokens adds the value.
- **A4. Let the values limit the provider `identity-provider` to one realm.** Rejected by R3: the platform's Keycloak
  holds one realm per tenant, and such a provider would refuse the tokens of every other tenant.
- **A10. Give the Pod a token for the API server whatever the cluster allows.** Rejected by R6: on a cluster that serves
  its keys to an anonymous request, the Pod would hold a credential for the API server that no request needs. This
  reverses the token part of ADR-0094 R2, which mounted the token in every installation.
- **A11. Wait by default for the realms `cloud-common`, `default`, `cpq`, and `external`, the realms of
  `AUTHZ_IDP_REALMS`.** Rejected by R16: `default` is the display name of a tenant, not the name of a realm, most
  installations hold neither `cpq` nor `external`, and a name that the Keycloak does not hold keeps the Pod not ready.
- **A12. Let a value leave the provider `kubernetes` out.** Rejected by R2: an installation that set it would refuse
  every token that the API server signs (ADR-0104 R21), where the architect and the owner of the policy decision
  code chose to accept Kubernetes tokens wherever the chart deploys the agent. A cluster whose issuer is not an https
  URL, where such a value would let a Pod become ready, is a cost this record accepts (Negative).
- **A13. Write the provider `kubernetes` only in the M2M modes `hybrid` and `k8s`.** Rejected by R2: `M2M_AUTH_MODE`
  changes none of the tokens that the agent accepts (ADR-0092 R15), and without the provider the agent would refuse
  every token that the API server signs (ADR-0104 R21). This reverses the earlier answer that tied the provider to
  those modes.
- **A16. Offer no value for the issuer of the API server, and always trust the issuer that kubeadm gives.** Rejected by
  R5: a managed cluster often has another issuer, and every token that its API server signs would get
  `TOKEN_ISSUER_UNKNOWN` (ADR-0104 R19, R21).
- **A17. Leave the restart of the Pods after an upgrade to the operator.** Rejected by R13: the agent reads the provider
  files only at start (ADR-0104 R5), so an upgrade that changes a value would have no effect until someone restarts
  every Pod, and nothing would show that it has none.

## Consequences

Positive:

- An installation whose Keycloak meets the condition of R3, and whose API server has the issuer that kubeadm gives, sets
  no value of a provider but `IDENTITY_PROVIDER_URL` (R3, R5).
- A Keycloak at another host with the same paths, whose tokens name that host in `iss`, needs only a new
  `IDENTITY_PROVIDER_URL` (R3).

Negative:

- A Keycloak whose addresses differ from the ones that the chart derives, such as a Keycloak without `/auth` in its
  paths, needs both the issuers and the address of the keys in the values (R3).
- Through the chart an installation cannot trust one realm of its Keycloak alone or check the `aud` of identity-provider
  tokens. Each needs a change of the chart, or a deployment without the chart whose provider files are written by hand
  (R3, R15).
- On a cluster whose API server has an https issuer other than the default of R5, as a managed cluster often has, every
  token that the API server signs gets `TOKEN_ISSUER_UNKNOWN` in a ready Pod, until the values override the issuer (R5;
  ADR-0104 R19, R21). With the token for the API server, ADR-0104 R29 logs a warning at the start.
- Every Pod that the chart deploys waits for the keys of the provider `kubernetes` before it becomes ready (R2; ADR-0104
  R25). With the default address of R5, its readiness depends on the API server and on the agent's trust in the CA that
  signs the certificate of the API server (ADR-0094 Context). On a cluster whose API server has an issuer that is not an
  https URL, the API server serves no keys, so with the default address of R5 no Pod becomes ready, and the values
  cannot leave the provider `kubernetes` out (Context; R2; ADR-0091 R19).
- By default every Pod that the chart deploys holds a token for the API server, with the access of the agent's service
  account to the API server (R6). ADR-0104 R24 and R28 and ADR-0094 R28 limit where that token goes.
- An address of the keys of the API server that is not an in-cluster address stops the start while the Pod holds a token
  for the API server (ADR-0104 R28). Such an address works only with the token off, where its server serves the keys to
  an anonymous request (R5, R6).
- With the token off, a Pod stays not ready on a cluster that refuses an anonymous request for its keys, as a standard
  cluster does (R6; ADR-0091 R19).
- A list of realms in the values replaces the default whole, so values that add a realm also name `cloud-common` (R16).

Follow-ups:

- The documentation page of the chart values, which #232 owes, names the value for each override of R3, R5, R6, and R16,
  with its default and an example, such as the issuers and the address of the keys of a Keycloak without `/auth`. For
  each value it names the situation that calls for another value and what an operator observes when the value is wrong:
  the issuer of a managed cluster; the anonymous access to the keys that a Pod without the token needs; an address of
  the keys that is not an in-cluster address, which needs a Pod without the token; a list of realms, which replaces the
  default whole; and a cluster whose issuer is not an https URL, where no Pod becomes ready with the default address of
  the keys. It also names what the chart does with an unknown key or an invalid value under the values of this record,
  the error of the render on an empty `IDENTITY_PROVIDER_URL`, how an upgrade that changes a provider file restarts the
  Pods, that an old Pod whose container restarts during a rollout reads the new provider files, and that an edit of the
  provider files outside Helm takes effect only when the agent's container starts again. It names what the chart does
  with `M2M_AUTH_MODE`, which the platform's deployer passes to every service.
