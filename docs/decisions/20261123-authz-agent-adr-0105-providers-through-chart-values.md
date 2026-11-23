# Configure the two providers through the chart values

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records, agreed on 2026-11-19 and 2026-11-23. On 2026-11-23 the architect and the owner of the policy decision code
  also agreed to drop the M2M modes, so the chart writes both providers in every installation (R1, R2).
- The owner of the policy decision code (`vlsi`) reviews this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

Where a statement of ADR-0091 or ADR-0094 disagrees with this record, this record replaces it. The Follow-ups name the
edits that bring those records in line with this one.

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the settings of the agent that the chart sets, and those that go away (ADR-0091 R64).
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  the tokens that the agent accepts in every installation (ADR-0092 R11), and `M2M_AUTH_MODE`, which the agent does
  not read (ADR-0092 R15), as #345 rewrites them.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the token for the API server (ADR-0094 R2), and the Pod without the default token of its service account
  (ADR-0094 R31).
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the token that the agent sends and the address at which the agent obtains it, which this record does not decide.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the provider directory, the provider files, and the members of a provider, which this record fills from the values.

## Context

ADR-0104 has the agent read two providers, `identity-provider` for the platform's Keycloak and `kubernetes` for the API
server of the cluster, from the provider files in the directory `/etc/authz/providers`. The Helm chart in
`helm-templates/authz-agent` deploys the agent on the platform, whose deployer passes nested values to a chart. The
deployer also passes `M2M_AUTH_MODE` to every application it deploys, and the agent does not read it (ADR-0092 R15).

The values of the chart carry `IDENTITY_PROVIDER_URL`, the address of the platform's Keycloak without a realm,
`http://identity-provider:8080` by default. They also carry `DEPLOYMENT_SESSION_ID`, which the deployer sets for each
install session, and which the chart puts into a label of its ConfigMap but not of the Pod template. The root of the
values schema accepts every key that it does not name (`additionalProperties: true`).

kubeadm gives the API server the issuer `https://kubernetes.default.svc.cluster.local` in the static Pod manifest that
it writes, unless the cluster configuration sets another one. The API server serves its keys only when its issuer is an
https URL (`pkg/serviceaccount/openidmetadata.go` and `pkg/controlplane` of Kubernetes).

## Decision

We will have the chart write the provider files of ADR-0104, with both providers in every installation, from the
values block `trustedProviders` and from `IDENTITY_PROVIDER_URL`.

### Terms

- **Provider directory**, **provider file**, **provider `identity-provider`**, **provider `kubernetes`**, **`exact`
  provider**, **`realm-template` provider**: as ADR-0104 defines them.
- **Values**: the values of the chart in `helm-templates/authz-agent`, its `values.yaml` and what an installation sets
  over it.
- **Values schema**: `helm-templates/authz-agent/values.schema.json`.
- **Base address**: the address that R4 makes of `IDENTITY_PROVIDER_URL`.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### `M2M_AUTH_MODE`

- **R1** (`chart`). The chart does not pass `M2M_AUTH_MODE` to the agent's container, and no value of `M2M_AUTH_MODE`
  in the values changes what the chart renders. The values schema accepts that key with any value.

#### The provider files

- **R2** (`chart`). The chart writes both the provider `identity-provider` and the provider `kubernetes`.
- **R3** (`chart`). The chart writes the provider `identity-provider` as a `realm-template` provider with these
  members:
  - `issuer.value`: `trustedProviders.identity-provider.issuerPattern`, or, when it is empty, the base address
    followed by `/auth/realms/{realm}`;
  - `jwksUri`: `trustedProviders.identity-provider.jwksUri`, or, when it is empty, the base address followed by
    `/auth/realms/{realm}/protocol/openid-connect/certs`;
  - `readinessRealms`: `trustedProviders.identity-provider.readinessRealms`;
  - `audience`: `{"mode": "skipValidation"}`.
- **R4** (`chart`). The base address is `IDENTITY_PROVIDER_URL` of the values, without its last character when that
  character is `/`. When R3 derives a member from an empty base address, the render of the chart fails with an error
  that names `IDENTITY_PROVIDER_URL`.
- **R5** (`chart`). The chart writes the provider `kubernetes` as an `exact` provider with these members:
  - `issuer.value`: `trustedProviders.kubernetes.issuer`;
  - `jwksUri`: `trustedProviders.kubernetes.jwksUri`;
  - `audience`: `{"mode": "matchAny", "values": ["netcracker"]}`;
  - `jwksBearerTokenFile`: only as R6 decides.
- **R6** (`chart`). When `trustedProviders.kubernetes.jwksAuthentication` is `service-account`, the chart mounts a
  projected service account token for the audiences of the API server in the agent's Pod, and writes its path as
  `jwksBearerTokenFile` of the provider `kubernetes`. In every other case the chart mounts no service account token for
  the audiences of the API server, and writes no `jwksBearerTokenFile`.

#### The values

- **R7** (`chart`). The values describe the providers in the block `trustedProviders`, whose keys are the `id` of each
  provider. The block holds only the keys that this table lists, with the defaults that `values.yaml` sets, and the
  values schema refuses any other key under `trustedProviders`:

  | Key | Default |
  | --- | --- |
  | `trustedProviders.identity-provider.issuerPattern` | `""` |
  | `trustedProviders.identity-provider.jwksUri` | `""` |
  | `trustedProviders.identity-provider.readinessRealms` | `[cloud-common]` |
  | `trustedProviders.kubernetes.issuer` | `https://kubernetes.default.svc.cluster.local` |
  | `trustedProviders.kubernetes.jwksUri` | `https://kubernetes.default.svc/openid/v1/jwks` |
  | `trustedProviders.kubernetes.jwksAuthentication` | `service-account` |

- **R8** (`chart`). The values schema accepts an empty `trustedProviders.identity-provider.issuerPattern`, and refuses
  a non-empty one that does not hold `{realm}` exactly once.
- **R9** (`chart`). The values schema refuses a `trustedProviders.kubernetes.jwksAuthentication` other than
  `service-account` and `none`.
- **R10** (`chart`). The values schema names each key of the values that ADR-0091 R64 removes, and refuses values that
  hold one of them, with an error that names the key.
- **R11** (`chart`). Comments in `values.yaml` inside the block `trustedProviders` show the `issuer.value` and the
  `jwksUri` that R3 derives from the default `IDENTITY_PROVIDER_URL`, and the values for a Keycloak whose addresses have
  no `/auth`.

#### The mount

- **R12** (`chart`). The chart writes its provider files into one ConfigMap, and mounts that ConfigMap whole at the
  provider directory, without `subPath`.
- **R13** (`chart`). The Pod template carries a checksum of the provider files that the ConfigMap of R12 holds. A
  change of a provider file changes the Pod template, and a change of that ConfigMap that leaves every provider file
  as it was, such as a change of its labels, does not.

#### The agent

- **R14** (`keys`, `startup`). The agent does not read `IDENTITY_PROVIDER_URL`.

### Implementation notes

Adds no requirement. The values that R7 lists, as `values.yaml` sets them:

```yaml
IDENTITY_PROVIDER_URL: "http://identity-provider:8080"

trustedProviders:
  identity-provider:
    # Empty: derived from IDENTITY_PROVIDER_URL as http://identity-provider:8080/auth/realms/{realm}
    # For a Keycloak without /auth: http://keycloak:8080/realms/{realm}
    issuerPattern: ""
    # Empty: derived from IDENTITY_PROVIDER_URL as
    # http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs
    # For a Keycloak without /auth: http://keycloak:8080/realms/{realm}/protocol/openid-connect/certs
    jwksUri: ""
    readinessRealms: [cloud-common]
  kubernetes:
    issuer: "https://kubernetes.default.svc.cluster.local"
    jwksUri: "https://kubernetes.default.svc/openid/v1/jwks"
    jwksAuthentication: service-account
```

The ConfigMap holds `identity-provider.json` and `kubernetes.json`, in the format of the examples of ADR-0104. One
helper template renders the data of the ConfigMap, and the Pod template takes its checksum, as in
`checksum/providers: {{ include "authz-agent.providerFiles" . | sha256sum }}`, rather than the checksum of the file
`configmap.yaml`, which also renders the labels and the ServiceAccount.

The token for the API server is a `serviceAccountToken` source without `audience`, which the kubelet requests for the
audiences of the API server, at `kubernetes/token` of the projected volume that the chart mounts at
`/var/run/secrets/tokens`. That volume holds the token for `netcracker` as well when ADR-0096 chooses it, so
`jwksBearerTokenFile` is `/var/run/secrets/tokens/kubernetes/token`.

In the values schema, a property whose schema is `false` refuses its key, and Helm names the path of the key in the
error, such as `at '/AUTHZ_IDP_REALMS': false schema` in Helm 4.3. Helm validates with the regular expressions of Go,
which have no lookahead and whose `.` does not match a line break. The schema of R8 therefore accepts an empty value,
or a non-empty one that matches `\{realm\}` and does not match `\{realm\}[\s\S]*\{realm\}`.

### Justification

The agent accepts Keycloak tokens and Kubernetes tokens in every installation (ADR-0092 R11), so the chart writes both
providers, and a Kubernetes token is verified wherever the chart deploys the agent (R2). The agent does not read
`M2M_AUTH_MODE` (ADR-0092 R15), so the chart passes nothing of it to the agent, and the values schema accepts the key,
because the platform's deployer passes it to every application (R1).

The block is keyed by the `id` of each provider, so the values, the provider files, and the errors of ADR-0104 R18
name a provider in the same way (R7). It holds only the two providers, because ADR-0104 R6 accepts no other `id`. The
template reads only the keys it knows, so the schema refuses every other key, such as an `audience`, that an operator
would otherwise set with no effect (R7).

Each provider has one `audience` that works in this stage. The platform's Keycloak has no audience mapper that names the
services of an installation, and those services request their service account tokens with the audience `netcracker`
(ADR-0094 Context). The chart writes these values rather than offering a setting (R3, R5).

The platform's Keycloak holds one realm per tenant, so its provider is a `realm-template` provider, and an `exact`
provider would trust a single realm (R3). A provider file written by hand outside the chart can still describe an
`exact` provider `identity-provider`.

Deriving both addresses from `IDENTITY_PROVIDER_URL` means that a Keycloak moved to another host with the same paths
needs one value (R3, R4). ADR-0104 R19 compares `iss` byte for byte, and a trailing `/` in `IDENTITY_PROVIDER_URL`
would put `//` into `issuer.value` and give every token `TOKEN_ISSUER_UNKNOWN`, so the chart drops it (R4). An empty
base address would give addresses that ADR-0104 R6 refuses, so the render fails first and names the value to set (R4).
For a Keycloak whose addresses have no `/auth`, the values set `issuerPattern` and `jwksUri` instead (R3, R11). An empty
`issuerPattern` means that the chart derives it (R3). An operator writes `issuerPattern` from the `iss` of the tokens,
so the values schema checks its `{realm}`, and a value copied from one token with the realm name in place of `{realm}`
fails at the install rather than stopping the start under ADR-0104 R6 (R8).

`cloud-common` is the platform's realm for M2M clients, so a Pod does not become ready before that realm's keys are
loaded. The agent holds no realm name of its own (ADR-0104 R13), so the values supply this one (R7).

The default issuer of the provider `kubernetes` is the one kubeadm gives the API server. The default `jwksUri` is the
in-cluster address of the keys. On a cluster whose issuer is an https URL, any service account of the cluster may read
them there with a token for the API server (Context; ADR-0094 Context). A cluster that kubeadm set up needs no value. On
a managed cluster with another https issuer, the values set `trustedProviders.kubernetes.issuer` and keep the in-cluster
`jwksUri` (R7). A standard cluster refuses an anonymous request for its keys (ADR-0094 Context), so the chart mounts a
token for the API server by default. `none` is for a cluster that serves its keys to an anonymous request, where the Pod
then holds no credential for the API server (R6, R9). The token is mounted only with `service-account`, where the
requests of the provider `kubernetes` for its keys carry it (R6).

Mounting the ConfigMap whole gives the provider directory exactly the files that the chart writes, and a provider file
that a later chart adds or drops needs no change of the mounts (R12). ADR-0104 R2 reads through the
links that such a mount creates (ADR-0104 Context). The agent reads the provider files only at start (ADR-0104 R5), so
a changed provider file takes effect in a container only when the container starts again, and the checksum makes
`helm upgrade` roll out new Pods (R13). The checksum covers the provider files alone, because `DEPLOYMENT_SESSION_ID`
changes the labels of the ConfigMap at every install session, and a checksum of the whole object would restart the Pods
at each of them (R13).

The agent holds nothing specific to Keycloak (ADR-0104), so turning the platform's address of Keycloak into provider
files is the chart's work, and a deployment without the chart writes the full addresses into its provider files (R14).

The root of the values schema accepts keys it does not name, so a key that the chart no longer reads would pass with no
error. Naming each one makes the schema refuse it at the install (R10). An installation that still lists its trusted
realms in `AUTHZ_IDP_REALMS` then stops at the install rather than trusting every realm of the Keycloak with no sign of
the change, and one that still sets `AUTHZ_TRUSTED_PROVIDERS` stops rather than running with the providers that the
chart writes from `trustedProviders`.

### Alternatives considered

- **A1. Give each member of a provider a key of its own at the top of the values, such as
  `TRUSTED_PROVIDERS_KUBERNETES_ISSUER`.** Rejected by R7: the platform's deployer passes nested values, and a block
  keyed by the `id` names a provider as the provider files do.
- **A2. Keep a free list of providers in the values, as `AUTHZ_TRUSTED_PROVIDERS` is, that replaces the providers the
  chart writes.** Rejected by R7 and R10: the platform needs only the two providers that the block names, with the
  members that R3 and R5 fix, and a free list would carry the whole format of the provider files into the values, where
  only the start of the agent checks it (ADR-0104 R3, R6, and R12 to R18).
- **A3. Set `audience` in the values.** Rejected by R7: each provider has one `audience` that works in this stage. A
  later stage that checks the `aud` of Keycloak tokens adds the setting.
- **A4. Write the provider `identity-provider` as an `exact` provider when `issuerPattern` holds no `{realm}`.**
  Rejected by R3 and R8: the platform's Keycloak holds one realm per tenant, and an `exact` provider would trust one of
  them.
- **A5. Write the provider `kubernetes` only in the M2M modes `hybrid` and `k8s` of `M2M_AUTH_MODE`.** Rejected by
  R2: the agent accepts Kubernetes tokens in every installation (ADR-0092 R11), and without the provider it would
  refuse each of them with `TOKEN_ISSUER_UNKNOWN`. An earlier version of this record did so.
- **A6. Pass `M2M_AUTH_MODE` to the agent, or refuse values that set it.** Rejected by R1: the agent does not read it
  (ADR-0092 R15), and the platform's deployer passes it to every application, so a refusal would stop every install of
  the chart on the platform.
- **A7. Let the agent build the addresses of the Keycloak from `IDENTITY_PROVIDER_URL`.** Rejected by R14: the agent
  would hold the paths of Keycloak, and a Keycloak without `/auth` would need a change of the agent.
- **A8. Mount each provider file with `subPath`.** Rejected by R12: each provider file would need a mount of its own,
  so a file that a later chart adds or drops would change the mounts as well as the ConfigMap.
- **A9. Take the checksum of the template file of the ConfigMap.** Rejected by R13: that file also renders the labels,
  and `DEPLOYMENT_SESSION_ID` would restart the Pods at every install session.
- **A10. Mount the token for the API server whatever the cluster allows.** Rejected by R6 and R9: on a cluster that
  serves its keys to an anonymous request, the Pod would hold a credential for the API server that no request needs.
  This reverses ADR-0094 R2.
- **A11. Default `readinessRealms` to the realms of `AUTHZ_IDP_REALMS`: `cloud-common`, `default`, `cpq`, and
  `external`.** Rejected by R7: `default` is the display name of a tenant, not the name of a realm, most installations
  hold neither `cpq` nor `external`, and a name that the Keycloak does not hold keeps the Pod not ready.
- **A12. Let a value under `trustedProviders.kubernetes` leave the provider `kubernetes` out.** Rejected by R2 and R7:
  it would be one more value that no installation on Kubernetes needs, and an installation that set it would refuse
  every Kubernetes token with `TOKEN_ISSUER_UNKNOWN`.

## Consequences

Positive:

- An installation on a cluster whose API server has the default issuer of R7, and whose Keycloak issues tokens with
  the `iss` `<IDENTITY_PROVIDER_URL>/auth/realms/<realm>`, sets no value of a provider (R2, R3, R7).
- A Keycloak at another host with the same paths, whose tokens name that host in `iss`, needs only a new
  `IDENTITY_PROVIDER_URL` for the provider `identity-provider` (R3, R4).

Negative:

- A Keycloak whose addresses have no `/auth` needs `issuerPattern` and `jwksUri` in the values, and a Keycloak whose
  tokens name it in `iss` at another address than `IDENTITY_PROVIDER_URL`, such as a public one, needs
  `issuerPattern` (R3).
- Through the chart an installation cannot describe an `exact` provider `identity-provider` or a check of the `aud` of
  Keycloak tokens. Each needs a change of the chart, or a provider file written by hand outside the chart (R3, R7).
- No rule requires the values schema to check a value that the chart writes into a member of a provider, except the
  `{realm}` of `issuerPattern` (R8). A value that breaks another condition of ADR-0104 can therefore pass the values
  schema and stop the start (ADR-0104 R6). Two such values are a `jwksUri` of the provider `identity-provider` without
  `{realm}`, and an `issuerPattern` whose `{realm}` fills only part of a path segment, such as `t-{realm}`.
- On a cluster whose API server has an https issuer other than the default of R7, as a managed cluster often does,
  every token that the API server signs gets `TOKEN_ISSUER_UNKNOWN` in a ready Pod, until
  `trustedProviders.kubernetes.issuer` names that issuer (R7; ADR-0104 R19, R21).
- Every Pod that the chart deploys waits for the keys of the API server before it becomes ready (R2; ADR-0104 R25). On
  a cluster whose API server has an issuer that is not an https URL, the API server serves no keys, so with the
  in-cluster `jwksUri` of R7 no Pod becomes ready, and the values cannot leave the provider `kubernetes` out (Context;
  ADR-0091 R19).
- With `jwksAuthentication` `none`, a Pod stays not ready on a cluster that refuses an anonymous request for its keys,
  as a standard cluster does (R6; ADR-0091 R19).
- A list in `readinessRealms` replaces the default whole, so values that add a realm list `cloud-common` again (R7).
- Values that still set a key of ADR-0091 R64 fail the validation of the install until the key is removed (R10).
- An edit of the ConfigMap outside Helm changes no checksum, so it takes effect in a Pod only when the agent's
  container starts again for another reason, and the Pods of one Deployment can then read different provider files
  (R13; ADR-0104 R5).
- The kubelet updates the files of the ConfigMap of R12 in every Pod that mounts it, old Pods included. A rollout can
  switch `jwksAuthentication` from `none` to `service-account`. During such a rollout, an old Pod whose container
  restarts, or that its ReplicaSet recreates, reads the new provider files with its old mounts. The new provider files
  then name a `jwksBearerTokenFile` that the old Pod does not hold, and stop the start of its agent at every restart
  until the rollout replaces the Pod (R6, R12; ADR-0104 R14).

Follow-ups:

- ADR-0091 R64 adds `AUTHZ_TRUSTED_PROVIDERS_FILE`, `AUTHZ_TRUSTED_PROVIDERS`, and `AUTHZ_JWKS_HTTP_TIMEOUT` to the
  settings that go away. ADR-0091 and ADR-0094 drop the statements that this record replaces, and ADR-0104 cites R13
  of this record in place of ADR-0091 R13.
- ADR-0101, which #235 proposes, cites R14 of this record in place of ADR-0091 R78.
- A record of a private CA decides how the cluster CA, which ADR-0094 R2 mounts, reaches the agent.
