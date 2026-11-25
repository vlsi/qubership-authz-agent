# Accept Kubernetes service account tokens from the namespaces of the installation

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the answers it takes from the owner of the policy
  decision code on the checks. On 2026-11-23 the architect and the owner of the policy decision code agreed to drop the
  M2M modes, so every installation that the chart deploys accepts Kubernetes tokens (ADR-0105 R2).
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the reloads of the keys, the verifier in which the namespace check of this record runs, and ADR-0091 R48, the future
  `iat` of a Kubernetes token.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, which accepts a Kubernetes token in `Authorization`, and ADR-0092 R7, a Kubernetes token as an M2M
  token.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  which token the agent sends, which this record does not decide.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the provider `kubernetes` and the Kubernetes token (ADR-0104 R22), the address of the keys of that provider (ADR-0104
  R23, R28), and the requests that carry the token for the API server (ADR-0104 R24).
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  the provider `kubernetes` that the chart writes in every installation (ADR-0105 R2), the token for the API server
  that the chart mounts (ADR-0105 R6), and ADR-0105 R15, under which an operator cannot set the audience of the
  provider `kubernetes`.
- [authz-agent-ADR-0106: Trust a private CA only through the system roots of the base image](20261123-authz-agent-adr-0106-trust-a-private-ca-through-the-system-roots.md):
  the term Cluster CA, and the cluster CA in the system roots of the agent's container (ADR-0106 R2).

## Context

Services of an installation call the agent with Kubernetes service account tokens as well as with identity-provider
tokens. The API server of the cluster signs the Kubernetes service account tokens, and the services request them with
the audience `netcracker`, which every M2M call between the services of an installation uses. Every Pod can also hold a
token that the API server issues for its own audience.

The API server puts the claim `kubernetes.io`, which holds the namespace and the service account, into every service
account token that the TokenRequest API issues, the token projected into a Pod among them
(`pkg/serviceaccount/claims.go` of Kubernetes).

The API server names itself in the `iss` of every token that its TokenRequest API issues and, when that address is an
https URL, publishes its keys under it. In one cloud that address cannot be reached from inside the cluster. The keys
are also at `https://kubernetes.default.svc/openid/v1/jwks`, and the server's certificate is signed by the cluster CA
from the ConfigMap `kube-root-ca.crt`. A standard cluster lets the group `system:serviceaccounts` read the keys through
the ClusterRoleBinding `system:service-account-issuer-discovery`, so any service account of the cluster may read them
with a token issued for the API server, and an anonymous request gets 401 or 403 unless the cluster allows it. The API
server serves its keys only when its issuer is an https URL (`pkg/serviceaccount/openidmetadata.go` and the code in
`pkg/controlplane` that installs the endpoint of the keys, read in Kubernetes 1.21, 1.27, and master of 2026-11-17).

The chart mounts projected tokens under `/var/run/secrets/tokens/<name>/token`, and a Pod can hold more than one.

One cluster hosts many installations, and the API server signs the tokens of all of them with the same keys. An
installation is a composite: a baseline and its satellites, each a blue-green domain with an origin and a peer
namespace. The platform creates the ConfigMap `topology` in every namespace, and its `data` key describes the composite
in a stable format.

## Decision

We will accept a Kubernetes token in every installation whose provider files hold the provider `kubernetes`, and only
when it passes the checks of this record and its namespace belongs to the installation.

### Terms

- **Provider file**, **provider `kubernetes`**, **Kubernetes token**, **identity-provider token**: as ADR-0104 defines
  them.
- **Token for the API server**: the token in the file that the `jwksBearerTokenFile` of the provider `kubernetes`
  names.
- **Cluster CA**: as ADR-0106 defines it.
- **Token for `netcracker`**: the projected token at `/var/run/secrets/tokens/netcracker/token`, unless ADR-0096 R6
  names another file.
- **In-cluster address**: an address whose host is `kubernetes.default.svc` or `kubernetes.default.svc.cluster.local`.
- **Topology file**: `/etc/topology/data`, the `data` key of the ConfigMap `topology`.
- **Namespace of the installation**: the namespace the agent runs in, and the origin and the peer of the baseline and of
  every satellite in the topology file.

### Rules

#### The provider

- **R31** (`chart`). The agent's Pod sets `automountServiceAccountToken: false`.
- **R3** (`chart`). The chart mounts the token for `netcracker` when ADR-0096 R2 chooses it.
- **R32** (`keys`). The provider `kubernetes` reads its keys only over https. A provider `kubernetes` whose `jwksUri`
  is not an https URL stops the start.
- **R28** (`keys`). The token for the API server never goes to a PIP.
- **R26** (`chart`). The chart mounts up to two projected tokens in the agent's Pod: the token for the API server and
  the token for `netcracker`.

#### The checks

- **R16** (`verify`). The `sub` of a Kubernetes token starts with `system:serviceaccount:`, or the token gets
  `TOKEN_SUBJECT_INVALID`. Its parts are not parsed: the namespace comes from R18.

#### The namespaces

- **R17** (`namespaces`). A Kubernetes token is accepted only from a namespace of the installation.
- **R18** (`namespaces`). The namespace is the `namespace` member of the `kubernetes.io` claim. A Kubernetes token
  without it is refused.
- **R19** (`chart`). The chart mounts the ConfigMap `topology` with `optional: true`.
- **R20** (`namespaces`). While the topology file is missing, cannot be parsed, or names no composite, only the
  namespace the agent runs in is allowed.
- **R21** (`namespaces`). The agent reads the topology file again every 20 seconds.
- **R22** (`verify`). The check of R17 runs on a verified token taken from the cache too.
- **R23** (`namespaces`). A namespace that leaves the topology is refused once the kubelet has updated the mounted file
  and the next read has run, with no restart.
- **R25** (`namespaces`). A token that R17 or R18 refuses gets the code `TOKEN_NAMESPACE_NOT_ALLOWED`.

### Justification

The namespace check is what limits who gets in (R17). The audience keeps out the tokens that the API server issues for
other purposes, the default token of every Pod among them, but it does not limit who holds an accepted token: anyone who
can create a Pod can request a projected token for any audience, `netcracker` included. For the same reason, the
namespace check runs on every Kubernetes token, a cached one included (R17, R22).

The signature cannot tell the services of one installation from those of another, because the API server signs both
with the same keys. The topology file is the platform's own description of the installation, kept in every namespace,
so the agent needs no list of its own.

The keys of the provider `kubernetes` decide which tokens pass as Kubernetes tokens, and the signer of a token writes
its namespace, so whoever replaces those keys on the path could make the agent accept a token from any namespace. The
keys are therefore read only over https, whether or not the request carries the token for the API server (R32). An
ambient mesh does not protect the path to the API server, because the mesh encrypts traffic only between its own Pods.
The API server serves TLS, so R32 refuses no address at which an API server serves its keys.

The token for the API server grants the agent's access to the API server. PIP addresses come from the policy
configuration, so whoever controls one would get that access if the token went to a PIP (R28).

The source of a token decides whether it is a Kubernetes token (ADR-0104 R22), and the claim `kubernetes.io` does not,
because the claim is whatever the signer puts in the token. The check of `sub` costs nothing, because the API server
always sets that prefix on a service account token (R16).

The agent calls the API server only to read its keys, not for every request, and needs no RBAC binding.

### Alternatives considered

- **A1. Ask the API server about every token with a TokenReview.** Rejected by ADR-0091 R68: it adds a call to the API
  server for every new token and needs the `system:auth-delegator` role, while the keys at the `jwksUri` of the
  provider `kubernetes` are enough to verify a token locally.
- **A2. Accept every namespace while the topology file is missing.** Rejected by R20: a missing ConfigMap would open the
  agent to every installation of the cluster.
- **A3. Refuse to start without the topology file.** Rejected by R20: a namespace without the ConfigMap could not run
  the agent at all, not even for its own services.
- **A8. Run without Kubernetes tokens when the file that the `jwksBearerTokenFile` of the provider `kubernetes` names
  is missing.** Rejected by ADR-0104 R14: the readiness probe would pass while the agent refuses those tokens. A missing
  file is an error of the deployment that no wait repairs, so the agent stops at the start.
- **A9. Read the keys of the provider `kubernetes` over http, as for a cluster whose issuer is an http URL.** Rejected
  by R32: anyone on the path could replace the keys, and an API server whose issuer is not an https URL serves no keys
  (Context).

## Consequences

Negative:

- Anyone who can create a Pod in a namespace of the installation can get a token the agent accepts.
- A service of the installation that receives a token for the audience `netcracker` can present it to the agent, since
  every M2M call between the services shares that audience.
- A token stays accepted until its `exp` after its Pod or service account is deleted, because the agent does not ask the
  API server. How long that is depends on the lifetime the caller requested.
- A namespace that joins the composite is accepted only after the kubelet updates the mounted file and the next read
  runs.
- Where the provider files hold no provider `kubernetes`, as outside Kubernetes, no token is a Kubernetes token, and a
  token that an API server signed is refused under ADR-0104 R21, unless a provider `identity-provider` names its issuer,
  which makes it an identity-provider token (ADR-0104 R22).
- The chart writes the provider `kubernetes` in every installation, so every Pod that the chart deploys waits for the
  keys of the API server before it becomes ready (ADR-0105 R2; ADR-0104 R25; ADR-0091 R14), and a token for the API
  server that the agent cannot read stops it at the start (ADR-0105 R6; ADR-0104 R14).
- On a cluster whose issuer is not an https URL the API server serves no keys (Context), so with the default address of
  the keys of ADR-0105 R5 every Pod that the chart deploys stays not ready (ADR-0105 R2, R5; ADR-0091 R19).
