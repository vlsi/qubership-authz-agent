# Trust a private CA only through the system roots of the base image

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. The decision was agreed with the architect on 2026-11-20.
- The owner of the policy decision code (`vlsi`) reviews this record.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  ADR-0091 R14, under which the agent becomes ready only with the policy snapshots, a usable key of every required
  source, and the default tenant.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  the term Policy source.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term Token for the API server, and ADR-0094 R31, which turns off the service-account volume of the Pod and which
  this record keeps. This request deletes ADR-0094 R2, which mounted the cluster CA and which R2 of this record
  replaces, and points the ADR-0094 term Cluster CA at the term of this record.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the requests for the keys of a provider (ADR-0104 R23), whose CA this record decides, and ADR-0104 R6, under which
  a provider file with the member `caFile` stops the start.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  ADR-0105 R2, the provider `kubernetes` in every installation, ADR-0105 R5, which by default loads the keys of that
  provider from the API server at an in-cluster address, and ADR-0105 R16, under which readiness waits by default for
  the keys of the realm `cloud-common`.
- [authz-agent-ADR-0101: Run the agent in Docker without Kubernetes](https://github.com/Netcracker/qubership-authz-agent/pull/235),
  proposed in #235: the Docker target, on which R1 holds as on Kubernetes.

## Context

Some servers that the agent calls over HTTPS present certificates that a private CA signs. The Kubernetes API server
presents a certificate that the cluster CA signs. Under `INTERNAL_TLS_ENABLED`, the platform's servers present
certificates that the internal CA signs.

When a container starts, the entrypoint of the base image `qubership-core-base` adds the certificates in the `.crt`,
`.cer`, and `.pem` files under `/tmp/cert` to the system roots
([#319](https://github.com/Netcracker/qubership-authz-agent/issues/319#issuecomment-7096026256)).

## Decision

We will verify every HTTPS request of the agent against the system roots alone, and the chart will add the cluster CA
and the internal CA to those roots.

### Terms

- **System roots**: the certificates of the trust store in `/etc/ssl/certs` of the agent's container, which the agent
  trusts for its HTTPS requests.
- **Cluster CA**: the CA that signs the certificate of the Kubernetes API server. The key `ca.crt` of the ConfigMap
  `kube-root-ca.crt` in the agent's namespace holds it.
- **Internal CA**: the CA that signs the certificates of the platform's servers under `INTERNAL_TLS_ENABLED`. The key
  `ca.crt` of the Secret `<SERVICE_NAME>-tls` in the agent's namespace holds it; `<SERVICE_NAME>` is the chart value
  `SERVICE_NAME`.
- **Provider file**, **provider `kubernetes`**, **Kubernetes token**, **required source**: as ADR-0104 defines them.
- **Token for the API server**, **in-cluster address**: as ADR-0094 defines them.
- **Policy source**: as ADR-0093 defines it.

### Rules

#### The agent

- **R1** (`keys`, `client`, `startup`, `policy`, `chart`). Every HTTPS request that the agent sends verifies the
  server's certificate against the system roots and against no other CA.

#### The chart

- **R2** (`chart`). On Kubernetes, the system roots hold the cluster CA.
- **R3** (`chart`). With `INTERNAL_TLS_ENABLED`, the system roots hold the internal CA, and a missing Secret
  `<SERVICE_NAME>-tls` keeps the Pod from starting.
- **R4** (`chart`). When `CA_CERTIFICATES_SECRET` names a Secret, the system roots hold the PEM certificates in the keys
  of that Secret whose names end in `.crt`, `.cer`, or `.pem`. A value of `CA_CERTIFICATES_SECRET` that names no Secret
  in the agent's namespace keeps the Pod from starting.
- **R5** (`chart`). The chart adds no certificate to the system roots other than those of R2, R3, and R4.

### Justification

One set of CAs serves every request and every target, so the code holds no CA setting per request, and a PIP, the policy
source, and tenant-manager trust a private CA the same way as Keycloak and the API server (R1).

The chart writes the provider `kubernetes` in every installation (ADR-0105 R2), so the agent accepts Kubernetes tokens
in every installation on Kubernetes. That provider loads its keys from the API server at an in-cluster address by
default (ADR-0105 R5), and always while the Pod holds the token for the API server (ADR-0104 R28). The cluster CA signs
the certificate of the API server, so every installation on Kubernetes gets the cluster CA (R2). An installation whose
values move the keys away from the API server gets it too, and every HTTPS request there trusts the cluster CA, a cost
the Negative consequences accept. The ConfigMap `kube-root-ca.crt` is in every namespace and holds the CA that the
service-account volume of a Pod gets, so the agent needs no service-account volume, which ADR-0094 R31 turns off (R2).

The Secret `<SERVICE_NAME>-tls` also holds `tls.crt`, a certificate of one service rather than a CA, so the chart adds
only its `ca.crt` to the system roots (R3, R5).

### Alternatives considered

- **A1. Name a CA per request: `keycloak.caFile`, a `caFile` per provider, a file with the cluster CA, and the CA in
  `CERTIFICATE_FILE_PATH` read by the agent.** Rejected by R1: each kind of request would need a CA setting of its own,
  and the PIPs have none.
- **A2. Take the cluster CA from the service-account volume of the Pod at
  `/var/run/secrets/kubernetes.io/serviceaccount`.** Rejected by ADR-0094 R31, which turns that volume off.
- **A4. Add every certificate of the Secret `<SERVICE_NAME>-tls` to the system roots with `INTERNAL_TLS_ENABLED`.**
  Rejected by R5: `tls.crt`, the certificate of one service, would join the system roots. An operator who names that
  Secret in `CA_CERTIFICATES_SECRET` gets `tls.crt` under R4.

## Consequences

Negative:

- On Kubernetes, every HTTPS request of the agent trusts the cluster CA, not only the request to the API server. A
  certificate that the cluster CA issues for any other host that the agent calls passes verification on the agent's
  requests to that host.
- The requests that carry the token for the API server trust every CA of the system roots, not the cluster CA alone. A
  certificate for `kubernetes.default.svc` that the internal CA or a CA of `CA_CERTIFICATES_SECRET` issues passes
  verification, and its holder can receive that token.
- A change of the CAs in a mounted Secret or ConfigMap takes effect once the Pod is recreated, as by
  `kubectl rollout restart`
  ([Netcracker/qubership-core-base-images#388](https://github.com/Netcracker/qubership-core-base-images/issues/388)).

Follow-ups:

- #235 adds the layers `image` and `docker` to the reading guide. An `ENV` in the image or a setting of the Compose
  example can change the CAs a request trusts, and the image can keep the CAs of R2 to R4 out of the system roots. So
  whichever of #235 and this change merges second adds both tags to R1 and the tag `image` to R2 to R4, and links
  the two records to each other's files under Related ADRs.
- The section on trusting a private CA that #250 adds to `components/authz-agent/README.md` names the three sources of
  R2 to R4.

## Open points

- **O1.** Who creates the Secret `<SERVICE_NAME>-tls` for the agent under `INTERNAL_TLS_ENABLED`? The agent serves no
  TLS itself. A deployer that passes `INTERNAL_TLS_ENABLED: true` to every service of an installation passes it to the
  agent too, and where nothing creates that Secret for the agent, R3 keeps the Pod from starting. One answer: the
  platform creates the Secret for every service of an installation with `INTERNAL_TLS_ENABLED`, and R3 stands as
  written. The other: nothing creates it for the agent, and a chart value names the Secret that holds the internal CA
  instead of `<SERVICE_NAME>-tls`. The architect (`mr-joom`) decides. It affects R3 and the term Internal CA.
- **O2.** A certificate of the Secret of `CA_CERTIFICATES_SECRET` can have the name under which the chart adds the
  cluster CA or the internal CA, and then only one of the two certificates with that name reaches the system roots.
  Which one? One answer: the cluster CA or the internal CA, so R2 and R3 take precedence over R4; that certificate of
  the Secret is then left out, and nothing reports it. The other: the certificate of that Secret, so R4 takes
  precedence over R2 and R3. Where it replaces the internal CA, the requests to the platform's servers whose
  certificates the internal CA signs fail verification. The agent then stays not ready while its readiness under
  ADR-0091 R14 depends on one of those servers, such as the Keycloak that serves the keys of the realm `cloud-common`
  (ADR-0105 R16), the policy source, or tenant-manager. Where it replaces the cluster CA while the provider
  `kubernetes` loads its keys from the API server, as at the default address of ADR-0105 R5, the agent loads no keys
  of that provider and stays not ready (ADR-0104 R25, ADR-0091 R14). The architect (`mr-joom`) decides. It affects R2
  to R4.
