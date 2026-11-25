# Trust a private CA only through the system roots of the base image

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record. The decision was agreed with the architect on 2026-11-20,
  and its open points were settled with the architect on 2026-11-25.
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
  the requests for the keys of a provider (ADR-0104 R23), whose CA this record decides, ADR-0104 R6, under which a
  provider file with the member `caFile` stops the start and which makes the provider `kubernetes` a `single` provider,
  ADR-0104 R25, under which every `single` provider is a required source, and ADR-0104 R28, under which that provider
  loads its keys from the API server while the Pod holds the token for the API server.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  ADR-0105 R2, the provider `kubernetes` in every installation, and ADR-0105 R5, which by default loads the keys of
  that provider from the API server at an in-cluster address.
- [authz-agent-ADR-0101: Run the agent in Docker without Kubernetes](https://github.com/Netcracker/qubership-authz-agent/pull/235),
  proposed in #235: the Docker target, on which R1 holds as on Kubernetes.

## Context

Some servers that the agent calls over HTTPS present certificates that a private CA signs. The Kubernetes API server
presents a certificate that the cluster CA signs. The platform's deployer creates the Secret `defaultsslcertificate` in
every application namespace and puts the CAs it is given into it. It passes the name of that Secret to every service as
`SSL_SECRET`, unless the environment names another Secret, and the MD5 of its bundle as `CERTIFICATE_BUNDLE_MD5SUM`
([#344](https://github.com/Netcracker/qubership-authz-agent/issues/344)).

When a container starts, the entrypoint of the base image `qubership-core-base` adds the certificates in the `.crt`,
`.cer`, and `.pem` files under `/tmp/cert` to the system roots
([#319](https://github.com/Netcracker/qubership-authz-agent/issues/319#issuecomment-7096026256)).

## Decision

We will verify every HTTPS request of the agent against the system roots alone, and the chart will add to those roots
the cluster CA and the certificates of the Secret that `SSL_SECRET` names.

### Terms

- **System roots**: the certificates of the trust store in `/etc/ssl/certs` of the agent's container, which the agent
  trusts for its HTTPS requests.
- **Cluster CA**: the CA that signs the certificate of the Kubernetes API server. The key `ca.crt` of the ConfigMap
  `kube-root-ca.crt` in the agent's namespace holds it.
- **Provider file**, **provider `kubernetes`**, **Kubernetes token**, **required source**: as ADR-0104 defines them.
- **Token for the API server**, **in-cluster address**: as ADR-0094 defines them.
- **Policy source**: as ADR-0093 defines it.

### Rules

#### The agent

- **R1** (`keys`, `client`, `startup`, `policy`, `chart`). Every HTTPS request that the agent sends verifies the
  server's certificate against the system roots and against no other CA.

#### The chart

- **R2** (`chart`). On Kubernetes, the system roots hold the cluster CA.
- **R4** (`chart`). When `SSL_SECRET` names a Secret, the system roots hold the PEM certificates in the keys of that
  Secret whose names end in `.crt`, `.cer`, or `.pem`. A certificate of that Secret never takes the place of the
  cluster CA in the system roots: R2 takes precedence over R4. A value of `SSL_SECRET` that is not empty and names no
  Secret in the agent's namespace keeps the Pod from starting.
- **R5** (`chart`). The chart adds no certificate to the system roots other than those of R2 and R4.
- **R7** (`chart`). When `SSL_SECRET` names a Secret, the agent's Pod template sets the environment variable
  `CERTIFICATE_BUNDLE_<SSL_SECRET>_MD5SUM` to the value of `CERTIFICATE_BUNDLE_MD5SUM`, so an upgrade that changes that
  value recreates the agent's Pods. In that name, `<SSL_SECRET>` stands for the value of `SSL_SECRET` as written.

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

The deployer passes `SSL_SECRET` to every service, so the agent trusts the CAs of the platform's servers with no setting
of its own, and a server that an https URL names is trusted once the deployer puts its CA into that Secret under a key
that R4 adds (R4). The CAs of the platform's servers reach the agent that way, so the chart adds no CA under the
platform's setting `INTERNAL_TLS_ENABLED` (R5).

The provider `kubernetes` is a required source (ADR-0104 R6, R25). While it loads its keys from the API server, as at
the default address of ADR-0105 R5, a certificate of the Secret of `SSL_SECRET` that took the place of the cluster CA
would keep the agent from loading those keys and from becoming ready (ADR-0104 R25, ADR-0091 R14). So R4 gives R2
precedence (R4).

The entrypoint adds the CAs to the system roots only when a container starts, and the deployer passes a new
`CERTIFICATE_BUNDLE_MD5SUM` when the bundle of `defaultsslcertificate` changes, so the new Pods trust the new CAs (R7).
R7 names the variable `CERTIFICATE_BUNDLE_<SSL_SECRET>_MD5SUM`, as the architect decided on 2026-11-25 (#344).

### Alternatives considered

- **A1. Name a CA per request: `keycloak.caFile`, a `caFile` per provider, a file with the cluster CA, and the CA in
  `CERTIFICATE_FILE_PATH` read by the agent.** Rejected by R1: each kind of request would need a CA setting of its own,
  and the PIPs have none.
- **A2. Take the cluster CA from the service-account volume of the Pod at
  `/var/run/secrets/kubernetes.io/serviceaccount`.** Rejected by ADR-0094 R31, which turns that volume off.
- **A6. Add the internal CA to the system roots under the platform's setting `INTERNAL_TLS_ENABLED`.** The internal
  CA is the `ca.crt` of the Secret `<SERVICE_NAME>-tls`, where `<SERVICE_NAME>` is the chart value `SERVICE_NAME`.
  Rejected by R5: the CAs of the platform's servers reach the agent through the Secret of `SSL_SECRET` (R4).
- **A7. Let a certificate of the Secret of `SSL_SECRET` take the place of the cluster CA.** Rejected by R4: while the
  provider `kubernetes` loads its keys from the API server, the agent would load none of them and would not become
  ready.
- **A8. Name the Secret with the CAs in a chart value of the agent's own, `CA_CERTIFICATES_SECRET`, instead of
  `SSL_SECRET`.** Rejected by R4: an installation by the deployer would trust none of the environment's CAs until an
  operator set that value, while the deployer already passes `SSL_SECRET` to every service.

## Consequences

Negative:

- On Kubernetes, every HTTPS request of the agent trusts the cluster CA, not only the request to the API server. A
  certificate that the cluster CA issues for any other host that the agent calls passes verification on the agent's
  requests to that host.
- The requests that carry the token for the API server trust every certificate of the system roots, not the cluster CA
  alone. A certificate for `kubernetes.default.svc` that a certificate of the Secret of `SSL_SECRET` issues, or that the
  Secret holds itself, passes verification, and its holder can receive that token.
- A change of the CAs takes effect once the Pod is recreated
  ([Netcracker/qubership-core-base-images#388](https://github.com/Netcracker/qubership-core-base-images/issues/388)).
  An upgrade that changes `CERTIFICATE_BUNDLE_MD5SUM` recreates the Pods (R7). A change of the cluster CA in the
  ConfigMap `kube-root-ca.crt`, or of the Secret of `SSL_SECRET` outside the deployer, needs the Pod recreated by hand,
  as with `kubectl rollout restart`.
- A certificate of the Secret of `SSL_SECRET` that would take the place of the cluster CA is left out of the system
  roots (R4).

Follow-ups:

- #235 adds the layers `image` and `docker` to the reading guide. An `ENV` in the image or a setting of the Compose
  example can change the CAs a request trusts, and the image can keep the CAs of R2 and R4 out of the system roots. So
  whichever of #235 and this change merges second adds both tags to R1 and the tag `image` to R2 and R4, and links the
  two records to each other's files under Related ADRs.
- The section on trusting a private CA that #250 adds to `components/authz-agent/README.md` names the two sources of R2
  and R4.
- #344 checks on a stand which keys `defaultsslcertificate` holds: R4 adds the keys whose names end in `.crt`, `.cer`,
  or `.pem`, and R5 no other.
