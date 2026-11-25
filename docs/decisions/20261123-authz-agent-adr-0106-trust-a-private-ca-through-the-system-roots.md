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
  ADR-0091 R19, a required source of keys that keeps the agent not ready.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term Token for the API server, and ADR-0094 R31, which turns off the service-account volume of the Pod and which
  this record keeps. This request deletes ADR-0094 R2, which mounted the cluster CA and which R2 of this record
  replaces, and points the ADR-0094 term Cluster CA at the term of this record.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the requests for the keys of a provider (ADR-0104 R23), whose CA this record decides, and ADR-0104 R6, under which
  a provider file with the member `caFile` stops the start.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  ADR-0105 R2, the provider `kubernetes` in every installation, and ADR-0105 R5, which by default loads the keys of
  that provider from the API server at an in-cluster address.
- [authz-agent-ADR-0101: Run the agent in Docker without Kubernetes](https://github.com/Netcracker/qubership-authz-agent/pull/235),
  proposed in #235: ADR-0101 R4, under which the agent starts and becomes ready on the Docker target as any uid in group
  0 and with a read-only root file system.

## Context

Some servers that the agent calls over HTTPS present certificates that a private CA signs. The Kubernetes API server
presents a certificate that the cluster CA signs. Under `INTERNAL_TLS_ENABLED`, the platform's servers present
certificates that the internal CA signs.

At every start of a container that runs it, the entrypoint of the base image `qubership-core-base` adds the PEM
certificates in the `.crt`, `.cer`, and `.pem` files under `/tmp/cert` to the trust store of the container. It writes
each certificate of a file to a copy named after the base name of that file and the certificate's position in it, such
as `ca_000.crt` and `ca_001.crt`, so of two files with the same name, the file it reads last replaces the copies of the
other, up to the number of certificates it holds. In the base image, uid 10001 and group 0 own
`/usr/local/share/ca-certificates` and `/etc/ssl/certs` and can write to them
([`core-alpine/Dockerfile`](https://github.com/Netcracker/qubership-core-base-images/blob/v2.5.15/images/core-alpine/Dockerfile#L23-L24)),
so the entrypoint can add the CAs for a container that runs as uid 10001 or as any uid in group 0. The chart sets a
read-only root file system on Kubernetes, and ADR-0101 R4 requires the agent to start and become ready under one on the
Docker target. With a read-only root file system, the entrypoint can add the CAs only where writable volumes are mounted
at both paths. A CA it cannot write is left out, and only an `ERROR` line of the entrypoint reports it
([#319](https://github.com/Netcracker/qubership-authz-agent/issues/319#issuecomment-7096026256),
[Netcracker/qubership-core-base-images#387](https://github.com/Netcracker/qubership-core-base-images/issues/387)).

## Decision

We will verify every HTTPS request of the agent against the system roots alone, and the chart will put the cluster CA
and the internal CA into `/tmp/cert`, where the entrypoint of the base image adds them to those roots.

### Terms

- **System roots**: the certificates of the trust store in `/etc/ssl/certs` of the agent's container. The agent trusts
  them for its HTTPS requests: the public CAs that the image ships, and the certificates that the entrypoint of the base
  image adds when the container starts.
- **Cluster CA**: the CA that signs the certificate of the Kubernetes API server. The key `ca.crt` of the ConfigMap
  `kube-root-ca.crt` in the agent's namespace holds it.
- **Internal CA**: the CA that signs the certificates of the platform's servers under `INTERNAL_TLS_ENABLED`. The key
  `ca.crt` of the Secret `<SERVICE_NAME>-tls` in the agent's namespace holds it; `<SERVICE_NAME>` is the chart value
  `SERVICE_NAME`.
- **Provider file**, **provider `kubernetes`**, **Kubernetes token**, **required source**: as ADR-0104 defines them.
- **Token for the API server**, **in-cluster address**: as ADR-0094 defines them.

### Rules

#### The agent

- **R1** (`keys`, `client`, `startup`, `policy`, `chart`). Every HTTPS request that the agent sends verifies the
  server's certificate against the system roots and against no other CA.

#### The chart

- **R2** (`chart`). On Kubernetes, the system roots hold the cluster CA.
- **R3** (`chart`). With `INTERNAL_TLS_ENABLED`, the system roots hold the internal CA, and a missing Secret
  `<SERVICE_NAME>-tls` keeps the Pod from starting.
- **R4** (`chart`). When `CA_CERTIFICATES_SECRET` names a Secret, the system roots hold the PEM certificates in the keys
  of that Secret whose names end in `.crt`, `.cer`, or `.pem`, other than a key named `kubernetes-ca.crt` and, while R3
  applies, a key named `internal-tls-ca.crt`. A value of `CA_CERTIFICATES_SECRET` that names no Secret in the agent's
  namespace keeps the Pod from starting.
- **R5** (`chart`). The chart adds no certificate to the system roots other than those of R2, R3, and R4.

### Implementation notes

Adds no requirement. The chart meets R2 to R5 with one `projected` volume mounted read-only at `/tmp/cert`. The cluster
CA goes there as `kubernetes-ca.crt` and the internal CA as `internal-tls-ca.crt`, the two names that R4 leaves out of
the Secret of `CA_CERTIFICATES_SECRET`. That Secret comes first among the sources, because a later source takes the
path of an earlier one. In kind with the base image `alpine-2.5.15`, a Pod with the three sources loaded keys from the
API server and from a server whose certificate a test internal CA signed, with no CA setting in the agent (#319). That
Pod listed the Secret standing in for `CA_CERTIFICATES_SECRET` last, where this template lists it first. Another Pod
showed that a later source takes the path of an earlier one.

```yaml
        - name: tmp-cert
          projected:
            defaultMode: 292
            sources:
              {{- if .Values.CA_CERTIFICATES_SECRET }}
              - secret:
                  name: '{{ .Values.CA_CERTIFICATES_SECRET }}'
              {{- end }}
              - configMap:
                  name: kube-root-ca.crt
                  items:
                    - key: ca.crt
                      path: kubernetes-ca.crt
              {{- if .Values.INTERNAL_TLS_ENABLED }}
              - secret:
                  name: '{{ .Values.SERVICE_NAME }}-tls'
                  items:
                    - key: ca.crt
                      path: internal-tls-ca.crt
              {{- end }}
```

The image meets R2 to R4 only by running the agent behind the entrypoint of the base image (#250). The entrypoint has to
be able to write `/usr/local/share/ca-certificates` and `/etc/ssl/certs`, since a CA it cannot write fails R2, R3, or
R4, so under the chart's read-only root file system the Pod mounts an `emptyDir` volume at each of the two paths. A
service-account volume at `/var/run/secrets/kubernetes.io/serviceaccount` would fail R4, because the entrypoint also
reads that directory, and its `ca.crt` takes the place of a key `ca.crt` of the Secret of `CA_CERTIFICATES_SECRET`. The
values comment on `CA_CERTIFICATES_SECRET` is the place to name the two keys that R4 leaves out, and the comments on
`CA_CERTIFICATES_SECRET` and `INTERNAL_TLS_ENABLED` the place to say to recreate the Pod after a CA is added or removed,
since a restart of the container can leave a removed CA trusted.

In the agent, R1 removes the field `caFile` of a provider (`Provider.CAFile` in `internal/token/keys` on main) and the
`tls.Config` that `fetch.go` builds from it, unless #201, whose provider files have no such member, removes them first.
A request keeps the `tls.Config` of the default transport.

Checks to add with the chart change: `test/scripts/test-chart-render.sh` renders the chart with and without
`INTERNAL_TLS_ENABLED` and `CA_CERTIFICATES_SECRET`. It asserts the sources of the volume with the Secret of
`CA_CERTIFICATES_SECRET` first among them, and that the agent's Pod sets `automountServiceAccountToken: false` and
mounts no volume under `/var/run/secrets/kubernetes.io/serviceaccount`, the check for the service-account case of R4.
The kind e2e installs with `--wait`, and the provider `kubernetes` keeps the agent not ready until its keys load, so the
install fails when the cluster CA is missing from the system roots. One run with the `kube-root-ca.crt` source removed
shows that failure.

### Justification

One set of CAs serves every request and every target, so the code holds no CA setting per request, and a PIP, the policy
source, and tenant-manager trust a private CA the same way as Keycloak and the API server (R1). The platform's images
take a private CA through `/tmp/cert`, so the chart puts the CAs of R2, R3, and R4 there.

The chart writes the provider `kubernetes` in every installation (ADR-0105 R2), so the agent accepts Kubernetes tokens
in every installation on Kubernetes. That provider loads its keys from the API server at an in-cluster address by
default (ADR-0105 R5), and always while the Pod holds the token for the API server (ADR-0104 R28). The cluster CA signs
the certificate of the API server, so every installation on Kubernetes gets the cluster CA (R2). An installation whose
values move the keys away from the API server gets it too, and every HTTPS request there trusts the cluster CA, a cost
the Negative consequences accept. The ConfigMap `kube-root-ca.crt` is in every namespace and holds the CA that the
service-account volume of a Pod gets, so the agent needs no service-account volume, which ADR-0094 R31 turns off (R2).

The Secret `<SERVICE_NAME>-tls` also holds `tls.crt`, a certificate of one service rather than a CA, and the entrypoint
adds every `.crt` file it finds (R3, R5). The chart puts the cluster CA and the internal CA in `/tmp/cert` as
`kubernetes-ca.crt` and `internal-tls-ca.crt`. Because the entrypoint names its copies after the base name of the file
it read, a key of the Secret of `CA_CERTIFICATES_SECRET` with one of those names would take the place of that CA,
and the agent could no longer verify the API server or the platform's servers. So the chart's CA wins, and only a key
with one of those two names is left out (R4, R5).

### Alternatives considered

- **A1. Name a CA per request: `keycloak.caFile`, a `caFile` per provider, a file with the cluster CA, and the CA in
  `CERTIFICATE_FILE_PATH` read by the agent.** Rejected by R1: each kind of request would need a CA setting of its own,
  and the PIPs have none.
- **A2. Mount the cluster CA in a projected service-account volume at
  `/var/run/secrets/kubernetes.io/serviceaccount`, which the entrypoint also reads.** Rejected by R4: its `ca.crt`
  takes the place of a key `ca.crt` of the Secret of `CA_CERTIFICATES_SECRET` in the trust store (#319), and the volume
  adds back what ADR-0094 R31 turns off.
- **A4. Mount every key of the Secret `<SERVICE_NAME>-tls` under `/tmp/cert` with `INTERNAL_TLS_ENABLED`.** Rejected by
  R5: the entrypoint would add `tls.crt`, the certificate of one service, to the system roots. An operator who names
  that Secret in `CA_CERTIFICATES_SECRET` gets `tls.crt` under R4.
- **A5. List the Secret of `CA_CERTIFICATES_SECRET` last among the projected sources, so that its key replaces the
  chart's file of the same name.** Rejected by R2 and R5: a key named `kubernetes-ca.crt` would replace the cluster CA,
  and the agent could no longer verify the API server.

## Consequences

Negative:

- On Kubernetes, every HTTPS request of the agent trusts the cluster CA, not only the request to the API server. A
  certificate that the cluster CA issues for any other host that the agent calls passes verification on the agent's
  requests to that host.
- The requests that carry the token for the API server trust every CA of the system roots, not the cluster CA alone. A
  certificate for `kubernetes.default.svc` that the internal CA or a CA of `CA_CERTIFICATES_SECRET` issues passes
  verification, and its holder can receive that token.
- A CA added to a mounted Secret or ConfigMap is trusted only after the container starts again. The entrypoint builds
  the trust store at the start of the container, and the Go standard library loads the system roots once per process
  ([`root.go`](https://github.com/golang/go/blob/go1.27.4/src/crypto/x509/root.go#L36-L37)).
- A CA whose key is removed from a mounted Secret or ConfigMap stays trusted until the Pod is recreated, as by
  `kubectl rollout restart`. When a bundle loses certificates, its copies past the new length stay trusted too,
  whichever of its certificates was removed. The entrypoint never deletes a copy, so a restart of the container replaces
  only the copies whose names the current files still produce, and the copies live in the `emptyDir` volume at
  `/usr/local/share/ca-certificates`, which outlives that restart
  ([Netcracker/qubership-core-base-images#388](https://github.com/Netcracker/qubership-core-base-images/issues/388)).
- Nothing reports a key of the Secret of `CA_CERTIFICATES_SECRET` that R4 leaves out.
- A CA that the entrypoint cannot write breaks R2, R3, or R4, and at start only the entrypoint's `ERROR` line reports
  it. Later, requests to servers whose certificates that CA signed fail verification, and a required source of keys
  keeps the agent not ready (ADR-0091 R19).

Follow-ups:

- #235 adds the layers `image` and `docker` to the reading guide. An `ENV` in the image or a setting of the Compose
  example can change the CAs a request trusts, and an image that does not run the base image's entrypoint breaks R2 to
  R4. So whichever of #235 and this change merges second adds both tags to R1 and the tag `image` to R2 to R4, and links
  the two records to each other's files under Related ADRs.
- The section on trusting a private CA that #250 adds to `components/authz-agent/README.md` names the three sources of
  R2 to R4.

## Open points

- **O1.** Who creates the Secret `<SERVICE_NAME>-tls` for the agent under `INTERNAL_TLS_ENABLED`? The agent serves no
  TLS itself. One answer: the platform creates the Secret for every service of an installation with
  `INTERNAL_TLS_ENABLED`, and R3 stands as written. The other: nothing creates it for the agent, and a chart value names
  the Secret that holds the internal CA instead of `<SERVICE_NAME>-tls`. A projected source that names a missing Secret
  keeps the Pod from starting (#319). The architect (`mr-joom`) decides. It affects R3 and the term Internal CA.
- **O2.** R2 to R5 assume that the cluster CA and the internal CA win when a key of the Secret of
  `CA_CERTIFICATES_SECRET` is named `kubernetes-ca.crt` or `internal-tls-ca.crt`. The other answer, A5, lets the key of
  that Secret win. The architect (`mr-joom`) decides. It affects R2 to R5.
