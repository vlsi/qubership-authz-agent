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
  the requests to Keycloak, whose CA this record moves to the system roots: ADR-0091 R2 and R72, which A1 reverses;
  ADR-0091 R19, a required source of keys that keeps the agent not ready.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the requests to the API server, whose cluster CA this record moves to the system roots: ADR-0094 R27, which A1
  reverses; ADR-0094 R31 stays.
- [authz-agent-ADR-0101: Run the agent in Docker without Kubernetes](https://github.com/Netcracker/qubership-authz-agent/pull/235),
  proposed in #235: the Docker target; ADR-0101 R4, the restrictions on the agent's container there, under which R6
  holds.

## Context

Some servers that the agent calls over HTTPS present certificates that a private CA signs. The Kubernetes API server
presents a certificate that the cluster CA signs. Under `INTERNAL_TLS_ENABLED`, the platform's servers present
certificates that the internal CA signs.

At every start of a container that runs it, the entrypoint of the base image `qubership-core-base` adds the PEM
certificates in the `.crt`, `.cer`, and `.pem` files under `/tmp/cert` to the trust store of the container. It names
each file it adds after the base name of the file it read, so two files with the same name leave one CA in the trust
store. A CA it cannot write is left out, and only an `ERROR` line of the entrypoint reports it
([#319](https://github.com/Netcracker/qubership-authz-agent/issues/319#issuecomment-7096026256),
[Netcracker/qubership-core-base-images#387](https://github.com/Netcracker/qubership-core-base-images/issues/387)).

## Decision

We will verify every HTTPS request of the agent against the system roots alone. On every target the agent's image adds
the CAs under `/tmp/cert` to those roots, and the chart puts the cluster CA and the internal CA there.

### Terms

- **System roots**: the certificates of the trust store in `/etc/ssl/certs` of the agent's container. The agent trusts
  them for its HTTPS requests: the public CAs that the image ships, and the certificates that the entrypoint of the base
  image adds when the container starts.
- **Cluster CA**: the CA that signs the certificate of the Kubernetes API server. The key `ca.crt` of the ConfigMap
  `kube-root-ca.crt` in the agent's namespace holds it.
- **Internal CA**: the CA that signs the certificates of the platform's servers under `INTERNAL_TLS_ENABLED`. The key
  `ca.crt` of the Secret `<SERVICE_NAME>-tls` in the agent's namespace holds it; `<SERVICE_NAME>` is the chart value
  `SERVICE_NAME`.

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

#### The image

- **R6** (`image`). When a container of the agent's image starts as any uid in group 0, the system roots gain the PEM
  certificates in the `.crt`, `.cer`, and `.pem` files under `/tmp/cert`, also with a read-only root file system and all
  Linux capabilities dropped. Of two such files with the same name, in any directories under `/tmp/cert`, the system
  roots gain the certificates of one.

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

The entrypoint has to be able to write `/usr/local/share/ca-certificates` and `/etc/ssl/certs`, since a CA it cannot
write fails R2, R3, R4, or R6. A service-account volume at `/var/run/secrets/kubernetes.io/serviceaccount` would fail
R4, because the entrypoint also reads that directory, and its `ca.crt` takes the place of a key `ca.crt` of the Secret
of `CA_CERTIFICATES_SECRET`. The values comment on `CA_CERTIFICATES_SECRET` is the place to name the two keys that R4
leaves out, and the comments on `CA_CERTIFICATES_SECRET` and `INTERNAL_TLS_ENABLED` the place to say that a changed CA
is trusted after the Pod restarts.

In the agent, R1 removes the field `caFile` of a provider (`Provider.CAFile` in `internal/token/keys`) and the
`tls.Config` that `fetch.go` builds from it, and, on the branches of the token packages, `keycloak.caFile`
(`Keycloak.CAFile`, #201), `clusterCAFile`, and `Options.InternalCAFile` (#159). A request keeps the `tls.Config` of
the default transport.

Checks to add with the chart change: `test/scripts/test-chart-render.sh` renders the chart with and without
`INTERNAL_TLS_ENABLED` and `CA_CERTIFICATES_SECRET`. It asserts the sources of the volume with the Secret of
`CA_CERTIFICATES_SECRET` first among them, and that the agent's Pod sets `automountServiceAccountToken: false` and
mounts no volume under `/var/run/secrets/kubernetes.io/serviceaccount`, the check for the service-account case of R4.
The kind e2e installs with `--wait`, and the provider `kubernetes` keeps the
agent not ready until its keys load, so the install fails when the cluster CA is missing from the system roots. One
run with the `kube-root-ca.crt` source removed shows that failure.

The image meets R6 by running the agent behind the entrypoint of the base image (#250). On Kubernetes the kind e2e shows
it, and on the Docker target the CI case of #239 that calls a server whose certificate a CA under `/tmp/cert` signed.

### Justification

One set of CAs serves every request and every target, so the code holds no CA setting per request, and a PIP, the policy
source, and tenant-manager trust a private CA the same way as Keycloak and the API server (R1). The platform's images
take a private CA through `/tmp/cert`, so the agent's image does the same on every target (R6). R6 holds under the
restrictions that the chart and ADR-0101 R4 ([#235](https://github.com/Netcracker/qubership-authz-agent/pull/235)) place
on the agent's container.

The agent accepts M2M tokens from Kubernetes in every installation on Kubernetes, as agreed in the review of this
record
([#330](https://github.com/Netcracker/qubership-authz-agent/pull/330#discussion_r4667182029)).
Whether their keys come from the API server of the cluster depends on the cluster's issuer, and the chart cannot read
the issuer when it renders. So every installation on Kubernetes gets the cluster CA (R2). The ConfigMap
`kube-root-ca.crt` is in every namespace and holds the CA that the service-account volume of a Pod gets, so the agent
needs no service-account volume, which ADR-0094 R31 turns off (R2).

The Secret `<SERVICE_NAME>-tls` also holds `tls.crt`, a certificate of one service rather than a CA, and the entrypoint
adds every `.crt` file it finds (R3, R5). The chart puts the cluster CA and the internal CA in `/tmp/cert` as
`kubernetes-ca.crt` and `internal-tls-ca.crt`. Because the entrypoint names each file it adds after the base name of the
file it read, a key of the Secret of `CA_CERTIFICATES_SECRET` with one of those names would take the place of that CA,
and the agent could no longer verify the API server or the platform's servers. So the chart's CA wins, and only a key
with one of those two names is left out (R4, R5).

### Alternatives considered

- **A1. Name a CA per request: `keycloak.caFile`, a `caFile` per provider, a file with the cluster CA, and the CA in
  `CERTIFICATE_FILE_PATH` read by the agent.** Rejected by R1. This reverses ADR-0091 R2 and R72 and ADR-0094 R27:
  each kind of request needed a CA setting of its own, and the PIPs had none.
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
- A CA added or replaced in a mounted Secret or ConfigMap is trusted only after the Pod restarts. The entrypoint builds
  the trust store at the start of the container, and the Go standard library loads the system roots once per process
  ([`root.go`](https://github.com/golang/go/blob/go1.27.4/src/crypto/x509/root.go#L36-L37)).
- Nothing reports a key of the Secret of `CA_CERTIFICATES_SECRET` that R4 leaves out.
- A CA that the entrypoint cannot write breaks R2, R3, R4, or R6, and at start only the entrypoint's `ERROR` line
  reports it. Later, requests to servers whose certificates that CA signed fail verification, and a required source of
  keys keeps the agent not ready (ADR-0091 R19).

Follow-ups:

- #235 adds the layers `image` and `docker` to the reading guide, and R6 names `image` already. An `ENV` in the image or
  a setting of the Compose example can change the CAs a request trusts, and an image that does not run the base image's
  entrypoint breaks R2 to R4 and R6. So whichever of #235 and this change merges second adds both tags to R1, the tag
  `docker` to R6, and the tag `image` to R2 to R4, and links the two records to each other's files under Related ADRs.
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
