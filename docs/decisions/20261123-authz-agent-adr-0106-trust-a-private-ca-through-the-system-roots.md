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
  this record replaces ADR-0091 R2, the CA of the requests to Keycloak, and the part of ADR-0091 R72 that set
  `keycloak.caFile` from `CERTIFICATE_FILE_PATH`, together with the field `caFile` that ADR-0091 R73 and R6 listed.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R11, the M2M modes.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  this record replaces the term Cluster CA of ADR-0094, the cluster CA in ADR-0094 R2 and R7, the CA in ADR-0094 R9,
  and ADR-0094 R27. ADR-0094 R31, the Pod without an automounted service-account token, stays.

## Context

The agent sends HTTPS requests to the Kubernetes API server for its keys in the M2M modes `hybrid` and `k8s`
(ADR-0094), and to Keycloak, the policy source, tenant-manager, and the PIPs. The API server presents a certificate
signed by the cluster CA. Under `INTERNAL_TLS_ENABLED` the platform's servers present certificates signed by the
platform's internal CA, which the platform's service charts mount from the Secret `<SERVICE_NAME>-tls` into the
directory that `CERTIFICATE_FILE_PATH` names. Neither CA is among the public CAs of the image.

The agent's image is built on `qubership-core-base`. In a container that runs the entrypoint of that image, the
entrypoint adds each `.crt`, `.cer`, and `.pem` file under `/tmp/cert`, and under
`/var/run/secrets/kubernetes.io/serviceaccount` where that directory exists, to the trust store in `/etc/ssl/certs`. It
does so at every start of the container and as the container's user. It names the file it adds after the base name of
the file it read, so two files with the same name in those directories leave one CA in the trust store. When it cannot
write a CA into the trust store, it logs an `ERROR` line that calls the data format of the source file invalid, and the
command it starts runs without that CA
([#319](https://github.com/Netcracker/qubership-authz-agent/issues/319#issuecomment-7096026256),
[Netcracker/qubership-core-base-images#387](https://github.com/Netcracker/qubership-core-base-images/issues/387)). The
Docker target delivers a private CA through `/tmp/cert` too (ADR-0101 R19 in
[#235](https://github.com/Netcracker/qubership-authz-agent/pull/235)).

## Decision

We will verify every HTTPS request of the agent against the system roots alone, and the chart will put the cluster CA
and the internal CA into `/tmp/cert`, where the entrypoint of the base image adds them to those roots.

### Terms

- **System roots**: the CA certificates of the trust store in `/etc/ssl/certs` of the agent's container.
- **Cluster CA**: the value of the key `ca.crt` of the ConfigMap `kube-root-ca.crt` in the agent's namespace.
- **Internal CA**: the value of the key `ca.crt` of the Secret `<SERVICE_NAME>-tls` in the agent's namespace, where
  `<SERVICE_NAME>` is the chart value `SERVICE_NAME`.

### Rules

#### The agent

- **R1** (`keys`, `client`, `startup`, `policy`, `chart`). Every HTTPS request that the agent sends verifies the
  server's certificate against the system roots and against no other CA.

#### The chart

- **R2** (`chart`). In the M2M modes `hybrid` and `k8s`, the agent's container holds the cluster CA as
  `/tmp/cert/kubernetes-ca.crt`.
- **R3** (`chart`). With `INTERNAL_TLS_ENABLED`, the agent's container holds the internal CA as
  `/tmp/cert/internal-tls-ca.crt`, and a missing Secret `<SERVICE_NAME>-tls` keeps the Pod from starting.
- **R4** (`chart`). When `CA_CERTIFICATES_SECRET` names a Secret, the agent's container holds the value of each key of
  that Secret as a file in `/tmp/cert` named after the key. Where R2 applies, a key named `kubernetes-ca.crt` is
  dropped, and where R3 applies, a key named `internal-tls-ca.crt` is dropped. A value of `CA_CERTIFICATES_SECRET` that
  names no Secret in the agent's namespace keeps the Pod from starting.
- **R5** (`chart`). The chart puts no file under `/tmp/cert` other than the files of R2, R3, and R4, and no file under
  `/var/run/secrets/kubernetes.io/serviceaccount`.

### Implementation notes

Adds no requirement. The chart meets R2 to R5 with one `projected` volume mounted read-only at `/tmp/cert`, rendered
when it has at least one source. The Secret of `CA_CERTIFICATES_SECRET` comes first among the sources, because a later
source takes the path of an earlier one. In kind with the base image `alpine-2.5.15`, a Pod with the three sources
loaded keys from the API server and from a server whose certificate a test internal CA signed, with no CA setting in the
agent (#319). That Pod listed the Secret standing in for `CA_CERTIFICATES_SECRET` last, where this template lists it
first. Another Pod showed that a later source takes the path of an earlier one. The template lowers the mode, because
ADR-0092 R15 reads it without regard to case:

```yaml
{{- $clusterCA := has (.Values.M2M_AUTH_MODE | default "" | lower) (list "hybrid" "k8s") }}
{{- if or $clusterCA .Values.INTERNAL_TLS_ENABLED .Values.CA_CERTIFICATES_SECRET }}
        - name: tmp-cert
          projected:
            defaultMode: 292
            sources:
              {{- if .Values.CA_CERTIFICATES_SECRET }}
              - secret:
                  name: '{{ .Values.CA_CERTIFICATES_SECRET }}'
              {{- end }}
              {{- if $clusterCA }}
              - configMap:
                  name: kube-root-ca.crt
                  items:
                    - key: ca.crt
                      path: kubernetes-ca.crt
              {{- end }}
              {{- if .Values.INTERNAL_TLS_ENABLED }}
              - secret:
                  name: '{{ .Values.SERVICE_NAME }}-tls'
                  items:
                    - key: ca.crt
                      path: internal-tls-ca.crt
              {{- end }}
{{- end }}
```

The values comment on `CA_CERTIFICATES_SECRET` is the place to name the two file names of R2 and R3, and the comments
on `CA_CERTIFICATES_SECRET` and `INTERNAL_TLS_ENABLED` the place to say that a changed CA is trusted after the Pod
restarts.

In the agent, R1 removes the field `caFile` of a provider (`Provider.CAFile` in `internal/token/keys`) and the
`tls.Config` that `fetch.go` builds from it, and, on the branches of the token packages, `keycloak.caFile`
(`Keycloak.CAFile`, #201), `clusterCAFile`, and `Options.InternalCAFile` (#159). A request keeps the `tls.Config` of
the default transport.

Checks to add with the chart change: `test/scripts/test-chart-render.sh` renders the chart in each M2M mode, with and
without `INTERNAL_TLS_ENABLED` and `CA_CERTIFICATES_SECRET`. It asserts the sources of the volume with the Secret of
`CA_CERTIFICATES_SECRET` first among them, and that no volume is mounted under
`/var/run/secrets/kubernetes.io/serviceaccount`. The kind e2e in `hybrid` or `k8s` installs with `--wait`, and the
provider `kubernetes` keeps the agent not ready until its keys load, so the install fails when the cluster CA is
missing from the system roots. One run with the `kube-root-ca.crt` source removed shows that failure.

### Justification

One set of CAs serves every request and every target, so the code holds no CA setting per request, and a PIP, the
policy source, and tenant-manager trust a private CA the same way as Keycloak and the API server (R1). The platform's
images take a private CA through `/tmp/cert`, and the Docker target uses the same directory.

The ConfigMap `kube-root-ca.crt` is in every namespace and holds the CA that the service-account volume of a Pod gets,
so the agent needs no service-account volume, which ADR-0094 R31 turns off (R2, R5). In `legacy` the agent sends no
request to the API server, so the cluster CA in the container would only add a CA that every request trusts (R2, R5).

The Secret `<SERVICE_NAME>-tls` also holds `tls.crt`, a certificate of one service rather than a CA, and the entrypoint
adds every `.crt` file it finds (R3, R5). The entrypoint names each file it adds after the base name of the file it
read, so the cluster CA and the internal CA get file names of their own (R2, R3). A key of the Secret of
`CA_CERTIFICATES_SECRET` with one of those names would otherwise take the place of the cluster CA or the internal CA,
and the agent could no longer verify the API server or the platform's servers. So the chart's file wins, and only a key
with one of the names of R2 and R3 is dropped (R4).

### Alternatives considered

- **A1. Name a CA per request: `keycloak.caFile`, a `caFile` per provider, a file with the cluster CA, and the CA in
  `CERTIFICATE_FILE_PATH` read by the agent.** Rejected by R1. This reverses ADR-0091 R2 and R72 and ADR-0094 R27:
  each kind of request needed a CA setting of its own, and the PIPs had none.
- **A2. Mount the cluster CA in a projected service-account volume at
  `/var/run/secrets/kubernetes.io/serviceaccount`, which the entrypoint also reads.** Rejected by R5. The volume adds
  back what ADR-0094 R31 turns off, and its `ca.crt` takes the place of any other `ca.crt` under `/tmp/cert` in the
  trust store (#319).
- **A3. Mount the ConfigMap `kube-root-ca.crt` under `/tmp/cert` in every M2M mode.** Rejected by R5: in `legacy` no
  request needs the cluster CA. An operator who names a Secret with that CA in `CA_CERTIFICATES_SECRET` gets it under
  R4.
- **A4. Mount every key of the Secret `<SERVICE_NAME>-tls` under `/tmp/cert` with `INTERNAL_TLS_ENABLED`.** Rejected by
  R5: the entrypoint would add `tls.crt`, the certificate of one service, to the system roots. An operator who names
  that Secret in `CA_CERTIFICATES_SECRET` gets every key under R4.
- **A5. List the Secret of `CA_CERTIFICATES_SECRET` last among the projected sources, so that its key replaces the
  chart's file of the same name.** Rejected by R2 and R4: a key named `kubernetes-ca.crt` would replace the cluster CA,
  and the agent could no longer verify the API server.

## Consequences

Negative:

- In `hybrid` and `k8s` every HTTPS request of the agent trusts the cluster CA, not only the request to the API server.
  A certificate that the cluster CA issues for any other host that the agent calls passes verification on the agent's
  requests to that host.
- The requests that carry the token for the API server trust every CA of the system roots, not the cluster CA alone. A
  certificate for `kubernetes.default.svc` that the internal CA or a CA of `CA_CERTIFICATES_SECRET` issues passes
  verification, and its holder can receive that token.
- A CA added or replaced in a mounted Secret or ConfigMap is trusted only after the Pod restarts. The entrypoint builds
  the trust store at the start of the container, and the Go standard library loads the system roots once per process
  ([`root.go`](https://github.com/golang/go/blob/go1.27.4/src/crypto/x509/root.go#L36-L37)).
- A key named `kubernetes-ca.crt` or `internal-tls-ca.crt` in the Secret of `CA_CERTIFICATES_SECRET` is dropped while
  the chart puts its own file of that name there, and nothing reports it (R4).
- A CA that the entrypoint cannot write is missing from the system roots. At start only the entrypoint's `ERROR` line
  reports it. Later, requests to servers whose certificates that CA signed fail verification, and a required source of
  keys keeps the Pod not ready (ADR-0091 R19).

Follow-ups:

- ADR-0101 R19 in #235 loses its last sentence, on `keycloak.caFile`, and its entry for ADR-0091 R2 under Related
  ADRs. #235 also adds the layers `image` and `docker` to the reading guide. An `ENV` in the image or a setting of the
  Compose example can change the CAs a request trusts, so whichever of #235 and this change merges second adds both
  tags to R1.
- #265 rewrites ADR-0094 R9 and keeps "and its CA" and the `caFile` line of its example. It also rewrites the range of
  ADR-0094 rules under Related ADRs of ADR-0091 as "R26 to R32". Whichever of #265 and this change merges second
  removes the first two and writes the range as "R26 and R28 to R32".
- The section on trusting a private CA that #250 adds to `components/authz-agent/README.md` names the three sources of
  R2 to R4.

## Open points

- **O1.** Who creates the Secret `<SERVICE_NAME>-tls` for the agent under `INTERNAL_TLS_ENABLED`? The agent serves no
  TLS itself. One answer: the platform creates the Secret for every service of an installation with
  `INTERNAL_TLS_ENABLED`, and R3 stands as written. The other: nothing creates it for the agent, and a chart value names
  the Secret that holds the internal CA instead of `<SERVICE_NAME>-tls`. A projected source that names a missing Secret
  keeps the Pod from starting (#319). The architect (`mr-joom`) decides. It affects R3 and the term Internal CA.
- **O2.** R4 assumes that the chart's file wins when a key of the Secret of `CA_CERTIFICATES_SECRET` has the name of the
  file of R2 or R3. The other answer, A5, lets the key of that Secret win. The architect (`mr-joom`) decides. It
  affects R2, R3, and R4.
