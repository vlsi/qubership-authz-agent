# qubership-authz-agent

An OPA-based authorization service for Kubernetes.  The deliverable is a
**Helm chart** that assembles the agent Pod: one container, `authz-agent`, a Go
service carrying the policy engine as a library, the check API, and the loops
that feed the engine (authz-agent-ADR-0080).  See
[`components/authz-agent/README.md`](components/authz-agent/README.md).

`authz-policy-admin`, the primary policy source, is a service of its own with
its own chart, `helm-templates/authz-policy-admin`: a Deployment with its
Service and PersistentVolumeClaim.  Its image name has no `authz-agent-` prefix
because it is not a container of the agent Pod.

## Maturity

**Pre-1.0, no releases yet.**  The component has no published release and no
stable API commitment.  The access-control-compatible API surface — the legacy
check endpoints the agent translates — is deliberately partly unimplemented:
only the paths that the test suites exercise are wired.  The deployment assumes
a Kubernetes cluster running the Netcracker platform (Keycloak realm structure,
M2M credential provisioning, optional service-mesh route registration).  A
team deploying this without the platform will need to supply their own identity
provider and adjust the Helm values accordingly.

## Policy source

[`authz-policy-admin`](components/authz-policy-admin/README.md) is the
supported policy source.  Install its chart beside the agent's, point the
agent's `AUTHZ_PAP_CLIENT_SOURCE_URL` at its Service
(`http://authz-policy-admin:18090` with the chart's defaults), and load
simplified policies and PIPs over its unauthenticated HTTP API.

Pulling policies from the platform's access-control service is also supported:
set `AUTHZ_PAP_CLIENT_SOURCE_URL` to the access-control service URL.  When
that is set, `authz-policy-admin` is not needed.

## Charts

The agent's chart is at `helm-templates/authz-agent/` and the policy source's
at `helm-templates/authz-policy-admin/`.

```sh
helm template helm-templates/authz-agent
helm template helm-templates/authz-policy-admin
```

## Building images

Each image has its own Dockerfile under `build/`:

```sh
# Build an image locally
docker build -t authz-agent:local        -f build/authz-agent/Dockerfile .
docker build -t authz-policy-admin:local -f build/authz-policy-admin/Dockerfile .
```

CI builds them, together with the test images and the transfer image of the charts, from the component list in
`.github/docker-dev-config.json`.

## Testing

See `test/BASELINE.md` for recorded baseline results.  All suites below were
verified from a clean clone on public images.

### Prerequisites

- Go 1.24+
- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa) (for Rego tests; also installable via `bash test/scripts/install-opa.sh`)
- Docker, `kind`, and `kubectl` (for the integration and parity suites, which run on kind)
- Docker Compose (for the load suite only)
- `helm` (for chart render test)

### Unit tests — Go

```sh
# Root module (four binaries + shared packages): 249 tests
go test -count=1 ./...

# Parity replay module
cd test/parity/suite && go test -count=1 ./...

# Integration testify module (non-integration tests only without a running stack)
cd test/integration/testify && go test -count=1 ./...

# Pip-stub module
cd test/integration/pipstub && go test -count=1 ./...
```

### Unit tests — Rego

```sh
# 352 policy tests
opa test policies/
```

### Chart render

```sh
bash test/scripts/test-chart-render.sh
```

### Integration test suite

Runs the Testify suite as a Job inside a kind cluster, against the Helm chart.
This is the check CI runs (`.github/workflows/integration-tests.yaml`).
Requires Docker, `kind`, `kubectl`, and `helm`.

```sh
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # container logs, events, decision logs into test/artifacts/kind/
make e2e-down     # delete the cluster
```

Expected: 20 groups pass, including the two catalog coverage checks. See
[test/k8s/README.md](test/k8s/README.md) for the individual targets and
[docs/local-integration-tests.md](docs/local-integration-tests.md) for a
walkthrough from a clean machine.

### Parity replay

Replays recorded HTTP requests against the agent and compares responses against
golden files captured from the legacy access-control service.  The goldens are
a frozen capture; they cannot be regenerated from this repository (see
`test/parity/README.md`).

```sh
make parity        # harness, chart, suite in namespace authz-parity
make parity-logs   # artifacts into test/artifacts/kind/parity/
```

Expected: 135/135 PASS. This is what CI runs (job `Parity on kind`).

## Development

After cloning, enable the bundled pre-commit hook so every commit is linted
with the same tools and configuration the CI uses (`.github/linters/`):

```sh
make install-hooks
```

`make lint` runs the same checks over the whole tree. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.
