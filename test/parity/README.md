# Parity Test Suite

The parity suite replays 129 captured test cases against the authz-agent and
compares the answers with golden files recording how the legacy access-control
service answered the same requests.

## What the goldens are

The JSON files under [`suite/testdata/golden/`](suite/testdata/golden/) are a
**frozen capture** of the legacy `access-control` service's behaviour. They
were recorded against a running instance of the legacy service (which is not
part of this repository) and committed as the reference baseline.

They cannot be regenerated from this repository. If you change authz-agent
behaviour in a way that alters the answers to these cases, the affected
goldens must be updated by hand (or the divergence recorded in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
rationale). The goldens are evidence of which cases the authz-agent matches
the legacy service on; they are not a test oracle that can be refreshed
without access to the original service.

## Prerequisites

1. **Docker**, **kind**, **kubectl**, and **helm** on the host, in the versions
   [docs/local-integration-tests.md](../../docs/local-integration-tests.md#2-prerequisites) names.
2. **Go 1.24+** to run the suite module's own unit tests (`cd test/parity/suite && go test ./...`).

## Run the replay suite

```bash
make parity        # cluster, images, harness, chart, suite in namespace authz-parity
make parity-logs   # artifacts into test/artifacts/kind/parity/
```

`make parity` runs the shared `e2e-cluster` and `e2e-images` targets first (every image the replay needs, including
the suite image built from [`suite/Dockerfile`](suite/Dockerfile)), then:

| Target | What it does |
| --- | --- |
| `parity-harness` | The test-stand chart with [`test/k8s/parity/test-stand-values.yaml`](../k8s/parity/test-stand-values.yaml) in namespace `authz-parity`: Keycloak as `idp` in dev mode with the parity realms; `pip-mock`; `entitlements-mock`; the M2M client-credentials Secret |
| `parity-install` | `helm upgrade --install` of the stub chart with its dev resource profile and [`test/k8s/parity/policy-admin-values.yaml`](../k8s/parity/policy-admin-values.yaml), then of the agent chart with its dev resource profile and [`test/k8s/parity/values.yaml`](../k8s/parity/values.yaml) |
| `parity-suite` | The suite Job of the test-stand release, run by `helm test`; its log is streamed |

Expected result: 135/135 cases green against authz-agent. CI runs the same targets (job `Parity on kind` in
`.github/workflows/integration-tests.yaml`).

The suite addresses `authz-agent`, `idp`, `pip-mock`, and `entitlements-mock` by Service name; nothing is published on
the host. To look at the stack from the host, port-forward, for example
`kubectl --context kind-authz-e2e -n authz-parity port-forward svc/authz-agent 28100:8080`.

### Iterating

After a change to the suite, `make e2e-images parity-suite` rebuilds the images and reruns the Job; the harness and
the chart stay. After a change to the product, run `make e2e-images parity-restart parity-suite`: the images keep their
tags, so the running Pods have to be restarted to pick the new build up. `make parity-install parity-suite` picks up
changed values of the agent and authz-policy-admin charts; changed test-stand values, the suite's env and args
included, take `make parity-harness parity-suite`.

### Teardown

```bash
kubectl --context kind-authz-e2e delete namespace authz-parity   # the replay only
make e2e-down                                                     # the whole cluster
```

## Identity provider

The `idp` Deployment runs the public Keycloak image (`quay.io/keycloak/keycloak`, the version the goldens were captured
against) and imports the realms of [`cloud-common-realm.json`](../k8s/parity/idp-seed/cloud-common-realm.json),
[`parity-realm.json`](../k8s/parity/idp-seed/parity-realm.json), and
[`parity-mt-b-realm.json`](../k8s/parity/idp-seed/parity-mt-b-realm.json) at every start. The `parity` realm it imports
also holds the users of [`suite/testdata/realm/`](suite/testdata/realm/README.md), so the cases that need those users
run on the kind harness. `make test-stand-files` adds them and gives them the first name, last
name, and email they have on the stand the goldens were recorded on: their files declare none, and Keycloak refuses a
password grant to such a user with `Account is not fully set up`. The realm files use only built-in Keycloak protocol
mappers and require no custom SPI extensions. The suite calls the standard OIDC token endpoint
(`/auth/realms/parity/protocol/openid-connect/token`) for `client_credentials` and `password` grants; no custom Keycloak
REST APIs are involved.

The chart sets `KC_HTTP_RELATIVE_PATH=/auth` so the realm is reachable at `/auth/realms/parity/...` (Keycloak dropped
the `/auth` prefix in v17; the parity fixtures carry that prefix throughout, so it is restored via config). It prefixes
the management endpoints too, which is why the probes hit `/auth/health/ready`.

## Goldens, accepted divergences, and the divergence backlog

The 129 committed goldens represent the legacy service's answers. The
authz-agent is expected to match all of them; cases where it intentionally
differs are listed in
[`suite/accepted_divergences.go`](suite/accepted_divergences.go) with a
recorded rationale (decision ID + reason string).

When authz-agent behaviour changes in a way that affects a previously-green
case:

- If the new behaviour is correct (i.e. the legacy answer was a bug): add an
  entry to `accepted_divergences.go` with the rationale.
- If the new behaviour is a regression: fix the regression.
- The golden files themselves should not be edited — they are the record of
  what the legacy service did, not a living test spec.

## Directory layout

```text
test/parity/
├── README.md                            (this file)
└── suite/                               (Go/testify parity suite)
    ├── Dockerfile                       (suite image for the kind run)
    ├── config.go
    ├── compare.go                       (golden read/diff; no write/record path)
    ├── accepted_divergences.go
    ├── testdata/
    │   ├── golden/                      (129 committed golden JSON files)
    │   └── fixtures/                    (seed policies and PIPs)
    └── test_row*.go                     (one file per parity endpoint row)
```

The harness lives under [`test/k8s/parity/`](../k8s/parity/): the manifests, the chart values, and the realm imports
in `idp-seed/`.
