# Kind end-to-end harness

Manifests and chart values for running the runtime suite against the Helm
chart on a kind cluster. The Makefile targets below apply them; you do not
apply them by hand. CI runs the same targets one step at a time.

| File | What it is |
| --- | --- |
| `keycloak.yaml` | Keycloak from the test image, which holds the realms of `authn/` |
| `authn/` | The realm files, their description, and the M2M client credentials |
| `pip-stub.yaml` | The PIP stub the uploaded PIP definitions call |
| `entitlements-mock.yaml` | A second stub instance for the entitlements endpoint |
| `values.yaml` | Chart values that point the agent at the harness Services and at the stub |
| `policy-admin-values.yaml` | Chart values for the `authz-policy-admin` stub, installed from its own chart |
| `runtime-suite-job.yaml` | The suite itself, built from `test/integration/testify/Dockerfile` |
| `runtime-suite-rbac.yaml` | The ServiceAccount the Job names; it is granted no rules |

Both namespaces run Keycloak from one image, `local/authz-test-keycloak:ci`,
built from [`test/keycloak/Dockerfile`](../keycloak/Dockerfile) by
`make e2e-images`. The image holds every realm the suites use, already
imported into its database: `authz-test` and `cloud-common` from `authn/`,
`parity` from `parity/idp-seed/`, and the users of
`test/parity/suite/testdata/realm/`. The Pod imports nothing at startup, and no
test adds a realm, a client, or a user to it. Each Deployment sets
`KC_HOSTNAME` to its own Service, so one image serves both issuers.

The two `cloud-common-realm.json` files differ, and the image holds one realm
of that name: the one from `authn/`, with the `parity-m2m` client of the
parity file added. A change to any of these realm files takes effect after
`make e2e-images` and `make e2e-restart` or `make parity-restart`.

The M2M client-credentials Secret is generated from the files under `authn/`
by `make e2e-harness`, so it has no manifest of its own.

`parity/` holds the same shape for the parity replay suite (`test/parity`):
Keycloak as `idp` from the same image,
`pip-mock` with the request-args rule set, `entitlements-mock`, chart values
with the parity realm as an explicit trusted provider, and the suite Job built
from `test/parity/suite/Dockerfile`. It runs in its own namespace, so its
Keycloak can be named `idp`, the issuer host in the parity realm's tokens,
next to the e2e namespace's `keycloak`.

## Run

```bash
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # collect artifacts into test/artifacts/kind/
make parity       # the parity replay: harness, chart, suite in namespace authz-parity
make parity-logs  # its artifacts, into test/artifacts/kind/parity/
make e2e-down     # delete the cluster
```

Step by step, in the order `make e2e` runs them:

| Target | What it does |
| --- | --- |
| `e2e-cluster` | Creates the kind cluster `authz-e2e` unless it exists |
| `e2e-images` | Builds the two product images, pip-stub, the suite images, and the Keycloak image, then loads them into the cluster |
| `e2e-harness` | Namespace, client-credentials Secret, Keycloak and the stubs; waits until they are Ready |
| `e2e-install` | `helm upgrade --install` of the stub chart with `policy-admin-values.yaml`, then of the agent chart with `values.yaml`, each with `--wait` |
| `e2e-suite` | Runs the Job, streams its log, and fails if the Job did not complete |
| `e2e-restart` | Restarts the Deployments that run local images and waits for them; needed after `e2e-images` on a running stand, because the tags do not change |

The parity targets mirror these: `parity-harness`, `parity-install`,
`parity-suite`, `parity-restart`, and `parity-logs`, all in `PARITY_NAMESPACE`. `parity` runs the
cluster and image targets first, then the three.

`KIND_CLUSTER`, `E2E_NAMESPACE`, `PARITY_NAMESPACE`, and `E2E_ARTIFACTS`
override the defaults. `E2E_HELM_ARGS` adds arguments to both chart installs;
`E2E_BASE_URL` and `PARITY_AC_BASE_URL` set where the suites send their
requests, the chart's Service by default.

## What runs

`runtime-suite-job.yaml` runs the whole Testify suite, including the two
coverage checks that need a full run (`FULL_RUNTIME_SUITE=true`). Groups that
inspect what the engine received, such as `TestOPARequestParity`, read the decision
logs the agent serves at `/internal/v1/decision-logs` instead of a capture
proxy: the agent's own store of the decisions it made.

The Job reaches every target by Service name and asks the API server for
nothing, so the `runtime-suite` ServiceAccount from `runtime-suite-rbac.yaml`
is granted no rules and its token is not mounted.
