# Kind end-to-end harness

Chart values for running the runtime suite against the Helm chart on a kind
cluster. The Makefile targets below install the charts with them; you do not
install them by hand. CI runs the same targets one step at a time.

| File | What it is |
| --- | --- |
| `test-stand-values.yaml` | Values of the test-stand chart, [`helm-templates/authz-test-stand`](../../helm-templates/authz-test-stand): Keycloak with the realms of `authn/`, the PIP stub, the entitlements stub, the tenant-manager emulator, the M2M client-credentials Secret, and the suite Job |
| `authn/` | The realm files and their description |
| `values.yaml` | Chart values that point the agent at the harness Services and at the stub |
| `policy-admin-values.yaml` | Chart values for the `authz-policy-admin` stub, installed from its own chart |

The test stand runs the public Keycloak image, `quay.io/keycloak/keycloak`, in
dev mode. The chart puts the realm files into a ConfigMap, and Keycloak imports
them with `--import-realm` at every start; no test adds a realm, a client, or a
user afterwards. The realm files of the chart are generated: `make
test-stand-files` writes them into `helm-templates/authz-test-stand/files/`
from `authn/`, `parity/idp-seed/`, and `test/parity/suite/testdata/realm/`, and
`make e2e-harness` and `make parity-harness` run it first. A changed realm file
reaches Keycloak with the next `make e2e-harness` or `make parity-harness`,
which restarts the Pod.

The stubs run the pip-stub image, one Deployment per instance that the values
file lists. The suite Job is a `helm test` hook of the test-stand release, so
installing the stand does not start it.

`parity/` holds the same shape for the parity replay suite (`test/parity`):
its `test-stand-values.yaml` sets up Keycloak as `idp` with the realms of
`parity/idp-seed/` and the users of `test/parity/suite/testdata/realm/`,
`pip-mock`, `entitlements-mock`, and the parity
suite Job. Its chart values add the parity realm as an explicit trusted
provider. It runs in its own namespace, so its Keycloak can be named `idp`, the
issuer host in the parity realm's tokens, next to the e2e namespace's
`keycloak`.

## Run

```bash
make e2e          # cluster, images, harness, chart, suite
make e2e-logs     # collect artifacts into test/artifacts/kind/
make parity       # the parity replay: harness, chart, suite in namespace authz-parity
make parity-logs  # its artifacts, into test/artifacts/kind/parity/
make e2e-down     # delete the cluster
```

A cluster that an older `make e2e` or `make parity` set up holds the harness objects that `kubectl apply` created, and
Helm refuses to take them over: the install fails with `exists and cannot be imported into the current release:
invalid ownership metadata`. Run `make e2e-down` once before the first run of the test-stand chart.

Step by step, in the order `make e2e` runs them:

| Target | What it does |
| --- | --- |
| `e2e-cluster` | Creates the kind cluster `authz-e2e` unless it exists |
| `e2e-images` | Builds the two product images, pip-stub, the tenant-manager emulator, and the suite images, then loads them into the cluster |
| `e2e-harness` | Generates the realm files (`test-stand-files`), then installs the test-stand chart with `test-stand-values.yaml` in the namespace: Keycloak, the stubs, the tenant-manager emulator, and the client-credentials Secret; waits until they are Ready. When the upgrade replaces the Keycloak Pod of a stand where the agent is installed, it restarts the agent, which otherwise keeps the old realm keys |
| `e2e-install` | `helm upgrade --install` of the stub chart with its dev resource profile and `policy-admin-values.yaml`, then of the agent chart with its dev resource profile and `values.yaml`, each with `--wait` |
| `e2e-suite` | Runs the suite Job with `helm test`, streams its log, and fails if the Job did not complete |
| `e2e-restart` | Restarts the Deployments that run local images and waits for them; needed after `e2e-images` on a running stand, because the tags do not change. Keycloak runs the public image and is not restarted |

The parity targets mirror these: `parity-harness`, `parity-install`,
`parity-suite`, `parity-restart`, and `parity-logs`, all in `PARITY_NAMESPACE`. `parity` runs the
cluster and image targets first, then the three.

`KIND_CLUSTER`, `E2E_NAMESPACE`, `PARITY_NAMESPACE`, and `E2E_ARTIFACTS`
override the defaults. `E2E_HELM_ARGS` adds arguments to the installs of the agent and authz-policy-admin charts, and
`TEST_STAND_HELM_ARGS` to the install of the test stand, which reads `TAG` and `IMAGE_PULL_POLICY` for images of its
own. `E2E_SUITE_TIMEOUT` and `PARITY_SUITE_TIMEOUT`, 15m by default, set how long `e2e-suite` and `parity-suite` wait
for the suite Job. They are the outermost of three limits: a suite that runs longer also needs `-test.timeout` in
`suite.args` (600s) and `suite.activeDeadlineSeconds` (900) raised in its values file, each no higher than the next.
`SUITE_START_SECONDS`, 180 by default, sets how long a suite container may take to start before `e2e-suite` or
`parity-suite` gives up with `The <job> container did not start within 180 seconds:`.
`E2E_BASE_URL` and `PARITY_AC_BASE_URL` set where the suites send their
requests, the chart's Service by default. They go into the suite Job's values at
`e2e-harness` or `parity-harness`. Given on the command line or in the environment
of `e2e-suite` or `parity-suite`, they are written into the installed release
before the run; otherwise the run keeps the URL the release has.

## What runs

The suite Job of `test-stand-values.yaml` runs the whole Testify suite, including the two
coverage checks that need a full run (`FULL_RUNTIME_SUITE=true`). Groups that
inspect what the engine received or decided, such as `TestDecisionLogs` and
`TestPIPDenyReason`, read the decision logs the agent serves at
`/internal/v1/decision-logs` instead of a capture proxy: the agent's own store of
the decisions it made.

The Job reaches every target by Service name and asks the API server for
nothing, so the `runtime-suite` ServiceAccount the chart creates for it
is granted no rules and its token is not mounted.
