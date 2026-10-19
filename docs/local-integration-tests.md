# Running the integration tests locally, from scratch

Step-by-step guide: bring up a kind cluster on a clean machine, build the images, install the Helm chart with the test
harness around it, and run the **runtime integration tests**: the Testify suite under `test/integration/testify/`,
executed as a Job inside that cluster. CI runs the same Makefile targets
(`.github/workflows/integration-tests.yaml`).

> Scope: runtime integration only. OPA contract tests, the chart render check, and the parity replay are in
> [Related checks](#7-related-checks) at the end.

---

## 1. What these tests are

- Orchestrator: the `e2e-*` targets in the [Makefile](../Makefile). `make e2e` runs them in order.
- The harness: the test-stand chart in `helm-templates/authz-test-stand`, installed with
  [test/k8s/test-stand-values.yaml](../test/k8s/test-stand-values.yaml). It runs Keycloak, which imports the realms of
  `test/k8s/authn/` at start, the `pip-stub` the uploaded PIP definitions call, and a second stub instance as
  `entitlements-mock`. Chart values under [test/k8s/](../test/k8s/) point the agent at them.
- The agent under test comes from the Helm chart in `helm-templates/authz-agent`, installed with `test/k8s/values.yaml`;
  its policy source, the `authz-policy-admin` stub, from `helm-templates/authz-policy-admin` with
  `test/k8s/policy-admin-values.yaml`.
- The suite runs as the Job of the test stand, a `helm test` hook, built from `test/integration/testify/Dockerfile`.
  Every target is a Service name, so no port has to leave the cluster.
- The step catalog (source of truth) is [test/readme.md](../test/readme.md) plus `test/integration/testify/catalog.go`;
  dedicated validation tests enforce that the two stay in sync.

---

## 2. Prerequisites

| Tool | Why | Check |
| --- | --- | --- |
| **Docker** | builds the images and runs the kind node | `docker info` |
| **kind** | the cluster | `kind version` |
| **kubectl** | streams the Job log, restarts Deployments | `kubectl version --client` |
| **helm** | installs the charts, runs the suite Job | `helm version` |
| **Go 1.24+** (the version `test/integration/testify/go.mod` declares) | the structural tests and `go vet`; the suite itself is compiled inside its image | `go version` |

You do **not** need a local OPA binary for the runtime tests (the agent carries the engine). It is only needed for the
Rego contract tests (section 7).

`kind`, `kubectl`, and `helm` install from their release pages or a package manager (Homebrew on macOS). On a
Debian/Ubuntu-family host Docker installs with:

```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo usermod -aG docker "$USER"   # then start a new login session (or: newgrp docker)
```

Verify the daemon works without sudo:

```bash
docker run --rm hello-world
```

> **GOROOT caveat.** If your shell exports a `GOROOT` that points at a *different* Go toolchain than the `go` on your
> `PATH`, `go test` fails with `[build failed]`. Either unset it for the run (`env -u GOROOT <command>`) or remove the
> stale `export GOROOT=...` from your shell profile. Confirm with `go env GOROOT`.

---

## 3. Resources

The cluster is one kind node. The harness plus the agent need roughly 2 CPUs and 4 GB of memory free for Docker;
Keycloak is the heaviest part. No host port is published. The first run pulls Keycloak and OPA into the node, which
takes minutes on a slow network; later runs reuse them.

---

## 4. Building the images

`make e2e-images` builds and loads everything the cluster needs:

| Image | Dockerfile |
| --- | --- |
| `local/authz-agent:ci`, `local/authz-policy-admin:ci` | `build/*/Dockerfile`, the product images |
| `local/pip-stub:ci` | `test/integration/pipstub/Dockerfile` |
| `local/authz-runtime-suite:ci` | `test/integration/testify/Dockerfile`, the suite compiled with `go test -c -tags integration` |
| `local/authz-parity-suite:ci` | `test/parity/suite/Dockerfile`, used by `make parity` |

The images are built for the host platform and loaded with `kind load`; the node runs the same architecture, so
nothing is emulated. OPA and Keycloak are pulled by the node from their registries.

---

## 5. Run (happy path)

From the repository root:

```bash
make e2e
```

Step by step, in the order `make e2e` runs them:

| Target | What it does |
| --- | --- |
| `e2e-cluster` | Creates the kind cluster `authz-e2e` unless it exists |
| `e2e-images` | Builds the images above and loads them into the cluster |
| `e2e-harness` | Namespace, realm ConfigMap, client-credentials Secret, Keycloak and the stubs; waits until they are Ready |
| `e2e-install` | `helm upgrade --install` of the stub chart with `test/k8s/policy-admin-values.yaml`, then of the agent chart with `test/k8s/values.yaml`, each with `--wait` |
| `e2e-suite` | Applies the Job and its RBAC, streams its log, and fails if the Job did not complete |

Each step prints a `STEP PASS/FAIL <name> <ms>` line. The Job sets `FULL_RUNTIME_SUITE=true`, so the run ends with the
two catalog coverage checks. Expected: `--- PASS: TestRuntimeSuite` with 19 groups.

Artifacts:

```bash
make e2e-logs     # every container log on the node, the namespace events, and the decision logs, into test/artifacts/kind/
make e2e-down     # delete the cluster
```

---

## 6. Iterating

- Changed the suite only: `make e2e-images e2e-suite`. The harness and the chart stay; the Job is recreated.
- Changed product code: `make e2e-images e2e-restart e2e-suite`. The images are rebuilt under the same tags, and a
  running Pod keeps the old content until it is restarted; `e2e-restart` restarts every Deployment that runs a local
  image and waits until it is Ready again. Without it the suite tests the previous build.
- Changed chart values: `make e2e-install e2e-suite`.
- Re-running `e2e-harness` after a change to a realm file replaces the Keycloak Pod, and a dev-mode Keycloak mints new
  realm keys on every start. Restart the agent afterwards so its JWKS bootstrap picks the new keys up, or the suite fails at
  `setup.wait_for_agent`:

  ```bash
  kubectl --context kind-authz-e2e -n authz-e2e rollout restart deploy/authz-agent
  ```

- A subset: set `RUNTIME_SUITE_RUN` (a `-test.run` regular expression) on the test-stand release, with
  `FULL_RUNTIME_SUITE` set to `false` so the coverage checks do not fail on a filtered run, then run `make e2e-suite`:

  ```bash
  helm --kube-context kind-authz-e2e -n authz-e2e upgrade authz-test-stand helm-templates/authz-test-stand \
    --reuse-values --set suite.env.RUNTIME_SUITE_RUN='^TestRuntimeSuite$/^TestCheckResource$' --set-string suite.env.FULL_RUNTIME_SUITE=false
  ```

  `make e2e-harness` restores the values of `test/k8s/test-stand-values.yaml`.
- Poking at the stack from the host, for example with the Postman collection in `test/`:

  ```bash
  kubectl --context kind-authz-e2e -n authz-e2e port-forward svc/authz-agent 8080:8080 8181:8181
  kubectl --context kind-authz-e2e -n authz-e2e port-forward svc/keycloak 5556:8080
  ```

  The environment file `test/authz-agent-runtime.postman_environment.json` targets these ports; set its
  `keycloak_base_url` to `http://localhost:5556/auth/realms/authz-test`.

Structural tests without a cluster (catalog and readme validation, spec lint):

```bash
cd test/integration/testify
go test -v -count=1 ./...    # no -tags integration
```

---

## 7. Related checks

OPA / Rego contract tests, no cluster needed:

```bash
test/scripts/install-opa.sh    # installs opa into test/tools/opa/
test/scripts/test-opa.sh
```

Chart render check and parity replay:

```bash
test/scripts/test-chart-render.sh
make parity                    # see test/parity/README.md
```

The minimum CI gate for compatibility-sensitive changes is listed in [test/readme.md](../test/readme.md).

---

## 8. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `go test` → `[build failed]` | `GOROOT` points at a different toolchain than `go` on `PATH`. Unset it or fix your profile (section 2). |
| `make e2e-cluster` fails | Docker is not running, or your user cannot reach `docker.sock` (section 2). |
| The Job Pod stays `Pending` or reports `ErrImageNeverPull` | The images are not in the cluster; run `make e2e-images`. |
| `helm --wait` times out on the first run | The node is still pulling Keycloak or OPA. Check `kubectl -n authz-e2e get pods`, then rerun `make e2e-install`. |
| `setup.wait_for_agent` fails after a harness rerun | Keycloak has new realm keys; restart the agent (section 6). |
| Need logs after a run | `make e2e-logs`, then look under `test/artifacts/kind/`. |
| Cluster left behind | `make e2e-down`. |
