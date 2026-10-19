# authz-test-stand

The test stand of the authz-agent suites, as a Helm chart: Keycloak with the test realms, instances of the pip-stub
image for the PIP, entitlements, and other stubs, the M2M client-credentials Secret, and a suite Job that `helm test`
runs. It is a test fixture, not a production chart. Every part is off by default; the
[values file](values.yaml) describes each one.

The kind harnesses install it with [`test/k8s/test-stand-values.yaml`](../../test/k8s/test-stand-values.yaml) (the
runtime suite) and [`test/k8s/parity/test-stand-values.yaml`](../../test/k8s/parity/test-stand-values.yaml) (the parity
suite); see [`test/k8s/README.md`](../../test/k8s/README.md).

## Generated files

The chart reads the realm files and the pip-stub rule files from `files/`, which git does not track. In a checkout,
generate them before you install or lint the chart:

```bash
make test-stand-files
```

The stage `chart-files` of [`build/authz-agent-transfer/Dockerfile`](../../build/authz-agent-transfer/Dockerfile)
writes them: the realms of `test/k8s/authn/` under `files/realms/e2e/`, the realms of `test/k8s/parity/idp-seed/` with
the users of `test/parity/suite/testdata/realm/` under `files/realms/parity/`, and the rule files of
`test/integration/pipstub/config/` under `files/pip-stub/`. Without them, an install that turns Keycloak or a stub with a
rule file on fails with `no realm files under files/realms/<realms>/` or `no file files/pip-stub/<file>`.

## Install from the transfer image

The release publishes the image `ghcr.io/netcracker/authz-agent-transfer` with the three charts of this repository
under `/charts/`, and this chart's `files/` already generated. The images the chart runs, `pip-stub` and
`authz-parity-suite`, are published under the same version.

1. Copy the charts out of the image:

   ```bash
   docker create --name authz-charts ghcr.io/netcracker/authz-agent-transfer:<version> true
   docker cp authz-charts:/charts ./charts
   docker rm authz-charts
   ```

2. Install the stand with a values file of your own. Start from
   [`test/k8s/parity/test-stand-values.yaml`](../../test/k8s/parity/test-stand-values.yaml) and change what is
   specific to kind:

   - delete `TAG`, `IMAGE_PULL_POLICY`, `pipStub.imageRepository`, and `suite.imageRepository`, so the chart pulls
     the published images and `--set TAG` picks their version;
   - change the addresses in `suite.env` to the services of your stand;
   - turn `idp.enabled` off where the stand has its own Keycloak with the parity realms, and `clientCredentials.enabled`
     off where the platform provisions the client-credentials Secret.

   ```bash
   helm upgrade --install authz-test-stand ./charts/authz-test-stand --set TAG=<version> -f my-test-stand-values.yaml
   ```

3. Run the suite and print its log:

   ```bash
   helm test authz-test-stand --timeout 15m --logs
   ```

`helm test` exits non-zero when the suite fails. It deletes the Job of the previous run before it starts a new one.
