#
# Transfer image: the Helm charts of this repository, for a stand that installs
# them without a checkout.
#
#   /charts/authz-agent
#   /charts/authz-policy-admin
#   /charts/authz-test-stand   with its generated files/ in place
#
# The stage chart-files generates the files the test-stand chart reads from
# files/. `make test-stand-files` writes the same stage into a checkout:
#
#   files/realms/e2e/      authz-test and cloud-common from test/k8s/authn/
#   files/realms/parity/   cloud-common, parity-mt-b, and parity from
#                          test/k8s/parity/idp-seed/; the parity realm also
#                          holds the users of test/parity/suite/testdata/realm/
#   files/pip-stub/        the rule files of test/integration/pipstub/config/
#
# Build context is the repository root:
#   docker build -t authz-agent-transfer -f build/authz-agent-transfer/Dockerfile .

FROM --platform=$BUILDPLATFORM ghcr.io/jqlang/jq:1.8.1@sha256:4f34c6d23f4b1372ac789752cc955dc67c2ae177eb1b5860b75cdc5091ce6f91 AS jq

FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS generate
COPY --from=jq /jq /usr/local/bin/jq
WORKDIR /src
COPY test/k8s/authn/authz-test-realm.json test/k8s/authn/cloud-common-realm.json e2e/
COPY test/k8s/parity/idp-seed/cloud-common-realm.json test/k8s/parity/idp-seed/parity-realm.json \
     test/k8s/parity/idp-seed/parity-mt-b-realm.json parity/
COPY test/parity/suite/testdata/realm/ users/
COPY test/integration/pipstub/config/ pip-stub/
# The user files under testdata/realm/ hold no first name, last name, or email,
# and Keycloak 26 refuses a password grant to such a user with "Account is not
# fully set up". The profile function fills them in with the values these users
# have on the stand the goldens were recorded on, for example Parity,
# R29LevelM2M, and parity-r29-level-m2m@example.test, so the tokens carry the
# same claims as the ones the goldens were recorded with. The build fails if a
# user is declared twice.
COPY build/authz-agent-transfer/profile.jq /root/.jq
RUN mkdir -p /out/realms/e2e /out/realms/parity /out/pip-stub \
 && cp e2e/*.json /out/realms/e2e/ \
 && cp parity/cloud-common-realm.json parity/parity-mt-b-realm.json /out/realms/parity/ \
 && jq --slurp '.[0].users += ([.[1:][]] | add | map(profile)) | .[0]' \
      parity/parity-realm.json users/*.json > /out/realms/parity/parity-realm.json \
 && jq -e '[.users[].username] | length == (unique | length)' /out/realms/parity/parity-realm.json \
 && jq -e '[.users[].id | select(.)] | length == (unique | length)' /out/realms/parity/parity-realm.json \
 && cp pip-stub/* /out/pip-stub/

FROM scratch AS chart-files
COPY --from=generate /out/ /

FROM scratch
COPY helm-templates/authz-agent/ /charts/authz-agent/
COPY helm-templates/authz-policy-admin/ /charts/authz-policy-admin/
COPY helm-templates/authz-test-stand/ /charts/authz-test-stand/
COPY --from=chart-files / /charts/authz-test-stand/files/
