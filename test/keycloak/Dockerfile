#
# Keycloak for the kind harnesses, with every realm the e2e and the parity
# suites use already imported into its database. A Pod of this image serves
# the realms as soon as Keycloak is up, without --import-realm or a partial
# import before a test.
#
# Realms in the database:
#   authz-test    test/k8s/authn/authz-test-realm.json
#   cloud-common  test/k8s/authn/cloud-common-realm.json, plus the clients of
#                 test/k8s/parity/idp-seed/cloud-common-realm.json
#   parity        test/k8s/parity/idp-seed/parity-realm.json, plus the users
#                 of test/parity/suite/testdata/realm/*.json
#   parity-mt-b   test/k8s/parity/idp-seed/parity-mt-b-realm.json, the realm
#                 of tenant B of the two-tenant cases (PARITY_MT_TENANT_B_*)
#
# The issuer is not part of the image: each Deployment sets KC_HOSTNAME to its
# own Service name.
#
# Build context is the repository root:
#   docker build -t authz-test-keycloak -f test/keycloak/Dockerfile .

FROM --platform=$BUILDPLATFORM ghcr.io/jqlang/jq:1.8.1@sha256:4f34c6d23f4b1372ac789752cc955dc67c2ae177eb1b5860b75cdc5091ce6f91 AS jq

# The two harnesses keep different cloud-common files, and one Keycloak holds
# one realm of that name. The e2e file is the base, and the parity file adds
# its parity-m2m client; the e2e access token lifespan, 1800 s, applies to
# both. The build fails if a client or a user is declared twice.
FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS realms
COPY --from=jq /jq /usr/local/bin/jq
WORKDIR /src
COPY test/k8s/authn/authz-test-realm.json test/k8s/authn/cloud-common-realm.json authn/
COPY test/k8s/parity/idp-seed/cloud-common-realm.json test/k8s/parity/idp-seed/parity-realm.json \
     test/k8s/parity/idp-seed/parity-mt-b-realm.json parity/
COPY test/parity/suite/testdata/realm/ users/
# The user files under testdata/realm/ hold no first name, last name, or
# email, and Keycloak 26 refuses a password grant to such a user with "Account
# is not fully set up". The profile function fills them in with the values
# these users have on the stand the goldens were recorded on, for example
# Parity, R29LevelM2M, and parity-r29-level-m2m@example.test, so the tokens
# carry the same claims as the ones the goldens were recorded with.
COPY test/keycloak/profile.jq /root/.jq
RUN mkdir /realms \
 && cp authn/authz-test-realm.json /realms/authz-test-realm.json \
 && cp parity/parity-mt-b-realm.json /realms/parity-mt-b-realm.json \
 && jq --slurpfile p parity/cloud-common-realm.json '.clients += $p[0].clients' \
      authn/cloud-common-realm.json > /realms/cloud-common-realm.json \
 && jq --slurp '.[0].users += ([.[1:][]] | add | map(profile)) | .[0]' \
      parity/parity-realm.json users/*.json > /realms/parity-realm.json \
 && jq -e '[.clients[].clientId] | length == (unique | length)' /realms/cloud-common-realm.json \
 && jq -e '[.users[].username] | length == (unique | length)' /realms/parity-realm.json \
 && jq -e '[.users[].id | select(.)] | length == (unique | length)' /realms/parity-realm.json

# The import writes the dev-file H2 database. Its files do not depend on the
# CPU architecture, so the import runs once on the build platform and every
# target platform copies the result.
FROM --platform=$BUILDPLATFORM quay.io/keycloak/keycloak:26.3.5@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba AS import
COPY --from=realms /realms/ /tmp/realms/
RUN /opt/keycloak/bin/kc.sh import --dir /tmp/realms

FROM quay.io/keycloak/keycloak:26.3.5@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba
COPY --from=import --chown=1000:0 /opt/keycloak/data/h2/ /opt/keycloak/data/h2/
# The fixtures address the realms under /auth, and Keycloak dropped that
# prefix in version 17. KC_HTTP_RELATIVE_PATH prefixes the management
# endpoints too, so the health check is /auth/health/ready on port 9000.
ENV KC_HTTP_RELATIVE_PATH=/auth \
    KC_HEALTH_ENABLED=true
# No bootstrap admin: the realms carry every client and user the suites need.
CMD ["start-dev"]
