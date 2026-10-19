# Keycloak Realm Import — `authz-test`

This document describes the repository-managed Keycloak realm import used by the runtime integration test environment.

## Realm

| Property                         | Value                                         |
| -------------------------------- | --------------------------------------------- |
| Realm name                       | `authz-test`                                  |
| Issuer (fixed via `KC_HOSTNAME`) | `http://keycloak:8080/auth/realms/authz-test` |
| OIDC discovery                   | `<issuer>/.well-known/openid-configuration`   |
| JWKS URI                         | `<issuer>/protocol/openid-connect/certs`      |
| Token endpoint                   | `<issuer>/protocol/openid-connect/token`      |
| SSL required                     | `none` (dev mode)                             |
| Access token lifespan            | 30 minutes (realm default)                    |

## Clients

| Client ID             | Secret                       | Public | Direct Access Grants | Standard Flow | Service Accounts |
| --------------------- | ---------------------------- | ------ | -------------------- | ------------- | ---------------- |
| `authz-agent`         | `authz-agent-secret`         | No     | Yes                  | No            | No               |
| `authz-agent-expired` | `authz-agent-expired-secret` | No     | Yes                  | No            | No               |

## Protocol Mappers

| Client                | Mapper Name                    | Type                   | Purpose                                                                                                          |
| --------------------- | ------------------------------ | ---------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `authz-agent`         | `authz-agent-audience`         | `oidc-audience-mapper` | Adds `authz-agent` to the `aud` claim of both access and ID tokens so the trusted-provider audience check passes |
| `authz-agent-expired` | `authz-agent-expired-audience` | `oidc-audience-mapper` | Adds `authz-agent` to the `aud` claim for short-lived expired-token test flow                                    |

## Token Lifetimes by Client

| Client ID             | Access token lifespan                               | Usage                                            |
| --------------------- | --------------------------------------------------- | ------------------------------------------------ |
| `authz-agent`         | 30 minutes                                          | Default client for all regular runtime scenarios |
| `authz-agent-expired` | 5 seconds (`access.token.lifespan` client override) | Setup step `setup.token_acquire_expired`         |

## Realm-Level Roles Built In by Keycloak

Keycloak natively places realm roles into the `realm_access.roles` JWT claim through the
built-in `realm roles` protocol mapper in the `roles` client scope. No custom mapper is
needed for `realm_access.roles` population.

## Realm Roles

| Role                            | Purpose                                                    |
| ------------------------------- | ---------------------------------------------------------- |
| `ROLE_ADMINISTRATOR`            | Full access to all resource types in runtime test policies |
| `ROLE_ORDER_MANAGEMENT_RO_USER` | Read access to ORDER resources with RLS condition          |

## Test Users

| Username       | Email                      | Password   | Realm Roles                     |
| -------------- | -------------------------- | ---------- | ------------------------------- |
| `order-reader` | `order-reader@example.com` | `password` | `ROLE_ORDER_MANAGEMENT_RO_USER` |
| `admin`        | `admin@example.com`        | `password` | `ROLE_ADMINISTRATOR`            |

Both users have `emailVerified: true` and `enabled: true`.

## Role Assignments and Authorization Behavior

- `order-reader`: has `ROLE_ORDER_MANAGEMENT_RO_USER` which grants OLS access to ORDER/READ.
  RLS for ORDER/READ requires `resource.ownerId == subject.id`; since the Keycloak `sub` claim
  is a UUID, the RLS condition only matches when the test resource `ownerId` equals that UUID.
- `admin`: has `ROLE_ADMINISTRATOR` which grants OLS access to ORDER/READ with open RLS
  (`condition: true`).

## Import Procedure

1. The test-stand chart, `helm-templates/authz-test-stand`, puts the realm JSON files into a
   ConfigMap mounted at `/opt/keycloak/data/import`.
2. The container starts with `start-dev --import-realm` and imports them at every start.
   `KC_HOSTNAME=http://keycloak:8080/auth` fixes the token issuer to the in-cluster Service name, so tokens carry
   `iss: http://keycloak:8080/auth/realms/authz-test`, matching the trusted-provider config.
3. The import creates the realm, clients, roles, and users from the JSON file. A change to the
   file takes effect after `make e2e-harness`, which regenerates the chart files and restarts
   the Pod.

## How the Runtime Environment Uses This Import

1. `make e2e-harness` installs the test-stand chart with `test/k8s/test-stand-values.yaml`,
   which runs Keycloak with `authz-test-realm.json` and `cloud-common-realm.json`.
2. `authz-agent` trusted-provider config points to `http://keycloak:8080/auth/realms/authz-test`.
3. On startup, `authz-agent` bootstrap fetches OIDC discovery from the Keycloak issuer,
   resolves the `jwks_uri`, downloads the JWKS, and writes it into the OPA data path.
4. The Testify integration suite acquires tokens from Keycloak using the password grant:
   short-lived expired tokens via `authz-agent-expired`, and regular tokens via `authz-agent`.
5. Acquired tokens carry `realm_access.roles` with the assigned realm roles, which is the
   only claim source for authorization-role derivation.

## Token Claims Structure

A Keycloak-issued access token for the `order-reader` user contains (among other standard claims):

```json
{
  "iss": "http://keycloak:8080/auth/realms/authz-test",
  "sub": "<keycloak-generated-uuid>",
  "aud": ["authz-agent"],
  "preferred_username": "order-reader",
  "email": "order-reader@example.com",
  "realm_access": {
    "roles": ["ROLE_ORDER_MANAGEMENT_RO_USER"]
  }
}
```

## Artifact Location

| Artifact                 | Path                                                             |
| ------------------------ | ---------------------------------------------------------------- |
| Realm import JSON        | `test/k8s/authn/authz-test-realm.json`                           |
| This description         | `test/k8s/authn/REALM-DESCRIPTION.md`                            |
| Identity provider wiring | `IDENTITY_PROVIDER_URL` in `test/k8s/values.yaml`                |
