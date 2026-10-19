# Parity IdP seed realms

These realm files are the realms of the parity test stand. The test-stand chart,
[`helm-templates/authz-test-stand`](../../../../helm-templates/authz-test-stand), imports them
into Keycloak at every start when its `idp.realms` value is `parity`, as in
[`test-stand-values.yaml`](../test-stand-values.yaml). `make test-stand-files` copies them into
the chart and adds the users of `test/parity/suite/testdata/realm/` to the `parity` realm.

The stand is also a two-tenant stand for the cases that need one (see "Two-tenant stand" in
[`test/parity/README.md`](../../../parity/README.md)): `parity-realm.json` holds `mt-a` and
`mt-a-admin` with `ROLE_MT_READER` and `ROLE_MT_ADMIN`, the users of tenant A, and
`parity-mt-b-realm.json` is the realm of tenant B, `parity-mt-b`, with `mt-b`, `mt-b-admin` and
the `parity-end-user` client. The client `parity-m2m-tenant-b` carries tenant B's identifier,
`parity-mt-b`, in its `tenant-id` claim. Such a stand sets `PARITY_MT_TENANT_A_ID=default`,
`PARITY_MT_TENANT_B_ID=parity-mt-b`, and the two realms' base URLs.

## Why the notes live here and not in the JSON

Each entry below used to be a `_comment` key inside the realm JSON. The
identity-provider fork tolerated unknown keys; stock Keycloak 26.6.4 does not, and
the import aborts with `Unrecognized field "_comment" (class RealmRepresentation)`.
That blocked the `infra-keycloak` image, so the notes moved out of the data and into
this file, word for word. Do not put `_comment` back into the JSON.

## Notes, in the order they appeared

### `cloud-common-realm.json`

- **was at line 2** — A minimal `cloud-common` realm required for inter-service M2M
  authentication. The access-control service uses `cloud-common` as the hard-coded M2M
  auth realm and loops forever on `client_not_found` if the `parity-m2m` client is not
  present there. The client shape (confidential + service-accounts + audience mapper)
  mirrors `parity-realm.json` so AC can authenticate against either realm with the same
  credentials.

### `parity-realm.json`

- **was at line 2** — Parity IdP bootstrap. Originally seeded with one realm, one M2M
  client, and one test user for the smoke script. Extended additively to add:
  (a) a dedicated password-grant confidential client `parity-end-user` so the Go suite
  can mint end-user tokens without calling the Keycloak admin REST API;
  (b) a fixed set of test users (parity-reviewer, parity-multi-role, parity-other,
  parity-anon-baseline) each addressing a unique `(resourceType, operation, role, user)`
  tuple in the parity fixtures;
  (c) two custom user attributes, `department` and `tier`, plumbed through standard
  `oidc-usermodel-attribute-mapper` protocol mappers so TOKEN-PIP test rows can read
  them as JWT claims. The original `parity-m2m` client and `parity-reader` user are
  preserved. Roles added: `ROLE_PARITY_REVIEWER`, `ROLE_PARITY_OTHER`.

- **was at line 57** — Password-grant-capable confidential client used exclusively by the
  Go suite's `TokenFactory` to mint end-user access tokens. Separate from `parity-m2m`
  so (a) the suite can rotate this client's secret without touching the M2M seed path,
  and (b) the `netcracker` audience mapper is intentionally absent here — end-user tokens
  go through the service's incoming-token relay path, not the M2M bearer path; adding the
  audience would blur the distinction the suite is designed to assert. The `department`
  and `tier` user-attribute mappers emit JWT claims that TOKEN-PIP parity fixtures read
  via `subject.<alias>`.

- **was at line 107** — Fixed UUID for golden stability: the rsqlFilterCondition golden contains this subject.id, so a non-deterministic Keycloak-generated UUID would break the 'second run shows zero diff' stability gate across down -v + up -d cycles.

- **was at line 124** — Reviewer user for AGG rows that need two distinct single-role subjects on the same (resourceType, operation) locator. Department=compliance / tier=silver so SUB block fixtures can pin a distinct scalar rendering per user.

- **was at line 141** — Multi-role user for AGG rows that need one subject holding both ROLE_PARITY_READER and ROLE_PARITY_REVIEWER so the legacy engine combines matching policy rows across roles on one evaluation. Department=engineering / tier=platinum.

- **was at line 158** — Isolation user holding only ROLE_PARITY_OTHER, which no seed policy addresses. Used by rows that need a guaranteed DENY from a valid end-user token so the suite can distinguish 'role-does-not-grant' from 'no-token-at-all' failures.

- **was at line 175** — Anonymous-baseline user. Holds no parity role at all so the 'Authorization-Type: anonymous' rows can contrast the 'no roles reached the engine' baseline against a named user baseline. Tokens for this user are acquired but dropped by the suite when Authorization-Type: anonymous is set per D-V item 4.
