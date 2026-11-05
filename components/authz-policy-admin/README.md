# authz-policy-admin

`authz-policy-admin` is the supported policy source for `qubership-authz-agent`.
It implements a subset of the access-control v3 configuration API so that
teams without a platform access-control installation can load policies into the
agent through the same pull path that production uses.

It has a Helm chart of its own, `helm-templates/authz-policy-admin`: a
Deployment with its Service and PersistentVolumeClaim.  Install it beside the
agent's chart and point the agent's `AUTHZ_PAP_CLIENT_SOURCE_URL` at its
Service, `http://authz-policy-admin:18090` with the chart's defaults. The chart
takes its sizing from one of its resource profiles, `resource-profiles/dev.yaml`
for a dev install, passed with `-f`.

## HTTP API

### Simplified-policy API (northbound, for seeding policies)

These paths mirror the access-control v1 simplified-policy surface, so callers
that already load policies into access-control work unchanged.

```text
GET  /access/v1/simplifiedPolicies/domainPolicies/{domainName}
PUT  /access/v1/simplifiedPolicies/domainPolicies/{domainName}

GET  /access/v1/simplifiedPolicies/domainPIPs/{domainName}
PUT  /access/v1/simplifiedPolicies/domainPIPs/{domainName}
```

PUT body for policies: a JSON array of simplified-policy objects.
PUT body for PIPs:     a JSON array of simplified-PIP objects.

A PUT that access-control would refuse is answered with 400 and
`{"error": "<reason>"}`, naming the item and the field, and stores nothing.
The stub checks a subset of access-control's rules:

- a PIP name is `subject.` followed by dot-separated attributes of letters,
  digits, and underscores, none starting with a digit;
- a PIP field holds the JSON shape access-control binds it to: `headers`,
  `defaultValue`, and the other text, number, and boolean fields take no
  array or object, so `headers` is one text of comma-separated header names,
  and `customMapping` and `productMapping` take an object;
- a PIP has the fields its `pipType` reads: a `url` (or a `beanName` for
  `GENERAL`), a `resourceType` for `FILTERED`, a `claim` for `TOKEN`, a
  `jsonPath` for `type` `JSON`; a `GENERAL` PIP calls with `GET` or `POST`, and
  no PIP reads or forwards the `Authorization` or `Tenant` header;
- a `${subject.<name>}` reference in a PIP names what access-control resolves:
  only `${subject.id}` in a `url`, and a built-in subject attribute or a
  `TOKEN` or `HEADER` PIP in a request attribute or a mapping key;
- a policy has `component`, `resourceType`, `operation`, and non-empty
  `roles`, an `id` that is a UUID, and `predicates` with a `mongodbPredicate`;
- a policy `condition` is absent, `null`, a boolean, or a non-empty text that
  the agent's condition parser accepts, and each operator in it takes the
  operands access-control pairs with it, so `subject.x MATCH 5` and
  `subject.roles == 'R'` are refused. With
  `AUTHZ_POLICY_ADMIN_REQUIRE_DECLARED_PIPS` set, the condition also reads
  only PIPs the tenant has declared.

A PIP name declared twice in one upload, or in another domain of the same
tenant, is answered with 409. An upload these checks accept may still be one
access-control refuses.

Each tenant keeps its own collections. The tenant of a request is the
`tenant_id` query parameter, else the `Tenant` header, else `default`, so a
PUT replaces only what the same tenant uploaded for that domain. A tenant
other than letters, digits, dot, underscore, and dash is refused with 400.

The API is **unauthenticated**.  Deploy `authz-policy-admin` only in
development and test namespaces, never in a namespace that is reachable by
untrusted callers.

### v3 config export (southbound, read by the agent's pull loop)

These paths are the pull endpoint that the agent's pull loop polls at the interval set
by `AUTHZ_PAP_CLIENT_PULL_INTERVAL`.

```text
GET  /access/v3/config/policySets
GET  /access/v3/config/pips
```

Both require an `Authorization` header (the bearer token that the agent holds;
the value is not validated, only presence-checked).  They return the union of
all tenants and domains, and each policy set and PIP carries the tenant that
uploaded it in `tenantId`; the `default` tenant is exported as
`AUTHZ_POLICY_ADMIN_DEFAULT_TENANT_ID`.  An empty store exports `"policySets": []` and
`"pips": []`.

### Health / status

```text
GET  /authz-policy-admin/hash
```

Returns a JSON object with:

```json
{
  "hash":         "<sha256 of policies>",
  "policiesHash": "<sha256 of policies>",
  "pipsHash":     "<sha256 of PIPs>",
  "revision":     <integer, incremented on each upload>,
  "domains":      ["<domain1>", "<domain2>"]
}
```

A domain of a tenant other than `default` is listed as `<tenant>/<domain>`.
`hash` and `policiesHash` are the same value; `hash` is kept for callers
written against an earlier version of the stub.  This endpoint is also used
by the Helm chart probes and the Docker Compose health checks.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `LOGGING_LEVEL_ROOT` | `info` | Level of the platform logger; the chart sets it from its `LOG_LEVEL` value |
| `AUTHZ_POLICY_ADMIN_PORT` | `18090` | TCP port to listen on |
| `AUTHZ_POLICY_ADMIN_DEFAULT_TENANT_ID` | `default` | `tenantId` of the `default` tenant in the v3 export. Set it to the ID the agent resolves its default tenant to |
| `AUTHZ_POLICY_ADMIN_REQUIRE_DECLARED_PIPS` | `false` | `true` refuses a policy whose condition reads a PIP the tenant has not declared in any domain, as access-control does. The test suites upload policies before their PIPs and leave it off |
| `AUTHZ_POLICY_ADMIN_DATA_DIR` | `` (empty) | Directory for persistence. Empty means in-memory only (data lost on restart). The Helm chart always sets this to the PVC mount path. |

## Volumes and persistence

When `AUTHZ_POLICY_ADMIN_DATA_DIR` is set, policies and PIPs are persisted to
disk so that a restart reloads the last uploaded state.  Data is stored as
JSON files under that directory, one file per tenant, domain, and collection:
`policies-<domain>.json` for the `default` tenant and
`policies-<tenant>@<domain>.json` for another tenant, and the same with the
`pips-` prefix.

In the Helm chart:

- The PVC is named `authz-policy-admin-data` (the service name plus `-data`).
- The default mount path is `AUTHZ_POLICY_ADMIN_DATA_DIR: /var/lib/authz-policy-admin`.
- The storage class and size are controlled by
  `AUTHZ_POLICY_ADMIN_STORAGE_CLASS` and `AUTHZ_POLICY_ADMIN_STORAGE_SIZE`.

## Image

Built from `build/authz-policy-admin/Dockerfile`.  Published as
`ghcr.io/netcracker/qubership-authz-policy-admin`: `qubership-` plus the
service name, as the platform names its images, and no `authz-agent-` prefix
because it is a service of its own rather than a container of the agent Pod.

## Relationship to the platform's access-control service

When a platform access-control service is available (for example, in a
production Netcracker environment), set `AUTHZ_PAP_CLIENT_SOURCE_URL` to point
the agent at it directly.  `authz-policy-admin` is then not needed.

`authz-policy-admin` implements only the subset of the API that the agent uses:
the simplified-policy upload paths and the v3 export paths.  It does not
implement POST / PATCH / DELETE on the PIP path (those return 405), nor any
management or tenant-management surface.
