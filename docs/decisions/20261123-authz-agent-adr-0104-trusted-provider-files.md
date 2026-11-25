# Describe the two trusted providers in a fixed directory of provider files

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the departures from earlier answers that it
  records, agreed on 2026-11-19, 2026-11-23, and 2026-11-25. On 2026-11-23 the architect and the owner of the policy
  decision code also agreed to drop the M2M modes, so no rule of this record depends on `M2M_AUTH_MODE`. On 2026-11-25
  the architect also decided that a token of any provider may hold the claim `kubernetes.io`, dropped the check of an
  in-cluster address in the provider `identity-provider`, and chose a warning at the start on the issuer of the provider
  `kubernetes` (R22, R29, A18 to A20).
- The owner of the policy decision code (`vlsi`) reviews this record, and on 2026-11-24 proposed the format of a
  provider file that R6 states.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0091: Verify tokens before policy evaluation against the keys of trusted issuers](20261029-authz-agent-adr-0091-verify-tokens-before-policy-evaluation.md):
  the term Stops the start, the readiness that waits for a usable key of every required source (ADR-0091 R14, R19), the
  loads and the codes of a token whose key is not found (ADR-0091 R23, R38, R39, R81), and the checks of a token
  (ADR-0091 R40 to R48). This request deletes from ADR-0091 the rules whose place this record takes: R73, R6, and R66
  (now R6 of this record), R1 and R3 (now R19 of this record), R4 and R9 (now R23 of this record), R5 (now R20 and R21
  of this record), R7 (now R17 and R19 of this record), R8 (now R6 of this record), R10 (now R24 and R28 of this
  record), R11 (now R21 of this record), R12 (now R5 of this record), R15 (now R13 of this record), and R49 and R50 (now
  R26 of this record). It also deletes ADR-0091 R2 and the `caFile` half of ADR-0091 R72 with the member `caFile`, and
  ADR-0091 A15, which rejected a reading of a discovery document. It deletes the terms Trusted providers file, Marked
  provider, File token, and Realm token, points the other terms for providers and tokens at this record, and restates
  ADR-0091 R14, R16, R17, R19, R21, R29, R34, R35, R37, R48, R52, R54, R60, and R64 in the terms of this record.
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  the M2M test of an identity-provider token (ADR-0092 R6, R21) and of a Kubernetes token (ADR-0092 R7), the kinds of
  token that `Authorization` accepts (ADR-0092 R11), and ADR-0092 R15, under which `M2M_AUTH_MODE` changes no token
  that this record accepts. This request makes ADR-0092 R6, R7, R11, and R21 name the kinds of R22, and deletes
  ADR-0092 R8, which A13 reverses.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  the term In-cluster address, the checks of a Kubernetes token (ADR-0094 R16 to R18, R25), the https rule for the keys
  of the provider `kubernetes` (ADR-0094 R32), and the projected tokens that the chart mounts (ADR-0094 R26). This
  request deletes from ADR-0094 the rules whose place this record takes: R1 (now R16 of this record), R4 and R5
  (reversed by A6 and A7 of this record, with R6 and R14 of this record in their place), R6, R8, and the token half of
  R7 (now R23 and R24 of this record), the address half of R9 (now R6 and R23 of this record), R10 and R12 (now R24 and
  R28 of this record), R11 (now R6 of this record), R14 (now R26 of this record), and R29 (now R6 of this record). It
  deletes ADR-0094 R13, which stopped the start for a provider that looked like the API server, with no successor (A19),
  and ADR-0094 R27 and the CA halves of ADR-0094 R7 and R9, which named the CA of the requests that this record
  replaces, with no successor here. It also deletes ADR-0094 A4 to A6, which rejected a fixed address of the keys, an
  issuer set in the configuration, and discovery without a token: this record configures the address and the issuer and
  drops discovery (R6, R23). It makes the token for the API server the token in the `jwksBearerTokenFile` of the
  provider `kubernetes`, and restates ADR-0094 R16 to R25, R28, and R32 in the terms of this record.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
  the steps of a check request (ADR-0095 R1), the answer to a request whose `Incoming-Token` fails a check (ADR-0095
  R3), and the index of reason codes (ADR-0095 R16). This request makes steps 1 and 2 of ADR-0095 R1 name the checks of
  this record, and makes ADR-0095 R16 index `TOKEN_ISSUER_UNKNOWN` by R21, and `TOKEN_AUDIENCE_MISSING` and
  `TOKEN_AUDIENCE_INVALID` by R26.
- [authz-agent-ADR-0096: Choose the token the agent sends by `M2M_AUTH_MODE`](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the token that the agent obtains from the realm `cloud-common`, which is an identity-provider token under R22. This
  request makes ADR-0096 call that token an identity-provider token, and cite R14 of this record where it cited
  ADR-0094 R5.
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  the provider files that the chart writes from its values (ADR-0105 R2, R3, R5, R16), the token for the API server that
  the chart gives the Pod (ADR-0105 R6), and the restart of the Pods when an upgrade changes a provider file (ADR-0105
  R13).

## Context

ADR-0091 verifies every token against the keys of trusted issuers before policy evaluation. Two servers sign the tokens
that an installation sends to the agent: the platform's Keycloak, with one realm per tenant, and the API server of the
cluster, which signs Kubernetes service account tokens (ADR-0094). Keycloak names a realm in `iss` as
`<address>/auth/realms/<realm>`, without `/auth` from Keycloak 17 on (the Keycloak 17 release notes), and serves the
keys of the realm at that address followed by `/protocol/openid-connect/certs`. Before this record, ADR-0091 described
the issuers in one trusted providers file, with a `keycloak` section for the realms and a list of providers, one of
which the member `kubernetes: true` marked as the API server.

A service account token that the TokenRequest API issues, the token projected into a Pod among them, names the issuer of
the API server in `iss` (`GenerateToken` in `pkg/serviceaccount/jwt.go` of Kubernetes). A token from a Secret of the
type `kubernetes.io/service-account-token` names `kubernetes/serviceaccount` in `iss` and has no `exp` (`LegacyIssuer`
in `pkg/serviceaccount/legacy.go`).

A ConfigMap mounted as a directory without `subPath` shows each key as a symbolic link into a directory whose name
starts with `..`, and the kubelet updates the mount by switching that directory (`AtomicWriter` in
`pkg/volume/util/atomic_writer.go` of Kubernetes).

## Decision

We will read the trusted providers from the JSON files in the fixed directory `/etc/authz/providers`, accept only the
providers under the keys `identity-provider` and `kubernetes`, and let the key of a provider decide its checks. The
`iss` of a token will match the configured `issuer` or `issuerTemplate` as a whole, and the keys will come only from
the configured `jwksUri`.

### Terms

- **Provider directory**: the directory that R1 names.
- **Provider file**: an entry of the provider directory that R2 makes one.
- **Provider**: a member of the `providers` object of a provider file, named by its key.
- **Provider `identity-provider`**, **provider `kubernetes`**: the provider under that key.
- **`realms` provider**, **`single` provider**: a provider whose `type` is that value.
- **Realm**: a `realms` provider together with one realm name that R20 accepts.
- **Source**: a `single` provider or a realm, as a place that keys are read from.
- **Required source**: a source that R25 names.
- **Issuer**: the value of the `iss` claim of a token.
- **Kubernetes token**, **identity-provider token**: the two kinds of token that R22 names.
- **In-cluster address**: as ADR-0094 defines it.
- **Stops the start**: as ADR-0091 defines it.

### Rules

#### The provider files

- **R1** (`keys`, `startup`). The agent reads its providers from the directory `/etc/authz/providers`. No setting
  changes this path.
- **R2** (`keys`). Every entry directly in the provider directory whose name ends in `.json` and does not start with `.`
  is a provider file, unless it is a directory or a symbolic link to one. The agent reads a provider file through a
  symbolic link, reads no directory, and skips every other entry of the provider directory.
- **R3** (`keys`). A provider file stops the start when the agent cannot read it, when its content is not a JSON text
  under RFC 8259, or when one of its objects holds two members with the same name.
- **R4** (`keys`). The providers of all provider files form one set. A provider directory that is missing or cannot be
  read stops the start, and so does a set without a provider.
- **R5** (`startup`). The agent reads the provider directory and the provider files only at start.

#### The format of a provider file

- **R6** (`keys`). A provider file is valid under the JSON Schema
  [`api/provider-file.v1.schema.json`](../../api/provider-file.v1.schema.json), draft 2020-12. A provider file that the
  schema does not accept stops the start.

#### The members of a provider

- **R12** (`keys`). Each name in `readinessRealms` is a realm name as it stands in place of `{realm}` in `iss` after
  percent-decoding. The agent uses each name as written and resolves none of them through tenant-manager or another
  service. A name that R20 does not accept stops the start.
- **R13** (`keys`). A provider without `readinessRealms` names no realm as required, and the agent adds no realm of its
  own, `cloud-common` included.
- **R14** (`keys`). A `jwksBearerTokenFile` whose file the agent cannot read at start stops the start.

#### The providers together

- **R16** (`keys`). Two provider files that each hold a provider under the same key stop the start.
- **R17** (`keys`). Two providers that overlap stop the start. Two `single` providers overlap when their `issuer` values
  are equal. A `single` and a `realms` provider overlap when the `issuer` of the `single` one, taken as an `iss`,
  matches the `realms` one under R19. Two `realms` providers overlap when their `issuerTemplate` values have the same
  scheme, host, and port and the same number of path segments, and are equal in each segment where neither holds
  `{realm}`.
- **R18** (`keys`). An error that stops the start under R3, R4, R6, R12 to R14, R16, R17, or R28 names the provider
  directory or the provider file at fault. An error about a member of a provider file other than `providers` names each
  such member. Where the error concerns a provider, it names the provider by its key and names the member at fault. An
  error under R16 or R17 names both providers, each with its provider file. An error about `jwksBearerTokenFile` in the
  provider `identity-provider` also says that the provider of Kubernetes tokens has the key `kubernetes`.

#### The source of a token

- **R19** (`keys`, `verify`). The `iss` of a token matches a `single` provider when it equals `issuer` byte for byte,
  and that provider is then the source of the token. It matches a `realms` provider when it is longer than the bytes of
  `issuerTemplate` before and after `{realm}` together, starts with the bytes before `{realm}`, ends with the bytes
  after `{realm}`, and the bytes between those two parts percent-decode to a realm name that R20 accepts; the realm with
  that name is then the source of the token. Nothing is normalized before the comparison: not the case of the scheme or
  the host, a default port, a trailing slash, or the percent-encoding outside the realm name.
- **R20** (`keys`). A realm name is accepted when it is valid UTF-8, is not empty, is not `.` or `..`, holds no `/`,
  `?`, `#`, or character of the Unicode class Cc, and is at most 255 bytes long.
- **R21** (`verify`). A token whose `iss` is missing or matches no provider under R19 is refused with
  `TOKEN_ISSUER_UNKNOWN`.
- **R22** (`verify`). A token whose source under R19 is the provider `kubernetes` is a Kubernetes token, and a token
  whose source is the provider `identity-provider` or one of its realms is an identity-provider token. The key of the
  provider alone decides the kind: no other member of the provider, its `type` included, and no claim of the token
  changes it. A check that a record attaches to a Kubernetes token never runs on an identity-provider token, and an
  identity-provider token that holds the claim `kubernetes.io` gets no check and no refusal from that claim.

#### The keys

- **R23** (`keys`). The agent requests the keys of a source only at the `jwksUri` of its provider, as written. For a
  realm it puts the realm name, escaped as one path segment, in place of `{realm}`. It follows no redirect, requests no
  discovery document, and builds no address from a token other than by putting the realm name into `jwksUri`.
- **R24** (`keys`). The agent sends the token in the file that `jwksBearerTokenFile` names, as a bearer token, only with
  the requests for the keys of its provider. R28 and ADR-0094 R32 limit the addresses of those requests.
- **R28** (`keys`). A provider `kubernetes` whose `jwksBearerTokenFile` is set and whose `jwksUri` is not an in-cluster
  address stops the start.
- **R29** (`keys`, `startup`). At start, once the agent has read the file that the `jwksBearerTokenFile` of the provider
  `kubernetes` names (R14), it reads the `iss` of the token in it without checking its signature and compares it byte
  for byte with the `issuer` of the provider. When the two differ, or the token holds no `iss` that the agent can read,
  the agent logs one warning. The warning names the provider file, the `issuer`, the file that `jwksBearerTokenFile`
  names, and the `iss` where the agent read one, and never holds the token. The comparison changes neither the start nor
  readiness. Without `jwksBearerTokenFile` the agent compares nothing.
- **R25** (`keys`, `startup`). The required sources are every `single` provider and every realm whose name the
  `readinessRealms` of its provider lists.

#### The audience

- **R26** (`verify`). A token whose provider has the `audience` mode `matchAny` passes the check of `aud` when its
  `aud` is a string that is one of the `values`, or an array of strings that holds one of them, compared byte for byte.
  A token without `aud` is refused with `TOKEN_AUDIENCE_MISSING`, and a token with any other `aud`, such as an array
  that also holds a number, is refused with `TOKEN_AUDIENCE_INVALID`. With the mode `ignore`, the agent does not check
  `aud`, whether the token has one or not. The check is the same for a token in `Authorization` and in
  `Incoming-Token`.

### Implementation notes

Adds no requirement. Two files describe a Keycloak at `http://identity-provider:8080` and the API server of the
cluster. Each names the schema in `$schema`, which the schema allows, so an editor that reads JSON Schema validates and
completes the file. `identity-provider.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/Netcracker/qubership-authz-agent/main/api/provider-file.v1.schema.json",
  "providers": {
    "identity-provider": {
      "type": "realms",
      "issuerTemplate": "http://identity-provider:8080/auth/realms/{realm}",
      "jwksUri": "http://identity-provider:8080/auth/realms/{realm}/protocol/openid-connect/certs",
      "readinessRealms": ["cloud-common"],
      "audience": {"mode": "ignore"}
    }
  }
}
```

`kubernetes.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/Netcracker/qubership-authz-agent/main/api/provider-file.v1.schema.json",
  "providers": {
    "kubernetes": {
      "type": "single",
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
      "jwksBearerTokenFile": "/var/run/secrets/tokens/kubernetes/token",
      "audience": {"mode": "matchAny", "values": ["netcracker"]}
    }
  }
}
```

A token with `iss` `http://identity-provider:8080/auth/realms/a%20b` selects the realm `a b`, whose keys the agent
requests at `http://identity-provider:8080/auth/realms/a%20b/protocol/openid-connect/certs`. In Go, `url.PathEscape`
escapes the name, and `os.Stat` on an entry follows a symbolic link.

Both files are valid under `api/provider-file.v1.schema.json`, and a JSON Schema validator for draft 2020-12 can check a
file against it. The patterns of the schema use only syntax that ECMA-262 and Go's `regexp` read alike. ECMA-262 is the
dialect that draft 2020-12 names for `pattern`.

### Justification

A fixed directory gives the agent one place to look and a deployment one place to mount, with no setting that the chart
and the agent have to agree on (R1). Several files let each provider stand in a file of its own (R2, R4). The agent
skips names that start with `.` and reads through symbolic links, because a ConfigMap mounted as a directory keeps its
data in hidden directories and links each key into them (R2). Reading the files only at start fixes the providers of a
process for its lifetime, and an upgrade that changes a provider file restarts the Pods (R5; ADR-0105 R13).

A JSON Schema states the format of a provider file in one place, in a notation that validators and editors read, and
the other rules state what the agent does with each member (R6). The schema is a file of its own with an `$id`, so a
provider file can name it in `$schema`, an editor then validates and completes the file without setup, and the version
in the name of the file gives the format a version for later changes. R20 stays outside the schema, because R19
applies it to the realm name in an `iss` as well, and its limit counts bytes, where `maxLength` of JSON Schema counts
characters (R12, R20).

`providers` is an object keyed by the name of each provider. A misspelled key gets one error that names it, where a
misspelled name inside a list of providers gets an error from every branch of the schema, and an editor offers exactly
the two keys. R3 already refuses one key twice in one file, so R16 compares only the files. `type` decides which members
a provider accepts, so a missing or unknown `type` gets one error, and an editor offers the members of the chosen type.
Its values `realms` and `single` name the shape of a provider, one issuer per realm or one issuer, rather than how `iss`
is compared, because R19 compares `iss` byte for byte for both.

The format is built to take more identity providers later without a new format. This stage trusts two providers: the
platform's Keycloak and the API server of the cluster. Later stages may add an identity provider of a project, aliases
of one issuer (`issuerAliases`), a check of `aud` that differs between the two headers or that an operator sets in the
chart values, and provider files that a project mounts beside the chart's. The provider file is shaped for that.
`providers` is an object keyed by name, so a new provider is a new key, and the files written for this stage stay valid.
`type` says how a provider names its issuers, apart from its key. `audience` is an object that can gain a mode. The
agent merges every provider file of the directory, so another file can add a provider (R2, R4). The schema file carries
its version in its name, `provider-file.v1.schema.json`, which its `$id` repeats, so a later format gets a file and an
`$id` of its own. Each new key needs a record of its own that decides what its tokens may do: their kind and the checks
they get. Until such a record exists, R6 refuses any other key (R6, R22).

A member that the agent ignored would be a setting that the operator relies on and the agent does not apply. Stopping
the start shows the mistake before any token is accepted, and a file in the former format cannot run with members that
the agent no longer reads, such as `allowMissingAud` or `caFile` (R3, R6).

The key decides the kind of a token, and with the kind the checks that other records attach to it: the namespace of
ADR-0094 R17, the M2M test of ADR-0092 R6, R7, and R21, and the future `iat` of ADR-0091 R48 (R6, R22). With two keys, a
file cannot describe the API server under a third key that gets none of those checks. Further providers wait for a
later stage, which decides what their tokens may do. The key `identity-provider` keeps the name that the platform's
`IDENTITY_PROVIDER_URL` gives its Keycloak. No check can tell that Keycloak from another identity provider that a file
describes under the same key, and the tokens of such a provider pass the M2M test of ADR-0092 R6 and R21 with whatever
claims it signs. The description of the key in the schema therefore states that it stands for the platform's Keycloak
alone (R6, R22).

The claim `kubernetes.io` is whatever the signer puts in a token, so it decides neither the kind of a token nor which
checks run on it (R22). A provider `identity-provider` whose issuer is an API server therefore makes the tokens of that
API server identity-provider tokens, with no namespace check. The architect accepted that cost on 2026-11-25, and the
Negative consequences name it (R22). Where the provider files hold no provider `kubernetes`, as outside Kubernetes, a
token that an API server signed is refused under R21, unless a provider `identity-provider` names its issuer (R22). A
token from a Secret has no `exp` (Context), so ADR-0091 R44 refuses it.

`iss` names the signer, and RFC 7519, section 2, compares such values as case-sensitive strings with no
canonicalization. Comparing all of it, the host included, means a token that names another server starts no load, and
every verified token carries an `iss` in a form that the configuration names (R19). No `iss` can match two providers,
so a token has one source and no rule has to choose between providers (R17, R19). Only the provider
`identity-provider` can be a `realms` provider in this stage, so the overlap of two of them cannot occur yet; R17 states
it so that a later stage that allows another key keeps the same check.

A token selects its source but names no address: the keys come from the `jwksUri` that the operator wrote, so a token
cannot send the agent to a server of its choosing (R23). A configured `jwksUri` needs no discovery document, whose
server would choose the address of the keys, and it works where the issuer of the API server cannot be reached from
inside the cluster (ADR-0094 Context). `{realm}` stands for one whole path segment, and R20 keeps the decoded name from
adding a segment, a query, or a fragment, so the name stays inside its segment of the address (R6, R20, R23).

The agent holds nothing specific to Keycloak: the path `/auth/realms/`, the path of the keys, and the realm
`cloud-common` come from the provider files, so a Keycloak without `/auth` needs another file and no change of the agent
(R6, R13, R19, R23).

The required sources are the ones that the configuration names: a `single` provider and the realms in
`readinessRealms` (R25). Every other realm loads on its first token. The names are the realm names that tokens carry,
because the agent runs where no tenant-manager exists (R12).

The token in `jwksBearerTokenFile` grants access to the API server of the cluster, so only the provider `kubernetes` may
name one, and it goes only with the requests for the keys of that provider (R6, R24). A host outside the cluster that
received the token would get that access, so R28 keeps the token to an in-cluster address. A cluster that serves its
keys to an anonymous request needs no token, so the member is optional. A member that names a file the Pod does not hold
is a fault of the deployment that no wait repairs, so it stops the start (R14). An operator who sets
`jwksBearerTokenFile` on the provider `identity-provider` most likely meant the provider of Kubernetes tokens, so the
error names its key (R18).

The issuer of the provider `kubernetes` is a value of the provider file (R6; A6). A wrong value leaves the Pod ready
while every token that the API server signs gets `TOKEN_ISSUER_UNKNOWN` (R21). The token in `jwksBearerTokenFile` comes
from the API server of the cluster, so its `iss` shows the issuer that the provider should name, and a warning at the
start points at the mistake before the refusals do. The comparison only warns: the agent reads the token without
checking its signature, and a token from a Secret names another `iss` even when the `issuer` is right (Context), so the
token never becomes a second source of the issuer (R29).

`audience` has no default, so the file states whether `aud` is checked. The platform's Keycloak has no audience mapper
that names the services of an installation, so a file for it sets `ignore`, which R6 allows. The name of the mode says
that a token with any `aud`, or with none, passes the check, a token issued for another service included (R26). The
check of a provider is the same in both headers, so a Kubernetes token that the API server issued for another audience,
such as the default token of a Pod, passes in neither (R26).

### Alternatives considered

- **A1. Name the providers file with a setting, as `AUTHZ_TRUSTED_PROVIDERS_FILE` does.** Rejected by R1: every
  deployment mounts the files at one path, so the setting would only be one more value that the chart and the agent
  have to agree on.
- **A2. Mark the provider of the API server with `kubernetes: true` and accept any key.** Rejected by R6 and R22: the
  kind of a token would follow from a member that a file can set on any provider, and the key and the mark could
  disagree. This reverses ADR-0091 R6 and the choice of ADR-0094 that the mark, not the name of the provider, decides
  which tokens are Kubernetes tokens.
- **A3. Accept any key, and choose the checks of a provider with a member of its own, such as `kind`.** Rejected by R6
  and R22: each kind of token has one provider in this stage, so the member could only repeat the key or contradict it.
- **A4. Find the keys through OIDC discovery under the issuer.** Rejected by R23: the server of the discovery document,
  not the configuration, would choose the address of the keys, and in one cloud the issuer of the API server cannot be
  reached from inside the cluster. This reverses ADR-0091 R4 and ADR-0094 R6.
- **A5. Take the realm from the part of `iss` after the last slash, and leave the host uncompared.** Rejected by R19:
  a token that names any server would start a load at the configured Keycloak, and the `iss` of a verified token could
  name a server that the configuration does not. This reverses ADR-0091 R3 and the answer on the trusted realms in the
  questionnaire of 2026-11-03.
- **A6. Take the issuer of the provider `kubernetes` from the `iss` of the token in `jwksBearerTokenFile`.** Rejected
  by R6: the provider file states the issuer, and `jwksBearerTokenFile` is optional, so the agent cannot rely on it to
  learn the issuer. This reverses ADR-0094 R4 and the answer on the issuer of the API server in the questionnaire of
  2026-11-03.
- **A7. Require `jwksBearerTokenFile` wherever the provider files hold the provider `kubernetes`.** Rejected by R6: a
  cluster that serves its keys to an anonymous request needs no token, and the Pod then holds no credential for the API
  server. This reverses ADR-0094 R5.
- **A8. Drop the provider `kubernetes` when the file that its `jwksBearerTokenFile` names is missing.** Rejected by
  R14: the readiness probe would pass while the agent refuses every token that the API server signs.
- **A9. Give `readinessRealms` the default `cloud-common`.** Rejected by R13: the agent would carry the name of a realm
  of the platform's Keycloak, and a file for any other server would have to work around it. This reverses ADR-0091
  R15.
- **A10. Resolve the names in `readinessRealms` through tenant-manager, as for `AUTHZ_IDP_REALMS`.** Rejected by R12:
  the agent runs where no tenant-manager exists, and a token carries the realm name, not the display name of its
  tenant.
- **A11. Never check the `aud` of a Keycloak token, whatever the provider file states.** Rejected by R6 and R26: the
  provider file decides for each provider and in both headers, so a Keycloak that adds an audience for the services gets
  the check without a change of the agent. This reverses ADR-0091 R49 and departs from the answer on the `aud` of a
  Keycloak token in the questionnaire of 2026-11-03.
- **A12. Let one `iss` match two providers, and prefer one of them.** Rejected by R17: the source of a token would
  depend on a rule of precedence that an operator has to know. This reverses the precedence of a provider over the
  realm rule in ADR-0091 R7.
- **A13. Keep the tokens of a `single` provider `identity-provider` from being M2M tokens, as ADR-0092 R8 did for a
  file token.** Rejected by R22: the key alone decides the kind, so both types of the provider `identity-provider` give
  an identity-provider token, and ADR-0092 R6 and R21 decide whether it is an M2M token. This reverses ADR-0092 R8.
- **A16. Give every provider a limit of its own on the tokens it accepts, such as the namespaces of the installation for
  the API server of the agent's cluster, in place of a kind of token.** Rejected by R22: no installation needs the
  tokens of another cluster in this stage, and such a limit would change ADR-0094 well beyond one rule. A later record
  can give each provider a limit of its own.
- **A17. Keep `providers` as a list of objects, each named by a member `id`.** Rejected by R6: a misspelled `id` gets
  an error from every branch of the schema rather than one error that names it, and two providers with one `id` in one
  file need a check of their own, where R3 already refuses one key twice in one file.
- **A18. Refuse a token that holds the claim `kubernetes.io` and whose source is not the provider `kubernetes`, with
  `TOKEN_KUBERNETES_CLAIM_NOT_ALLOWED`.** Rejected by R22: the claim is whatever the signer puts in the token, and the
  architect decided on 2026-11-25 that a token of any provider may hold it, with the checks of a Kubernetes token
  following the provider. This reverses the refusal by the claim in the answer of 2026-11-18 in #305.
- **A19. Stop the start when a provider `identity-provider` names an in-cluster address in `issuer`, `issuerTemplate`,
  or `jwksUri`.** The architect decided on 2026-11-25 that the check of an in-cluster address stays only where the token
  for the API server goes (R28): a provider `identity-provider` that names the API server is a mistake of the provider
  file, as a wrong issuer is (Negative). This reverses ADR-0094 R13.
- **A20. Stop the start, or keep the Pod not ready, when the `issuer` of the provider `kubernetes` differs from the
  `iss` of the token in `jwksBearerTokenFile`.** Rejected by R29: the provider file is the only source of the issuer
  (R6), the agent reads the token without checking its signature, and a token from a Secret names another `iss` even
  when the `issuer` is right (Context).

## Consequences

Positive:

- A Keycloak without `/auth`, or at another address, needs another provider file and no change of the agent (R6, R19,
  R23).
- A misspelled key or member of a provider file gets an error that names it, and an editor that reads JSON Schema
  validates and completes a provider file that names the schema in `$schema` (R6, R18).

Negative:

- A file in the former format of ADR-0091 stops the start (R6), so the agent, the chart, and the test stands move to
  the provider files in one change.
- No check tells the platform's Keycloak from another identity provider that a provider file describes under the key
  `identity-provider`. The tokens of such a provider are identity-provider tokens, so they pass the M2M test of ADR-0092
  R6 and R21 with whatever claims that provider signs (R22).
- An `iss` that differs from `issuer` or `issuerTemplate` in any byte, such as another case of the host, an explicit
  default port, or a trailing slash, gets `TOKEN_ISSUER_UNKNOWN` (R19, R21). A Keycloak whose tokens name it at another
  address than the provider file, such as its public address, needs that address in `issuer` or `issuerTemplate`, and a
  Keycloak that issues tokens under two addresses cannot be described in this stage.
- After an upgrade to Keycloak 17 without `/auth`, new tokens get `TOKEN_ISSUER_UNKNOWN`, and the reloads of the realms
  that the agent holds fail, until the provider file names the new `issuerTemplate` and the new address of the keys
  (R19, R21, R23).
- A wrong `issuer` or `issuerTemplate` leaves the Pod ready: the keys of the provider still load from `jwksUri`, and
  every token of the provider gets `TOKEN_ISSUER_UNKNOWN` (R19, R21). For the provider `kubernetes` the issuer is a
  value set for each cluster, where A6 would read it from a token that the kubelet writes, so a wrong value refuses
  every token that the API server signs, in a Pod that is ready. For the provider `kubernetes` with
  `jwksBearerTokenFile`, R29 logs a warning at the start.
- A `realms` provider `identity-provider` without `readinessRealms` has no required source, so the Pod becomes ready
  before any realm has loaded keys, and a wrong `jwksUri` shows only in the refusals of its tokens and in the warnings
  of ADR-0091 R81 (R13, R25; ADR-0091 R23, R38, R39, R81).
- A provider `kubernetes` without `jwksBearerTokenFile` requests its keys without a token. A standard cluster refuses
  that request (ADR-0094 Context), and the Pod stays not ready (ADR-0091 R19).
- A name in `readinessRealms` that the Keycloak does not hold, such as the display name of a tenant, keeps the Pod not
  ready until the file changes (R12; ADR-0091 R14, R19).
- A change of a provider file takes effect only at the next start (R5).
- A token of a `single` provider `identity-provider` is an identity-provider token (R22), so the M2M test of ADR-0092
  R6 and R21 applies to it, where ADR-0092 R8 kept the tokens of a provider outside the realms of the Keycloak from
  being M2M tokens (A13).
- No rule of this record names the CA that the requests of R23 trust, and the rules of ADR-0091 and ADR-0094 that
  named one went with the requests that this record replaces. A `caFile` now stops the start under R6. An https
  `jwksUri` whose certificate a private CA or the cluster CA signs therefore works only once the agent trusts that CA in
  another way.
- A provider `identity-provider` whose issuer is an API server makes every token of that API server an identity-provider
  token (R22). Where the provider `kubernetes` names the same issuer, R17 stops the start. Otherwise, where the keys
  load without a token, as the public keys of a managed cluster do, the token of a Pod of that cluster passes with no
  namespace check of ADR-0094, and nothing at the start or in a refusal shows the mistake. Where the keys need a token,
  as at the in-cluster address of a standard cluster, they never load, because only the provider `kubernetes` may hold
  `jwksBearerTokenFile` (R6), and a `single` provider then keeps the Pod not ready (R25; ADR-0091 R19).
- A token of the provider `identity-provider` that holds the claim `kubernetes.io` passes, and policy evaluation gets
  that claim among the verified claims (ADR-0091 R54). Its kind is identity-provider (R22), so no check of ADR-0094
  compared the namespace in it with the namespaces of the installation. A policy that reads that namespace without
  checking the kind trusts what the identity provider wrote.
- A token from a Secret in `jwksBearerTokenFile` names `kubernetes/serviceaccount` in `iss` (Context), so R29 warns at
  every start even when the `issuer` is right. The chart mounts projected tokens (ADR-0094 R26), whose `iss` is the
  issuer of the API server.
- A provider `kubernetes` without `jwksBearerTokenFile` may name the issuer and the keys of the API server of another
  cluster, because R28 limits the address of its keys only when that member is set (R24, R28). The tokens of that
  cluster are then Kubernetes tokens, ADR-0094 R17 compares only the names of their namespaces, which another cluster
  can also use, and R29 has no token to compare the issuer with.
- An `Incoming-Token` with an `aud` that its provider does not accept fails the check of R26. The request goes on, and
  policy evaluation gets the reason code of the failure rather than the claims of that token (ADR-0095 R3).

Follow-ups:

- A record of a private CA decides the CA that the requests of R23 trust, in place of the term Cluster CA of ADR-0094.
