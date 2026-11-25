# Verify tokens before policy evaluation against the keys of trusted issuers

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Owner

kichasov

#### Participants and approvers

- The project architect (`mr-joom`) approves this record, and with it the answers it takes from the owner of the policy
  decision code on realms, key selection, reloads, and checks.
- The owner of the policy decision code (`vlsi`) returned the questionnaire of 2026-11-03.
- The Netcracker/qubership-authz-agent maintainers (kichasov).

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  this record supersedes these statements. Under "Handlers instead of Lua": the check routes refuse a missing or invalid
  token in `Authorization` before the policies run (ADR-0092 R1, R2), the policies no longer validate the tokens (R58),
  and the handlers no longer build the same input as before, because the compact tokens leave it (R76). Under
  "In-process supporting logic": the JWKS bootstrap no longer writes keys into the store (R67), and the reload of the
  trusted providers goes away (ADR-0104 R5).
- [authz-agent-ADR-0092: Accept any verified token in Authorization and limit a caller that is not M2M to its tenant](20261029-authz-agent-adr-0092-tokens-in-authorization.md):
  ADR-0092 R6, R7, and R21, the M2M test whose result the verification returns.
- [authz-agent-ADR-0093: Take the tenant of a decision from the verified user token, then from the request](20261029-authz-agent-adr-0093-tenant-of-a-decision.md):
  ADR-0093 R10 to R14, the default tenant, and ADR-0093 R17, the policy snapshots that readiness waits for.
- [authz-agent-ADR-0094: Accept Kubernetes service account tokens from the namespaces of the installation](20261029-authz-agent-adr-0094-kubernetes-service-account-tokens.md):
  ADR-0094 R3, R26, R28, R31, and R32, the provider `kubernetes` and the tokens that the chart mounts, and
  ADR-0094 R16 to R25, the extra checks of a Kubernetes token.
- [authz-agent-ADR-0095: Refuse a check request before policy evaluation](20261029-authz-agent-adr-0095-refuse-before-policy-evaluation.md):
    ADR-0095 R16, the index of the reason codes.
- [authz-agent-ADR-0096: Choose the token the agent sends with a setting of its own](20261105-authz-agent-adr-0096-token-the-agent-sends.md):
  the agent's token, which liveness does not depend on.
- [authz-agent-ADR-0104: Describe the two trusted providers in a fixed directory of provider files](20261123-authz-agent-adr-0104-trusted-provider-files.md):
  the provider files and the words for providers, realms, sources, issuers, and the two kinds of token (ADR-0104 R22);
  the source of a token (ADR-0104 R19 to R21), the address of its keys (ADR-0104 R23), the required sources (ADR-0104
  R25), and the check of `aud` (ADR-0104 R26).
- [authz-agent-ADR-0105: Configure the two providers through the chart values](20261123-authz-agent-adr-0105-providers-through-chart-values.md):
  the provider files that the chart writes, with both providers in every installation (ADR-0105 R2) and the provider
  `identity-provider` derived from `IDENTITY_PROVIDER_URL` (ADR-0105 R3); the token that the chart mounts for the
  `jwksBearerTokenFile` of the provider `kubernetes` (ADR-0105 R6); and the restart of the Pods when an upgrade changes
  a provider file (ADR-0105 R13).

## Context

A check route of the agent receives two tokens: the caller's token in `Authorization` and, optionally, the user's token
in `Incoming-Token`. Today Go fetches the keys of the trusted providers into the store as `data.authn`, and
`policies/identity.rego` parses and verifies both tokens on every evaluation. The token rules are split between the Go
code that loads keys and the Rego that checks claims, and a request with a bad token is evaluated before it is refused.

Every tenant has its own realm in one Keycloak, and the name of the realm is the identifier of the tenant. A token of a
realm names that realm in `iss`: `<address>/auth/realms/<realm>`. The agent runs in Kubernetes and on plain Linux, where
no tenant-manager may exist.

This record and ADR-0092 to ADR-0096 replace the numbers ADR-0084 to ADR-0086, which are retired. ADR-0084 became
ADR-0091, ADR-0092, and ADR-0095, ADR-0085 became ADR-0093 and the realms of ADR-0091, and ADR-0086 became ADR-0094 and
ADR-0096.

## Decision

We will verify every token in Go against the keys of the trusted issuers before the decision is evaluated.

### Terms

- **Provider directory**, **provider file**: as ADR-0104 defines them.
- **Provider**: as ADR-0104 defines it.
- **Provider `identity-provider`**, **provider `kubernetes`**: as ADR-0104 defines them.
- **`single` provider**: as ADR-0104 defines it.
- **Realm**: as ADR-0104 defines it.
- **Source**: as ADR-0104 defines it.
- **Required source**: as ADR-0104 defines it.
- **Load**: one attempt to read the keys of one source. A reload is any load of a source after its first one.
- **On-demand load**: a load that a token starts. The hourly reload is not one.
- **Result**: what a load that ended stores for its source: an answer, a 404, or a failure. R39 decides which.
- **Last result**: the result that a load of a source stored most recently. A realm the agent does not hold has
  none.
- **Kubernetes token**, **identity-provider token**: as ADR-0104 defines them.
- **Issuer**: as ADR-0104 defines it.
- **Stops the start**: the agent exits with an error before it serves a request. A package below `startup` reports this
  by returning an error from its constructor or parser.

The word Keycloak names the server.

### Rules

#### Trusted issuers

- **R78** (`keys`). The agent does not read `IDENTITY_PROVIDER_URL`.

#### Readiness

- **R14** (`startup`). The agent is ready once it has all of these:
  1. the policy snapshot of every tenant of the policy source (ADR-0093 R17);
  2. a usable key of every required source (ADR-0104 R25);
  3. the default tenant (ADR-0093 R10 to R14).
- **R16** (`keys`). A realm whose name is not in the `readinessRealms` of its provider loads on the first token that
  names it and does not affect readiness.
- **R17** (`startup`). The 503 of `/ready` names each unmet condition: the `single` provider by its key, the realm by
  its name, the tenant, or the default tenant.
- **R18** (`startup`). Liveness reports only that the process serves requests. It does not depend on keys, policy
  snapshots, tenant-manager, or the agent's token of ADR-0096.
- **R19** (`keys`). Keys that do not arrive do not end the process. The agent retries a required source with pauses of
  up to 10 seconds, logs a warning for each attempt, and stays not ready. The exception is a `jwksBearerTokenFile` whose
  file the agent cannot read at start, which stops the start under ADR-0104 R14.
- **R20** (`keys`). An agent that became ready stays ready whatever result a later reload ends with, also when it leaves
  a source without keys.

#### Finding a key

- **R21** (`keys`). A key is found by the source of the token under ADR-0104 R19 and then by `kid`, so two realms may
  publish one `kid`.
- **R22** (`verify`). `kid` is required. A token without it is refused with `TOKEN_KID_MISSING`.
- **R69** (`verify`). A token without `kid` starts no load.
- **R23** (`verify`). A token whose `kid` matches no loaded key of its source after R29 to R33, R70, and R71 is refused
  with the code of its result under R38:

  | Result | Code |
  | --- | --- |
  | An answer | `TOKEN_KID_UNKNOWN` |
  | A 404 | `TOKEN_KID_UNKNOWN` |
  | A failure, or no result | `TOKEN_KEYS_UNAVAILABLE` |

- **R24** (`keys`). A key in a JWKS without a `kid` is not loaded, because no token can name it.
- **R79** (`keys`, `verify`). The usable entries of a JWKS under one `kid` load as a list of keys, whatever their
  number. A key fits the `alg` of a token when its entry names that `alg`, or when its entry names no `alg` and its key
  type fits that `alg`, as its curve must for an EC or OKP key (R41). A token passes the check of its signature when a
  key of the list under its `kid` that fits its `alg` verifies it. A token whose `kid` matches a loaded key of its
  source, and for which no key of the list under that `kid` fits its `alg`, is refused with `TOKEN_ALG_NOT_ALLOWED`, and
  R43 does not apply to it.
- **R80** (`keys`). During a load, the agent refuses a response with any status other than 404 whose body is longer
  than 1 MiB (1048576 bytes), counted after it removes the gzip coding it requested.

#### Reloads

- **R25** (`keys`). The keys of every source are reloaded every hour.
- **R26** (`keys`). The hourly reload has a jitter per source of up to 10 percent.
- **R27** (`keys`). The hourly reload does not count toward the limit of R33.
- **R28** (`keys`). A reload whose result is not an answer keeps the keys already loaded. A key is removed only when a
  load ends in an answer without it. A key the agent cannot use counts as absent.
- **R29** (`keys`). A token that finds no key among those loaded starts an on-demand load of its source and of no other
  source. R69, R31, R33, R37, and ADR-0104 R19 to R21 limit this rule.
- **R70** (`keys`). A realm no token named before loads the same way.
- **R30** (`keys`). The requests that arrive while an on-demand load runs share it.
- **R71** (`keys`). Each of those requests waits at most 3 seconds.
- **R31** (`keys`). A source takes at most one on-demand load a minute. A request within that minute, when no load runs,
  is checked against the keys already loaded and sends no request.
- **R32** (`keys`). A token whose key is loaded never waits.
- **R33** (`keys`). An agent process starts at most 10 on-demand loads a minute over all sources. Past that, a token is
  checked against the keys already loaded.
- **R34** (`keys`). An agent process keeps at most 1000 realms of the provider `identity-provider`.
- **R35** (`keys`). A realm whose name is not in the `readinessRealms` of its provider, and that never loaded a key, is
  not asked again for a minute, and then gives up its place, so names that exist on no Keycloak do not fill the list.
  The hourly reload of R25 may ask it once more within that minute.
- **R36** (`keys`). A realm that loaded keys keeps its place, and a reload whose result is not an answer leaves its
  keys, as R28 states.
- **R37** (`keys`). With 1000 realms of the provider `identity-provider` held, a token of another realm of that provider
  evicts none of them and is refused with `TOKEN_KEYS_UNAVAILABLE`.
- **R38** (`keys`, `verify`). The result of a token under R23 is the last result of its source, with two exceptions.
  When the token started or joined an on-demand load of its source (R29, R30), only a result stored after that on-demand
  load started counts, and when no such result is stored by the time the token is checked, the token has no result. A
  token whose wait of R71 runs out, or whose request is canceled or reaches its deadline, before the load ends is
  checked at that moment. A token whose on-demand load R33 refused has no result.
- **R39** (`keys`). A load ends with one of these results:
  1. an answer, when the source returned a JWKS (a document with a `keys` array, even an empty one) and R80 does not
     refuse the response;
  2. a 404, when a request of the load got a 404;
  3. a failure in every other case, such as a 200 with any other body, a timeout, a 5xx, or a response that R80
     refuses.

  The agent does not read the body of a 404.
- **R81** (`keys`). A load of a source that is not required, whose result is not an answer, logs one warning that names
  the source, the result, and the request that decided it: its address, and the HTTP status of its response or the
  error.

#### Checks

- **R40** (`verify`). A token that is not a compact JWT, or whose header or payload cannot be parsed, is refused with
  `TOKEN_FORMAT_INVALID`.
- **R41** (`verify`). Only asymmetric algorithms are accepted: RS, PS, and ES with the curve of the algorithm, and EdDSA
  with Ed25519. HMAC, `none`, and any other `alg` are refused with `TOKEN_ALG_NOT_ALLOWED`.
- **R42** (`keys`). An RSA key needs a modulus of at least 2048 bits, and a shorter key is not loaded.
- **R43** (`verify`). A signature that does not verify is refused with `TOKEN_SIGNATURE_INVALID`. R79 limits this rule.
- **R44** (`verify`). `exp` is required, and `nbf` is honored when present, with a leeway of 30 seconds for every token.
  The codes are `TOKEN_EXP_MISSING`, `TOKEN_EXPIRED`, and `TOKEN_NOT_YET_VALID`.
- **R45** (`verify`). `exp` and `nbf` are checked against the time after the key is found, so a token that expires while
  its request waits for a load is refused.
- **R46** (`verify`). `iat` is required, or the token is refused with `TOKEN_IAT_MISSING`.
- **R47** (`verify`). A token whose `exp` comes before its `iat` is refused with `TOKEN_IAT_INVALID`.
- **R48** (`verify`). A Kubernetes token under ADR-0104 R22 with an `iat` more than 30 seconds in the future is refused
  with `TOKEN_IAT_INVALID`. No other token is refused for a future `iat`.
- **R51** (`verify`). `iss` is the one claim read before the signature verifies. Every other claim is read only after
  that.

#### What the verification returns

- **R52** (`handler`). `Incoming-Token` is verified as fully as `Authorization`, the check of `aud` under ADR-0104 R26
  included. The calling service is not trusted to have checked it.
- **R53** (`handler`). An empty `Incoming-Token` counts as no header, and nothing is verified.
- **R54** (`verify`). For a token that passes, the verification returns its verified claims whole, as the token carries
  them, its kind, and the result of the M2M test of ADR-0092 R6, R7, and R21. The kinds are the two of ADR-0104 R22: an
  identity-provider token and a Kubernetes token.
- **R55** (`verify`). For a token that fails, the verification returns the reason code of the check it failed and no
  claims, so no reader can rely on them.
- **R77** (`verify`). A token that fails several checks gets the code of the first check that runs. The order of the
  checks is the implementer's choice, within R51 and R69.
- **R74** (`verify`). The verification result of a failed token names its source only when the signature of the token
  verified.
- **R75** (`keys`). A line in the application log may name the realm in the `iss` of an unverified token, in quotes and
  as text taken from the token.
- **R56** (`verify`). The verification result holds no token in its compact form.
- **R76** (`handler`). The input of policy evaluation holds no token in its compact form.
- **R57** (`verify`). The verification selects no claims by what a policy declares.
- **R68** (`handler`). Every token is verified in Go against the keys of the trusted issuers before the decision is
  evaluated.

#### The policies and the store

- **R58** (`policy`). The policies do not verify tokens or read keys.
- **R67** (`keys`). The agent writes no keys into the store, and `data.authn` does not exist.

#### The verified-token cache

- **R59** (`verify`). A verified token is cached under the SHA-256 of its compact form until `exp`.
- **R60** (`verify`). A token that a check of this record, of ADR-0094 R16, or of ADR-0104 R21 or R26 refuses is not
  cached. A token refused for its namespace stays in the cache, because ADR-0094 R22 checks it again.
- **R61** (`verify`). A cached token is returned only while the key that verified it is still loaded for its source, so
  a withdrawn key stops a cached token at once.
- **R62** (`verify`). The cache holds the result of the verification and the claims, and nothing computed for a request.
- **R63** (`verify`). The cache holds at most 10000 tokens and evicts the least recently used one.

#### Settings that go away

- **R64** (`chart`). The settings of the current key loading go away: `AUTHZ_IDP_REALMS`,
  `AUTHZ_JWKS_BOOTSTRAP_REQUIRED`, `AUTHZ_JWKS_HTTP_RETRIES`, `AUTHZ_JWKS_HTTP_TIMEOUT`, `AUTHZ_TRUSTED_PROVIDERS`,
  `AUTHZ_TRUSTED_PROVIDERS_FILE`, and `AUTHZ_TRUSTED_PROVIDERS_RELOAD_INTERVAL`.
- **R65** (`chart`). The values schema refuses those settings, so an installation that still sets `AUTHZ_IDP_REALMS`
  learns that its trust widens.

### Justification

Verifying in Go puts every token rule in one tested package, and the cache verifies a token once until it expires (R59).
A request with a bad token in `Authorization` is refused before any policy runs, and the policies do not depend on how
keys are fetched (R58).

The operator names where keys come from: the provider files name each provider, its issuer, and the address of its
keys (ADR-0104 R19, R23). `iss` selects among the providers and their realms before the signature verifies and grants
nothing, because a token can name neither a server nor a key of its own (R51; ADR-0104 R23). A token that names another
realm than the one that signed it finds no key there or fails on its signature, so a token of a tenant cannot pass as a
token of `cloud-common`.

Taking the realm from `iss` needs no list of tenants, it lets the agent run without tenant-manager, and the same `kid`
in two realms stops being a conflict (R21; ADR-0104 R19).

A realm or a provider signs with a new key as soon as the key is active, so a token that finds no key makes the agent
look again (R29). That is how OpenID Connect Core 1.0, section 10.1.1, and the common clients find a rotated key. The
load is per source, so one unknown `kid` costs one realm rather than every realm. The limits bound what invented tokens
cost Keycloak, because a load happens before any signature is checked (R31, R33 to R35). When a load ends in an answer
(R39), the hourly reload drops a key that the source withdrew (R25, R28). A source that is down keeps its keys, so an
outage does not change which tokens the keys already loaded verify (R28).

A token that waited for a load counts only a result stored after the load started. In an older answer, an invented `kid`
and a key that the source added since look the same, so a 401 would refuse a valid token. A token that R31 keeps from
starting a load counts the last result, which is at most a minute old, because the source was asked within that minute.
When R33 refuses a load, the last result can be as old as the interval of the hourly reload (R25, R26), so a token whose
load R33 refused counts none. A result stored during the wait decides as any last result does, because a 503 after an
answer would report an outage that did not happen, and R23 gives a 404 the code of an answer (R23, R25, R26, R31, R33,
R38, R39).

A 404 says that no keys are at the address the agent asked, whether Keycloak does not hold the realm or a proxy has no
route for the path. The agent does not count it as an outage, so a token whose `kid` matches no loaded key gets the 401
of a token that names a key the source does not publish (R23, R39). The keys the agent holds stay, because the agent
cannot tell which of the two sent the 404, and a fault of the path should not refuse the tokens that those keys verify
(R28, R39). The agent does not read the body of the 404, because a check of the body would tie the agent to the error
format of one Keycloak version (R39).

A `single` provider has an address of its own, so a 404 for it most likely means a wrong `jwksUri` (R39). A wrong
`jwksUri` of the provider `identity-provider`, or a proxy with no route for it, can give a 404 for every realm. The
required sources show it at start, because the agent stays not ready until each of them has a usable key, and the 503 of
`/ready` names them (R14, R17, R19). For a source that is not required, the warning of R81 names the address of the
request that got the 404, and the limits of loads bound how many such warnings there are (R25, R31, R33, R81).

A source may list several keys under one `kid`, as RFC 7517, section 4.5, allows for keys of different `kty`. The agent
keeps them all and accepts a token that any of them verifies, so every JWKS that a source publishes loads, and the order
of its entries decides nothing (R79). The `alg` of an entry names the algorithm that the key is meant for (RFC 7517,
section 4.4), so an entry with an `alg` verifies only a token of that `alg`, and a key listed for RS256 does not verify
a PS256 token. A token whose `kid` matches held keys, none of which fits its `alg`, gets `TOKEN_ALG_NOT_ALLOWED`, the
code of an `alg` that no key accepts, rather than the code of a bad signature, and the order of the entries does not
change it (R43, R79). The limit of 1 MiB bounds the memory that reading the body of one response takes, and with it the
length of a list (R80).

Readiness rather than the process keeps traffic away from a Pod without keys (R14, R19): a restart would ask a Keycloak
that is already down, and the Pod would lose what it has loaded. Liveness stays apart for the same reason, because a
probe that followed keys would restart the Pod anyway, with a back-off that delays the recovery (R18).

The jitter keeps the Pods of one rollout from reloading in step (R26).

The cache holds the `Incoming-Token` of every user, and a Kubernetes token stays until an `exp` that its caller chose,
so the bound keeps the memory of a Pod independent of how many tokens it sees (R63).

Verifying `Incoming-Token` means that a service forwards the token as it is, and the agent does not rely on what the
service says about its user (R52). The verification ends at verified claims, so it does not depend on what a policy
declares (R57), and a failed token gives its readers a reason code instead of claims that nothing verified (R55).

### Alternatives considered

- **A1. Keep the checks in Rego.** Rejected by R58: the rules stay split between Go and Rego, and a request with a bad
  token is evaluated before it is refused.
- **A2. List the tenants from tenant-manager and keep one provider per realm.** Rejected by ADR-0104 R19: every
  deployment would need tenant-manager, and a `kid` that two realms publish would need a rule of its own. This reverses
  the choice of the meeting of 2026-10-28.
- **A3. Find a key by `kid` alone.** Rejected by R21: nothing makes a `kid` unique across realms.
- **A4. Make `kid` optional and select a key by `x5t` or as the one key of the issuer.** Rejected by R22: Keycloak and
  the API server set `kid` on every token they sign, so the extra selection rules would add code that no token reaches.
  The owner of the policy decision code answered for this option on the questionnaire of 2026-11-03, and this record
  keeps the required `kid` of the questionnaire of 2026-10-19.
- **A5. Stop the start when a required source has no keys.** Rejected by R19: a restart would ask a Keycloak that is
  already down, and the Pod would lose what it has loaded.
- **A6. Reload the keys every 24 hours.** Rejected by R25: a withdrawn key would stay accepted for up to a day.
- **A7. Reload only on the hourly schedule, never on demand.** Rejected by R29: the tokens a rotated key signs would be
  refused for up to an hour.
- **A8. Build the JWKS address of a realm from a path fixed in the agent.** Rejected by ADR-0104 R23: the agent would
  carry the path of the keys of one Keycloak layout, and a Keycloak with another layout would need a change of the agent
  rather than another provider file.
- **A9. Trust the service that sends `Incoming-Token`.** Rejected by R52: a user token that nothing checked would reach
  policy evaluation.
- **A10. Pass the compact token to policy evaluation.** Rejected by R76: a raw credential would reach the input and
  possibly a log.
- **A11. Compute the subject and the TOKEN PIP values in the verification.** Rejected by R57: the verification would
  have to read the PIP declarations of every tenant.
- **A14. Count a 404 for a required source as a failure, so that a token whose `kid` matches no loaded key gets
  `TOKEN_KEYS_UNAVAILABLE`.** Rejected by R39, under which a 404 for any source is a 404 rather than a failure, so that
  R23 gives the tokens of every source the same code, whether or not the configuration names the source. A wrong address
  of a required source still shows at start, because R14 keeps the agent not ready until the source has a usable key and
  `/ready` names it (R17).
- **A15. Count only a 404 of the discovery document as a 404, and a 404 of the `jwks_uri` that the document names as a
  failure.** Rejected by R39: R39 decides by a 404 to any request of a load, so the rule read the same when keys were
  found through discovery and reads the same now that a load is one request to a configured JWKS address (ADR-0104 R23).
  A `jwks_uri` that returns 404 after its discovery document returned 200 then ends the load in a 404, so R23 refuses a
  token whose `kid` matches no loaded key with `TOKEN_KID_UNKNOWN` rather than `TOKEN_KEYS_UNAVAILABLE`. This reverses
  the answer that the owner of the policy decision code gave on 2026-11-16.
- **A16. Refuse a response whose JWKS lists two usable entries under one `kid` that differ in key material or `alg`.**
  Rejected by R79: while the source lists such entries, the agent would load none of the keys the source adds and would
  keep the keys the source withdrew (R28), and RFC 7517, section 4.5, allows keys of different `kty` under one `kid`.
- **A17. Give a token whose result under R38 is a 404 a reason code of its own that names a missing realm.** Rejected by
  R23: the agent does not read the body of a 404, so the 404 of a proxy with no route and the 404 of a Keycloak that
  does not hold the realm look the same, and such a code would claim more than the agent knows (R39).

## Consequences

Negative:

- Every realm of the Keycloak is trusted, so an installation that listed a few realms in `AUTHZ_IDP_REALMS` accepts more
  tokens than before.
- Tokens reach Keycloak before any signature is checked. The limits bound the requests, but a stream of invented realms
  can hold all 10 loads, and a realm not loaded yet or a rotated key then waits up to a minute with its tokens refused.
- A Pod that cannot reach Keycloak stays not ready rather than failing, so the signal is the readiness probe and the
  warnings.
- Two requests with the same token at about the same time can get different codes, `TOKEN_KID_UNKNOWN` (401) and
  `TOKEN_KEYS_UNAVAILABLE` (503), depending on whether each one waited for an on-demand load that had not ended, whether
  R33 refused the load that one of them would have started, and on which result a load of the source had stored last
  when each one was checked against the keys already loaded (R23, R31, R33, R38).
- A key that a source activates under a new `kid` within a minute after an on-demand load of that source ended in an
  answer gives its tokens `TOKEN_KID_UNKNOWN` until the minute ends, because R31 lets no token start another load and
  the last result is that answer, without the key. The hourly reload ends this earlier when it loads the key, and gives
  the tokens `TOKEN_KEYS_UNAVAILABLE` instead when it ends in a failure. A client that reacts to the 401 by fetching a
  new token gets one signed by the same key, so the tokens of the new key are refused until the minute ends or the
  hourly reload loads the key (R23, R25, R31, R38).
- A 404 that something other than the server of the keys sends, such as a proxy with no route, gives `TOKEN_KID_UNKNOWN`
  (401) rather than `TOKEN_KEYS_UNAVAILABLE` (503) to a token whose `kid` matches no loaded key and whose result under
  R38 is that 404, for as long as the 404 lasts and up to a minute after it ends (R23, R31, R35, R39). A client then
  takes a fault of the path for a bad token. A request whose `Incoming-Token` gets that code does not end with the 503
  that ADR-0095 R3 gives for an outage, and is handled as ADR-0095 handles any user token that fails a check, so while
  the 404 lasts the decision is made without the user's token. Outside the required sources, nothing shows such a fault
  at start, and while it lasts the warnings of R81 name the address and the status.
- A token of a realm that Keycloak does not hold, as after its tenant is deleted, gets `TOKEN_KID_UNKNOWN` when its
  `kid` matches no loaded key and its result under R38 is a 404. That is the code of a token with an invented `kid`, so
  the audit and the metric of a refusal do not tell the two apart (R23, R39).
- After a realm is deleted from Keycloak, a Pod that loaded its keys before keeps them and accepts the tokens of the
  realm until they expire, and the realm keeps its place in the list of R34 until a restart (R28, R36, R39). A Pod that
  holds no keys of the realm refuses the same tokens, with the code that R23 gives.
- A token of a required source whose `kid` matches no loaded key and whose result under R38 is a 404 gets
  `TOKEN_KID_UNKNOWN` (401) rather than `TOKEN_KEYS_UNAVAILABLE` (503), although the configuration names that source.
  Before the source has a usable key, only a client that reaches a Pod that is not ready sees it (R14, R23, R39). After
  the source has keys, a 404 that starts later leaves the Pod ready and logs no warning, because R19 warns only while
  the agent is not ready and R81 only for a source that is not required, so only the refusals with `TOKEN_KID_UNKNOWN`
  show it (R19, R20, R81).
- A key that a source adds under a `kid` the agent already holds starts no on-demand load, because a token signed by it
  finds a key under its `kid`. Such a token gets `TOKEN_ALG_NOT_ALLOWED` when no held key under its `kid` fits its
  `alg`, and `TOKEN_SIGNATURE_INVALID` when one fits and none verifies it, until a load of the source ends in an answer,
  such as the hourly reload of R25 (R25, R28, R29, R43, R79).
- While a source returns a response that the agent refuses under R80, the agent keeps the keys it holds for that source
  (R28). A key that the source withdrew stays accepted. A token signed by a key that the source added gets
  `TOKEN_KEYS_UNAVAILABLE` when its `kid` matches no key the agent holds (R23). When the source added the key under a
  `kid` the agent already holds, the token is checked against the held keys without a load and gets
  `TOKEN_ALG_NOT_ALLOWED` when no held key under its `kid` fits its `alg`, and `TOKEN_SIGNATURE_INVALID` when one fits
  and none verifies it (R32, R43, R79). A source that has no keys loaded yet stays without keys, and a required source
  then keeps the agent not ready (R14, R19).
- An edit of a provider file outside Helm takes effect only at the next restart of the Pods (ADR-0104 R5; ADR-0105 R13).
- A provider that signs tokens without `kid` cannot be used, because all its tokens are refused.
- A token without `iat` passes the current policies, and an `iat` up to 300 seconds in the future passes for every
  token. This record refuses a token without `iat`, so a provider that does not set it cannot be used, and it checks a
  future `iat` only for a Kubernetes token.
- The limits of 10 loads a minute and 1000 realms have no measurement behind them. They fit the one or two tenants of
  most production installations. After a restart, a Pod of an installation with more than 10 active realms refuses the
  tokens of the realms past the limit, for about one minute per 10 realms.

Follow-ups:

- When this record is accepted, the status of ADR-0080 names the statements it supersedes.
