# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package token_taxonomy_test

import rego.v1

fixtures := data.fixtures.identity

authn_fixture := fixtures.authn

valid_authz_token := sprintf("Bearer %v", [fixtures.tokens.valid])

# ── Helper: canonical authorize with admission + subject ─────────────────

canonical_input(authz_token, subject_token) := {
  "authorizationToken": authz_token,
  "resources": [{"resourceType": "Customer", "operation": "READ", "resource": {}}],
  "subject": subject_token,
  "ignoreRls": true,
}

legacy_input(authz_token, subject_token) := {
  "compatPath": "/access/v1/check/resource",
  "authorizationToken": authz_token,
  "subject": subject_token,
  "legacyBody": {"type": "Customer", "operation": "READ", "resource": {}},
}

# ── TOKEN_MISSING ────────────────────────────────────────────────────────

test_admission_missing_returns_401 if {
  actual := data.authorize_internals.admission
    with input as canonical_input("", valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Authorization token is missing"
}

test_subject_missing_returns_deny if {
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, "")
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Authorization token is missing"
}

test_legacy_missing_returns_401 if {
  actual := data.authorize_internals.admission
    with input as legacy_input("", "")
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Authorization token is missing"
}

# ── Anonymous mode never answers with an evaluation error ────────────────
#
# The anonymous-accept and anonymous-with-bad-token rules used to overlap: for a
# subject like `Basic abc` both fired, producing two different values for one
# input, which OPA reports as an eval_conflict_error — a 5xx to an
# unauthenticated caller rather than a deny. They are complementary now.

anonymous_input(subject) := {
  "authorizationType": "anonymous",
  "subject": subject,
}

test_anonymous_with_non_bearer_subject_denies_rather_than_erroring if {
  auth := data.identity.authenticate(anonymous_input("Basic abc")) with data.authn as authn_fixture
  not auth.authenticated
  auth.error.reasonCode == "TOKEN_SCHEME_INVALID"
}

test_anonymous_with_blank_subject_is_anonymous if {
  auth := data.identity.authenticate(anonymous_input("   ")) with data.authn as authn_fixture
  auth.authenticated
  auth.subject.type == "ANONYMOUS"
}

test_anonymous_with_absent_subject_is_anonymous if {
  auth := data.identity.authenticate(anonymous_input("")) with data.authn as authn_fixture
  auth.authenticated
  auth.subject.type == "ANONYMOUS"
}

test_anonymous_with_valid_token_uses_the_token_subject if {
  auth := data.identity.authenticate(
    anonymous_input(sprintf("Bearer %v", [fixtures.tokens.valid])),
  ) with data.authn as authn_fixture
  auth.authenticated
  auth.subject.id == "user-allow"
}

# ── TOKEN_SCHEME_INVALID ─────────────────────────────────────────────────

test_admission_scheme_invalid_returns_401 if {
  actual := data.authorize_internals.admission
    with input as canonical_input("Basic sometoken", valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Authorization scheme must be Bearer"
}

test_subject_scheme_invalid_returns_deny if {
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, "Basic sometoken")
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Authorization scheme must be Bearer"
}

test_admission_naked_jwt_returns_401 if {
  actual := data.authorize_internals.admission
    with input as canonical_input(fixtures.tokens.valid, valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Authorization scheme must be Bearer"
}

test_subject_naked_jwt_returns_deny if {
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, fixtures.tokens.valid)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Authorization scheme must be Bearer"
}

test_legacy_scheme_invalid_returns_401 if {
  actual := data.authorize_internals.admission
    with input as legacy_input("Basic sometoken", "Basic sometoken")
    with data.authn as authn_fixture
  actual.authError.status == 401
}

test_legacy_naked_jwt_returns_401 if {
  actual := data.authorize_internals.admission
    with input as legacy_input(fixtures.tokens.valid, fixtures.tokens.valid)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Authorization scheme must be Bearer"
}

# ── TOKEN_FORMAT_INVALID ─────────────────────────────────────────────────

test_admission_format_invalid_returns_401 if {
  actual := data.authorize_internals.admission
    with input as canonical_input("Bearer not-a-jwt", valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Token is not a valid JWT"
}

test_subject_format_invalid_returns_deny if {
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, "Bearer not-a-jwt")
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Token is not a valid JWT"
}

# ── TOKEN_EXPIRED ────────────────────────────────────────────────────────

test_admission_expired_returns_401 if {
  token := sprintf("Bearer %v", [fixtures.tokens.expired])
  actual := data.authorize_internals.admission
    with input as canonical_input(token, valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Token has expired"
}

test_subject_expired_returns_deny if {
  token := sprintf("Bearer %v", [fixtures.tokens.expired])
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Token has expired"
}

# ── The iss claim is not a trust criterion (authz-agent-ADR-0075) ────────
#
# `wrongIssuer` is signed by the same key, with the same kid, and differs from
# `valid` only in its `iss`. It is accepted. This is the point of the ADR, not a
# gap in it: Keycloak reports the issuer as the host the request arrived
# through, so one realm reached via the in-cluster Service, the private gateway
# and the public gateway mints three issuer strings for the same key. The kid,
# and the signature under it, is what identifies the token.

test_admission_foreign_issuer_is_accepted if {
  token := sprintf("Bearer %v", [fixtures.tokens.wrongIssuer])
  actual := data.authorize_internals.admission
    with input as canonical_input(token, valid_authz_token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.tokenPayload
}

test_subject_foreign_issuer_is_accepted if {
  token := sprintf("Bearer %v", [fixtures.tokens.wrongIssuer])
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.tokenPayload
}

# Only the absence of an authError is asserted here: the legacy_input helper
# does not carry enough for the compat path to produce a decision — even the
# `valid` token yields `results: []` through it — so 401-or-not is the whole
# signal this shape can give. The canonical sibling above checks the decision.
test_legacy_foreign_issuer_is_accepted if {
  token := sprintf("Bearer %v", [fixtures.tokens.wrongIssuer])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
}

# ── One kid, several candidate keys ──────────────────────────────────────
#
# `collidingKid` carries the same kid as the primary key but is signed by a
# different provider's key. The first candidate cannot verify it; the second
# can, and the token is accepted on that one.

test_colliding_kid_is_resolved_by_signature if {
  token := sprintf("Bearer %v", [fixtures.tokens.collidingKid])
  r := data.identity.validate_token_with_reason(token) with data.authn as authn_fixture
  r.valid
  r.providerId == "other-idp"
}

# ── A second key of the same provider ────────────────────────────────────
#
# The supported rotation flow: a realm publishes two keys, both are indexed,
# tokens signed by either verify. The old key can then be retired.

test_second_key_of_same_provider_verifies if {
  token := sprintf("Bearer %v", [fixtures.tokens.secondKey])
  r := data.identity.validate_token_with_reason(token) with data.authn as authn_fixture
  r.valid
  r.providerId == "test-idp"
}

# ── TOKEN_KID_UNKNOWN ────────────────────────────────────────────────────

test_admission_unknown_kid_returns_401 if {
  token := sprintf("Bearer %v", [fixtures.tokens.unknownKid])
  actual := data.authorize_internals.admission
    with input as canonical_input(token, valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT kid is not found in trusted provider keys"
}

test_subject_unknown_kid_returns_deny if {
  token := sprintf("Bearer %v", [fixtures.tokens.unknownKid])
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT kid is not found in trusted provider keys"
}

test_legacy_unknown_kid_returns_401 if {
  token := sprintf("Bearer %v", [fixtures.tokens.unknownKid])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── Valid admission + valid subject -> ALLOW ─────────────────────────────

test_valid_admission_and_subject_allow if {
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, valid_authz_token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.tokenPayload
}

# ── Admission short-circuit: OLS/RLS not evaluated on admission failure ──

test_admission_failure_short_circuits_policy if {
  actual := data.authorize_internals.admission
    with input as canonical_input("Bearer not-a-jwt", valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  not object.get(actual, "results", false)
}

# ── OLS DENY reason ─────────────────────────────────────────────────────

# ── RLS DENY reason ─────────────────────────────────────────────────────

# ── Incoming-Token ignored ───────────────────────────────────────────────
# Validates that the OPA input contract uses subject/authorizationToken
# and does not accept Incoming-Token as a field.

test_incoming_token_field_is_not_used if {
  actual := data.authorize_internals.admission
    with input as {
      "authorizationToken": valid_authz_token,
      "resources": [{"resourceType": "Customer", "operation": "READ", "resource": {}}],
      "subject": valid_authz_token,
      "incoming-token": valid_authz_token,
      "ignoreRls": true,
    }
    with data.authn as authn_fixture

  actual.tokenPayload
}

test_incoming_token_cannot_replace_missing_subject if {
  actual := data.authorize_internals.admission
    with input as {
      "authorizationToken": valid_authz_token,
      "resources": [{"resourceType": "Customer", "operation": "READ", "resource": {}}],
      "subject": "",
      "incoming-token": valid_authz_token,
      "ignoreRls": true,
    }
    with data.authn as authn_fixture

  actual.subjectError
}

# ── Legacy endpoints: invalid token always 401, never 200+DENY ───────────

test_legacy_expired_token_returns_401_not_deny if {
  token := sprintf("Bearer %v", [fixtures.tokens.expired])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  not object.get(actual, "results", false)
}

test_legacy_format_invalid_returns_401 if {
  actual := data.authorize_internals.admission
    with input as legacy_input("Bearer garbage", "Bearer garbage")
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Token is not a valid JWT"
}

# ── Crafted JWT helper ────────────────────────────────────────────────────
# Builds a JWT from raw header/payload objects with a dummy signature.
# io.jwt.decode parses the structure; signature verification will fail.

craft_jwt(header_obj, payload_obj) := jwt if {
  h := base64url.encode_no_pad(json.marshal(header_obj))
  p := base64url.encode_no_pad(json.marshal(payload_obj))
  jwt := concat(".", [h, p, "ZHVtbXlzaWduYXR1cmU"])
}

valid_header := {"alg": "RS256", "typ": "JWT", "kid": "test-idp-k1"}
valid_payload := {
  "iss": "https://idp.test.local/realms/main",
  "sub": "crafted-user",
  "aud": ["authz-agent"],
  "iat": 1704067200,
  "nbf": 1704067200,
  "exp": 2019427200,
  "realm_access": {"roles": ["ROLE_VIEWER"]},
}

# ── validate_token_with_reason unit tests ────────────────────────────────

test_vtwr_token_missing if {
  r := data.identity.validate_token_with_reason("") with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_MISSING"
}

test_vtwr_scheme_invalid if {
  r := data.identity.validate_token_with_reason("Basic foo") with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_SCHEME_INVALID"
}

test_vtwr_format_invalid if {
  r := data.identity.validate_token_with_reason("Bearer not-a-jwt") with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_FORMAT_INVALID"
}

test_vtwr_expired if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.expired]),
  ) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_EXPIRED"
}

test_vtwr_foreign_issuer_is_valid if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.wrongIssuer]),
  ) with data.authn as authn_fixture
  r.valid
  r.providerId == "test-idp"
}

test_vtwr_unknown_kid if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.unknownKid]),
  ) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_KID_UNKNOWN"
}

test_vtwr_valid if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.valid]),
  ) with data.authn as authn_fixture
  r.valid
}

# ── TOKEN_KID_MISSING ────────────────────────────────────────────────────
#
# `noKid` is a properly signed token whose header simply has no kid. Since the
# lookup is by kid alone there is nothing to try, and there is deliberately no
# single-key fallback: guessing was the one place the agent used to.

test_vtwr_kid_missing if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.noKid]),
  ) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_KID_MISSING"
}

test_admission_kid_missing_returns_401 if {
  token := sprintf("Bearer %v", [fixtures.tokens.noKid])
  actual := data.authorize_internals.admission
    with input as canonical_input(token, valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT header does not contain required kid"
}

test_subject_kid_missing_returns_deny if {
  token := sprintf("Bearer %v", [fixtures.tokens.noKid])
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, token)
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT header does not contain required kid"
}

test_legacy_kid_missing_returns_401 if {
  token := sprintf("Bearer %v", [fixtures.tokens.noKid])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# An empty-string kid is a missing kid, not an unknown one: `not header.kid`
# is false for "", so without the explicit check this reported KID_UNKNOWN and
# sent the operator looking for a key that was never named.
test_vtwr_empty_kid_reads_as_missing if {
  header := object.union(valid_header, {"kid": ""})
  jwt := craft_jwt(header, valid_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_KID_MISSING"
}

# When a token is missing both, the algorithm is the more alarming fact — an
# `alg: none` token is an attack, a missing kid is usually a misconfigured IdP.
test_vtwr_alg_none_outranks_missing_kid if {
  jwt := craft_jwt({"alg": "none", "typ": "JWT"}, valid_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_ALG_NOT_ALLOWED"
}

# ── An absent iss claim is no longer an error ────────────────────────────

test_vtwr_absent_issuer_is_not_itself_a_rejection_reason if {
  jwt := craft_jwt(valid_header, object.remove(valid_payload, ["iss"]))
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture

  # The crafted token has a dummy signature, so it still fails — but on the
  # signature, which is the only thing left that can reject it. The old
  # TOKEN_ISSUER_MISSING (priority 40) would have outranked that.
  not r.valid
  r.reasonCode == "TOKEN_SIGNATURE_INVALID"
}

# The positive half of the same statement, with a real signature: a properly
# signed token with no `iss` claim at all authenticates. `wrongIssuer` covers
# "a different iss"; this covers "no iss".
test_vtwr_signed_token_without_issuer_is_accepted if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.noIssuer]),
  ) with data.authn as authn_fixture
  r.valid
  r.providerId == "test-idp"
}

# ── TOKEN_ALG_NOT_ALLOWED ───────────────────────────────────────────────

test_vtwr_alg_not_allowed if {
  bad_header := object.union(valid_header, {"alg": "HS256"})
  jwt := craft_jwt(bad_header, valid_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_ALG_NOT_ALLOWED"
}

test_admission_alg_not_allowed_returns_401 if {
  bad_header := object.union(valid_header, {"alg": "HS256"})
  jwt := craft_jwt(bad_header, valid_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT algorithm is not allowed by trusted provider"
}

test_subject_alg_not_allowed_returns_deny if {
  bad_header := object.union(valid_header, {"alg": "HS256"})
  jwt := craft_jwt(bad_header, valid_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT algorithm is not allowed by trusted provider"
}

test_legacy_alg_not_allowed_returns_401 if {
  bad_header := object.union(valid_header, {"alg": "HS256"})
  jwt := craft_jwt(bad_header, valid_payload)
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# The allowlist is exhaustive rather than prefix-matched: an invented `RSFOO`
# must be rejected here, not handed to decode_verify in the hope that it fails.
test_vtwr_invented_alg_is_rejected if {
  bad_header := object.union(valid_header, {"alg": "RSFOO"})
  jwt := craft_jwt(bad_header, valid_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_ALG_NOT_ALLOWED"
}

# ── Algorithm confusion, with real signatures ────────────────────────────
#
# The crafted cases above carry a dummy signature, so they would be rejected
# even if the algorithm check did nothing. These two are properly formed: with
# `algorithms` gone from the provider config, the algorithm check is the only
# thing that stops them.

test_vtwr_alg_none_is_rejected if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.algNone]),
  ) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_ALG_NOT_ALLOWED"
}

# HS256 signed with the verifier's own RSA public key as the shared secret —
# the classic key-confusion attack. The kid is valid and the MAC is correct for
# that secret; only "the algorithm must be asymmetric" rejects it.
test_vtwr_symmetric_alg_is_rejected if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.symmetricAlg]),
  ) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_ALG_NOT_ALLOWED"
}

# ── An omitted `audiences` means the aud claim is not checked ────────────
#
# This is the shape the chart generates by default (authz-agent-ADR-0075 §6),
# and the one place the implementation cannot be read off the intent:
# `io.jwt.decode_verify` REJECTS a token carrying an `aud` when the constraint
# set names none, so "do not check aud" has to be expressed by handing the
# token's own audience back. Without these two tests a default install would
# reject every real Keycloak token and nothing would have caught it.

authn_without_audiences := json.patch(authn_fixture, [{
  "op": "remove",
  "path": "/trustedProviders/byId/test-idp/audiences",
}])

test_no_configured_audiences_accepts_a_token_that_has_one if {
  r := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.valid]),
  ) with data.authn as authn_without_audiences
  r.valid
  r.providerId == "test-idp"

  # ... and the same token verifies against the configured-audience provider,
  # so this is not passing because the fixture lost something else.
  configured := data.identity.validate_token_with_reason(
    sprintf("Bearer %v", [fixtures.tokens.valid]),
  ) with data.authn as authn_fixture
  configured.valid
}

# The kid here is `test-idp-k2`, which resolves to exactly one candidate. The
# primary kid would not do: it is also claimed by `other-idp`, whose entry still
# configures audiences, so the missing-aud complaint would come from THAT
# provider and the test would prove nothing about this one.
test_no_configured_audiences_accepts_a_token_that_has_none if {
  header := object.union(valid_header, {"kid": "test-idp-k2"})
  jwt := craft_jwt(header, object.remove(valid_payload, ["aud"]))
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_without_audiences

  # The crafted token has a dummy signature, so it cannot pass — but it must
  # fail on the signature, which is the only thing left to reject it.
  not r.valid
  r.reasonCode == "TOKEN_SIGNATURE_INVALID"
}

# ── TOKEN_AUDIENCE_MISSING ──────────────────────────────────────────────

test_vtwr_audience_missing if {
  jwt := craft_jwt(valid_header, object.remove(valid_payload, ["aud"]))
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_AUDIENCE_MISSING"
}

test_admission_audience_missing_returns_401 if {
  jwt := craft_jwt(valid_header, object.remove(valid_payload, ["aud"]))
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT does not contain aud claim"
}

test_subject_audience_missing_returns_deny if {
  jwt := craft_jwt(valid_header, object.remove(valid_payload, ["aud"]))
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT does not contain aud claim"
}

test_legacy_audience_missing_returns_401 if {
  jwt := craft_jwt(valid_header, object.remove(valid_payload, ["aud"]))
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── TOKEN_AUDIENCE_INVALID ──────────────────────────────────────────────

test_vtwr_audience_invalid if {
  bad_payload := object.union(valid_payload, {"aud": ["wrong-audience"]})
  jwt := craft_jwt(valid_header, bad_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_AUDIENCE_INVALID"
}

test_admission_audience_invalid_returns_401 if {
  bad_payload := object.union(valid_payload, {"aud": ["wrong-audience"]})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT audience is not allowed by trusted provider"
}

test_subject_audience_invalid_returns_deny if {
  bad_payload := object.union(valid_payload, {"aud": ["wrong-audience"]})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT audience is not allowed by trusted provider"
}

test_legacy_audience_invalid_returns_401 if {
  bad_payload := object.union(valid_payload, {"aud": ["wrong-audience"]})
  jwt := craft_jwt(valid_header, bad_payload)
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── TOKEN_NOT_YET_VALID ─────────────────────────────────────────────────

test_vtwr_not_yet_valid if {
  bad_payload := object.union(valid_payload, {"nbf": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_NOT_YET_VALID"
}

test_admission_not_yet_valid_returns_401 if {
  bad_payload := object.union(valid_payload, {"nbf": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Token is not yet valid"
}

test_subject_not_yet_valid_returns_deny if {
  bad_payload := object.union(valid_payload, {"nbf": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Token is not yet valid"
}

test_legacy_not_yet_valid_returns_401 if {
  bad_payload := object.union(valid_payload, {"nbf": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── TOKEN_IAT_INVALID ───────────────────────────────────────────────────

test_vtwr_iat_invalid if {
  bad_payload := object.union(valid_payload, {"iat": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_IAT_INVALID"
}

test_admission_iat_invalid_returns_401 if {
  bad_payload := object.union(valid_payload, {"iat": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "Token iat claim is invalid"
}

test_subject_iat_invalid_returns_deny if {
  bad_payload := object.union(valid_payload, {"iat": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "Token iat claim is invalid"
}

test_legacy_iat_invalid_returns_401 if {
  bad_payload := object.union(valid_payload, {"iat": 4102444800})
  jwt := craft_jwt(valid_header, bad_payload)
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── TOKEN_SIGNATURE_INVALID ─────────────────────────────────────────────

test_vtwr_signature_invalid if {
  jwt := craft_jwt(valid_header, valid_payload)
  r := data.identity.validate_token_with_reason(sprintf("Bearer %v", [jwt])) with data.authn as authn_fixture
  not r.valid
  r.reasonCode == "TOKEN_SIGNATURE_INVALID"
}

test_admission_signature_invalid_returns_401 if {
  jwt := craft_jwt(valid_header, valid_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(sprintf("Bearer %v", [jwt]), valid_authz_token)
    with data.authn as authn_fixture
  actual.authError.status == 401
  actual.authError.reason == "JWT signature verification failed"
}

test_subject_signature_invalid_returns_deny if {
  jwt := craft_jwt(valid_header, valid_payload)
  actual := data.authorize_internals.admission
    with input as canonical_input(valid_authz_token, sprintf("Bearer %v", [jwt]))
    with data.authn as authn_fixture
  not object.get(actual, "authError", false)
  actual.subjectError
  actual.subjectError == "JWT signature verification failed"
}

test_legacy_signature_invalid_returns_401 if {
  jwt := craft_jwt(valid_header, valid_payload)
  token := sprintf("Bearer %v", [jwt])
  actual := data.authorize_internals.admission
    with input as legacy_input(token, token)
    with data.authn as authn_fixture
  actual.authError.status == 401
}

# ── Indirectly covered taxonomy keys ─────────────────────────────────────
#
# TOKEN_READ_FAILED:
#   Catch-all default fallback in _primary_token_error. Fires when no
#   other error rule matches. In practice every reachable failure path is
#   classified by a specific taxonomy key. Covered by: default rule exists
#   and returns {valid:false, reasonCode:"TOKEN_READ_FAILED"}.
#
# TOKEN_DECODE_FAILED:
#   OPA's io.jwt.decode either succeeds (returns header/payload) or fails
#   entirely (non-JWT input). When it fails, _can_decode_jwt returns false
#   and TOKEN_FORMAT_INVALID fires (priority 30). There is no intermediate
#   "partially decoded" state in OPA. Covered by: test_vtwr_format_invalid,
#   test_admission_format_invalid_returns_401, test_subject_format_invalid_returns_deny.
#
# TOKEN_REQUIRED_CLAIM_MISSING:
#   The one claim a token cannot do without is the header kid → TOKEN_KID_MISSING
#   (priority 40); a configured audience adds aud → TOKEN_AUDIENCE_MISSING
#   (priority 90). Both have explicit tests above. No further claim is
#   configurable as required, so TOKEN_REQUIRED_CLAIM_MISSING has no distinct
#   trigger path.
#
# TOKEN_ISSUER_MISSING, TOKEN_PROVIDER_UNTRUSTED:
#   Retired by authz-agent-ADR-0075. Nothing reads the iss claim any more, and
#   "cannot be attributed to a trusted provider" is now exactly
#   TOKEN_KID_UNKNOWN — one condition, one name. See
#   test_vtwr_issuer_absent_is_valid and test_vtwr_foreign_issuer_is_valid.
