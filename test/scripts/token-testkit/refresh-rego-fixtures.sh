#!/usr/bin/env bash

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

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATE_JWKS_SCRIPT="${SCRIPT_DIR}/generate-rsa-jwks.sh"
MINT_SCRIPT="${SCRIPT_DIR}/mint-jwt.sh"

TOOLKIT_DIR="${TOOLKIT_DIR:-}"
PROVIDER_ID="test-idp"
KID="test-idp-k1"
ISSUER="https://idp.test.local/realms/main"
AUDIENCE="authz-agent"
VALID_ISSUED_AT="1704067200"
VALID_EXPIRES_IN="315360000"
EXPIRED_ISSUED_AT="1577836800"
EXPIRED_EXPIRES_IN="300"

# A second key of the SAME provider. This is the key rotation flow
# in fixture form: a realm publishes two keys at once and
# tokens signed by either must verify, so the operator can add a key, restart,
# and only then retire the old one.
SECOND_KEY_ID="second-key"
SECOND_KID="test-idp-k2"

# A DIFFERENT provider that happens to have chosen the SAME kid. Nothing stops
# two realms picking the same key identifier, so a kid resolves to a list of
# candidates and each is tried until one verifies.
COLLIDING_PROVIDER_ID="other-idp"
COLLIDING_ISSUER="https://idp.test.local/realms/other"

IDENTITY_FIXTURE_FILE="${ROOT_DIR}/policies/fixtures/identity/token_auth_fixtures.json"
AUTHN_DATA_DIR="${ROOT_DIR}/policies/test-data/authn"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

mint_token() {
  local subject="$1"
  local roles_csv="$2"
  local issued_at="$3"
  local expires_in="$4"
  local claims_json="${5:-}"
  local issuer="${6:-$ISSUER}"
  local kid="${7:-$KID}"
  local signing_key="${8:-$PRIVATE_KEY}"
  local claims_file=""
  local token=""

  if [[ -z "${claims_json}" ]]; then
    claims_json="{}"
  fi

  if [[ "${claims_json}" != "{}" ]]; then
    claims_file="$(mktemp)"
    printf '%s\n' "${claims_json}" > "${claims_file}"
  fi

  if [[ -n "${claims_file}" ]]; then
    token="$("${MINT_SCRIPT}" \
      --private-key "${signing_key}" \
      --kid "${kid}" \
      --issuer "${issuer}" \
      --subject "${subject}" \
      --audiences "${AUDIENCE}" \
      --roles "${roles_csv}" \
      --issued-at "${issued_at}" \
      --expires-in "${expires_in}" \
      --claims-file "${claims_file}")"
  else
    token="$("${MINT_SCRIPT}" \
      --private-key "${signing_key}" \
      --kid "${kid}" \
      --issuer "${issuer}" \
      --subject "${subject}" \
      --audiences "${AUDIENCE}" \
      --roles "${roles_csv}" \
      --issued-at "${issued_at}" \
      --expires-in "${expires_in}")"
  fi

  rm -f "${claims_file}"
  printf '%s\n' "${token}"
}

require_cmd jq
require_cmd mktemp
require_cmd base64

if [[ ! -x "${GENERATE_JWKS_SCRIPT}" ]]; then
  echo "error: JWKS generator is not executable: ${GENERATE_JWKS_SCRIPT}" >&2
  exit 1
fi

if [[ ! -x "${MINT_SCRIPT}" ]]; then
  echo "error: mint script is not executable: ${MINT_SCRIPT}" >&2
  exit 1
fi

cleanup_toolkit="false"
if [[ -z "${TOOLKIT_DIR}" ]]; then
  TOOLKIT_DIR="$(mktemp -d)"
  cleanup_toolkit="true"
fi

cleanup() {
  if [[ "${cleanup_toolkit}" == "true" ]]; then
    rm -rf "${TOOLKIT_DIR}"
  fi
}

trap cleanup EXIT

"${GENERATE_JWKS_SCRIPT}" \
  --provider-id "${PROVIDER_ID}" \
  --kid "${KID}" \
  --issuer "${ISSUER}" \
  --audiences "${AUDIENCE}" \
  --output-dir "${TOOLKIT_DIR}" \
  --force >/dev/null

MANIFEST_FILE="${TOOLKIT_DIR}/manifest.json"
PRIVATE_KEY="$(jq -r '.privateKey' "${MANIFEST_FILE}")"
JWKS_FILE="$(jq -r '.jwksFile' "${MANIFEST_FILE}")"

if [[ -z "${PRIVATE_KEY}" || ! -f "${PRIVATE_KEY}" ]]; then
  echo "error: generated private key is missing" >&2
  exit 1
fi

if [[ -z "${JWKS_FILE}" || ! -f "${JWKS_FILE}" ]]; then
  echo "error: generated JWKS file is missing" >&2
  exit 1
fi

"${GENERATE_JWKS_SCRIPT}" \
  --provider-id "${SECOND_KEY_ID}" \
  --kid "${SECOND_KID}" \
  --issuer "${ISSUER}" \
  --audiences "${AUDIENCE}" \
  --output-dir "${TOOLKIT_DIR}/second" \
  --force >/dev/null

"${GENERATE_JWKS_SCRIPT}" \
  --provider-id "${COLLIDING_PROVIDER_ID}" \
  --kid "${KID}" \
  --issuer "${COLLIDING_ISSUER}" \
  --audiences "${AUDIENCE}" \
  --output-dir "${TOOLKIT_DIR}/colliding" \
  --force >/dev/null

SECOND_PRIVATE_KEY="$(jq -r '.privateKey' "${TOOLKIT_DIR}/second/manifest.json")"
SECOND_JWKS_FILE="$(jq -r '.jwksFile' "${TOOLKIT_DIR}/second/manifest.json")"
COLLIDING_PRIVATE_KEY="$(jq -r '.privateKey' "${TOOLKIT_DIR}/colliding/manifest.json")"
COLLIDING_JWKS_FILE="$(jq -r '.jwksFile' "${TOOLKIT_DIR}/colliding/manifest.json")"
PUBLIC_KEY="$(jq -r '.publicKey' "${MANIFEST_FILE}")"

valid_token="$(mint_token "user-allow" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
service_token="$(mint_token "svc-1" "ROLE_SERVICE" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" '{"level":"m2m"}')"
expired_token="$(mint_token "user-old" "ROLE_VIEWER" "${EXPIRED_ISSUED_AT}" "${EXPIRED_EXPIRES_IN}")"
wrong_issuer_token="$(mint_token "user-wrong-iss" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" "{}" "https://idp.test.local/realms/other")"
unknown_kid_token="$(mint_token "user-unknown-kid" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" "{}" "${ISSUER}" "${PROVIDER_ID}-unknown-kid")"
no_roles_token="$(mint_token "user-no-roles" "" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
viewer_user_1_token="$(mint_token "user-1" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
viewer_user_2_token="$(mint_token "user-2" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
editor_user_1_token="$(mint_token "user-1" "ROLE_EDITOR" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
guest_user_1_token="$(mint_token "user-1" "ROLE_GUEST" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
order_reader_token="$(mint_token "order-reader-1" "ROLE_ORDER_MANAGEMENT_RO_USER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}")"
groups_only_order_reader_token="$(mint_token "order-reader-1" "" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" '{"groups":["ROLE_ORDER_MANAGEMENT_RO_USER"]}')"

# Signed by the provider's second key. Must verify exactly like the first.
second_key_token="$(mint_token "user-second-key" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" "{}" "${ISSUER}" "${SECOND_KID}" "${SECOND_PRIVATE_KEY}")"
# Same kid as the primary key, different provider, different key material: the
# first candidate cannot verify it and the second one can.
colliding_kid_token="$(mint_token "user-colliding-kid" "ROLE_VIEWER" "${VALID_ISSUED_AT}" "${VALID_EXPIRES_IN}" "{}" "${COLLIDING_ISSUER}" "${KID}" "${COLLIDING_PRIVATE_KEY}")"

# A properly signed token carrying no `iss` claim at all. Nothing
# reads that claim, so this must authenticate — the counterpart to `wrongIssuer`,
# which carries a different one.
no_issuer_token="$("${MINT_SCRIPT}" \
  --private-key "${PRIVATE_KEY}" \
  --kid "${KID}" \
  --issuer "${ISSUER}" \
  --subject "user-no-iss" \
  --audiences "${AUDIENCE}" \
  --roles "ROLE_VIEWER" \
  --issued-at "${VALID_ISSUED_AT}" \
  --expires-in "${VALID_EXPIRES_IN}" \
  --drop-claim iss)"

# Rejection fixtures. None of these can be produced by mint_token, which always
# signs RS256 with a kid.
no_kid_token="$("${MINT_SCRIPT}" \
  --private-key "${PRIVATE_KEY}" \
  --no-kid \
  --issuer "${ISSUER}" \
  --subject "user-no-kid" \
  --audiences "${AUDIENCE}" \
  --roles "ROLE_VIEWER" \
  --issued-at "${VALID_ISSUED_AT}" \
  --expires-in "${VALID_EXPIRES_IN}")"

alg_none_token="$("${MINT_SCRIPT}" \
  --algorithm none \
  --kid "${KID}" \
  --issuer "${ISSUER}" \
  --subject "user-alg-none" \
  --audiences "${AUDIENCE}" \
  --roles "ROLE_VIEWER" \
  --issued-at "${VALID_ISSUED_AT}" \
  --expires-in "${VALID_EXPIRES_IN}")"

# The key-confusion attack: HS256 with the verifier's own RSA public key as the
# shared secret. It carries a valid kid, so only the algorithm check stops it.
symmetric_alg_token="$("${MINT_SCRIPT}" \
  --algorithm HS256 \
  --hmac-key "${PUBLIC_KEY}" \
  --kid "${KID}" \
  --issuer "${ISSUER}" \
  --subject "user-hs256" \
  --audiences "${AUDIENCE}" \
  --roles "ROLE_VIEWER" \
  --issued-at "${VALID_ISSUED_AT}" \
  --expires-in "${VALID_EXPIRES_IN}")"

# `data.authn` in the shape pap-client publishes it:
# providers keyed by id, keys keyed by kid with a one-key JWKS per candidate.
authn_document="$(
  jq -n \
    --slurpfile primary "${JWKS_FILE}" \
    --slurpfile second "${SECOND_JWKS_FILE}" \
    --slurpfile colliding "${COLLIDING_JWKS_FILE}" \
    --arg providerId "${PROVIDER_ID}" \
    --arg collidingProviderId "${COLLIDING_PROVIDER_ID}" \
    --arg kid "${KID}" \
    --arg secondKid "${SECOND_KID}" \
    --arg audience "${AUDIENCE}" \
    '
    def candidate(providerId; jwks):
      {
        providerId: providerId,
        alg: jwks.keys[0].alg,
        kty: jwks.keys[0].kty,
        jwksJson: ({keys: [jwks.keys[0]]} | tojson)
      };
    {
      trustedProviders: {
        byId: {
          ($providerId): {id: $providerId, audiences: [$audience], required: true},
          ($collidingProviderId): {id: $collidingProviderId, audiences: [$audience]}
        }
      },
      jwksByKid: {
        ($kid): [
          candidate($providerId; $primary[0]),
          candidate($collidingProviderId; $colliding[0])
        ],
        ($secondKid): [candidate($providerId; $second[0])]
      }
    }'
)"

mkdir -p "${AUTHN_DATA_DIR}"
rm -rf "${AUTHN_DATA_DIR}/jwks"
printf '%s\n' "${authn_document}" | jq '.' > "${AUTHN_DATA_DIR}/authn.json"

jq -n \
  --argjson authn "${authn_document}" \
  --arg issuer "${ISSUER}" \
  --arg valid "${valid_token}" \
  --arg secondKey "${second_key_token}" \
  --arg collidingKid "${colliding_kid_token}" \
  --arg noKid "${no_kid_token}" \
  --arg algNone "${alg_none_token}" \
  --arg symmetricAlg "${symmetric_alg_token}" \
  --arg noIssuer "${no_issuer_token}" \
  --arg service "${service_token}" \
  --arg expired "${expired_token}" \
  --arg wrongIssuer "${wrong_issuer_token}" \
  --arg unknownKid "${unknown_kid_token}" \
  --arg noRoles "${no_roles_token}" \
  --arg viewerUser1 "${viewer_user_1_token}" \
  --arg viewerUser2 "${viewer_user_2_token}" \
  --arg editorUser1 "${editor_user_1_token}" \
  --arg guestUser1 "${guest_user_1_token}" \
  --arg orderReader "${order_reader_token}" \
  --arg groupsOnlyOrderReader "${groups_only_order_reader_token}" \
  '{
    authn: $authn,
    tokens: {
      valid: $valid,
      service: $service,
      expired: $expired,
      wrongIssuer: $wrongIssuer,
      unknownKid: $unknownKid,
      noKid: $noKid,
      algNone: $algNone,
      symmetricAlg: $symmetricAlg,
      noIssuer: $noIssuer,
      secondKey: $secondKey,
      collidingKid: $collidingKid,
      noRoles: $noRoles,
      viewerUser1: $viewerUser1,
      viewerUser2: $viewerUser2,
      editorUser1: $editorUser1,
      guestUser1: $guestUser1,
      orderReader: $orderReader,
      groupsOnlyOrderReader: $groupsOnlyOrderReader
    }
  }' > "${IDENTITY_FIXTURE_FILE}"

echo "Updated Rego token fixtures:"
echo "  ${IDENTITY_FIXTURE_FILE}"
echo "  ${AUTHN_DATA_DIR}/authn.json"
