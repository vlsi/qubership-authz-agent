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

package authorize_internals

import rego.v1

# ── Admission gate (authorizationToken) ──────────────────────────────────

_admission_token := object.get(input, "authorizationToken", "")

_has_admission_token if {
  object.get(input, "authorizationToken", "__missing__") != "__missing__"
}

_admission_validation := data.identity.validate_token_with_reason(_admission_token) if {
  _has_admission_token
}

_admission_ok if {
  not _has_admission_token
}

_admission_ok if {
  _has_admission_token
  _admission_validation.valid
}

# ── Admission ─────────────────────────────────────────────────────────────
#
# admission is the outcome of the caller and subject checks without any
# decision: authError when the admission token is refused, subjectError
# with the reason when the subject's token is, and otherwise in
# tokenPayload the verified claims the subject is read from: those of the
# subject's token, or for an anonymous request those of the admission
# token, whose roles the legacy service grants the anonymous subject ({}
# without one). The agent decides check/resource and check/filter with the
# generated module of the request's tenant and asks this package only who the
# subject is.

admission := {"authError": {
  "status": 401,
  "message": _admission_validation.reason,
  "reason": _admission_validation.reason,
}} if {
  _has_admission_token
  not _admission_validation.valid
}

admission := {"subjectError": object.get(object.get(auth, "error", {}), "reason", "unauthorized")} if {
  _admission_ok
  auth := authentication_context
  not auth.authenticated
}

admission := {"tokenPayload": _subject_claims(auth)} if {
  _admission_ok
  auth := authentication_context
  auth.authenticated
}

_subject_claims(auth) := object.get(_admission_validation, "payload", {}) if {
  data.identity.anonymous_mode(input)
  _has_admission_token
} else := object.get(auth, "tokenPayload", {})

_can_reuse_admission_subject if {
  _has_admission_token
  _admission_validation.valid
  not data.identity.anonymous_mode(input)
  object.get(input, "subject", "") == _admission_token
}

authentication_context := {
  "authenticated": true,
  "subject": data.identity.subject_from_verification(_admission_validation),
  "tokenPayload": object.get(_admission_validation, "payload", {}),
} if {
  _can_reuse_admission_subject
}

authentication_context := data.identity.authenticate(input) if {
  not _can_reuse_admission_subject
}
