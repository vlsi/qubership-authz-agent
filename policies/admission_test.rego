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

package admission_test

import rego.v1

fixtures := data.fixtures.identity

valid_token := sprintf("Bearer %v", [fixtures.tokens.valid])

admission(req) := got if {
  got := data.authorize_internals.admission
    with input as object.union({"resources": []}, req)
    with data.authn as fixtures.authn
}

# The subject of an anonymous request is read from the admission token,
# whose roles the legacy service grants the anonymous subject.
test_anonymous_request_takes_the_claims_of_the_admission_token if {
  got := admission({"authorizationToken": valid_token, "subject": "", "authorizationType": "anonymous"})
  got.tokenPayload.sub == "user-allow"
  got.tokenPayload.realm_access.roles == ["ROLE_VIEWER"]
}

test_anonymous_request_without_an_admission_token_has_no_claims if {
  got := admission({"subject": "", "authorizationType": "anonymous"})
  got.tokenPayload == {}
}

test_request_with_a_subject_takes_the_claims_of_the_subject_token if {
  got := admission({"authorizationToken": valid_token, "subject": valid_token})
  got.tokenPayload.sub == "user-allow"
}

test_refused_admission_token_is_an_auth_error if {
  got := admission({"authorizationToken": "Bearer not-a-token", "subject": valid_token})
  got.authError.status == 401
}

test_refused_subject_token_is_a_subject_error if {
  got := admission({"authorizationToken": valid_token, "subject": "Bearer not-a-token"})
  is_string(got.subjectError)
}
