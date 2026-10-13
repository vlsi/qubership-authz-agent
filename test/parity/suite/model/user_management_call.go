// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

// UserManagementCallOutcome is the golden shape of the calls the User
// Management stub received over one request, in the order they arrived. A
// request that made no call records an empty list.
type UserManagementCallOutcome struct {
	Calls []UserManagementCall `json:"calls"`
}

// UserManagementCall is one call the User Management stub received.
// RequestURI is the request target as it arrived, path and query still
// encoded as the caller wrote them. HeaderNames lists the lower-case name of
// every header the call carried, sorted. Headers holds the values of the few
// headers whose value a golden can hold: a token replaced by a label naming
// whose it is, the tenant replaced by a label when it is the request's, and
// any other value as it is. Body is the body as text, empty when there was
// none.
type UserManagementCall struct {
	Method      string         `json:"method"`
	RequestURI  string         `json:"requestUri"`
	HeaderNames []string       `json:"headerNames"`
	Headers     map[string]any `json:"headers"`
	Body        string         `json:"body,omitempty"`
}
