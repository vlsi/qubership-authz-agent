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

import "encoding/json"

// Member is a JSON member whose absence is recorded apart from null: Present
// is false when the body had no such member, and Value holds the decoded value
// otherwise, nil for null. A struct field of this type tagged omitzero is
// written only when Present is set.
type Member struct {
	Present bool
	Value   any
}

// IsZero reports whether the member was absent.
func (m Member) IsZero() bool { return !m.Present }

// MarshalJSON writes the value, null when it is nil.
func (m Member) MarshalJSON() ([]byte, error) { return json.Marshal(m.Value) }

// UnmarshalJSON marks the member present, also for null, and decodes its value.
func (m *Member) UnmarshalJSON(b []byte) error {
	m.Present = true
	return json.Unmarshal(b, &m.Value)
}

// CheckResourceV2Outcome is the golden shape of a case's check/resource request
// sent through v2. Status is the HTTP status, Decision the decision member of
// the body, false for a refused request, and Obligations the obligations
// member as the body carried it, absent when the body had none. Message is the
// body of a 400 or 409 answer where the case file records it (see
// [PolicyLoadOutcome]).
type CheckResourceV2Outcome struct {
	Status      int    `json:"status"`
	Decision    bool   `json:"decision"`
	Obligations Member `json:"obligations,omitzero"`
	Message     any    `json:"message,omitempty"`
}

// CheckResourceBulkOperationsV2Outcome is the golden shape of a case's
// check/resource/bulk/operations request sent through v2: the status, on 200
// the allowed ids of each operation, sorted, and the obligations member as in
// [CheckResourceV2Outcome].
type CheckResourceBulkOperationsV2Outcome struct {
	Status      int                  `json:"status"`
	Decision    *map[string][]string `json:"decision,omitempty"`
	Obligations Member               `json:"obligations,omitzero"`
	Message     any                  `json:"message,omitempty"`
}

// FilterV2Outcome is the golden shape of a case's check/filter request sent
// through v2: the status, the filter result members of the body, and the
// obligations member as in [CheckResourceV2Outcome].
type FilterV2Outcome struct {
	Status      int                       `json:"status"`
	Result      OldFilterEvaluationResult `json:"result"`
	Obligations Member                    `json:"obligations,omitzero"`
	Message     any                       `json:"message,omitempty"`
}
