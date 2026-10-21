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

// OldFilterEvaluationResult is the v1 POST /access/v1/check/filter response
// body. CalculationResult is a string because the parity assertion is on the
// wire form (ALLOW / DENY / NOT_APPLICABLE / USE_FILTER_CONDITION), not on a
// typed enum. The four text dialects are [FilterText], so a golden records and
// a comparison tells apart a string, null, and an absent member; the error body
// of a refused request has none of them.
// CustomFilterCondition is json.RawMessage because its shape varies and the
// parity suite compares it as JSON rather than field by field.
type OldFilterEvaluationResult struct {
	CalculationResult      string          `json:"calculationResult"`
	FilterCondition        FilterText      `json:"filterCondition,omitzero"`
	MongodbFilterCondition FilterText      `json:"mongodbFilterCondition,omitzero"`
	RsqlFilterCondition    FilterText      `json:"rsqlFilterCondition,omitzero"`
	SqlFilterCondition     FilterText      `json:"sqlFilterCondition,omitzero"`
	CustomFilterCondition  json.RawMessage `json:"customFilterCondition,omitempty"`
}

// FilterResponse is the v2 POST /access/v2/check/filter response body: the
// fields of OldFilterEvaluationResult and an Obligations block, which the
// parity suite always filters out via cmpopts.IgnoreFields per D-E.
type FilterResponse struct {
	CalculationResult      string          `json:"calculationResult"`
	FilterCondition        FilterText      `json:"filterCondition,omitzero"`
	MongodbFilterCondition FilterText      `json:"mongodbFilterCondition,omitzero"`
	RsqlFilterCondition    FilterText      `json:"rsqlFilterCondition,omitzero"`
	SqlFilterCondition     FilterText      `json:"sqlFilterCondition,omitzero"`
	CustomFilterCondition  json.RawMessage `json:"customFilterCondition,omitempty"`
	Obligations            json.RawMessage `json:"obligations,omitempty"`
}

// FilterText is the predicate of one text dialect in a check/filter answer, in
// the form the body carried it: a string, null, or no member at all. Present is
// false for an absent member, and Text is nil for null. A struct field of this
// type tagged omitzero is written only when Present is set, so a golden written
// from it keeps the form legacy answered.
type FilterText struct {
	Present bool
	Text    *string
}

// FilterTextOf returns the member that carries the string s.
func FilterTextOf(s string) FilterText { return FilterText{Present: true, Text: &s} }

// FilterTextNull returns the member that carries null.
func FilterTextNull() FilterText { return FilterText{Present: true} }

// IsZero reports whether the member was absent.
func (t FilterText) IsZero() bool { return !t.Present }

// String returns the text, and "" for null and for an absent member.
func (t FilterText) String() string {
	if t.Text == nil {
		return ""
	}
	return *t.Text
}

// Map returns the member with f applied to its text. Null and an absent member
// are returned as they are.
func (t FilterText) Map(f func(string) string) FilterText {
	if t.Text == nil {
		return t
	}
	return FilterTextOf(f(*t.Text))
}

// MarshalJSON writes the text, and null when Text is nil.
func (t FilterText) MarshalJSON() ([]byte, error) { return json.Marshal(t.Text) }

// UnmarshalJSON marks the member present, also for null, and decodes its text.
// A value that is neither a string nor null is an error.
func (t *FilterText) UnmarshalJSON(b []byte) error {
	t.Present = true
	t.Text = nil
	return json.Unmarshal(b, &t.Text)
}
