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

package regogen

import (
	"testing"

	"authz-agent/internal/jsonvalue"
)

// The text a string compares a structure by prints a scalar member as Java
// text with numbers stripped of trailing zeros, and a nested member as
// compact JSON with its numbers as written. The expected texts are what the
// specification's agent profile prints.
func TestStructureText(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`["x", null]`, `[x, null]`},
		{`[1.0, true]`, `[1, true]`},
		{`[1.50e1, -0.0, 100]`, `[15, 0, 100]`},
		{`[["a"], "b"]`, `[["a"], b]`},
		{`{"k": {"b": "c"}}`, `{k={"b":"c"}}`},
		{`{"a": [1.0]}`, `{a=[1.0]}`},
		{`[]`, `[]`},
	} {
		v, err := jsonvalue.Decode([]byte(tc.value))
		if err != nil {
			t.Fatalf("jsonvalue.Decode(%s): %v", tc.value, err)
		}
		if got := structureText(v); got != tc.want {
			t.Errorf("structureText(%s) = %q, want %q", tc.value, got, tc.want)
		}
	}
}
