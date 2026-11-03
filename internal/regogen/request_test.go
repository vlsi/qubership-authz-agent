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

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// The expected values in this file are what the specification's agent profile
// resolves for the same body.

func TestReadBodyTakesResourceTypeWhereTypeIsEmpty(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"a type", `{"type": "doc", "resourceType": "r"}`, `"doc"`},
		{"no type", `{"resourceType": "r"}`, `"r"`},
		{"a null type", `{"type": null, "resourceType": "r"}`, `"r"`},
		{"an empty type", `{"type": "", "resourceType": "r"}`, `"r"`},
		{"a false type", `{"type": false, "resourceType": "r"}`, `"r"`},
		{"an empty list", `{"type": [], "resourceType": "r"}`, `"r"`},
		{"an empty object", `{"type": {}, "resourceType": "r"}`, `"r"`},
		{"a true type", `{"type": true, "resourceType": "r"}`, `true`},
		{"a zero type", `{"type": 0, "resourceType": "r"}`, `0`},
		{"a list type", `{"type": ["x"], "resourceType": "r"}`, `["x"]`},
		{"neither", `{"type": ""}`, `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ReadBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("ReadBody(%s): %v", tc.body, err)
			}
			if got := jsonText(b.ResourceType); got != tc.want {
				t.Errorf("ReadBody(%s).ResourceType = %s, want %s", tc.body, got, tc.want)
			}
		})
	}
}

func TestReadBodyKeepsTheOperationAsSent(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"a string", `{"operation": "READ"}`, `"READ"`},
		{"a number", `{"operation": 5.0}`, `5.0`},
		{"no operation", `{}`, `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ReadBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("ReadBody(%s): %v", tc.body, err)
			}
			if got := jsonText(b.Operation); got != tc.want {
				t.Errorf("ReadBody(%s).Operation = %s, want %s", tc.body, got, tc.want)
			}
		})
	}
}

func TestReadBodyRefusesABodyThatIsNotAnObject(t *testing.T) {
	if _, err := ReadBody([]byte(`[{"operation": "read"}]`)); err == nil {
		t.Errorf("ReadBody of a list: no error")
	}
}

// A resource that is null differs from a body without the member resource
// for the whole resource, which is then VALUE null, and for a path that ends
// in a dot, which is then ERROR.
func TestResolveReadsTheResourceOperandsOfTheBody(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW",
		"resource == 'x' OR resource.a == 'x' OR resource.a.b == 'x' OR resource.a. == 'x' OR null == 'x' "+
			"OR resource.l[0] == 'x'"), table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const whole, a, ab, dot, null = `["res",""]`, `["res",".a"]`, `["res",".a.b"]`, `["res",".a."]`, `["null"]`
	for _, tc := range []struct {
		name, body, key string
		state           spectables.State
		value           string
	}{
		{"no resource", `{}`, a, spectables.StateAbsent, ""},
		{"no resource, the whole resource", `{}`, whole, spectables.StateAbsent, ""},
		{"a null resource, the whole resource", `{"resource": null}`, whole, spectables.StateValue, "null"},
		{"a null resource", `{"resource": null}`, a, spectables.StateAbsent, ""},
		{"a list resource", `{"resource": [1, 2]}`, a, spectables.StateAbsent, ""},
		{"no member", `{"resource": {"b": "x"}}`, a, spectables.StateAbsent, ""},
		{"a null member", `{"resource": {"a": null}}`, a, spectables.StateNull, ""},
		{"an empty list", `{"resource": {"a": []}}`, a, spectables.StateEmptyColl, ""},
		{"a list", `{"resource": {"a": [null]}}`, a, spectables.StateValue, "[null]"},
		{"a number as written", `{"resource": {"a": 1e400}}`, a, spectables.StateValue, "1e400"},
		{"a nested member", `{"resource": {"a": {"b": "x"}}}`, ab, spectables.StateValue, `"x"`},
		{"a null parent", `{"resource": {"a": null}}`, ab, spectables.StateAbsent, ""},
		{"an empty object parent", `{"resource": {"a": {}}}`, ab, spectables.StateAbsent, ""},
		{"a string parent", `{"resource": {"a": "s"}}`, ab, spectables.StateAbsent, ""},
		{"a dot at the end", `{"resource": {"a": "x"}}`, dot, spectables.StateError, ""},
		{"a dot at the end, no resource", `{}`, dot, spectables.StateAbsent, ""},
		{"a dot at the end, a null resource", `{"resource": null}`, dot, spectables.StateError, ""},
		{"null, a member null", `{"resource": {"null": "x"}}`, null, spectables.StateValue, `"x"`},
		{"null, a null member null", `{"resource": {"null": null}}`, null, spectables.StateNull, ""},
		{"null, no member null", `{"resource": {"a": "x"}}`, null, spectables.StateAbsent, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ReadBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("ReadBody(%s): %v", tc.body, err)
			}
			values := map[string]Resolved{}
			m.Resolve(b, values)
			got, ok := values[tc.key]
			if !ok {
				t.Fatalf("Resolve(%s): no value of %s", tc.body, tc.key)
			}
			value := ""
			if got.State == spectables.StateValue {
				value = jsonText(got.Value)
			}
			if got.State != tc.state || value != tc.value {
				t.Errorf("Resolve(%s)[%s] = %s %s, want %s %s", tc.body, tc.key, got.State, value, tc.state, tc.value)
			}
		})
	}
}

// A path with an index is read in the query, through nc.resource_path.
func TestResolveLeavesOutALazilyReadPath(t *testing.T) {
	m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.l[0] == 'x' OR resource.a == 'x'"),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	values := map[string]Resolved{}
	m.Resolve(Body{HasResource: true, Resource: nil}, values)
	key, _ := SpecKey(policyir.Resource{Path: ".l[0]"})
	if v, ok := values[key]; ok {
		t.Errorf("Resolve: %s = %v, want no value", key, v)
	}
	if _, ok := values[keyA]; !ok {
		t.Errorf("Resolve: no value of %s", keyA)
	}
}

// The knob trailing_dot_path names the state of a path that ends in a dot,
// and DROP reads the path without it.
func TestResolveReadsAPathThatEndsInADotByTheKnob(t *testing.T) {
	const dot = `["res",".a."]`
	for _, tc := range []struct {
		knob, key string
		state     spectables.State
		value     string
	}{
		{"ERROR", dot, spectables.StateError, ""},
		{"ABSENT", dot, spectables.StateAbsent, ""},
		{"DROP", keyA, spectables.StateValue, `"w"`},
	} {
		t.Run(tc.knob, func(t *testing.T) {
			tab := editedTable(t, `"trailing_dot_path": "ERROR"`, `"trailing_dot_path": "`+tc.knob+`"`)
			m, err := Generate(tenantWithSet(t, "DENY_UNLESS_PERMIT", "ALLOW", "resource.a. == 'w'"), tab,
				DefaultOptions())
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			values := map[string]Resolved{}
			m.Resolve(Body{HasResource: true, Resource: claimsOf(t, `{"a": "w"}`)}, values)
			got := values[tc.key]
			value := ""
			if got.State == spectables.StateValue {
				value = jsonText(got.Value)
			}
			if got.State != tc.state || value != tc.value || len(values) != 1 {
				t.Errorf("Resolve under %s = %v, want %s: %s %s", tc.knob, values, tc.key, tc.state, tc.value)
			}
		})
	}
}
