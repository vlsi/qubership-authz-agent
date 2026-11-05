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

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// uploadCase is one upload and, for a refused one, the text its error has to
// contain.
type uploadCase struct {
	name, body, wantError string
}

// assertRefused fails unless the upload of tc to path answers 400 with a JSON
// error that contains tc.wantError, and the domain still reads empty.
func assertRefused(t *testing.T, path string, tc uploadCase) {
	t.Helper()
	mux := newTestServer(t, t.TempDir())
	rec := do(t, mux, http.MethodPut, path, tc.body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT %s %s = %d %s, want 400", path, tc.body, rec.Code, rec.Body)
	}
	var resp struct{ Error string }
	decode(t, rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, tc.wantError) {
		t.Errorf("PUT %s %s: error %q, want it to contain %q", path, tc.body, resp.Error, tc.wantError)
	}
	var stored []json.RawMessage
	decode(t, do(t, mux, http.MethodGet, path, "").Body.Bytes(), &stored)
	if len(stored) != 0 {
		t.Errorf("after the refused PUT %s %s the domain reads %d items, want 0", path, tc.body, len(stored))
	}
}

// assertAccepted fails unless the upload of tc to path answers 200.
func assertAccepted(t *testing.T, path string, tc uploadCase) {
	t.Helper()
	mux := newTestServer(t, t.TempDir())
	if rec := do(t, mux, http.MethodPut, path, tc.body); rec.Code != http.StatusOK {
		t.Errorf("PUT %s %s = %d %s, want 200", path, tc.body, rec.Code, rec.Body)
	}
}

// A PIP name is subject. followed by dot-separated attributes of letters,
// digits, and underscores, none starting with a digit.
func TestPIPNameIsRefusedUnlessItIsASubjectAttribute(t *testing.T) {
	for _, tc := range []uploadCase{
		{"without the subject prefix", `[{"name":"department","pipType":"TOKEN","claim":"dept"}]`, `"department"`},
		{"absent", `[{"pipType":"TOKEN","claim":"dept"}]`, `name ""`},
		{"an attribute starting with a digit", `[{"name":"subject.1dept","pipType":"TOKEN","claim":"dept"}]`, `"subject.1dept"`},
		{"a dash", `[{"name":"subject.my-dept","pipType":"TOKEN","claim":"dept"}]`, `"subject.my-dept"`},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"one attribute", `[{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}]`, ""},
		{"a path starting with an underscore", `[{"name":"subject._org.dept_2","pipType":"TOKEN","claim":"dept"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// headers is one text of comma-separated header names, and a mapping field
// is a JSON object.
func TestPIPFieldOfTheWrongJSONShapeIsRefused(t *testing.T) {
	const url = `"url":"http://pip/allowed"`
	for _, tc := range []uploadCase{
		{"headers as an object", `[{"name":"subject.ids",` + url + `,"headers":{"X-Trace":"1"}}]`, "field headers"},
		{"headers as an array", `[{"name":"subject.ids",` + url + `,"headers":["X-Trace","X-Org"]}]`, "field headers"},
		{"defaultValue as an array", `[{"name":"subject.ids",` + url + `,"defaultValue":["none"]}]`, "field defaultValue"},
		{"customMapping as a text", `[{"name":"subject.permissions","pipType":"MAPPING","customMapping":"r"}]`, "field customMapping"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"headers as a text", `[{"name":"subject.ids",` + url + `,"headers":"X-Trace, X-Org"}]`, ""},
		{"defaultValue as a number", `[{"name":"subject.ids",` + url + `,"defaultValue":5}]`, ""},
		{"customMapping as an object", `[{"name":"subject.permissions","pipType":"MAPPING","customMapping":{}}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// A simplified policy's condition is a text the condition parser accepts, a
// boolean, or absent.
func TestPolicyConditionIsRefusedUnlessItParses(t *testing.T) {
	policy := func(condition string) string {
		return `[{"component":"BILLING","resourceType":"INVOICE","operation":"READ","roles":["R"],"condition":` +
			condition + `}]`
	}
	for _, tc := range []uploadCase{
		{"MATCH with a number", policy(`"subject.x MATCH 5 OR resource.a == 'y'"`), "number as a MATCH pattern"},
		{"empty", policy(`""`), "condition is empty"},
		{"blank", policy(`"   "`), "blank"},
		{"a number", policy(`5`), "want a text"},
		{"an array", policy(`["resource.a == 'y'"]`), "want a text"},
		{"an object", policy(`{"text":"resource.a == 'y'"}`), "want a text"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, policiesPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"MATCH with a pattern", policy(`"subject.x MATCH abc OR resource.a == 'y'"`), ""},
		{"padded with a form feed", policy(`"\fresource.a == 'y'"`), ""},
		{"true", policy(`true`), ""},
		{"false", policy(`false`), ""},
		{"null", policy(`null`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, policiesPath+"billing", tc) })
	}
}
