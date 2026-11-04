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
	"reflect"
	"slices"
	"testing"

	"authz-agent/internal/jsonvalue"
)

const keyR = `["subj","r"]`

// resolveSubject generates the module of a set whose condition reads
// subject.r, declared by pip, and resolves the subject of a request with
// claims and headers.
func resolveSubject(t *testing.T, pip, claims string, headers map[string]string) (Resolved, []string) {
	t.Helper()
	m, err := Generate(tenantWithSetAndPIPs(t, "DENY_UNLESS_PERMIT", "ALLOW", "subject.r == 'x'", pip),
		table(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := Request{Headers: headers}
	if claims != "" {
		req.Claims = mustDecode(t, claims).(*jsonvalue.Object)
	}
	unread := m.ResolveSubject(&req)
	return req.Values[keyR], unread
}

func TestResolveSubject_ReadsAHeaderPIP(t *testing.T) {
	for _, tc := range []struct {
		name, pip string
		headers   map[string]string
		want      Resolved
	}{
		{"one item", `{"name": "subject.r", "pipType": "HEADER", "header": "X-R"}`,
			map[string]string{"x-r": " a\t"}, resolved(t, "VALUE", `"a"`)},
		{"items split at commas, repeats dropped", `{"name": "subject.r", "pipType": "HEADER", "header": "X-R"}`,
			map[string]string{"x-r": "a, b ,a,"}, Resolved{State: "VALUE", Value: []jsonvalue.Value{"a", "b"}, HeaderList: true}},
		{"a byte above ASCII as one Latin-1 character", `{"name": "subject.r", "pipType": "HEADER", "header": "X-R"}`,
			map[string]string{"x-r": "\xe9"}, resolved(t, "VALUE", `"é"`)},
		{"an empty header takes the default", `{"name": "subject.r", "pipType": "HEADER", "header": "X-R", "defaultValue": "d"}`,
			map[string]string{"x-r": "  "}, resolved(t, "VALUE", `"d"`)},
		{"no header and no default", `{"name": "subject.r", "pipType": "HEADER", "header": "X-R"}`,
			map[string]string{}, Resolved{State: "PIP_EMPTY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := resolveSubject(t, tc.pip, "", tc.headers)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("value of subject.r = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveSubject_ReadsATokenPIP(t *testing.T) {
	for _, tc := range []struct {
		name, pip, claims string
		want              Resolved
	}{
		{"a claim by name", `{"name": "subject.r", "pipType": "TOKEN", "claim": "region"}`,
			`{"region": "eu"}`, resolved(t, "VALUE", `"eu"`)},
		{"a claim by a path from $", `{"name": "subject.r", "pipType": "TOKEN", "claim": "$.a.b"}`,
			`{"a": {"b": 1}}`, resolved(t, "VALUE", `1`)},
		{"a root bracket read as a key", `{"name": "subject.r", "pipType": "TOKEN", "claim": "['a.b']"}`,
			`{"a.b": "k"}`, resolved(t, "VALUE", `"k"`)},
		{"a list claim, repeats dropped", `{"name": "subject.r", "pipType": "TOKEN", "claim": "l"}`,
			`{"l": ["x", "x"]}`, resolved(t, "VALUE", `"x"`)},
		{"a missing claim takes the default split at commas", `{"name": "subject.r", "pipType": "TOKEN", "claim": "c", "defaultValue": "x, y"}`,
			`{}`, resolved(t, "VALUE", `["x", "y"]`)},
		{"a missing claim without a default", `{"name": "subject.r", "pipType": "TOKEN", "claim": "c"}`,
			`{}`, Resolved{State: "PIP_EMPTY"}},
		{"a blank claim", `{"name": "subject.r", "pipType": "TOKEN", "claim": " "}`,
			`{}`, Resolved{State: "ERROR"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unread := resolveSubject(t, tc.pip, tc.claims, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("value of subject.r = %+v, want %+v", got, tc.want)
			}
			if len(unread) != 0 {
				t.Errorf("unread = %v, want none", unread)
			}
		})
	}
}

// A MAPPING PIP is a source the agent does not read: its operand is ERROR
// and its key is returned. A GENERAL PIP is left to the module.
func TestResolveSubject_SetsAnUnreadSourceToError(t *testing.T) {
	got, unread := resolveSubject(t, `{"name": "subject.r", "pipType": "MAPPING", "productMapping": {"x": ["R"]}}`, `{}`, nil)
	if want := (Resolved{State: "ERROR"}); got != want || !slices.Equal(unread, []string{keyR}) {
		t.Errorf("MAPPING: value %+v, unread %v; want %+v, [%s]", got, unread, want, keyR)
	}

	got, unread = resolveSubject(t, `{"name": "subject.r", "pipType": "GENERAL", "url": "http://pip/r"}`, `{}`, nil)
	if got != (Resolved{}) || len(unread) != 0 {
		t.Errorf("GENERAL: value %+v, unread %v; want no value and none unread", got, unread)
	}
}
