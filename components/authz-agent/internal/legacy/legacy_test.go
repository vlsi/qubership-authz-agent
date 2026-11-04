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

package legacy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// message is the error's message, or "" for a nil error.
func message(err *RequestError) string {
	if err == nil {
		return ""
	}
	return err.Message
}

func TestCheckResource(t *testing.T) {
	empty := map[string]any{}
	cases := []struct {
		name string
		body string
		want []Resource
		err  string
	}{
		{"type, operation, and resource as sent", `{"type":"ORDER","operation":"READ","resource":{"id":1}}`,
			[]Resource{{ResourceType: "ORDER", Operation: "READ", Resource: map[string]any{"id": json.Number("1")}}}, ""},
		{"resource defaults to an empty object", `{"type":"ORDER","operation":"READ"}`,
			[]Resource{{ResourceType: "ORDER", Operation: "READ", Resource: empty}}, ""},
		{"a null resource stays null", `{"type":"ORDER","operation":"READ","resource":null}`,
			[]Resource{{ResourceType: "ORDER", Operation: "READ", Resource: nil}}, ""},
		{"a type that is not a string reaches the policy unchanged", `{"type":5,"operation":"READ"}`,
			[]Resource{{ResourceType: json.Number("5"), Operation: "READ", Resource: empty}}, ""},
		{"an empty body is a bad request", ``, nil, "bad request"},
		{"a blank body is a bad request", " \n\t", nil, "bad request"},
		{"an array body is a bad request", `[{"type":"ORDER","operation":"READ"}]`, nil, "bad request"},
		{"a truncated body is a bad request", `{"type":"ORDER","operation":"READ"`, nil, "bad request"},
		{"a null body has no type", `null`, nil, "Missing required parameter: type"},
		{"an absent type is missing", `{"operation":"READ"}`, nil, "Missing required parameter: type"},
		{"an empty type is missing", `{"type":"","operation":"READ"}`, nil, "Missing required parameter: type"},
		{"a null type is missing", `{"type":null,"operation":"READ"}`, nil, "Missing required parameter: type"},
		{"type is checked before operation", `{"type":"","operation":""}`, nil, "Missing required parameter: type"},
		{"an absent operation is missing", `{"type":"ORDER"}`, nil, "Missing required parameter: operation"},
		{"a null operation is missing", `{"type":"ORDER","operation":null}`, nil, "Missing required parameter: operation"},
		{"a type inside the resource is not the type", `{"resource":{"type":"X"},"operation":"READ"}`, nil, "Missing required parameter: type"},
		{"an empty operation is missing", `{"type":"ORDER","operation":""}`, nil, "Missing required parameter: operation"},
		{"a blank type is present", `{"type":" ","operation":"READ"}`,
			[]Resource{{ResourceType: " ", Operation: "READ", Resource: empty}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckResource([]byte(tc.body))
			if message(err) != tc.err {
				t.Fatalf("CheckResource(%s) error = %q, want %q", tc.body, message(err), tc.err)
			}
			if got := decoded(got); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CheckResource(%s) = %#v, want %#v", tc.body, got, tc.want)
			}
		})
	}
}

func TestCheckResourceBulk(t *testing.T) {
	cases := []struct {
		name string
		body string
		ids  []string
		n    int
		err  string
	}{
		{"ids follow the resources, empty for an entry without one",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"type":"ORDER","operation":"DELETE"},{"id":7,"type":"X","operation":"Y"}]`,
			[]string{"a", "", "7"}, 3, ""},
		{"an escaped id is decoded", `[{"id":"a\"b","type":"ORDER","operation":"READ"}]`, []string{`a"b`}, 1, ""},
		{"an empty array has nothing to check", `[]`, []string{}, 0, ""},
		{"the same id twice is refused",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"a","type":"ORDER","operation":"DELETE"}]`,
			nil, 0, "Duplicate resource id in bulk request: resource ids must be unique"},
		{"1 and \"1\" are different ids", `[{"id":1,"type":"ORDER","operation":"READ"},{"id":"1","type":"ORDER","operation":"READ"}]`,
			[]string{"1", "1"}, 2, ""},
		{"null ids are not compared", `[{"id":null,"type":"ORDER","operation":"READ"},{"id":null,"type":"ORDER","operation":"READ"}]`,
			[]string{"", ""}, 2, ""},
		{"a missing type is reported before a duplicate id",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"a","operation":"READ"}]`, nil, 0, "Missing required parameter: type"},
		{"a missing operation names the parameter", `[{"type":"ORDER"}]`, nil, 0, "Missing required parameter: operation"},
		{"an element that is not an object has no type", `["ORDER"]`, nil, 0, "Missing required parameter: type"},
		{"an object body is a bad request", `{"type":"ORDER","operation":"READ"}`, nil, 0, "bad request"},
		{"a null body is a bad request", `null`, nil, 0, "bad request"},
		{"an empty body is a bad request", ``, nil, 0, "bad request"},
		{"a truncated array is a bad request", `[{"type":"ORDER","operation":"READ"}`, nil, 0, "bad request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resources, ids, err := CheckResourceBulk([]byte(tc.body))
			if message(err) != tc.err {
				t.Fatalf("CheckResourceBulk(%s) error = %q, want %q", tc.body, message(err), tc.err)
			}
			if len(resources) != tc.n {
				t.Errorf("CheckResourceBulk(%s) = %d resources, want %d", tc.body, len(resources), tc.n)
			}
			if !reflect.DeepEqual(ids, tc.ids) {
				t.Errorf("CheckResourceBulk(%s) ids = %#v, want %#v", tc.body, ids, tc.ids)
			}
		})
	}
}

// One resource per operation, with the operation as a string whatever the
// caller sent, the item's type and resource repeated, and an Entry per
// resource carrying the item's id. An empty or null operation adds nothing,
// and a null id is no id.
func TestCheckResourceBulkOperations_ExpandsOperations(t *testing.T) {
	body := `[{"id":"a","type":"ORDER","operations":["READ",5,"",null],"resource":{"k":"v"}},{"id":null,"type":"DOC","operations":["WRITE"]}]`
	resources, entries, err := CheckResourceBulkOperations([]byte(body))
	if err != nil {
		t.Fatalf("CheckResourceBulkOperations(%s) error = %q", body, err.Message)
	}
	kv := map[string]any{"k": "v"}
	wantResources := []Resource{
		{ResourceType: "ORDER", Operation: "READ", Resource: kv},
		{ResourceType: "ORDER", Operation: "5", Resource: kv},
		{ResourceType: "DOC", Operation: "WRITE", Resource: map[string]any{}},
	}
	if got := decoded(resources); !reflect.DeepEqual(got, wantResources) {
		t.Errorf("resources = %#v, want %#v", got, wantResources)
	}
	wantEntries := []Entry{{ID: "a", Operation: "READ"}, {ID: "a", Operation: "5"}, {ID: "", Operation: "WRITE"}}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Errorf("entries = %#v, want %#v", entries, wantEntries)
	}
}

func TestCheckResourceBulkOperations_Refusals(t *testing.T) {
	cases := []struct {
		name string
		body string
		n    int
		err  string
	}{
		{"only empty operations leave nothing to check", `[{"type":"ORDER","operations":[""]}]`, 0, ""},
		{"an empty array has nothing to check", `[]`, 0, ""},
		{"absent operations are missing", `[{"type":"ORDER"}]`, 0, "Missing required parameter: operations"},
		{"operations that are not an array are missing", `[{"type":"ORDER","operations":"READ"}]`, 0, "Missing required parameter: operations"},
		{"empty operations are missing", `[{"type":"ORDER","operations":[]}]`, 0, "Missing required parameter: operations"},
		{"null operations are missing", `[{"type":"ORDER","operations":null}]`, 0, "Missing required parameter: operations"},
		{"a missing type names the parameter", `[{"operations":["READ"]}]`, 0, "Missing required parameter: type"},
		{"the same id twice is refused", `[{"id":"a","type":"ORDER","operations":["READ"]},{"id":"a","type":"DOC","operations":["READ"]}]`,
			0, "Duplicate resource id in bulk request: resource ids must be unique"},
		{"an object body is a bad request", `{"type":"ORDER","operations":["READ"]}`, 0, "bad request"},
		{"an empty body is a bad request", ``, 0, "bad request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resources, _, err := CheckResourceBulkOperations([]byte(tc.body))
			if message(err) != tc.err {
				t.Fatalf("CheckResourceBulkOperations(%s) error = %q, want %q", tc.body, message(err), tc.err)
			}
			if len(resources) != tc.n {
				t.Errorf("CheckResourceBulkOperations(%s) = %d resources, want %d", tc.body, len(resources), tc.n)
			}
		})
	}
}

// The one type of the body is repeated on every resource of every entry;
// a null operation adds nothing, and a null id is no id.
func TestCheckResourceBulkOperationsV2_SharesTheType(t *testing.T) {
	body := `{"type":"ORDER","entries":[{"id":"a","operations":["READ",null,"WRITE"]},{"id":null,"operations":["READ"],"resource":{"o":1}}]}`
	resources, entries, err := CheckResourceBulkOperationsV2([]byte(body))
	if err != nil {
		t.Fatalf("CheckResourceBulkOperationsV2(%s) error = %q", body, err.Message)
	}
	empty := map[string]any{}
	wantResources := []Resource{
		{ResourceType: "ORDER", Operation: "READ", Resource: empty},
		{ResourceType: "ORDER", Operation: "WRITE", Resource: empty},
		{ResourceType: "ORDER", Operation: "READ", Resource: map[string]any{"o": json.Number("1")}},
	}
	if got := decoded(resources); !reflect.DeepEqual(got, wantResources) {
		t.Errorf("resources = %#v, want %#v", got, wantResources)
	}
	wantEntries := []Entry{{ID: "a", Operation: "READ"}, {ID: "a", Operation: "WRITE"}, {ID: "", Operation: "READ"}}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Errorf("entries = %#v, want %#v", entries, wantEntries)
	}
}

func TestCheckResourceBulkOperationsV2_EmptyEntriesHaveNothingToCheck(t *testing.T) {
	body := `{"type":"ORDER","entries":[]}`
	resources, entries, err := CheckResourceBulkOperationsV2([]byte(body))
	if err != nil || len(resources) != 0 || len(entries) != 0 {
		t.Errorf("CheckResourceBulkOperationsV2(%s) = %d resources, %d entries, error %q, want none of each", body, len(resources), len(entries), message(err))
	}
}

func TestCheckResourceBulkOperationsV2_Refusals(t *testing.T) {
	cases := []struct {
		name string
		body string
		err  string
	}{
		{"an empty body is a bad request", ``, "bad request"},
		{"an array body is a bad request", `[]`, "bad request"},
		{"a null body has no type", `null`, "Missing required parameter: type"},
		{"a missing type names the parameter", `{"entries":[]}`, "Missing required parameter: type"},
		{"absent entries are missing", `{"type":"ORDER"}`, "Missing required parameter: entries"},
		{"entries that are not an array are a bad request", `{"type":"ORDER","entries":{}}`, "bad request"},
		{"null entries are a bad request", `{"type":"ORDER","entries":null}`, "bad request"},
		{"an entry without operations names the parameter", `{"type":"ORDER","entries":[{"id":"a"}]}`, "Missing required parameter: operations"},
		{"an entry that is not an object has no operations", `{"type":"ORDER","entries":["a"]}`, "Missing required parameter: operations"},
		{"the same id twice is refused", `{"type":"ORDER","entries":[{"id":"a","operations":["READ"]},{"id":"a","operations":["READ"]}]}`,
			"Duplicate resource id in bulk request: resource ids must be unique"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := CheckResourceBulkOperationsV2([]byte(tc.body))
			if message(err) != tc.err {
				t.Errorf("CheckResourceBulkOperationsV2(%s) error = %q, want %q", tc.body, message(err), tc.err)
			}
		})
	}
}

func TestCheckFilter(t *testing.T) {
	cases := []struct {
		name                    string
		resourceType, operation string
		want                    []Resource
		err                     string
	}{
		{"a blank operation means ALL", "ORDER", " ", []Resource{{ResourceType: "ORDER", Operation: "ALL", Resource: map[string]any{}}}, ""},
		{"an absent operation means ALL", "ORDER", "", []Resource{{ResourceType: "ORDER", Operation: "ALL", Resource: map[string]any{}}}, ""},
		{"values keep their spaces", " ORDER ", " READ", []Resource{{ResourceType: " ORDER ", Operation: " READ", Resource: map[string]any{}}}, ""},
		{"a blank resource type is a bad request", " ", "READ", nil, "bad request"},
		{"an absent resource type is a bad request", "", "", nil, "bad request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckFilter(tc.resourceType, tc.operation)
			if message(err) != tc.err {
				t.Fatalf("CheckFilter(%q, %q) error = %q, want %q", tc.resourceType, tc.operation, message(err), tc.err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CheckFilter(%q, %q) = %#v, want %#v", tc.resourceType, tc.operation, got, tc.want)
			}
		})
	}
}

func TestInput(t *testing.T) {
	resources := []Resource{{ResourceType: "ORDER", Operation: "READ", Resource: map[string]any{}}}
	wantResources := []any{map[string]any{"resourceType": "ORDER", "operation": "READ", "resource": map[string]any{}}}
	cases := []struct {
		name    string
		headers map[string][]string
		want    map[string]any
	}{
		{"the tokens, the request id, and the other headers lowercased",
			map[string][]string{
				"Authorization": {"Bearer m2m"}, "Incoming-Token": {"Bearer user"}, "Authorization-Type": {""},
				"X-Request-Id": {"r1"}, "X-Tenant": {"acme"}, "Host": {"agent"}, "Content-Type": {"application/json"},
				"X-Authz-Original-Path": {"/x"},
			},
			map[string]any{
				"authorizationToken": "Bearer m2m", "subject": "Bearer user", "authorizationType": "",
				"requestHeaders": map[string]any{"authorization-type": "", "x-tenant": "acme"}, "requestId": "r1",
				"resources": wantResources,
			}},
		{"the subject falls back to the admission token",
			map[string][]string{"Authorization": {"Bearer m2m"}},
			map[string]any{
				"authorizationToken": "Bearer m2m", "subject": "Bearer m2m", "authorizationType": "",
				"requestHeaders": map[string]any{}, "requestId": "", "resources": wantResources,
			}},
		{"an authorization type other than anonymous keeps the subject",
			map[string][]string{"Authorization": {"Bearer m2m"}, "Incoming-Token": {"Bearer user"}, "Authorization-Type": {"Basic"}},
			map[string]any{
				"authorizationToken": "Bearer m2m", "subject": "Bearer user", "authorizationType": "Basic",
				"requestHeaders": map[string]any{"authorization-type": "Basic"}, "requestId": "", "resources": wantResources,
			}},
		{"an anonymous caller has no subject and keeps the admission token",
			map[string][]string{"Authorization": {"Bearer m2m"}, "Incoming-Token": {"Bearer user"}, "Authorization-Type": {" Anonymous "}},
			map[string]any{
				"authorizationToken": "Bearer m2m", "subject": "", "authorizationType": " Anonymous ",
				"requestHeaders": map[string]any{"authorization-type": " Anonymous "}, "requestId": "", "resources": wantResources,
			}},
		{"a repeated header contributes its last value",
			map[string][]string{"Authorization": {"Bearer first", "Bearer last"}, "X-Tenant": {"a", "b"}},
			map[string]any{
				"authorizationToken": "Bearer last", "subject": "Bearer last", "authorizationType": "",
				"requestHeaders": map[string]any{"x-tenant": "b"}, "requestId": "", "resources": wantResources,
			}},
		{"no headers at all",
			nil,
			map[string]any{
				"authorizationToken": "", "subject": "", "authorizationType": "",
				"requestHeaders": map[string]any{}, "requestId": "", "resources": wantResources,
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Input(tc.headers, resources); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Input(%v) = %#v, want %#v", tc.headers, got, tc.want)
			}
		})
	}
}

func TestAuthError(t *testing.T) {
	cases := []struct {
		name    string
		result  any
		status  int
		body    string
		refused bool
	}{
		{"a decision without authError is not refused", map[string]any{"results": []any{}}, 0, "", false},
		{"status and message as the policy gave them",
			map[string]any{"authError": map[string]any{"status": json.Number("403"), "message": "Token has expired"}}, 403, `{"message":"Token has expired"}`, true},
		{"an authError without fields is 401 unauthorized", map[string]any{"authError": map[string]any{}}, 401, `{"message":"unauthorized"}`, true},
		{"a status that is not a number is 401",
			map[string]any{"authError": map[string]any{"status": "403"}}, 401, `{"message":"unauthorized"}`, true},
		{"a status as a float is truncated",
			map[string]any{"authError": map[string]any{"status": 403.9}}, 403, `{"message":"unauthorized"}`, true},
		{"a status as an int is kept",
			map[string]any{"authError": map[string]any{"status": 429}}, 429, `{"message":"unauthorized"}`, true},
		{"a message that is not a string is passed on",
			map[string]any{"authError": map[string]any{"message": map[string]any{"code": json.Number("7")}}}, 401, `{"message":{"code":7}}`, true},
		{"a null authError still refuses", map[string]any{"authError": nil}, 401, `{"message":"unauthorized"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body, refused := AuthError(tc.result)
			if refused != tc.refused || status != tc.status || string(body) != tc.body {
				t.Errorf("AuthError(%v) = %d %s %v, want %d %s %v", tc.result, status, body, refused, tc.status, tc.body, tc.refused)
			}
		})
	}
}

func decision(results ...any) map[string]any {
	return map[string]any{"rlsIgnored": false, "results": results}
}

func allow(predicates ...any) map[string]any {
	r := map[string]any{"isAllowed": true}
	if predicates != nil {
		r["predicates"] = predicates
	}
	return r
}

var deny = map[string]any{"isAllowed": false}

func TestCheckResourceResponse(t *testing.T) {
	cases := []struct {
		name   string
		result any
		v2     bool
		want   string
	}{
		{"the first result allowed is true", decision(allow(), deny), false, `true`},
		{"the first result denied is false", decision(deny, allow()), false, `false`},
		{"no results is false", decision(), false, `false`},
		{"a result that is not an object is false", decision("yes"), false, `false`},
		{"isAllowed as a string is false", decision(map[string]any{"isAllowed": "true"}), false, `false`},
		{"v2 wraps the boolean", decision(allow()), true, `{"decision":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(CheckResourceResponse(tc.result, tc.v2)); got != tc.want {
				t.Errorf("CheckResourceResponse(%v, v2=%v) = %s, want %s", tc.result, tc.v2, got, tc.want)
			}
		})
	}
}

func TestCheckResourceBulkResponse(t *testing.T) {
	cases := []struct {
		name   string
		result any
		ids    []string
		want   string
	}{
		{"the ids of the allowed results, in order", decision(allow(), deny, allow()), []string{"a", "b", "c"}, `["a","c"]`},
		{"an allowed entry without an id is left out", decision(allow(), allow()), []string{"", "b"}, `["b"]`},
		{"nothing allowed is an empty array", decision(deny), []string{"a"}, `[]`},
		{"no results is an empty array", nil, []string{"a"}, `[]`},
		{"results beyond the ids are ignored", decision(allow(), allow()), []string{"a"}, `["a"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(CheckResourceBulkResponse(tc.result, tc.ids)); got != tc.want {
				t.Errorf("CheckResourceBulkResponse(%v, %v) = %s, want %s", tc.result, tc.ids, got, tc.want)
			}
		})
	}
}

func TestCheckResourceBulkOperationsResponse(t *testing.T) {
	entries := []Entry{{ID: "a", Operation: "READ"}, {ID: "a", Operation: "WRITE"}, {ID: "b", Operation: "READ"}}
	cases := []struct {
		name    string
		result  any
		entries []Entry
		v2      bool
		want    string
	}{
		{"allowed ids grouped by operation, operations sorted, none allowed as an empty array",
			decision(allow(), deny, allow()), entries, false, `{"READ":["a","b"],"WRITE":[]}`},
		{"v2 wraps the map", decision(allow(), deny, allow()), entries, true, `{"decision":{"READ":["a","b"],"WRITE":[]}}`},
		{"an allowed entry without an id keeps its operation and adds nothing",
			decision(allow()), []Entry{{ID: "", Operation: "READ"}}, false, `{"READ":[]}`},
		{"entries beyond the results keep their operations", decision(allow()), entries, false, `{"READ":["a"],"WRITE":[]}`},
		{"no entries is an empty map", nil, nil, false, `{}`},
		{"no entries in v2 is an empty decision", nil, nil, true, `{"decision":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(CheckResourceBulkOperationsResponse(tc.result, tc.entries, tc.v2)); got != tc.want {
				t.Errorf("CheckResourceBulkOperationsResponse(%v, %v, v2=%v) = %s, want %s", tc.result, tc.entries, tc.v2, got, tc.want)
			}
		})
	}
}

func typedPredicate(typ string, value any) map[string]any {
	return map[string]any{"predicateType": typ, "predicate": value}
}

func TestFilterResponse(t *testing.T) {
	const denied = `{"calculationResult":"DENY","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"","sqlFilterCondition":"","customFilterCondition":null}`
	const allowed = `{"calculationResult":"ALLOW","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"","sqlFilterCondition":"","customFilterCondition":null}`
	cases := []struct {
		name   string
		result any
		want   string
	}{
		{"no results is DENY", decision(), denied},
		{"a denied result is DENY whatever its predicates", decision(map[string]any{"isAllowed": false, "predicates": []any{typedPredicate("rsql", "a==b")}}), denied},
		{"allowed without predicates is ALLOW", decision(allow()), allowed},
		{"allowed with predicates of unknown types is ALLOW", decision(allow(typedPredicate("jpql", "a==b"))), allowed},
		{"a null predicate counts as none", decision(allow(typedPredicate("rsql", nil))), allowed},
		{"every typed predicate in its field, querydsl as filterCondition",
			decision(allow(typedPredicate("rsql", "dept==eng"), typedPredicate("querydsl", "dept eq eng"), typedPredicate("mongodb", map[string]any{"dept": "eng"}),
				typedPredicate("sql", "dept = 'eng'"), typedPredicate("custom", "x"))),
			`{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"dept eq eng","mongodbFilterCondition":"{\"dept\":\"eng\"}","rsqlFilterCondition":"dept==eng","sqlFilterCondition":"dept = 'eng'","customFilterCondition":"x"}`},
		{"only querydsl is still USE_FILTER_CONDITION", decision(allow(typedPredicate("querydsl", "dept eq eng"))),
			`{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"dept eq eng","mongodbFilterCondition":"","rsqlFilterCondition":"","sqlFilterCondition":"","customFilterCondition":null}`},
		{"the first predicate of a type wins", decision(allow(typedPredicate("rsql", "first"), typedPredicate("rsql", "second"))),
			`{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"first","sqlFilterCondition":"","customFilterCondition":null}`},
		{"HTML characters are not escaped", decision(allow(typedPredicate("rsql", "a<b"))),
			`{"calculationResult":"USE_FILTER_CONDITION","filterCondition":"","mongodbFilterCondition":"","rsqlFilterCondition":"a<b","sqlFilterCondition":"","customFilterCondition":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(FilterResponse(tc.result)); got != tc.want {
				t.Errorf("FilterResponse(%v) = %s, want %s", tc.result, got, tc.want)
			}
		})
	}
}

// decoded returns rs without their raw fields, which TestRawFieldsKeepTheTextOfTheRequest
// checks on its own.
func decoded(rs []Resource) []Resource {
	if rs == nil {
		return nil
	}
	out := make([]Resource, len(rs))
	for i, r := range rs {
		r.Raw = RawResource{}
		out[i] = r
	}
	return out
}

func TestRawFieldsKeepTheTextOfTheRequest(t *testing.T) {
	got, err := CheckResource([]byte(`{"type":"ORDER","operation":"READ","resource":{"b":1.50,"a":2}}`))
	if err != nil {
		t.Fatalf("CheckResource: %v", err)
	}
	want := RawResource{Type: json.RawMessage(`"ORDER"`), Operation: json.RawMessage(`"READ"`),
		Resource: json.RawMessage(`{"b":1.50,"a":2}`)}
	if !reflect.DeepEqual(got[0].Raw, want) {
		t.Errorf("CheckResource raw = %s, want %s", rawText(got[0].Raw), rawText(want))
	}

	got, _, err = CheckResourceBulkOperations([]byte(`[{"id":"a","type":"ORDER","operations":["READ",5]}]`))
	if err != nil {
		t.Fatalf("CheckResourceBulkOperations: %v", err)
	}
	if len(got) != 2 || string(got[1].Raw.Operation) != "5" || string(got[1].Raw.Type) != `"ORDER"` || got[1].Raw.Resource != nil {
		t.Errorf("CheckResourceBulkOperations raw = %v, want type \"ORDER\", operation 5, no resource", rawTexts(got))
	}
}

func rawText(r RawResource) string {
	return fmt.Sprintf("{type %s, operation %s, resource %s}", r.Type, r.Operation, r.Resource)
}

func rawTexts(rs []Resource) []string {
	var out []string
	for _, r := range rs {
		out = append(out, rawText(r.Raw))
	}
	return out
}
