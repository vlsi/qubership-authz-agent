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

// Package legacy translates between the check routes of the legacy
// access-control API and the canonical authorize decision. Each route's
// body and headers become the input the policies evaluate, and the decision
// becomes the response shape of that route, as the Lua filters of the Envoy
// container did before the service took the routes over.
//
// The Check functions parse a request and return its resources; [Input]
// wraps them with the tokens and headers into the policy input; the
// Response functions shape the decision. A request the legacy API refuses
// before any policy runs comes back as a *RequestError.
package legacy

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/open-policy-agent/opa/v1/util"
)

// RequestError is a request the legacy API refuses before any policy runs.
// The response is status 400 with Message as its message.
type RequestError struct {
	Message string
}

func (e *RequestError) Error() string { return e.Message }

var (
	errBadRequest  = &RequestError{Message: "bad request"}
	errDuplicateID = &RequestError{Message: "Duplicate resource id in bulk request: resource ids must be unique"}
)

func errMissing(parameter string) *RequestError {
	return &RequestError{Message: "Missing required parameter: " + parameter}
}

// Resource is one entry of input.resources. The values are kept as the
// caller sent them, so a resource type or operation that is not a string
// reaches the policy unchanged.
type Resource struct {
	ResourceType any
	Operation    any
	Resource     any
	// Raw holds the same three fields as the request wrote them, member
	// order and number text included, for the generated policies; a field
	// the request left out is empty.
	Raw RawResource
}

// RawResource is the JSON text of a resource's fields as the request wrote
// them; an empty field is one the request left out.
type RawResource struct {
	Type, Operation, Resource json.RawMessage
}

// Entry is the legacy id and operation behind one Resource of a
// bulk/operations request. The response groups the allowed ids by
// operation and keeps the order of the entries within each operation.
type Entry struct {
	ID        string
	Operation string
}

// checkItem is the body of a check/resource request and one element of a
// check/resource/bulk body.
type checkItem struct {
	ID        json.RawMessage `json:"id"`
	Type      json.RawMessage `json:"type"`
	Operation json.RawMessage `json:"operation"`
	Resource  json.RawMessage `json:"resource"`
}

// operationsItem is one element of a v1 bulk/operations body.
type operationsItem struct {
	ID         json.RawMessage `json:"id"`
	Type       json.RawMessage `json:"type"`
	Operations json.RawMessage `json:"operations"`
	Resource   json.RawMessage `json:"resource"`
}

// v2Body is the body of a v2 bulk/operations request: one resource type for
// every entry.
type v2Body struct {
	Type    json.RawMessage `json:"type"`
	Entries json.RawMessage `json:"entries"`
}

// v2Entry is one element of v2Body.Entries.
type v2Entry struct {
	ID         json.RawMessage `json:"id"`
	Operations json.RawMessage `json:"operations"`
	Resource   json.RawMessage `json:"resource"`
}

// CheckResource parses the body of the check/resource routes: an object
// with type and operation, and an optional resource that defaults to an
// empty object. A body that is empty, or JSON that is neither an object
// nor null, is refused as "bad request"; a missing, null, or empty type or
// operation names the parameter, so a null body is missing its type. Only
// the top-level fields count: a type inside the resource is not the type.
func CheckResource(body []byte) ([]Resource, *RequestError) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errBadRequest
	}
	var it checkItem
	if err := json.Unmarshal(body, &it); err != nil {
		return nil, errBadRequest
	}
	r, err := it.resource()
	if err != nil {
		return nil, err
	}
	return []Resource{r}, nil
}

// CheckResourceBulk parses the body of check/resource/bulk: an array of
// check/resource objects, each with an optional id. The ids come back in
// the order of the resources, "" for an entry without one, for
// [CheckResourceBulkResponse]. Two entries with the same id are refused.
func CheckResourceBulk(body []byte) ([]Resource, []string, *RequestError) {
	items, err := array(body)
	if err != nil {
		return nil, nil, err
	}
	resources := make([]Resource, 0, len(items))
	ids := make([]string, 0, len(items))
	rawIDs := make([]json.RawMessage, 0, len(items))
	for _, raw := range items {
		var it checkItem
		if json.Unmarshal(raw, &it) != nil {
			return nil, nil, errMissing("type")
		}
		r, err := it.resource()
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, r)
		ids = append(ids, text(it.ID))
		rawIDs = append(rawIDs, it.ID)
	}
	if err := uniqueIDs(rawIDs); err != nil {
		return nil, nil, err
	}
	return resources, ids, nil
}

// CheckResourceBulkOperations parses the body of the v1 bulk/operations
// routes: an array of objects with type, a non-empty operations array, and
// an optional id and resource. Every operation of an item becomes one
// Resource, paired with an Entry for [CheckResourceBulkOperationsResponse];
// an operation that is an empty string or null contributes none, and an id
// that is null counts as absent. Two items with the same id are refused.
func CheckResourceBulkOperations(body []byte) ([]Resource, []Entry, *RequestError) {
	items, err := array(body)
	if err != nil {
		return nil, nil, err
	}
	var resources []Resource
	var entries []Entry
	rawIDs := make([]json.RawMessage, 0, len(items))
	for _, raw := range items {
		var it operationsItem
		if json.Unmarshal(raw, &it) != nil || !present(it.Type) {
			return nil, nil, errMissing("type")
		}
		ops, ok := operations(it.Operations)
		if !ok {
			return nil, nil, errMissing("operations")
		}
		resources, entries, err = expand(resources, entries, it.Type, ops, it.Resource, text(it.ID))
		if err != nil {
			return nil, nil, err
		}
		rawIDs = append(rawIDs, it.ID)
	}
	if err := uniqueIDs(rawIDs); err != nil {
		return nil, nil, err
	}
	return resources, entries, nil
}

// CheckResourceBulkOperationsV2 parses the body of the v2 bulk/operations
// routes: an object with type and an entries array, each entry with a
// non-empty operations array and an optional id and resource. The
// resources and entries follow the v1 rules of
// [CheckResourceBulkOperations] with the one type shared.
func CheckResourceBulkOperationsV2(body []byte) ([]Resource, []Entry, *RequestError) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil, errBadRequest
	}
	var b v2Body
	if json.Unmarshal(body, &b) != nil {
		return nil, nil, errBadRequest
	}
	if !present(b.Type) {
		return nil, nil, errMissing("type")
	}
	if len(b.Entries) == 0 {
		return nil, nil, errMissing("entries")
	}
	items, err := array(b.Entries)
	if err != nil {
		return nil, nil, err
	}
	var resources []Resource
	var entries []Entry
	rawIDs := make([]json.RawMessage, 0, len(items))
	for _, raw := range items {
		var e v2Entry
		if json.Unmarshal(raw, &e) != nil {
			return nil, nil, errMissing("operations")
		}
		ops, ok := operations(e.Operations)
		if !ok {
			return nil, nil, errMissing("operations")
		}
		resources, entries, err = expand(resources, entries, b.Type, ops, e.Resource, text(e.ID))
		if err != nil {
			return nil, nil, err
		}
		rawIDs = append(rawIDs, e.ID)
	}
	if err := uniqueIDs(rawIDs); err != nil {
		return nil, nil, err
	}
	return resources, entries, nil
}

// CheckFilter builds the resource of the check/filter routes from the query
// parameters. resourceType must not be blank. Both values are kept as sent,
// spaces included; an operation the request left out is empty.
func CheckFilter(resourceType, operation string) ([]Resource, *RequestError) {
	if strings.TrimSpace(resourceType) == "" {
		return nil, errBadRequest
	}
	return []Resource{{ResourceType: resourceType, Operation: operation, Resource: map[string]any{}}}, nil
}

// resource validates the item and converts it.
func (it checkItem) resource() (Resource, *RequestError) {
	if !present(it.Type) {
		return Resource{}, errMissing("type")
	}
	if !present(it.Operation) {
		return Resource{}, errMissing("operation")
	}
	return newResource(it.Type, it.Operation, it.Resource)
}

// newResource converts the raw fields; a missing resource is an empty
// object.
func newResource(typ, op, res json.RawMessage) (Resource, *RequestError) {
	t, err := value(typ, "")
	if err != nil {
		return Resource{}, err
	}
	o, err := value(op, "")
	if err != nil {
		return Resource{}, err
	}
	r, err := value(res, map[string]any{})
	if err != nil {
		return Resource{}, err
	}
	return Resource{ResourceType: t, Operation: o, Resource: r,
		Raw: RawResource{Type: typ, Operation: op, Resource: res}}, nil
}

// expand appends one Resource and Entry per operation of a bulk/operations
// item, skipping operations that are empty strings or null.
func expand(resources []Resource, entries []Entry, typ json.RawMessage, ops []json.RawMessage, res json.RawMessage, id string) ([]Resource, []Entry, *RequestError) {
	for _, op := range ops {
		name := text(op)
		if name == "" {
			continue
		}
		r, err := newResource(typ, nil, res)
		if err != nil {
			return nil, nil, err
		}
		r.Operation = name
		r.Raw.Operation = op
		resources = append(resources, r)
		entries = append(entries, Entry{ID: id, Operation: name})
	}
	return resources, entries, nil
}

// array splits a JSON array body into its elements. Any other body,
// including an empty one, is refused as "bad request".
func array(body []byte) ([]json.RawMessage, *RequestError) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errBadRequest
	}
	var items []json.RawMessage
	if json.Unmarshal(trimmed, &items) != nil {
		return nil, errBadRequest
	}
	return items, nil
}

// operations splits the operations field of a bulk/operations item; ok is
// false when the field is absent, not an array, or empty.
func operations(raw json.RawMessage) (ops []json.RawMessage, ok bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	if json.Unmarshal(trimmed, &ops) != nil || len(ops) == 0 {
		return nil, false
	}
	return ops, true
}

// present reports whether a required field carries a value: absent, null,
// and "" all count as missing.
func present(raw json.RawMessage) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "", "null", `""`:
		return false
	}
	return true
}

// value decodes a field into the Go value the engine takes, with numbers
// as json.Number, and returns fallback when the field is absent.
func value(raw json.RawMessage, fallback any) (any, *RequestError) {
	if len(raw) == 0 {
		return fallback, nil
	}
	var v any
	if err := util.UnmarshalJSON(raw, &v); err != nil {
		return nil, errBadRequest
	}
	return v, nil
}

// text is a scalar field as the response names it: a JSON string decoded,
// any other value as it was written, and "" when the field is absent or
// null.
func text(raw json.RawMessage) string {
	s := string(bytes.TrimSpace(raw))
	if s == "" || s == "null" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		var decoded string
		if json.Unmarshal(raw, &decoded) == nil {
			return decoded
		}
	}
	return s
}

// uniqueIDs refuses a bulk request whose entries share an id. Ids compare
// as written, so 1 and "1" are different ids; absent and null ids are not
// compared.
func uniqueIDs(ids []json.RawMessage) *RequestError {
	seen := map[string]bool{}
	for _, raw := range ids {
		s := string(bytes.TrimSpace(raw))
		if s == "" || s == "null" {
			continue
		}
		if seen[s] {
			return errDuplicateID
		}
		seen[s] = true
	}
	return nil
}

// skipHeaders are the request headers left out of input.requestHeaders: the
// transport's own, the tokens the input carries in their own fields, and
// the two the agent itself uses for the request id and the decision log.
var skipHeaders = map[string]bool{
	":authority": true, ":path": true, ":method": true, ":scheme": true, ":status": true, ":protocol": true,
	"content-type": true, "content-length": true, "accept-encoding": true, "host": true,
	"transfer-encoding": true, "connection": true, "x-forwarded-for": true, "x-forwarded-proto": true,
	"x-request-id": true, "x-envoy-expected-rq-timeout-ms": true, "authorization": true,
	"x-authz-original-path": true, "incoming-token": true,
}

// Input builds the canonical authorize input of a legacy request from its
// headers and resources. The admission token is the Authorization header.
// The subject is Incoming-Token when present, else Authorization, and empty
// when Authorization-Type is anonymous. input.requestHeaders carries the
// remaining headers under their lowercase names for the HEADER PIPs, and
// input.requestId the X-Request-Id. A repeated header contributes its last
// value.
func Input(headers map[string][]string, resources []Resource) map[string]any {
	get := func(name string) string {
		for k, values := range headers {
			if strings.EqualFold(k, name) && len(values) > 0 {
				return values[len(values)-1]
			}
		}
		return ""
	}
	authType := get("authorization-type")
	admission := get("authorization")
	subject := ""
	if !strings.EqualFold(strings.TrimSpace(authType), "anonymous") {
		if subject = get("incoming-token"); subject == "" {
			subject = admission
		}
	}
	requestHeaders := map[string]any{}
	for k, values := range headers {
		name := strings.ToLower(k)
		if skipHeaders[name] || len(values) == 0 {
			continue
		}
		requestHeaders[name] = values[len(values)-1]
	}
	list := make([]any, len(resources))
	for i, r := range resources {
		list[i] = map[string]any{"resourceType": r.ResourceType, "operation": r.Operation, "resource": r.Resource}
	}
	return map[string]any{
		"authorizationToken": admission,
		"subject":            subject,
		"authorizationType":  authType,
		"requestHeaders":     requestHeaders,
		"requestId":          get("x-request-id"),
		"resources":          list,
	}
}

// AuthError reports a decision the policy refused before evaluating the
// resources. status is result.authError.status, or 401 when it is not a
// number; body is {"message": result.authError.message}, with
// "unauthorized" when the policy gave no message. ok is false when the
// decision carries no authError.
func AuthError(result any) (status int, body []byte, ok bool) {
	raw, refused := object(result)["authError"]
	if !refused {
		return 0, nil, false
	}
	status = 401
	var message any = "unauthorized"
	fields := object(raw)
	if n, isNumber := number(fields["status"]); isNumber {
		status = n
	}
	if m, given := fields["message"]; given {
		message = m
	}
	return status, mustJSON(map[string]any{"message": message}), true
}

// CheckResourceResponse is the body of the check/resource routes: whether
// the first result is allowed, as a bare boolean for v1 and as
// {"decision": bool} for v2.
func CheckResourceResponse(result any, v2 bool) []byte {
	decision := allowed(first(results(result)))
	if v2 {
		return mustJSON(map[string]bool{"decision": decision})
	}
	return mustJSON(decision)
}

// CheckResourceBulkResponse is the body of check/resource/bulk: the ids of
// the entries whose result is allowed, in request order. An entry without
// an id is left out even when allowed.
func CheckResourceBulkResponse(result any, ids []string) []byte {
	out := []string{}
	for i, r := range results(result) {
		if i < len(ids) && ids[i] != "" && allowed(r) {
			out = append(out, ids[i])
		}
	}
	return mustJSON(out)
}

// CheckResourceBulkOperationsResponse is the body of the bulk/operations
// routes: the allowed ids grouped by operation, with every requested
// operation present even when none of its ids is allowed, and the
// operations in lexical order. v2 wraps the map as {"decision": ...}. With
// no entries the map is empty.
func CheckResourceBulkOperationsResponse(result any, entries []Entry, v2 bool) []byte {
	byOperation := map[string][]string{}
	for _, e := range entries {
		byOperation[e.Operation] = []string{}
	}
	for i, r := range results(result) {
		if i >= len(entries) {
			break
		}
		if e := entries[i]; e.ID != "" && allowed(r) {
			byOperation[e.Operation] = append(byOperation[e.Operation], e.ID)
		}
	}
	if v2 {
		return mustJSON(map[string]any{"decision": byOperation})
	}
	return mustJSON(byOperation)
}

func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func results(result any) []any {
	list, _ := object(result)["results"].([]any)
	return list
}

func first(list []any) any {
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

func allowed(item any) bool {
	return object(item)["isAllowed"] == true
}

// number converts a number of the decision, which the engine returns as a
// json.Number, to an int.
func number(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return int(f), true
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// mustJSON encodes a response body without escaping HTML characters; the
// Lua filters wrote the bytes as they were.
func mustJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}
