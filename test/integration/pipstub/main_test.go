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
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func resetState() {
	routes = map[string]*pipRoute{}
	calls = []callRecord{}
	counters = map[string]int{}
	rules = nil
	ruleCounter = map[string]int{}
	compiledRe = map[string]*regexp.Regexp{}
}

func TestJsonPathGet(t *testing.T) {
	body := map[string]any{
		"requestAttributes": map[string]any{"resourceType": "Customer"},
		"ids":               []any{map[string]any{"id": "C1"}, map[string]any{"id": "C2"}},
	}
	cases := []struct {
		path string
		want any
		ok   bool
	}{
		{"$", body, true},
		{"$.requestAttributes.resourceType", "Customer", true},
		{"$.ids[0].id", "C1", true},
		{"$.ids[1].id", "C2", true},
		{"$.ids[9].id", nil, false},
		{"$.missing.x", nil, false},
	}
	for _, c := range cases {
		got, ok := jsonPathGet(body, c.path)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v want %v", c.path, ok, c.ok)
		}
		if ok && !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: got %v want %v", c.path, got, c.want)
		}
	}
}

func TestRuleMatches_ContentMatching(t *testing.T) {
	m := stubMatch{
		Method:  "POST",
		Path:    "/api/v1/pip/allowed",
		Query:   map[string]string{"tenant": "100"},
		Headers: map[string]string{"X-Trace-Id": "*"},
		Body:    []bodyPredicate{{JsonPath: "$.requestAttributes.resourceType", Equals: "Customer"}},
	}
	match := callRecord{
		Method:  "POST",
		Path:    "/api/v1/pip/allowed",
		Query:   map[string][]string{"tenant": {"100"}},
		Headers: map[string]string{"x-trace-id": "abc"},
		Body:    map[string]any{"requestAttributes": map[string]any{"resourceType": "Customer"}},
	}
	if !ruleMatches(m, match) {
		t.Fatal("expected full match")
	}
	// wrong tenant
	bad := match
	bad.Query = map[string][]string{"tenant": {"999"}}
	if ruleMatches(m, bad) {
		t.Fatal("expected query mismatch to fail")
	}
	// missing header
	bad2 := match
	bad2.Headers = map[string]string{}
	if ruleMatches(m, bad2) {
		t.Fatal("expected missing header to fail")
	}
	// wrong body predicate
	bad3 := match
	bad3.Body = map[string]any{"requestAttributes": map[string]any{"resourceType": "Order"}}
	if ruleMatches(m, bad3) {
		t.Fatal("expected body predicate mismatch to fail")
	}
}

func TestHandlePIP_EchoRule(t *testing.T) {
	resetState()
	rules = []stubRule{{
		Name:    "echo",
		Match:   stubMatch{Path: "/api/v1/pip/echo"},
		Respond: &stubRespond{Status: 200, Echo: true},
	}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pip/echo?a=1", strings.NewReader(`{"k":"v"}`))
	req.Header.Set("X-Trace-Id", "t-1")
	rr := httptest.NewRecorder()
	handlePIP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var echoed map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &echoed); err != nil {
		t.Fatalf("echo body: %v (%s)", err, rr.Body.String())
	}
	if echoed["method"] != "POST" || echoed["path"] != "/api/v1/pip/echo" {
		t.Fatalf("echo mismatch: %v", echoed)
	}
	body, _ := echoed["body"].(map[string]any)
	if body["k"] != "v" {
		t.Fatalf("echo body payload mismatch: %v", echoed["body"])
	}
	// the call was captured with full request content
	if len(calls) != 1 || calls[0].BodyRaw != `{"k":"v"}` || calls[0].Headers["x-trace-id"] != "t-1" {
		t.Fatalf("call capture mismatch: %+v", calls)
	}
}

func TestHandlePIP_RuleThenLegacyFallback(t *testing.T) {
	resetState()
	// a rule for /rule only; legacy route for /legacy
	rules = []stubRule{{
		Name:    "r",
		Match:   stubMatch{Path: "/rule"},
		Respond: &stubRespond{Status: 200, JSON: map[string]any{"from": "rule"}},
	}}
	routes["/legacy"] = &pipRoute{Path: "/legacy", Responses: []pipResponse{{StatusCode: 200, Body: map[string]any{"from": "route"}}}}

	// /rule → rule engine
	rr := httptest.NewRecorder()
	handlePIP(rr, httptest.NewRequest(http.MethodGet, "/rule", nil))
	if !strings.Contains(rr.Body.String(), `"from":"rule"`) {
		t.Fatalf("expected rule response, got %s", rr.Body.String())
	}
	// /legacy → falls through to legacy path route
	rr2 := httptest.NewRecorder()
	handlePIP(rr2, httptest.NewRequest(http.MethodGet, "/legacy", nil))
	if !strings.Contains(rr2.Body.String(), `"from":"route"`) {
		t.Fatalf("expected legacy route response, got %s", rr2.Body.String())
	}
	// unknown → 404
	rr3 := httptest.NewRecorder()
	handlePIP(rr3, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rr3.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr3.Code)
	}
}

func TestLoadRuleConfigFile(t *testing.T) {
	resetState()
	loadRuleConfig("config/requestargs.responses.yaml")
	if len(rules) == 0 {
		t.Fatal("expected rules loaded from config/requestargs.responses.yaml")
	}
	byName := map[string]stubRule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	echo, ok := byName["echo-parity"]
	if !ok || echo.Respond == nil || !echo.Respond.Echo {
		t.Fatalf("echo-parity rule missing or not echo: %+v", echo)
	}
	slow, ok := byName["slow-upstream"]
	if !ok || slow.Respond == nil || slow.Respond.DelayMs != 3000 {
		t.Fatalf("slow-upstream rule missing delayMs: %+v", slow)
	}
	flaky, ok := byName["flaky-then-ok"]
	if !ok || len(flaky.RespondSequence) != 2 {
		t.Fatalf("flaky-then-ok sequence wrong: %+v", flaky)
	}
	allowed, ok := byName["allowed-ids-for-customer-read"]
	if !ok || len(allowed.Match.Body) != 1 || allowed.Match.Body[0].Equals != "Customer" {
		t.Fatalf("allowed rule body predicate wrong: %+v", allowed)
	}
}

func TestHandlePIP_RespondSequence(t *testing.T) {
	resetState()
	rules = []stubRule{{
		Name:  "flaky",
		Match: stubMatch{Path: "/flaky"},
		RespondSequence: []stubRespond{
			{Status: 503, JSON: map[string]any{"error": "warmup"}},
			{Status: 200, JSON: []any{"X1", "X2"}},
		},
	}}
	codes := []int{}
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		handlePIP(rr, httptest.NewRequest(http.MethodGet, "/flaky", nil))
		codes = append(codes, rr.Code)
	}
	// 503, then 200, then clamps to last (200)
	if !reflect.DeepEqual(codes, []int{503, 200, 200}) {
		t.Fatalf("sequence codes: %v", codes)
	}
}

// serve sends one request to handlePIP and returns its status and body.
func serve(method, target string) (int, string) {
	rr := httptest.NewRecorder()
	handlePIP(rr, httptest.NewRequest(method, target, nil))
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// The default route answers a path that has no route of its own, the routed
// path keeps its own answer, and a stub with no default route answers 404.
func TestHandlePIP_DefaultRouteAnswersUnroutedPaths(t *testing.T) {
	cases := []struct {
		name, path  string
		withDefault bool
		wantStatus  int
		wantBody    string
	}{
		{"an unrouted path gets the default answer", "/users/u-1", true, 200, `{"from":"default"}`},
		{"a routed path keeps its own answer", "/routed", true, 200, `{"from":"route"}`},
		{"an unrouted path without a default route is 404", "/users/u-1", false, 404,
			`{"error":"no rule or route for /users/u-1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetState()
			routes["/routed"] = &pipRoute{Path: "/routed", Responses: []pipResponse{{StatusCode: 200, Body: map[string]any{"from": "route"}}}}
			if tc.withDefault {
				routes[defaultRoute] = &pipRoute{Path: defaultRoute, Responses: []pipResponse{{StatusCode: 200, Body: map[string]any{"from": "default"}}}}
			}
			status, body := serve(http.MethodGet, tc.path)
			if status != tc.wantStatus || body != tc.wantBody {
				t.Errorf("GET %s = %d %s, want %d %s", tc.path, status, body, tc.wantStatus, tc.wantBody)
			}
		})
	}
}

// The default route serves its responses in sequence across every unrouted
// path, clamped to the last, as one route does for its own path.
func TestHandlePIP_DefaultRouteServesItsSequenceAcrossPaths(t *testing.T) {
	resetState()
	routes[defaultRoute] = &pipRoute{Path: defaultRoute, Responses: []pipResponse{{StatusCode: 503}, {StatusCode: 200}}}
	var got []int
	for _, path := range []string{"/a", "/b", "/a"} {
		status, _ := serve(http.MethodGet, path)
		got = append(got, status)
	}
	if want := []int{503, 200, 200}; !reflect.DeepEqual(got, want) {
		t.Errorf("statuses of /a, /b, /a = %v, want %v", got, want)
	}
}

// The call record keeps the request target as it arrived, while path holds it
// decoded and without the query.
func TestHandlePIP_RecordsTheRequestTargetAsSent(t *testing.T) {
	resetState()
	serve(http.MethodGet, "/users/a%2Fb%20c%3F?x=1")
	if len(calls) != 1 {
		t.Fatalf("recorded %d calls, want 1", len(calls))
	}
	got := calls[0]
	if got.RequestURI != "/users/a%2Fb%20c%3F?x=1" || got.Path != "/users/a/b c?" {
		t.Errorf("requestUri %q, path %q, want %q and %q", got.RequestURI, got.Path, "/users/a%2Fb%20c%3F?x=1", "/users/a/b c?")
	}
}
