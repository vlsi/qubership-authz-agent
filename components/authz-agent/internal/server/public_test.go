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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/regogen"
)

// publicSets stands in for the product policies on the public routes, in
// the tenant default: a READ of an ORDER is allowed with the rsql predicate
// type==ORDER, and any other operation is denied.
const publicSets = `{"policySets": [{"policySetId": "s", "name": "s", "status": "ACTIVE", "tenantId": "default",
	"target": "resourceType == 'ORDER'", "combiningAlgorithm": "DENY_UNLESS_PERMIT",
	"policies": [{"policyId": "p", "target": "true", "combiningAlgorithm": "DENY_UNLESS_PERMIT", "tenantId": "default",
		"rules": [{"ruleId": "r", "target": "operation == 'READ'", "effect": "ALLOW", "tenantId": "default",
			"rsqlPredicate": "type==ORDER"}]}]}]}`

// newPublicApp builds the public surface over publicSets, with the routing
// options main uses. collector is the base URL the download is relayed to,
// "" for none.
func newPublicApp(t *testing.T, logs *decisionlog.Logger, collector string) *fiber.App {
	t.Helper()
	return newPublicAppWithLog(t, logs, collector, nil)
}

// newPublicAppWithLog is newPublicApp with the diagnostics of the request
// path sent to log, and the platform's context middleware ahead of the
// routes, as the platform's Fiber builder installs it in main.
func newPublicAppWithLog(t *testing.T, logs *decisionlog.Logger, collector string, log Logger) *fiber.App {
	t.Helper()
	return newPublicAppOver(t, map[string]string{"internals.rego": admissionStub}, logs,
		Options{CollectorURL: collector, Log: log, Snapshots: registry(t, publicSets), DefaultTenant: func() string { return "default" }})
}

// registry is a snapshot registry loaded with the policy sets of sets and
// no PIPs.
func registry(t *testing.T, sets string) *snapshot.Registry {
	t.Helper()
	tab, err := regogen.DefaultTable()
	if err != nil {
		t.Fatal(err)
	}
	reg := snapshot.New(snapshot.Config{}, tab, quietLoader{})
	if _, err := reg.Load(context.Background(), []byte(sets), []byte(`{"pips": []}`)); err != nil {
		t.Fatal(err)
	}
	return reg
}

// newPublicAppOver builds the public surface over modules, with
// data.users.admin set to root, the decisions logged to logs, and the
// platform's context middleware ahead of the routes.
func newPublicAppOver(t *testing.T, modules map[string]string, logs *decisionlog.Logger, opts Options) *fiber.App {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: modules})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := eng.Put(context.Background(), []string{"users"}, map[string]any{"admin": "root"}); err != nil {
		t.Fatal(err)
	}
	srv := Register(fiber.New(fiber.Config{Immutable: true, DisableStartupMessage: true}), eng, logs, opts)
	app := fiber.New(fiber.Config{Immutable: true, StrictRouting: true, CaseSensitive: true, DisableStartupMessage: true})
	app.Use(platformContext)
	srv.RegisterPublic(app)
	return app
}

// call sends one request and returns the status, the body, and the
// Content-Type of the response.
func call(t *testing.T, app *fiber.App, method, path, body string, headers map[string]string) (int, string, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), resp.Header.Get(fiber.HeaderContentType)
}

var admin = map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer admin"}

// contextIDs keeps the request id of the context every line was written
// under, which is the id the platform log format prints as request_id.
type contextIDs struct{ seen []string }

func (r *contextIDs) record(ctx context.Context) {
	if id, err := xrequestid.Of(ctx); err == nil {
		r.seen = append(r.seen, id.GetRequestId())
	}
}

func (r *contextIDs) DebugC(ctx context.Context, _ string, _ ...any) { r.record(ctx) }
func (r *contextIDs) WarnC(ctx context.Context, _ string, _ ...any)  { r.record(ctx) }
func (r *contextIDs) ErrorC(ctx context.Context, _ string, _ ...any) { r.record(ctx) }

// platformContext is the middleware the platform's Fiber builder installs
// ahead of the routes: it builds the propagated context from the headers as
// they arrived, and copies what is propagated back into the response.
func platformContext(c *fiber.Ctx) error {
	headers := map[string]any{}
	for key, value := range c.Request().Header.All() {
		headers[string(key)] = string(value)
	}
	c.SetUserContext(ctxmanager.InitContext(context.Background(), headers))
	if err := ctxhelper.AddResponsePropagatableContextData(c.UserContext(), c.Response().Header.Add); err != nil {
		return err
	}
	return c.Next()
}

// TestPublic_TheRequestIdNamesTheRequestEverywhere: the decision log reads
// the request header and a log line reads the propagated context, so support
// holding one of two ids finds nothing under the other. A request that
// arrives without an X-Request-Id is given one, and the context built from
// that same absent header holds an id of its own, which the generated one
// replaces; a request that brings an id keeps it in all three places.
func TestPublic_TheRequestIdNamesTheRequestEverywhere(t *testing.T) {
	ctxmanager.Register(baseproviders.Get())
	for _, tc := range []struct{ name, given string }{
		{"no request id was sent", ""},
		{"the caller sent a request id", "id-from-the-caller"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, events, stop := collector(t)
			defer stop()
			lines := &contextIDs{}
			app := newPublicAppWithLog(t, logs, "", lines)

			resp := checkResourceWithID(t, app, tc.given)
			defer func() { _ = resp.Body.Close() }()

			logged := loggedRequestID(t, nextEvent(t, events), tc.given)
			if got := resp.Header.Get(fiber.HeaderXRequestID); got != logged {
				t.Errorf("the response carries request id %q, want %q, the one the decision was logged under", got, logged)
			}
			assertLinesCarry(t, lines, logged)
		})
	}
}

// checkResourceWithID sends one legacy check, under the given request id when
// it is not empty, and fails the test unless it is answered.
func checkResourceWithID(t *testing.T, app *fiber.App, given string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/access/v1/check/resource",
		strings.NewReader(`{"type":"ORDER","operation":"READ"}`))
	req.Header.Set("Incoming-Token", "Bearer admin")
	if given != "" {
		req.Header.Set(fiber.HeaderXRequestID, given)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("POST /access/v1/check/resource: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /access/v1/check/resource = %d, want 200", resp.StatusCode)
	}
	return resp
}

// loggedRequestID is the id the decision was recorded under: the one the
// caller gave, or a generated UUID when it gave none.
func loggedRequestID(t *testing.T, ev decisionlog.Event, given string) string {
	t.Helper()
	logged := ev.RequestContext.HTTP.Headers["x-request-id"]
	if len(logged) != 1 {
		t.Fatalf("the decision log recorded x-request-id %q, want one value", logged)
	}
	if given != "" && logged[0] != given {
		t.Fatalf("the decision was logged under request id %q, want %q, the one the caller sent", logged[0], given)
	}
	if given == "" && len(logged[0]) != 36 {
		t.Fatalf("the decision was logged under request id %q, want a generated UUID", logged[0])
	}
	return logged[0]
}

// assertLinesCarry fails unless every line the request produced was written
// under want, and unless it produced any.
func assertLinesCarry(t *testing.T, lines *contextIDs, want string) {
	t.Helper()
	if len(lines.seen) == 0 {
		t.Fatal("no line was written under the request's context, so the id it carries cannot be checked")
	}
	for i, got := range lines.seen {
		if got != want {
			t.Errorf("line %d was written under request id %q, want %q, the one the decision was logged under", i+1, got, want)
		}
	}
}

// TestPublic_CheckResource: the v1 route answers a bare boolean and the v2
// route {"decision": bool}, both as JSON, from the first result.
func TestPublic_CheckResource(t *testing.T) {
	app := newPublicApp(t, nil, "")
	cases := []struct {
		name, path, body, want string
	}{
		{"v1 allowed", "/access/v1/check/resource?tenant_id=default", `{"type":"ORDER","operation":"READ","resource":{}}`, `true`},
		{"v1 denied", "/access/v1/check/resource", `{"type":"ORDER","operation":"DELETE"}`, `false`},
		{"v2 allowed", "/access/v2/check/resource?obligations=false", `{"type":"ORDER","operation":"READ"}`, `{"decision":true}`},
		{"v2 denied", "/access/v2/check/resource", `{"type":"ORDER","operation":"DELETE"}`, `{"decision":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, contentType := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != 200 || body != tc.want || contentType != fiber.MIMEApplicationJSON {
				t.Errorf("POST %s = %d %s (%s), want 200 %s (%s)", tc.path, code, body, contentType, tc.want, fiber.MIMEApplicationJSON)
			}
		})
	}
}

// TestPublic_CheckResource_Refusals: a request the legacy API rejects is a
// 400 with the legacy message before any policy runs; a request the policy
// refuses carries the authError's status and message; and a GET reaches
// the handler like a POST, so its empty body is what is rejected.
func TestPublic_CheckResource_Refusals(t *testing.T) {
	app := newPublicApp(t, nil, "")
	cases := []struct {
		name, method, body string
		headers            map[string]string
		status             int
		want               string
	}{
		{"an empty body", http.MethodPost, ``, admin, 400, `{"message":"bad request"}`},
		{"a missing type", http.MethodPost, `{"resource":{"id":"1"}}`, admin, 400, `{"message":"Missing required parameter: type"}`},
		{"no subject", http.MethodPost, `{"type":"ORDER","operation":"READ"}`, nil, 403, `{"message":"no subject"}`},
		{"a GET without a body", http.MethodGet, ``, admin, 400, `{"message":"bad request"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, tc.method, "/access/v1/check/resource", tc.body, tc.headers)
			if code != tc.status || body != tc.want {
				t.Errorf("%s /access/v1/check/resource = %d %s, want %d %s", tc.method, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Bulk: the bulk route lists the allowed ids and the
// bulk/operations routes group them by operation; a bulk/operations request
// without a single operation is answered without the policy, so it needs no
// token.
func TestPublic_Bulk(t *testing.T) {
	app := newPublicApp(t, nil, "")
	cases := []struct {
		name, path, body string
		headers          map[string]string
		status           int
		want             string
	}{
		{"bulk lists the allowed ids", "/access/v1/check/resource/bulk?tenant_id=default",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"b","type":"ORDER","operation":"DELETE"},{"type":"ORDER","operation":"READ"}]`,
			admin, 200, `["a"]`},
		{"bulk refuses duplicate ids", "/access/v1/check/resource/bulk",
			`[{"id":"a","type":"ORDER","operation":"READ"},{"id":"a","type":"ORDER","operation":"READ"}]`,
			admin, 400, `{"message":"Duplicate resource id in bulk request: resource ids must be unique"}`},
		{"v1 bulk/operations groups by operation", "/access/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ","DELETE"]},{"id":"b","type":"ORDER","operations":["READ"]}]`,
			admin, 200, `{"DELETE":[],"READ":["a","b"]}`},
		{"v1 preview is the same route", "/preview/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ"]}]`, admin, 200, `{"READ":["a"]}`},
		{"v2 bulk/operations wraps the map", "/access/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":["READ","DELETE"]}]}`, admin, 200, `{"decision":{"DELETE":[],"READ":["a"]}}`},
		{"v2 preview is the same route", "/preview/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":["DELETE"]}]}`, admin, 200, `{"decision":{"DELETE":[]}}`},
		{"v1 without an operation needs no token", "/access/v1/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":[""]}]`, nil, 200, `{}`},
		{"v2 without an operation needs no token", "/access/v2/check/resource/bulk/operations",
			`{"type":"ORDER","entries":[{"id":"a","operations":[""]}]}`, nil, 200, `{"decision":{}}`},
		{"a body the v1 route cannot parse", "/access/v1/check/resource/bulk/operations",
			`{"type":"ORDER"}`, admin, 400, `{"message":"bad request"}`},
		{"a body the v2 route cannot parse", "/access/v2/check/resource/bulk/operations",
			`[{"id":"a","type":"ORDER","operations":["READ"]}]`, admin, 400, `{"message":"bad request"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, tc.headers)
			if code != tc.status || body != tc.want {
				t.Errorf("POST %s = %d %s, want %d %s", tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Filter: the filter routes read the query, not the body, and
// answer the legacy filter shape with the policy's predicates, a dialect
// the policy gives none as null.
func TestPublic_Filter(t *testing.T) {
	app := newPublicApp(t, nil, "")
	const useFilter = `{"calculationResult":"USE_FILTER_CONDITION","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":"type==ORDER","sqlFilterCondition":null,"customFilterCondition":null}`
	const denied = `{"calculationResult":"DENY","filterCondition":null,"mongodbFilterCondition":null,"rsqlFilterCondition":null,"sqlFilterCondition":null,"customFilterCondition":null}`
	cases := []struct {
		name, path, body string
		status           int
		want             string
	}{
		{"v1 with an operation", "/access/v1/check/filter?resourceType=ORDER&operation=READ&tenant_id=default", "", 200, useFilter},
		{"v2 is the same shape", "/access/v2/check/filter?resourceType=ORDER&operation=READ", "", 200, useFilter},
		{"a denied operation", "/access/v1/check/filter?resourceType=ORDER&operation=DELETE", "", 200, denied},
		{"the last resourceType wins", "/access/v1/check/filter?resourceType=DOC&resourceType=ORDER&operation=READ", "", 200, useFilter},
		{"a body is ignored", "/access/v1/check/filter?resourceType=ORDER&operation=READ", `{"type":"DOC","operation":"DELETE"}`, 200, useFilter},
		{"no resourceType", "/access/v1/check/filter?operation=READ", "", 400, `{"message":"bad request"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, admin)
			if code != tc.status || body != tc.want {
				t.Errorf("POST %s = %d %s, want %d %s", tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_Surface: the check routes, /api-version, /health, and the
// decision-log download answer as Envoy answered them, and every other path,
// /access/v1/authorize included, is 404 {"message":"not found"}.
func TestPublic_Surface(t *testing.T) {
	app := newPublicApp(t, nil, "")
	authorize := `{"input":{"subject":"Bearer admin","resources":[{"resourceType":"ORDER","operation":"READ"}]}}`
	cases := []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"an unknown path", http.MethodGet, "/unknown/endpoint", "", 404, `{"message":"not found"}`},
		{"POST /access/v1/authorize", http.MethodPost, "/access/v1/authorize", authorize, 404, `{"message":"not found"}`},
		{"a check route with a trailing slash", http.MethodPost, "/access/v1/check/resource/", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"a mistyped check route", http.MethodPost, "/access/v1/check/resourc", `{"type":"ORDER","operation":"READ"}`, 404, `{"message":"not found"}`},
		{"api-version by GET", http.MethodGet, "/api-version", "", 200, LegacyAPIVersion},
		{"api-version by POST", http.MethodPost, "/api-version", "", 200, LegacyAPIVersion},
		{"the decision-log download without a pap-client", http.MethodGet, "/internal/v1/decision-logs", "", 404, `{"message":"not found"}`},
		{"health by GET without a pap-client", http.MethodGet, "/health", "", 200, `{"status":"healthy"}`},
		{"health by POST without a pap-client", http.MethodPost, "/health", "", 405, `{"message":"method not allowed"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := call(t, app, tc.method, tc.path, tc.body, nil)
			if code != tc.status || body != tc.want {
				t.Errorf("%s %s = %d %s, want %d %s", tc.method, tc.path, code, body, tc.status, tc.want)
			}
		})
	}
}

// TestPublic_CheckRoutesIgnoreExplain: a check route reads no query
// parameter beyond the ones its request shape names, so ?explain=full gets
// the same answer as the plain request.
func TestPublic_CheckRoutesIgnoreExplain(t *testing.T) {
	app := newPublicApp(t, nil, "")
	body := `{"type":"ORDER","operation":"READ"}`
	for _, path := range []string{"/access/v1/check/resource", "/access/v1/check/resource?explain=full"} {
		if code, got, _ := call(t, app, http.MethodPost, path, body, admin); code != 200 || got != "true" {
			t.Errorf("POST %s = %d %s, want 200 true", path, code, got)
		}
	}
}

// recorder is an upstream stub that records the requests it saw as
// "METHOD /path?query" and answers with a fixed status, content type, and
// body.
func recorder(status int, contentType, body string) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return srv, &seen
}

// TestPublic_RelaysTheDownloadToTheCollector: the decision-log download
// goes to the collector that receives the decisions, query included, and
// a body larger than one network read comes back whole.
func TestPublic_RelaysTheDownloadToTheCollector(t *testing.T) {
	lines := strings.Repeat("{\"decision_id\":\"1\"}\n", 40000)
	collector, seen := recorder(http.StatusOK, "application/x-ndjson", lines)
	defer collector.Close()
	app := newPublicApp(t, nil, collector.URL)

	code, body, contentType := call(t, app, http.MethodGet, "/internal/v1/decision-logs?since=1", "", nil)
	if code != 200 || contentType != "application/x-ndjson" || len(body) != len(lines) {
		t.Errorf("GET /internal/v1/decision-logs = %d (%s) with %d bytes, want 200 (application/x-ndjson) with %d bytes", code, contentType, len(body), len(lines))
	}
	if strings.Join(*seen, ", ") != "GET /internal/v1/decision-logs?since=1" {
		t.Errorf("collector saw %q, want the download with its query", *seen)
	}
}

// TestPublic_ServesTheStoredDecisions: with the decisions stored in the
// service, the download serves the store as NDJSON for GET, answers 405 to
// any other method, and relays nothing to a collector.
func TestPublic_ServesTheStoredDecisions(t *testing.T) {
	collector, collectorSaw := recorder(http.StatusOK, "application/x-ndjson", "")
	defer collector.Close()
	store := decisionlog.NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	if _, err := store.Append([]decisionlog.Event{{DecisionID: "d-1", Path: "authorize"}}); err != nil {
		t.Fatal(err)
	}
	logs := decisionlog.New(decisionlog.Config{Store: store}, nil)
	app := newPublicApp(t, logs, collector.URL)

	code, body, contentType := call(t, app, http.MethodGet, "/internal/v1/decision-logs", "", nil)
	if code != 200 || contentType != "application/x-ndjson" || !strings.Contains(body, `"decision_id":"d-1"`) {
		t.Errorf("GET /internal/v1/decision-logs = %d %q (%s), want 200 NDJSON with the stored decision", code, body, contentType)
	}
	if code, body, _ := call(t, app, http.MethodPost, "/internal/v1/decision-logs", "", nil); code != 405 || body != `{"message":"method not allowed"}` {
		t.Errorf("POST /internal/v1/decision-logs = %d %s, want 405", code, body)
	}
	if len(*collectorSaw) != 0 {
		t.Errorf("collector saw %q, want nothing", *collectorSaw)
	}
}

// TestPublic_ReportsADecisionLogThatCannotBeRead: the download answers a
// message that names no cause, because the caller cannot act on one; the
// error the store returned is what an operator needs, so it is reported.
func TestPublic_ReportsADecisionLogThatCannotBeRead(t *testing.T) {
	// A regular file where a directory belongs: opening a path under it
	// fails for a reason that is not "the log has not been written yet",
	// which is the one failure the download answers 200 to.
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := decisionlog.New(decisionlog.Config{Store: decisionlog.NewStore(filepath.Join(notADir, "decisions.jsonl"))}, nil)
	reported := &levels{}
	app := newPublicAppWithLog(t, logs, "", reported)

	code, body, _ := call(t, app, http.MethodGet, "/internal/v1/decision-logs", "", nil)
	if code != 500 || body != `{"message":"failed to read decision logs"}` {
		t.Fatalf("GET /internal/v1/decision-logs over an unreadable store = %d %s, want 500", code, body)
	}
	errors := reported.at("error")
	if len(errors) != 1 {
		t.Fatalf("an unreadable decision log reported %v, want one error", reported.lines)
	}
	if !strings.Contains(errors[0], "decision log download failed") {
		t.Errorf("the failure reported %q, want it to name the download", errors[0])
	}
}

// TestPublic_RelayToACollectorThatDoesNotAnswer: a collector that cannot be
// reached is reported as 503 naming it, so the caller can tell the relay
// apart from an empty log, and the timeout is reported as a warning.
func TestPublic_RelayToACollectorThatDoesNotAnswer(t *testing.T) {
	reported := &levels{}
	app := newPublicAppWithLog(t, nil, "http://127.0.0.1:1", reported)
	code, body, _ := call(t, app, http.MethodGet, "/internal/v1/decision-logs", "", nil)
	if code != 503 || !strings.Contains(body, "collector unavailable") {
		t.Errorf("GET /internal/v1/decision-logs with no collector = %d %s, want 503 with a message naming the collector", code, body)
	}
	if got := reported.at("warn"); len(got) != 1 || !strings.Contains(got[0], "collector did not answer") {
		t.Errorf("an unreachable collector reported %v, want one warning naming the collector", reported.lines)
	}
}

// collector runs a decision-log uploader against a collector that forwards
// every event to the returned channel.
func collector(t *testing.T) (*decisionlog.Logger, <-chan decisionlog.Event, func()) {
	t.Helper()
	events := make(chan decisionlog.Event, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzipReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return
		}
		var batch []decisionlog.Event
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Errorf("decode: %v", err)
		}
		for _, ev := range batch {
			events <- ev
		}
	}))
	logs := decisionlog.New(decisionlog.Config{URL: srv.URL, Headers: []string{"x-request-id", "x-authz-original-path"}, FlushInterval: 20 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go logs.Run(ctx)
	return logs, events, func() {
		cancel()
		logs.Wait()
		srv.Close()
	}
}

func nextEvent(t *testing.T, events <-chan decisionlog.Event) decisionlog.Event {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("no decision log upload within 3s")
		return decisionlog.Event{}
	}
}

// TestPublic_LogsTheLegacyDecision: a legacy request is logged as the
// canonical decision at authorize, with the route as x-authz-original-path,
// a generated x-request-id when the caller sent none, and the input the
// translation built: the tokens in their fields and the other headers
// under requestHeaders.
func TestPublic_LogsTheLegacyDecision(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicApp(t, logs, "")
	headers := map[string]string{"Authorization": "Bearer m2m", "Incoming-Token": "Bearer admin", "X-Tenant": "acme"}

	code, body, _ := call(t, app, http.MethodPost, "/access/v1/check/resource?tenant_id=default", `{"type":"ORDER","operation":"READ"}`, headers)
	if code != 200 || body != `true` {
		t.Fatalf("POST /access/v1/check/resource = %d %s, want 200 true", code, body)
	}
	ev := nextEvent(t, events)
	if ev.Path != "authorize" || ev.DecisionID == "" {
		t.Errorf("event path %q decision id %q, want authorize and an id", ev.Path, ev.DecisionID)
	}
	recorded := ev.RequestContext.HTTP.Headers
	if got := recorded["x-authz-original-path"]; len(got) != 1 || got[0] != "/access/v1/check/resource" {
		t.Errorf("x-authz-original-path = %q, want [/access/v1/check/resource]", got)
	}
	requestID := recorded["x-request-id"]
	if len(requestID) != 1 || len(requestID[0]) != 36 {
		t.Fatalf("x-request-id = %q, want one generated UUID", requestID)
	}
	input := ev.Input.(map[string]any)
	if input["requestId"] != requestID[0] || input["authorizationToken"] != "Bearer m2m" || input["subject"] != "Bearer admin" {
		t.Errorf("input = %v, want the generated request id and the tokens from the headers", input)
	}
	requestHeaders := input["requestHeaders"].(map[string]any)
	if requestHeaders["x-tenant"] != "acme" || requestHeaders["authorization"] != nil || requestHeaders["incoming-token"] != nil {
		t.Errorf("requestHeaders = %v, want x-tenant and neither token", requestHeaders)
	}
	if ev.Result.(map[string]any)["rlsIgnored"] != false {
		t.Errorf("result = %v, want the canonical decision", ev.Result)
	}
}

// TestPublic_LogsTheRouteAsOriginalPath: every legacy route records its
// route as x-authz-original-path. The bulk/operations routes record their
// own path and query, so the access and preview routes stay apart; the
// others record the route's path alone. The caller's request id is kept.
func TestPublic_LogsTheRouteAsOriginalPath(t *testing.T) {
	logs, events, stop := collector(t)
	defer stop()
	app := newPublicApp(t, logs, "")
	single := `{"type":"ORDER","operation":"READ"}`
	bulk := `[{"id":"a","type":"ORDER","operation":"READ"}]`
	operations := `[{"id":"a","type":"ORDER","operations":["READ"]}]`
	operationsV2 := `{"type":"ORDER","entries":[{"id":"a","operations":["READ"]}]}`
	cases := []struct {
		path, body, want string
	}{
		{"/access/v1/check/resource?tenant_id=default", single, "/access/v1/check/resource"},
		{"/access/v2/check/resource?tenant_id=default", single, "/access/v2/check/resource"},
		{"/access/v1/check/resource/bulk?tenant_id=default", bulk, "/access/v1/check/resource/bulk"},
		{"/access/v1/check/resource/bulk/operations?tenant_id=default", operations, "/access/v1/check/resource/bulk/operations?tenant_id=default"},
		{"/preview/v1/check/resource/bulk/operations?tenant_id=default", operations, "/preview/v1/check/resource/bulk/operations?tenant_id=default"},
		{"/access/v2/check/resource/bulk/operations?tenant_id=default", operationsV2, "/access/v2/check/resource/bulk/operations?tenant_id=default"},
		{"/preview/v2/check/resource/bulk/operations?tenant_id=default", operationsV2, "/preview/v2/check/resource/bulk/operations?tenant_id=default"},
		{"/access/v1/check/filter?resourceType=ORDER", "", "/access/v1/check/filter"},
		{"/access/v2/check/filter?resourceType=ORDER", "", "/access/v2/check/filter"},
	}
	for i, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			requestID := fmt.Sprintf("req-%d", i)
			headers := map[string]string{"Authorization": "Bearer m2m", "X-Request-Id": requestID}
			if code, body, _ := call(t, app, http.MethodPost, tc.path, tc.body, headers); code != 200 {
				t.Fatalf("POST %s = %d %s, want 200", tc.path, code, body)
			}
			recorded := nextEvent(t, events).RequestContext.HTTP.Headers
			if got := recorded["x-authz-original-path"]; len(got) != 1 || got[0] != tc.want {
				t.Errorf("x-authz-original-path for POST %s = %q, want [%s]", tc.path, got, tc.want)
			}
			if got := recorded["x-request-id"]; len(got) != 1 || got[0] != requestID {
				t.Errorf("x-request-id for POST %s = %q, want [%s]", tc.path, got, requestID)
			}
		})
	}
}
