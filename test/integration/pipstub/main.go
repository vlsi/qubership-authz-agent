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

// Command pip-stub is the mock PIP/entitlements endpoint used by test/parity
// and test/integration. It has two layers, additively (ADR-0066 request-args
// work):
//
//   - Legacy path-routing: register {path -> [responses]} via a JSON
//     PUT/POST /pip-stub/configure, or the hardcoded defaults. Responses are
//     served sequentially per path (clamped to the last). This layer keeps
//     every existing test working unchanged.
//   - Static rule engine (opt-in via PIP_STUB_CONFIG, a YAML file, usually
//     bind-mounted read-only): an ordered `rules` list matched against the full
//     request content (method/path/query/headers/body). The first fully-matching
//     rule wins. Supports `echo` (reply with the received request — the parity
//     mechanism), `delayMs` (server-side delay to drive client-timeout cases),
//     stateful `respondSequence`, and explicit status/headers.
//
// Precedence per request: record it, try the configured rules first; on no rule
// match fall back to the legacy path routes, then to the default route; else
// 404. When PIP_STUB_CONFIG is unset there are no rules and behaviour is
// exactly as before.
//
// The default route is the path-route registered under defaultRoute (*): it
// answers every request whose path has no route of its own, in sequence like
// any other route. No request path is *, so it never shadows a real route.
// A stub nobody configures with it answers an unrouted request 404, as it did
// before the default route existed.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Legacy path-routing model (unchanged wire contract) ──────────────────────

type pipResponse struct {
	StatusCode int    `json:"statusCode"`
	Body       any    `json:"body"`
	BodyRaw    string `json:"bodyRaw,omitempty"`
}

type pipRoute struct {
	Path      string        `json:"path"`
	Responses []pipResponse `json:"responses"`
}

// ── Full request capture (extended additively) ───────────────────────────────

type callRecord struct {
	Path string `json:"path"`
	// RequestURI is the request target as it arrived, before the path is
	// decoded and the query is split off, so that a caller that encodes a
	// value in the path differently from one that does not can be told apart.
	RequestURI string              `json:"requestUri"`
	Method     string              `json:"method"`
	Query      map[string][]string `json:"query,omitempty"`
	Headers    map[string]string   `json:"headers,omitempty"`
	BodyRaw    string              `json:"bodyRaw,omitempty"`
	Body       any                 `json:"body,omitempty"`
}

// ── Static rule engine model (YAML) ──────────────────────────────────────────

type stubConfig struct {
	Version int        `yaml:"version"`
	Rules   []stubRule `yaml:"rules"`
}

type stubRule struct {
	Name            string        `yaml:"name"`
	Match           stubMatch     `yaml:"match"`
	Respond         *stubRespond  `yaml:"respond"`
	RespondSequence []stubRespond `yaml:"respondSequence"`
}

type stubMatch struct {
	Method    string            `yaml:"method"`
	Path      string            `yaml:"path"`
	PathRegex string            `yaml:"pathRegex"`
	Query     map[string]string `yaml:"query"`
	Headers   map[string]string `yaml:"headers"`
	Body      []bodyPredicate   `yaml:"body"`
}

type bodyPredicate struct {
	JsonPath string `yaml:"jsonPath"`
	Equals   any    `yaml:"equals"`
}

type stubRespond struct {
	Status  int               `yaml:"status"`
	JSON    any               `yaml:"json"`
	Raw     string            `yaml:"raw"`
	Echo    bool              `yaml:"echo"`
	Headers map[string]string `yaml:"headers"`
	DelayMs int               `yaml:"delayMs"`
}

// defaultRoute is the path under which /pip-stub/configure registers the
// answer to every request whose path has no route of its own.
const defaultRoute = "*"

var (
	routes      map[string]*pipRoute
	calls       []callRecord
	counters    map[string]int // legacy per-path response index
	rules       []stubRule
	ruleCounter map[string]int // per-rule respondSequence index
	compiledRe  map[string]*regexp.Regexp
	mu          sync.Mutex
)

func main() {
	port := envOr("PIP_STUB_PORT", "8090")
	configPath := envOr("PIP_STUB_CONFIG", "")

	routes = make(map[string]*pipRoute)
	calls = make([]callRecord, 0)
	counters = make(map[string]int)
	ruleCounter = make(map[string]int)
	compiledRe = make(map[string]*regexp.Regexp)

	if configPath != "" {
		loadRuleConfig(configPath)
	}

	loadDefaultRoutes()

	http.HandleFunc("/pip-stub/calls", handleCalls)
	http.HandleFunc("/pip-stub/reset", handleReset)
	http.HandleFunc("/pip-stub/configure", handleConfigure)
	http.HandleFunc("/", handlePIP)

	addr := "0.0.0.0:" + port
	log.Printf("pip-stub listening on %s with %d path-routes and %d rules", addr, len(routes), len(rules))
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadDefaultRoutes() {
	defaults := []pipRoute{
		{Path: "/api/v1/pip/allowed", Responses: []pipResponse{{StatusCode: 200, Body: []string{"C1", "C2", "C3"}}}},
		{Path: "/api/v1/pip/tenantScope", Responses: []pipResponse{{StatusCode: 200, Body: "TENANT-DEFAULT"}}},
	}
	for i := range defaults {
		if _, exists := routes[defaults[i].Path]; !exists {
			routes[defaults[i].Path] = &defaults[i]
		}
	}
}

func loadRuleConfig(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("warning: cannot read PIP_STUB_CONFIG %s: %v", path, err)
		return
	}
	var cfg stubConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		log.Printf("warning: invalid PIP_STUB_CONFIG YAML: %v", err)
		return
	}
	rules = cfg.Rules
	seenNames := make(map[string]bool, len(rules))
	for i := range rules {
		// respondSequence counters key on rule name; duplicate/blank names alias.
		if seenNames[rules[i].Name] {
			log.Printf("warning: duplicate rule name %q — respondSequence counters will alias", rules[i].Name)
		}
		seenNames[rules[i].Name] = true
		if rules[i].Match.PathRegex != "" {
			re, err := regexp.Compile(rules[i].Match.PathRegex)
			if err != nil {
				log.Printf("warning: rule %q has invalid pathRegex %q: %v", rules[i].Name, rules[i].Match.PathRegex, err)
				continue
			}
			compiledRe[rules[i].Match.PathRegex] = re
		}
		log.Printf("loaded rule: %s", rules[i].Name)
	}
}

func handlePIP(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	var parsedBody any
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &parsedBody)
	}

	rec := callRecord{
		Path:       r.URL.Path,
		RequestURI: r.RequestURI,
		Method:     r.Method,
		Query:      map[string][]string(r.URL.Query()),
		Headers:    flattenHeaders(r.Header),
		BodyRaw:    string(bodyBytes),
		Body:       parsedBody,
	}

	mu.Lock()
	calls = append(calls, rec)

	// 1. Rule engine (first fully-matching rule wins).
	if resp, ok := matchRule(rec); ok {
		mu.Unlock()
		writeRespond(w, resp, rec)
		return
	}

	// 2. Legacy path routes (fallback so existing tests keep working), then
	// the default route.
	key := r.URL.Path
	route, ok := routes[key]
	if !ok || len(route.Responses) == 0 {
		key = defaultRoute
		route, ok = routes[key]
	}
	if !ok || len(route.Responses) == 0 {
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"error":"no rule or route for %s"}`, r.URL.Path)
		return
	}
	idx := counters[key]
	if idx >= len(route.Responses) {
		idx = len(route.Responses) - 1
	}
	counters[key] = idx + 1
	resp := route.Responses[idx]
	mu.Unlock()

	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if resp.BodyRaw != "" {
		_, _ = fmt.Fprint(w, resp.BodyRaw)
		return
	}
	_ = json.NewEncoder(w).Encode(resp.Body)
}

// matchRule returns the response for the first rule that fully matches, and
// advances the per-rule sequence counter. Caller holds mu.
func matchRule(rec callRecord) (stubRespond, bool) {
	for i := range rules {
		rule := rules[i]
		if !ruleMatches(rule.Match, rec) {
			continue
		}
		if len(rule.RespondSequence) > 0 {
			idx := ruleCounter[rule.Name]
			if idx >= len(rule.RespondSequence) {
				idx = len(rule.RespondSequence) - 1
			}
			ruleCounter[rule.Name] = idx + 1
			return rule.RespondSequence[idx], true
		}
		if rule.Respond != nil {
			return *rule.Respond, true
		}
		// A matching rule with no response is a 200 empty body.
		return stubRespond{Status: http.StatusOK}, true
	}
	return stubRespond{}, false
}

func ruleMatches(m stubMatch, rec callRecord) bool {
	if m.Method != "" && !strings.EqualFold(m.Method, rec.Method) {
		return false
	}
	if m.Path != "" && m.Path != rec.Path {
		return false
	}
	if m.PathRegex != "" {
		re, ok := compiledRe[m.PathRegex]
		if !ok || !re.MatchString(rec.Path) {
			return false
		}
	}
	for k, want := range m.Query {
		got, present := rec.Query[k]
		if !present || len(got) == 0 {
			return false
		}
		if want != "*" && got[0] != want {
			return false
		}
	}
	for k, want := range m.Headers {
		got, present := rec.Headers[strings.ToLower(k)]
		if !present {
			return false
		}
		if want != "*" && got != want {
			return false
		}
	}
	for _, pred := range m.Body {
		got, ok := jsonPathGet(rec.Body, pred.JsonPath)
		if !ok || !valuesEqual(got, pred.Equals) {
			return false
		}
	}
	return true
}

func writeRespond(w http.ResponseWriter, resp stubRespond, rec callRecord) {
	if resp.DelayMs > 0 {
		time.Sleep(time.Duration(resp.DelayMs) * time.Millisecond)
	}
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	switch {
	case resp.Echo:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":  rec.Method,
			"path":    rec.Path,
			"query":   rec.Query,
			"headers": rec.Headers,
			"body":    rec.Body,
		})
	case resp.Raw != "":
		_, _ = fmt.Fprint(w, resp.Raw)
	default:
		_ = json.NewEncoder(w).Encode(resp.JSON)
	}
}

// ── Control surface (unchanged) ──────────────────────────────────────────────

func handleCalls(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	snapshot := make([]callRecord, len(calls))
	copy(snapshot, calls)
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	calls = make([]callRecord, 0)
	counters = make(map[string]int)
	ruleCounter = make(map[string]int)
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"status":"reset"}`)
}

func handleConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var cfg []pipRoute
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}
	mu.Lock()
	for i := range cfg {
		routes[cfg[i].Path] = &cfg[i]
	}
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"status":"configured","routes":%d}`, len(cfg))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// flattenHeaders lowercases header names (case-insensitive matching) and joins
// multi-value headers with ", " — the last-value-wins convention is avoided so
// tests can see everything sent.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

// jsonPathGet is a minimal dot/index walker ($.a.b, $.a[0].b) over parsed JSON
// — enough for rule body predicates. Returns (value, true) on a resolved path.
func jsonPathGet(root any, path string) (any, bool) {
	if path == "" || path == "$" {
		return root, true
	}
	p := strings.TrimPrefix(path, "$")
	p = strings.TrimPrefix(p, ".")
	cur := root
	for _, seg := range splitPath(p) {
		if idx, isIdx := parseIndex(seg); isIdx {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// splitPath splits `a.b[0].c` into ["a","b","[0]","c"].
func splitPath(p string) []string {
	var out []string
	for _, dotSeg := range strings.Split(p, ".") {
		if dotSeg == "" {
			continue
		}
		for {
			open := strings.IndexByte(dotSeg, '[')
			if open < 0 {
				if dotSeg != "" {
					out = append(out, dotSeg)
				}
				break
			}
			if open > 0 {
				out = append(out, dotSeg[:open])
			}
			close := strings.IndexByte(dotSeg, ']')
			if close < 0 {
				break
			}
			out = append(out, dotSeg[open:close+1])
			dotSeg = dotSeg[close+1:]
		}
	}
	return out
}

func parseIndex(seg string) (int, bool) {
	if len(seg) >= 2 && seg[0] == '[' && seg[len(seg)-1] == ']' {
		n, err := strconv.Atoi(seg[1 : len(seg)-1])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// valuesEqual compares a parsed-JSON value against a YAML `equals` value,
// normalizing numeric types (JSON numbers are float64, YAML ints are int).
func valuesEqual(got, want any) bool {
	if gf, ok := toFloat(got); ok {
		if wf, ok := toFloat(want); ok {
			return gf == wf
		}
	}
	return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
