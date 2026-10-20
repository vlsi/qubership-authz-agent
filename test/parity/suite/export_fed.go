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

package paritysuite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"

	"authz-agent/test/parity/suite/model"
)

// exportFedProfile is the PARITY_PROFILE under which the agent pulls its
// configuration from v3 exports the suite serves, instead of from
// authz-policy-admin seeded with simplified policies. TestExportFedAgent runs
// under it, and TestParitySuite skips.
const exportFedProfile = "authz-agent-export"

func isExportFedProfile(profile string) bool {
	return normalizeProfile(profile) == exportFedProfile
}

// Paths of the v3 configuration API the agent's pull loop fetches.
const (
	exportPolicySetsPath = "/access/v3/config/policySets"
	exportPIPsPath       = "/access/v3/config/pips"
)

// The empty export, which replay mounts before each function. It matches
// PARITY_EXPORT_EMPTY of the Makefile, which the stand serves until the suite
// starts.
var (
	emptyExportPolicySets = json.RawMessage(`{"policySets":[]}`)
	emptyExportPIPs       = json.RawMessage(`{"pips":[]}`)
)

// ExportFedConfig holds the settings of the export-fed profile. They are read
// apart from [Config] because no other test reads them.
type ExportFedConfig struct {
	// BundleDir is the export bundle the specification writes: index.json and
	// exports/<id>.json. PARITY_EXPORT_BUNDLE, default testdata/export-bundle.
	BundleDir string
	// SourceControlURL is the control endpoint of the pipstub instance the
	// agent's AUTHZ_PAP_CLIENT_SOURCE_URL points at, which serves the mounted
	// export. PARITY_EXPORT_SOURCE_CONTROL_URL, default http://localhost:28194.
	SourceControlURL string
	// Run selects the test functions of the bundle whose name it matches.
	// PARITY_EXPORT_RUN, default every function.
	Run *regexp.Regexp
	// PullTimeout bounds the wait for the agent to load a mounted export.
	// PARITY_EXPORT_PULL_TIMEOUT_SECONDS, default 30.
	PullTimeout time.Duration
}

// LoadExportFedConfig reads the PARITY_EXPORT_* variables.
func LoadExportFedConfig() (ExportFedConfig, error) {
	cfg := ExportFedConfig{
		BundleDir:        envOr("PARITY_EXPORT_BUNDLE", "testdata/export-bundle"),
		SourceControlURL: envOr("PARITY_EXPORT_SOURCE_CONTROL_URL", "http://localhost:"+envOr("PARITY_EXPORT_SOURCE_PORT", "28194")),
		PullTimeout:      30 * time.Second,
	}
	if v := os.Getenv("PARITY_EXPORT_RUN"); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return cfg, fmt.Errorf("PARITY_EXPORT_RUN: %w", err)
		}
		cfg.Run = re
	}
	if v := os.Getenv("PARITY_EXPORT_PULL_TIMEOUT_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("PARITY_EXPORT_PULL_TIMEOUT_SECONDS=%q: want a positive number of seconds", v)
		}
		cfg.PullTimeout = time.Duration(n) * time.Second
	}
	return cfg, nil
}

// exportBundleVersion is the version of index.json this reader understands.
const exportBundleVersion = 1

// exportBundle is index.json of an export bundle: per recorded test function,
// the log the profile replays.
type exportBundle struct {
	Version   int              `json:"version"`
	Functions []exportFunction `json:"functions"`
}

type exportFunction struct {
	Test   string        `json:"test"`
	Events []exportEvent `json:"events"`
}

// exportEvent is one entry of a function's log, by Ev:
//   - "pin", "configure", "pin-reset", "calls-reset": a call to a PIP stub
//     (Mock names the stub by the URL it had when the log was dumped);
//   - "export": mount the export ID;
//   - "http": send a decision request as recorded, with the token labels of
//     Headers replaced by tokens;
//   - "golden": compare the answer to the last request with the golden at
//     Path. Status is "pinned" when every export knob the specification
//     read on the way to the export is pinned by goldens, else "inferred";
//     Class is the difference class the specification predicts, "agree" when
//     it predicts none; Agent is the answer it predicts for the agent.
type exportEvent struct {
	Ev        string            `json:"ev"`
	Mock      string            `json:"mock,omitempty"`
	Path      string            `json:"path,omitempty"`
	Responses []PipStubResponse `json:"responses,omitempty"`
	Routes    []pipStubRoute    `json:"routes,omitempty"`
	ID        string            `json:"id,omitempty"`
	Method    string            `json:"method,omitempty"`
	Query     string            `json:"query,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      json.RawMessage   `json:"body,omitempty"`
	Status    string            `json:"status,omitempty"`
	Class     string            `json:"class,omitempty"`
	Families  []string          `json:"families,omitempty"`
	Agent     json.RawMessage   `json:"agent,omitempty"`
}

// readExportBundle reads index.json of dir and refuses a version this reader
// does not know.
func readExportBundle(dir string) (exportBundle, error) {
	var b exportBundle
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("decode %s: %w", filepath.Join(dir, "index.json"), err)
	}
	if b.Version != exportBundleVersion {
		return b, fmt.Errorf("export bundle version %d, this suite reads %d", b.Version, exportBundleVersion)
	}
	return b, nil
}

// bundleExports reads the exports of a bundle: exports/<id>.json lists the
// ids of its elements, elements.json holds each element once.
type bundleExports struct {
	dir      string
	elements map[string]json.RawMessage
}

func openBundleExports(dir string) (*bundleExports, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "elements.json"))
	if err != nil {
		return nil, err
	}
	b := &bundleExports{dir: dir}
	if err := json.Unmarshal(raw, &b.elements); err != nil {
		return nil, fmt.Errorf("decode %s: %w", filepath.Join(dir, "elements.json"), err)
	}
	return b, nil
}

// documents returns the two documents of the export id as the source serves
// them: {"policySets": [...]} and {"pips": [...]}.
func (b *bundleExports) documents(id string) (policySets, pips json.RawMessage, err error) {
	raw, err := os.ReadFile(filepath.Join(b.dir, "exports", id+".json"))
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		PolicySets []string `json:"policySets"`
		PIPs       []string `json:"pips"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("decode export %s: %w", id, err)
	}
	if policySets, err = b.document("policySets", doc.PolicySets); err != nil {
		return nil, nil, fmt.Errorf("export %s: %w", id, err)
	}
	if pips, err = b.document("pips", doc.PIPs); err != nil {
		return nil, nil, fmt.Errorf("export %s: %w", id, err)
	}
	return policySets, pips, nil
}

func (b *bundleExports) document(member string, ids []string) (json.RawMessage, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "{%q:[", member)
	for i, id := range ids {
		el, ok := b.elements[id]
		if !ok {
			return nil, fmt.Errorf("no element %s in elements.json", id)
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(el)
	}
	buf.WriteString("]}")
	return buf.Bytes(), nil
}

// goldenRow returns the row whose golden directory starts path, and the sub
// case under it.
func goldenRow(path string) (ParityEndpointID, string, bool) {
	best, bestLen := ParityEndpointID(0), 0
	for id, meta := range rowMetas {
		dir := meta.GoldenDir + "/"
		if strings.HasPrefix(path, dir) && len(dir) > bestLen {
			best, bestLen = id, len(dir)
		}
	}
	if bestLen == 0 {
		return 0, "", false
	}
	return best, strings.TrimSuffix(path[bestLen:], ".json"), true
}

// decisionOutcome turns the agent's answer to a decision request into the
// golden target of row id, as the case runners build it.
func decisionOutcome(id ParityEndpointID, status int, body []byte) (any, error) {
	target := NewGoldenTarget(id)
	ok := status == http.StatusOK
	switch t := target.(type) {
	case *model.CheckResourceOutcome:
		t.Status = status
		t.Decision = ok && decodeBoolean(body)
		return t, nil
	case *model.FilterOutcome:
		t.Status = status
		if ok {
			if err := decodeJSON(body, &t.Result); err != nil {
				return nil, err
			}
		}
		return t, nil
	case *model.CheckResourceBulkOutcome:
		t.Status = status
		if ok {
			var ids []string
			if err := decodeJSON(body, &ids); err != nil {
				return nil, err
			}
			sort.Strings(ids)
			if ids == nil {
				ids = []string{}
			}
			t.Allowed = &ids
		}
		return t, nil
	case *model.CheckResourceBulkOperationsOutcome:
		t.Status = status
		if ok {
			byOp := map[string][]string{}
			if err := decodeJSON(body, &byOp); err != nil {
				return nil, err
			}
			for op := range byOp {
				sort.Strings(byOp[op])
			}
			t.Decision = &byOp
		}
		return t, nil
	case *bool:
		// A plain row records a 200 answer; a refusal is not a denial.
		if !ok {
			return nil, fmt.Errorf("status %d: %s", status, strings.TrimSpace(string(body)))
		}
		*t = decodeBoolean(body)
		return t, nil
	}
	if !ok {
		return nil, fmt.Errorf("status %d: %s", status, strings.TrimSpace(string(body)))
	}
	if err := decodeJSON(body, target); err != nil {
		return nil, err
	}
	return target, nil
}

// sameOutcome compares two golden targets of row id the way the comparator
// compares an answer with its golden.
func sameOutcome(id ParityEndpointID, subCase string, want, got any) string {
	return cmp.Diff(normalizeComparable(id, subCase, want), normalizeComparable(id, subCase, got), compareOptionsFor(id)...)
}

// tokenLabel is a token as the dump writes it: "<realm>/m2m:<client>" or
// "<realm>/user:<username>@<client>".
type tokenLabel struct {
	realm, client, user string
}

var tokenLabelPattern = regexp.MustCompile(`^([^/]+)/(?:m2m:([^@]+)|user:([^@]+)@(.+))$`)

func parseTokenLabel(s string) (tokenLabel, bool) {
	m := tokenLabelPattern.FindStringSubmatch(s)
	if m == nil {
		return tokenLabel{}, false
	}
	if m[2] != "" {
		return tokenLabel{realm: m[1], client: m[2]}, true
	}
	return tokenLabel{realm: m[1], user: m[3], client: m[4]}, true
}

// labelTokens mints the tokens a recorded request carried, by their labels.
type labelTokens struct {
	cfg       Config
	factories map[string]*TokenFactory // realm -> factory
	clients   map[string]ClientCredentials
}

func newLabelTokens(cfg Config) *labelTokens {
	lt := &labelTokens{cfg: cfg, factories: map[string]*TokenFactory{}, clients: map[string]ClientCredentials{}}
	lt.factories[realmOf(cfg.IDPBaseURL)] = NewTokenFactory(cfg)
	for _, t := range []TenantRealm{cfg.Tenants.A, cfg.Tenants.B} {
		if t.IDPBaseURL != "" {
			c := cfg
			c.IDPBaseURL = t.IDPBaseURL
			lt.factories[realmOf(t.IDPBaseURL)] = NewTokenFactory(c)
		}
	}
	tc := cfg.TenantClaim
	for _, c := range []ClientCredentials{
		{ID: cfg.M2MClientID, Secret: cfg.M2MClientSecret}, {ID: cfg.EndUserClientID, Secret: cfg.EndUserClientSecret},
		tc.M2MTenantA, tc.M2MTenantB, tc.M2MTenantUnknown, tc.M2MTenantEmpty, tc.EndUserTenantA,
	} {
		lt.clients[c.ID] = c
	}
	for id, c := range cfg.TokenSubject {
		lt.clients[id] = c
	}
	return lt
}

// realmOf returns the realm name of an identity provider base URL such as
// http://idp:8080/auth/realms/parity, with or without a trailing slash, as
// NewTokenFactory accepts both.
func realmOf(base string) string {
	base = strings.TrimRight(base, "/")
	return base[strings.LastIndex(base, "/")+1:]
}

// errNoRealm marks a request whose token comes from a realm this stand lacks.
var errNoRealm = errors.New("the stand has no such realm")

// errNoIdentity marks a request whose user the stand's realm refuses a token
// for with invalid_grant, such as a user of the two-tenant stand on the kind
// harness. A wrong end-user password gets the same answer, which is why the
// profile first mints a token for a user the parity realm always has
// (checkKnownUser). A transport error, a server error or a refused client is
// not one.
var errNoIdentity = errors.New("the stand cannot issue a token for this user")

func (lt *labelTokens) token(label string) (string, error) {
	l, ok := parseTokenLabel(label)
	if !ok {
		return "", fmt.Errorf("token label %q", label)
	}
	f, ok := lt.factories[l.realm]
	if !ok {
		return "", fmt.Errorf("%w: %s", errNoRealm, l.realm)
	}
	client, ok := lt.clients[l.client]
	if !ok {
		return "", fmt.Errorf("token label %q names a client this suite has no secret for", label)
	}
	if l.user == "" {
		return f.M2MTokenFor(client)
	}
	tok, err := f.EndUserTokenVia(client, l.user)
	var refused *TokenRequestError
	if errors.As(err, &refused) && refused.InvalidGrant() {
		return "", fmt.Errorf("%w: %s: %v", errNoIdentity, l.user, err)
	}
	return tok, err
}

// exportSource serves an export to the agent and returns once the agent has
// loaded it.
type exportSource interface {
	Mount(ctx context.Context, policySets, pips json.RawMessage) error
}

// stubExportSource serves the export from a pipstub instance and waits until
// the agent has loaded it: a pull that fetched both documents after the mount
// has finished, which the pull loop shows by starting the next one.
type stubExportSource struct {
	stub    *PipController
	timeout time.Duration
	poll    time.Duration
}

func (s *stubExportSource) Mount(ctx context.Context, policySets, pips json.RawMessage) error {
	routes := []pipStubRoute{
		{Path: exportPolicySetsPath, Responses: []PipStubResponse{{StatusCode: http.StatusOK, BodyRaw: string(policySets)}}},
		{Path: exportPIPsPath, Responses: []PipStubResponse{{StatusCode: http.StatusOK, BodyRaw: string(pips)}}},
	}
	if err := s.stub.configure(ctx, routes); err != nil {
		return err
	}
	if err := s.stub.ResetCalls(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(s.timeout)
	var last []PipStubCall
	for time.Now().Before(deadline) {
		calls, err := s.stub.GetCalls(ctx)
		if err != nil {
			return err
		}
		last = calls
		if loadedAfterMount(calls) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.poll):
		}
	}
	return fmt.Errorf("timed out after %s waiting for the agent to pull the mounted export; calls since the mount: %s",
		s.timeout, callPaths(last))
}

// loadedAfterMount reports whether calls, made since the mount, hold a fetch
// of the policy sets, a fetch of the PIPs after it, and a fetch of the policy
// sets after that. A pull fetches the policy sets first, so a PIP fetch that
// comes first belongs to a pull that fetched the policy sets of the previous
// export, and only the pull that starts after the mount loads this one.
func loadedAfterMount(calls []PipStubCall) bool {
	step := 0
	for _, c := range calls {
		switch {
		case step == 0 && c.Path == exportPolicySetsPath, step == 1 && c.Path == exportPIPsPath:
			step++
		case step == 2 && c.Path == exportPolicySetsPath:
			return true
		}
	}
	return false
}

func callPaths(calls []PipStubCall) string {
	paths := make([]string, 0, len(calls))
	for _, c := range calls {
		paths = append(paths, c.Path)
	}
	return "[" + strings.Join(paths, " ") + "]"
}

// exportVerdict is the outcome of one golden of the export-fed profile.
type exportVerdict string

const (
	verdictMatch    exportVerdict = "match"
	verdictAccepted exportVerdict = "accepted"
	verdictDiffers  exportVerdict = "differs"
	verdictSkipped  exportVerdict = "skipped"
)

// exportResult is the verdict of one golden, with what the report needs.
type exportResult struct {
	Test, Path, Class, Status string
	Families                  []string
	Verdict                   exportVerdict
	Detail                    string
}

// exportReplayer replays the functions of a bundle against the agent.
type exportReplayer struct {
	exports   *bundleExports
	baseURL   string
	source    exportSource
	stubs     func(mockURL string) *PipController
	tokens    func(label string) (string, error)
	client    *http.Client
	goldenDir string
}

// replay runs one function and returns a verdict per golden. The caller resets
// the stubs' pinned routes between functions; every route an event pins is
// recorded for that reset. The function starts from the empty export, so the
// agent never decides on the policies of the function before: a pull that
// fails on the function's first export keeps the empty one, as on a fresh
// stand, whatever ran before and whatever PARITY_EXPORT_RUN selected.
func (r *exportReplayer) replay(ctx context.Context, fn exportFunction) ([]exportResult, error) {
	var out []exportResult
	if err := r.source.Mount(ctx, emptyExportPolicySets, emptyExportPIPs); err != nil {
		return out, fmt.Errorf("the empty export: %w", err)
	}
	var status int
	var body []byte
	var sendErr error
	sent := false
	for i := 0; i < len(fn.Events); i++ {
		ev := fn.Events[i]
		switch ev.Ev {
		case "pin":
			if err := pinResponses(ctx, r.stubs(ev.Mock), ev.Path, ev.Responses); err != nil {
				return out, err
			}
		case "configure":
			for _, route := range ev.Routes {
				if err := pinResponses(ctx, r.stubs(ev.Mock), route.Path, route.Responses); err != nil {
					return out, err
				}
			}
		case "pin-reset":
			if err := r.stubs(ev.Mock).ResetPinnedRoutes(ctx); err != nil {
				return out, err
			}
		case "calls-reset":
			if err := r.stubs(ev.Mock).ResetCalls(ctx); err != nil {
				return out, err
			}
		case "export":
			ps, pips, err := r.exports.documents(ev.ID)
			if err != nil {
				return out, err
			}
			if err := r.source.Mount(ctx, ps, pips); err != nil {
				return out, fmt.Errorf("export %s: %w", ev.ID, err)
			}
		case "http":
			status, body, sendErr = r.send(ctx, ev)
			sent = true
		case "golden":
			// The variants of a golden the stand recorded by order class follow
			// each other; the agent's answer has to match one of them.
			group := []exportEvent{ev}
			for i+1 < len(fn.Events) && fn.Events[i+1].Ev == "golden" && sameClassified(ev.Path, fn.Events[i+1].Path) {
				i++
				group = append(group, fn.Events[i])
			}
			res := r.judge(group, sent, status, body, sendErr)
			res.Test = fn.Test
			out = append(out, res)
		default:
			return out, fmt.Errorf("unknown event %q in %s", ev.Ev, fn.Test)
		}
	}
	return out, nil
}

var classVariant = regexp.MustCompile(`-when-the-pip-was-(read|skipped)(/|\.json$)`)

func sameClassified(a, b string) bool {
	return classVariant.MatchString(a) && classVariant.ReplaceAllString(a, "$2") == classVariant.ReplaceAllString(b, "$2")
}

func (r *exportReplayer) send(ctx context.Context, ev exportEvent) (int, []byte, error) {
	u := strings.TrimRight(r.baseURL, "/") + ev.Path
	if ev.Query != "" {
		u += "?" + ev.Query
	}
	var reader io.Reader
	trimmed := bytes.TrimSpace(ev.Body)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		payload := []byte(trimmed)
		// The dump writes a body that is not JSON as a JSON string.
		var text string
		if trimmed[0] == '"' && json.Unmarshal(trimmed, &text) == nil {
			payload = []byte(text)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, ev.Method, u, reader)
	if err != nil {
		return 0, nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range ev.Headers {
		if k == "Authorization" || k == "Incoming-Token" {
			tok, err := r.tokens(v)
			if err != nil {
				return 0, nil, err
			}
			v = "Bearer " + tok
		}
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// judge compares the answer to the last request with a golden, or with the
// variants of a classified one. A difference whose class acceptedExportDivergences
// lists passes when the agent answers as the bundle predicts for that class.
func (r *exportReplayer) judge(group []exportEvent, sent bool, status int, body []byte, sendErr error) exportResult {
	ev := group[0]
	res := exportResult{Path: ev.Path, Class: ev.Class, Status: ev.Status, Families: ev.Families}
	switch {
	case !sent:
		res.Verdict, res.Detail = verdictSkipped, "no request precedes the golden"
		return res
	case errors.Is(sendErr, errNoRealm), errors.Is(sendErr, errNoIdentity):
		res.Verdict, res.Detail = verdictSkipped, sendErr.Error()
		return res
	case sendErr != nil:
		res.Verdict, res.Detail = verdictDiffers, "request: "+sendErr.Error()
		return res
	}
	id, subCase, ok := goldenRow(ev.Path)
	if !ok {
		// The bundle names only decision goldens, so an unknown directory means the
		// bundle and this suite disagree on the golden kinds.
		res.Verdict, res.Detail = verdictDiffers, "no row has this golden directory"
		return res
	}
	actual, err := decisionOutcome(id, status, body)
	if err != nil {
		res.Verdict, res.Detail = verdictDiffers, err.Error()
		return res
	}
	wants := make([]any, len(group))
	for i, g := range group {
		gid, _, _ := goldenRow(g.Path)
		want, err := readGoldenTarget(r.goldenDir, gid, g.Path)
		if err != nil {
			// The bundle names only goldens the specification compared, so a
			// golden the suite cannot read means the bundle and the golden tree
			// differ, not that the case waits for a recording.
			res.Verdict, res.Detail = verdictDiffers, "the bundle names a golden the suite cannot read: "+err.Error()
			return res
		}
		wants[i] = want
	}
	var diffs []string
	for i, g := range group {
		gid, gsub, _ := goldenRow(g.Path)
		d := sameOutcome(gid, gsub, wants[i], actual)
		if d == "" {
			res.Verdict = verdictMatch
			return res
		}
		diffs = append(diffs, d)
	}
	res.Verdict, res.Detail = verdictDiffers, strings.Join(diffs, "\n")
	if accepted, ok := acceptedExportDivergences[ev.Class]; ok && len(ev.Agent) > 0 && !grantsMore(actual, wants) {
		predicted := NewGoldenTarget(id)
		if err := json.Unmarshal(ev.Agent, predicted); err == nil && sameOutcome(id, subCase, predicted, actual) == "" {
			res.Verdict = verdictAccepted
			res.Detail = fmt.Sprintf("class %s, decided in %s: %s", ev.Class, accepted.Decision, accepted.Reason)
		}
	}
	return res
}

// grantsMore reports whether actual allows something that one of the golden
// targets wants (the variants of one golden) does not: a check that allows
// where the golden denies, an id or an operation the golden leaves out, or a
// filter result of a higher rank (DENY, then USE_FILTER_CONDITION, then
// ALLOW). An accepted class covers such an answer only in part A of the
// profile, where its entry sets AllowsMore.
func grantsMore(actual any, wants []any) bool {
	for _, want := range wants {
		if !grants(actual, want) {
			return false
		}
	}
	return len(wants) > 0
}

func grants(actual, want any) bool {
	switch a := actual.(type) {
	case *bool:
		w, _ := want.(*bool)
		return *a && (w == nil || !*w)
	case *model.CheckResourceOutcome:
		w, _ := want.(*model.CheckResourceOutcome)
		return a.Status == http.StatusOK && a.Decision && (w == nil || w.Status != http.StatusOK || !w.Decision)
	case *[]string:
		w, _ := want.(*[]string)
		return w != nil && !subset(*a, *w)
	case *model.CheckResourceResponse:
		w, _ := want.(*model.CheckResourceResponse)
		return a.Decision && (w == nil || !w.Decision)
	case *model.CheckResourceBulkOutcome:
		// A refused golden allows no id, so an answer that allows none grants
		// nothing more than it.
		var allowed []string
		if w, _ := want.(*model.CheckResourceBulkOutcome); w != nil && w.Allowed != nil {
			allowed = *w.Allowed
		}
		return a.Allowed != nil && !subset(*a.Allowed, allowed)
	case *map[string][]string:
		w, _ := want.(*map[string][]string)
		return w != nil && !opsSubset(*a, *w)
	case *model.CheckResourceBulkOperationsOutcome:
		var allowed map[string][]string
		if w, _ := want.(*model.CheckResourceBulkOperationsOutcome); w != nil && w.Decision != nil {
			allowed = *w.Decision
		}
		return a.Decision != nil && !opsSubset(*a.Decision, allowed)
	case *model.CheckResourcesResponse:
		w, _ := want.(*model.CheckResourcesResponse)
		return w != nil && !opsSubset(a.Decision, w.Decision)
	case *model.FilterOutcome:
		w, _ := want.(*model.FilterOutcome)
		if w == nil || w.Status != http.StatusOK {
			return a.Status == http.StatusOK && filterRank(a.Result.CalculationResult) > 0
		}
		return a.Status == http.StatusOK && filterRank(a.Result.CalculationResult) > filterRank(w.Result.CalculationResult)
	case *model.OldFilterEvaluationResult:
		w, _ := want.(*model.OldFilterEvaluationResult)
		return w != nil && filterRank(a.CalculationResult) > filterRank(w.CalculationResult)
	case *model.FilterResponse:
		w, _ := want.(*model.FilterResponse)
		return w != nil && filterRank(a.CalculationResult) > filterRank(w.CalculationResult)
	}
	return false
}

func filterRank(result string) int {
	switch result {
	case "USE_FILTER_CONDITION":
		return 1
	case "ALLOW":
		return 2
	}
	return 0
}

func subset(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			return false
		}
	}
	return true
}

func opsSubset(a, b map[string][]string) bool {
	for op, ids := range a {
		if !subset(ids, b[op]) {
			return false
		}
	}
	return true
}

// exportRunProblem returns why a run of the profile established nothing, or ""
// when at least one golden was compared: a selector that matched no function
// of the bundle, or a stand that skipped every golden.
func exportRunProblem(results []exportResult) string {
	for _, res := range results {
		if res.Verdict != verdictSkipped {
			return ""
		}
	}
	return fmt.Sprintf("%d goldens selected, none compared: PARITY_EXPORT_RUN matched no function of the bundle, or "+
		"the stand skipped every golden", len(results))
}

// checkKnownUser mints the token of a user the parity realm always seeds, so
// that a wrong end-user password or client secret fails the run instead of
// skipping every end-user golden as a user the stand lacks.
func checkKnownUser(lt *labelTokens) error {
	label := realmOf(lt.cfg.IDPBaseURL) + "/user:" + UserProfileReader.Username() + "@" + lt.cfg.EndUserClientID
	if _, err := lt.token(label); err != nil {
		return fmt.Errorf("the parity realm refuses a token for %s: %w", UserProfileReader.Username(), err)
	}
	return nil
}

// readGoldenTarget reads the golden at path under dir into the target of row id.
func readGoldenTarget(dir string, id ParityEndpointID, path string) (any, error) {
	raw, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		return nil, err
	}
	target := NewGoldenTarget(id)
	if err := json.Unmarshal(raw, target); err != nil {
		return nil, fmt.Errorf("decode golden %s: %w", path, err)
	}
	return target, nil
}

// exportReport counts the verdicts per family and lists the differences,
// those of classes tenant and conversion first: the bundle's wrong allows are
// of these two classes.
func exportReport(results []exportResult) string {
	type key struct{ family, verdict string }
	counts := map[key]int{}
	families := map[string]bool{}
	var differs []exportResult
	for _, r := range results {
		fams := r.Families
		if len(fams) == 0 {
			fams = []string{"none"}
		}
		for _, f := range fams {
			counts[key{f, string(r.Verdict)}]++
			families[f] = true
		}
		if r.Verdict == verdictDiffers {
			differs = append(differs, r)
		}
	}
	names := make([]string, 0, len(families))
	for f := range families {
		names = append(names, f)
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "export-fed agent: %d goldens\n", len(results))
	for _, f := range names {
		fmt.Fprintf(&b, "  family %-14s match %d, accepted %d, differs %d, skipped %d\n", f,
			counts[key{f, string(verdictMatch)}], counts[key{f, string(verdictAccepted)}],
			counts[key{f, string(verdictDiffers)}], counts[key{f, string(verdictSkipped)}])
	}
	first := func(c string) bool { return c == "tenant" || c == "conversion" }
	sort.SliceStable(differs, func(i, j int) bool { return first(differs[i].Class) && !first(differs[j].Class) })
	for _, r := range differs {
		fmt.Fprintf(&b, "DIFFERS %s (%s, class %s, export %s)\n", r.Path, r.Test, r.Class, r.Status)
	}
	return b.String()
}

// pinResponses pins path to answer with responses in turn, as
// [PipController.PinRoute] pins one response, so that ResetPinnedRoutes
// resets it.
func pinResponses(ctx context.Context, pc *PipController, path string, responses []PipStubResponse) error {
	if err := pc.configure(ctx, []pipStubRoute{{Path: path, Responses: responses}}); err != nil {
		return err
	}
	pc.mu.Lock()
	pc.pinnedPaths[path] = struct{}{}
	pc.mu.Unlock()
	return nil
}

// stubFor maps the URL a dumped log names a stub by to the controller of that
// stub on this stand: the entitlements stub, else the PIP stub.
func stubFor(pip, ea *PipController) func(string) *PipController {
	return func(mock string) *PipController {
		if u, err := url.Parse(mock); err == nil && (u.Port() == "28192" || strings.Contains(u.Host, "entitlements")) {
			return ea
		}
		return pip
	}
}
