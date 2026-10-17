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

// Package note — pip_control.go wraps the real pipstub control surface at
// test/integration/pipstub/main.go:50-183. Three caveats surfaced during
// the initial analysis; this file encodes them deliberately so test authors
// do not rediscover them:
//
//  1. Control path is PUT|POST /pip-stub/configure (pipstub/main.go:52),
//     NOT /__mock__/responses. Body is a JSON array of pipRoute objects.
//  2. GET /pip-stub/reset (pipstub/main.go:51) clears `calls` and
//     `counters` only — route registrations persist across resets
//     (pipstub/main.go:152-160). The only way to "unregister" a route is
//     to re-PUT the same path with a fresh response set; the helper tracks
//     every pinned path in an internal map so ResetPinnedRoutes() can
//     flush them to a known-safe 404 fallback between tests.
//  3. Path matching is strictly literal against r.URL.Path
//     (pipstub/main.go:110). No wildcards / regex / templates. The
//     PinEntitlementsV3ForUser helper resolves the per-user literal path
//     once per pin call — see OQ-SUITE-11 option 1.
//
// The same control surface is reused for the entitlements-mock service
// added by D-U. Two PipController instances are therefore
// instantiated at SetupSuite time: one bound to Config.PipMockControlURL
// for pip-mock, one bound to Config.EAMockControlURL for entitlements-mock.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// PipStubResponse mirrors pipstub's pipResponse struct verbatim.
// pipstub accepts body as an arbitrary JSON value (Go any), so every scalar /
// array / object / null shape a test needs is representable without touching
// bodyRaw. bodyRaw is kept here as an optional escape hatch for shapes Go
// cannot marshal cleanly.
type PipStubResponse struct {
	StatusCode int    `json:"statusCode"`
	Body       any    `json:"body,omitempty"`
	BodyRaw    string `json:"bodyRaw,omitempty"`
}

// pipStubRoute mirrors pipstub's pipRoute struct.
type pipStubRoute struct {
	Path      string            `json:"path"`
	Responses []PipStubResponse `json:"responses"`
}

// PipStubCall mirrors pipstub's callRecord JSON payload from GET
// /pip-stub/calls. The stub now also captures query + body (ADR-0066 request
// args); those fields are added here as needed by assertion code. Note: header
// NAMES in Headers are lowercased by the stub (flattenHeaders, pipstub/main.go)
// for case-insensitive matching — look them up in lowercase (e.g.
// `call.Headers["x-request-id"]`, not `"X-Request-Id"`).
type PipStubCall struct {
	Path    string              `json:"path"`
	Method  string              `json:"method"`
	Query   map[string][]string `json:"query,omitempty"`
	Headers map[string]string   `json:"headers,omitempty"`
	BodyRaw string              `json:"bodyRaw,omitempty"`
	Body    any                 `json:"body,omitempty"`
}

// PipController wraps the /pip-stub/configure + /pip-stub/reset control
// surface of one pipstub instance (either pip-mock or entitlements-mock).
type PipController struct {
	baseURL string
	client  *http.Client

	mu          sync.Mutex
	pinnedPaths map[string]struct{}
}

// NewPipController builds a controller bound to the given base URL. The
// URL is treated as the pipstub service's host-published endpoint (e.g.
// http://localhost:28091).
func NewPipController(baseURL string) *PipController {
	return &PipController{
		baseURL:     strings.TrimRight(baseURL, "/"),
		client:      &http.Client{Timeout: defaultHTTPClient.Timeout},
		pinnedPaths: make(map[string]struct{}),
	}
}

// PinRoute pins a single literal path to return the given status/body. If
// the path was already pinned in this suite run, the previous response list
// is overwritten (pipstub map-upsert semantics, pipstub/main.go:175-179).
func (pc *PipController) PinRoute(ctx context.Context, path string, resp PipStubResponse) error {
	if path == "" {
		return fmt.Errorf("paritysuite: PinRoute requires non-empty path")
	}
	payload := []pipStubRoute{{Path: path, Responses: []PipStubResponse{resp}}}
	if err := pc.configure(ctx, payload); err != nil {
		return err
	}
	pc.mu.Lock()
	pc.pinnedPaths[path] = struct{}{}
	pc.mu.Unlock()
	return nil
}

// PinEntitlementsV3ForUser resolves the V3 per-user EA path template once
// against the literal user id and pins it via PinRoute. Per OQ-SUITE-11
// option 1 this is how the ENT block works around pipstub's lack of
// path templating.
func (pc *PipController) PinEntitlementsV3ForUser(ctx context.Context, userID string, resp PipStubResponse) error {
	if userID == "" {
		return fmt.Errorf("paritysuite: PinEntitlementsV3ForUser requires non-empty userID")
	}
	path := fmt.Sprintf("/api/v3/user-entitlements/user/%s", userID)
	return pc.PinRoute(ctx, path, resp)
}

// PinEntitlementsV3PerDefinition pins the per-(resourceType,name) lookup path
// legacy AC calls when the EA cache has a definition hit but no resource-id
// entry.
func (pc *PipController) PinEntitlementsV3PerDefinition(ctx context.Context, userID, resourceType, name string, resp PipStubResponse) error {
	if userID == "" || resourceType == "" || name == "" {
		return fmt.Errorf("paritysuite: PinEntitlementsV3PerDefinition requires all of userID/resourceType/name")
	}
	path := fmt.Sprintf("/api/v3/user-entitlements/user/%s/resource-type/%s/name/%s", userID, resourceType, name)
	return pc.PinRoute(ctx, path, resp)
}

// ResetCalls clears pipstub's observed-call list + counters without
// unregistering routes. Matches GET /pip-stub/reset verbatim.
func (pc *PipController) ResetCalls(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pc.baseURL+"/pip-stub/reset", nil)
	if err != nil {
		return err
	}
	resp, err := pc.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pipstub reset failed: status=%d", resp.StatusCode)
	}
	return nil
}

// GetCalls returns pipstub's observed call log.
func (pc *PipController) GetCalls(ctx context.Context) ([]PipStubCall, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pc.baseURL+"/pip-stub/calls", nil)
	if err != nil {
		return nil, err
	}
	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pipstub calls failed: status=%d", resp.StatusCode)
	}
	var calls []PipStubCall
	if err := json.NewDecoder(resp.Body).Decode(&calls); err != nil {
		return nil, fmt.Errorf("decode pipstub calls: %w", err)
	}
	return calls, nil
}

// pinnedPathContains reports whether a path pinned since the last
// ResetPinnedRoutes contains part.
func (pc *PipController) pinnedPathContains(part string) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for path := range pc.pinnedPaths {
		if strings.Contains(path, part) {
			return true
		}
	}
	return false
}

// ResetPinnedRoutes re-issues /pip-stub/configure with a 404-fallback
// response for every path pinned in this suite run. Use in TearDownTest to
// ensure the next test's SetupTest starts from a known state even though
// pipstub's own reset does not unregister routes.
func (pc *PipController) ResetPinnedRoutes(ctx context.Context) error {
	pc.mu.Lock()
	paths := make([]string, 0, len(pc.pinnedPaths))
	for path := range pc.pinnedPaths {
		paths = append(paths, path)
	}
	pc.pinnedPaths = make(map[string]struct{})
	pc.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}
	payload := make([]pipStubRoute, 0, len(paths))
	for _, path := range paths {
		payload = append(payload, pipStubRoute{
			Path:      path,
			Responses: []PipStubResponse{{StatusCode: http.StatusNotFound, Body: map[string]string{"error": "reset"}}},
		})
	}
	return pc.configure(ctx, payload)
}

func (pc *PipController) configure(ctx context.Context, payload []pipStubRoute) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode pipstub configure payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, pc.baseURL+"/pip-stub/configure", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pc.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pipstub configure failed: status=%d", resp.StatusCode)
	}
	return nil
}
