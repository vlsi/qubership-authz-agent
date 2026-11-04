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

// Package server registers the HTTP routes of the agent on Fiber apps: the
// public surface the clients call, which [Server.RegisterPublic] adds, and
// the internal surface the probes read, which [Register] adds.
package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/snapshot"
)

// LegacyAPIVersion is the body of GET /api-version: the specification
// versions the legacy service announces, kept byte for byte.
const LegacyAPIVersion = `{"specs":[{"specRootUrl":"/access","major":3,"minor":0,"supportedMajors":[1,2,3]},{"specRootUrl":"/api","major":1,"minor":1,"supportedMajors":[1]},{"specRootUrl":"/template","major":1,"minor":0,"supportedMajors":[1]},{"specRootUrl":"/preview","major":2,"minor":0,"supportedMajors":[1,2]}]}`

// Logger receives what the request path has to report. Every method takes
// the request's context, which carries the id the platform log format prints
// as request_id, so a line here can be matched with the caller's own line for
// the same request.
//
// The decision itself is not written here: its input carries the caller's
// token and claims, and the decision log is the surface that records those,
// under the collector's own retention.
type Logger interface {
	DebugC(ctx context.Context, format string, args ...any)
	WarnC(ctx context.Context, format string, args ...any)
	ErrorC(ctx context.Context, format string, args ...any)
}

// discardLogger is the logger a caller that passes none gets.
type discardLogger struct{}

func (discardLogger) DebugC(context.Context, string, ...any) {
	// Deliberately empty: a caller that passes no logger wants no line.
}
func (discardLogger) WarnC(context.Context, string, ...any) {
	// Deliberately empty: a caller that passes no logger wants no line.
}
func (discardLogger) ErrorC(context.Context, string, ...any) {
	// Deliberately empty: a caller that passes no logger wants no line.
}

// Options tune the routes.
type Options struct {
	// Health reports the state of the loops the service runs; nil means
	// the service is healthy and ready as long as it answers.
	Health func() Report
	// Log receives the diagnostics of the request path; nil discards them.
	Log Logger
	// CollectorURL is the base URL of the decision-log collector the
	// decisions are uploaded to, which serves the download of the ones it
	// received; the public surface relays GET /internal/v1/decision-logs to
	// it unless the decisions are stored in the service. Empty, with no
	// store, leaves the download unregistered.
	CollectorURL string
	// Snapshots answers check/resource and its bulk routes with the
	// generated policies of the request's tenant; nil answers them, like
	// check/filter, with the embedded policies.
	Snapshots *snapshot.Registry
	// DefaultTenant is the tenant of a request that names none by the
	// query parameter tenant_id or the header Tenant.
	DefaultTenant func() string
}

// Server owns the handlers.
type Server struct {
	engine *engine.Engine
	logs   *decisionlog.Logger
	opts   Options
}

// Register adds the routes of the internal surface to app: /health,
// /ready, and /api-version.
func Register(app *fiber.App, eng *engine.Engine, logs *decisionlog.Logger, opts Options) *Server {
	if opts.Log == nil {
		opts.Log = discardLogger{}
	}
	s := &Server{engine: eng, logs: logs, opts: opts}
	app.Get("/health", s.health)
	app.Get("/ready", s.ready)
	app.Get("/api-version", apiVersion)
	return s
}

// Report is the state of the service as its loops see it. Healthy is the
// liveness verdict, which the trusted providers decide; Loaded is the
// readiness one, set once the policies have loaded and never cleared.
type Report struct {
	Healthy bool
	// Message names the reason when the service is unhealthy or not ready.
	Message string
	// ConfigError is the trusted providers file's error, when that is the
	// reason.
	ConfigError string
	// Bootstrap carries the counts when a bootstrap threshold is not met or
	// a required provider is missing.
	Bootstrap *authn.Details
	Loaded    bool
	// Snapshots is the state of every tenant's generated policies, nil
	// without a registry.
	Snapshots *snapshot.Health
}

// HealthResponse is the body of a healthy GET /health.
type HealthResponse struct {
	Status    string           `json:"status"`
	Snapshots *snapshot.Health `json:"snapshots,omitempty"`
}

// HealthErrorResponse is the body of a 503 GET /health or GET /ready.
type HealthErrorResponse struct {
	Message string              `json:"message"`
	Details *HealthErrorDetails `json:"details,omitempty"`
}

// HealthErrorDetails carries the diagnostics of an unhealthy verdict.
// OPAReady is always true: the service holds the engine, so there is no
// separate engine to wait for. The field stays because the body's shape is
// what the platform's probes and dashboards already read.
type HealthErrorDetails struct {
	OPAReady    *bool            `json:"opaReady,omitempty"`
	ConfigError string           `json:"configError,omitempty"`
	Bootstrap   *authn.Details   `json:"bootstrap,omitempty"`
	Snapshots   *snapshot.Health `json:"snapshots,omitempty"`
}

// health answers 200 with the state of every
// tenant's generated policies when healthy, 503 with the reason and its
// details otherwise. A tenant whose candidate was refused leaves the
// service healthy: the tenant names the refusal, and the other tenants
// are served. The policies' first load is not part of it, so a liveness
// probe does not restart a service that is still waiting for its source;
// /ready carries that.
func (s *Server) health(c *fiber.Ctx) error {
	if s.opts.Health == nil {
		return c.JSON(HealthResponse{Status: "healthy"})
	}
	report := s.opts.Health()
	if report.Healthy {
		return c.JSON(HealthResponse{Status: "healthy", Snapshots: report.Snapshots})
	}
	return unavailable(c, report)
}

// ready is the readiness answer: 200 {"status":"ready"} once the service
// is healthy and the policies have loaded, 503 with the reason otherwise.
func (s *Server) ready(c *fiber.Ctx) error {
	if s.opts.Health == nil {
		return c.JSON(fiber.Map{"status": "ready"})
	}
	report := s.opts.Health()
	if !report.Healthy {
		return unavailable(c, report)
	}
	if !report.Loaded {
		report.Message = "policies not loaded yet"
		return unavailable(c, report)
	}
	return c.JSON(fiber.Map{"status": "ready"})
}

// unavailable writes the 503 body of /health and /ready.
func unavailable(c *fiber.Ctx, report Report) error {
	ready := true
	return c.Status(http.StatusServiceUnavailable).JSON(HealthErrorResponse{
		Message: report.Message,
		Details: &HealthErrorDetails{
			OPAReady:    &ready,
			ConfigError: report.ConfigError,
			Bootstrap:   report.Bootstrap,
			Snapshots:   report.Snapshots,
		},
	})
}

func apiVersion(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.SendString(LegacyAPIVersion)
}

// opaError writes an error body in the shape of OPA's REST API.
func opaError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"code": code, "message": message})
}

func (s *Server) logDecision(c *fiber.Ctx, id string, segments []string, input, result any, ok bool) {
	ev := decisionlog.Event{
		DecisionID:  id,
		Path:        strings.Join(segments, "/"),
		RequestedBy: strings.Clone(c.IP()),
	}
	if input != nil {
		ev.Input = input
	}
	if ok {
		ev.Result = result
	}
	if names := s.logs.Headers(); len(names) > 0 {
		ev.RequestContext = &decisionlog.RequestContext{HTTP: &decisionlog.HTTPRequestContext{Headers: recordedHeaders(c, names)}}
	}
	s.logs.Log(ev)
}

// recordedHeaders copies the values of the named request headers, keyed by
// the configured lowercase names, out of the request buffer.
func recordedHeaders(c *fiber.Ctx, names []string) map[string][]string {
	headers := map[string][]string{}
	all := c.GetReqHeaders()
	for _, name := range names {
		for k, values := range all {
			if !strings.EqualFold(k, name) {
				continue
			}
			copied := make([]string, len(values))
			for i, v := range values {
				copied[i] = strings.Clone(v)
			}
			headers[name] = copied
		}
	}
	return headers
}
