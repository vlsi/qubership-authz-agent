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

// authz-agent is the authorization agent as one service: the HTTP surface
// the clients call, the embedded policy engine, and the loops that feed it
// with the trusted providers' keys, the policies and PIPs, and the agent's
// own token.
package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberserver "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2"
	"github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2/security"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	// memlimit sets the Go memory limit from the container's cgroup limit in
	// its init function; importing it is the whole configuration.
	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/components/authz-agent/internal/server"
	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/pips"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen"
	"authz-agent/policies"
)

var logger logging.Logger

func init() {
	// The environment is the only property source: the image ships no
	// application.yaml, and the chart configures the service through
	// AUTHZ_* variables.
	configloader.Init(configloader.EnvPropertySource())
	serviceloader.Register(1, &security.DummyFiberServerSecurityMiddleware{})
	logger = logging.GetLogger("authz-agent")
}

func main() {
	cfg := loadConfig(get)
	modules, err := policies.Modules()
	if err != nil {
		logger.Errorf("policies: %v", err)
		os.Exit(1)
	}
	eng, err := engine.New(engine.Options{Modules: modules})
	if err != nil {
		logger.Errorf("policy engine: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.DecisionLogFile != "" {
		cfg.DecisionLogs.Store = decisionlog.NewStore(cfg.DecisionLogFile)
	}
	logs := decisionlog.New(cfg.DecisionLogs, logger.Warnf)

	// The trusted providers' keys are fetched before the service listens:
	// a token cannot be verified without them, and the outcome, whatever
	// it is, goes into the health report.
	var providers *authn.Manager
	if cfg.Authn.File != "" {
		providers = authn.New(cfg.Authn, eng, logger)
		providers.Bootstrap(ctx)
	}
	var tokens *m2m.Source
	if cfg.M2M.TokenURL != "" || cfg.M2M.TokenFile != "" {
		tokens = m2m.New(cfg.M2M, eng, logger)
	}
	cfg.Pull.Entitlements = pips.LoadEntitlementsConfigFromEnv()
	var source pull.Tokens
	ownToken := func() (string, error) { return "", m2m.ErrNoToken }
	if tokens != nil {
		source = tokens
		ownToken = tokens.Bearer
	}
	table, err := regogen.DefaultTable()
	if err != nil {
		logger.Errorf("specification table: %v", err)
		os.Exit(1)
	}
	cacheTTL := cfg.PIPCacheTTL
	if cacheTTL == 0 {
		cacheTTL = -1
	}
	snapshots := snapshot.New(snapshot.Config{
		HTTP:     &regobuiltins.HTTP{Client: &http.Client{}, Token: ownToken, Timeout: cfg.PIPTimeout},
		CacheTTL: cacheTTL,
	}, table, logger)
	cfg.Pull.Snapshots = snapshots
	tenant := newDefaultTenant(cfg.DefaultTenant, cfg.Authn.TenantManagerURL)
	puller := pull.New(cfg.Pull, eng, source, logger)
	opts := server.Options{
		Log:            logger,
		CollectorURL:   cfg.DecisionLogs.URL,
		NDBuiltinCache: cfg.NDBuiltinCache,
		Health:         func() server.Report { return report(providers, puller, snapshots) },
		Snapshots:      snapshots,
		DefaultTenant:  tenant.Get,
	}

	// Immutable: strings handed out by the request context, such as a header
	// that goes into a decision log event, must not alias the buffer the
	// server reuses for the next request.
	internal, err := fiberserver.New(fiber.Config{
		Immutable:             true,
		BodyLimit:             32 << 20,
		DisableStartupMessage: true,
	}).WithPrometheus("/prometheus").Process()
	if err != nil {
		logger.Errorf("fiber: %v", err)
		os.Exit(1)
	}
	// The public routes match the way Envoy's path matches did: exact,
	// case-sensitive, and without a trailing slash.
	public, err := fiberserver.New(fiber.Config{
		Immutable:             true,
		BodyLimit:             32 << 20,
		StrictRouting:         true,
		CaseSensitive:         true,
		DisableStartupMessage: true,
	}).Process()
	if err != nil {
		logger.Errorf("fiber: %v", err)
		os.Exit(1)
	}
	srv := server.Register(internal, eng, logs, opts)
	srv.RegisterPublic(public)

	if tokens != nil {
		go tokens.Run(ctx)
	}
	if puller != nil {
		go puller.Run(ctx)
	}
	go tenant.Run(ctx, 30*time.Second)
	if providers != nil {
		go providers.Run(ctx)
	}
	if serve(ctx, stop, logs, cfg, len(modules), public, internal) {
		os.Exit(1)
	}
}

// serve binds the sockets of the public and the internal surface, logs the
// startup line with the number of policy modules, and runs both surfaces
// through [serveUntilShutdown]. It reports whether the service failed: a
// socket that could not be bound, or a surface that ended on its own.
//
// Both sockets are bound before either surface serves, so an address
// already in use fails the start rather than leaving one surface up; the
// public socket is closed again when the internal one cannot be bound.
func serve(ctx context.Context, stop func(), logs *decisionlog.Logger, cfg config, modules int, public, internal *fiber.App) bool {
	publicSocket, err := net.Listen("tcp", cfg.PublicAddr)
	if err != nil {
		logger.Errorf("public listener on %s: %v", cfg.PublicAddr, err)
		return true
	}
	internalSocket, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		_ = publicSocket.Close()
		logger.Errorf("internal listener on %s: %v", cfg.Addr, err)
		return true
	}
	logger.Infof("authz-agent: %d policy modules, decision logs to %q, public surface on %s, internal surface on %s",
		modules, decisionLogTarget(cfg), cfg.PublicAddr, cfg.Addr)
	return serveUntilShutdown(ctx, stop, logs, []surface{
		{"public", public, publicSocket},
		{"internal", internal, internalSocket},
	})
}

// surface is one of the service's two HTTP surfaces: the app, the socket it
// serves, and the name the logs call it.
type surface struct {
	name   string
	app    *fiber.App
	socket net.Listener
}

// serveUntilShutdown runs the decision-log loop and the surfaces until ctx
// ends, shuts the surfaces down, and drains the log queue. It reports
// whether a surface ended on its own, which is a failed start rather than a
// shutdown; stop ends ctx for the rest of the process when one does.
//
// The order the two halves end in is the point. Fiber's shutdown waits for
// the requests still in their handlers, and every one of those produces a
// decision, so the queue is read until the last handler has returned. A
// logger sharing ctx with the surfaces stops reading at the signal instead,
// and the decisions of a rolling restart are the ones an operator reading
// the log afterwards goes looking for.
func serveUntilShutdown(ctx context.Context, stop func(), logs *decisionlog.Logger, surfaces []surface) bool {
	logCtx, stopLogs := context.WithCancel(context.WithoutCancel(ctx))
	go logs.Run(logCtx)

	// A surface that ends on its own cancels the signal context, and the
	// caller then ends the other one and the loops; one that ends because
	// the shutdown closed its socket is not that failure.
	var failed atomic.Bool
	var servers sync.WaitGroup
	for _, s := range surfaces {
		servers.Add(1)
		go func() {
			defer servers.Done()
			if err := s.app.Listener(s.socket); err != nil && ctx.Err() == nil {
				logger.Errorf("%s server on %s: %v", s.name, s.socket.Addr(), err)
				failed.Store(true)
				stop()
			}
		}()
	}
	<-ctx.Done()
	for _, s := range surfaces {
		if err := s.app.ShutdownWithTimeout(5 * time.Second); err != nil {
			logger.Warnf("shutdown: %v", err)
		}
	}
	// The shutdown above does nothing for a server still on its way to
	// Serve, so the sockets are closed as well; one already closed by its
	// own shutdown returns the error this ignores.
	for _, s := range surfaces {
		_ = s.socket.Close()
	}
	servers.Wait()
	// Every handler has returned, so nothing can queue a decision now.
	stopLogs()
	logs.Wait()
	return failed.Load()
}

// get reads one key through configloader, except that an environment
// variable set to the empty string is returned as the empty string:
// configloader falls back to the default there, and the chart sets a URL to
// "" to switch it off.
func get(key, fallback string) string {
	if value, ok := os.LookupEnv(strings.ToUpper(strings.ReplaceAll(key, ".", "_"))); ok && value == "" {
		return ""
	}
	return configloader.GetOrDefaultString(key, fallback)
}

// report composes the state of the loops: the trusted providers' outcome
// under the bootstrap rules decides Healthy, and the policies' first load
// decides Loaded; the state of every tenant's snapshot goes along. providers
// may be nil; puller and snapshots may not.
func report(providers *authn.Manager, puller *pull.Puller, snapshots *snapshot.Registry) server.Report {
	r := server.Report{Healthy: true}
	if providers != nil {
		healthy, message, configError, details := authn.Evaluate(providers.Status())
		if !healthy {
			r.Healthy, r.Message, r.ConfigError, r.Bootstrap = false, message, configError, details
		}
	}
	status := puller.Status()
	r.Conversion = status.Conversion
	r.Loaded = status.PoliciesLoaded
	h := snapshots.Health()
	r.Snapshots = &h
	return r
}

func decisionLogTarget(cfg config) string {
	if cfg.DecisionLogFile != "" {
		return cfg.DecisionLogFile
	}
	return cfg.DecisionLogs.URL
}
