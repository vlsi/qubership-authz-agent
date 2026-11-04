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
	"strconv"
	"strings"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/components/authz-agent/internal/snapshot"
	"authz-agent/internal/regobuiltins"
)

// config is what the service needs to start. Every value comes from the
// environment through configloader: AUTHZ_HTTP_ADDR is `authz.http.addr`,
// and so on.
type config struct {
	// Addr is the listen address of the internal surface: the probes, the
	// metrics, and /api-version.
	Addr string
	// PublicAddr is the listen address of the surface the clients call.
	PublicAddr string
	// DecisionLogs configures the delivery: an empty URL disables the
	// upload, and DecisionLogFile stores the decisions instead.
	DecisionLogs decisionlog.Config
	// DecisionLogFile stores the decisions in the service instead of
	// uploading them; empty uploads.
	DecisionLogFile string
	// NDBuiltinCache records the non-deterministic builtin calls of a
	// decision, the PIP requests and their responses, into its event, as
	// OPA's nd_builtin_cache does.
	NDBuiltinCache bool
	// Authn configures the trusted providers; an empty File disables them.
	Authn authn.Config
	// Pull configures the policy pull; [pull.Config] says what disables it.
	Pull pull.Config
	// M2M configures the agent's own token; empty TokenURL and TokenFile
	// disable it.
	M2M m2m.Config
	// DefaultTenant is the display name of the tenant a check request is
	// decided in when it names none; tenant-manager resolves it to the
	// tenant's ID.
	DefaultTenant string
	// PIPTimeout bounds one call of a PIP the generated policies make.
	PIPTimeout time.Duration
	// PIPCacheTTL is how long the answer of a cacheable PIP is reused
	// across decision requests; zero turns the cache off.
	PIPCacheTTL time.Duration
}

// lookup reads one configuration key; configloader in main, a map in tests.
type lookup func(key, fallback string) string

// loadConfig builds the configuration from the environment.
func loadConfig(get lookup) config {
	return config{
		NDBuiltinCache: boolean(get, "authz.nd.builtin.cache", true),
		Addr:           get("authz.http.addr", "0.0.0.0:8181"),
		PublicAddr:     get("authz.public.addr", "0.0.0.0:8080"),
		DecisionLogs: decisionlog.Config{
			URL:     get("authz.decision.log.url", ""),
			Headers: splitList(get("authz.decision.log.headers", "")),
			Labels:  map[string]string{"id": "authz-agent"},
		},
		DecisionLogFile: get("authz.decision.log.file", ""),
		Authn: authn.Config{
			File:             get("authz.trusted.providers.file", authn.DefaultFile),
			Required:         boolean(get, "authz.jwks.bootstrap.required", true),
			HTTPTimeout:      seconds(get, "authz.jwks.http.timeout", authn.DefaultHTTPTimeout),
			HTTPRetries:      integer(get, "authz.jwks.http.retries", authn.DefaultHTTPRetries),
			TenantManagerURL: get("authz.tenant.manager.url", "http://tenant-manager:8080"),
			ReloadInterval:   seconds(get, "authz.trusted.providers.reload.interval", authn.DefaultReloadInterval),
		},
		Pull: pull.Config{
			SourceURL:   strings.TrimRight(get("authz.pap.client.source.url", ""), "/"),
			Interval:    seconds(get, "authz.pap.client.pull.interval", pull.DefaultInterval),
			HTTPTimeout: pull.DefaultHTTPTimeout,
		},
		M2M: m2m.Config{
			TokenURL:         get("authz.m2m.token.url", ""),
			ClientIDFile:     get("authz.m2m.client.id.file", m2m.DefaultClientIDFile),
			ClientSecretFile: get("authz.m2m.client.secret.file", m2m.DefaultClientSecretFile),
			RenewBefore:      seconds(get, "authz.m2m.renew.before.seconds", m2m.DefaultRenewBefore),
			TokenFile:        get("authz.pap.client.token.file", m2m.DefaultTokenFile),
			WatchInterval:    m2m.DefaultWatchInterval,
		},
		DefaultTenant: strings.TrimSpace(get("authz.default.tenant", "default")),
		PIPTimeout:    seconds(get, "authz.pip.timeout", regobuiltins.DefaultTimeout),
		PIPCacheTTL:   seconds(get, "authz.pip.cache.ttl", snapshot.DefaultCacheTTL),
	}
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// seconds reads a whole number of seconds; a value that is not one keeps
// the fallback, and 0 is kept as 0 for the keys where it means off.
func seconds(get lookup, key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(get(key, ""))
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return fallback
	}
	return time.Duration(n) * time.Second
}

// integer reads a positive integer; anything else keeps the fallback.
func integer(get lookup, key string, fallback int) int {
	raw := strings.TrimSpace(get(key, ""))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// boolean reads true/false in the spellings the pap-client accepted;
// anything else keeps the fallback.
func boolean(get lookup, key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(get(key, ""))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}
