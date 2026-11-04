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
	"testing"
	"time"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
	"authz-agent/internal/regobuiltins"
)

func fromMap(values map[string]string) lookup {
	return func(key, fallback string) string {
		if v, ok := values[key]; ok {
			return v
		}
		return fallback
	}
}

// TestLoadConfig_EnvironmentOnly: the settings come from the environment
// keys, with the service defaults behind them.
func TestLoadConfig_EnvironmentOnly(t *testing.T) {
	cfg := loadConfig(fromMap(map[string]string{}))
	if cfg.Addr != "0.0.0.0:8181" || cfg.PublicAddr != "0.0.0.0:8080" {
		t.Fatalf("default addresses: %+v", cfg)
	}
	if cfg.DecisionLogs.URL != "" {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg = loadConfig(fromMap(map[string]string{
		"authz.http.addr":            ":9090",
		"authz.public.addr":          ":9091",
		"authz.decision.log.url":     "http://collector:8183",
		"authz.decision.log.headers": "x-request-id,x-authz-original-path",
	}))
	if cfg.Addr != ":9090" || cfg.PublicAddr != ":9091" {
		t.Fatalf("addresses from env: %+v", cfg)
	}
	if cfg.DecisionLogs.URL != "http://collector:8183" || len(cfg.DecisionLogs.Headers) != 2 || cfg.DecisionLogs.Labels["id"] != "authz-agent" {
		t.Fatalf("decision logs from env: %+v", cfg.DecisionLogs)
	}
}

// TestLoadConfig_LoopsOnTheServicesOwn: on its own the service runs every
// loop from its default place, and each key of the loops is read with the
// spellings the pap-client accepted.
func TestLoadConfig_LoopsOnTheServicesOwn(t *testing.T) {
	cfg := loadConfig(fromMap(map[string]string{}))
	wantAuthn := authn.Config{File: "/etc/authz/trusted-providers.json", Required: true, HTTPTimeout: 5 * time.Second, HTTPRetries: 3,
		TenantManagerURL: "http://tenant-manager:8080", ReloadInterval: 30 * time.Second}
	if cfg.Authn != wantAuthn {
		t.Errorf("default trusted providers = %+v, want %+v", cfg.Authn, wantAuthn)
	}
	wantPull := pull.Config{Interval: 30 * time.Second, HTTPTimeout: 30 * time.Second}
	if cfg.Pull != wantPull {
		t.Errorf("default pull = %+v, want %+v", cfg.Pull, wantPull)
	}
	wantM2M := m2m.Config{ClientIDFile: "/etc/secret/username", ClientSecretFile: "/etc/secret/password", RenewBefore: 60 * time.Second,
		TokenFile: "/var/run/secrets/tokens/netcracker/token", WatchInterval: 15 * time.Second}
	if cfg.M2M != wantM2M {
		t.Errorf("default m2m = %+v, want %+v", cfg.M2M, wantM2M)
	}
	if cfg.DecisionLogFile != "" {
		t.Errorf("default decision log file %q, want none", cfg.DecisionLogFile)
	}
	cfg = loadConfig(fromMap(map[string]string{
		"authz.trusted.providers.file":            "/p.json",
		"authz.jwks.bootstrap.required":           "off",
		"authz.jwks.http.timeout":                 "2",
		"authz.jwks.http.retries":                 "20",
		"authz.trusted.providers.reload.interval": "0",
		"authz.tenant.manager.url":                "",
		"authz.pap.client.source.url":             "http://policy-admin:18090/",
		"authz.pap.client.pull.interval":          "2",
		"authz.pap.client.token.file":             "/t",
		"authz.m2m.token.url":                     "http://idp/token",
		"authz.m2m.client.id.file":                "/id",
		"authz.m2m.client.secret.file":            "/secret",
		"authz.m2m.renew.before.seconds":          "30",
		"authz.decision.log.file":                 "/var/log/authz/decision-logs.jsonl",
	}))
	if cfg.Authn.File != "/p.json" || cfg.Authn.Required || cfg.Authn.HTTPTimeout != 2*time.Second || cfg.Authn.HTTPRetries != 20 ||
		cfg.Authn.ReloadInterval != 0 || cfg.Authn.TenantManagerURL != "" {
		t.Errorf("trusted providers from env = %+v", cfg.Authn)
	}
	if cfg.Pull.SourceURL != "http://policy-admin:18090" || cfg.Pull.Interval != 2*time.Second {
		t.Errorf("pull from env = %+v", cfg.Pull)
	}
	if cfg.M2M.TokenURL != "http://idp/token" || cfg.M2M.ClientIDFile != "/id" || cfg.M2M.ClientSecretFile != "/secret" ||
		cfg.M2M.RenewBefore != 30*time.Second || cfg.M2M.TokenFile != "/t" {
		t.Errorf("m2m from env = %+v", cfg.M2M)
	}
	if cfg.DecisionLogFile != "/var/log/authz/decision-logs.jsonl" {
		t.Errorf("decision log file %q from env", cfg.DecisionLogFile)
	}
}

// TestLoadConfig_MalformedNumbersKeepTheDefaults: a duration, a count, or
// a flag that does not parse keeps its default rather than switching a
// loop off.
func TestLoadConfig_MalformedNumbersKeepTheDefaults(t *testing.T) {
	cfg := loadConfig(fromMap(map[string]string{
		"authz.jwks.http.timeout":        "soon",
		"authz.jwks.http.retries":        "0",
		"authz.jwks.bootstrap.required":  "maybe",
		"authz.pap.client.pull.interval": "-1",
	}))
	if cfg.Authn.HTTPTimeout != authn.DefaultHTTPTimeout || cfg.Authn.HTTPRetries != authn.DefaultHTTPRetries || !cfg.Authn.Required || cfg.Pull.Interval != pull.DefaultInterval {
		t.Errorf("malformed values: %+v %+v, want the defaults", cfg.Authn, cfg.Pull)
	}
}

// TestLoadConfig_NDBuiltinCache: the builtin calls are recorded unless the
// environment turns the cache off, since a decision log without them cannot
// say which PIP answers the decision rests on.
func TestLoadConfig_NDBuiltinCache(t *testing.T) {
	if cfg := loadConfig(fromMap(nil)); !cfg.NDBuiltinCache {
		t.Error("the builtin calls must be recorded by default")
	}
	if cfg := loadConfig(fromMap(map[string]string{"authz.nd.builtin.cache": "false"})); cfg.NDBuiltinCache {
		t.Error("authz.nd.builtin.cache=false must stop the recording")
	}
}

// TestLoadConfig_DecisionPath: the default tenant, the timeout of a PIP
// call, and the entitlements service, each by default and from the
// environment.
func TestLoadConfig_DecisionPath(t *testing.T) {
	cfg := loadConfig(fromMap(map[string]string{}))
	if cfg.DefaultTenant != "default" || cfg.PIPTimeout != regobuiltins.DefaultTimeout || cfg.EntitlementsURL != "" {
		t.Errorf("defaults: tenant %q, timeout %v, entitlements %q; want default, %v, none",
			cfg.DefaultTenant, cfg.PIPTimeout, cfg.EntitlementsURL, regobuiltins.DefaultTimeout)
	}
	cfg = loadConfig(fromMap(map[string]string{
		"authz.default.tenant":   " acme ",
		"authz.pip.timeout":      "5",
		"authz.entitlements.url": " http://ent:8080 ",
	}))
	if cfg.DefaultTenant != "acme" || cfg.PIPTimeout != 5*time.Second || cfg.EntitlementsURL != "http://ent:8080" {
		t.Errorf("from env: tenant %q, timeout %v, entitlements %q; want acme, 5s, http://ent:8080",
			cfg.DefaultTenant, cfg.PIPTimeout, cfg.EntitlementsURL)
	}
}
