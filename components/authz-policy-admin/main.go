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

// Command authz-policy-admin is a stand-in for the access-control v3 config API
// (GET /access/v3/config/policySets and GET /access/v3/config/pips).
//
// It accepts simplified policies and PIPs on access-control's own upload paths
// and serves them back in v3 export shape — the same shape the real access-control serves
// and the PolicyPuller pulls. This means the converter under test is the real
// production one, not a shortcut.
//
// It has two consumers:
//
//   - the automated test suites: testify and parity run it on kind, SVT in
//     Docker Compose, and all three seed it over the same upload paths;
//   - its own Helm chart, helm-templates/authz-policy-admin, installed beside
//     the agent's, which lets a team with no access-control installation load
//     policies into authz-agent through the same pull path production uses
//     (authz-agent-ADR-0073).
//
// The simplified-policy API — access-control's own paths, prefix included, so a
// caller that loaded policies into access-control keeps working unchanged:
//
//	GET  /access/v1/simplifiedPolicies/domainPolicies/{domainName}
//	PUT  /access/v1/simplifiedPolicies/domainPolicies/{domainName}  — replace a domain
//	GET  /access/v1/simplifiedPolicies/domainPIPs/{domainName}
//	PUT  /access/v1/simplifiedPolicies/domainPIPs/{domainName}      — replace a domain
//
// access-control also serves POST / PATCH / DELETE on the PIP path; this stub
// answers 405 there rather than pretending. Nothing is authenticated, which is
// exactly why the stub is limited to development and test namespaces (ADR-0073).
//
// The v3 API surface (pap-client puller → stub) serves the union of all
// domains:
//
//	GET  /access/v3/config/policySets   — v3 policy-set export envelope
//	GET  /access/v3/config/pips         — v3 PIP export envelope
//
// One stub-specific route remains, for the container health probe:
//
//	GET  /authz-policy-admin/hash       — current hashes, revision and known domains
//
// Hash semantics: each collection's hash is a content hash (see store.go), so
// the puller re-fetches when the data actually changed and a restart that
// reloads the same data keeps serving the same hash.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

// logSink is the part of the platform logger this command writes through.
// The narrow type is what lets a test record what a run reported.
type logSink interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// logger is shared by every file of the command.
var logger logSink

func init() {
	// The environment is the only property source, as in authz-agent: the
	// image ships no application.yaml, and the chart configures the stub
	// through AUTHZ_POLICY_ADMIN_* variables and LOGGING_LEVEL_ROOT.
	configloader.Init(configloader.EnvPropertySource())
	logger = logging.GetLogger("authz-policy-admin")
}

func main() {
	// AUTHZ_POLICY_ADMIN_DATA_DIR is empty by default: the test stacks run the stub
	// in-memory, and an unset value keeps `docker run` of this image working
	// without a mounted volume. The Helm chart always sets it to the PVC
	// mount path.
	mux, addr, err := build(os.Getenv("AUTHZ_POLICY_ADMIN_DATA_DIR"), envOr("AUTHZ_POLICY_ADMIN_PORT", "18090"),
		envOr("AUTHZ_POLICY_ADMIN_DEFAULT_TENANT_ID", defaultTenant))
	if err != nil {
		logger.Errorf("%v", err)
		os.Exit(1)
	}
	logger.Infof("authz-policy-admin listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Errorf("listening on %s: %v", addr, err)
		os.Exit(1)
	}
}

// build opens the store under dataDir, assembles the routes over it, and
// returns them with the address port makes. The export gives the default
// tenant the tenantId defaultTenantID. An empty dataDir keeps the
// policies in memory, which the run reports, as it reports that the upload
// API is open to whoever can reach it.
func build(dataDir, port, defaultTenantID string) (*http.ServeMux, string, error) {
	st, err := newStore(dataDir)
	if err != nil {
		return nil, "", fmt.Errorf("store: %w", err)
	}
	if dataDir == "" {
		logger.Warnf("persistence disabled: AUTHZ_POLICY_ADMIN_DATA_DIR not set, policies live in memory only and are lost on restart")
	} else {
		logger.Infof("persisting policies and PIPs under %s", dataDir)
	}
	// Stated on every start, because whoever reads these logs should know it:
	// the upload API accepts policies from anyone who can reach it.
	logger.Warnf("the simplified-policy API is unauthenticated — deploy this only in development and test namespaces")
	if ds := st.Domains(); len(ds) > 0 {
		logger.Infof("domains with content: %v", ds)
	}

	mux := http.NewServeMux()
	(&server{st: st, defaultTenantID: defaultTenantID}).routes(mux)
	return mux, "0.0.0.0:" + port, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
