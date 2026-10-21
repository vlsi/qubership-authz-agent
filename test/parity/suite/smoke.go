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
	"fmt"
	"net/http"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// RunSmokePhase is the Go-owned replacement for the deleted smoke.sh
// pre-flight. It executes the profile-specific smoke checks sequentially and
// returns the first failure as a step-numbered error so SetupSuite can abort
// before any test method runs.
func RunSmokePhase(ctx context.Context, cfg Config, tokens *TokenFactory, pipMock *PipController) error {
	if isAuthzAgentProfile(cfg.Profile) {
		// ADR-0049 landed at the Envoy + Lua layer
		// (/api-version + Incoming-Token subject derivation + prohibited
		// HEADER PIP). A later ADR-0049 stage landed every deferred v1 / v2
		// compatibility endpoint as an Envoy + Lua transform, so step 8
		// (v2 check-resource) is graduated out of the skip list.
		// A final ADR-0049 stage landed the narrow `allowMissingAud` opt-in
		// canonical-path branch in identity.rego (plus the parity-agent
		// trusted-providers.json opt-in), so steps 5/6/7 — the
		// Incoming-Token parity assertions that previously failed at
		// subject-token verification — are graduated out of the skip
		// list too.
		//
		// The GENERAL-PIP parity assertions (steps 9 / 10 / 11) stay
		// skipped pending a separate investigation: the pip-stub route
		// pinning the suite uses against the authz-agent parity harness
		// is not plumbed through the dedicated `parity-authz-pip-mock`
		// network alias today, and the GENERAL-PIP HTTP probe from
		// pap-client hits a different control plane than smoke.go
		// pins. This is a pre-existing, deliberately kept skip.
		return runSmokePhase(ctx, cfg, tokens, pipMock, map[int]string{
			9:  "v1 GENERAL-PIP parity deferred",
			10: "v1 GENERAL-PIP observability deferred",
			11: "v1 GENERAL-PIP parity deferred",
		})
	}
	return runSmokePhase(ctx, cfg, tokens, pipMock, nil)
}

func runSmokePhase(ctx context.Context, cfg Config, tokens *TokenFactory, pipMock *PipController, skipped map[int]string) error {
	step := 0
	expectedAssertions := 12 - len(skipped)
	var skippedList []string

	if reason, ok := skipped[1]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 1 %s", reason))
	} else {
		apiStatus, apiVersion, err := HelperApiVersion(ctx, cfg)
		if err != nil {
			return smokeStepErr(1, "GET /api-version", err)
		}
		if apiStatus != http.StatusOK {
			return smokeStepErr(1, "GET /api-version", fmt.Errorf("status=%d", apiStatus))
		}
		if len(apiVersion.Specs) == 0 {
			return smokeStepErr(1, "GET /api-version", fmt.Errorf("empty specs array"))
		}
		step++
	}

	m2m, err := tokens.M2MToken()
	if err != nil || m2m == "" {
		if err == nil {
			err = fmt.Errorf("empty token")
		}
		return smokeStepErr(2, "mint M2M token", err)
	}
	step++

	endUser, err := tokens.EndUserToken(UserProfileReader)
	if err != nil || endUser == "" {
		if err == nil {
			err = fmt.Errorf("empty token")
		}
		return smokeStepErr(3, "mint reader token", err)
	}
	step++

	// Legacy AC caches GENERAL-PIP values sticky enough that reusing the
	// reader subject during smoke can leak the cached allow-list into the
	// reader-driven parity rows that run afterwards. Keep the smoke GENERAL-PIP
	// assertions on a different subject that still carries ROLE_PARITY_READER.
	generalPipUser, err := tokens.EndUserToken(UserProfileMultiRole)
	if err != nil || generalPipUser == "" {
		if err == nil {
			err = fmt.Errorf("empty token")
		}
		return smokeStepErr(9, "mint multi-role GENERAL-PIP token", err)
	}

	if err := pipMock.ResetCalls(ctx); err != nil {
		return smokeStepErr(4, "reset pip-mock calls", err)
	}
	step++

	nonAnon := TokenBundle{M2M: m2m, EndUser: endUser}
	generalPipBundle := TokenBundle{M2M: m2m, EndUser: generalPipUser}

	if reason, ok := skipped[5]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 5 %s", reason))
	} else {
		status, decision, _, err := HelperCheckResourceV1(
			ctx,
			cfg,
			model.CheckAccessRequest{
				Operation: "READ",
				Type:      "PARITY_CUSTOMER",
				Resource:  map[string]any{"id": "smoke-1"},
			},
			nonAnon,
			PerCallOptions{},
		)
		if err != nil {
			return smokeStepErr(5, "v1 check/resource allow", err)
		}
		if status != http.StatusOK || !decision {
			return smokeStepErr(5, "v1 check/resource allow", fmt.Errorf("status=%d decision=%v", status, decision))
		}
		step++
	}

	if reason, ok := skipped[6]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 6 %s", reason))
	} else {
		status, decision, _, err := HelperCheckResourceV1(
			ctx,
			cfg,
			model.CheckAccessRequest{
				Operation: "WRITE",
				Type:      "PARITY_CUSTOMER",
				Resource:  map[string]any{"id": "smoke-2"},
			},
			nonAnon,
			PerCallOptions{},
		)
		if err != nil {
			return smokeStepErr(6, "v1 check/resource deny", err)
		}
		if status != http.StatusOK || decision {
			return smokeStepErr(6, "v1 check/resource deny", fmt.Errorf("status=%d decision=%v", status, decision))
		}
		step++
	}

	if reason, ok := skipped[7]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 7 %s", reason))
	} else {
		filterStatus, filterResp, _, err := HelperFilterV1(ctx, cfg, "PARITY_ORDER", "LIST", nonAnon, PerCallOptions{})
		if err != nil {
			return smokeStepErr(7, "v1 check/filter", err)
		}
		if filterStatus != http.StatusOK || filterResp.CalculationResult == "" || filterResp.RsqlFilterCondition.String() == "" {
			return smokeStepErr(7, "v1 check/filter", fmt.Errorf("status=%d calculationResult=%q rsql=%q", filterStatus, filterResp.CalculationResult, filterResp.RsqlFilterCondition.String()))
		}
		step++
	}

	if reason, ok := skipped[8]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 8 %s", reason))
	} else {
		v2Status, v2Resp, _, err := HelperCheckResourceV2(
			ctx,
			cfg,
			model.CheckResourceRequest{
				Operation: "READ",
				Type:      "PARITY_CUSTOMER",
				Resource:  map[string]any{"id": "smoke-3"},
			},
			nonAnon,
			PerCallOptions{},
		)
		if err != nil {
			return smokeStepErr(8, "v2 check/resource", err)
		}
		if v2Status != http.StatusOK || !v2Resp.Decision {
			return smokeStepErr(8, "v2 check/resource", fmt.Errorf("status=%d decision=%v", v2Status, v2Resp.Decision))
		}
		step++
	}

	if reason, ok := skipped[9]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 9 %s", reason))
	} else {
		if err := pipMock.PinRoute(ctx, "/api/v1/pip/allowed", PipStubResponse{
			StatusCode: http.StatusOK,
			Body:       []string{"smoke-pip", "smoke-pip-2", "smoke-pip-3"},
		}); err != nil {
			return smokeStepErr(9, "pin GENERAL-PIP allow set", err)
		}
		status, decision, _, err := HelperCheckResourceV1(
			ctx,
			cfg,
			model.CheckAccessRequest{
				Operation: "EXECUTE",
				Type:      "PARITY_PAYMENT",
				Resource:  map[string]any{"id": "smoke-pip"},
			},
			generalPipBundle,
			PerCallOptions{},
		)
		if err != nil {
			return smokeStepErr(9, "v1 check/resource GENERAL-PIP allow", err)
		}
		if status != http.StatusOK || !decision {
			return smokeStepErr(9, "v1 check/resource GENERAL-PIP allow", fmt.Errorf("status=%d decision=%v", status, decision))
		}
		step++
	}

	if reason, ok := skipped[10]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 10 %s", reason))
	} else {
		calls, err := pipMock.GetCalls(ctx)
		if err != nil {
			return smokeStepErr(10, "read pip-mock calls", err)
		}
		if !containsCallPath(calls, "/api/v1/pip/allowed") {
			return smokeStepErr(10, "read pip-mock calls", fmt.Errorf("missing /api/v1/pip/allowed in %v", calls))
		}
		step++
	}

	if reason, ok := skipped[11]; ok {
		skippedList = append(skippedList, fmt.Sprintf("step 11 %s", reason))
	} else {
		if err := pipMock.PinRoute(ctx, "/api/v1/pip/allowed", PipStubResponse{
			StatusCode: http.StatusOK,
			Body:       []string{},
		}); err != nil {
			return smokeStepErr(11, "re-pin GENERAL-PIP deny set", err)
		}
		status, decision, _, err := HelperCheckResourceV1(
			ctx,
			cfg,
			model.CheckAccessRequest{
				Operation: "EXECUTE",
				Type:      "PARITY_PAYMENT",
				Resource:  map[string]any{"id": "smoke-pip-not-allowed"},
			},
			generalPipBundle,
			PerCallOptions{},
		)
		if err != nil {
			return smokeStepErr(11, "v1 check/resource GENERAL-PIP deny", err)
		}
		if status != http.StatusOK || decision {
			return smokeStepErr(11, "v1 check/resource GENERAL-PIP deny", fmt.Errorf("status=%d decision=%v", status, decision))
		}
		step++
	}

	anonStatus, _, anonRaw, err := HelperCheckResourceV1(
		ctx,
		cfg,
		model.CheckAccessRequest{
			Operation: "READ",
			Type:      "PARITY_CUSTOMER",
			Resource:  map[string]any{"id": "smoke-anon"},
		},
		TokenBundle{M2M: m2m, Anonymous: true},
		PerCallOptions{},
	)
	if err != nil {
		return smokeStepErr(12, "v1 check/resource anonymous", err)
	}
	trimmedAnon := strings.TrimSpace(string(bytes.TrimSpace(anonRaw)))
	if anonStatus != http.StatusOK || (trimmedAnon != "true" && trimmedAnon != "false") {
		return smokeStepErr(12, "v1 check/resource anonymous", fmt.Errorf("status=%d body=%q", anonStatus, trimmedAnon))
	}
	step++

	if step != expectedAssertions {
		return fmt.Errorf("smoke phase internal error: completed %d steps", step)
	}
	if len(skippedList) == 0 {
		fmt.Println("[paritysuite] smoke phase: 12/12 assertions green")
		return nil
	}
	fmt.Printf("[paritysuite] smoke phase: %d/%d assertions green (skipped: %s)\n", step, expectedAssertions, strings.Join(skippedList, ", "))
	return nil
}

func containsCallPath(calls []PipStubCall, want string) bool {
	for _, call := range calls {
		if call.Path == want {
			return true
		}
	}
	return false
}

func smokeStepErr(step int, what string, err error) error {
	return fmt.Errorf("step %d (%s): %w", step, what, err)
}
