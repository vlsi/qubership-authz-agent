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

//go:build integration

package paritysuite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// ParitySuite is the testify entry point per D-A, with one test method per
// row of the Planned Test Catalogue. The TearDownTest hook already calls ResetPinnedRoutes on
// pip-mock, entitlements-mock and user-management-mock so every sub-case starts from a known
// state per D-O.
type ParitySuite struct {
	suite.Suite

	cfg        Config
	tokens     *TokenFactory
	comparator *GoldenComparator
	pipMock    *PipController
	eaMock     *PipController
	// umMock is the User Management stub. The suite pins it or reads its
	// calls only for case files that ask to, so a stand without it runs
	// every other file.
	umMock *PipController
	// errorBodies is set while runCaseFile runs a file that records the body
	// of a 400 or 409 answer beside its status; see recordsErrorBodies.
	errorBodies bool
	// scopeRead is set while a test runs a case file that declares or pins a
	// permission scope; see TearDownTest.
	scopeRead bool
}

// scopeCacheTTL outlasts the cachePeriod the case files declare for the
// permission scope PIP, one second. The stand caches a subject's scope per
// (subject, tenant) for the cachePeriod of the declaration that read it.
const scopeCacheTTL = 1500 * time.Millisecond

// TestParitySuite is the `go test` entry. Use
// `go test -tags integration -run ^TestParitySuite$ ./...` to drive it. It
// skips under the export-fed profile, whose agent pulls from the exports
// TestExportFedAgent serves and ignores the uploads this suite makes.
func TestParitySuite(t *testing.T) {
	if isExportFedProfile(LoadConfig().Profile) {
		t.Skipf("PARITY_PROFILE=%s runs TestExportFedAgent only", exportFedProfile)
	}
	suite.Run(t, new(ParitySuite))
}

func (s *ParitySuite) SetupSuite() {
	s.cfg = LoadConfig()
	s.tokens = NewTokenFactory(s.cfg)
	s.comparator = NewGoldenComparator(s.cfg)
	s.pipMock = NewPipController(s.cfg.PipMockControlURL)
	s.eaMock = NewPipController(s.cfg.EAMockControlURL)
	s.umMock = NewPipController(s.cfg.UMMockControlURL)

	ctx := context.Background()
	seeder := NewDomainSeeder(s.cfg, s.tokens)

	if err := seeder.WipeDomain(ctx, s.cfg.DomainName); err != nil {
		s.T().Fatalf("wipe before smoke seed: %v", err)
	}
	if err := seeder.SeedDomain(ctx, s.cfg.DomainName, smokeFixtureFS); err != nil {
		s.T().Fatalf("seed smoke fixtures: %v", err)
	}
	if err := RunSmokePhase(ctx, s.cfg, s.tokens, s.pipMock); err != nil {
		s.T().Fatalf("smoke phase: %v", err)
	}
	if err := s.pipMock.ResetPinnedRoutes(ctx); err != nil {
		s.T().Fatalf("reset pip-mock after smoke: %v", err)
	}
	if err := s.pipMock.ResetCalls(ctx); err != nil {
		s.T().Fatalf("reset pip-mock calls after smoke: %v", err)
	}
	if err := s.eaMock.ResetPinnedRoutes(ctx); err != nil {
		s.T().Fatalf("reset entitlements-mock after smoke: %v", err)
	}
	if err := s.eaMock.ResetCalls(ctx); err != nil {
		s.T().Fatalf("reset entitlements-mock calls after smoke: %v", err)
	}
	if err := seeder.WipeDomain(ctx, s.cfg.DomainName); err != nil {
		s.T().Fatalf("wipe after smoke: %v", err)
	}
	if err := seeder.SeedDomain(ctx, s.cfg.DomainName, mainFixturesFor(s.cfg.Profile)); err != nil {
		s.T().Fatalf("seed main fixtures: %v", err)
	}
}

// TearDownTest resets every mock's pinned-route state so the next test's
// SetupTest starts from a clean slate. Tests that do not pin routes still
// pay nothing here — ResetPinnedRoutes is a no-op on an empty pin map.
//
// A test that pinned a permission scope route, or ran a case file that
// declares one, then waits scopeCacheTTL, so that the scope it read has left
// the stand's cache when the next test asks for the same subject's scope,
// pinned to another answer or not at all.
// On one stand for the whole suite, the next test read that scope otherwise:
// TestRound23SecondCarrierScopeTwoGrantsCases after ...NoGrantsCases, and
// TestRound46Diff2Part45Cases after Part43 and Part44, and Part25 after Part24,
// got the decisions of the previous test's grants. The goldens were recorded
// one test per stand.
func (s *ParitySuite) TearDownTest() {
	ctx := context.Background()
	if s.scopeRead || (s.pipMock != nil && s.pipMock.pinnedPathContains("/permission-scope/")) {
		time.Sleep(scopeCacheTTL)
		s.scopeRead = false
	}
	if s.pipMock != nil {
		if err := s.pipMock.ResetPinnedRoutes(ctx); err != nil {
			s.T().Logf("pip-mock reset warning: %v", err)
		}
	}
	if s.eaMock != nil {
		if err := s.eaMock.ResetPinnedRoutes(ctx); err != nil {
			s.T().Logf("entitlements-mock reset warning: %v", err)
		}
	}
	if s.umMock != nil {
		if err := s.umMock.ResetPinnedRoutes(ctx); err != nil {
			s.T().Logf("user-management-mock reset warning: %v", err)
		}
	}
}
