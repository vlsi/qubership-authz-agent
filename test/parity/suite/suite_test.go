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

	"github.com/stretchr/testify/suite"
)

// ParitySuite is the testify entry point per D-A, with one test method per
// row of the Planned Test Catalogue. The TearDownTest hook already calls ResetPinnedRoutes on both
// pip-mock and entitlements-mock so every sub-case starts from a known
// state per D-O.
type ParitySuite struct {
	suite.Suite

	cfg        Config
	tokens     *TokenFactory
	comparator *GoldenComparator
	pipMock    *PipController
	eaMock     *PipController
}

// TestParitySuite is the `go test` entry. Use
// `go test -tags integration -run ^TestParitySuite$ ./...` to drive it.
func TestParitySuite(t *testing.T) {
	suite.Run(t, new(ParitySuite))
}

func (s *ParitySuite) SetupSuite() {
	s.cfg = LoadConfig()
	s.tokens = NewTokenFactory(s.cfg)
	s.comparator = NewGoldenComparator(s.cfg)
	s.pipMock = NewPipController(s.cfg.PipMockControlURL)
	s.eaMock = NewPipController(s.cfg.EAMockControlURL)

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
	if err := seeder.SeedDomain(ctx, s.cfg.DomainName, mainFixtureFS); err != nil {
		s.T().Fatalf("seed main fixtures: %v", err)
	}
}

// TearDownTest resets both mocks' pinned-route state so the next test's
// SetupTest starts from a clean slate. Tests that do not pin routes still
// pay nothing here — ResetPinnedRoutes is a no-op on an empty pin map.
func (s *ParitySuite) TearDownTest() {
	ctx := context.Background()
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
}
