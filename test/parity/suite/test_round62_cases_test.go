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

// Round 62 asks the obligations member of v2 checks, filters, and bulk
// operations on a stand that runs with access-control.obligations.enabled=true
// and access-control.obligations.merge.strategy=weak; the files say so in
// standProperties, and the stand's owner sets the properties before the run.
// Each case writes a set that allows READ and the obligations of a domain in a
// tenant of its own, then asks for obligations as users of different roles. The cases are round 61's under the other strategy, so the two
// strategies compare case by case.
// The cases of round62/obligations-on-behalf.json send userId, so that file
// is recorded only on a stand whose user lookup answers for the parity realm's
// users. The cases are data under testdata/cases/round62, and each case's about
// field says what it asks.

// TestRound62ObligationsMustCases runs round62/obligations-must.json.
func (s *ParitySuite) TestRound62ObligationsMustCases() {
	s.runCaseFile("round62/obligations-must.json")
}

// TestRound62ObligationsShouldCases runs round62/obligations-should.json.
func (s *ParitySuite) TestRound62ObligationsShouldCases() {
	s.runCaseFile("round62/obligations-should.json")
}

// TestRound62ObligationsOnBehalfCases runs round62/obligations-on-behalf.json.
func (s *ParitySuite) TestRound62ObligationsOnBehalfCases() {
	s.runCaseFile("round62/obligations-on-behalf.json")
}
