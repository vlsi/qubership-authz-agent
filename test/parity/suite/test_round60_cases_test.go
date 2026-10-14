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

// Round 60 asks what the PAP does with obligations on a stand that runs with
// access-control.obligations.enabled=false: each case writes the obligations
// of a domain in a tenant of its own, reads them back by domain and through
// the raw and the merged export, with and without resource_types, and deletes
// them; one case sends v2 requests that ask for obligations, to record that
// the answers carry none. Each file records the stand's version first and opens
// and closes with a control. The cases are data under testdata/cases/round60,
// and each case's about field says what it asks.

// TestRound60ObligationsMustCases runs round60/obligations-must.json.
func (s *ParitySuite) TestRound60ObligationsMustCases() {
	s.runCaseFile("round60/obligations-must.json")
}

// TestRound60ObligationsShouldCases runs round60/obligations-should.json.
func (s *ParitySuite) TestRound60ObligationsShouldCases() {
	s.runCaseFile("round60/obligations-should.json")
}
