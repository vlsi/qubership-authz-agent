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

// Round 68 records the subject access-control builds from a token: which
// claim gives subject.id, name, type, serviceAccount, scopes and roles, and
// what a claim the token lacks or an array in place of a string gives. Each
// case is one subject, a token of the realm import or of a client of
// testdata/realm-clients/token-subject-clients.json, whose claims subjectClaims checks before
// anything is sent. The file records the stand's version first and opens and
// closes with a control. The cases are data under testdata/cases/round68, and
// each case's about field says what it asks.

// TestRound68TokensubjectClaimsCases runs round68/tokensubject-claims.json.
// It needs the clients of testdata/realm-clients/token-subject-clients.json
// and the users of testdata/realm/token-subject-users.json in the parity realm.
func (s *ParitySuite) TestRound68TokensubjectClaimsCases() {
	s.runCaseFile("round68/tokensubject-claims.json")
}
