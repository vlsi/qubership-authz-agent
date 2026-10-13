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

// Round 63 records the call access-control makes to the User Management API
// for a request with userId, on a stand whose INTERNAL_APIGATEWAY_URL points
// at user-management-mock. TestRound63OnbehalfMustCases asks the method, the
// path with each reserved character of userId, the headers, and the answer to
// an unrouted path, to failing statuses, to answers that are no user, to a
// repeated user, and to a bulk request; TestRound63OnbehalfShouldCases reads
// one candidate user through conditions over the subject. Each file records
// the stand's version first and opens and closes with a control. The cases
// are data under testdata/cases/round63, and each case's about field says
// what it asks.

// TestRound63OnbehalfMustCases runs round63/onbehalf-must.json.
func (s *ParitySuite) TestRound63OnbehalfMustCases() {
	s.runCaseFile("round63/onbehalf-must.json")
}

// TestRound63OnbehalfShouldCases runs round63/onbehalf-should.json.
func (s *ParitySuite) TestRound63OnbehalfShouldCases() {
	s.runCaseFile("round63/onbehalf-should.json")
}
