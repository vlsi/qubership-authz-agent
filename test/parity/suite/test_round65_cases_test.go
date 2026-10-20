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

// Round 65 asks the PAP questions left open after rounds 47 to 59: set status
// changes in a provisioned tenant and in one nobody provisioned, without a
// body, with a null body and with an empty object; customizations written by
// another tenant; PAP step sequences and the stored form of fields; and the
// differences the second models still show after their kits were refreshed.
// Every step that asks for a decision is followed by raw reads of both
// exports, policy sets and PIPs, so the export-fed profile can compare the
// agent at that point. Each case runs in a tenant of its own, and each file
// opens and closes with a control. The cases are data under
// testdata/cases/round65, and each case's about field says what it asks.

// TestRound65Diff2papMayCases runs round65/diff2pap-may.json.
func (s *ParitySuite) TestRound65Diff2papMayCases() {
	s.runCaseFile("round65/diff2pap-may.json")
}

// TestRound65Diff2papMustCases runs round65/diff2pap-must.json.
func (s *ParitySuite) TestRound65Diff2papMustCases() {
	s.runCaseFile("round65/diff2pap-must.json")
}

// TestRound65Diff2papShouldCases runs round65/diff2pap-should.json.
func (s *ParitySuite) TestRound65Diff2papShouldCases() {
	s.runCaseFile("round65/diff2pap-should.json")
}

// TestRound65OpenCustomAddedCases runs round65/open-custom-added.json.
func (s *ParitySuite) TestRound65OpenCustomAddedCases() {
	s.runCaseFile("round65/open-custom-added.json")
}

// TestRound65OpenForeignCustomIdCaseCases runs round65/open-foreign-custom-id-case.json.
func (s *ParitySuite) TestRound65OpenForeignCustomIdCaseCases() {
	s.runCaseFile("round65/open-foreign-custom-id-case.json")
}

// TestRound65OpenForeignMissingSetCases runs round65/open-foreign-missing-set.json.
func (s *ParitySuite) TestRound65OpenForeignMissingSetCases() {
	s.runCaseFile("round65/open-foreign-missing-set.json")
}

// TestRound65OpenForeignPipCopyCases runs round65/open-foreign-pip-copy.json.
func (s *ParitySuite) TestRound65OpenForeignPipCopyCases() {
	s.runCaseFile("round65/open-foreign-pip-copy.json")
}

// TestRound65OpenForeignRepeatsCases runs round65/open-foreign-repeats.json.
func (s *ParitySuite) TestRound65OpenForeignRepeatsCases() {
	s.runCaseFile("round65/open-foreign-repeats.json")
}

// TestRound65OpenGapsCases runs round65/open-gaps.json.
func (s *ParitySuite) TestRound65OpenGapsCases() {
	s.runCaseFile("round65/open-gaps.json")
}

// TestRound65OpenLifecycleKnobsNoBodyCases runs round65/open-lifecycle-knobs-no-body.json.
func (s *ParitySuite) TestRound65OpenLifecycleKnobsNoBodyCases() {
	s.runCaseFile("round65/open-lifecycle-knobs-no-body.json")
}

// TestRound65OpenLifecycleKnobsObjectBodyCases runs round65/open-lifecycle-knobs-object-body.json.
func (s *ParitySuite) TestRound65OpenLifecycleKnobsObjectBodyCases() {
	s.runCaseFile("round65/open-lifecycle-knobs-object-body.json")
}

// TestRound65OpenLifecycleTenantsCases runs round65/open-lifecycle-tenants.json.
func (s *ParitySuite) TestRound65OpenLifecycleTenantsCases() {
	s.runCaseFile("round65/open-lifecycle-tenants.json")
}

// TestRound65OpenMiscCases runs round65/open-misc.json.
func (s *ParitySuite) TestRound65OpenMiscCases() {
	s.runCaseFile("round65/open-misc.json")
}

// TestRound65OpenSurvivorsCases runs round65/open-survivors.json.
func (s *ParitySuite) TestRound65OpenSurvivorsCases() {
	s.runCaseFile("round65/open-survivors.json")
}

// TestRound65PapfieldsMayCases runs round65/papfields-may.json.
func (s *ParitySuite) TestRound65PapfieldsMayCases() {
	s.runCaseFile("round65/papfields-may.json")
}

// TestRound65PapfieldsMustCases runs round65/papfields-must.json.
func (s *ParitySuite) TestRound65PapfieldsMustCases() {
	s.runCaseFile("round65/papfields-must.json")
}

// TestRound65PapfieldsShouldCases runs round65/papfields-should.json.
func (s *ParitySuite) TestRound65PapfieldsShouldCases() {
	s.runCaseFile("round65/papfields-should.json")
}

// TestRound65PapseqMayCases runs round65/papseq-may.json.
func (s *ParitySuite) TestRound65PapseqMayCases() {
	s.runCaseFile("round65/papseq-may.json")
}

// TestRound65PapseqMustCases runs round65/papseq-must.json.
func (s *ParitySuite) TestRound65PapseqMustCases() {
	s.runCaseFile("round65/papseq-must.json")
}
