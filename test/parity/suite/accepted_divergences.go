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
	"fmt"
	"path/filepath"
	"strings"
)

// acceptedDivergenceRoot holds one file per accepted divergence, mirroring the
// layout under testdata/golden. It is deliberately a separate tree: the golden
// directory is immutable evidence recorded from live access-control, and mixing
// "what the agent does instead" into it would blur that line.
const acceptedDivergenceRoot = "testdata/accepted-divergences"

// AcceptedDivergence records a case where authz-agent knowingly answers
// differently from the legacy golden.
//
// This is NOT a way to silence a failing case. The case still runs, still calls
// the agent, and its response is still compared byte-for-byte — only against the
// recorded divergent answer instead of the golden. Three outcomes follow:
//
//   - the agent matches the golden        -> pass (the divergence is gone; the
//     entry here is now stale and should be deleted)
//   - the agent matches this record       -> pass, with a line in the test log
//   - the agent matches neither           -> fail
//
// So a regression that changes the answer a third way is still caught, which is
// the property a t.Skip would have thrown away.
type AcceptedDivergence struct {
	// Reason states why the agent is allowed to differ, in one sentence.
	Reason string
	// Decision names where the decision is written down in full.
	Decision string
	// AllowsMore marks a decision that also covers an answer allowing what
	// the golden denies. Only part A of the export-fed profile
	// (acceptedLegacyDifference) reads it; every other comparison rejects
	// such an answer whatever the entry says.
	AllowsMore bool
}

// acceptedDivergences is keyed by "<row id>|<subCase>".
//
// Every entry needs a decision document. Adding one without it, or adding one to
// make an unexplained failure go away, defeats the purpose of the suite.
var acceptedDivergences = map[string]AcceptedDivergence{
	key(PSUITE_ROW_2_CHECK_RESOURCE_V1, "general-pip-dict/allow"): {
		Reason: "The agent resolves the dict aliases returned by a GENERAL PIP, which " +
			"legacy access-control could not, so it allows where legacy denied by inability " +
			"rather than by policy.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
	key(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, "general-pip-dict"): {
		Reason: "Same dict-alias resolution as row 2, seen through the bulk endpoint: the " +
			"agent returns the ids legacy left out because it could not evaluate the condition.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
	key(PSUITE_ROW_7_CHECK_RESOURCE_V2, "general-pip-dict/allow"): {
		Reason:   "Same dict-alias resolution as row 2, on the v2 response shape.",
		Decision: "docs/parity/general-pip-dict-divergences.md",
	},
}

// acceptedExportDivergences is keyed by the difference class the
// specification's export bundle gives a golden of the export-fed profile
// (TestExportFedAgent): set-type, conversion, tenant, pip-kind, pull-failure.
// A class is accepted, not a case, because one decision about the conversion
// explains every golden of the class. Such a golden still runs and passes only
// when the agent answers exactly as the bundle predicts for it, so an agent that
// answers a third way still fails.
//
// Every entry needs a decision document, as acceptedDivergences does. An
// answer that allows what the golden denies (grantsMore) is accepted only
// where the entry sets AllowsMore: a wrong allow is an agent defect until its
// own decision says otherwise. Part A of the profile also keys this map by
// the classes it derives from the exports legacy held (legacyClass), such as
// undeclared-pip, which the bundle never gives.
var acceptedExportDivergences = map[string]AcceptedDivergence{
	"set-type": {
		Reason: "The agent evaluates the simplified model only: it skips every policy set whose type is not " +
			"SIMPLIFIED, so a decision that rests on a regular policy set differs from legacy.",
		Decision: "docs/parity/export-fed-agent-divergences.md",
	},
	"undeclared-pip": {
		Reason: "The agent takes a subject attribute with no declared PIP as an unknown value of its own " +
			"operand only, and evaluates the rest of the condition; legacy fails the whole rule, so a " +
			"condition such as subject.x == 'v' OR resource.a == 'y' allows in the agent and denies in legacy.",
		Decision:   "docs/parity/export-fed-agent-divergences.md",
		AllowsMore: true,
	},
}

func key(id ParityEndpointID, subCase string) string {
	return fmt.Sprintf("%d|%s", int(id), subCase)
}

// acceptedDivergenceFor returns the record for a case, if one exists.
func acceptedDivergenceFor(id ParityEndpointID, subCase string) (AcceptedDivergence, bool) {
	d, ok := acceptedDivergences[key(id, subCase)]
	return d, ok
}

// acceptedDivergencePath maps a golden path to its accepted-divergence
// counterpart, keeping the same relative layout under the separate root.
func acceptedDivergencePath(goldenRoot, goldenPath string) string {
	rel, err := filepath.Rel(goldenRoot, goldenPath)
	if err != nil {
		// Fall back to the base name rather than failing the case for a path quirk;
		// a missing file is reported clearly by the caller either way.
		rel = filepath.Base(goldenPath)
	}
	return filepath.Join(acceptedDivergenceRoot, rel)
}

// AcceptedDivergenceDriftError is returned when a case is registered as an
// accepted divergence but the agent now answers a third way — neither the golden
// nor the recorded divergence. That is a real finding: the behaviour moved after
// someone decided it was settled.
type AcceptedDivergenceDriftError struct {
	GoldenPath   string
	AcceptedPath string
	Reason       string
	Diff         string
}

func (e *AcceptedDivergenceDriftError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "accepted divergence drifted at %s\n", e.AcceptedPath)
	fmt.Fprintf(&b, "  the case diverges from the golden %s, which is expected: %s\n", e.GoldenPath, e.Reason)
	fmt.Fprintf(&b, "  but it no longer matches the recorded divergence either:\n%s", e.Diff)
	fmt.Fprintf(&b, "  Decide which is right before touching the recorded file: the agent may have\n")
	fmt.Fprintf(&b, "  regressed, or the divergence may have widened.\n")
	return b.String()
}
