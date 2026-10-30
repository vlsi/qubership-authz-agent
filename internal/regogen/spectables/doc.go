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

// Package spectables loads the leaf-outcome tables that the executable
// specification of the legacy policy language exports for the Rego generator.
//
// A table answers one question: what does a comparison leaf evaluate to, given
// its operator, the kind and state of each operand, and where the leaf stands.
// The generator writes Rego from these answers and never from hand-written
// cases, so a question the table cannot answer is a generation error. [Load]
// therefore rejects an export that leaves any operator, operand kind, state, or
// context of a required combination without an outcome, and [Table.Lookup]
// returns an error, never a default outcome, for a key outside the table.
//
// # Export format
//
// The export is one JSON document, described for the exporter by schema.json in
// this directory. Its top level carries:
//
//   - schema_version: 3. [Load] also reads version 2, where every combination
//     carries cells of its own in the outcomes of its profile, and version 1,
//     the format without value rules and node rules, with one class x for an
//     object, a nested list, and a list with a null element.
//   - spec_tag: the tag of the specification commit the tables were computed
//     from, such as r65. A changed decision changes a knob, the
//     specification gets a new tag, and the export is regenerated under it.
//   - profiles: exactly the two profiles, "legacy" and "agent". The legacy
//     profile is what the legacy service does; the agent profile is legacy with
//     the differences the agent makes on purpose. The generator reads the agent
//     profile, and the registry of differences compares the two.
//   - negates: from version 3, each negated operator and the operator it
//     negates, exactly the pairs of [Negations].
//
// Each profile carries:
//
//   - knobs: the specification settings that the generator's templates for the
//     value-by-value case need, keyed by their name in the specification:
//     exactly fold, eq_numeric, list_eq_by_value, and subset_fold.
//   - kinds: for every operand kind of [Kinds], the states the operand can be in
//     and, when the states include VALUE, the classes of value it can hold
//     ([Classes]).
//   - nodes: how the outcomes of the nodes above the leaves combine, as the
//     profile's settings give them ([Nodes]): the outcome of each algorithm
//     of [Algorithms] when its children include a permit only, a deny only,
//     both, and neither; the algorithm of a node that names none; the
//     outcome of a rule whose effect is neither ALLOW nor DENY; what a rule
//     without an effect counts as; and the value of an absent target or
//     condition. Every algorithm and rule effect is required, and an unknown
//     one is an error, so the generator never falls back to a default.
//   - leaf: from version 3, the outcome of the profile that each outcome of
//     legacy the profile lacks becomes: ABORT and ERR in the agent profile,
//     nothing in the legacy profile.
//   - aliases: from version 3, the operand kinds that answer as an earlier
//     kind, their representative, which has the same domain.
//   - cells: the outcomes.
//
// # Derived cells
//
// From version 3 the cells of both profiles carry legacy's outcomes, and a
// combination of operator and operand kinds may have no cells of its own.
// [Load] then gives it the cells of its source: the combination over the
// representatives of its kinds when that one has cells of its own, with the
// kinds renamed; else, for a negated operator, the cells of its positive
// operator with T and F swapped, in outcome and in the outcomes of a by_value
// cell; else the combination over the representatives, renamed. The leaf map
// then rewrites every outcome of the profile, and a by_value cell whose
// outcomes it takes to one outcome becomes a cell of that outcome. Every rule
// below holds for the cells after this step.
//
// # Cells
//
// A cell names an operator, a left side, an optional right side, a context, and
// an outcome:
//
//	{"op": "EQ",
//	 "left": {"kind": "res:path", "state": "NULL"},
//	 "right": {"kind": "lit:str"},
//	 "place": "rule_condition",
//	 "outcome": "F"}
//
// The operator and the kind of each side are required. The right side is
// present exactly when the operator is binary; MATCH and NOT_MATCH take the
// pattern kind on the right, and no other operator takes it on either side.
//
// Every other field narrows the cell, and an omitted one matches every value: a
// side without a state matches every state of its kind's domain, a side in state
// VALUE without a class matches every class, and an omitted place, effect,
// disjunction, or in_iterate matches every value of that context dimension. A
// class is allowed only beside state VALUE. For each profile and each
// combination of operator, left kind, and right kind, the cells must cover every
// point of the grid of contexts, left (state, class) pairs, and right (state,
// class) pairs exactly once; a hole and an overlap are both errors.
//
// The outcome is one of [Outcomes] for the profile (in the file of version 3,
// one of legacy's): T, F, or U in the agent
// profile, where T is the true rail, F the false rail, and U neither rail; T, F,
// ABORT, or ERR in the legacy profile. Both profiles also allow bad_request, a
// request the service rejects with 400, and unsupported, a form the
// specification does not evaluate. The outcome by_value marks a cell whose
// outcome depends on the operand values rather than on their states; such a cell
// lists in outcomes the two or more outcomes the values can produce, and in
// value_rule the rules of [ValueRules] the specification went through to reach
// them, sorted. A cell that moves to another rule therefore changes the
// export, and the generator can pick its template of the comparison by rule
// and fail generation on a rule it has none for. value_rule appears on no
// other cell.
//
// The export carries no provenance: a field or a knob that the format does not
// define, such as a reference to the golden that fixed a cell, is rejected.
package spectables
