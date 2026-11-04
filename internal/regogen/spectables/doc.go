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

// Package spectables loads the leaf-outcome table that the executable
// specification of the legacy policy language writes for the Rego generator.
//
// A table answers one question: what does a comparison leaf evaluate to, given
// its operator, the kind and state of each operand, and where the leaf stands.
// The generator writes Rego from these answers and never from hand-written
// cases, so a question the table cannot answer is a generation error. [Load]
// therefore rejects a table that leaves any operator, operand kind, state, or
// context of a required combination without an outcome, and [Table.Lookup]
// returns an error, never a default outcome, for a key outside the table.
//
// # Table
//
// The specification computes two profiles: legacy, what the legacy service
// does, and agent, legacy with the differences the agent makes on purpose. Its
// exporter writes the table of the agent profile, with the cells of each
// combination written as grids. schema.json in this directory describes the
// table, and [Load] reads it in schema version [SchemaVersion].
//
// The table is one JSON document. Its top level carries:
//
//   - schema_version: 4.
//   - spec_tag: the tag of the specification commit the tables were computed
//     from, such as r65. A changed decision changes a knob, the
//     specification gets a new tag, and the table is regenerated under it.
//   - negates: each negated operator and the operator it negates, exactly the
//     pairs of [Negations].
//   - knobs: the specification settings that the generator's templates for the
//     value-by-value case need, keyed by their name in the specification:
//     exactly those of [RequiredKnobs].
//   - kinds: for every operand kind of [Kinds], the states the operand can be in
//     and, when the states include VALUE, the classes of value it can hold
//     ([Classes]). The order of the states and classes is the order of the
//     points of a grid.
//   - nodes: how the outcomes of the nodes above the leaves combine, as the
//     agent profile's settings give them ([Nodes]): the outcome of each
//     algorithm of [Algorithms] when its children include a permit only, a deny
//     only, both, and neither; the algorithm of a node that names none; the
//     outcome of a rule whose effect is neither ALLOW nor DENY; what a rule
//     without an effect counts as; and the value of an absent target or
//     condition. Every algorithm and rule effect is required, and an unknown
//     one is an error, so the generator never falls back to a default.
//   - leaf: for each outcome of legacy the agent profile lacks, ABORT and ERR,
//     the outcome of the agent profile it becomes.
//   - aliases: the operand kinds that answer as an earlier kind, their
//     representative, which has the same domain.
//   - codes: the results the grids name, each under a code of one ASCII letter
//     or digit.
//   - cells: the outcomes, as lines of a combination that each cover the
//     contexts their qualifiers name.
//
// # Results
//
// A result is an outcome, in legacy's outcomes:
//
//	"a": {"outcome": "by_value", "outcomes": ["T", "F"], "value_rule": ["eq"]}
//
// The outcome is one of legacy's [Outcomes]; after the leaf map it is one of
// the agent profile's: T, F, or U, where T is the true rail, F the false rail,
// and U neither rail. Both profiles also allow bad_request, a request the
// service rejects with 400, and unsupported, a form the specification does
// not evaluate. The outcome by_value marks a result that depends on the
// operand values rather than on their states; it lists in outcomes the two or
// more outcomes the values can produce, and in value_rule the rules of
// [ValueRules] the specification went through to reach them, sorted. A cell
// that moves to another rule therefore changes the table, and the generator
// can pick its template of the comparison by rule and fail generation on a
// rule it has none for. value_rule appears on no other result.
//
// The exporter writes T, F, ABORT, ERR, bad_request, and unsupported under
// the codes T, F, A, E, B, and X, and keeps the code its previous table gave a
// by_value result, so that a new result does not renumber the lines of
// combinations that did not change.
//
// # Cells
//
// A line of cells holds fields separated by spaces: the operator, the left
// kind, the right kind for a binary operator, any qualifiers of the context,
// and the grid:
//
//	EQ operation res:path aaaaaaAaaE
//	IN res:path subj.permissionScope in_iterate=true kkAFE kkAFE ddAFE dFAFE dFAFE ddAFE A F F E
//
// MATCH and NOT_MATCH take the pattern kind on the right, and no other
// operator takes it on either side. A qualifier is place=, effect=,
// disjunction=, or in_iterate= with a value of [Places], [Effects], true, or
// false; the line covers the contexts that match every qualifier it has.
//
// The grid has a row for each point of the left kind, each row a code for
// each point of the right kind, or one code for a unary operator. A point is a
// state of the kind's domain, with VALUE once per class, in the order kinds
// lists them. One row stands for every row, and one code in a row for every
// code of the row. For each combination of operator, left kind, and right
// kind, the lines must cover every context exactly once; a hole and an
// overlap are both errors.
//
// # Derived cells
//
// A combination of operator and operand kinds may have no lines of its own.
// [Load] then gives it the lines of its source: the combination over the
// representatives of its kinds when that one has lines of its own; else, for a
// negated operator, the lines of its positive operator with T and F swapped,
// in outcome and in the outcomes of a by_value result; else the combination
// over the representatives. The leaf map then rewrites every result, and a
// by_value result whose outcomes it takes to one outcome becomes a result of
// that outcome. Every rule above holds for the lines after this step.
//
// The table carries no provenance: a field or a knob that the format does not
// define, such as a reference to the golden that fixed a cell, is rejected.
package spectables
