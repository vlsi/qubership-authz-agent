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

package regogen

import (
	"maps"
	"slices"
	"strings"

	"authz-agent/internal/regogen/spectables"
)

// LeafReport says how the generator built one comparison of a condition:
// where the condition is, and the cell of the specification's table each pair
// of operand points took its outcome from. [Generate] writes one for each
// comparison of each condition it translates when [Options.Report] is set, in
// the order it translates them, so the same tree gives the same report. A
// condition is translated once per place, effect, and copy of the tree, and a
// condition that several nodes share gets its entries once.
type LeafReport struct {
	// Set, Policy, and Rule are the IDs of the innermost set, the policy,
	// and the rule of the condition, empty above the condition's level; a
	// simplified policy has a Set (its group) and a Policy.
	Set, Policy, Rule string
	// Place is where the condition stands: a target, a rule condition, or
	// the condition of a simplified policy.
	Place spectables.Place
	// Operation and Depth are the operation and the nesting depth of the
	// copy of the tree that subject allowed or subject denied reads; empty
	// and 0 in the tree itself.
	Operation string
	Depth     int
	// Leaf is the comparison as the generator prints it: the operands and
	// the operator, without the condition around it.
	Leaf string
	// Cells lists the cell of each pair of points of the operands' domains.
	// It is empty for a comparison that reads a PIP the tenant does not
	// declare, which is undefined without a cell.
	Cells []CellReport
}

// CellReport is the cell one pair of operand points took its outcome from.
type CellReport struct {
	Left, Right spectables.Point
	// Outcome is the cell's outcome; by_value for a cell whose outcome the
	// values decide.
	Outcome spectables.Outcome
	// Template names how the generator answers a by_value cell: the value
	// rules of the template it used, comma-separated, or a fixed
	// description where no template applies; empty for any other cell.
	Template string
}

// whereNow records the set, policy, and rule whose condition the generator
// translates next.
type whereNow struct {
	set, policy, rule string
	place             spectables.Place
}

// reportLeaf records one comparison when the options ask for a report.
func (g *gen) reportLeaf(leaf string, cells []CellReport) {
	if !g.opt.Report {
		return
	}
	r := LeafReport{Set: g.where.set, Policy: g.where.policy, Rule: g.where.rule, Place: g.where.place, Leaf: leaf,
		Cells: cells}
	if g.fixedOp != nil {
		r.Operation, r.Depth = *g.fixedOp, g.fixedDepth
	}
	g.report = append(g.report, r)
}

// reportCells lists the cell of each pair of points, with the template of each
// by_value cell from templates.
func reportCells(L, R *side, lps, rps []point, cells [][]spectables.Cell, templates map[[2]int]string) []CellReport {
	var out []CellReport
	for i, lp := range lps {
		for j, rp := range rps {
			c := CellReport{Left: lp.spec(L.kind), Outcome: cells[i][j].Outcome, Template: templates[[2]int{i, j}]}
			if R != nil {
				c.Right = rp.spec(R.kind)
			}
			out = append(out, c)
		}
	}
	return out
}

// opText is an operator as a condition writes it.
func opText(op spectables.Operator) string {
	if t, ok := relText[op]; ok {
		return t
	}
	switch op {
	case spectables.OpEQ:
		return "=="
	case spectables.OpNE:
		return "!="
	}
	return strings.ReplaceAll(string(op), "_", " ")
}

// ruleNames is the comma-separated sorted list of the rules.
func ruleNames(rules map[spectables.ValueRule]bool) string {
	names := make([]string, 0, len(rules))
	for _, r := range slices.Sorted(maps.Keys(rules)) {
		names = append(names, string(r))
	}
	return strings.Join(names, ",")
}
