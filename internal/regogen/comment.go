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
	"fmt"
	"regexp"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
)

// The module text carries comments that lead a reader from a line back to
// the policy it came from. Every node of the tree has a label: setLabel of
// its set's ID for a top-level set or simplified group, then _sK for the K-th
// nested set, _pK for the K-th policy, and _rK for the K-th rule, counting
// from 1 within the parent. A label depends on the IDs and positions inside
// one top-level set alone, so an edit of one set leaves the labels of the
// others as they were. The first clause that reads a node writes the node's
// source above it: the IDs, the names, the target, and the condition.

// exprSrc is the leaf an expression of a condition came from.
type exprSrc struct {
	// node is the label of the node whose target or condition holds the
	// leaf.
	node string
	// nodes, on a reference to a subject group or to a shared rule, are the
	// labels of the innermost nodes the referenced clauses came from at
	// this reference.
	nodes []string
	// atom is the comparison as policyir.FormatCondition writes it.
	atom string
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// setLabel returns the label of a top-level set or simplified group: set_
// and the first 8 hex digits of a UUID, or for any other ID, set_ and the ID
// with each _ doubled and each character other than a letter or a digit
// written as _<hex code>_, which reads back to the ID.
func setLabel(id string) string {
	if uuidRE.MatchString(id) {
		return "set_" + strings.ToLower(id[:8])
	}
	return "set_" + escapeID(id)
}

// escapeID writes id as an identifier: letters and digits as they are, _ as
// __, and any other character as _ and its hex code and _.
func escapeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteString("__")
		default:
			fmt.Fprintf(&b, "_%x_", r)
		}
	}
	return b.String()
}

// source records the lines that describe the node with label to a reader of
// the module, and the label of its parent, empty for a top-level node.
func (g *gen) source(label, parent string, lines ...string) {
	if _, ok := g.sources[label]; ok {
		return
	}
	g.sources[label] = nodeSource{parent: parent, lines: lines}
}

type nodeSource struct {
	parent string
	lines  []string
}

// condText is a condition as one line of a comment, or TRUE without one.
func condText(c *policyir.Condition) string {
	if c == nil {
		return "(none)"
	}
	return policyir.FormatCondition(c)
}

func atomText(a policyir.Atom) string {
	return policyir.FormatCondition(&policyir.Condition{Disjuncts: [][]policyir.Atom{{a}}})
}

// stamp returns d with src on every expression that has no source yet.
func stamp(d dnf, src *exprSrc) dnf {
	if len(d) == 0 {
		return d
	}
	out := make(dnf, len(d))
	for i, c := range d {
		nc := make(clause, len(c))
		for j, e := range c {
			if e.src == nil {
				e.src = src
			}
			nc[j] = e
		}
		out[i] = nc
	}
	return out
}

// withCell returns c with the cell on each check of a state or a class that
// has none yet.
func withCell(c clause, cell string) clause {
	out := make(clause, len(c))
	for i, e := range c {
		if e.cell == "" && (e.fact.field == 's' || e.fact.field == 't') {
			e.cell = cell
		}
		out[i] = e
	}
	return out
}

// clauseNodes returns the labels of the innermost nodes the expressions of c
// came from: a label that another one extends is left out.
func clauseNodes(c clause) []string {
	var labels []string
	for _, e := range c {
		if e.src == nil {
			continue
		}
		for _, l := range append([]string{e.src.node}, e.src.nodes...) {
			if l != "" && !slices.Contains(labels, l) {
				labels = append(labels, l)
			}
		}
	}
	out := labels[:0:0]
	for _, l := range labels {
		if !slices.ContainsFunc(labels, func(o string) bool { return strings.HasPrefix(o, l+"_") }) {
			out = append(out, l)
		}
	}
	slices.Sort(out)
	return out
}

// dnfNodes returns the labels of the innermost nodes the clauses of d came
// from.
func dnfNodes(d dnf) []string {
	var all clause
	for _, c := range d {
		all = append(all, c...)
	}
	return clauseNodes(all)
}

// atoms returns the distinct comparisons the expressions of d came from, in
// the order they first appear.
func atoms(d dnf) []string {
	var out []string
	for _, c := range d {
		for _, e := range c {
			if e.src != nil && e.src.atom != "" && !slices.Contains(out, e.src.atom) {
				out = append(out, e.src.atom)
			}
		}
	}
	return out
}

// lineComment is the comment after an expression: for a check of a state or
// a class, the comparison it belongs to and, where one cell decides it, the
// points and the outcome; for a subject group's membership, the comparisons
// it holds; empty for any other expression.
func lineComment(e expr) string {
	atom := ""
	if e.src != nil {
		atom = e.src.atom
	}
	switch {
	case atom != "" && e.cell != "":
		return atom + ": " + e.cell
	case atom != "" && (e.fact.field == 's' || e.fact.field == 't'):
		return atom
	}
	return e.cell
}

// commentLine makes s fit on one comment line.
func commentLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}

// legend opens a module: what the names and the fields of the input mean.
const legend = `# Generated from the policies of one tenant; the comments name the policy
# each line came from.
#
# A node label names a policy set by set_ and the first 8 hex digits of its
# ID, then _sK the K-th nested set, _pK the K-th policy, and _rK the K-th rule
# in it. A comment block with the IDs, names, targets, and conditions stands
# above the first clause read from a node, and "# <label>" above each run of
# clauses from one node.
#
# Rules: <node>_any_<b><x> holds when some child of the node has bound b (lo,
# hi) equal to x (P permit, D deny); decN_<b><x> is that bound of the
# decision for another operation (subject allowed or denied); mN and cN hold
# a product or a condition rail that several clauses share; <rule>__body
# holds the clauses of a long rule.
#
# input.<field>[<operand>] is a field of the value record of an operand,
# keyed by the operand as a policy writes it: s state, t class, k key, ks
# keys of the elements, raw text, seg, eseg, and nseg path segments from the
# start, from the end, and their count, n0 a list holds null, tk the key of
# the text a string equals a list or an object by, o the key two lists or
# objects are equal by, ln length, ea and eb element tokens, nk the number <
# and > compare, sa and sb the tokens IS SUBSET reads. A class is s string, n
# number or boolean, l list, hl list from a header, xn list with null, xl
# nested list, xo object, z null. input.sroles holds the folded roles,
# input.g the subject groups the request is in, input.m2m whether the subject
# is machine-to-machine, and input.ps the passes of an iterate over the
# permission scope.
`

// commenter writes the comments above the clauses of one module text.
type commenter struct {
	g       *gen
	b       *strings.Builder
	printed map[string]bool
	// last is the label comment written above the previous clause, so a
	// run of clauses from one node gets it once.
	last string
}

// clause writes, above clause c, the source of every node c came from that
// no earlier clause wrote, and the labels of those nodes when they differ
// from the previous clause's.
func (cm *commenter) clause(c clause) {
	labels := clauseNodes(c)
	if len(labels) == 0 {
		return
	}
	for _, l := range labels {
		cm.source(l)
	}
	line := "# " + strings.Join(labels, ", ")
	if line != cm.last {
		cm.b.WriteString(line + "\n")
		cm.last = line
	}
}

// source writes the source of the node with label, after its parent's.
func (cm *commenter) source(label string) {
	if cm.printed[label] {
		return
	}
	cm.printed[label] = true
	src, ok := cm.g.sources[label]
	if !ok {
		return
	}
	if src.parent != "" {
		cm.source(src.parent)
	}
	cm.b.WriteString("# " + label + ": " + commentLine(src.lines[0]) + "\n")
	for _, l := range src.lines[1:] {
		cm.b.WriteString("#   " + commentLine(l) + "\n")
	}
	cm.last = ""
}
