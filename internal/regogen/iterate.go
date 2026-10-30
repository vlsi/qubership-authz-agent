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

// An iterate over subject.permissionScope evaluates its set once per
// assignment of the subject's permission scope, and combines the passes by
// the iterate's algorithm. The projection writes the passes to input.ps, each
// with the records of the scope keys the module reads in the layout of the
// input (p.s.rN, p.k.rN, ...), and sets input.psf when the permission scope
// cannot be read. The subtree of the set is translated with the pass as a
// parameter: its rules are functions of p, and a pass value reads p.
//
// No pass is no kid, so an empty scope gives the algorithm's outcome over no
// children; a failed scope leaves the node unknown, [deny, permit], as a
// failed source does.

const scopeFailed = "input.psf"

// iterateFlag returns the clauses where bound b of iterate node n is x.
func (g *gen) iterateFlag(n *node, b, x string) (dnf, error) {
	inner, err := g.inner(n, b, x)
	if err != nil {
		return nil, err
	}
	read := prod(dnf{{{cls: clsCheck, text: "not " + scopeFailed}}}, inner, true)
	switch b + x {
	case "loD", "hiP":
		// a failed scope is [deny, permit]
		read = union(read, dnf{{{cls: clsCheck, text: scopeFailed}}})
	}
	if x == "P" {
		return g.product(n.tgt.T(), read), nil
	}
	return union(n.tgt.U(), g.product(n.tgt.T(), read)), nil
}

// anyPass returns the clauses of "some pass of iterate node n has bound b
// equal to x", or of their negation, as a reference to a rule: a rule keeps
// the pass variable out of the clause that reads it.
func (g *gen) anyPass(n *node, b, x string, negate bool) (dnf, error) {
	name := n.id + "_any_" + b + x
	if _, ok := g.anyBodies[name]; !ok {
		saved := g.pass
		g.pass = true
		d, err := g.flag(n.kids[0], b, x)
		if err != nil {
			g.pass = saved
			return nil, err
		}
		fn := g.rule(n.id+"_pass_"+b+x, d)
		g.pass = saved
		body := dnf{{{cls: clsCheck, text: "some p in input.ps"}, {cls: clsCheck, text: g.call(fn), rule: fn}}}
		if d.isFalse() {
			body = dnfFalse
		}
		g.rule(name, body)
		g.anyBodies[name] = body
	}
	if negate {
		if g.anyBodies[name].isFalse() {
			return dnfTrue, nil
		}
		return dnf{{{cls: clsCheck, text: "not " + name, rule: name}}}, nil
	}
	if g.anyBodies[name].isFalse() {
		return dnfFalse, nil
	}
	return dnf{{{cls: clsCheck, text: name, rule: name}}}, nil
}
