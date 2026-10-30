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
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// relText is the Rego operator of each relational operator.
var relText = map[spectables.Operator]string{spectables.OpLT: "<", spectables.OpLE: "<=", spectables.OpGT: ">",
	spectables.OpGE: ">="}

// relFlip is the operator that compares the operands in the other order.
var relFlip = map[spectables.Operator]spectables.Operator{spectables.OpLT: spectables.OpGT,
	spectables.OpLE: spectables.OpGE, spectables.OpGT: spectables.OpLT, spectables.OpGE: spectables.OpLE}

// orderKey returns the array that Rego orders as it orders the numbers: [0]
// for zero, [1, e, digits] for a positive number whose first significant
// digit has exponent e, and [-1, -e, complement] for a negative one, where
// complement replaces each digit d by 9-d and ends in "~", which sorts after
// every digit. Arrays compare element by element, so two keys compare as their
// numbers do at any exponent and any number of digits, which Rego's own
// numbers do not: OPA reads a number with a large exponent as 0 or spends
// milliseconds reading it.
func orderKey(d jsonvalue.Decimal) *ast.Term {
	sign, digits, adj := d.Parts()
	switch sign {
	case 0:
		return ast.ArrayTerm(ast.IntNumberTerm(0))
	case 1:
		return ast.ArrayTerm(ast.IntNumberTerm(1), ast.NumberTerm(jsonNumber(adj)), ast.StringTerm(digits))
	}
	comp := []byte(digits)
	for i, c := range comp {
		comp[i] = '9' - c + '0'
	}
	return ast.ArrayTerm(ast.IntNumberTerm(-1), ast.NumberTerm(jsonNumber(-adj)), ast.StringTerm(string(comp)+"~"))
}

func jsonNumber(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

// literalNumber returns the number <, <=, >, and >= read a number literal as:
// its exact value, as the specification reads a literal (it rounds only a
// number of the input to a double), and none for a fraction or an exponent
// beyond the range of a double, which compares false.
func literalNumber(text string) *jsonvalue.Decimal {
	d, ok := jsonvalue.ParseDecimal(text)
	if !ok {
		return nil
	}
	if !isIntegerLiteral(text) {
		if f, err := strconv.ParseFloat(text, 64); err != nil && math.IsInf(f, 0) {
			return nil
		}
	}
	return &d
}

func isIntegerLiteral(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// relTemplate is the template of <, <=, >, and >= between two strings or
// scalars: the numbers they read as compare, and a value that reads as no
// number makes the comparison false (rule rel).
func relTemplate(op spectables.Operator, L, R *side, b *tb) (tpl, bool) {
	out := tpl{fields: b.fields, rules: map[spectables.ValueRule]bool{spectables.RuleRel: true}}
	bind := conj(L.bind(), R.bind())
	operand := func(s *side) (string, bool) {
		if s.ref == nil {
			if s.lit.num == nil {
				return "", false
			}
			return orderKey(*s.lit.num).String(), true
		}
		b.use(s, "nk")
		return s.field("nk"), true
	}
	l, okL := operand(L)
	r, okR := operand(R)
	if !okL || !okR {
		// a literal that reads as no number: false whatever the other side
		out.t, out.f = dnfFalse, dnf{bind}
		return out, true
	}
	c := clsCheck
	if L.ref != nil && L.ref.Network || R.ref != nil && R.ref.Network {
		c = clsAfterBuilt
	}
	ref := L
	if L.ref == nil {
		ref = R
	}
	// The false rail is the complementary comparison, and a side without a
	// number: OPA leaves "not a < b" undefined, not true, when a is missing.
	co := relComplement[op]
	out.t = dnf{conj(bind, clause{{cls: c, text: fmt.Sprintf("%s %s %s", l, relText[op], r), fact: vfact(ref),
		test: relTest(op, L, R)}})}
	out.f = dnf{conj(bind, clause{{cls: c, text: fmt.Sprintf("%s %s %s", l, relText[co], r), fact: vfact(ref),
		test: relTest(co, L, R)}})}
	for _, s := range []*side{L, R} {
		if s.ref != nil {
			out.f = append(out.f, conj(bind, clause{{cls: c, text: "not " + s.field("nk"), fact: vfact(s),
				test: refTest(s, &test{kind: "nonum"})}}))
		}
	}
	return out, true
}

// relComplement is the operator that holds exactly where op does not, for two
// numbers.
var relComplement = map[spectables.Operator]spectables.Operator{spectables.OpLT: spectables.OpGE,
	spectables.OpLE: spectables.OpGT, spectables.OpGT: spectables.OpLE, spectables.OpGE: spectables.OpLT}

// relTest is the group test of a relational comparison; a literal on the left
// flips the operator so that the test reads the reference first.
func relTest(op spectables.Operator, L, R *side) *test {
	switch {
	case L.ref != nil && R.ref != nil:
		t := pairTest("relref", L, R)
		if t != nil {
			t.val = string(op)
		}
		return t
	case L.ref != nil:
		return refTest(L, &test{kind: "rel", val: string(op), num: R.lit.num})
	default:
		return refTest(R, &test{kind: "rel", val: string(relFlip[op]), num: L.lit.num})
	}
}

// relHolds reports whether a op b holds for two numbers, false when either is
// missing.
func relHolds(op string, a, b *jsonvalue.Decimal) bool {
	if a == nil || b == nil {
		return false
	}
	c := a.Compare(*b)
	switch spectables.Operator(op) {
	case spectables.OpLT:
		return c < 0
	case spectables.OpLE:
		return c <= 0
	case spectables.OpGT:
		return c > 0
	case spectables.OpGE:
		return c >= 0
	}
	panic("regogen: relational operator " + op)
}
