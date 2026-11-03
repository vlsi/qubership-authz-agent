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

package policyir

import (
	"errors"
	"fmt"
	"slices"

	"authz-agent/internal/jsonpath"
)

// Place is where a condition stands. One comparison can evaluate differently in
// a simplified policy, in a target, and in the condition of a rule.
type Place string

// The places. The spelling is the specification's.
const (
	PlaceSimplified    Place = "simplified"
	PlaceRuleCondition Place = "rule_condition"
	PlaceRuleTarget    Place = "rule_target"
	PlacePolicyTarget  Place = "policy_target"
	PlaceSetTarget     Place = "set_target"
)

var places = []Place{PlaceSimplified, PlaceRuleCondition, PlaceRuleTarget, PlacePolicyTarget, PlaceSetTarget}

// Places returns every place, in a slice the caller owns.
func Places() []Place { return slices.Clone(places) }

// Operator is a comparison operator, spelled as the specification spells it:
// IS_NOT_NULL, not "IS NOT NULL". Every spelling the PAP accepts maps to one
// of them: EQUALS, == and = are all OpEQ.
type Operator string

// The comparison operators.
const (
	OpEQ             Operator = "EQ"
	OpNE             Operator = "NE"
	OpLT             Operator = "LT"
	OpLE             Operator = "LE"
	OpGT             Operator = "GT"
	OpGE             Operator = "GE"
	OpIsNull         Operator = "IS_NULL"
	OpIsNotNull      Operator = "IS_NOT_NULL"
	OpIsEmpty        Operator = "IS_EMPTY"
	OpIsNotEmpty     Operator = "IS_NOT_EMPTY"
	OpIn             Operator = "IN"
	OpNotIn          Operator = "NOT_IN"
	OpContains       Operator = "CONTAINS"
	OpNotContains    Operator = "NOT_CONTAINS"
	OpContainsAny    Operator = "CONTAINS_ANY"
	OpNotContainsAny Operator = "NOT_CONTAINS_ANY"
	OpIsSubset       Operator = "IS_SUBSET"
	OpIsNotSubset    Operator = "IS_NOT_SUBSET"
	OpMatch          Operator = "MATCH"
	OpNotMatch       Operator = "NOT_MATCH"
)

var operators = []Operator{
	OpEQ, OpNE, OpLT, OpLE, OpGT, OpGE, OpIsNull, OpIsNotNull, OpIsEmpty, OpIsNotEmpty,
	OpIn, OpNotIn, OpContains, OpNotContains, OpContainsAny, OpNotContainsAny,
	OpIsSubset, OpIsNotSubset, OpMatch, OpNotMatch,
}

// Operators returns every comparison operator, in a slice the caller owns.
func Operators() []Operator { return slices.Clone(operators) }

// Unary reports whether the operator takes no right operand.
func (o Operator) Unary() bool {
	switch o {
	case OpIsNull, OpIsNotNull, OpIsEmpty, OpIsNotEmpty:
		return true
	default:
		return false
	}
}

// TakesList reports whether literals on the right of the operator form a
// [List].
func (o Operator) TakesList() bool {
	switch o {
	case OpIn, OpNotIn, OpContainsAny, OpNotContainsAny, OpIsSubset, OpIsNotSubset:
		return true
	default:
		return false
	}
}

// Atom is one conjunct of a condition. Its dynamic type is one of [Const],
// [IsM2M], [Access], [Compare], or [Unsupported].
type Atom interface {
	atom()
}

// Const is TRUE or FALSE written as a whole conjunct.
type Const struct {
	Value bool
}

// IsM2M is subject.isM2M written as a whole conjunct, with no operator.
type IsM2M struct{}

// Access is "subject allowed 'Operation' on resource", or "subject denied …"
// when Denied is set: the decision on the same resource for another operation.
// Operation is the quoted literal as written, and may be empty.
type Access struct {
	Denied    bool
	Operation string
}

// Compare is a comparison. Right is nil exactly when Op is unary. [NewCompare]
// documents which operands each side admits.
type Compare struct {
	Op    Operator
	Left  Operand
	Right Operand
}

func (Const) atom()       {}
func (IsM2M) atom()       {}
func (Access) atom()      {}
func (Compare) atom()     {}
func (Unsupported) atom() {}

// NewCompare returns the comparison of left and right by op. It returns an error
// when op is unknown, when right is set for a unary op or missing for a binary
// one, or when a side holds an operand its position does not admit:
//
//   - a [List] or a [Pattern] never stands on the left;
//   - a [Pattern] stands only on the right of MATCH and NOT MATCH, and the right
//     of those holds a [Pattern] whose text the parser reads there as one
//     pattern, with Path set exactly when the text starts with resource.;
//   - a [PIPRef] with Filtered set stands only on the right;
//   - a [List] stands only on the right of an operator that [Operator.TakesList],
//     and a [String], [Number], or [Bool] never does, because a single literal
//     there is a list of one;
//   - the path of a [Resource] compiles with [jsonpath.Compile].
//
// An [Unsupported] operand is admitted on either side.
func NewCompare(op Operator, left, right Operand) (Compare, error) {
	c := Compare{Op: op, Left: left, Right: right}
	if err := validateCompare(c); err != nil {
		return Compare{}, err
	}
	return c, nil
}

func validateCompare(c Compare) error {
	if !slices.Contains(operators, c.Op) {
		return fmt.Errorf("operator %q: unknown", c.Op)
	}
	if err := validateOperand(c.Left); err != nil {
		return fmt.Errorf("%s: left: %w", c.Op, err)
	}
	switch l := c.Left.(type) {
	case List, Pattern:
		return fmt.Errorf("%s: left: a %T never stands on the left", c.Op, c.Left)
	case PIPRef:
		if l.Filtered {
			return fmt.Errorf("%s: left: a FILTERED reference stands only on the right", c.Op)
		}
	}
	if err := compiles(c.Left); err != nil {
		return fmt.Errorf("%s: left: %w", c.Op, err)
	}
	if c.Op.Unary() {
		if c.Right != nil {
			return fmt.Errorf("%s: unary operator with a right operand %T", c.Op, c.Right)
		}
		return nil
	}
	if err := validateOperand(c.Right); err != nil {
		return fmt.Errorf("%s: right: %w", c.Op, err)
	}
	if _, ok := c.Right.(Unsupported); ok {
		return nil
	}
	if c.Op == OpMatch || c.Op == OpNotMatch {
		r, ok := c.Right.(Pattern)
		if !ok {
			return fmt.Errorf("%s: right: %T is not a pattern", c.Op, c.Right)
		}
		return patternText(c.Op, r)
	}
	if err := compiles(c.Right); err != nil {
		return fmt.Errorf("%s: right: %w", c.Op, err)
	}
	switch c.Right.(type) {
	case Pattern:
		return fmt.Errorf("%s: right: a pattern stands only right of MATCH and NOT_MATCH", c.Op)
	case List:
		if !c.Op.TakesList() {
			return fmt.Errorf("%s: right: the operator takes no list", c.Op)
		}
	case String, Number, Bool:
		if c.Op.TakesList() {
			return fmt.Errorf("%s: right: a single literal right of a list operator is a list of one", c.Op)
		}
	}
	return nil
}

// compiles returns an error when o is a [Resource] whose path
// [jsonpath.Compile] refuses.
func compiles(o Operand) error {
	r, ok := o.(Resource)
	if !ok {
		return nil
	}
	if _, err := jsonpath.Compile(r.Path); err != nil {
		return fmt.Errorf("resource path %q: %w; a frontend writes such a path as an Unsupported operand", r.Path, err)
	}
	return nil
}

// patternText returns an error when [readPattern] does not read the whole of
// r.Text as one pattern, refuses it, or reads it as a resource path exactly
// when r.Path is unset.
func patternText(op Operator, r Pattern) error {
	text := r.Text
	n, path, reason := readPattern(text)
	if reason == "" && n != len(text) {
		reason = "more than one token"
	}
	if reason == "" && path != r.Path {
		reason = fmt.Sprintf("Path is %v, want %v", r.Path, path)
	}
	if reason != "" {
		return fmt.Errorf("%s: right: pattern %q: %s", op, text, reason)
	}
	return nil
}

// Condition is a target or a condition: a disjunction of conjunctions of atoms,
// since the language has neither parentheses nor a standalone NOT. Every
// conjunction holds at least one atom, and there is at least one conjunction.
// A nil *Condition is an absent target or condition.
type Condition struct {
	Place     Place
	Disjuncts [][]Atom
}

// NewCondition returns the condition at place made of disjuncts, copying them.
// It returns an error when place is unknown, when there are no disjuncts or a
// disjunct is empty, or when an atom is invalid.
func NewCondition(place Place, disjuncts ...[]Atom) (*Condition, error) {
	c := &Condition{Place: place, Disjuncts: make([][]Atom, len(disjuncts))}
	for i, d := range disjuncts {
		c.Disjuncts[i] = slices.Clone(d)
	}
	if err := validateCondition(c); err != nil {
		return nil, err
	}
	return c, nil
}

// HasOr reports whether the condition has more than one disjunct.
func (c *Condition) HasOr() bool {
	return len(c.Disjuncts) > 1
}

func validateCondition(c *Condition) error {
	if !slices.Contains(places, c.Place) {
		return fmt.Errorf("condition: place %q unknown", c.Place)
	}
	if len(c.Disjuncts) == 0 {
		return errors.New("condition: no disjuncts")
	}
	for i, d := range c.Disjuncts {
		if len(d) == 0 {
			return fmt.Errorf("condition: disjunct %d is empty", i)
		}
		for j, a := range d {
			if err := validateAtom(a); err != nil {
				return fmt.Errorf("condition: disjunct %d, atom %d: %w", i, j, err)
			}
		}
	}
	return nil
}

func validateAtom(a Atom) error {
	switch v := a.(type) {
	case nil:
		return errors.New("atom: nil")
	case Const, IsM2M, Access:
		return nil
	case Compare:
		return validateCompare(v)
	case Unsupported:
		return validateUnsupported(v)
	default:
		return fmt.Errorf("atom: unknown type %T", a)
	}
}
