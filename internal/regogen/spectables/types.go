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

package spectables

import "slices"

// Operator is a comparison operator of the policy language, spelled as the
// specification spells it: IS_NOT_NULL, not "IS NOT NULL".
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

// Operators lists every comparison operator. An export must cover each one.
var Operators = []Operator{
	OpEQ, OpNE, OpLT, OpLE, OpGT, OpGE, OpIsNull, OpIsNotNull, OpIsEmpty, OpIsNotEmpty,
	OpIn, OpNotIn, OpContains, OpNotContains, OpContainsAny, OpNotContainsAny,
	OpIsSubset, OpIsNotSubset, OpMatch, OpNotMatch,
}

// Unary reports whether the operator takes no right operand.
func (o Operator) Unary() bool {
	switch o {
	case OpIsNull, OpIsNotNull, OpIsEmpty, OpIsNotEmpty:
		return true
	default:
		return false
	}
}

// Kind is the kind of an operand: what the operand reads, not the value it
// holds. Each name is the specification's own, except that the specification's
// single kind for a declared PIP is split here by pipType.
type Kind string

// The operand kinds.
const (
	KindOperation    Kind = "operation"
	KindResourceType Kind = "resourceType"

	// KindResource is the whole resource, KindResPath a path with one step,
	// KindResNested a path with several steps, and KindResJSONPath a path with
	// an index, a filter, a wildcard, or a recursive descent.
	KindResource    Kind = "resource"
	KindResPath     Kind = "res:path"
	KindResNested   Kind = "res:nested"
	KindResJSONPath Kind = "res:jsonpath"

	KindSubjID              Kind = "subj.id"
	KindSubjName            Kind = "subj.name"
	KindSubjType            Kind = "subj.type"
	KindSubjServiceAccount  Kind = "subj.serviceAccount"
	KindSubjRoles           Kind = "subj.roles"
	KindSubjScopes          Kind = "subj.scopes"
	KindSubjPermissions     Kind = "subj.permissions"
	KindSubjPermissionScope Kind = "subj.permissionScope"
	KindSubjIsM2M           Kind = "subj.isM2M"

	KindPIPToken    Kind = "pip:TOKEN"
	KindPIPHeader   Kind = "pip:HEADER"
	KindPIPGeneral  Kind = "pip:GENERAL"
	KindPIPFiltered Kind = "pip:FILTERED"
	KindPIPMapping  Kind = "pip:MAPPING"

	// KindEntitled is subject.entitledResources.of(...).as(...).
	KindEntitled Kind = "ent"

	KindLitStr  Kind = "lit:str"
	KindLitNum  Kind = "lit:num"
	KindLitBool Kind = "lit:bool"
	KindNull    Kind = "null"

	// The list literal kinds: all numbers or not, one element or several.
	KindListStr1 Kind = "list:str1"
	KindListStrN Kind = "list:strn"
	KindListNum1 Kind = "list:num1"
	KindListNumN Kind = "list:numn"

	// KindPattern is the right operand of MATCH and NOT_MATCH, and of no other
	// operator.
	KindPattern Kind = "pattern"
)

// Kinds lists every operand kind. An export must declare a domain for each one
// and cover each one in every position its operators admit.
var Kinds = []Kind{
	KindOperation, KindResourceType,
	KindResource, KindResPath, KindResNested, KindResJSONPath,
	KindSubjID, KindSubjName, KindSubjType, KindSubjServiceAccount, KindSubjRoles, KindSubjScopes,
	KindSubjPermissions, KindSubjPermissionScope, KindSubjIsM2M,
	KindPIPToken, KindPIPHeader, KindPIPGeneral, KindPIPFiltered, KindPIPMapping,
	KindEntitled,
	KindLitStr, KindLitNum, KindLitBool, KindNull,
	KindListStr1, KindListStrN, KindListNum1, KindListNumN,
	KindPattern,
}

// State is the state an operand resolves to on a request. Every state except
// VALUE is one the specification gives its own outcome, independent of any value.
type State string

// The operand states.
const (
	StateValue        State = "VALUE"
	StateAbsent       State = "ABSENT"
	StateNull         State = "NULL"
	StatePIPEmpty     State = "PIP_EMPTY"
	StateEmptyColl    State = "EMPTY_COLL"
	StateEmptySel     State = "EMPTY_SEL"
	StateIndexOOB     State = "INDEX_OOB"
	StatePIPNull      State = "PIP_NULL"
	StateError        State = "ERROR"
	StateSingleOdd    State = "SINGLE_ODD"
	StateScalarOdd    State = "SCALAR_ODD"
	StateScopeOutside State = "SCOPE_OUTSIDE"
)

// States lists every operand state.
var States = []State{
	StateValue, StateAbsent, StateNull, StatePIPEmpty, StateEmptyColl, StateEmptySel,
	StateIndexOOB, StatePIPNull, StateError, StateSingleOdd, StateScalarOdd, StateScopeOutside,
}

// Class is the class of value an operand in state VALUE holds.
type Class string

// The value classes.
const (
	// ClassString is a string.
	ClassString Class = "s"
	// ClassScalar is a number or a boolean.
	ClassScalar Class = "n"
	// ClassList is a list of scalars.
	ClassList Class = "l"
	// ClassHeaderList is a list of scalars read from a HEADER or GENERAL PIP.
	ClassHeaderList Class = "hl"
	// ClassOther is any other value, such as an object or a nested list.
	ClassOther Class = "x"
)

// Classes lists every value class.
var Classes = []Class{ClassString, ClassScalar, ClassList, ClassHeaderList, ClassOther}

// Place is where a condition that contains the leaf stands.
type Place string

// The places.
const (
	PlaceSimplified    Place = "simplified"
	PlaceRuleCondition Place = "rule_condition"
	PlaceRuleTarget    Place = "rule_target"
	PlacePolicyTarget  Place = "policy_target"
	PlaceSetTarget     Place = "set_target"
)

// Places lists every place.
var Places = []Place{PlaceSimplified, PlaceRuleCondition, PlaceRuleTarget, PlacePolicyTarget, PlaceSetTarget}

// Effect is the effect of the rule the leaf belongs to.
type Effect string

// The effects.
const (
	EffectAllow Effect = "ALLOW"
	EffectDeny  Effect = "DENY"
)

// Effects lists every effect.
var Effects = []Effect{EffectAllow, EffectDeny}

// Profile names a behavior the tables describe.
type Profile string

// The profiles.
const (
	// ProfileLegacy is what the legacy service does.
	ProfileLegacy Profile = "legacy"
	// ProfileAgent is the legacy behavior with the differences the agent
	// makes on purpose; the generator reads this profile.
	ProfileAgent Profile = "agent"
)

// Profiles lists every profile. An export must carry each one.
var Profiles = []Profile{ProfileLegacy, ProfileAgent}

// Outcome is what a leaf evaluates to.
type Outcome string

// The outcomes.
const (
	// OutcomeT is true: the leaf is on its true rail.
	OutcomeT Outcome = "T"
	// OutcomeF is false: the leaf is on its false rail.
	OutcomeF Outcome = "F"
	// OutcomeU is unknown, in the agent profile only: the leaf is on neither
	// rail.
	OutcomeU Outcome = "U"
	// OutcomeAbort ends the rule, in the legacy profile only.
	OutcomeAbort Outcome = "ABORT"
	// OutcomeErr fails the decision on the resource, in the legacy profile only.
	OutcomeErr Outcome = "ERR"
	// OutcomeBadRequest rejects the request with 400.
	OutcomeBadRequest Outcome = "bad_request"
	// OutcomeUnsupported marks a form the specification does not evaluate.
	OutcomeUnsupported Outcome = "unsupported"
	// OutcomeByValue marks a cell whose outcome depends on the operand values;
	// [Cell.Outcomes] lists the outcomes the values can produce.
	OutcomeByValue Outcome = "by_value"
)

// Outcomes lists the outcomes a cell of the profile may carry, by_value
// included, and reports false for an unknown profile.
func Outcomes(p Profile) ([]Outcome, bool) {
	switch p {
	case ProfileAgent:
		return []Outcome{OutcomeT, OutcomeF, OutcomeU, OutcomeBadRequest, OutcomeUnsupported, OutcomeByValue}, true
	case ProfileLegacy:
		return []Outcome{OutcomeT, OutcomeF, OutcomeAbort, OutcomeErr, OutcomeBadRequest, OutcomeUnsupported, OutcomeByValue}, true
	default:
		return nil, false
	}
}

// valueOutcomes lists the outcomes a by_value cell of the profile may list.
func valueOutcomes(p Profile) []Outcome {
	if p == ProfileAgent {
		return []Outcome{OutcomeT, OutcomeF, OutcomeU}
	}
	return []Outcome{OutcomeT, OutcomeF, OutcomeAbort, OutcomeErr}
}

// RequiredKnobs lists the specification settings every profile of an export
// carries, and no other: a knob is added here and to schema.json when a
// template of the generator starts to read it.
var RequiredKnobs = []string{"fold", "eq_numeric", "list_eq_by_value", "subset_fold"}

// Domain is what an operand of one kind can resolve to: its states and, when
// the states include VALUE, the classes of value it can hold.
type Domain struct {
	States  []State `json:"states"`
	Classes []Class `json:"classes,omitempty"`
}

// Point is one concrete operand: its kind, its state, and its class. Class is
// set exactly when State is VALUE.
type Point struct {
	Kind  Kind
	State State
	Class Class
}

// Context is where a leaf stands.
type Context struct {
	Place       Place
	Effect      Effect
	Disjunction bool // the condition contains OR
	InIterate   bool // the leaf is evaluated in a pass of iterate
}

// Key is the question [Table.Lookup] answers. Right is the zero Point for a
// unary operator.
type Key struct {
	Op          Operator
	Left, Right Point
	Context     Context
}

// Cell is the answer to a [Key].
type Cell struct {
	Outcome Outcome
	// Outcomes lists, for an Outcome of by_value, the outcomes the operand
	// values can produce; it is nil otherwise.
	Outcomes []Outcome
}

func admitsRight(op Operator, k Kind) bool {
	if op == OpMatch || op == OpNotMatch {
		return k == KindPattern
	}
	return k != KindPattern
}

func admitsLeft(k Kind) bool {
	return k != KindPattern
}

func known[T comparable](all []T, v T) bool {
	return slices.Contains(all, v)
}
