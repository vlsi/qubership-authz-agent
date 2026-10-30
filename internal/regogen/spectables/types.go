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
	// ClassNullElement is a list with a null element.
	ClassNullElement Class = "xn"
	// ClassNested is a list with a list or an object element, and no null
	// element.
	ClassNested Class = "xl"
	// ClassObject is an object.
	ClassObject Class = "xo"
	// ClassNull is a null value in state VALUE, such as a whole resource that
	// is JSON null; it differs from state NULL.
	ClassNull Class = "z"
	// ClassOther is the one class of schema version 1 for an object, a nested
	// list, and a list with a null element; version 2 splits it into
	// ClassNullElement, ClassNested, and ClassObject.
	ClassOther Class = "x"
)

// Classes lists every value class of schema version 2.
var Classes = []Class{ClassString, ClassScalar, ClassList, ClassHeaderList, ClassNullElement, ClassNested,
	ClassObject, ClassNull}

// classesV1 lists the value classes of schema version 1.
var classesV1 = []Class{ClassString, ClassScalar, ClassList, ClassHeaderList, ClassOther}

// ValueRule names the branch of the specification that decides a by_value
// cell from the operand values.
type ValueRule string

// The value rules. A negated operator reports the rule of the operator it
// negates.
const (
	// RuleEq compares two scalars under == and !=: fold, numbers, Java text.
	RuleEq ValueRule = "eq"
	// RuleListEq compares two lists under ==.
	RuleListEq ValueRule = "list_eq"
	// RuleStructureTextLeft compares a list or an object on the left with a
	// string on the right by the Java text of the structure.
	RuleStructureTextLeft ValueRule = "structure_text_left"
	// RuleArrayEq is == with a list on the left that the structure text does
	// not decide.
	RuleArrayEq ValueRule = "array_eq"
	// RuleObjectEq compares two objects under IN and CONTAINS.
	RuleObjectEq ValueRule = "object_eq"
	// RuleRel is <, <=, >, and >=.
	RuleRel ValueRule = "rel"
	// RuleEmpty is IS EMPTY and IS NOT EMPTY over a value.
	RuleEmpty ValueRule = "empty"
	// RuleInAny is IN over a scalar: some element equal.
	RuleInAny ValueRule = "in_any"
	// RuleContainsAny is CONTAINS and CONTAINS ANY: some pair equal.
	RuleContainsAny ValueRule = "contains_any"
	// RuleContainsRightAttributeList is CONTAINS with an attribute list on the
	// right.
	RuleContainsRightAttributeList ValueRule = "contains_right_attribute_list"
	// RuleSubset is IS SUBSET.
	RuleSubset ValueRule = "subset"
	// RuleMatch is the pattern of MATCH.
	RuleMatch ValueRule = "match"
	// RuleNullElementEnds is a null element of a list that ends the rule
	// before the values are compared.
	RuleNullElementEnds ValueRule = "null_element_ends"
	// RuleRightListScalarOps is a list on the right of ==, !=, CONTAINS, or
	// NOT CONTAINS.
	RuleRightListScalarOps ValueRule = "right_list_scalar_ops"
	// RuleSingleOdd is a one-element GENERAL list of null, a boolean, or an
	// object, read as a value.
	RuleSingleOdd ValueRule = "single_odd"
	// RuleScalarOddRel is a GENERAL body that is a number or a boolean
	// (state SCALAR_ODD) on either side of <, <=, >, or >=: a boolean and a
	// number each give the outcome their setting names, before the values
	// are compared.
	RuleScalarOddRel ValueRule = "scalar_odd_rel"
)

// ValueRules lists every value rule.
var ValueRules = []ValueRule{RuleEq, RuleListEq, RuleStructureTextLeft, RuleArrayEq, RuleObjectEq, RuleRel,
	RuleEmpty, RuleInAny, RuleContainsAny, RuleContainsRightAttributeList, RuleSubset, RuleMatch,
	RuleNullElementEnds, RuleRightListScalarOps, RuleSingleOdd, RuleScalarOddRel}

// NodeOutcome is the outcome of a node of the policy tree.
type NodeOutcome string

// The node outcomes.
const (
	NodePermit        NodeOutcome = "permit"
	NodeDeny          NodeOutcome = "deny"
	NodeNotApplicable NodeOutcome = "na"
)

// NodeOutcomes lists every node outcome.
var NodeOutcomes = []NodeOutcome{NodePermit, NodeDeny, NodeNotApplicable}

// Algorithms lists the combining algorithms a node may name.
var Algorithms = []string{"DENY_UNLESS_PERMIT", "PERMIT_OVERRIDES", "DENY_OVERRIDES", "PERMIT_UNLESS_DENY"}

// RuleEffects lists the rule effects other than ALLOW and DENY that the
// effects of [Nodes] map, with "other" for every effect not listed.
var RuleEffects = []string{"USE_FILTER_CONDITION", "NOT_APPLICABLE", "other"}

// AbsentEffects lists what a rule without an effect may count as: ALLOW,
// DENY, or the effects entry "other".
var AbsentEffects = []string{"ALLOW", "DENY", "other"}

// Combination is the outcome of a node by what its applicable children give:
// some permit and no deny, some deny and no permit, both, and neither.
type Combination struct {
	Permit NodeOutcome `json:"permit"`
	Deny   NodeOutcome `json:"deny"`
	Both   NodeOutcome `json:"both"`
	None   NodeOutcome `json:"none"`
}

// Nodes holds how the specification combines the outcomes of the nodes above
// the leaves.
type Nodes struct {
	// Algorithms maps each name of [Algorithms] to its combination.
	Algorithms map[string]Combination `json:"algorithms"`
	// AbsentAlgorithm is the algorithm of a node that names none.
	AbsentAlgorithm string `json:"absent_algorithm"`
	// Effects maps each name of [RuleEffects] to the node outcome of a rule
	// with that effect whose target and condition hold.
	Effects map[string]NodeOutcome `json:"effects"`
	// AbsentEffect is what a rule without an effect counts as, one of
	// [AbsentEffects].
	AbsentEffect string `json:"absent_effect"`
	// AbsentExpression is the value of an absent target or condition: T or F.
	AbsentExpression Outcome `json:"absent_expression"`
}

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
// of schema version 2 carries, and no other: a knob is added here and to
// schema.json when a template of the generator starts to read it.
// right_list_scalar_ops is the outcome of ==, !=, CONTAINS, and NOT CONTAINS
// with a list of two or more values on the right that is not a literal list,
// and right_list_attribute says whether a resource attribute there is
// compared instead (EVAL).
var RequiredKnobs = []string{"fold", "eq_numeric", "list_eq_by_value", "subset_fold", "right_list_scalar_ops",
	"right_list_attribute"}

// knobsV1 lists the knobs of schema version 1.
var knobsV1 = []string{"fold", "eq_numeric", "list_eq_by_value", "subset_fold"}

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
	// ValueRule lists, for an Outcome of by_value in schema version 2, the
	// value rules the specification went through, sorted; it is nil otherwise.
	ValueRule []ValueRule
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
