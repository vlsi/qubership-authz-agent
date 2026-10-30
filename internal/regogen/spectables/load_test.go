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

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// The operators and operand kinds every export must cover, written out here
// rather than taken from the package, so that a list shrunk in the package
// leaves combinations of the fixture uncovered by the loader's check.
var (
	fixtureOps = []string{"EQ", "NE", "LT", "LE", "GT", "GE", "IS_NULL", "IS_NOT_NULL", "IS_EMPTY",
		"IS_NOT_EMPTY", "IN", "NOT_IN", "CONTAINS", "NOT_CONTAINS", "CONTAINS_ANY", "NOT_CONTAINS_ANY",
		"IS_SUBSET", "IS_NOT_SUBSET", "MATCH", "NOT_MATCH"}
	fixtureUnary = []string{"IS_NULL", "IS_NOT_NULL", "IS_EMPTY", "IS_NOT_EMPTY"}
	fixtureKinds = []string{"operation", "resourceType", "resource", "res:path", "res:nested", "res:jsonpath",
		"subj.id", "subj.name", "subj.type", "subj.serviceAccount", "subj.roles", "subj.scopes",
		"subj.permissions", "subj.permissionScope", "subj.isM2M",
		"pip:TOKEN", "pip:HEADER", "pip:GENERAL", "pip:FILTERED", "pip:MAPPING", "ent",
		"lit:str", "lit:num", "lit:bool", "null", "list:str1", "list:strn", "list:num1", "list:numn", "pattern"}
)

type doc = map[string]any

// The cells of EQ(res:path, lit:str) in the agent profile of completeExport,
// where res:path has the domain {VALUE/s, VALUE/l, NULL}. Every other
// combination has one cell of outcome F that matches every point.
const (
	eqNullOr           = iota // left NULL, disjunction -> F
	eqNullIterate             // left NULL, no disjunction, in_iterate -> U
	eqNullDeny                // left NULL, neither, effect DENY -> T
	eqNullAllow               // left NULL, neither, effect ALLOW -> F
	eqValueS                  // left VALUE/s -> by_value [T, F]
	eqValueLRuleTarget        // left VALUE/l, place rule_target -> bad_request
	// Then left VALUE/l, one cell for each other place -> U.
)

func completeExport() doc {
	return doc{
		"schema_version": 2,
		"spec_tag":       "r99",
		"profiles": doc{
			"legacy": fixtureProfile(nil),
			"agent":  fixtureProfile(eqResPathLitStrCells()),
		},
	}
}

func eqResPathLitStrCells() []any {
	left := func(state, class string) doc {
		s := doc{"kind": "res:path", "state": state}
		if class != "" {
			s["class"] = class
		}
		return s
	}
	right := doc{"kind": "lit:str"}
	cells := []any{
		eqNullOr: doc{"op": "EQ", "left": left("NULL", ""), "right": right, "disjunction": true, "outcome": "F"},
		eqNullIterate: doc{"op": "EQ", "left": left("NULL", ""), "right": right, "disjunction": false, "in_iterate": true,
			"outcome": "U"},
		eqNullDeny: doc{"op": "EQ", "left": left("NULL", ""), "right": right, "disjunction": false, "in_iterate": false,
			"effect": "DENY", "outcome": "T"},
		eqNullAllow: doc{"op": "EQ", "left": left("NULL", ""), "right": right, "disjunction": false, "in_iterate": false,
			"effect": "ALLOW", "outcome": "F"},
		eqValueS: doc{"op": "EQ", "left": left("VALUE", "s"), "right": right, "outcome": "by_value", "outcomes": []any{"T", "F"},
			"value_rule": []any{"eq"}},
		eqValueLRuleTarget: doc{"op": "EQ", "left": left("VALUE", "l"), "right": right, "place": "rule_target",
			"outcome": "bad_request"},
	}
	for _, place := range []string{"simplified", "rule_condition", "policy_target", "set_target"} {
		cells = append(cells, doc{"op": "EQ", "left": left("VALUE", "l"), "right": right, "place": place, "outcome": "U"})
	}
	return cells
}

// fixtureProfile covers every combination with a cell of outcome F that matches
// every point, except EQ(res:path, lit:str) when eq is not nil.
func fixtureProfile(eq []any) doc {
	kinds := doc{}
	for _, k := range fixtureKinds {
		kinds[k] = doc{"states": []any{"VALUE", "NULL"}, "classes": []any{"s"}}
	}
	kinds["res:path"] = doc{"states": []any{"VALUE", "NULL"}, "classes": []any{"s", "l"}}
	kinds["lit:str"] = doc{"states": []any{"VALUE"}, "classes": []any{"s"}}
	kinds["pattern"] = doc{"states": []any{"VALUE"}, "classes": []any{"s"}}

	var cells []any
	for _, op := range fixtureOps {
		for _, lk := range fixtureKinds {
			if lk == "pattern" {
				continue
			}
			for _, rk := range fixtureRights(op) {
				if op == "EQ" && lk == "res:path" && rk == "lit:str" && eq != nil {
					cells = append(cells, eq...)
					continue
				}
				c := doc{"op": op, "left": doc{"kind": lk}, "outcome": "F"}
				if rk != "" {
					c["right"] = doc{"kind": rk}
				}
				cells = append(cells, c)
			}
		}
	}
	return doc{
		"knobs": doc{"fold": "java", "eq_numeric": false, "list_eq_by_value": true, "subset_fold": false,
			"right_list_scalar_ops": "ABORT", "right_list_attribute": "EVAL", "string_list_split": "SPLIT_TRIM",
			"idiom_list_item_trim": "java_trim"},
		"kinds": kinds,
		"nodes": fixtureNodes(),
		"cells": cells,
	}
}

// fixtureNodes are the default node rules of the specification.
func fixtureNodes() doc {
	combination := func(both, none string) doc {
		return doc{"permit": "permit", "deny": "deny", "both": both, "none": none}
	}
	return doc{
		"algorithms": doc{
			"DENY_UNLESS_PERMIT": combination("permit", "deny"),
			"PERMIT_OVERRIDES":   combination("permit", "na"),
			"DENY_OVERRIDES":     combination("deny", "na"),
			"PERMIT_UNLESS_DENY": combination("deny", "permit"),
		},
		"absent_algorithm":  "DENY_UNLESS_PERMIT",
		"effects":           doc{"USE_FILTER_CONDITION": "deny", "NOT_APPLICABLE": "na", "other": "na"},
		"absent_effect":     "other",
		"absent_expression": "T",
	}
}

func nodesOf(d doc) doc { return profileOf(d, "agent")["nodes"].(doc) }

// versionOne returns completeExport in schema version 1: no nodes, no value
// rules, and class x.
func versionOne() doc {
	d := completeExport()
	d["schema_version"] = 1
	for _, p := range []string{"legacy", "agent"} {
		delete(profileOf(d, p), "nodes")
		profileOf(d, p)["kinds"].(doc)["res:path"] = doc{"states": []any{"VALUE", "NULL"}, "classes": []any{"s", "l", "x"}}
	}
	delete(eqCell(d, eqValueS), "value_rule")
	for _, p := range []string{"legacy", "agent"} {
		delete(profileOf(d, p)["knobs"].(doc), "right_list_scalar_ops")
		delete(profileOf(d, p)["knobs"].(doc), "right_list_attribute")
		delete(profileOf(d, p)["knobs"].(doc), "string_list_split")
		delete(profileOf(d, p)["knobs"].(doc), "idiom_list_item_trim")
	}
	pr := profileOf(d, "agent")
	pr["cells"] = append(agentCells(d), doc{"op": "EQ", "left": doc{"kind": "res:path", "state": "VALUE", "class": "x"},
		"right": doc{"kind": "lit:str"}, "outcome": "F"})
	return d
}

func fixtureRights(op string) []string {
	switch {
	case slices.Contains(fixtureUnary, op):
		return []string{""}
	case op == "MATCH" || op == "NOT_MATCH":
		return []string{"pattern"}
	default:
		return slices.DeleteFunc(slices.Clone(fixtureKinds), func(k string) bool { return k == "pattern" })
	}
}

func profileOf(d doc, p string) doc { return d["profiles"].(doc)[p].(doc) }

func agentCells(d doc) []any { return profileOf(d, "agent")["cells"].([]any) }

// removeCells drops the agent cells for which drop returns true.
func removeCells(d doc, drop func(c doc) bool) {
	pr := profileOf(d, "agent")
	pr["cells"] = slices.DeleteFunc(agentCells(d), func(c any) bool { return drop(c.(doc)) })
}

func kindOf(side any) string {
	if side == nil {
		return ""
	}
	return side.(doc)["kind"].(string)
}

func isCombo(c doc, op, left, right string) bool {
	return c["op"] == op && kindOf(c["left"]) == left && kindOf(c["right"]) == right
}

// eqCell returns cell i of EQ(res:path, lit:str) in the agent profile, one of
// the eq constants.
func eqCell(d doc, i int) doc {
	n := 0
	for _, c := range agentCells(d) {
		if isCombo(c.(doc), "EQ", "res:path", "lit:str") {
			if n == i {
				return c.(doc)
			}
			n++
		}
	}
	panic("no such cell")
}

func load(t *testing.T, d doc) (*Table, error) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal(fixture): %v", err)
	}
	return Load(bytes.NewReader(b))
}

func mustLoad(t *testing.T, d doc) *Table {
	t.Helper()
	tab, err := load(t, d)
	if err != nil {
		t.Fatalf("Load(complete export) error = %v, want nil", err)
	}
	return tab
}

func ruleCondition() Context {
	return Context{Place: PlaceRuleCondition, Effect: EffectAllow}
}

func TestLookupFindsTheCellThatCoversTheKey(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeExport())
	resPath := func(s State, c Class) Point { return Point{Kind: KindResPath, State: s, Class: c} }
	litStr := Point{Kind: KindLitStr, State: StateValue, Class: ClassString}
	tests := []struct {
		name string
		key  Key
		want Cell
	}{
		{
			name: "a cell narrowed by disjunction matches every place, effect, and iteration",
			key:  Key{Op: OpEQ, Left: resPath(StateNull, ""), Right: litStr, Context: Context{Place: PlaceSetTarget, Effect: EffectDeny, Disjunction: true, InIterate: true}},
			want: Cell{Outcome: OutcomeF},
		},
		{
			name: "a cell narrowed by iteration answers inside iterate",
			key:  Key{Op: OpEQ, Left: resPath(StateNull, ""), Right: litStr, Context: Context{Place: PlaceRuleCondition, Effect: EffectAllow, InIterate: true}},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "a cell narrowed by effect answers for DENY",
			key:  Key{Op: OpEQ, Left: resPath(StateNull, ""), Right: litStr, Context: Context{Place: PlaceRuleCondition, Effect: EffectDeny}},
			want: Cell{Outcome: OutcomeT},
		},
		{
			name: "a cell narrowed by effect answers for ALLOW",
			key:  Key{Op: OpEQ, Left: resPath(StateNull, ""), Right: litStr, Context: Context{Place: PlaceRuleCondition, Effect: EffectAllow}},
			want: Cell{Outcome: OutcomeF},
		},
		{
			name: "a value cell lists the outcomes the values produce and the rule that decides them",
			key:  Key{Op: OpEQ, Left: resPath(StateValue, ClassString), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeByValue, Outcomes: []Outcome{OutcomeT, OutcomeF}, ValueRule: []ValueRule{RuleEq}},
		},
		{
			name: "a cell narrowed to one place answers in that place",
			key:  Key{Op: OpEQ, Left: resPath(StateValue, ClassList), Right: litStr, Context: Context{Place: PlaceRuleTarget, Effect: EffectAllow}},
			want: Cell{Outcome: OutcomeBadRequest},
		},
		{
			name: "a cell narrowed to another place answers there",
			key:  Key{Op: OpEQ, Left: resPath(StateValue, ClassList), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "a unary operator is looked up without a right side",
			key:  Key{Op: OpIsNull, Left: resPath(StateValue, ClassList), Context: ruleCondition()},
			want: Cell{Outcome: OutcomeF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tab.Lookup(ProfileAgent, tt.key)
			if err != nil {
				t.Fatalf("Lookup(agent, %+v) error = %v, want nil", tt.key, err)
			}
			if got.Outcome != tt.want.Outcome || !slices.Equal(got.Outcomes, tt.want.Outcomes) ||
				!slices.Equal(got.ValueRule, tt.want.ValueRule) {
				t.Errorf("Lookup(agent, %+v) = %+v, want %+v", tt.key, got, tt.want)
			}
		})
	}
}

func TestLookupReadsTheProfileItIsGiven(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeExport())
	key := Key{
		Op:      OpEQ,
		Left:    Point{Kind: KindResPath, State: StateNull},
		Right:   Point{Kind: KindLitStr, State: StateValue, Class: ClassString},
		Context: Context{Place: PlaceRuleCondition, Effect: EffectDeny},
	}
	tests := []struct {
		prof Profile
		want Outcome
	}{
		{ProfileAgent, OutcomeT},
		{ProfileLegacy, OutcomeF},
	}
	for _, tt := range tests {
		got, err := tab.Lookup(tt.prof, key)
		if err != nil || got.Outcome != tt.want {
			t.Errorf("Lookup(%s, %+v) = %+v, %v, want outcome %s", tt.prof, key, got, err, tt.want)
		}
	}
}

func TestLoadKeepsTheSpecTagAndKnobs(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeExport())
	if got := tab.SpecTag(); got != "r99" {
		t.Errorf("SpecTag() = %q, want %q", got, "r99")
	}
	if got, ok := tab.Knob(ProfileAgent, "fold"); !ok || string(got) != `"java"` {
		t.Errorf(`Knob(agent, "fold") = %s, %t, want "java", true`, got, ok)
	}
}

func TestLookupRefusesAKeyOutsideTheTable(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeExport())
	litStr := Point{Kind: KindLitStr, State: StateValue, Class: ClassString}
	// IS_NULL(res:path) has one cell that matches every state, class, and
	// context, so only the check of the key itself can refuse the keys on it.
	tests := []struct {
		name string
		key  Key
		prof Profile // agent when empty
	}{
		{
			name: "a state outside the kind's domain",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateError}, Context: ruleCondition()},
		},
		{
			name: "a class outside the kind's domain",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateValue, Class: ClassOther}, Context: ruleCondition()},
		},
		{
			name: "a class beside a state other than VALUE",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateNull, Class: ClassString}, Context: ruleCondition()},
		},
		{
			name: "a right side for a unary operator",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateNull}, Right: litStr, Context: ruleCondition()},
		},
		{
			name: "no right side for a binary operator",
			key:  Key{Op: OpEQ, Left: Point{Kind: KindResPath, State: StateNull}, Context: ruleCondition()},
		},
		{
			name: "an unknown profile",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateNull}, Context: ruleCondition()},
			prof: "stage2",
		},
		{
			name: "an unknown place",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateNull}, Context: Context{Place: "filter", Effect: EffectAllow}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prof := tt.prof
			if prof == "" {
				prof = ProfileAgent
			}
			got, err := tab.Lookup(prof, tt.key)
			if !errors.Is(err, ErrNotCovered) {
				t.Errorf("Lookup(%s, %+v) = %+v, %v, want ErrNotCovered", prof, tt.key, got, err)
			}
		})
	}
}

func TestLoadRejectsAnIncompleteExport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(d doc)
		names string // the part of the error that names what is missing
	}{
		{
			name:  "an operator with no cells",
			edit:  func(d doc) { removeCells(d, func(c doc) bool { return c["op"] == "NE" }) },
			names: "agent: NE(operation, operation) has no cells",
		},
		{
			name: "one combination with no cells",
			edit: func(d doc) {
				removeCells(d, func(c doc) bool { return isCombo(c, "CONTAINS", "pip:GENERAL", "list:strn") })
			},
			names: "agent: CONTAINS(pip:GENERAL, list:strn) has no cells",
		},
		{
			name:  "an operand kind with no domain",
			edit:  func(d doc) { delete(profileOf(d, "agent")["kinds"].(doc), "pip:MAPPING") },
			names: "agent: operand kind pip:MAPPING has no domain",
		},
		{
			name: "a hole in one context",
			edit: func(d doc) {
				removeCells(d, func(c doc) bool { return c["place"] == "rule_condition" && isCombo(c, "EQ", "res:path", "lit:str") })
			},
			names: "agent: EQ(res:path, lit:str): no cell covers 8 points, the first at left VALUE/l, right VALUE/s, place rule_condition",
		},
		{
			name:  "a hole in one effect",
			edit:  func(d doc) { removeCells(d, func(c doc) bool { return c["effect"] == "DENY" }) },
			names: "agent: EQ(res:path, lit:str): no cell covers 5 points, the first at left NULL, right VALUE/s, place simplified, effect DENY, disjunction false, in_iterate false",
		},
		{
			name:  "a profile",
			edit:  func(d doc) { delete(d["profiles"].(doc), "agent") },
			names: "profile agent is missing",
		},
		{
			name:  "a knob",
			edit:  func(d doc) { delete(profileOf(d, "agent")["knobs"].(doc), "subset_fold") },
			names: "agent: knob subset_fold is missing",
		},
		{
			name:  "a knob of schema version 2",
			edit:  func(d doc) { delete(profileOf(d, "agent")["knobs"].(doc), "right_list_scalar_ops") },
			names: "agent: knob right_list_scalar_ops is missing",
		},
		{
			name:  "the node rules",
			edit:  func(d doc) { delete(profileOf(d, "agent"), "nodes") },
			names: "agent: nodes is missing",
		},
		{
			name:  "an algorithm",
			edit:  func(d doc) { delete(nodesOf(d)["algorithms"].(doc), "PERMIT_UNLESS_DENY") },
			names: "agent: nodes: algorithm PERMIT_UNLESS_DENY is missing",
		},
		{
			name:  "a rule effect",
			edit:  func(d doc) { delete(nodesOf(d)["effects"].(doc), "other") },
			names: "agent: nodes: rule effect other is missing",
		},
		{
			name:  "one outcome of an algorithm",
			edit:  func(d doc) { delete(nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"].(doc), "none") },
			names: "agent: nodes: DENY_OVERRIDES.none is missing",
		},
		{
			name:  "the absent algorithm",
			edit:  func(d doc) { delete(nodesOf(d), "absent_algorithm") },
			names: "agent: nodes: absent_algorithm is missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := completeExport()
			tt.edit(d)
			_, err := load(t, d)
			if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), tt.names) {
				t.Errorf("Load() error = %v, want ErrIncomplete naming %q", err, tt.names)
			}
		})
	}
}

func TestLoadRejectsAnInvalidExport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(d doc)
		names string // the part of the error that names the problem
	}{
		{
			name:  "a provenance field",
			edit:  func(d doc) { eqCell(d, eqNullOr)["prov"] = "recorded by case 17" },
			names: `unknown field "prov"`,
		},
		{
			name:  "a provenance knob",
			edit:  func(d doc) { profileOf(d, "agent")["knobs"].(doc)["fold_prov"] = "recorded by case 17" },
			names: `agent: unknown knob "fold_prov"`,
		},
		{
			name:  "an empty spec tag",
			edit:  func(d doc) { d["spec_tag"] = "" },
			names: "spec_tag is empty",
		},
		{
			name:  "another schema version",
			edit:  func(d doc) { d["schema_version"] = 3 },
			names: "schema_version is 3, want 2",
		},
		{
			name:  "a by_value cell without a value rule",
			edit:  func(d doc) { delete(eqCell(d, eqValueS), "value_rule") },
			names: "by_value has no value_rule",
		},
		{
			name:  "an unknown value rule",
			edit:  func(d doc) { eqCell(d, eqValueS)["value_rule"] = []any{"eq", "regex_lookahead"} },
			names: `unknown value rule "regex_lookahead"`,
		},
		{
			name:  "value rules out of order",
			edit:  func(d doc) { eqCell(d, eqValueS)["value_rule"] = []any{"null_element_ends", "in_any"} },
			names: "is not sorted, or repeats a rule",
		},
		{
			name:  "a repeated value rule",
			edit:  func(d doc) { eqCell(d, eqValueS)["value_rule"] = []any{"eq", "eq"} },
			names: "is not sorted, or repeats a rule",
		},
		{
			name:  "an unknown outcome of a rule effect",
			edit:  func(d doc) { nodesOf(d)["effects"].(doc)["other"] = "indeterminate" },
			names: `agent: nodes: effects.other has unknown node outcome "indeterminate"`,
		},
		{
			name:  "a value rule on a constant cell",
			edit:  func(d doc) { eqCell(d, eqNullOr)["value_rule"] = []any{"eq"} },
			names: "value_rule is set for outcome F",
		},
		{
			name: "class x in schema version 2",
			edit: func(d doc) {
				profileOf(d, "agent")["kinds"].(doc)["res:path"] = doc{"states": []any{"VALUE", "NULL"}, "classes": []any{"s", "l", "x"}}
			},
			names: `agent: operand kind res:path: class "x" is unknown or repeated`,
		},
		{
			name: "an unknown algorithm",
			edit: func(d doc) {
				nodesOf(d)["algorithms"].(doc)["FIRST_APPLICABLE"] = nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"]
			},
			names: `agent: nodes: unknown algorithm "FIRST_APPLICABLE"`,
		},
		{
			name:  "an unknown node outcome",
			edit:  func(d doc) { nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"].(doc)["none"] = "indeterminate" },
			names: `agent: nodes: DENY_OVERRIDES.none has unknown node outcome "indeterminate"`,
		},
		{
			name:  "an absent algorithm that is not an algorithm",
			edit:  func(d doc) { nodesOf(d)["absent_algorithm"] = "FIRST_APPLICABLE" },
			names: `agent: nodes: absent_algorithm "FIRST_APPLICABLE" is not an algorithm`,
		},
		{
			name:  "an unknown rule effect",
			edit:  func(d doc) { nodesOf(d)["effects"].(doc)["PERMIT"] = "permit" },
			names: `agent: nodes: unknown rule effect "PERMIT"`,
		},
		{
			name:  "an unknown absent effect",
			edit:  func(d doc) { nodesOf(d)["absent_effect"] = "NOT_APPLICABLE" },
			names: `agent: nodes: absent_effect "NOT_APPLICABLE" is not one of`,
		},
		{
			name:  "an absent expression that is undefined",
			edit:  func(d doc) { nodesOf(d)["absent_expression"] = "U" },
			names: `agent: nodes: absent_expression "U" is not T or F`,
		},
		{
			name: "node rules in schema version 1",
			edit: func(d doc) {
				nodes := nodesOf(d)
				for k, v := range versionOne() {
					d[k] = v
				}
				profileOf(d, "agent")["nodes"] = nodes
			},
			names: "agent: nodes is set in schema version 1",
		},
		{
			name: "a value rule in schema version 1",
			edit: func(d doc) {
				for k, v := range versionOne() {
					d[k] = v
				}
				eqCell(d, eqValueS)["value_rule"] = []any{"eq"}
			},
			names: "value_rule is set in schema version 1",
		},
		{
			name:  "an unknown profile",
			edit:  func(d doc) { d["profiles"].(doc)["stage2"] = fixtureProfile(nil) },
			names: `unknown profile "stage2"`,
		},
		{
			name:  "a legacy outcome in the agent profile",
			edit:  func(d doc) { eqCell(d, eqNullOr)["outcome"] = "ABORT" },
			names: `outcome "ABORT" is not an outcome of profile agent`,
		},
		{
			name:  "an agent outcome in the legacy profile",
			edit:  func(d doc) { profileOf(d, "legacy")["cells"].([]any)[0].(doc)["outcome"] = "U" },
			names: `outcome "U" is not an outcome of profile legacy`,
		},
		{
			name:  "a legacy outcome in a by_value list of the agent profile",
			edit:  func(d doc) { eqCell(d, eqValueS)["outcomes"] = []any{"T", "ABORT"} },
			names: `by_value outcome "ABORT" is not an outcome of profile agent`,
		},
		{
			name:  "by_value with one outcome",
			edit:  func(d doc) { eqCell(d, eqValueS)["outcomes"] = []any{"T"} },
			names: "by_value lists 1 outcomes, want at least 2",
		},
		{
			name:  "outcomes beside an outcome other than by_value",
			edit:  func(d doc) { eqCell(d, eqNullOr)["outcomes"] = []any{"T", "F"} },
			names: "outcomes is set for outcome F",
		},
		{
			name: "two cells covering one point",
			edit: func(d doc) {
				pr := profileOf(d, "agent")
				pr["cells"] = append(agentCells(d), doc{"op": "EQ", "left": doc{"kind": "res:path", "state": "NULL"}, "right": doc{"kind": "lit:str"}, "place": "set_target", "outcome": "T"})
			},
			names: "agent: EQ(res:path, lit:str): several cells cover",
		},
		{
			name:  "an unknown operator",
			edit:  func(d doc) { eqCell(d, eqNullOr)["op"] = "LIKE" },
			names: `unknown operator "LIKE"`,
		},
		{
			name:  "a domain for an unknown operand kind",
			edit:  func(d doc) { profileOf(d, "agent")["kinds"].(doc)["pip:REGO"] = doc{"states": []any{"NULL"}} },
			names: `agent: unknown operand kind "pip:REGO"`,
		},
		{
			name: "a right side on a unary operator",
			edit: func(d doc) {
				for _, c := range agentCells(d) {
					if c.(doc)["op"] == "IS_NULL" {
						c.(doc)["right"] = doc{"kind": "lit:str"}
						return
					}
				}
			},
			names: "IS_NULL takes no right side",
		},
		{
			name:  "a pattern on the right of EQ",
			edit:  func(d doc) { eqCell(d, eqNullOr)["right"] = doc{"kind": "pattern"} },
			names: `EQ does not take kind "pattern" on the right`,
		},
		{
			name:  "a pattern on the left",
			edit:  func(d doc) { eqCell(d, eqNullOr)["left"] = doc{"kind": "pattern"} },
			names: `EQ does not take kind "pattern" on the left`,
		},
		{
			name:  "a class without state VALUE",
			edit:  func(d doc) { eqCell(d, eqNullOr)["left"].(doc)["class"] = "s" },
			names: `left class "s" is set without state VALUE`,
		},
		{
			name:  "a class outside the kind's domain",
			edit:  func(d doc) { eqCell(d, eqValueS)["left"].(doc)["class"] = "xo" },
			names: `left class "xo" is not in the domain of res:path`,
		},
		{
			name:  "a state outside the kind's domain",
			edit:  func(d doc) { eqCell(d, eqNullOr)["left"].(doc)["state"] = "ERROR" },
			names: `left state "ERROR" is not in the domain of res:path`,
		},
		{
			name:  "an unknown place",
			edit:  func(d doc) { eqCell(d, eqValueLRuleTarget)["place"] = "filter" },
			names: `unknown place "filter"`,
		},
		{
			name:  "an unknown effect",
			edit:  func(d doc) { eqCell(d, eqNullDeny)["effect"] = "PERMIT" },
			names: `unknown effect "PERMIT"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := completeExport()
			tt.edit(d)
			_, err := load(t, d)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.names) {
				t.Errorf("Load() error = %v, want ErrInvalid naming %q", err, tt.names)
			}
		})
	}
}

// An export written before version 2 still loads: class x, no value rules,
// and no node rules.
func TestLoadReadsSchemaVersion1(t *testing.T) {
	t.Parallel()
	tab, err := load(t, versionOne())
	if err != nil {
		t.Fatalf("Load(version 1 export) error = %v, want nil", err)
	}
	if got := tab.SchemaVersion(); got != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", got)
	}
	if _, ok := tab.Nodes(ProfileAgent); ok {
		t.Errorf("Nodes(agent) reports node rules for a version 1 export, want none")
	}
	key := Key{Op: OpEQ, Left: Point{Kind: KindResPath, State: StateValue, Class: ClassOther},
		Right: Point{Kind: KindLitStr, State: StateValue, Class: ClassString}, Context: ruleCondition()}
	if _, err := tab.Lookup(ProfileAgent, key); err != nil {
		t.Errorf("Lookup(agent, class x) error = %v, want nil", err)
	}
}

func TestNodesReturnsTheNodeRulesOfTheProfile(t *testing.T) {
	t.Parallel()
	d := completeExport()
	nodesOf(d)["algorithms"].(doc)["PERMIT_UNLESS_DENY"].(doc)["none"] = "na"
	tab := mustLoad(t, d)
	agent, ok := tab.Nodes(ProfileAgent)
	if !ok {
		t.Fatalf("Nodes(agent) reports no node rules, want them")
	}
	if got, want := agent.Algorithms["PERMIT_UNLESS_DENY"], (Combination{NodePermit, NodeDeny, NodeDeny, NodeNotApplicable}); got != want {
		t.Errorf("Nodes(agent).Algorithms[PERMIT_UNLESS_DENY] = %+v, want %+v", got, want)
	}
	legacy, _ := tab.Nodes(ProfileLegacy)
	if got := legacy.Algorithms["PERMIT_UNLESS_DENY"].None; got != NodePermit {
		t.Errorf("Nodes(legacy).Algorithms[PERMIT_UNLESS_DENY].None = %q, want %q", got, NodePermit)
	}
	if agent.AbsentAlgorithm != "DENY_UNLESS_PERMIT" || agent.Effects["USE_FILTER_CONDITION"] != NodeDeny ||
		agent.AbsentEffect != "other" || agent.AbsentExpression != OutcomeT {
		t.Errorf("Nodes(agent) = %+v, want the fixture's absent algorithm, effects, absent effect, and absent expression", agent)
	}
}

func TestLoadRejectsADocumentThatIsNotOneExport(t *testing.T) {
	t.Parallel()
	complete, err := json.Marshal(completeExport())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		input string
	}{
		{name: "malformed JSON", input: `{"schema_version": 1,`},
		{name: "data after the export", input: string(complete) + ` {}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(strings.NewReader(tt.input))
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Load(%.40q...) error = %v, want ErrInvalid", tt.input, err)
			}
		})
	}
}

// TestLoadAcceptsTheExportNamedBySpectablesExport loads the file that the
// SPECTABLES_EXPORT environment variable names, so that the specification's
// exporter can check its output with this loader. It is skipped when the
// variable is unset.
func TestLoadAcceptsTheExportNamedBySpectablesExport(t *testing.T) {
	path := os.Getenv("SPECTABLES_EXPORT")
	if path == "" {
		t.Skip("SPECTABLES_EXPORT is unset")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tab, err := Load(f)
	if err != nil {
		t.Fatalf("Load(%s) error = %v, want nil", path, err)
	}
	if got := tab.SchemaVersion(); got != SchemaVersion {
		t.Fatalf("Load(%s): schema_version %d, want %d", path, got, SchemaVersion)
	}
	t.Logf("Load(%s): spec_tag %s", path, tab.SpecTag())
}
