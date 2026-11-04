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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The operators and operand kinds every table must cover, written out here
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

// completeTable returns a table whose EQ(res:path, lit:str) has the lines of
// eqLines, and every other combination the one line of fixtureTable.
func completeTable() doc { return fixtureTable(eqLines()) }

// eqLines returns the lines of EQ(res:path, lit:str) in completeTable, in
// legacy's outcomes, where res:path has the points VALUE/s, VALUE/l, and NULL,
// and lit:str the point VALUE/s. Every place has four lines: the row of NULL
// answers F under OR, ERR in a pass of iterate, and otherwise T for DENY and F
// for ALLOW. The row of VALUE/s answers by value (code a) and the row of
// VALUE/l ERR, except bad_request in place rule_target.
func eqLines() []string {
	var lines []string
	for _, place := range []string{"simplified", "rule_condition", "rule_target", "policy_target", "set_target"} {
		list := "E"
		if place == "rule_target" {
			list = "B"
		}
		for _, q := range []struct{ qualifiers, null string }{
			{"effect=ALLOW disjunction=false in_iterate=false", "F"},
			{"disjunction=false in_iterate=true", "E"},
			{"disjunction=true", "F"},
			{"effect=DENY disjunction=false in_iterate=false", "T"},
		} {
			lines = append(lines, fmt.Sprintf("EQ res:path lit:str place=%s %s a %s %s", place, q.qualifiers, list, q.null))
		}
	}
	return lines
}

// negatesDoc returns Negations as the table lists them.
func negatesDoc() doc {
	negates := doc{}
	for neg, pos := range Negations {
		negates[string(neg)] = string(pos)
	}
	return negates
}

// fixtureTable covers every combination with one line of code F, except
// EQ(res:path, lit:str), which takes eq when eq is not nil. Every kind has the
// points VALUE/s and NULL, except res:path with VALUE/s, VALUE/l, and NULL,
// and lit:str and pattern with VALUE/s alone. The agent maps ABORT to F and ERR
// to U, and subj.name is an alias of subj.id.
func fixtureTable(eq []string) doc {
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
				head := strings.TrimSpace(op + " " + lk + " " + rk)
				if head == "EQ res:path lit:str" && eq != nil {
					for _, l := range eq {
						cells = append(cells, l)
					}
					continue
				}
				cells = append(cells, head+" F")
			}
		}
	}
	return doc{
		"schema_version": 4,
		"spec_tag":       "r99",
		"negates":        negatesDoc(),
		"knobs": doc{"fold": "java", "eq_numeric": false, "list_eq_by_value": true, "subset_fold": false,
			"right_list_scalar_ops": "ABORT", "right_list_attribute": "EVAL", "string_list_split": "SPLIT_TRIM",
			"idiom_list_item_trim": "java_trim", "trailing_dot_path": "ERROR"},
		"kinds":   kinds,
		"nodes":   fixtureNodes(),
		"leaf":    doc{"ABORT": "F", "ERR": "U"},
		"aliases": doc{"subj.name": "subj.id"},
		"codes":   fixtureCodes(),
		"cells":   cells,
	}
}

// fixtureCodes returns a code for each result the fixtures use.
func fixtureCodes() doc {
	byValue := func(outcomes ...any) doc {
		return doc{"outcome": "by_value", "outcomes": outcomes, "value_rule": []any{"eq"}}
	}
	return doc{
		"T": doc{"outcome": "T"}, "F": doc{"outcome": "F"}, "A": doc{"outcome": "ABORT"},
		"E": doc{"outcome": "ERR"}, "B": doc{"outcome": "bad_request"}, "X": doc{"outcome": "unsupported"},
		"a": byValue("T", "F"), "b": byValue("T", "ABORT"), "c": byValue("T", "ERR"),
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

func nodesOf(d doc) doc { return d["nodes"].(doc) }

func codeOf(d doc, code string) doc { return d["codes"].(doc)[code].(doc) }

// setLines replaces the lines of the combination head, such as
// "EQ res:path lit:str", with lines; no lines leaves the combination to its
// source.
func setLines(d doc, head string, lines ...string) {
	kept := slices.DeleteFunc(d["cells"].([]any), func(c any) bool { return strings.HasPrefix(c.(string), head+" ") })
	for _, l := range lines {
		kept = append(kept, l)
	}
	d["cells"] = kept
}

// dropLines removes the lines that contain every one of parts.
func dropLines(d doc, parts ...string) {
	d["cells"] = slices.DeleteFunc(d["cells"].([]any), func(c any) bool {
		return !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(c.(string), p) })
	})
}

// replaceLine replaces the line from with to; from must be a line of d.
func replaceLine(d doc, from, to string) {
	cells := d["cells"].([]any)
	i := slices.Index(cells, any(from))
	if i < 0 {
		panic("no line " + from)
	}
	cells[i] = to
}

func load(t *testing.T, d doc) (*Table, error) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal(fixture): %v", err)
	}
	return Load(strings.NewReader(string(b)))
}

func mustLoad(t *testing.T, d doc) *Table {
	t.Helper()
	tab, err := load(t, d)
	if err != nil {
		t.Fatalf("Load(fixture) error = %v, want nil", err)
	}
	return tab
}

func ruleCondition() Context {
	return Context{Place: PlaceRuleCondition, Effect: EffectAllow}
}

func TestLookupFindsTheCellThatCoversTheKey(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeTable())
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
			got, err := tab.Lookup(tt.key)
			if err != nil {
				t.Fatalf("Lookup(%+v) error = %v, want nil", tt.key, err)
			}
			if got.Outcome != tt.want.Outcome || !slices.Equal(got.Outcomes, tt.want.Outcomes) ||
				!slices.Equal(got.ValueRule, tt.want.ValueRule) {
				t.Errorf("Lookup(%+v) = %+v, want %+v", tt.key, got, tt.want)
			}
		})
	}
}

func TestLoadKeepsTheSpecTagAndKnobs(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeTable())
	if got := tab.SpecTag(); got != "r99" {
		t.Errorf("SpecTag() = %q, want %q", got, "r99")
	}
	if got, ok := tab.Knob("fold"); !ok || string(got) != `"java"` {
		t.Errorf(`Knob("fold") = %s, %t, want "java", true`, got, ok)
	}
}

func TestLookupRefusesAKeyOutsideTheTable(t *testing.T) {
	t.Parallel()
	tab := mustLoad(t, completeTable())
	litStr := Point{Kind: KindLitStr, State: StateValue, Class: ClassString}
	// IS_NULL(res:path) has one line that matches every state, class, and
	// context, so only the check of the key itself can refuse the keys on it.
	tests := []struct {
		name string
		key  Key
	}{
		{
			name: "a state outside the kind's domain",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateError}, Context: ruleCondition()},
		},
		{
			name: "a class outside the kind's domain",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateValue, Class: ClassObject}, Context: ruleCondition()},
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
			name: "an unknown place",
			key:  Key{Op: OpIsNull, Left: Point{Kind: KindResPath, State: StateNull}, Context: Context{Place: "filter", Effect: EffectAllow}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tab.Lookup(tt.key)
			if !errors.Is(err, ErrNotCovered) {
				t.Errorf("Lookup(%+v) = %+v, %v, want ErrNotCovered", tt.key, got, err)
			}
		})
	}
}

// The grid of a line has a row per left point and a code per right point, the
// points in the order of the domains: res:path VALUE/s, VALUE/l, NULL on the
// left, operation VALUE/s, NULL on the right. A single row stands for every
// left point.
func TestLookupReadsTheGridByLeftRowAndRightColumn(t *testing.T) {
	t.Parallel()
	d := completeTable()
	setLines(d, "EQ res:path operation", "EQ res:path operation TF EB XA")
	setLines(d, "NE res:path operation", "NE res:path operation BX")
	tab := mustLoad(t, d)
	resPath := func(s State, c Class) Point { return Point{Kind: KindResPath, State: s, Class: c} }
	operation := func(s State, c Class) Point { return Point{Kind: KindOperation, State: s, Class: c} }
	tests := []struct {
		op          Operator
		left, right Point
		want        Outcome
	}{
		{OpEQ, resPath(StateValue, ClassString), operation(StateValue, ClassString), OutcomeT},
		{OpEQ, resPath(StateValue, ClassString), operation(StateNull, ""), OutcomeF},
		{OpEQ, resPath(StateValue, ClassList), operation(StateValue, ClassString), OutcomeU},
		{OpEQ, resPath(StateValue, ClassList), operation(StateNull, ""), OutcomeBadRequest},
		{OpEQ, resPath(StateNull, ""), operation(StateValue, ClassString), OutcomeUnsupported},
		{OpEQ, resPath(StateNull, ""), operation(StateNull, ""), OutcomeF},
		{OpNE, resPath(StateValue, ClassList), operation(StateValue, ClassString), OutcomeBadRequest},
		{OpNE, resPath(StateNull, ""), operation(StateNull, ""), OutcomeUnsupported},
	}
	for _, tt := range tests {
		key := Key{Op: tt.op, Left: tt.left, Right: tt.right, Context: ruleCondition()}
		if got, err := tab.Lookup(key); err != nil || got.Outcome != tt.want {
			t.Errorf("Lookup(%+v) = %+v, %v, want outcome %s", key, got, err, tt.want)
		}
	}
}

func TestLoadRejectsAnIncompleteTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(d doc)
		names string // the part of the error that names what is missing
	}{
		{
			name:  "an operator with no lines",
			edit:  func(d doc) { dropLines(d, "IN ") },
			names: "IN(operation, operation) has no cells",
		},
		{
			name:  "one combination with no lines",
			edit:  func(d doc) { setLines(d, "CONTAINS pip:GENERAL list:strn") },
			names: "CONTAINS(pip:GENERAL, list:strn) has no cells",
		},
		{
			name:  "an operand kind with no domain",
			edit:  func(d doc) { delete(d["kinds"].(doc), "pip:MAPPING") },
			names: "operand kind pip:MAPPING has no domain",
		},
		{
			name:  "a hole in one place",
			edit:  func(d doc) { dropLines(d, "EQ res:path lit:str ", "place=rule_condition") },
			names: "EQ(res:path, lit:str): no line covers 8 contexts, the first at place rule_condition, effect ALLOW, disjunction false, in_iterate false",
		},
		{
			name:  "a hole in one effect",
			edit:  func(d doc) { dropLines(d, "effect=DENY") },
			names: "EQ(res:path, lit:str): no line covers 5 contexts, the first at place simplified, effect DENY, disjunction false, in_iterate false",
		},
		{
			name: "a hole that a qualifier leaves",
			edit: func(d doc) {
				replaceLine(d, "EQ operation operation F", "EQ operation operation in_iterate=true F")
			},
			names: "EQ(operation, operation): no line covers 20 contexts, the first at place simplified, effect ALLOW, disjunction false, in_iterate false",
		},
		{
			name:  "a knob",
			edit:  func(d doc) { delete(d["knobs"].(doc), "subset_fold") },
			names: "knob subset_fold is missing",
		},
		{
			name:  "a knob a template reads",
			edit:  func(d doc) { delete(d["knobs"].(doc), "right_list_scalar_ops") },
			names: "knob right_list_scalar_ops is missing",
		},
		{
			name:  "the node rules",
			edit:  func(d doc) { delete(d, "nodes") },
			names: "nodes is missing",
		},
		{
			name:  "an algorithm",
			edit:  func(d doc) { delete(nodesOf(d)["algorithms"].(doc), "PERMIT_UNLESS_DENY") },
			names: "nodes: algorithm PERMIT_UNLESS_DENY is missing",
		},
		{
			name:  "a rule effect",
			edit:  func(d doc) { delete(nodesOf(d)["effects"].(doc), "other") },
			names: "nodes: rule effect other is missing",
		},
		{
			name:  "one outcome of an algorithm",
			edit:  func(d doc) { delete(nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"].(doc), "none") },
			names: "nodes: DENY_OVERRIDES.none is missing",
		},
		{
			name:  "the absent algorithm",
			edit:  func(d doc) { delete(nodesOf(d), "absent_algorithm") },
			names: "nodes: absent_algorithm is missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := completeTable()
			tt.edit(d)
			_, err := load(t, d)
			if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), tt.names) {
				t.Errorf("Load() error = %v, want ErrIncomplete naming %q", err, tt.names)
			}
		})
	}
}

func TestLoadRejectsAnInvalidTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(d doc)
		names string // the part of the error that names the problem
	}{
		{
			name:  "a provenance field",
			edit:  func(d doc) { d["prov"] = "recorded by case 17" },
			names: `unknown field "prov"`,
		},
		{
			name:  "a provenance knob",
			edit:  func(d doc) { d["knobs"].(doc)["fold_prov"] = "recorded by case 17" },
			names: `unknown knob "fold_prov"`,
		},
		{
			name:  "an empty spec tag",
			edit:  func(d doc) { d["spec_tag"] = "" },
			names: "spec_tag is empty",
		},
		{
			name:  "the schema version of the earlier export",
			edit:  func(d doc) { d["schema_version"] = 3 },
			names: "schema_version is 3, want 4",
		},
		{
			name:  "the cells of the earlier export",
			edit:  func(d doc) { d["cells"] = []any{doc{"op": "EQ", "left": doc{"kind": "operation"}, "outcome": "F"}} },
			names: "cannot unmarshal object",
		},

		{
			name:  "a code of two letters",
			edit:  func(d doc) { d["codes"].(doc)["FF"] = doc{"outcome": "F"} },
			names: `code "FF" is not one ASCII letter or digit`,
		},
		{
			name:  "a code that is not a letter or digit",
			edit:  func(d doc) { d["codes"].(doc)["-"] = doc{"outcome": "F"} },
			names: `code "-" is not one ASCII letter or digit`,
		},
		{
			name:  "a code the codes do not define",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation Q") },
			names: `cells[0] EQ(operation, operation): row "Q" names code "Q", which codes does not define`,
		},
		{
			name:  "a code of an outcome of the agent profile",
			edit:  func(d doc) { codeOf(d, "F")["outcome"] = "U" },
			names: `code "F": outcome "U" is not an outcome of profile legacy`,
		},
		{
			name:  "a by_value code without a value rule",
			edit:  func(d doc) { delete(codeOf(d, "a"), "value_rule") },
			names: `code "a": by_value has no value_rule`,
		},
		{
			name:  "an unknown value rule",
			edit:  func(d doc) { codeOf(d, "a")["value_rule"] = []any{"eq", "regex_lookahead"} },
			names: `unknown value rule "regex_lookahead"`,
		},
		{
			name:  "value rules out of order",
			edit:  func(d doc) { codeOf(d, "a")["value_rule"] = []any{"null_element_ends", "in_any"} },
			names: "is not sorted, or repeats a rule",
		},
		{
			name:  "a repeated value rule",
			edit:  func(d doc) { codeOf(d, "a")["value_rule"] = []any{"eq", "eq"} },
			names: "is not sorted, or repeats a rule",
		},
		{
			name:  "a value rule on a constant code",
			edit:  func(d doc) { codeOf(d, "F")["value_rule"] = []any{"eq"} },
			names: "value_rule is set for outcome F",
		},
		{
			name:  "an outcome of the agent profile in a by_value list",
			edit:  func(d doc) { codeOf(d, "a")["outcomes"] = []any{"T", "U"} },
			names: `by_value outcome "U" is not an outcome of profile legacy`,
		},
		{
			name:  "by_value with one outcome",
			edit:  func(d doc) { codeOf(d, "a")["outcomes"] = []any{"T"} },
			names: "by_value lists 1 outcomes, want at least 2",
		},
		{
			name:  "outcomes beside an outcome other than by_value",
			edit:  func(d doc) { codeOf(d, "F")["outcomes"] = []any{"T", "F"} },
			names: "outcomes is set for outcome F",
		},

		{
			name:  "a row with more codes than right points",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation FFF") },
			names: `row "FFF" has 3 codes, want 2 or 1`,
		},
		{
			name:  "more rows than left points",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation F F F") },
			names: "EQ(operation, operation): has 3 rows, want 2 or 1",
		},
		{
			name:  "a line without a grid",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation in_iterate=true") },
			names: "has 0 rows, want 2 or 1",
		},
		{
			name:  "a line of one word",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ") },
			names: `"EQ" has no operator, kind, or grid`,
		},
		{
			name:  "an unknown qualifier",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation scope=tenant F") },
			names: `qualifier "scope=tenant" is unknown or repeated`,
		},
		{
			name: "a repeated qualifier",
			edit: func(d doc) {
				replaceLine(d, "EQ operation operation F", "EQ operation operation in_iterate=true in_iterate=false F")
			},
			names: `qualifier "in_iterate=false" is unknown or repeated`,
		},
		{
			name:  "an unknown place",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation place=filter F") },
			names: `qualifier "place=filter" is unknown or repeated`,
		},
		{
			name:  "an unknown effect",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation effect=PERMIT F") },
			names: `qualifier "effect=PERMIT" is unknown or repeated`,
		},
		{
			name:  "a flag that is not true or false",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation operation disjunction=yes F") },
			names: `qualifier "disjunction=yes" is unknown or repeated`,
		},
		{
			name: "two lines that cover one context",
			edit: func(d doc) {
				d["cells"] = append(d["cells"].([]any), "EQ operation operation in_iterate=true T")
			},
			names: "EQ(operation, operation): several lines cover 20 contexts, the first at place simplified, effect ALLOW, disjunction false, in_iterate true",
		},
		{
			name:  "an unknown operator",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "LIKE operation operation F") },
			names: `unknown operator "LIKE"`,
		},
		{
			name:  "a right side on a unary operator",
			edit:  func(d doc) { replaceLine(d, "IS_NULL operation F", "IS_NULL operation lit:str F") },
			names: "IS_NULL takes no right side",
		},
		{
			name:  "a pattern on the right of EQ",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ operation pattern F") },
			names: `EQ does not take kind "pattern" on the right`,
		},
		{
			name:  "a pattern on the left",
			edit:  func(d doc) { replaceLine(d, "EQ operation operation F", "EQ pattern operation F") },
			names: `EQ does not take kind "pattern" on the left`,
		},

		{
			name: "the class x, which the format splits into xn, xl, and xo",
			edit: func(d doc) {
				d["kinds"].(doc)["res:path"] = doc{"states": []any{"VALUE", "NULL"}, "classes": []any{"s", "l", "x"}}
			},
			names: `operand kind res:path: class "x" is unknown or repeated`,
		},
		{
			name:  "a domain for an unknown operand kind",
			edit:  func(d doc) { d["kinds"].(doc)["pip:REGO"] = doc{"states": []any{"NULL"}} },
			names: `unknown operand kind "pip:REGO"`,
		},

		{
			name:  "an unknown outcome of a rule effect",
			edit:  func(d doc) { nodesOf(d)["effects"].(doc)["other"] = "indeterminate" },
			names: `nodes: effects.other has unknown node outcome "indeterminate"`,
		},
		{
			name: "an unknown algorithm",
			edit: func(d doc) {
				nodesOf(d)["algorithms"].(doc)["FIRST_APPLICABLE"] = nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"]
			},
			names: `nodes: unknown algorithm "FIRST_APPLICABLE"`,
		},
		{
			name:  "an unknown node outcome",
			edit:  func(d doc) { nodesOf(d)["algorithms"].(doc)["DENY_OVERRIDES"].(doc)["none"] = "indeterminate" },
			names: `nodes: DENY_OVERRIDES.none has unknown node outcome "indeterminate"`,
		},
		{
			name:  "an absent algorithm that is not an algorithm",
			edit:  func(d doc) { nodesOf(d)["absent_algorithm"] = "FIRST_APPLICABLE" },
			names: `nodes: absent_algorithm "FIRST_APPLICABLE" is not an algorithm`,
		},
		{
			name:  "an unknown rule effect",
			edit:  func(d doc) { nodesOf(d)["effects"].(doc)["PERMIT"] = "permit" },
			names: `nodes: unknown rule effect "PERMIT"`,
		},
		{
			name:  "an unknown absent effect",
			edit:  func(d doc) { nodesOf(d)["absent_effect"] = "NOT_APPLICABLE" },
			names: `nodes: absent_effect "NOT_APPLICABLE" is not one of`,
		},
		{
			name:  "an absent expression that is undefined",
			edit:  func(d doc) { nodesOf(d)["absent_expression"] = "U" },
			names: `nodes: absent_expression "U" is not T or F`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := completeTable()
			tt.edit(d)
			_, err := load(t, d)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.names) {
				t.Errorf("Load() error = %v, want ErrInvalid naming %q", err, tt.names)
			}
		})
	}
}

func TestNodesReturnsTheNodeRulesOfTheTable(t *testing.T) {
	t.Parallel()
	d := completeTable()
	nodesOf(d)["algorithms"].(doc)["PERMIT_UNLESS_DENY"].(doc)["none"] = "na"
	tab := mustLoad(t, d)
	nodes := tab.Nodes()
	if got, want := nodes.Algorithms["PERMIT_UNLESS_DENY"], (Combination{NodePermit, NodeDeny, NodeDeny, NodeNotApplicable}); got != want {
		t.Errorf("Nodes().Algorithms[PERMIT_UNLESS_DENY] = %+v, want %+v", got, want)
	}
	if nodes.AbsentAlgorithm != "DENY_UNLESS_PERMIT" || nodes.Effects["USE_FILTER_CONDITION"] != NodeDeny ||
		nodes.AbsentEffect != "other" || nodes.AbsentExpression != OutcomeT {
		t.Errorf("Nodes() = %+v, want the fixture's absent algorithm, effects, absent effect, and absent expression", nodes)
	}
}

func TestLoadRejectsADocumentThatIsNotOneTable(t *testing.T) {
	t.Parallel()
	complete, err := json.Marshal(completeTable())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		input string
	}{
		{name: "malformed JSON", input: `{"schema_version": 4,`},
		{name: "data after the table", input: string(complete) + ` {}`},
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

// TestLoadAcceptsTheExportNamedBySpectablesExport loads the table that the
// SPECTABLES_EXPORT environment variable names, so that the specification's
// exporter can check its output with this package. It is skipped when the
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
	t.Logf("Load(%s): spec_tag %s", path, tab.SpecTag())
}

// eqPositive is the line of EQ(res:path, lit:str) the derivation tests start
// from, in legacy's outcomes: T or ABORT by value on VALUE/s (code b), ERR on
// VALUE/l, and T on NULL. A line the tests tell apart from its source answers
// ERR, which no mirror produces.
const eqPositive = "EQ res:path lit:str b E T"

func TestLoadDerivesTheCellsATableLeavesOut(t *testing.T) {
	t.Parallel()
	resPath := func(s State, c Class) Point { return Point{Kind: KindResPath, State: s, Class: c} }
	litStr := Point{Kind: KindLitStr, State: StateValue, Class: ClassString}
	subj := func(k Kind) Point { return Point{Kind: k, State: StateNull} }
	byValue := func(rule ValueRule, outs ...Outcome) Cell {
		return Cell{Outcome: OutcomeByValue, Outcomes: outs, ValueRule: []ValueRule{rule}}
	}
	tests := []struct {
		name string
		edit func(d doc)
		key  Key
		want Cell
	}{
		{
			name: "a negated combination without lines takes its positive operator's result with T and F swapped",
			edit: func(d doc) { setLines(d, "NE res:path lit:str") },
			key:  Key{Op: OpNE, Left: resPath(StateNull, ""), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeF},
		},
		{
			name: "a mirrored by_value result swaps T and F among its outcomes and keeps its value rule",
			edit: func(d doc) {
				setLines(d, "EQ subj.id lit:str", "EQ subj.id lit:str c")
				setLines(d, "NE subj.id lit:str")
			},
			key:  Key{Op: OpNE, Left: subj(KindSubjID), Right: litStr, Context: ruleCondition()},
			want: byValue(RuleEq, OutcomeF, OutcomeU),
		},
		{
			name: "a mirror keeps an outcome other than T and F",
			edit: func(d doc) { setLines(d, "NE res:path lit:str") },
			key:  Key{Op: OpNE, Left: resPath(StateValue, ClassList), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "a negated combination with lines of its own is not mirrored",
			edit: func(d doc) { setLines(d, "NE res:path lit:str", "NE res:path lit:str E") },
			key:  Key{Op: OpNE, Left: resPath(StateNull, ""), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "an alias combination without lines takes its representative's lines",
			edit: func(d doc) {
				setLines(d, "EQ subj.id lit:str", "EQ subj.id lit:str T")
				setLines(d, "EQ subj.name lit:str")
			},
			key:  Key{Op: OpEQ, Left: subj(KindSubjName), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeT},
		},
		{
			name: "an alias combination with lines of its own keeps them",
			edit: func(d doc) {
				setLines(d, "EQ subj.id lit:str", "EQ subj.id lit:str T")
				setLines(d, "EQ subj.name lit:str", "EQ subj.name lit:str E")
			},
			key:  Key{Op: OpEQ, Left: subj(KindSubjName), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "a negated alias combination takes its representative's own lines rather than the mirror",
			edit: func(d doc) {
				setLines(d, "NE subj.id lit:str", "NE subj.id lit:str E")
				setLines(d, "EQ subj.name lit:str", "EQ subj.name lit:str T")
				setLines(d, "NE subj.name lit:str")
			},
			key:  Key{Op: OpNE, Left: subj(KindSubjName), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "a negated alias combination without lines takes the mirror of its positive one, renamed",
			edit: func(d doc) {
				setLines(d, "EQ subj.id lit:str", "EQ subj.id lit:str T")
				setLines(d, "EQ subj.name lit:str")
				setLines(d, "NE subj.name lit:str")
			},
			key:  Key{Op: OpNE, Left: subj(KindSubjName), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeF},
		},
		{
			name: "a combination with an alias on both sides takes its representatives' lines",
			edit: func(d doc) {
				setLines(d, "EQ subj.id subj.id", "EQ subj.id subj.id T")
				setLines(d, "EQ subj.name subj.name")
			},
			key:  Key{Op: OpEQ, Left: subj(KindSubjName), Right: subj(KindSubjName), Context: ruleCondition()},
			want: Cell{Outcome: OutcomeT},
		},
		{
			name: "the leaf map takes ERR to U",
			edit: func(d doc) {},
			key:  Key{Op: OpEQ, Left: resPath(StateValue, ClassList), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeU},
		},
		{
			name: "the leaf map takes ABORT among the outcomes of a by_value result to F",
			edit: func(d doc) {},
			key:  Key{Op: OpEQ, Left: resPath(StateValue, ClassString), Right: litStr, Context: ruleCondition()},
			want: byValue(RuleEq, OutcomeT, OutcomeF),
		},
		{
			name: "a by_value result whose outcomes the leaf map takes to one outcome answers that outcome",
			edit: func(d doc) { setLines(d, "NE res:path lit:str") },
			key:  Key{Op: OpNE, Left: resPath(StateValue, ClassString), Right: litStr, Context: ruleCondition()},
			want: Cell{Outcome: OutcomeF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := fixtureTable([]string{eqPositive})
			tt.edit(d)
			tab := mustLoad(t, d)
			got, err := tab.Lookup(tt.key)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Lookup(%+v) = %+v, %v, want %+v", tt.key, got, err, tt.want)
			}
		})
	}
}

func TestLoadRejectsAnInvalidDerivation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(d doc)
		names string // the part of the error that names the problem
	}{
		{
			name:  "negates without one pair of the language",
			edit:  func(d doc) { delete(d["negates"].(doc), "NE") },
			names: "negates is map[",
		},
		{
			name:  "a leaf map that leaves an outcome of legacy unmapped",
			edit:  func(d doc) { delete(d["leaf"].(doc), "ERR") },
			names: "leaf does not map ERR",
		},
		{
			name:  "a leaf map of an outcome the profile has",
			edit:  func(d doc) { d["leaf"].(doc)["T"] = "F" },
			names: `leaf maps "T" to "F"`,
		},
		{
			name:  "a leaf map to an outcome no by_value result of the profile lists",
			edit:  func(d doc) { d["leaf"].(doc)["ABORT"] = "bad_request" },
			names: `leaf maps "ABORT" to "bad_request"`,
		},
		{
			name:  "an alias of itself",
			edit:  func(d doc) { d["aliases"].(doc)["subj.type"] = "subj.type" },
			names: "alias subj.type names subj.type, which is itself or another alias",
		},
		{
			name:  "an alias of the pattern",
			edit:  func(d doc) { d["aliases"].(doc)["subj.type"] = "pattern" },
			names: `alias "subj.type" of "pattern" names an unknown kind or the pattern`,
		},
		{
			name:  "an alias of an alias",
			edit:  func(d doc) { d["aliases"].(doc)["subj.type"] = "subj.name" },
			names: "alias subj.type names subj.name, which is itself or another alias",
		},
		{
			name:  "an alias with another domain than its representative",
			edit:  func(d doc) { d["kinds"].(doc)["subj.name"] = doc{"states": []any{"NULL"}} },
			names: "alias subj.name has another domain than its representative subj.id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := fixtureTable(nil)
			tt.edit(d)
			_, err := load(t, d)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.names) {
				t.Errorf("Load() error = %v, want ErrInvalid naming %q", err, tt.names)
			}
		})
	}
}
