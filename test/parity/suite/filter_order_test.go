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

package paritysuite

import (
	"encoding/json"
	"testing"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
)

// Two answers of one policy set that list the terms of an operator in another
// order, at any depth, canonicalize to one text. The texts are the recorded
// deny-predicates-under-deny-overrides and filter-four-groups-on-one-type
// answers with their terms permuted at every level.
func TestCanonicalFilterDialects_TermOrderDoesNotReachTheComparison(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		canonicalize func(string) string
		recorded     string
		permuted     string
	}{
		{
			name:         "rsql terms of an AND and of a bracketed OR",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     "(b==2,a==1);c!=3;d!=4",
			permuted:     "d!=4;(a==1,b==2);c!=3",
		},
		{
			name:         "rsql bracketed groups of four sources",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     "(regular1==1),(simplified1==1,simplified2==2),(regular2==2)",
			permuted:     "(simplified2==2,simplified1==1),(regular2==2),(regular1==1)",
		},
		{
			name:         "sql terms under NOT and in a bracketed OR",
			canonicalize: func(s string) string { return canonicalInfix(s, sqlSeparators) },
			recorded:     "(b=2 OR a=1) AND NOT (c=3) AND NOT (d=4)",
			permuted:     "NOT (d=4) AND (a=1 OR b=2) AND NOT (c=3)",
		},
		{
			name:         "mongodb elements of $and and of a nested $or",
			canonicalize: func(s string) string { return canonicalInfix(s, mongodbSeparators) },
			recorded:     `{ "$and": [ { "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }, {{ "c": 3 }}, {{ "d": 4 }} ] }`,
			permuted:     `{ "$and": [ {{ "d": 4 }}, { "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }, {{ "c": 3 }} ] }`,
		},
		{
			name:         "method chain operands of and and of a nested or",
			canonicalize: canonicalMethodChain,
			recorded:     "((T.b.eq(2)).or(T.a.eq(1))).and((T.c.eq(3)).not()).and((T.d.eq(4)).not())",
			permuted:     "((T.d.eq(4)).not()).and((T.a.eq(1)).or(T.b.eq(2))).and((T.c.eq(3)).not())",
		},
		{
			name:         "sql IN list elements",
			canonicalize: func(s string) string { return canonicalInfix(s, sqlSeparators) },
			recorded:     "perms IN ('parity_other_permission', 'parity_permission') AND a=1",
			permuted:     "a=1 AND perms IN ('parity_permission', 'parity_other_permission')",
		},
		{
			name:         "method chain in-call arguments",
			canonicalize: canonicalMethodChain,
			recorded:     `(T.id.in("b", "a")).and(T.x.eq(1))`,
			permuted:     `(T.x.eq(1)).and(T.id.in("a", "b"))`,
		},
		{
			name:         "rsql in-clause elements",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			recorded:     `id=in=("row10-dict-1", "row10-dict-2");amount=le="1000"`,
			permuted:     `amount=le="1000";id=in=("row10-dict-2", "row10-dict-1")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tc.canonicalize(tc.permuted), tc.canonicalize(tc.recorded); got != want {
				t.Errorf("canonical(%q) = %q, want canonical(%q) = %q", tc.permuted, got, tc.recorded, want)
			}
		})
	}
}

// Sorting the terms of an operator keeps the brackets that bind them, so two
// expressions that group the same terms differently stay apart.
func TestCanonicalFilterDialects_GroupingStaysApart(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		canonicalize func(string) string
		left, right  string
	}{
		{
			name:         "rsql OR inside the AND against AND inside the OR",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			left:         "(a==1,b==2);c==3",
			right:        "a==1,(b==2;c==3)",
		},
		{
			name:         "method chain and of an or against or of an and",
			canonicalize: canonicalMethodChain,
			left:         "(T.a.eq(1).or(T.b.eq(2))).and(T.c.eq(3))",
			right:        "(T.a.eq(1).and(T.b.eq(2))).or(T.c.eq(3))",
		},
		{
			name:         "method chain mixing and with or keeps its order",
			canonicalize: canonicalMethodChain,
			left:         "T.b.eq(2).or(T.a.eq(1)).and(T.c.eq(3))",
			right:        "T.a.eq(1).and(T.c.eq(3)).or(T.b.eq(2))",
		},
		{
			name:         "rsql quoted separator is not a term boundary",
			canonicalize: func(s string) string { return canonicalInfix(s, rsqlSeparators) },
			left:         `name=="b,a";x==1`,
			right:        `name=="a,b";x==1`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.canonicalize(tc.left); got == tc.canonicalize(tc.right) {
				t.Errorf("canonical(%q) = canonical(%q) = %q, want them apart", tc.left, tc.right, got)
			}
		})
	}
}

// A customFilterCondition recorded with indentation compares equal to the compact
// one the stand answers, with the operands of a logic node in either order. A
// null value stays null.
func TestCanonicalJSON_IndentationAndApplyOrderDoNotReachTheComparison(t *testing.T) {
	t.Parallel()
	recorded := json.RawMessage(`{
  "logic": {
    "op": "OR",
    "apply": [
      {
        "path": "p1"
      },
      {
        "path": "p2"
      }
    ]
  },
  "data": {
    "p1": {"predicate": "a:1"},
    "p2": {"predicate": "b:2"}
  }
}`)
	answered := json.RawMessage(`{"data":{"p2":{"predicate":"b:2"},"p1":{"predicate":"a:1"}},"logic":{"apply":[{"path":"p2"},{"path":"p1"}],"op":"OR"}}`)

	if got, want := string(canonicalJSON(answered)), string(canonicalJSON(recorded)); got != want {
		t.Errorf("canonicalJSON(answered) = %s, want canonicalJSON(recorded) = %s", got, want)
	}
	if got := canonicalJSON(json.RawMessage("null")); string(got) != "null" {
		t.Errorf("canonicalJSON(null) = %s, want null", got)
	}
}

// The comparator applies the rewrite to a check/filter outcome as a whole, so a
// golden and an answer that differ in term order alone in every dialect and in
// the customFilterCondition diff empty.
func TestNormalizeComparable_FilterOutcomeWithPermutedTermsDiffsEmpty(t *testing.T) {
	t.Parallel()
	recorded := &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
		CalculationResult:      "USE_FILTER_CONDITION",
		FilterCondition:        model.FilterTextOf("(T.b.eq(2)).or(T.a.eq(1))"),
		MongodbFilterCondition: model.FilterTextOf(`{ "$or": [ {{ "b": 2 }}, {{ "a": 1 }} ] }`),
		RsqlFilterCondition:    model.FilterTextOf("b==2,a==1"),
		SqlFilterCondition:     model.FilterTextOf("b=2 OR a=1"),
		CustomFilterCondition:  json.RawMessage("{\n  \"logic\": {\n    \"op\": \"OR\",\n    \"apply\": [{\"path\": \"b\"}, {\"path\": \"a\"}]\n  }\n}"),
	}}
	answered := &model.FilterOutcome{Status: 200, Result: model.OldFilterEvaluationResult{
		CalculationResult:      "USE_FILTER_CONDITION",
		FilterCondition:        model.FilterTextOf("(T.a.eq(1)).or(T.b.eq(2))"),
		MongodbFilterCondition: model.FilterTextOf(`{ "$or": [ {{ "a": 1 }}, {{ "b": 2 }} ] }`),
		RsqlFilterCondition:    model.FilterTextOf("a==1,b==2"),
		SqlFilterCondition:     model.FilterTextOf("a=1 OR b=2"),
		CustomFilterCondition:  json.RawMessage(`{"logic":{"op":"OR","apply":[{"path":"a"},{"path":"b"}]}}`),
	}}

	want := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", recorded)
	got := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", answered)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("normalizeComparable() of two term orders differs (-recorded +answered):\n%s", diff)
	}
}

// filterOutcomeWithRsql decodes a v1 filter outcome whose rsqlFilterCondition
// member is the JSON text member, or absent when member is empty, the way the
// comparator decodes a golden.
func filterOutcomeWithRsql(t *testing.T, member string) *model.FilterOutcome {
	t.Helper()
	body := `{"status": 200, "result": {"calculationResult": "ALLOW"`
	if member != "" {
		body += `, "rsqlFilterCondition": ` + member
	}
	body += `}}`
	var out model.FilterOutcome
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", body, err)
	}
	return &out
}

// A filter text recorded as "", as null, and with no member are three answers:
// the comparator reports a difference between any two of them, and a golden
// written back from the decoded answer keeps the form it was read in.
func TestNormalizeComparable_FilterTextKeepsEmptyNullAndAbsentApart(t *testing.T) {
	t.Parallel()
	forms := []struct{ name, member, written string }{
		{"empty string", `""`, `{"calculationResult":"ALLOW","rsqlFilterCondition":""}`},
		{"null", `null`, `{"calculationResult":"ALLOW","rsqlFilterCondition":null}`},
		{"absent", ``, `{"calculationResult":"ALLOW"}`},
	}
	for _, recorded := range forms {
		for _, answered := range forms {
			t.Run(recorded.name+" against "+answered.name, func(t *testing.T) {
				want := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", filterOutcomeWithRsql(t, recorded.member))
				got := normalizeComparable(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, "regular/x/filter", filterOutcomeWithRsql(t, answered.member))
				diff := cmp.Diff(want, got)
				if same := recorded.name == answered.name; same != (diff == "") {
					t.Errorf("cmp.Diff(%s, %s) = %q, want an empty diff exactly when the forms are the same", recorded.name, answered.name, diff)
				}
			})
		}
		t.Run(recorded.name+" written back", func(t *testing.T) {
			b, err := json.Marshal(filterOutcomeWithRsql(t, recorded.member).Result)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(b) != recorded.written {
				t.Errorf("json.Marshal(result with %s) = %s, want %s", recorded.name, b, recorded.written)
			}
		})
	}
}

// A text member that is neither a string nor null fails the decoding of the
// whole answer instead of being recorded as some string.
func TestFilterText_ANumberIsRefused(t *testing.T) {
	t.Parallel()
	var out model.OldFilterEvaluationResult
	if err := json.Unmarshal([]byte(`{"calculationResult": "ALLOW", "rsqlFilterCondition": 5}`), &out); err == nil {
		t.Errorf("json.Unmarshal(rsqlFilterCondition 5) = nil error, result %+v, want an error", out)
	}
}
