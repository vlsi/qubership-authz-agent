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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// GoldenComparator owns golden read / diff plumbing per D-M. A single
// comparator instance is shared across all replay tests; it stores the
// on-disk golden root (defaults to test/parity/suite/testdata/golden under
// the module root). The goldens are a frozen capture of the legacy
// access-control service behaviour — they cannot be regenerated from this
// repository (the legacy service source is not included).
type GoldenComparator struct {
	goldenRoot string
}

// NewGoldenComparator builds a comparator bound to the given config. The
// golden root is resolved relative to the current working directory — tests
// run from the module root, so testdata/golden points at the correct tree.
func NewGoldenComparator(_ Config) *GoldenComparator {
	return &GoldenComparator{
		goldenRoot: "testdata/golden",
	}
}

// GoldenPath constructs the full on-disk path for a golden file at
// <goldenRoot>/<row-meta-dir>/<subCase>.json. Callers pass subCase as
// "allow-incoming" or "token-pip/allow" — the latter form is the D-X sub-case
// directory convention.
func (gc *GoldenComparator) GoldenPath(id ParityEndpointID, subCase string) string {
	meta := Meta(id)
	return filepath.Join(gc.goldenRoot, meta.GoldenDir, subCase+".json")
}

// Compare asserts parity between the actual (freshly-decoded) response and
// the committed golden at <row,subCase>.
//
// The actual parameter must be a typed Go pointer matching the row's
// NewGoldenTarget factory; passing the wrong type is a test-authoring
// bug and panics fast at compare time.
func (gc *GoldenComparator) Compare(id ParityEndpointID, subCase string, actual any) error {
	goldenPath := gc.GoldenPath(id, subCase)

	raw, err := os.ReadFile(goldenPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrGoldenNotRecorded, goldenPath)
	}
	if err != nil {
		return fmt.Errorf("read golden %s: %w", goldenPath, err)
	}

	expected := NewGoldenTarget(id)
	if err := json.Unmarshal(raw, expected); err != nil {
		return fmt.Errorf("unmarshal golden %s: %w", goldenPath, err)
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		panic(fmt.Sprintf("paritysuite: comparator type mismatch for row %d: actual=%T expected=%T", int(id), actual, expected))
	}

	expected = normalizeComparable(id, subCase, expected)
	actual = normalizeComparable(id, subCase, actual)

	opts := compareOptionsFor(id)
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		gc.writeObservedSidecar(goldenPath, actual)
		if accepted, ok := acceptedDivergenceFor(id, subCase); ok {
			return gc.compareAgainstAccepted(id, subCase, goldenPath, actual, accepted, opts)
		}
		return &GoldenMismatchError{GoldenPath: goldenPath, Diff: diff}
	}
	return nil
}

// compareAgainstAccepted handles a case registered in acceptedDivergences. The
// response is compared against the recorded divergent answer with the same
// options used for the golden, so the case keeps asserting something exact: it
// passes only if the agent still answers the way the decision says it should.
func (gc *GoldenComparator) compareAgainstAccepted(
	id ParityEndpointID,
	subCase string,
	goldenPath string,
	actual any,
	accepted AcceptedDivergence,
	opts []cmp.Option,
) error {
	acceptedPath := acceptedDivergencePath(gc.goldenRoot, goldenPath)

	raw, err := os.ReadFile(acceptedPath)
	if err != nil {
		return fmt.Errorf(
			"case %s/%s is registered as an accepted divergence but its recorded answer is missing at %s: %w",
			Meta(id).GoldenDir, subCase, acceptedPath, err)
	}

	recorded := NewGoldenTarget(id)
	if err := json.Unmarshal(raw, recorded); err != nil {
		return fmt.Errorf("unmarshal accepted divergence %s: %w", acceptedPath, err)
	}
	recorded = normalizeComparable(id, subCase, recorded)

	if diff := cmp.Diff(recorded, actual, opts...); diff != "" {
		return &AcceptedDivergenceDriftError{
			GoldenPath:   goldenPath,
			AcceptedPath: acceptedPath,
			Reason:       accepted.Reason,
			Diff:         diff,
		}
	}

	// Passing quietly would let the suite read as fully equivalent to legacy when
	// it is not. Say so on every run.
	fmt.Printf("ACCEPTED DIVERGENCE %s/%s: differs from %s as decided in %s — %s\n",
		Meta(id).GoldenDir, subCase, goldenPath, accepted.Decision, accepted.Reason)
	return nil
}

func (gc *GoldenComparator) writeObservedSidecar(goldenPath string, actual any) {
	observedPath := strings.TrimSuffix(goldenPath, ".json") + ".observed.json"
	encoded, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(observedPath), 0o755)
	_ = os.WriteFile(observedPath, append(encoded, '\n'), 0o644)
}

// compareOptionsFor returns the cmp.Option set for a given row per D-M. The
// ignore-list is deliberately minimal — Obligations is the pre-locked entry
// (D-E), and the body of a pap-error-v1 golden, which the spec repository
// compares by class, is the other; anything else requires a one-line
// justification and an escalation OQ before being added.
func compareOptionsFor(id ParityEndpointID) []cmp.Option {
	meta := Meta(id)
	opts := []cmp.Option{}
	if meta.SortSlices {
		opts = append(opts, cmpopts.SortSlices(func(a, b string) bool { return a < b }))
	}
	if id == PSUITE_PAP_ERROR {
		// The error body is recorded for the spec repository, which compares the
		// class of its message rather than its text: the text changes between
		// builds of access-control and differs in a replacement PAP.
		opts = append(opts, cmpopts.IgnoreFields(model.PapErrorOutcome{}, "Body"))
	}
	if meta.IgnoreObligations {
		// Obligations is the only pre-committed ignore per D-E / D3.
		opts = append(opts,
			cmpopts.IgnoreFields(model.CheckResourceResponse{}, "Obligations"),
			cmpopts.IgnoreFields(model.CheckResourcesResponse{}, "Obligations"),
			cmpopts.IgnoreFields(model.FilterResponse{}, "Obligations"),
		)
	}
	return opts
}

// normalizeComparable applies row/sub-case specific canonicalization before
// cmp.Diff. Legacy AC's predicate-union path for row 63/PSUITE row 6
// agg-two-predicates is semantically stable but order-unstable on a cold
// stack: either `a,b` or `b,a` can be emitted for the same OR-aggregation.
// Step 3 records semantic parity there by sorting the top-level comma-delimited
// RSQL clauses for that single sub-case only.
//
// D-AF-AA (2026-04-19): `PSUITE_ROW_10_CHECK_FILTER_V2 / general-pip-dict`
// exercises the same set-semantic ordering invariant on the `in` clause's
// element list — authz-agent produces `("row10-dict-1","row10-dict-2")`
// deterministically across runs while legacy's freshly-recorded golden
// captured `("row10-dict-2","row10-dict-1")`. Authz-agent determinism is
// verified (5-run byte-identical); the divergence is a set-semantic
// element-order swap and is normalized here by sorting the elements
// inside every `=in=(…)` clause before diff. The same normalizer applies
// to `PSUITE_ROW_10_CHECK_FILTER_V2 / general-pip-list` for symmetry even
// though its authz-agent ordering currently matches the golden — a future
// variation in either side's array handling shouldn't re-red-flag a
// set-semantic leaf that already matches today.
//
// Every check/filter row goes through normalizeFilterOrder as well: access-control
// joins the predicates of the applicable rules in an order that differs between
// runs at every level of the expression, in every dialect, and in the apply
// arrays of customFilterCondition, and the two sub-case rewrites of this function
// cover only the leaves where that was first seen.
//
// Every outcome that records the body of a refusal goes through withoutMessage
// first, so a golden with the body and one without compare alike.
func normalizeComparable(id ParityEndpointID, subCase string, v any) any {
	v = withoutMessage(v)
	if id == PSUITE_ROW_6_CHECK_FILTER_V1 && subCase == "agg-two-predicates" {
		v = normalizeFilterTopLevelCommaTerms(v)
	}
	if id == PSUITE_ROW_10_CHECK_FILTER_V2 && (subCase == "general-pip-dict" || subCase == "general-pip-list") {
		v = normalizeFilterInClauseElements(v)
	}
	v = withSortedObligations(v)
	switch id {
	case PSUITE_ROW_6_CHECK_FILTER_V1, PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, PSUITE_ROW_10_CHECK_FILTER_V2,
		PSUITE_ROW_10_CHECK_FILTER_V2_OUTCOME:
		return normalizeFilterOrder(v)
	}
	return v
}

// withSortedObligations returns a copy of v with every list of strings in its
// obligations member sorted when v is a v2 outcome, and v itself otherwise.
// The fields of an obligation name a set of resource fields, and a merge of
// the obligations of several roles need not list them in one order from run
// to run.
func withSortedObligations(v any) any {
	switch typed := v.(type) {
	case *model.CheckResourceV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	case *model.CheckResourceBulkOperationsV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		clone.Obligations.Value = sortedStringLists(clone.Obligations.Value)
		return &clone
	}
	return v
}

// sortedStringLists returns a copy of v, a decoded JSON value, in which every
// array whose elements are all strings is sorted.
func sortedStringLists(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, value := range x {
			out[key] = sortedStringLists(value)
		}
		return out
	case []any:
		out := make([]any, len(x))
		strs := true
		for i, e := range x {
			out[i] = sortedStringLists(e)
			_, ok := e.(string)
			strs = strs && ok
		}
		if strs {
			slices.SortFunc(out, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
		}
		return out
	}
	return v
}

// withoutMessage returns a copy of v with its Message cleared when v is an
// outcome that records the body of a refusal, and v itself otherwise. The body
// is the stand's wording, which a replacement need not match; the status beside
// it is what the golden asserts.
func withoutMessage(v any) any {
	switch typed := v.(type) {
	case *model.PolicyLoadOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.FilterOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOperationsOutcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.CheckResourceBulkOperationsV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		clone.Message = nil
		return &clone
	}
	return v
}

func normalizeFilterTopLevelCommaTerms(v any) any {
	switch typed := v.(type) {
	case *model.OldFilterEvaluationResult:
		clone := *typed
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(normalizeTopLevelCommaTerms)
		return &clone
	case *model.FilterResponse:
		clone := *typed
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(normalizeTopLevelCommaTerms)
		return &clone
	default:
		return v
	}
}

func normalizeFilterInClauseElements(v any) any {
	switch typed := v.(type) {
	case *model.OldFilterEvaluationResult:
		clone := *typed
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(normalizeRsqlInElements)
		return &clone
	case *model.FilterResponse:
		clone := *typed
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(normalizeRsqlInElements)
		return &clone
	default:
		return v
	}
}

func normalizeTopLevelCommaTerms(expr string) string {
	if expr == "" || !strings.Contains(expr, ",") {
		return expr
	}

	parts := strings.Split(expr, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// normalizeRsqlInElements sorts the element list inside every `=in=(…)`
// clause in the supplied RSQL expression. Used by the D-AF-AA comparator
// allowlist extension for leaves where the rendered `in` clause is
// semantically a set — element order carries no meaning, and the legacy
// vs authz-agent diff of `("a","b")` vs `("b","a")` is a set-equivalent
// divergence. The implementation is deliberately tolerant of whitespace
// between elements and preserves the surrounding predicate shape byte-
// for-byte outside the `(…)` block.
func normalizeRsqlInElements(expr string) string {
	if expr == "" {
		return expr
	}

	var out strings.Builder
	i := 0
	for i < len(expr) {
		idx := strings.Index(expr[i:], "=in=(")
		if idx < 0 {
			out.WriteString(expr[i:])
			return out.String()
		}
		out.WriteString(expr[i : i+idx+len("=in=(")])
		start := i + idx + len("=in=(")
		close := strings.Index(expr[start:], ")")
		if close < 0 {
			out.WriteString(expr[start:])
			return out.String()
		}
		inner := expr[start : start+close]
		parts := strings.Split(inner, ",")
		for k := range parts {
			parts[k] = strings.TrimSpace(parts[k])
		}
		sort.Strings(parts)
		out.WriteString(strings.Join(parts, ", "))
		out.WriteString(")")
		i = start + close + 1
	}
	return out.String()
}

// ErrGoldenNotRecorded is returned by [GoldenComparator.Compare] when no golden
// file exists for the case. A case whose golden is expected to exist treats it
// as a failure; a case written ahead of its golden capture skips on it (see
// requirePendingGolden).
var ErrGoldenNotRecorded = errors.New("golden not recorded")

// GoldenMismatchError carries the diff text so the testify assertion layer
// can surface it via s.T().Errorf without re-invoking cmp.Diff.
type GoldenMismatchError struct {
	GoldenPath string
	Diff       string
}

func (e *GoldenMismatchError) Error() string {
	return fmt.Sprintf("golden mismatch at %s:\n%s", e.GoldenPath, e.Diff)
}
