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

package acconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

// exportBundleEnv names the directory of an export bundle: the v3 exports the
// executable specification predicts for the recorded parity cases, each with
// the conversion the specification expects this package to produce.
const exportBundleEnv = "PARITY_EXPORT_BUNDLE"

// bundleExport is one file under exports/ of the bundle. Every list holds ids
// of elements.json, which stores each element of every export once.
type bundleExport struct {
	PolicySets []string `json:"policySets"`
	PIPs       []string `json:"pips"`
	Agent      struct {
		Pull     string         `json:"pull"`
		Error    string         `json:"error"`
		Policies []string       `json:"policies"`
		PIPs     []string       `json:"pips"`
		Stats    map[string]int `json:"stats"`
	} `json:"agent"`
}

// joinElements builds a JSON list of the elements ids name, wrapped in an
// object under member when member is not empty.
func joinElements(elements map[string]json.RawMessage, member string, ids []string) (json.RawMessage, error) {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		el, ok := elements[id]
		if !ok {
			return nil, fmt.Errorf("no element %s in elements.json", id)
		}
		parts = append(parts, string(el))
	}
	list := "[" + strings.Join(parts, ",") + "]"
	if member == "" {
		return json.RawMessage(list), nil
	}
	return json.RawMessage(fmt.Sprintf("{%q:%s}", member, list)), nil
}

// exportRefusedEnv names the file TestExportBundleConformance writes the
// conditions the agent's parser refuses to, as a JSON object from the
// condition text to the parser's error.
const exportRefusedEnv = "PARITY_EXPORT_REFUSED_OUT"

// TestExportBundleConformance compares the conversion of every export in the
// bundle named by PARITY_EXPORT_BUNDLE with the conversion the bundle predicts:
// whether the pull succeeds, the simplified policies, the PIPs, and the skip
// counts. The parity suite's export-fed profile and the specification's
// comparison with the legacy decisions both rest on that prediction, so a
// mismatch means the prediction, not this package, needs fixing until the
// conversion is changed on purpose.
//
// The prediction does not parse conditions: it reads the conditions the
// agent's parser refuses from a list this test writes to the file named by
// PARITY_EXPORT_REFUSED_OUT. A pull that fails on a condition missing from that
// list fails the test; rerun it with the variable set and give the file to the
// specification.
func TestExportBundleConformance(t *testing.T) {
	dir := os.Getenv(exportBundleEnv)
	if dir == "" {
		t.Skipf("%s names no bundle directory", exportBundleEnv)
	}
	problems, refused, n, err := checkExportBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	t.Logf("%d exports compared, %d distinct conditions the agent's parser refuses", n, len(refused))
	if out := os.Getenv(exportRefusedEnv); out != "" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(refused); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The committed bundle under testdata holds two exports whose predictions
// match the conversion (a pull that succeeds, and one the agent's parser
// fails) and one export wrong in each slot the test compares (the outcome of
// the pull, the policies, the counts), so the comparison runs on every build
// and its negative control fires.
func TestExportBundleConformance_ReportsEveryPredictionThatDiffers(t *testing.T) {
	problems, refused, n, err := checkExportBundle("testdata/export-bundle")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("checkExportBundle compared %d exports, want the 5 of the fixture", n)
	}
	want := []string{
		"export mistyped: pull = failed",
		"export wrong-policies: policies differ",
		"export wrong-stats: stats = ",
	}
	if len(problems) != len(want) {
		t.Fatalf("problems = %q, want one per export that differs: %q", problems, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(problems[i], w) {
			t.Errorf("problem %d = %q, want it to start with %q", i, problems[i], w)
		}
	}
	if refused["true < 'v'"] == "" {
		t.Errorf("refused = %v, want the condition true < 'v' the fixture's parser refuses", refused)
	}
}

// A float64 holds every integer only up to 2^53, so a prediction off by one
// above it has to differ, while the same number written another way does not.
func TestJSONDiff_ComparesNumbersExactly(t *testing.T) {
	cases := []struct {
		name, got, predicted string
		same                 bool
	}{
		{"the same integer above 2^53", `{"defaultValue":9007199254740993}`, `{"defaultValue":9007199254740993}`, true},
		{"an integer above 2^53 and its float64 neighbor", `{"defaultValue":9007199254740993}`, `{"defaultValue":9007199254740992}`, false},
		{"an integer and the same value with a fraction", `[5]`, `[5.0]`, true},
		{"a number and its text", `[5]`, `["5"]`, false},
	}
	for _, tc := range cases {
		d := jsonDiff(roundTripJSON(json.RawMessage(tc.got)), json.RawMessage(tc.predicted))
		if (d == "") != tc.same {
			t.Errorf("%s: jsonDiff(%s, %s) = %q, want equal: %v", tc.name, tc.got, tc.predicted, d, tc.same)
		}
	}
}

func TestJSONDiff_PrintsNumbersAsNumbers(t *testing.T) {
	d := jsonDiff(roundTripJSON(json.RawMessage(`[5, 5.5, 1e-3]`)), json.RawMessage(`["5", 5.5, 0.001]`))
	for _, want := range []string{`got       [5,5.5,0.001]`, `predicted ["5",5.5,0.001]`} {
		if !strings.Contains(d, want) {
			t.Errorf("jsonDiff = %q, want it to contain %q", d, want)
		}
	}
}

// checkExportBundle compares every export of the bundle in dir with its
// prediction and returns one problem per export that differs, sorted by
// export id, the conditions the agent's parser refuses, and the number of
// exports read.
func checkExportBundle(dir string) (problems []string, refused map[string]string, n int, err error) {
	files, err := filepath.Glob(filepath.Join(dir, "exports", "*.json"))
	if err != nil || len(files) == 0 {
		return nil, nil, 0, fmt.Errorf("no exports under %s: %v", filepath.Join(dir, "exports"), err)
	}
	sort.Strings(files)
	rawElements, err := os.ReadFile(filepath.Join(dir, "elements.json"))
	if err != nil {
		return nil, nil, 0, err
	}
	var elements map[string]json.RawMessage
	if err := json.Unmarshal(rawElements, &elements); err != nil {
		return nil, nil, 0, fmt.Errorf("decode elements: %w", err)
	}
	refused = map[string]string{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, 0, err
		}
		var ex bundleExport
		if err := json.Unmarshal(raw, &ex); err != nil {
			return nil, nil, 0, fmt.Errorf("decode %s: %w", file, err)
		}
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		problem, conds, err := checkExport(elements, ex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("export %s: %w", name, err)
		}
		for c, msg := range conds {
			refused[c] = msg
		}
		if problem != "" {
			problems = append(problems, "export "+name+": "+problem)
		}
	}
	return problems, refused, len(files), nil
}

// checkExport compares one export's conversion with its prediction: the
// outcome of the pull, then for a pull that succeeds the policies, the PIPs
// and the counts, and returns the first slot that differs.
func checkExport(elements map[string]json.RawMessage, ex bundleExport) (string, map[string]string, error) {
	policySets, err := joinElements(elements, "policySets", ex.PolicySets)
	if err != nil {
		return "", nil, err
	}
	pipsDoc, err := joinElements(elements, "pips", ex.PIPs)
	if err != nil {
		return "", nil, err
	}
	got := convertLikeThePull(policySets, pipsDoc)
	refused := refusedConditions(policySets)
	if got.pull != ex.Agent.Pull {
		return fmt.Sprintf("pull = %s (%s), predicted %s (%s)", got.pull, got.err, ex.Agent.Pull, ex.Agent.Error), refused, nil
	}
	if got.pull != "ok" {
		return "", refused, nil
	}
	wantPolicies, err := joinElements(elements, "", ex.Agent.Policies)
	if err != nil {
		return "", nil, err
	}
	wantPIPs, err := joinElements(elements, "", ex.Agent.PIPs)
	if err != nil {
		return "", nil, err
	}
	if diff := jsonDiff(got.policies, wantPolicies); diff != "" {
		return "policies differ from the prediction: " + diff, refused, nil
	}
	if diff := jsonDiff(got.pips, wantPIPs); diff != "" {
		return "PIPs differ from the prediction: " + diff, refused, nil
	}
	if want := predictedStats(ex.Agent.Stats); got.stats != want {
		return fmt.Sprintf("stats = %+v, predicted %+v", got.stats, want), refused, nil
	}
	return "", refused, nil
}

// refusedConditions returns each condition of the converted policies that
// NormalizePolicies refuses on its own, with the parser's error.
func refusedConditions(policySets json.RawMessage) map[string]string {
	policies, _, err := ConvertPolicySets(policySets, discardLogger())
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, p := range policies {
		cond, ok := p.Condition.(string)
		if !ok {
			continue
		}
		if _, err := simplifiedpolicies.NormalizePolicies([]simplifiedpolicies.Policy{p}); err != nil &&
			!strings.Contains(err.Error(), "is required") {
			out[cond] = strings.TrimPrefix(err.Error(), "simplified policy 0: ")
		}
	}
	return out
}

type pulled struct {
	pull     string
	err      string
	policies any
	pips     any
	stats    Stats
}

// convertLikeThePull runs the steps of the agent's pull after the fetch: both
// conversions, then the normalization of policies and PIPs. The pull also
// loads the documents (activation index, entitlements, store), which cannot
// fail on a converted export and is left out. pull is "ok", "failed" (the
// agent keeps its previous documents), or "crash" (normalization panics on a
// goroutine with no recover, which ends the agent).
func convertLikeThePull(policySets, pipsRaw json.RawMessage) (out pulled) {
	out.pull = "failed"
	policies, stats, err := ConvertPolicySets(policySets, discardLogger())
	if err != nil {
		out.err = err.Error()
		return out
	}
	pipList, err := ConvertPIPs(pipsRaw, discardLogger())
	if err != nil {
		out.err = err.Error()
		return out
	}
	if _, err := simplifiedpolicies.NormalizePolicies(policies); err != nil {
		out.err = err.Error()
		return out
	}
	if err := normalizePIPs(pipList); err != nil {
		out.pull, out.err = "crash", err.Error()
		return out
	}
	out.pull, out.policies, out.pips, out.stats = "ok", roundTripJSON(policies), roundTripJSON(pipList), stats
	return out
}

// normalizePIPs turns a panic of pips.NormalizeItems into an error: the pull
// loop runs it on a goroutine with no recover, so a panic there ends the agent.
func normalizePIPs(items []pips.SimplifiedPIP) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("normalize pips: panic: %v", r)
		}
	}()
	_, _, err = pips.NormalizeItems(items)
	return err
}

func predictedStats(m map[string]int) Stats {
	return Stats{
		PolicySets:        m["policy_sets"],
		PolicySetsSkipped: m["policy_sets_skipped"],
		Rules:             m["rules"],
		RulesSkipped:      m["rules_skipped"],
		RulesDenySkipped:  m["rules_deny_skipped"],
		Policies:          m["policies"],
	}
}

func roundTripJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out, err := decodeExact(raw)
	if err != nil {
		panic(err)
	}
	return out
}

// exactNumber is a JSON number in lowest terms, so that 5 and 5.0 are equal
// and two integers above 2^53 that a float64 would merge are not.
type exactNumber string

// MarshalJSON writes the number as an exact decimal, so a difference that
// jsonDiff prints shows numbers as numbers: 11/2 as 5.5.
func (n exactNumber) MarshalJSON() ([]byte, error) {
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return nil, fmt.Errorf("not a number: %s", string(n))
	}
	// A number decoded from JSON text is a decimal fraction, so some number of
	// digits after the point prints it exactly.
	for digits := 0; digits <= 1100; digits++ {
		text := r.FloatString(digits)
		if back, _ := new(big.Rat).SetString(text); back.Cmp(r) == 0 {
			return []byte(text), nil
		}
	}
	return json.Marshal(string(n))
}

// decodeExact decodes raw as json.Unmarshal into any does, except that every
// number becomes an exactNumber.
func decodeExact(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return exactNumbers(v)
}

func exactNumbers(v any) (any, error) {
	switch t := v.(type) {
	case json.Number:
		r, ok := new(big.Rat).SetString(string(t))
		if !ok {
			return nil, fmt.Errorf("not a number: %s", t)
		}
		return exactNumber(r.RatString()), nil
	case []any:
		for i := range t {
			e, err := exactNumbers(t[i])
			if err != nil {
				return nil, err
			}
			t[i] = e
		}
	case map[string]any:
		for k := range t {
			e, err := exactNumbers(t[k])
			if err != nil {
				return nil, err
			}
			t[k] = e
		}
	}
	return v, nil
}

// jsonDiff returns "" when got and the predicted JSON hold the same values,
// else both texts.
func jsonDiff(got any, predicted json.RawMessage) string {
	var want any
	if len(predicted) > 0 {
		var err error
		if want, err = decodeExact(predicted); err != nil {
			return "the prediction is not JSON: " + err.Error()
		}
	}
	if gotNil, wantNil := isEmptyList(got), isEmptyList(want); gotNil && wantNil {
		return ""
	}
	if reflect.DeepEqual(got, want) {
		return ""
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	return fmt.Sprintf("\n  got       %s\n  predicted %s", g, w)
}

func isEmptyList(v any) bool {
	if v == nil {
		return true
	}
	l, ok := v.([]any)
	return ok && len(l) == 0
}
