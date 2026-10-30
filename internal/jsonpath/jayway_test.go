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

//go:build jayway

package jsonpath

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"authz-agent/internal/jsonvalue"
)

// This file compares Select with Jayway JsonPath, which the legacy service
// evaluates its paths with. It runs only under the build tag jayway:
//
//	JAYWAY_CLASSPATH=<json-path 2.9.0, jackson-databind, and their dependencies> \
//	go test -count=1 -tags jayway -run Jayway ./internal/jsonpath/
//
// make test-jayway resolves the class path with Maven and runs the same
// command. The test skips without JAYWAY_CLASSPATH and fails where it is set
// and java is not on the PATH; Run.java needs java 17 or later. go test does not see a change to
// Run.java, so -count=1 keeps it from reusing a cached result.

// knownJaywayDifferences names the cases whose answer differs from Jayway's,
// with what Jayway does instead. A case listed here fails if it agrees with
// Jayway, so the list cannot outlive a difference.
var knownJaywayDifferences = map[string]string{
	"keys of an object":        "Jayway returns the keys as a set; the agent returns its Java text, [p, r]",
	"keys keep document order": "Jayway returns the keys as a set; the agent returns its Java text, [z, a]",
	"keys after a star over objects": "Jayway returns the keys of each object as a set; " +
		"the agent returns the Java text of each set, [x]",
}

// knownJaywayBugs names the cases where Jayway 2.9.0 has a bug the package
// does not repeat, with what Jayway does. A listed case fails once Jayway
// agrees with the package, so the list cannot outlive a fix.
var knownJaywayBugs = map[string]string{
	"regex does not match a missing member":                            "matches a missing member as empty text",
	"regex does not match null":                                        "matches null as empty text",
	"regex does not match an object":                                   "matches an object as empty text",
	"regex reads a list element that looks like a path as text":        "reads a document string that compiles as a path as a path, which matches as empty text",
	"regex reads a list element that looks like a longer path as text": "reads a document string that compiles as a path as a path, which matches as empty text",
	"regex reads a list element that looks like JSON as text":          "reads a document string that parses as JSON as JSON, which matches as empty text",
	"regex reads a list element as written":                            "unescapes a document string in a list",
	"regex over a list skips an object element":                        "throws \"Could not determine value type\" for an object in a document list",
	"subsetof over a list holding an object is false":                  "throws \"Could not determine value type\" for an object in a document list",
	"anyof reads a list element with its quotes":                       "strips one pair of quotes from a document string in a list",
	"a list item that looks like a path is text":                       "reads a list item that compiles as a path as a path, which equals nothing",
	"a list item that looks like JSON is text":                         "reads a list item that parses as JSON as JSON, which equals no string",
	"a list item is unescaped once":                                    "unescapes a list item twice, once as JSON and once as a literal",
	"a list item keeps double quotes":                                  "strips one pair of double quotes from a list item",
	"empty over an object tests its members":                           "throws ClassCastException for empty over an object",
	"slice from a negative start to a positive end":                    "wraps a negative start of [a:b] around the list (json-path/JsonPath#1076)",
	"slice from before the start to a positive end":                    "wraps a negative start of [a:b] around the list (json-path/JsonPath#1076)",
	"first after a star drops an empty object member":                  "throws IndexOutOfBoundsException for first() of an empty list reached through an object member",
	"last of one element":                                              "throws for last() of a one-element list: it reads index size-1 only where that is above 0",
	"last after a star with a one-element list":                        "throws for last() of a one-element list: it reads index size-1 only where that is above 0",
	"max of negative numbers":                                          "starts max() at Double.MIN_VALUE, the smallest positive double (json-path/JsonPath#942)",
	"max of zero":                                                      "starts max() at Double.MIN_VALUE, the smallest positive double (json-path/JsonPath#942)",
	"max of a negative infinity":                                       "starts max() at Double.MIN_VALUE, the smallest positive double (json-path/JsonPath#942)",
	"min of an infinity":                                               "starts min() at Double.MAX_VALUE, so an infinity never replaces it (json-path/JsonPath#942)",
	"nested filter selects a member the inner filter selects something in": "selects an element whose member is any list " +
		"or object, as it tests only that the path exists",
	"nested filter tests an object member itself": "selects an element whose member is any list or object, " +
		"as it tests only that the path exists",
	"nested filter over an object member the inner filter rejects": "selects an element whose member is any list or " +
		"object, as it tests only that the path exists",
	"slice to a negative end counts it from the end":               "does not count a negative end of [a:b] from the end (json-path/JsonPath#1081)",
	"slice from a negative start counts it from the end":           "wraps a negative start of [a:b] around the list (json-path/JsonPath#1076)",
	"last after a star drops an empty list element":                "throws for last() of an empty list, where it drops first() of one",
	"anyof compares a list element that looks like a path as text": "reads a document string that compiles as a path as a path, which equals nothing",
}

// jaywayAnswer is one line Run.java prints.
type jaywayAnswer struct {
	ID           string          `json:"id"`
	Value        json.RawMessage `json:"value"`
	CompileError string          `json:"compileError"`
	Error        string          `json:"error"`
	Message      string          `json:"message"`
}

func TestSelect_AgreesWithJayway(t *testing.T) {
	var cases []selectCase
	cases = append(cases, sharedCases...)
	cases = append(cases, ownDocumentCases...)
	for _, set := range [][]selectCase{
		jaywayCases, lengthOfStringCases, intRangeCases, asciiClassCases, asciiFoldCases, exactNumberCases, sumCases,
	} {
		cases = append(cases, set...)
	}
	known := maps.Clone(knownJaywayDifferences)
	maps.Copy(known, knownJaywayBugs)
	// Every case is compared but the one that starts with ['key'].
	compareWithJayway(t, cases, known, len(cases)-1)
}

// TestSelect_ComparisonSuiteAgreesWithJayway runs the queries of a local
// checkout of github.com/cburgmer/json-path-comparison, named by
// JSONPATH_COMPARISON_DIR, through Select and Jayway. The suite is under
// GPL-3.0, so the test reads it in place and the repository holds none of it.
// A query outside the subset is skipped, and at least
// minComparedSuiteQueries are compared, so that a regression in Compile
// cannot pass by skipping queries.
func TestSelect_ComparisonSuiteAgreesWithJayway(t *testing.T) {
	dir := os.Getenv("JSONPATH_COMPARISON_DIR")
	if dir == "" {
		t.Skip("JSONPATH_COMPARISON_DIR is not set")
	}
	selectors, err := filepath.Glob(filepath.Join(dir, "queries", "*", "selector"))
	if err != nil || len(selectors) == 0 {
		t.Fatalf("no queries under %s: %v", dir, err)
	}
	var cases []selectCase
	for _, sel := range selectors {
		selector, err := os.ReadFile(sel)
		if err != nil {
			t.Fatal(err)
		}
		document, err := os.ReadFile(filepath.Join(filepath.Dir(sel), "document.json"))
		if err != nil {
			t.Fatal(err)
		}
		path, ok := strings.CutPrefix(strings.TrimSpace(string(selector)), "$")
		if !ok {
			continue
		}
		cases = append(cases, selectCase{name: filepath.Base(filepath.Dir(sel)), doc: string(document), path: path})
	}
	compareWithJayway(t, cases, knownComparisonSuiteDifferences, minComparedSuiteQueries)
}

// TestSelect_JaywayTestSuiteAgreesWithJayway runs the paths and documents
// that Jayway JsonPath's own tests evaluate through Select and Jayway.
// JAYWAY_SUITE_CALLS names the directory that testdata/jayway/recorder writes
// while those tests run; make jayway-suite-calls fills it. A pair that several
// tests evaluate is compared once, named after the first test in name order,
// as Class.method#n for the method's nth recorded call. Jayway reads a path
// that starts with neither $ nor @ as if it started with "$.", and so does the
// test. A path that starts with @ is skipped, as Compile takes the part of a
// path after the $. At least minComparedJaywaySuiteCalls pairs are compared.
func TestSelect_JaywayTestSuiteAgreesWithJayway(t *testing.T) {
	dir := os.Getenv("JAYWAY_SUITE_CALLS")
	if dir == "" {
		t.Skip("JAYWAY_SUITE_CALLS is not set")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no recorded calls under %s: %v", dir, err)
	}
	type call struct {
		Test         string  `json:"test"`
		Seq          int     `json:"seq"`
		Path         string  `json:"path"`
		Doc          *string `json:"doc"`
		CompileError bool    `json:"compileError"`
	}
	type pair struct{ doc, path string }
	names := map[pair]string{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for line := range bytes.Lines(data) {
			var c call
			if err := json.Unmarshal(line, &c); err != nil {
				t.Fatalf("%s: %v: %s", file, err, line)
			}
			var path string
			switch {
			case strings.HasPrefix(c.Path, "$"):
				path = c.Path[1:]
			case strings.HasPrefix(c.Path, "@"):
				continue
			default:
				path = "." + c.Path
			}
			doc := "null"
			if !c.CompileError {
				var buf bytes.Buffer
				if err := json.Compact(&buf, []byte(*c.Doc)); err != nil {
					t.Fatalf("%s: the document of %s#%d is not JSON: %v", file, c.Test, c.Seq, err)
				}
				doc = buf.String()
			}
			name := fmt.Sprintf("%s#%d", c.Test, c.Seq)
			if old, seen := names[pair{doc, path}]; !seen || name < old {
				names[pair{doc, path}] = name
			}
		}
	}
	cases := make([]selectCase, 0, len(names))
	for p, name := range names {
		cases = append(cases, selectCase{name: name, doc: p.doc, path: p.path})
	}
	slices.SortFunc(cases, func(a, b selectCase) int { return strings.Compare(a.name, b.name) })
	compareWithJayway(t, cases, knownJaywaySuiteDifferences, minComparedJaywaySuiteCalls)
}

// minComparedJaywaySuiteCalls is a little below the 395 pairs from the tests
// of Jayway JsonPath 2.9.0 that the package compiles or that Jayway and the
// package both refuse.
const minComparedJaywaySuiteCalls = 390

// knownJaywaySuiteDifferences names the pairs from Jayway's own tests whose
// answer differs from Jayway's, with what Jayway does instead.
var knownJaywaySuiteDifferences = map[string]string{
	"internal.function.KeySetFunctionTest.testKeySet#1": "Jayway returns the keys as a set; the agent returns its Java text, [a, b]",
}

// minComparedSuiteQueries is a little below the 144 json-path-comparison
// queries at the pinned commit that the package compiles or that Jayway and
// the package both refuse.
const minComparedSuiteQueries = 140

// compareWithJayway runs every case through Select and Jayway as a subtest.
// A case fails where the answers differ and known does not list it, or where
// they agree and known lists it, and where Compile accepts a path Jayway does
// not compile. A path that both refuse to compile agrees. The test fails
// where fewer than minCompared cases are compared, and where a name in known
// is not among them.
func compareWithJayway(t *testing.T, cases []selectCase, known map[string]string, minCompared int) {
	t.Helper()
	answers := runJayway(t, cases)
	compared := map[string]bool{}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a := answers[tt.name]
			root, err := jsonvalue.Decode([]byte(tt.doc))
			if err != nil {
				t.Skipf("Decode: %v", err)
			}
			p, err := Compile(tt.path)
			if err == nil && p.refused {
				// the path compiles to select nothing because Jayway does
				// not compile it
				err = errJaywayRefuses
			}
			switch {
			case err != nil && a.CompileError != "":
				compared[tt.name] = true
				if reason, listed := known[tt.name]; listed {
					t.Errorf("Compile(%s) and Jayway both refuse the path, but the case is listed as a difference: %s",
						tt.path, reason)
				}
				return
			case err != nil:
				t.Skipf("Compile: %v", err)
			case a.CompileError != "":
				compared[tt.name] = true
				t.Fatalf("Compile(%s) accepts a path Jayway refuses: %s: %s", tt.path, a.CompileError, a.Message)
			}
			r := p.Select(root)
			if r.Kind == KindBracket {
				t.Skip("a leading ['key'] is a rule of the policy language, not of Jayway")
			}
			compared[tt.name] = true
			same, jayway := agrees(t, r, a)
			reason, listed := known[tt.name]
			switch {
			case !same && !listed:
				t.Errorf("Select(%s) = %s %s, Jayway %s", tt.path, r.Kind, resultText(r), jayway)
			case same && listed:
				t.Errorf("Select(%s) agrees with Jayway (%s), but the case is listed as a difference: %s",
					tt.path, jayway, reason)
			}
		})
	}
	for name := range known {
		if !compared[name] {
			t.Errorf("%q is listed as a difference, but no case of that name was compared with Jayway", name)
		}
	}
	if len(compared) < minCompared {
		t.Errorf("compared %d cases with Jayway, want at least %d", len(compared), minCompared)
	}
}

// knownComparisonSuiteDifferences names the queries of json-path-comparison
// whose answer differs from Jayway's, with what Jayway does instead.
var knownComparisonSuiteDifferences = map[string]string{
	"filter_expression_with_subfilter": "Jayway bug: it selects an element whose member is any list, as it tests " +
		"only that the nested path exists",
	"array_slice_with_negative_start_and_positive_end_and_range_of_-1": "Jayway bug: it wraps a negative start " +
		"of [a:b] around the list (json-path/JsonPath#1076)",
	"array_slice_with_negative_start_and_positive_end_and_range_of_0": "Jayway bug: it wraps a negative start " +
		"of [a:b] around the list (json-path/JsonPath#1076)",
	"array_slice_with_negative_start_and_positive_end_and_range_of_1": "Jayway bug: it wraps a negative start " +
		"of [a:b] around the list (json-path/JsonPath#1076)",
	"array_slice_with_positive_start_and_negative_end_and_range_of_1": "Jayway bug: it does not count a negative " +
		"end of [a:b] from the end (json-path/JsonPath#1081)",
}

// runJayway evaluates every case with Run.java and returns the answers by
// case name.
func runJayway(t *testing.T, cases []selectCase) map[string]jaywayAnswer {
	t.Helper()
	classpath := os.Getenv("JAYWAY_CLASSPATH")
	if classpath == "" {
		t.Skip("JAYWAY_CLASSPATH is not set")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("JAYWAY_CLASSPATH is set, but java is not on the PATH: %v", err)
	}
	type input struct {
		ID   string `json:"id"`
		Doc  string `json:"doc"`
		Path string `json:"path"`
	}
	in := make([]input, len(cases))
	for i, c := range cases {
		in[i] = input{ID: c.name, Doc: c.doc, Path: "$" + c.path}
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), java, "-cp", classpath, filepath.Join("testdata", "jayway", "Run.java"), file)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Run.java: %v\n%s", err, stderr.String())
	}
	answers := map[string]jaywayAnswer{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<24)
	for sc.Scan() {
		var a jaywayAnswer
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatalf("Run.java printed %s: %v", sc.Text(), err)
		}
		answers[a.ID] = a
	}
	for _, c := range cases {
		if _, ok := answers[c.name]; !ok {
			t.Fatalf("Run.java printed no answer for %q; case names must be unique", c.name)
		}
	}
	if len(answers) != len(cases) {
		t.Fatalf("Run.java answered %d cases of %d; case names must be unique", len(answers), len(cases))
	}
	return answers
}

// agrees reports whether r is what the legacy service makes of Jayway's
// answer a, and returns that answer as text. The legacy service ends the rule
// on any exception Jayway throws while it reads a path, as it does where
// Jayway finds nothing; KindMissing, KindNullParent, and KindIndexOutOfBounds
// are the ways a path finds nothing. A list of several values becomes a set,
// so KindMany agrees with a list that holds the same values in any order.
func agrees(t *testing.T, r Result, a jaywayAnswer) (bool, string) {
	t.Helper()
	if a.Error != "" {
		nothing := r.Kind == KindMissing || r.Kind == KindNullParent || r.Kind == KindIndexOutOfBounds
		return nothing, a.Error + ": " + a.Message
	}
	v, err := jsonvalue.Decode(a.Value)
	if err != nil {
		t.Fatalf("Decode(%s): %v", a.Value, err)
	}
	switch r.Kind {
	case KindOne:
		return sameJSON(r.Value, v), string(a.Value)
	case KindMany:
		list, ok := v.([]jsonvalue.Value)
		return ok && sameElements(r.Value.([]jsonvalue.Value), list), string(a.Value)
	}
	return false, string(a.Value)
}

func resultText(r Result) string {
	if r.Kind == KindOne || r.Kind == KindMany {
		return text(r.Value)
	}
	return ""
}

// sameJSON compares two values as JSON, with numbers compared as exact decimals,
// so 1 equals 1.0. A Number such as Infinity equals the object Run.java
// prints for that double.
func sameJSON(a, b jsonvalue.Value) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case jsonvalue.Number:
		if obj, ok := b.(*jsonvalue.Object); ok {
			d, _ := obj.Get("double")
			return obj.Len() == 1 && d == string(x)
		}
		y, ok := b.(jsonvalue.Number)
		if !ok {
			return false
		}
		dx, okx := jsonvalue.ParseDecimal(string(x))
		dy, oky := jsonvalue.ParseDecimal(string(y))
		return okx && oky && dx.Compare(dy) == 0
	case []jsonvalue.Value:
		y, ok := b.([]jsonvalue.Value)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case *jsonvalue.Object:
		y, ok := b.(*jsonvalue.Object)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for _, k := range x.Keys() {
			xv, _ := x.Get(k)
			yv, ok := y.Get(k)
			if !ok || !sameJSON(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

// sameElements reports whether a and b hold equal values with equal counts,
// in any order.
func sameElements(a, b []jsonvalue.Value) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, x := range a {
		found := false
		for j, y := range b {
			if !used[j] && sameJSON(x, y) {
				used[j], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
