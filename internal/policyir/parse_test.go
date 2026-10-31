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
	"testing"
)

// The expected lines are FormatCondition of the tree the specification's
// parser builds for the same text.
func TestParseCondition(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.a == 'y'", `resource.a EQ "y"`},
		{"a = 'y'", `resource.a EQ "y"`},
		{"resourceX == 1", `resource.resourceX EQ 1`},
		{"resource IS EMPTY", `resource IS_EMPTY`},
		{"resource.a.b. == 1", `resource.a.b. EQ 1`},
		{"resource.l[0]. == 1", `resource.l[0]. EQ 1`},
		{"resource.a.. == 1", `unsupported(jsonpath "resource.a..") EQ 1`},
		{"resource[ 0 ] == 1", `resource[0] EQ 1`},
		{"resource.a[?(@.key == '[ 0 ]')].id == 's'", `resource.a[?(@.key == '[ 0 ]')].id EQ "s"`},
		{"resource.a[?(@.s =~ /[ 0 ]/)].id CONTAINS 'space'", `resource.a[?(@.s =~ /[ 0 ]/)].id CONTAINS "space"`},
		{"resource.a[?(@.s =~ /[ 0 ]/)][ 1 ] == 1", `resource.a[?(@.s =~ /[ 0 ]/)][1] EQ 1`},
		{"subject.l[0] IS NULL", `resource.subject.l[0] IS_NULL`},
		{"resource.a GREATER THAN OR EQUAL TO 5", `resource.a GE 5`},
		{"resource.a IS NOT NULL", `resource.a IS_NOT_NULL`},
		{"resource.a == null", `resource.a EQ resource.null`},
		{"resource.a == TRUE", `resource.a EQ true`},
		{"operation IN 'READ', 'EDIT'", `operation IN ["READ", "EDIT"] raw="'READ', 'EDIT'"`},
		{"resource.n IN 1,2", `resource.n IN [1, 2] raw="1,2"`},
		{"subject.roles CONTAINS ANY 'A'", `subject.roles CONTAINS_ANY ["A"]`},
		{"resource.p MATCH /api/*", `resource.p MATCH pattern("/api/*")`},
		{"resource.p MATCH resource.q", `resource.p MATCH pattern("resource.q")`},
		{"resource.v MATCH resource.*", `resource.v MATCH pattern("resource.*")`},
		{"resource.v NOT MATCH resource.*", `resource.v NOT_MATCH pattern("resource.*")`},
		{"resource.v MATCH subject.l[:]", `resource.v MATCH pattern("subject.l[:]")`},
		{"resource.v MATCH resource.a[0, 1]", `resource.v MATCH pattern("resource.a[0, 1]")`},
		{"subject allowed 'EDIT' on resource OR subject.isM2M", `subject allowed "EDIT" on resource OR subject.isM2M`},
		{"TRUE AND resource.a == 1", `TRUE AND resource.a EQ 1`},
		{"subject.region.code == 'x'", `pip("subject.region.code") EQ "x"`},
		{"subject.permissionScope == 'x'", `pip("subject.permissionScope") EQ "x"`},
		{"subject.permissionScope.a.b == 'x'", `subject.permissionScope["a.b"] EQ "x"`},
		{"subject.permissionScopes == 'x'", `pip("subject.permissionScopes") EQ "x"`},
		{"subject.permissionScopeFoo.a == 'x'", `pip("subject.permissionScopeFoo.a") EQ "x"`},
		{"resource.x IN subject.owners FILTERED 'READ'", `resource.x IN pip("subject.owners.filtered") FILTERED "READ"`},
		{"subject.entitledResources.of('order').as('id','owner') CONTAINS resource.id",
			`subject.entitledResources.of("order").as["id", "owner"] CONTAINS resource.id`},
		{"resource.items[?(@.k == 'v')].length() == 1", `resource.items[?(@.k == 'v')].length() EQ 1`},
		{"resource.a == 'y'\n", `resource.a EQ "y"`},
		{"", `TRUE`},
		{"False", `FALSE`},
		{" tRuE\t", `TRUE`},
		{"\x01false\x0b", `FALSE`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

// The raw token of a list runs from its first item to its last as written,
// whatever literal precedes the list.
func TestParseConditionKeepsTheListTokenAsWritten(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.a == 10 AND resource.x IN 'p','q'", `resource.a EQ 10 AND resource.x IN ["p", "q"] raw="'p','q'"`},
		{"resource.a == 'xy' AND resource.n IN 1, 2", `resource.a EQ "xy" AND resource.n IN [1, 2] raw="1, 2"`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

// An operand is the token the legacy lexer reads: its longest token, and on a
// tie the boolean, the subject attribute, the PIP, or the permission scope
// rather than the resource attribute. Each row that the attribute token wins
// stands beside a control the shorter token wins. Booleans with a comma used
// to read as a list, subject.x-y and subject.1x as PIPs, and the key of
// subject.permissionScope.a[0] as a resource path.
func TestParseConditionReadsTheLongestLegacyToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.x IN true,false", `resource.x IN unsupported(jsonpath "true,false")`},
		{"resource.x IN FALSE,true", `resource.x IN unsupported(jsonpath "FALSE,true")`},
		{"resource.x == true", `resource.x EQ true`},
		{"resource.x IN null,false", `resource.x IN unsupported(jsonpath "null,false")`},
		{"subject.x-y == 'v'", `resource.subject.x-y EQ "v"`},
		{"subject.1x == 'v'", `resource.subject.1x EQ "v"`},
		{"subject.x_y == 'v'", `pip("subject.x_y") EQ "v"`},
		{"subject.id.region == 'eu'", `pip("subject.id.region") EQ "eu"`},
		{"subject.id == 'eu'", `subject.id EQ "eu"`},
		{"subject.entitledResources == 'eu'", `pip("subject.entitledResources") EQ "eu"`},
		{"subject.roles. CONTAINS 'r'", `resource.subject.roles. CONTAINS "r"`},
		{"subject.roles CONTAINS 'r'", `subject.roles CONTAINS "r"`},
		{"subject.permissionScope.a[0] == 'v'", `subject.permissionScope["a[0]"] EQ "v"`},
		{"subject.permissionScope.a[ 0 ] == 'v'", `subject.permissionScope["a[ 0 ]"] EQ "v"`},
		{"subject.permissionScope.a. == 'v'", `subject.permissionScope["a."] EQ "v"`},
		{"subject.permissionScope.a == 'v'", `subject.permissionScope["a"] EQ "v"`},
		{"subject.permissionScope._a == 'v'", `subject.permissionScope["_a"] EQ "v"`},
		{"subject.permissionScope.1a == 'v'", `resource.subject.permissionScope.1a EQ "v"`},
		{"subject.permissionScope.a] IS NULL", `unsupported(jsonpath "subject.permissionScope.a]") IS_NULL`},
		{"subject.permissionScope.ab] IS NULL", `subject.permissionScope["ab]"] IS_NULL`},
		{"resource.v MATCH subject.x-y", `resource.v MATCH pattern("subject.x-y")`},
		{"resource.v MATCH subject.name%", `resource.v MATCH pattern("subject.name%")`},
		{"resource.v MATCH a#b", `resource.v MATCH pattern("a#b")`},
		{"resource.v MATCH resource.subject.x-y", `resource.v MATCH pattern("resource.subject.x-y")`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

func TestParseConditionRefuses(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, text, reason string }{
		{"two spaces between tokens", "resource.a  == 'y'", "double space"},
		{"no spaces around a comparison", "resource.a=='y'", "no space around a comparison"},
		{"a double-quoted string", `resource.a == "y"`, "double-quoted string"},
		{"a lower-case connective", "resource.a == 'y' or resource.b == 'z'", "lower-case keyword"},
		{"no space before a connective", "resource.a == 'y'AND resource.b == 'z'", "no space before a connective"},
		{"a standalone NOT", "NOT resource.a == 1", "standalone NOT"},
		{"a number with a leading zero after the minus", "resource.a == -05", "number: -05"},
		{"a list of strings and numbers", "resource.a IN 'a', 1", "mixed-type list"},
		{"booleans with a space after the comma", "resource.x IN FALSE, true", "trailing text: true"},
		{"lower-case booleans with a space after the comma", "resource.x IN true, false", "trailing text: false"},
		{"a quoted MATCH pattern", "resource.a MATCH 'x'", "quoted MATCH pattern"},
		{"spaces only", "   ", "blank"},
		{"a tab between tokens", "resource.a ==\t'y'", "tab or line break between tokens"},
		{"a misspelled word operator", "resource.a LESS THAN OR EQUALS 5", "misspelled word operator"},
		{"a lower-case operator", "resource.a is null", "lower-case keyword"},
		{"a connective with nothing after it", "resource.a == 'x' OR", "operand: "},
		{"a bare subject", "subject == 1", "bare subject"},
		{"a full-width digit", "resource.x == ５", "operand: ５"},
		{"an Arabic-Indic digit in a list", "resource.x IN 3, ٤", "list element"},
		{"an Arabic-Indic digit as a bracket index", "resource.a[٣] == 1", "operator at: [٣] == 1"},
		{"a non-ASCII letter in a filter of a path", "resource.a[?(@.k == 'é')] == 1", "operator at: [?(@.k == 'é')] == 1"},
		{"a vertical tab inside a MATCH pattern", "resource.p MATCH ab\vc", "trailing text: \vc"},
		{"a unit separator inside a MATCH pattern", "resource.p MATCH ab\x1fc", "trailing text: \x1fc"},
		{"false spelled with a long s", "falſe", "operator at: ſe"},
		{"true after a no-break space", "\u00a0true", "operand: \u00a0true"},
		{"a number as a MATCH pattern", "resource.a MATCH 5", "number as a MATCH pattern"},
		{"a placeholder in a MATCH pattern", "resource.a MATCH /api/{id}", "placeholder in MATCH pattern"},
		{"a subject attribute as a MATCH pattern", "resource.p NOT MATCH subject.name", "MATCH pattern: subject.name is neither a pattern nor an attribute"},
		{"a permission scope as a MATCH pattern", "resource.v MATCH subject.permissionScope.a[0]", "MATCH pattern: subject.permissionScope.a[0] is neither a pattern nor an attribute"},
		{"a boolean as a MATCH pattern", "resource.v MATCH true", "MATCH pattern: true is neither a pattern nor an attribute"},
		{"a PIP name as a MATCH pattern", "resource.v MATCH subject.region.code",
			"MATCH pattern: subject.region.code is neither a pattern nor an attribute"},
		{"a keyword as a MATCH pattern", "resource.v MATCH NULL", "MATCH pattern: NULL is neither a pattern nor an attribute"},
		{"resourceType as a MATCH pattern", "resource.v MATCH resourceType",
			"MATCH pattern: resourceType is neither a pattern nor an attribute"},
		{"entitledResources as a MATCH pattern", "resource.v MATCH subject.entitledResources.of('x').as('a', 'b')",
			"MATCH pattern: subject.entitledResources.of('x').as('a', 'b') is neither a pattern nor an attribute"},
		{"a word operator without TO", "resource.a LESS THAN OR EQUAL 5", "misspelled word operator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("ParseCondition(%q) = %v, %v, want a *SyntaxError", tc.text, c, err)
			}
			if se.Reason != tc.reason {
				t.Errorf("ParseCondition(%q) reason = %q, want %q", tc.text, se.Reason, tc.reason)
			}
		})
	}
}

// Inside an iterate, subject.permissionScope.<key> reads the pass; outside it
// reads the subject attribute.
func TestParseConditionReadsThePassInsideAnIterate(t *testing.T) {
	t.Parallel()

	c, err := ParseCondition("subject.permissionScope.region CONTAINS resource.region", PlaceRuleCondition, "iterate1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FormatCondition(c), `pass("iterate1")["region"] CONTAINS resource.region`; got != want {
		t.Errorf("FormatCondition = %s, want %s", got, want)
	}
}

// subject.permissionScope without a key, and a name that only starts with
// permissionScope, are PIP names inside an iterate too. The bare name used to
// read the whole pass.
func TestParseConditionReadsAPIPNamedLikeThePassInsideAnIterate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"subject.permissionScopes CONTAINS resource.region", `pip("subject.permissionScopes") CONTAINS resource.region`},
		{"subject.permissionScope IS NULL", `pip("subject.permissionScope") IS_NULL`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "iterate1")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}

func TestParseConditionMarksAPathOutsideTheJSONPathSubset(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text string
		want string
	}{
		{"resource.a[*] == 1", `resource.a[*] EQ 1`},
		{"resource.x/y == 1", `unsupported(jsonpath "resource.x/y") EQ 1`},
		{"resource.x/y[ 0 ]. == 1", `unsupported(jsonpath "resource.x/y[ 0 ].") EQ 1`},
		{"resource.a['b','c'] == 1", `unsupported(jsonpath "resource.a['b','c']") EQ 1`},
		{"resource.a[?(@.k ~ 'v')] == 1", `unsupported(jsonpath "resource.a[?(@.k ~ 'v')]") EQ 1`},
		{"resource.o[?(@.n=~/(?=u)/)].n == 1", `unsupported(jsonpath "resource.o[?(@.n=~/(?=u)/)].n") EQ 1`},
		{"resource.a[0:2:1] == 1", `unsupported(jsonpath "resource.a[0:2:1]") EQ 1`},
		{"subject.l[0:2:1] == 1", `unsupported(jsonpath "subject.l[0:2:1]") EQ 1`},
		{"foo[0:2:1] == 1", `unsupported(jsonpath "foo[0:2:1]") EQ 1`},
		{"resource['k'] == 1", `resource['k'] EQ 1`},
		{"resource.a[:] == 1", `resource.a[:] EQ 1`},
		{"resource.a[2147483648] == 1", `resource.a[2147483648] EQ 1`},
		{"resource.o[?(@.n=~/u.*/i && @.g==null)].n == 1", `resource.o[?(@.n=~/u.*/i && @.g==null)].n EQ 1`},
		{"resource.o[?(@.n=~/u.*/i && @.g == 'x')].n == 1", `resource.o[?(@.n=~/u.*/i && @.g == 'x')].n EQ 1`},
		{"resource.a[1:2] == 1", `resource.a[1:2] EQ 1`},
		{"resource..id == 1", `resource..id EQ 1`},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCondition(tc.text, PlaceRuleCondition, "")
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.text, err)
			}
			if got := FormatCondition(c); got != tc.want {
				t.Errorf("ParseCondition(%q) = %s, want %s", tc.text, got, tc.want)
			}
		})
	}
}
