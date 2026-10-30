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

package jsonvalue

import "testing"

func mustParseDecimal(t *testing.T, s string) Decimal {
	t.Helper()
	d, ok := ParseDecimal(s)
	if !ok {
		t.Fatalf("ParseDecimal(%q) refused a number", s)
	}
	return d
}

func TestDecimal_CompareIsExact(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"fractions equal as float64", "0.30000000000000001", "0.3", 1},
		{"17-digit integers", "12345678901234567", "12345678901234568", -1},
		{"integers past 2^53", "9007199254740993", "9007199254740992", 1},
		{"40-digit integers", "1234567890123456789012345678901234567890", "1234567890123456789012345678901234567891", -1},
		{"a 40-digit fraction", "0.1000000000000000000000000000000000000001", "0.1", 1},
		{"a negative long fraction", "-5", "-4.9999999999999999999", -1},
		{"minus zero equals zero", "-0.0", "0", 0},
		{"minus zero above a negative underflow", "-0.0", "-1e-400", 1},
		{"an underflow above zero", "1e-400", "0", 1},
		{"exponents past the double range", "1e400", "9e399", 1},
		{"an upper-case exponent with a sign", "1E+400", "1e400", 0},
		{"scale is not compared", "2.50", "2.5", 0},
		{"a plus sign", "+1", "1", 0},
		{"an Arabic-Indic digit", "٣", "3", 0},
		{"no integer digits", ".5", "0.5", 0},
		{"no fraction digits", "5.", "5", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := mustParseDecimal(t, tt.a), mustParseDecimal(t, tt.b)
			if got := a.Compare(b); got != tt.want {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if got := b.Compare(a); got != -tt.want {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.b, tt.a, got, -tt.want)
			}
		})
	}
}

func TestParseDecimal_RefusesWhatBigDecimalRefuses(t *testing.T) {
	for _, s := range []string{"", "+", "-", ".", "e5", "5e", "5e+", "1_0", " 5", "5 ", "NaN", "Infinity", "0x10", "1.2.3",
		"1e1152921504606846977", "1e10000000000000000000", "𝟙", "1e𝟙", "1e-10000000000000000000",
		"1e100000000000000000000000000000000000000"} {
		if d, ok := ParseDecimal(s); ok {
			t.Errorf("ParseDecimal(%q) = %v, want a refusal", s, d)
		}
	}
}

func TestParseDecimal_AcceptsTheLargestExponent(t *testing.T) {
	if got := mustParseDecimal(t, "1e1152921504606846976").String(); got != "1e1152921504606846976" {
		t.Errorf("ParseDecimal(1e1152921504606846976).String() = %q", got)
	}
}

// The scale, the digits after the point less the exponent, is taken at both
// ends of Java's int range and one past each.
func TestParseBigDecimal_RefusesAScaleOutsideTheIntRange(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1e-2147483647", true},
		{"1.1e-2147483646", true},
		{"1.1e-2147483647", false},
		{"1e2147483648", true},
		{"1e2147483649", false},
		{"10.0e2147483649", true},
		{"10.0e2147483650", false},
		{"0.0e-2147483648", false},
		{"1e1152921504606846976", false},
		{"12.50", true},
		{"1_0", false},
	}
	for _, tt := range tests {
		if _, ok := ParseBigDecimal(tt.in); ok != tt.want {
			t.Errorf("ParseBigDecimal(%q) accepted = %v, want %v", tt.in, ok, tt.want)
		}
		if _, ok := ParseDecimal(tt.in); tt.want && !ok {
			t.Errorf("ParseDecimal(%q) refused what ParseBigDecimal accepts", tt.in)
		}
	}
}

func TestDecimal_StringIsAJSONNumberWithoutTrailingZeros(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"0", "0"},
		{"-0.0", "0"},
		{"2.50", "2.5"},
		{"-1200", "-1200"},
		{"0.00015", "0.00015"},
		{"1e-7", "0.0000001"},
		{"1e-8", "1e-8"},
		{"1.5e-9", "1.5e-9"},
		{"1e19", "10000000000000000000"},
		{"1e20", "1e20"},
		{"-1.25e400", "-1.25e400"},
	}
	for _, tt := range tests {
		if got := mustParseDecimal(t, tt.in).String(); got != tt.want {
			t.Errorf("ParseDecimal(%q).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDecimal_ShortBoundaries(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"0", true},
		{"123456789012345", true},
		{"1234567890123456", false},
		{"1234567890123450000", true},
		{"1e307", true},
		{"1e308", false},
		{"1e-307", true},
		{"1e-308", false},
	}
	for _, tt := range tests {
		if got := mustParseDecimal(t, tt.in).Short(); got != tt.want {
			t.Errorf("ParseDecimal(%q).Short() = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDecimal_PartsAreTheSignTheDigitsAndTheFirstExponent(t *testing.T) {
	for _, tc := range []struct {
		in     string
		sign   int
		digits string
		adj    int64
	}{
		{"0.0125", 1, "125", -2},
		{"-1500", -1, "15", 3},
		{"7", 1, "7", 0},
		{"-0.0", 0, "", 0},
	} {
		sign, digits, adj := mustParseDecimal(t, tc.in).Parts()
		if sign != tc.sign || digits != tc.digits || adj != tc.adj {
			t.Errorf("ParseDecimal(%q).Parts() = %d, %q, %d, want %d, %q, %d", tc.in, sign, digits, adj, tc.sign,
				tc.digits, tc.adj)
		}
	}
}
