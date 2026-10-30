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

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Decimal is an exact decimal number, as Java's BigDecimal holds one for
// comparison: its value is coef × 10^exp. Scale is not kept, so 2.5 and 2.50
// are the same Decimal, and so are 0 and -0.0. The zero value is zero.
type Decimal struct {
	neg  bool
	coef string // decimal digits, no leading or trailing zero; empty for zero
	exp  int64
}

// maxExponent bounds the exponent ParseDecimal accepts, so that the adjusted
// exponent of any Decimal fits an int64 with room to spare.
const maxExponent = 1 << 60

// ParseDecimal reads s as Java's new BigDecimal(String) reads it: an optional
// sign, digits with an optional point, and an optional exponent, where a digit
// is a Unicode decimal digit in the Basic Multilingual Plane: Java tests each
// UTF-16 char, so a digit outside it is refused. Spaces, underscores, NaN, and
// Infinity are refused. An exponent up to ±2^60 is accepted, where BigDecimal
// accepts only a scale in the int range; [ParseBigDecimal] refuses the rest as
// BigDecimal does.
func ParseDecimal(s string) (Decimal, bool) {
	d, _, ok := parseDecimal(s)
	return d, ok
}

// ParseBigDecimal reads s as [ParseDecimal] does, and refuses a number whose
// scale, the count of digits after the point less the exponent, is outside the
// int range, such as 1.1e-2147483647 or 1e2147483649: Java's
// new BigDecimal(String) throws NumberFormatException for it.
func ParseBigDecimal(s string) (Decimal, bool) {
	d, scale, ok := parseDecimal(s)
	return d, ok && scale >= math.MinInt32 && scale <= math.MaxInt32
}

// parseDecimal returns the number s holds and its scale as BigDecimal counts
// it.
func parseDecimal(s string) (Decimal, int64, bool) {
	// A number starts with a sign, a digit, or a point. Refusing any other
	// ASCII start here spares a string that is not a number the copy below.
	if s == "" {
		return Decimal{}, 0, false
	}
	if c := s[0]; c < utf8.RuneSelf && c != '+' && c != '-' && c != '.' && (c < '0' || c > '9') {
		return Decimal{}, 0, false
	}
	var d Decimal
	rs := []rune(s)
	i := 0
	if i < len(rs) && (rs[i] == '+' || rs[i] == '-') {
		d.neg = rs[i] == '-'
		i++
	}
	var digits []byte
	intDigits, fracDigits := 0, 0
	for i < len(rs) && isDigit(rs[i]) {
		digits = append(digits, digitValue(rs[i]))
		intDigits++
		i++
	}
	if i < len(rs) && rs[i] == '.' {
		i++
		for i < len(rs) && isDigit(rs[i]) {
			digits = append(digits, digitValue(rs[i]))
			fracDigits++
			i++
		}
	}
	if intDigits+fracDigits == 0 {
		return Decimal{}, 0, false
	}
	var exp int64
	if i < len(rs) && (rs[i] == 'e' || rs[i] == 'E') {
		i++
		expNeg := false
		if i < len(rs) && (rs[i] == '+' || rs[i] == '-') {
			expNeg = rs[i] == '-'
			i++
		}
		start := i
		for i < len(rs) && isDigit(rs[i]) {
			d := int64(digitValue(rs[i]) - '0')
			if exp > (maxExponent-d)/10 {
				return Decimal{}, 0, false
			}
			exp = exp*10 + d
			i++
		}
		if i == start {
			return Decimal{}, 0, false
		}
		if expNeg {
			exp = -exp
		}
	}
	if i != len(rs) {
		return Decimal{}, 0, false
	}
	return newDecimal(d.neg, string(digits), exp-int64(fracDigits)), int64(fracDigits) - exp, true
}

// newDecimal normalizes coef × 10^exp: it strips leading zeros, moves trailing
// zeros into the exponent, and drops the sign of zero.
func newDecimal(neg bool, coef string, exp int64) Decimal {
	coef = strings.TrimLeft(coef, "0")
	if coef == "" {
		return Decimal{}
	}
	trimmed := strings.TrimRight(coef, "0")
	return Decimal{neg: neg, coef: trimmed, exp: exp + int64(len(coef)-len(trimmed))}
}

// isDigit reports whether r is a digit Java's Character.isDigit accepts in one
// UTF-16 char.
func isDigit(r rune) bool {
	return r <= 0xFFFF && unicode.IsDigit(r)
}

// digitValue returns the ASCII digit of r, which must be a Unicode decimal
// digit. Unicode encodes each set of decimal digits as a run of ten code
// points from zero to nine, and adjacent sets continue the count.
func digitValue(r rune) byte {
	if r >= '0' && r <= '9' {
		return byte(r)
	}
	n := 0
	for unicode.IsDigit(r - rune(n) - 1) {
		n++
	}
	return byte('0' + n%10)
}

// IsZero reports whether d is zero.
func (d Decimal) IsZero() bool {
	return d.coef == ""
}

// adjusted returns the exponent of the first significant digit.
func (d Decimal) adjusted() int64 {
	return d.exp + int64(len(d.coef)) - 1
}

// Compare returns -1, 0, or 1 as d is less than, equal to, or greater than e,
// exactly, at any number of digits and any exponent.
func (d Decimal) Compare(e Decimal) int {
	ds, es := d.sign(), e.sign()
	if ds != es {
		if ds < es {
			return -1
		}
		return 1
	}
	if ds == 0 {
		return 0
	}
	c := compareMagnitude(d, e)
	if d.neg {
		return -c
	}
	return c
}

// Parts returns the sign of d (-1, 0, or 1), its significant digits without
// leading or trailing zeros, and the exponent of ten of the first of them, so
// that 0.0125 is 1, "125", -2. Zero has empty digits and exponent 0.
func (d Decimal) Parts() (sign int, digits string, adjusted int64) {
	if d.IsZero() {
		return 0, "", 0
	}
	return d.sign(), d.coef, d.adjusted()
}

func (d Decimal) sign() int {
	switch {
	case d.IsZero():
		return 0
	case d.neg:
		return -1
	}
	return 1
}

func compareMagnitude(d, e Decimal) int {
	if a, b := d.adjusted(), e.adjusted(); a != b {
		if a < b {
			return -1
		}
		return 1
	}
	// Equal adjusted exponents align the first digits, and neither coefficient
	// ends in zero, so the longer of two coefficients that share a prefix is
	// the larger number.
	return strings.Compare(d.coef, e.coef)
}

// Short reports whether d has at most 15 significant digits and the exponent
// of its first digit is from -307 to 307. OPA's own comparison orders two
// such numbers correctly: it compares them exactly, and where it compares two
// fractions that end in zeros as float64 values instead, a float64 holds each
// closely enough to keep their order. OPA reads a number with a far larger exponent as 0, or
// spends milliseconds reading it.
func (d Decimal) Short() bool {
	if d.IsZero() {
		return true
	}
	adj := d.adjusted()
	return len(d.coef) <= 15 && adj >= -307 && adj <= 307
}

// String returns d as a JSON number: plain digits while the exponent of the
// first significant digit is from -7 to 19, otherwise one digit before the
// point and an exponent, such as 1.5e400. The text has no trailing zeros, and
// zero is 0.
func (d Decimal) String() string {
	if d.IsZero() {
		return "0"
	}
	var b strings.Builder
	if d.neg {
		b.WriteByte('-')
	}
	adj := d.adjusted()
	switch {
	case adj >= 20 || adj < -7:
		b.WriteString(d.coef[:1])
		if len(d.coef) > 1 {
			b.WriteByte('.')
			b.WriteString(d.coef[1:])
		}
		b.WriteByte('e')
		b.WriteString(strconv.FormatInt(adj, 10))
	case d.exp >= 0:
		b.WriteString(d.coef)
		b.WriteString(strings.Repeat("0", int(d.exp)))
	case adj >= 0:
		b.WriteString(d.coef[:adj+1])
		b.WriteByte('.')
		b.WriteString(d.coef[adj+1:])
	default:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", int(-adj-1)))
		b.WriteString(d.coef)
	}
	return b.String()
}
