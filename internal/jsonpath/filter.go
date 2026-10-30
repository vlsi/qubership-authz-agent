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

package jsonpath

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"authz-agent/internal/jsonvalue"
)

// predicate tests one element for a filter.
type predicate func(e jsonvalue.Value) bool

var (
	listOpRE  = regexp.MustCompile(`^@(?:\.([` + word + `-]+))?` + space + `+(in|nin|subsetof|anyof|noneof)` + space + `+\[((?:` + space + `*'[^']*'` + space + `*,?)*)\]$`)
	quotedRE  = regexp.MustCompile(`'([^']*)'`)
	sizeRE    = regexp.MustCompile(`^@\.([` + word + `-]+)` + space + `+(?:size` + space + `+(\p{Nd}+)|empty` + space + `+(true|false))$`)
	regexOpRE = regexp.MustCompile(`^@(?:\.([` + word + `-]+))?` + space + `*=~` + space + `*/(.*)/(i?)$`)
	compareRE = regexp.MustCompile(`^@(?:\.([` + word + `-]+))?` + space + `*(==|!=|<=|>=|<|>)` + space + `*('([^']*)'|-?\p{Nd}+(?:\.\p{Nd}+)?|true|false|null)$`)
	nestedRE  = regexp.MustCompile(`^@\.([` + word + `-]+)\[\?\((.*)\)\]$`)
	existsRE  = regexp.MustCompile(`^@\.([` + word + `-]+)$`)
)

// missing is the member of an element that has none.
type missing struct{}

// member returns the member key of e, or e itself for an empty key, and
// missing where e is not an object or has no such member.
func member(e jsonvalue.Value, key string) jsonvalue.Value {
	if key == "" {
		return e
	}
	if obj, ok := e.(*jsonvalue.Object); ok {
		if v, ok := obj.Get(key); ok {
			return v
		}
	}
	return missing{}
}

// parseFilter compiles the text between [?( and )]. It splits on || and then
// on && wherever they stand, inside a quoted string too.
//
// parseFilter adds to reads the key of each member of the element that the
// filter reads, and "" where it reads the element itself, once for each
// operand that reads it; a nested filter reads only within that member.
func parseFilter(expr string, reads *[]string) (predicate, error) {
	expr = strings.TrimFunc(expr, isSpace)
	for _, sep := range []string{"||", "&&"} {
		parts := strings.Split(expr, sep)
		if len(parts) == 1 {
			continue
		}
		preds := make([]predicate, len(parts))
		var first error
		for i, part := range parts {
			p, err := parseFilter(part, reads)
			switch {
			case errors.Is(err, errJaywayRefuses):
				return nil, err
			case errors.Is(err, errGoRegex):
				// Jayway compiles the pattern, so a later part it does not
				// compile still decides
				if first == nil {
					first = err
				}
			case err != nil:
				return nil, err
			}
			preds[i] = p
		}
		if first != nil {
			return nil, first
		}
		if sep == "||" {
			return func(e jsonvalue.Value) bool {
				return slices.ContainsFunc(preds, func(p predicate) bool { return p(e) })
			}, nil
		}
		return func(e jsonvalue.Value) bool {
			return !slices.ContainsFunc(preds, func(p predicate) bool { return !p(e) })
		}, nil
	}
	addRead := func(key string) {
		*reads = append(*reads, key)
	}
	if m := listOpRE.FindStringSubmatch(expr); m != nil {
		addRead(m[1])
		return listFilter(m[1], m[2], quotedRE.FindAllStringSubmatch(m[3], -1))
	}
	if m := sizeRE.FindStringSubmatch(expr); m != nil {
		addRead(m[1])
		return sizeFilter(m[1], m[2], m[3])
	}
	if m := regexOpRE.FindStringSubmatch(expr); m != nil {
		addRead(m[1])
		return regexFilter(m[1], m[2], m[3] == "i")
	}
	if m := compareRE.FindStringSubmatch(expr); m != nil {
		addRead(m[1])
		return compareFilter(m[1], m[2], m[3], m[4])
	}
	if m := nestedRE.FindStringSubmatch(expr); m != nil {
		addRead(m[1])
		var innerReads []string
		inner, err := parseFilter(m[2], &innerReads)
		if err != nil {
			return nil, err
		}
		return nestedFilter(m[1], inner), nil
	}
	if m := existsRE.FindStringSubmatch(expr); m != nil {
		key := m[1]
		addRead(key)
		return func(e jsonvalue.Value) bool {
			_, absent := member(e, key).(missing)
			return !absent
		}, nil
	}
	return nil, fmt.Errorf("filter %q", expr)
}

// nestedFilter compiles @.key[?(inner)]: the element is selected where the
// path @.key[?(inner)] selects something, that is, where its member is a list
// with an element inner holds for, or an object inner holds for, as a filter
// over one object tests the object. Jayway 2.9.0 only tests that the path
// exists, so it selects an element whose member is any list or object.
func nestedFilter(key string, inner predicate) predicate {
	return func(e jsonvalue.Value) bool {
		switch v := member(e, key).(type) {
		case []jsonvalue.Value:
			return slices.ContainsFunc(v, inner)
		case *jsonvalue.Object:
			return inner(v)
		}
		return false
	}
}

// literal is the right side of a comparison or an item of a list.
type literal struct {
	kind byte // 's' string, 'n' number, 'b' boolean, 'z' null
	text string
	// A string literal keeps the decimal it reads as, if any, and its UTF-16
	// chars; a number literal keeps its value and its text as BigDecimal
	// prints it, which a string in the document is compared with.
	num     jsonvalue.Decimal
	isNum   bool
	units   []uint16
	numText string
	b       bool
}

// stringLiteral returns the literal of a string that a filter compares with.
func stringLiteral(s string) literal {
	l := literal{kind: 's', text: s, units: utf16.Encode([]rune(s))}
	l.num, l.isNum = jsonvalue.ParseDecimal(s)
	return l
}

// listItem returns the literal of an item of an in, nin, subsetof, anyof, or
// noneof list, unescaped as the literal of == is. Jayway 2.9.0 unescapes an
// item twice and may read it as a path or as JSON; the package reads it as
// the string it is written as.
func listItem(s string) (literal, error) {
	text, err := quotedText(s)
	if err != nil {
		return literal{}, err
	}
	return stringLiteral(text), nil
}

// equal reports whether a document value equals l as Jayway's value nodes do.
// A string equals a string with the same text, and a number literal whose
// BigDecimal text is the string, so "5.0" equals 5.0 and not 5. A number
// equals a number literal of the same value, and a string literal that reads
// as that value, so 5 equals '5.0'. A boolean equals the same boolean, and
// null equals null. A missing member, a list, and an object equal nothing.
func equal(v jsonvalue.Value, l literal) bool {
	switch x := v.(type) {
	case string:
		switch l.kind {
		case 's':
			return x == l.text
		case 'n':
			return x == l.numText
		}
	case jsonvalue.Number:
		d, ok := jsonvalue.ParseDecimal(string(x))
		switch l.kind {
		case 'n':
			return ok && d.Compare(l.num) == 0
		case 's':
			return ok && l.isNum && d.Compare(l.num) == 0
		}
	case bool:
		return l.kind == 'b' && x == l.b
	case nil:
		return l.kind == 'z'
	}
	return false
}

// compareFilter compiles @.key op literal, with a literal in quotes, a
// number, true, false, or null. A literal in quotes is unescaped. == and !=
// compare as [equal] does; != also selects an element without the member.
// <, <=, >, and >= order two numbers by value and two strings as Java's
// String.compareTo does, and are false for any other pair.
func compareFilter(key, op, lit, quoted string) (predicate, error) {
	var l literal
	switch {
	case strings.HasPrefix(lit, "'"):
		text, err := quotedText(quoted)
		if err != nil {
			return nil, err
		}
		l = stringLiteral(text)
	case lit == "true" || lit == "false":
		l = literal{kind: 'b', b: lit == "true"}
	case lit == "null":
		l = literal{kind: 'z'}
	default:
		var ok bool
		l = literal{kind: 'n', text: lit}
		if strings.ContainsFunc(lit, func(r rune) bool { return r > 0xFFFF && unicode.IsDigit(r) }) {
			// Jayway reads one UTF-16 char at a time, and half a digit
			// fails the path's compilation
			return nil, fmt.Errorf("number %q has a digit outside the Basic Multilingual Plane: %w", lit,
				errJaywayRefuses)
		}
		if l.num, ok = jsonvalue.ParseDecimal(lit); !ok {
			return nil, fmt.Errorf("number %q", lit)
		}
		l.numText, _ = jsonvalue.BigDecimalText(lit)
	}
	return func(e jsonvalue.Value) bool {
		v := member(e, key)
		switch op {
		case "==":
			return equal(v, l)
		case "!=":
			return !equal(v, l)
		}
		switch x := v.(type) {
		case jsonvalue.Number:
			d, ok := jsonvalue.ParseDecimal(string(x))
			return l.kind == 'n' && ok && order(op, d.Compare(l.num))
		case string:
			return l.kind == 's' && order(op, javaCompare(x, l.units))
		}
		return false
	}, nil
}

// javaCompare compares a string with UTF-16 chars as Java's String.compareTo
// does, by UTF-16 code units, so a character outside the Basic Multilingual
// Plane orders before U+E000 to U+FFFF.
func javaCompare(a string, b []uint16) int {
	i := 0
	for _, r := range a {
		r1, r2 := utf16.EncodeRune(r)
		units := [2]rune{r, 0}
		n := 1
		if r1 != unicode.ReplacementChar {
			units, n = [2]rune{r1, r2}, 2
		}
		for _, u := range units[:n] {
			if i == len(b) {
				return 1
			}
			if c := cmp.Compare(uint16(u), b[i]); c != 0 {
				return c
			}
			i++
		}
	}
	if i < len(b) {
		return -1
	}
	return 0
}

// order reports whether a comparison result c satisfies op.
func order(op string, c int) bool {
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	}
	return c >= 0
}

// listFilter compiles in, nin, subsetof, anyof, and noneof against a list of
// strings in quotes, each read by [listItem]. A value is in the list where it
// equals an item as [equal] has it, so the number 5.0 is in ['5']. subsetof,
// anyof, and noneof test the elements of a list member and are false for any
// other member. A list or an object among the elements equals no item; Jayway
// 2.9.0 throws there, and reads a string element that looks like a path or
// JSON as such, which the package does not repeat.
func listFilter(key, op string, quoted [][]string) (predicate, error) {
	items := make([]literal, len(quoted))
	for i, q := range quoted {
		var err error
		if items[i], err = listItem(q[1]); err != nil {
			return nil, err
		}
	}
	listed := func(v jsonvalue.Value) bool {
		return slices.ContainsFunc(items, func(l literal) bool { return equal(v, l) })
	}
	return func(e jsonvalue.Value) bool {
		v := member(e, key)
		switch op {
		case "in":
			return listed(v)
		case "nin":
			return !listed(v)
		}
		list, ok := v.([]jsonvalue.Value)
		if !ok {
			return false
		}
		switch op {
		case "subsetof":
			return !slices.ContainsFunc(list, func(x jsonvalue.Value) bool { return !listed(x) })
		case "anyof":
			return slices.ContainsFunc(list, listed)
		}
		return !slices.ContainsFunc(list, listed) // noneof
	}, nil
}

// sizeFilter compiles size and empty. The size of a string is its length in
// UTF-16 code units, as Java counts it, and the size of a list is its number
// of elements; size tests no other value. A size beyond the int range is
// compared as it is written, so no value has it. An object is empty where it
// has no member; Jayway 2.9.0 throws for empty over an object instead.
func sizeFilter(key, size, empty string) (predicate, error) {
	n := -1
	if size != "" {
		var err error
		if n, err = parseInt(size); errors.Is(err, errBeyondInt) {
			// no length reaches it; -1 stands for empty, so take -2
			n, err = -2, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return func(e jsonvalue.Value) bool {
		var l int
		switch v := member(e, key).(type) {
		case string:
			for _, r := range v {
				l += utf16.RuneLen(r)
			}
		case []jsonvalue.Value:
			l = len(v)
		case *jsonvalue.Object:
			if size != "" {
				return false
			}
			l = v.Len()
		default:
			return false
		}
		if size != "" {
			return l == n
		}
		return (l == 0) == (empty == "true")
	}, nil
}

// regexFilter compiles =~. The pattern has to match the whole text of the
// member: a string itself, a number as BigDecimal prints it, or true or
// false. A list matches where one of its elements does. Anything else has no
// text and does not match; Jayway 2.9.0 matches null, an object, and a missing
// member as empty text instead.
func regexFilter(key, pattern string, fold bool) (predicate, error) {
	translated, err := javaPattern(pattern, fold)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGoRegex, err)
	}
	// The pattern compiles alone first, so that an unbalanced parenthesis
	// cannot break out of the anchors around it.
	if _, err := regexp.Compile(translated); err != nil {
		return nil, fmt.Errorf("%w: %w", errGoRegex, err)
	}
	re, err := regexp.Compile(`\A(?:` + translated + `)\z`)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGoRegex, err)
	}
	matches := func(v jsonvalue.Value) bool {
		text, ok := regexInput(v)
		return ok && re.MatchString(text)
	}
	return func(e jsonvalue.Value) bool {
		v := member(e, key)
		if list, ok := v.([]jsonvalue.Value); ok {
			return slices.ContainsFunc(list, matches)
		}
		return matches(v)
	}, nil
}

// regexInput returns the text =~ matches a value by, and false for a value
// with no text.
func regexInput(v jsonvalue.Value) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case jsonvalue.Number:
		if s, ok := jsonvalue.BigDecimalText(string(x)); ok {
			return s, true
		}
		return string(x), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

// Classes that Java and Go spell alike but fill differently: Java's \s also
// holds \x0B, \v is vertical whitespace, and . stops at every line
// terminator, not only \n.
const (
	javaSpace    = `\t\n\x0B\f\r `
	javaVertical = `\n\x0B\f\r\x{85}\x{2028}\x{2029}`
	javaDot      = `[^\n\r\x{85}\x{2028}\x{2029}]`
)

// javaPattern rewrites a java.util.regex pattern, compiled with
// CASE_INSENSITIVE where fold is set, into Go's syntax with the same matches.
// It refuses what Go cannot match the same way or what Java refuses: an
// escape of a letter or a digit other than \d, \D, \w, \W, \s, \S, \t, \n,
// \r, \f, \a, \v, \x, \A, \z, and \Z, which covers backreferences, \b, \B,
// \p, and \Q; \S inside brackets; a group that opens with (? other than (?:
// and (?<name>, which covers lookaround and inline flags; a group name used
// twice; a nested or intersected character class, and ] first in brackets;
// $ or \Z with something after them; { outside a repetition; and an
// unescaped /. A pattern Go itself does not compile, such as one with a
// possessive repetition, is refused by the caller. With fold, an ASCII letter matches
// both of its cases and nothing else, as Java folds ASCII only; \x is then
// refused.
func javaPattern(pattern string, fold bool) (string, error) {
	rs := []rune(pattern)
	var b strings.Builder
	names := map[string]bool{}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\':
			if i+1 == len(rs) {
				return "", fmt.Errorf("trailing backslash in %q", pattern)
			}
			if rs[i+1] == 'Z' {
				if !onlyCloseParens(rs[i+2:]) {
					return "", fmt.Errorf(`\Z before the end of %q`, pattern)
				}
				b.WriteString(`\z`)
				i++
				continue
			}
			s, _, _, n, err := escape(rs[i+1:], false, false, fold)
			if err != nil {
				return "", fmt.Errorf("%w in %q", err, pattern)
			}
			b.WriteString(s)
			i += n
		case r == '[':
			end, s, err := charClass(rs, i, fold)
			if err != nil {
				return "", fmt.Errorf("%w in %q", err, pattern)
			}
			b.WriteString(s)
			i = end
		case r == '.':
			b.WriteString(javaDot)
		case r == '$':
			if !onlyCloseParens(rs[i+1:]) {
				return "", fmt.Errorf("$ before the end of %q", pattern)
			}
			b.WriteString(`\z`)
		case r == '{':
			end := quantifierEnd(rs, i)
			if end < 0 {
				return "", fmt.Errorf("{ outside a repetition in %q", pattern)
			}
			b.WriteString(string(rs[i : end+1]))
			i = end
		case r == '(' && i+1 < len(rs) && rs[i+1] == '?':
			end, err := groupStart(rs, i)
			if err != nil {
				return "", fmt.Errorf("%w in %q", err, pattern)
			}
			if rs[i+2] == '<' {
				name := string(rs[i+3 : end])
				if names[name] {
					return "", fmt.Errorf("group name %s twice in %q", name, pattern)
				}
				names[name] = true
			}
			b.WriteString(string(rs[i : end+1]))
			i = end
		case r == '/':
			return "", fmt.Errorf("unescaped / in %q", pattern)
		case fold && isASCIILetter(r):
			b.WriteString("[" + string(r) + string(swapCase(r)) + "]")
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// onlyCloseParens reports whether rs holds nothing but closing parentheses,
// so an end anchor before them stands at the end of every match.
func onlyCloseParens(rs []rune) bool {
	return !slices.ContainsFunc(rs, func(r rune) bool { return r != ')' })
}

// quantifierEnd returns the index of the } that closes a repetition {n},
// {n,}, or {n,m} starting at rs[i], or -1.
func quantifierEnd(rs []rune, i int) int {
	j := i + 1
	start := j
	for j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
		j++
	}
	if j == start {
		return -1
	}
	if j < len(rs) && rs[j] == ',' {
		j++
		for j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
			j++
		}
	}
	if j < len(rs) && rs[j] == '}' {
		return j
	}
	return -1
}

// groupStart returns the index of the last rune of a group opening (?: or
// (?<name> at rs[i]. Any other (? is refused.
func groupStart(rs []rune, i int) (int, error) {
	if i+2 < len(rs) && rs[i+2] == ':' {
		return i + 2, nil
	}
	if i+3 < len(rs) && rs[i+2] == '<' && isASCIILetter(rs[i+3]) {
		for j := i + 3; j < len(rs); j++ {
			switch {
			case rs[j] == '>' && j > i+3:
				return j, nil
			case rs[j] > unicode.MaxASCII || !unicode.IsLetter(rs[j]) && !unicode.IsDigit(rs[j]):
				return 0, fmt.Errorf("group name")
			}
		}
	}
	return 0, fmt.Errorf("group %q", string(rs[i:min(len(rs), i+3)]))
}

// escape translates the escape whose letter starts rs, inside a character
// class where inClass is set, and as the end of a range there where bound is
// set. It returns the Go text, the character the escape stands for where it
// stands for one, whether it does, and the number of runes it read.
func escape(rs []rune, inClass, bound, fold bool) (string, rune, bool, int, error) {
	e := rs[0]
	switch {
	case e > unicode.MaxASCII:
		return "", 0, false, 0, fmt.Errorf("escape \\%c", e)
	case !unicode.IsLetter(e) && !unicode.IsDigit(e):
		return `\` + string(e), e, true, 1, nil
	}
	switch e {
	case 'd', 'D', 'w', 'W':
		return `\` + string(e), 0, false, 1, nil
	case 's':
		if inClass {
			return javaSpace, 0, false, 1, nil
		}
		return "[" + javaSpace + "]", 0, false, 1, nil
	case 'S':
		if inClass {
			return "", 0, false, 0, fmt.Errorf(`\S inside brackets`)
		}
		return "[^" + javaSpace + "]", 0, false, 1, nil
	case 'v':
		if bound || inClass && len(rs) > 1 && rs[1] == '-' {
			// Java reads \v at either end of a range as the one char
			// U+000B.
			return `\x{b}`, '\v', true, 1, nil
		}
		if inClass {
			return javaVertical, 0, false, 1, nil
		}
		return "[" + javaVertical + "]", 0, false, 1, nil
	case 't', 'n', 'r', 'f', 'a':
		c := map[rune]rune{'t': '\t', 'n': '\n', 'r': '\r', 'f': '\f', 'a': '\a'}[e]
		return `\` + string(e), c, true, 1, nil
	case 'x':
		if fold {
			return "", 0, false, 0, fmt.Errorf(`\x with the flag i`)
		}
		return hexEscape(rs)
	case 'A', 'z':
		if !inClass {
			return `\` + string(e), 0, false, 1, nil
		}
	}
	return "", 0, false, 0, fmt.Errorf("escape \\%c", e)
}

// hexEscape reads \xhh or \x{h...} from rs, which starts at the x.
func hexEscape(rs []rune) (string, rune, bool, int, error) {
	var digits string
	n := 1
	switch {
	case len(rs) > 1 && rs[1] == '{':
		end := slices.Index(rs, '}')
		if end < 0 {
			return "", 0, false, 0, fmt.Errorf(`\x{ without }`)
		}
		digits, n = string(rs[2:end]), end+1
	case len(rs) > 2:
		digits, n = string(rs[1:3]), 3
	}
	c, err := strconv.ParseUint(digits, 16, 32)
	if err != nil || digits == "" || c > unicode.MaxRune {
		return "", 0, false, 0, fmt.Errorf(`\x escape`)
	}
	return fmt.Sprintf(`\x{%x}`, c), rune(c), true, n, nil
}

// charClass translates the character class that opens at rs[i] and returns
// the index of its closing ].
func charClass(rs []rune, i int, fold bool) (int, string, error) {
	var b strings.Builder
	b.WriteByte('[')
	j := i + 1
	if j < len(rs) && rs[j] == '^' {
		b.WriteByte('^')
		j++
	}
	if j < len(rs) && rs[j] == ']' {
		return 0, "", fmt.Errorf("] first in brackets")
	}
	for j < len(rs) && rs[j] != ']' {
		lo, loText, loChar, err := classAtom(rs, &j, false, fold)
		if err != nil {
			return 0, "", err
		}
		if !loChar || j+1 >= len(rs) || rs[j] != '-' || rs[j+1] == ']' {
			b.WriteString(loText)
			if fold && loChar && isASCIILetter(lo) {
				b.WriteRune(swapCase(lo))
			}
			continue
		}
		j++
		hi, hiText, hiChar, err := classAtom(rs, &j, true, fold)
		if err != nil {
			return 0, "", err
		}
		if !hiChar || hi < lo {
			return 0, "", fmt.Errorf("range %c-%c", lo, hi)
		}
		b.WriteString(loText + "-" + hiText)
		if fold {
			for _, span := range [][2]rune{{'a', 'z'}, {'A', 'Z'}} {
				from, to := max(lo, span[0]), min(hi, span[1])
				if from <= to {
					b.WriteRune(swapCase(from))
					b.WriteByte('-')
					b.WriteRune(swapCase(to))
				}
			}
		}
	}
	if j >= len(rs) {
		return 0, "", fmt.Errorf("[ without ]")
	}
	b.WriteByte(']')
	return j, b.String(), nil
}

// classAtom reads one item of a character class at rs[*j], the end of a range
// where bound is set, and advances *j past it. It returns the character the
// item stands for and its Go text, and whether the item is a single character
// rather than a class such as \d. An unescaped / is refused, as Jayway ends
// the pattern there, inside brackets too.
func classAtom(rs []rune, j *int, bound, fold bool) (rune, string, bool, error) {
	r := rs[*j]
	switch {
	case r == '[':
		return 0, "", false, fmt.Errorf("brackets inside brackets")
	case r == '&' && *j+1 < len(rs) && rs[*j+1] == '&':
		return 0, "", false, fmt.Errorf("&& inside brackets")
	case r == '/':
		return 0, "", false, fmt.Errorf("unescaped / inside brackets")
	case r == '\\':
		if *j+1 >= len(rs) {
			return 0, "", false, fmt.Errorf("trailing backslash")
		}
		s, c, isChar, n, err := escape(rs[*j+1:], true, bound, fold)
		*j += 1 + n
		return c, s, isChar, err
	}
	*j++
	if r <= unicode.MaxASCII && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
		return r, `\` + string(r), true, nil
	}
	return r, string(r), true, nil
}

func isASCIILetter(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

func swapCase(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 'a' + 'A'
	}
	return r - 'A' + 'a'
}
