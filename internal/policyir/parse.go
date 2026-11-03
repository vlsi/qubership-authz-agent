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
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"authz-agent/internal/jsonpath"
)

// SyntaxError reports condition text that [ParseCondition] refuses. The PAP
// refuses such text on store too.
type SyntaxError struct {
	Text   string
	Reason string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("condition %q: %s", e.Text, e.Reason)
}

// ParseCondition parses the text of a target or a condition at place. Empty
// text, and the whole text "true" or "false" in any ASCII letter case, are
// constants, and so is such a text with characters up to U+0020 around it.
// The legacy PDP compares the text before trimming it, so this is a
// difference from legacy that only text stored by a PAP older than 6.1.6 can
// show. iterVar is the [Iterate.Var] of the innermost enclosing iterate, or
// empty: inside one, subject.permissionScope reads the pass as a [PassValue].
//
// ParseCondition accepts every text the PAP stores, and returns a *SyntaxError
// for text the specification's condition parser refuses. It also accepts some
// text the PAP refuses on store, such as TRUE AND resource.a == 1, so a
// successful parse does not mean the PAP would store the text.
//
// A resource path the agent cannot execute yet becomes an [Unsupported]
// operand, except on the right of MATCH and NOT MATCH, where the path is
// pattern text.
func ParseCondition(text string, place Place, iterVar string) (*Condition, error) {
	if b, ok := wholeBool(text); ok {
		return NewCondition(place, []Atom{Const{Value: b}})
	}
	p, err := newParser(text)
	if err != nil {
		return nil, err
	}
	p.iterVar = iterVar
	disjuncts, err := p.expr()
	if err != nil {
		return nil, err
	}
	c, err := NewCondition(place, disjuncts...)
	if err != nil {
		return nil, p.fail(err.Error())
	}
	return c, nil
}

// wholeBool reports the value of text when it is "true" or "false" in any ASCII
// letter case once the characters up to U+0020 around it are removed, as
// Java's String.trim removes them. A non-ASCII letter never matches, so
// "falſe" is not false.
func wholeBool(text string) (value, ok bool) {
	switch strings.Map(asciiLower, strings.TrimFunc(text, func(r rune) bool { return r <= ' ' })) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

func asciiLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}

type parser struct {
	text    string
	s       string
	i       int
	iterVar string
}

// The regular expressions of an operand path, as the specification's parser
// reads one: pathKey is a key after a dot, jpFilter a filter of up to two
// levels, and jpFunction a function step.
const (
	pathKey    = `[A-Za-z0-9_@][A-Za-z0-9_/:$~@!&|-]*`
	jpFilter   = `\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\]|\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\])*\)\])*\)\]`
	jpFunction = `\.(?:length|min|max|avg|sum|first|last|keys)\(\)`
)

var (
	quotedRE       = regexp.MustCompile(`'[^']*'`)
	listCommaRE    = regexp.MustCompile(`(''|[0-9]) *, *`)
	bracketsRE     = regexp.MustCompile(`\[[^\]]*\]`)
	bracketParenRE = regexp.MustCompile(`\[[^\]]*\]|\([^()]*\)`)
	tightCompareRE = regexp.MustCompile(`[^ !=<>](==|!=|<=|>=)|(==|!=|<=|>=)[^ ]`)
	connectiveRE   = regexp.MustCompile(`(OR|AND) `)
	lowerKeywordRE = regexp.MustCompile(`^(or|and)\b`)
	lowerOpRE      = regexp.MustCompile(`^(is|and|or|in|contains|match)\b`)
	misspelledOpRE = regexp.MustCompile(`^(LESS|GREATER) THAN OR EQUALS? ?`)
	stringLitRE    = regexp.MustCompile(`^'([^']*)'`)
	numberLitRE    = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?|-[1-9][0-9]*(?:\.[0-9]+)?|-0\.[0-9]*[1-9])`)
	numberStartRE  = regexp.MustCompile(`^-?[0-9.]`)
	entitledRE     = regexp.MustCompile(`^subject\.entitledResources\.of\('([^']*)'\)\.as\(('[^']*'(?: *, *'[^']*')*)\)`)
	entitledAsRE   = regexp.MustCompile(`'([^']*)'`)
	indexStepRE    = regexp.MustCompile(`^\[ *(-?[0-9]+) *\]`)
	accessRE       = regexp.MustCompile(`^subject (allowed|denied) '([^']*)' on resource`)
	constAtomRE    = regexp.MustCompile(`^(TRUE|FALSE|true|false)`)
	filteredRE     = regexp.MustCompile(`^ FILTERED '([^']*)'`)
	listMoreRE     = regexp.MustCompile(`^ *,`)
	boolAttrRE     = regexp.MustCompile(`^(?:TRUE|true|FALSE|false)[$@,:?*(=)~<>/&|!'-][A-Za-z0-9_$@,:?*(=)~<>/&|!'.-]*`)
	boolLitRE      = regexp.MustCompile(`^(?:TRUE|true|FALSE|false)`)

	// prefixedPathRE and plainPathRE match an operand path that starts with
	// resource or subject, and one that does not.
	prefixedPathRE = regexp.MustCompile(`^(?:resource|subject)(?:` + jpFunction + `|\.\.?` + pathKey + `|` + jpFilter +
		`|\[[^\]]*\]|\])+\.?`)
	plainPathRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_*-]*(?:\.\.?` + pathKey + `|\[[^\]]*\])*`)

	// matchTokenRE matches the right operand of MATCH and NOT MATCH, and
	// matchBracketsRE the same operand when it is a path with spaces inside
	// its brackets.
	matchTokenRE    = regexp.MustCompile(`^[^ \t\n\v\f\r]+`)
	matchBracketsRE = regexp.MustCompile(`^[^\[\] ]*(?:\[[^\]]*\][^\[\] ]*)+`)
	matchNumberRE   = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?$`)

	// scopeTokenRE and pipTokenRE match the start of a
	// subject.permissionScope.<key> token and the whole of a PIP token.
	scopeTokenRE = regexp.MustCompile(`^subject\.permissionScope\.[A-Za-z_]`)
	pipTokenRE   = regexp.MustCompile(`^subject(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)
)

// patternReserved holds the words the legacy lexer reads as a token of their
// own where a MATCH pattern may stand.
var patternReserved = map[string]bool{
	"OR": true, "AND": true, "IS": true, "NOT": true, "NULL": true, "IN": true, "CONTAINS": true, "SUBSET": true,
	"EMPTY": true, "MATCH": true, "EQUALS": true, "FILTERED": true, "on": true, "allowed": true, "denied": true,
	"resource": true, "subject": true, "resourceType": true, "operation": true,
	"true": true, "TRUE": true, "false": true, "FALSE": true,
}

var keywords = map[string]bool{
	"OR": true, "AND": true, "IS": true, "NOT": true, "NULL": true, "IN": true, "CONTAINS": true, "ANY": true,
	"SUBSET": true, "EMPTY": true, "MATCH": true, "TRUE": true, "FALSE": true, "GREATER": true, "LESS": true,
	"THAN": true, "EQUAL": true, "EQUALS": true, "on": true,
}

// opWords lists the operator spellings, longer phrases before their prefixes.
var opWords = []struct {
	word string
	op   Operator
}{
	{"GREATER THAN OR EQUAL TO", OpGE}, {"LESS THAN OR EQUAL TO", OpLE},
	{"GREATER THAN", OpGT}, {"LESS THAN", OpLT},
	{"IS NOT NULL", OpIsNotNull}, {"IS NULL", OpIsNull}, {"IS NOT EMPTY", OpIsNotEmpty}, {"IS EMPTY", OpIsEmpty},
	{"IS NOT SUBSET", OpIsNotSubset}, {"IS SUBSET", OpIsSubset},
	{"NOT CONTAINS ANY", OpNotContainsAny}, {"CONTAINS ANY", OpContainsAny},
	{"NOT CONTAINS", OpNotContains}, {"CONTAINS", OpContains},
	{"NOT IN", OpNotIn}, {"IN", OpIn}, {"NOT MATCH", OpNotMatch}, {"MATCH", OpMatch},
	{"NOT EQUALS", OpNE}, {"EQUALS", OpEQ}, {"==", OpEQ}, {"!=", OpNE}, {"<=", OpLE}, {">=", OpGE},
	{"<", OpLT}, {">", OpGT}, {"=", OpEQ},
}

func newParser(text string) (*parser, error) {
	fail := func(reason string) (*parser, error) { return nil, &SyntaxError{Text: text, Reason: reason} }
	if text != "" && strings.TrimSpace(text) == "" {
		return fail("blank")
	}
	s, ok := dropLineBreaks(text)
	if !ok {
		return fail("tab or line break between tokens")
	}
	s = strings.Trim(s, " ")
	masked := quotedRE.ReplaceAllString(s, "''")
	masked = joinListCommas(masked)
	outside := bracketsRE.ReplaceAllString(masked, "[]")
	for i := 0; i+1 < len(outside); i++ {
		if outside[i] == ' ' && outside[i+1] == ' ' && (i == 0 || outside[i-1] != ',') {
			return fail("double space")
		}
	}
	bare := bracketParenRE.ReplaceAllString(masked, "_")
	if tightCompareRE.MatchString(bare) {
		return fail("operator at: no space around a comparison")
	}
	for _, loc := range connectiveRE.FindAllStringIndex(bare, -1) {
		if loc[0] == 0 || !isSpaceOrWord(lastRune(bare[:loc[0]])) {
			return fail("trailing: no space before a connective")
		}
	}
	return &parser{text: text, s: s}, nil
}

// dropLineBreaks drops a tab, a line feed, or a carriage return outside a
// string where it stands beside a space or at either end, and reports false
// where one stands for the single space between two tokens.
func dropLineBreaks(s string) (string, bool) {
	var out strings.Builder
	quoted := false
	tail := len(strings.TrimRightFunc(s, unicode.IsSpace))
	for i, ch := range s {
		if ch == '\'' {
			quoted = !quoted
		}
		if (ch == '\t' || ch == '\n' || ch == '\r') && !quoted {
			prev := lastRune(out.String())
			next := s[i+1:]
			if out.Len() == 0 || prev == ' ' || strings.HasPrefix(next, " ") || i >= tail {
				continue
			}
			return "", false
		}
		out.WriteRune(ch)
	}
	return out.String(), true
}

// joinListCommas removes the spaces around each comma between two list
// elements, so a list counts as one token for the spacing checks.
func joinListCommas(masked string) string {
	var out strings.Builder
	rest := masked
	for {
		loc := listCommaRE.FindStringSubmatchIndex(rest)
		if loc == nil {
			out.WriteString(rest)
			return out.String()
		}
		after := rest[loc[1]:]
		if strings.HasPrefix(after, "''") || startsWithNumber(after) {
			out.WriteString(rest[:loc[0]])
			out.WriteString(rest[loc[2]:loc[3]])
			out.WriteByte(',')
		} else {
			out.WriteString(rest[:loc[2]+1])
			loc[1] = loc[2] + 1
		}
		rest = rest[loc[1]:]
	}
}

func startsWithNumber(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

func isWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isSpaceOrWord(r rune) bool {
	return r == ' ' || isWord(r)
}

// endsToken reports whether rest, the text after a literal, starts with
// neither a word character nor a dot.
func endsToken(rest string) bool {
	if rest == "" {
		return true
	}
	r := firstRune(rest)
	return !isWord(r) && r != '.'
}

func (p *parser) fail(reason string) error {
	return &SyntaxError{Text: p.text, Reason: reason}
}

func (p *parser) rest() string { return p.s[p.i:] }

func (p *parser) ws() {
	if p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

// at reports whether w starts at the current position and is not the prefix
// of a longer word.
func (p *parser) at(w string) bool {
	if !strings.HasPrefix(p.rest(), w) {
		return false
	}
	j := p.i + len(w)
	if j == len(p.s) {
		return true
	}
	return !isWord(firstRune(p.s[j:])) || !unicode.IsLetter(lastRune(w))
}

func (p *parser) eat(w string) bool {
	save := p.i
	p.ws()
	if p.at(w) {
		p.i += len(w)
		return true
	}
	p.i = save
	return false
}

func (p *parser) expr() ([][]Atom, error) {
	if p.s == "" {
		return [][]Atom{{Const{Value: true}}}, nil
	}
	var ors [][]Atom
	for {
		c, err := p.conj()
		if err != nil {
			return nil, err
		}
		ors = append(ors, c)
		if !p.eat("OR") {
			break
		}
	}
	p.ws()
	if p.i != len(p.s) {
		if lowerKeywordRE.MatchString(p.rest()) {
			return nil, p.fail("lower-case keyword")
		}
		return nil, p.fail("trailing: " + truncate(p.rest(), 30))
	}
	return ors, nil
}

func (p *parser) conj() ([]Atom, error) {
	var ands []Atom
	for {
		a, err := p.atom()
		if err != nil {
			return nil, err
		}
		ands = append(ands, a)
		if !p.eat("AND") {
			return ands, nil
		}
	}
}

// followedByConnective reports whether rest is empty or starts with " OR " or
// " AND ".
func followedByConnective(rest string) bool {
	return rest == "" || strings.HasPrefix(rest, " OR ") || strings.HasPrefix(rest, " AND ")
}

func (p *parser) atom() (Atom, error) {
	p.ws()
	rest := p.rest()
	if m := accessRE.FindStringSubmatch(rest); m != nil && endsToken(rest[len(m[0]):]) {
		p.i += len(m[0])
		return Access{Denied: m[1] == "denied", Operation: m[2]}, nil
	}
	if strings.HasPrefix(rest, "subject.isM2M") && followedByConnective(rest[len("subject.isM2M"):]) {
		p.i += len("subject.isM2M")
		return IsM2M{}, nil
	}
	if m := constAtomRE.FindString(rest); m != "" && followedByConnective(rest[len(m):]) {
		p.i += len(m)
		return Const{Value: strings.EqualFold(m, "TRUE")}, nil
	}
	left, err := p.operand()
	if err != nil {
		return nil, err
	}
	p.ws()
	if misspelledOpRE.MatchString(p.rest()) && !strings.HasPrefix(p.rest(), "LESS THAN OR EQUAL TO") &&
		!strings.HasPrefix(p.rest(), "GREATER THAN OR EQUAL TO") {
		return nil, p.fail("misspelled word operator")
	}
	var op Operator
	for _, w := range opWords {
		if p.at(w.word) {
			op = w.op
			p.i += len(w.word)
			break
		}
	}
	if op == "" {
		switch {
		case lowerOpRE.MatchString(p.rest()):
			return nil, p.fail("lower-case keyword")
		default:
			return nil, p.fail("operator at: " + truncate(p.rest(), 25))
		}
	}
	if op.Unary() {
		return p.compare(op, left, nil)
	}
	p.ws()
	if op == OpMatch || op == OpNotMatch {
		right, err := p.pattern()
		if err != nil {
			return nil, err
		}
		return p.compare(op, left, right)
	}
	start := p.i
	right, err := p.operand()
	if err != nil {
		return nil, err
	}
	if m := filteredRE.FindStringSubmatch(p.rest()); m != nil {
		if ref, ok := right.(PIPRef); ok {
			p.i += len(m[0])
			right = PIPRef{Name: ref.Name + ".filtered", Filtered: true, FilteredOperation: m[1]}
		}
	}
	if op.TakesList() {
		if lit, ok := right.(Literal); ok {
			right, err = p.list(lit, start)
			if err != nil {
				return nil, err
			}
		}
	}
	return p.compare(op, left, right)
}

// compare returns the comparison, with an operand its position does not admit
// reported as a *SyntaxError.
func (p *parser) compare(op Operator, left, right Operand) (Atom, error) {
	c, err := NewCompare(op, left, right)
	if err != nil {
		return nil, p.fail(err.Error())
	}
	return c, nil
}

// pattern reads the right operand of MATCH and NOT MATCH as [readPattern]
// reads it.
func (p *parser) pattern() (Operand, error) {
	n, path, reason := readPattern(p.rest())
	if reason != "" {
		return nil, p.fail(reason)
	}
	tok := p.rest()[:n]
	p.i += n
	return Pattern{Text: tok, Path: path}, nil
}

// readPattern returns the length of the MATCH pattern at the start of rest,
// whether the pattern is a resource path, and the reason it is refused, or ""
// when it is not. The pattern is the text up to the next space; in a path that
// starts with resource. or subject. and opens more brackets than it closes,
// the spaces inside brackets belong to the pattern too. A pattern is refused
// when it is quoted, holds '{', '+', or a character beyond ASCII, is a number,
// is a word such as resource, true, or NULL that the PAP refuses there, is
// subject.entitledResources.of(...).as(...), or starts with subject. and is a
// permission scope, a built-in subject attribute, or a PIP name.
func readPattern(rest string) (n int, path bool, reason string) {
	tok := matchTokenRE.FindString(rest)
	if tok == "" {
		return 0, false, "MATCH without a pattern"
	}
	prefixed := strings.HasPrefix(tok, "resource.") || strings.HasPrefix(tok, "subject.")
	if prefixed && strings.Count(tok, "[") > strings.Count(tok, "]") {
		if b := matchBracketsRE.FindString(rest); b != "" {
			tok = b
		}
	}
	n = len(tok)
	switch {
	case strings.HasPrefix(tok, "'") || strings.HasPrefix(tok, `"`):
		return n, false, "quoted MATCH pattern"
	case strings.Contains(tok, "{"):
		return n, false, "placeholder in MATCH pattern"
	case matchNumberRE.MatchString(tok):
		return n, false, "number as a MATCH pattern"
	case !isASCII(tok) || strings.Contains(tok, "+") || tok == "resource" || tok == "subject":
		return n, false, "MATCH pattern: " + tok
	case patternReserved[tok] || len(entitledRE.FindString(rest)) == n:
		return n, false, "MATCH pattern: " + tok + " is neither a pattern nor an attribute"
	case strings.HasPrefix(tok, "subject.") && isSubjectToken(tok):
		return n, false, "MATCH pattern: a subject operand"
	}
	return n, strings.HasPrefix(tok, "resource."), ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// list reads the rest of a list whose first literal, first, has just been
// read from position start.
func (p *parser) list(first Literal, start int) (List, error) {
	items := []Literal{first}
	for listMoreRE.MatchString(p.rest()) {
		p.i = strings.Index(p.s[p.i:], ",") + p.i + 1
		for strings.HasPrefix(p.rest(), " ") {
			p.i++
		}
		lit, err := p.literal()
		if err != nil {
			return List{}, err
		}
		l, ok := lit.(Literal)
		if !ok {
			return List{}, p.fail("list element")
		}
		items = append(items, l)
	}
	raw := ""
	if len(items) > 1 {
		raw = p.s[start:p.i]
	}
	l := List{Items: items, Raw: raw}
	if err := validateList(l); err != nil {
		return List{}, p.fail("mixed-type list")
	}
	return l, nil
}

// literal reads a literal at the current position, and returns nil with no
// error when there is none. TRUE, true, FALSE, or false followed by a
// character of a path, such as true,false, is not a literal but the path of
// a resource attribute of that whole text.
func (p *parser) literal() (Operand, error) {
	rest := p.rest()
	if m := stringLitRE.FindStringSubmatch(rest); m != nil {
		p.i += len(m[0])
		return String{Value: m[1]}, nil
	}
	if strings.HasPrefix(rest, `"`) {
		return nil, p.fail("double-quoted string")
	}
	if m := numberLitRE.FindString(rest); m != "" && endsToken(rest[len(m):]) {
		p.i += len(m)
		return Number{Text: m}, nil
	}
	if numberStartRE.MatchString(rest) {
		return nil, p.fail("number: " + truncate(rest, 10))
	}
	if m := boolAttrRE.FindString(rest); m != "" {
		p.i += len(m)
		return p.resource("."+m, m, false), nil
	}
	if m := boolLitRE.FindString(rest); m != "" && endsToken(rest[len(m):]) {
		p.i += len(m)
		return Bool{Value: strings.EqualFold(m, "true")}, nil
	}
	return nil, nil
}

func (p *parser) operand() (Operand, error) {
	p.ws()
	lit, err := p.literal()
	if err != nil || lit != nil {
		return lit, err
	}
	rest := p.rest()
	if m := entitledRE.FindStringSubmatch(rest); m != nil {
		p.i += len(m[0])
		var as []string
		for _, a := range entitledAsRE.FindAllStringSubmatch(m[2], -1) {
			as = append(as, a[1])
		}
		return Entitled{ResourceType: m[1], As: as}, nil
	}
	if strings.HasPrefix(rest, "NOT ") {
		return nil, p.fail("standalone NOT")
	}
	tok := pathToken(rest)
	if strings.HasPrefix(rest, "null") && endsToken(rest[len("null"):]) {
		// null ends where a literal does, so null* is null and then *
		tok = "null"
	}
	if tok == "" || keywords[tok] {
		return nil, p.fail("operand: " + truncate(rest, 30))
	}
	if strings.Contains(tok, "[]") || strings.Contains(tok, `"`) {
		return nil, p.fail("operand: empty brackets or double quotes in a path")
	}
	p.i += len(tok)
	if isScopeToken(tok) && (strings.Contains(tok, "[") || strings.HasSuffix(tok, ".")) {
		return p.subjectToken(tok), nil
	}
	path := tok
	dot := strings.HasSuffix(tok, ".") && !strings.HasSuffix(tok, "..")
	if dot {
		path = tok[:len(tok)-1]
		if strings.HasPrefix(path, "subject.") {
			return p.resource("."+path, tok, true), nil
		}
	}
	path = normalizeIndexes(path)
	switch {
	case path == "operation":
		return Operation{}, nil
	case path == "resourceType":
		return ResourceType{}, nil
	case path == "resource" || strings.HasPrefix(path, "resource.") || strings.HasPrefix(path, "resource["):
		return p.resource(path[len("resource"):], tok, dot), nil
	case strings.HasPrefix(path, "subject.") && !strings.ContainsAny(path, "[]") && isSubjectToken(path):
		return p.subjectToken(path), nil
	case path == "subject":
		return nil, p.fail("bare subject")
	}
	return p.resource("."+path, tok, dot), nil
}

// pathToken returns the operand path at the start of s, or "" when none
// starts there. A path that starts with resource or subject takes keys,
// two-dot keys, functions such as .length(), filters, brackets, and a ']'
// without its '[', and keeps one dot at its end; resource alone is a path
// where neither a word character, a dot, nor a bracket follows it. Any other
// path is a name of letters, digits, '_', '*', and '-' followed by keys,
// two-dot keys, and brackets. A key is a letter, a digit, '_', or '@',
// followed by those and the characters of "/:$~!&|-".
func pathToken(s string) string {
	if m := prefixedPathRE.FindString(s); m != "" {
		return m
	}
	if rest, ok := strings.CutPrefix(s, "resource"); ok && (rest == "" || !isWord(firstRune(rest)) && rest[0] != '.' && rest[0] != '[') {
		return "resource"
	}
	return plainPathRE.FindString(s)
}

// normalizeIndexes drops the spaces inside each index step of path, [ 0 ] to
// [0], and leaves the text of a literal as written: a quoted string, and a
// regular expression after =~.
func normalizeIndexes(path string) string {
	var b strings.Builder
	quoted, regex := false, false
	// last and prev are the last two bytes outside a literal, spaces and
	// quotes left out.
	var last, prev byte
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case regex:
			regex = c != '/'
		case c == '\'':
			quoted = !quoted
		case quoted:
		case c == '/' && prev == '=' && last == '~':
			regex = true
		case c == '[':
			if m := indexStepRE.FindStringSubmatch(path[i:]); m != nil {
				b.WriteString("[" + m[1] + "]")
				i += len(m[0]) - 1
				prev, last = last, ']'
				continue
			}
		}
		if !quoted && !regex && c != ' ' && c != '\'' {
			prev, last = last, c
		}
		b.WriteByte(c)
	}
	return b.String()
}

// resource returns the resource operand for path, written with one dot at its
// end when dot, or an [Unsupported] one quoting text, the operand as written,
// when [jsonpath.Compile] refuses the path.
func (p *parser) resource(path, text string, dot bool) Operand {
	if _, err := jsonpath.Compile(path); err != nil {
		return Unsupported{Form: FormJSONPath, Text: text}
	}
	return Resource{Path: path, TrailingDot: dot}
}

// isSubjectToken reports whether tok, a path that starts with "subject.", is
// a permission scope, a built-in subject attribute, or a PIP name, rather
// than the path of a resource attribute.
func isSubjectToken(tok string) bool {
	return isScopeToken(tok) || pipTokenRE.MatchString(tok)
}

// isScopeToken reports whether tok is a subject.permissionScope.<key> token: a
// key that starts with a letter or '_' and has no ']' without its '['. The key
// "a]" is not one, so subject.permissionScope.a] is the path of a resource
// attribute.
func isScopeToken(tok string) bool {
	return scopeTokenRE.MatchString(tok) && strings.Count(tok, "]") <= strings.Count(tok, "[")
}

// subjectToken returns the operand for tok, a token for which
// [isSubjectToken] holds. The key of a permission scope is the rest of tok as
// written, so subject.permissionScope.a[0] reads the key "a[0]" and
// subject.permissionScope.a. the key "a."; inside an iterate it is a key of
// the pass. A name that is not exactly a built-in attribute is a PIP name, so
// subject.id.region and subject.entitledResources are PIP names, and so is
// subject.permissionScope without a key.
func (p *parser) subjectToken(tok string) Operand {
	name := tok[len("subject."):]
	if isScopeToken(tok) {
		key := name[len("permissionScope."):]
		if p.iterVar != "" {
			return PassValue{Var: p.iterVar, Key: key}
		}
		return Subject{Attr: SubjectPermissionScope, Key: key}
	}
	if a := SubjectAttr(name); a != SubjectPermissionScope && slices.Contains(subjectAttrs, a) {
		return Subject{Attr: a}
	}
	return PIPRef{Name: tok}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
