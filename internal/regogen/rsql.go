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

package regogen

import (
	"errors"
	"regexp"
	"strings"
)

// The RSQL text of a DENY predicate is negated on its parse tree: the
// comparisons swap to their opposites and the joins by De Morgan. The parser
// reads RSQL as rsql-parser 2.x does, with any =word= operator accepted. Its
// tokens, by longest match and then by this order:
//
//	SKIP        " " | "\t"
//	UNRESERVED  ( ~["\"", "'", "(", ")", ";", ",", "=", "<", ">", "!", "~", " "] )+
//	SQ, DQ      a single- or double-quoted value, a backslash escaping any character
//	AND         ";" | " and "
//	OR          "," | " or "
//	LP, RP      "(" , ")"
//	COMP        ( "=" [a-zA-Z]* | "!" ) "="  |  ( ">" | "<" ) "="?

// errRSQL is a text the parser refuses, or a comparison with no opposite.
var errRSQL = errors.New("rsql: no negation")

var rsqlNegOp = map[string]string{"==": "!=", "!=": "==", "=in=": "=out=", "=out=": "=in=", "=lt=": "=ge=",
	"=ge=": "=lt=", "=le=": "=gt=", "=gt=": "=le=", "<": ">=", ">=": "<", "<=": ">", ">": "<="}

var rsqlDefaultOps = map[string]bool{"==": true, "!=": true, "=lt=": true, "<": true, "=le=": true, "<=": true,
	"=gt=": true, ">": true, "=ge=": true, ">=": true, "=in=": true, "=out=": true}

type rsqlToken struct{ kind, text string }

var (
	rsqlUnreserved = regexp.MustCompile(`^[^"'();,=<>!~ ]+`)
	rsqlFIQL       = regexp.MustCompile(`^(=[a-zA-Z]*|!)=`)
	rsqlAlt        = regexp.MustCompile(`^[<>]=?`)
)

func rsqlQuoted(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j + 1
		}
	}
	return -1
}

func rsqlTokens(s string) ([]rsqlToken, error) {
	var out []rsqlToken
	for i := 0; i < len(s); {
		best, bestOrder, kind := 0, 0, ""
		cand := func(n, order int, k string) {
			if n > best || n == best && order < bestOrder {
				best, bestOrder, kind = n, order, k
			}
		}
		rest := s[i:]
		if s[i] == ' ' || s[i] == '\t' {
			cand(1, 0, "SKIP")
		}
		if m := rsqlUnreserved.FindString(rest); m != "" {
			cand(len(m), 1, "UNRESERVED")
		}
		if s[i] == '\'' || s[i] == '"' {
			if e := rsqlQuoted(s, i); e > 0 {
				cand(e-i, 2, "Q")
			}
		}
		switch {
		case s[i] == ';':
			cand(1, 4, "AND")
		case strings.HasPrefix(rest, " and "):
			cand(5, 4, "AND")
		}
		switch {
		case s[i] == ',':
			cand(1, 5, "OR")
		case strings.HasPrefix(rest, " or "):
			cand(4, 5, "OR")
		}
		if s[i] == '(' {
			cand(1, 6, "LP")
		}
		if s[i] == ')' {
			cand(1, 7, "RP")
		}
		if m := rsqlFIQL.FindString(rest); m != "" {
			cand(len(m), 8, "COMP")
		}
		if m := rsqlAlt.FindString(rest); m != "" {
			cand(len(m), 9, "COMP")
		}
		if kind == "" {
			return nil, errRSQL
		}
		if kind != "SKIP" {
			out = append(out, rsqlToken{kind, s[i : i+best]})
		}
		i += best
	}
	return out, nil
}

// rsqlNode is a parsed RSQL text: a comparison (kind "cmp") with its
// arguments as written, or an and or an or of parts.
type rsqlNode struct {
	kind  string
	sel   string
	op    string
	args  []string
	parts []*rsqlNode
}

type rsqlParser struct {
	t []rsqlToken
	i int
}

func (p *rsqlParser) peek() string {
	if p.i < len(p.t) {
		return p.t[p.i].kind
	}
	return "EOF"
}

func (p *rsqlParser) take(kind string) (string, error) {
	if p.peek() != kind {
		return "", errRSQL
	}
	p.i++
	return p.t[p.i-1].text, nil
}

func (p *rsqlParser) join(kind, sep string, next func() (*rsqlNode, error)) (*rsqlNode, error) {
	first, err := next()
	if err != nil {
		return nil, err
	}
	parts := []*rsqlNode{first}
	for p.peek() == sep {
		p.i++
		n, err := next()
		if err != nil {
			return nil, err
		}
		parts = append(parts, n)
	}
	if len(parts) == 1 {
		return first, nil
	}
	// a nested group of the same join is flattened into this one
	var flat []*rsqlNode
	for _, x := range parts {
		if x.kind == kind {
			flat = append(flat, x.parts...)
		} else {
			flat = append(flat, x)
		}
	}
	return &rsqlNode{kind: kind, parts: flat}, nil
}

func (p *rsqlParser) or() (*rsqlNode, error) { return p.join("or", "OR", p.and) }

func (p *rsqlParser) and() (*rsqlNode, error) { return p.join("and", "AND", p.constraint) }

func (p *rsqlParser) constraint() (*rsqlNode, error) {
	if p.peek() == "LP" {
		p.i++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if _, err := p.take("RP"); err != nil {
			return nil, err
		}
		return e, nil
	}
	sel, err := p.take("UNRESERVED")
	if err != nil {
		return nil, err
	}
	op, err := p.take("COMP")
	if err != nil {
		return nil, err
	}
	n := &rsqlNode{kind: "cmp", sel: sel, op: op}
	if p.peek() != "LP" {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.args = []string{v}
		return n, nil
	}
	p.i++
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.args = append(n.args, v)
		if p.peek() != "OR" {
			break
		}
		p.i++
	}
	if _, err := p.take("RP"); err != nil {
		return nil, err
	}
	if op != "=in=" && op != "=out=" && len(n.args) > 1 && rsqlDefaultOps[op] {
		return nil, errRSQL
	}
	return n, nil
}

func (p *rsqlParser) value() (string, error) {
	switch p.peek() {
	case "UNRESERVED", "Q":
		p.i++
		return p.t[p.i-1].text, nil
	}
	return "", errRSQL
}

func parseRSQL(s string) (*rsqlNode, error) {
	t, err := rsqlTokens(s)
	if err != nil {
		return nil, err
	}
	p := &rsqlParser{t: t}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek() != "EOF" {
		return nil, errRSQL
	}
	return n, nil
}

func (n *rsqlNode) negate() (*rsqlNode, error) {
	if n.kind == "cmp" {
		op, ok := rsqlNegOp[n.op]
		if !ok {
			return nil, errRSQL
		}
		return &rsqlNode{kind: "cmp", sel: n.sel, op: op, args: n.args}, nil
	}
	kind := "and"
	if n.kind == "and" {
		kind = "or"
	}
	out := &rsqlNode{kind: kind}
	for _, x := range n.parts {
		y, err := x.negate()
		if err != nil {
			return nil, err
		}
		out.parts = append(out.parts, y)
	}
	return out, nil
}

func (n *rsqlNode) write() string {
	if n.kind == "cmp" {
		if len(n.args) > 1 || n.op == "=in=" || n.op == "=out=" {
			return n.sel + n.op + "(" + strings.Join(n.args, ",") + ")"
		}
		return n.sel + n.op + n.args[0]
	}
	sep := ","
	if n.kind == "and" {
		sep = ";"
	}
	parts := make([]string, len(n.parts))
	for i, x := range n.parts {
		parts[i] = x.write()
		if x.kind != "cmp" && x.kind != n.kind {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, sep)
}

// negateRSQL returns the negation of the RSQL text s: its parse tree with
// each comparison swapped to its opposite and each join by De Morgan, the
// values as written. It returns false for a text the parser refuses and for
// one with a comparison that has no opposite, such as =like=.
func negateRSQL(s string) (string, bool) {
	n, err := parseRSQL(s)
	if err != nil {
		return "", false
	}
	neg, err := n.negate()
	if err != nil {
		return "", false
	}
	return neg.write(), true
}
