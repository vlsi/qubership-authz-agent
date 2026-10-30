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

// Package jsonpath selects values from a document as the legacy policy
// language selects them with a jsonPath, in the subset of jsonPath this
// package implements. The legacy service evaluates a path with Jayway
// JsonPath, and the package answers as Jayway does over a document whose
// numbers are exact, with two kinds of exception. Where the legacy service
// reads Jayway's answer in its own way, the package answers as the legacy
// service does: a path that Jayway finds nothing for or throws on selects
// nothing, and keys() of an object selects one string. Where Jayway 2.9.0 has
// a bug, such as max() of negative numbers or a slice with a negative start,
// the package gives the answer Jayway means to give; each such place is named
// where it is implemented. A path outside the subset fails to [Compile] with
// an error that wraps [ErrUnsupported], so a policy that holds such a path can
// be refused before it runs.
//
// Where a path would visit or select parts of a document many times over,
// such as ..key over {"key":{"key":...}}, [Path.Select] stops with
// [KindTooLarge] instead of the selection Jayway gives, so that its time stays
// linear in the size of the document.
//
// A path here has no leading $: it starts with the first step, as in
// .items[*].name or [0].id. The caller strips the $ of a PIP declaration and
// reads a leading ['key'] as .key where the policy language does.
//
// # Steps
//
//   - .key and ['key'] select a member. A key after a dot holds letters,
//     digits, _, -, and any of : $ ~ @ ! & |; after its first character it
//     may also hold *. A key of digits is a key, not an index: .roles.1 reads
//     the member "1" of an object. A bracket step may follow a dot, as in
//     .[*] and .a.['k']. A key in brackets is unescaped as Jayway does, so
//     ['a\nb'] reads the member whose key holds a newline.
//   - ..key selects every member named key at any depth; an object gives its
//     own member before the members inside its values.
//   - [n] selects an element; a negative n counts from the end.
//   - [n,m,...] selects the listed elements that exist, and [a:b], [a:], and
//     [:b] select a range of elements, where a negative bound counts from the
//     end. Jayway does not compile [:], an index or a bound beyond Java's
//     int range, or one with a digit outside the Basic Multilingual Plane;
//     the legacy service reads the attribute of such a path as absent, so
//     the path compiles and selects nothing ([KindMissing]) whatever the
//     document.
//   - [*] selects every element of a list and every member of an object.
//   - [?(filter)] tests every element of a list and every object; over one
//     value that is neither, the path selects nothing.
//   - A last step of .length(), .min(), .max(), .avg(), .sum(), .first(),
//     .last(), or .keys() computes a value from what the path selected,
//     after a step that selects several values from each of them. A function
//     after .. is refused.
//
// # Filters
//
// A filter is @ or @.key compared with a literal by ==, !=, <, <=, >, or >=,
// where the literal is a string in single quotes, a decimal number, true,
// false, or null; @.key alone, which tests that the member exists; in, nin,
// subsetof, anyof, and noneof against a list of strings in single quotes;
// size and empty; =~ with a java.util.regex pattern and an optional flag i;
// @.key[?(filter)], which holds where the filter selects something in the
// member; and
// && and || between filters, || binding looser. A pattern Go cannot match the
// way java.util.regex does is refused, such as one with lookaround, a
// backreference, \b, or \p.
//
// Only a space may stand around an operator, as in Jayway. A literal in
// quotes, an item of a list among them, is unescaped as Jayway unescapes the
// literal of ==. A filter splits at every && and ||, so a filter that holds
// either inside a nested filter or inside a quoted literal is refused.
package jsonpath

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"authz-agent/internal/jsonvalue"
)

// ErrUnsupported is the error [Compile] wraps for a path outside the subset.
var ErrUnsupported = errors.New("jsonpath: unsupported path")

// errJaywayRefuses marks a step Jayway does not compile, which makes the path
// select nothing rather than leave the subset.
var errJaywayRefuses = errors.New("jsonpath: Jayway does not compile the path")

// errGoRegex marks a filter pattern that Jayway compiles and Go cannot match
// as java.util.regex does: the path leaves the subset, unless a later part
// of it is one Jayway does not compile.
var errGoRegex = errors.New("a pattern Go does not match as java.util.regex does")

// errBeyondInt marks a number beyond the int range, which Jayway does not
// compile as an index or a slice bound.
var errBeyondInt = fmt.Errorf("beyond the int range: %w", errJaywayRefuses)

// Kind is how a path selected.
type Kind string

// The kinds of selection.
const (
	// KindOne selected one value, which may be null.
	KindOne Kind = "one"
	// KindMany went through a step that can select several values; the
	// result is the list of what it selected, possibly empty.
	KindMany Kind = "many"
	// KindMissing selected nothing where one value was expected.
	KindMissing Kind = "missing"
	// KindNullParent read a member of null or of an empty object other than
	// the document itself; a member of a null or empty document is
	// KindMissing.
	KindNullParent Kind = "nullparent"
	// KindIndexOutOfBounds read an index outside a list.
	KindIndexOutOfBounds Kind = "oob"
	// KindBracket is a path that starts with ['key'], which a resource path
	// reads differently from a PIP path.
	KindBracket Kind = "bracket"
	// KindTooLarge stopped a path whose work outgrew its document. The
	// selection counts a value once for each selected value that holds it, so
	// a path that selects nested values reaches the limit within a few
	// levels: ..children over a binary tree 8 levels deep, a document of
	// 5 KB, or ..key over {"key":{"key":...}} nested 50 deep, a document of
	// 401 bytes. Jayway selects such values; the package refuses them, so that
	// a document cannot make a path take time quadratic in its size. A path
	// that ends in a scalar member of the nested values, such as
	// ..children[*].id, stays within the limit.
	KindTooLarge Kind = "toolarge"
)

// Result is what a path selected. Value is the value for [KindOne], a
// []jsonvalue.Value for [KindMany], and nil for the other kinds.
type Result struct {
	Kind  Kind
	Value jsonvalue.Value
}

// Path is a compiled path. It is safe for concurrent use.
type Path struct {
	steps []step
	// refused is set for a path Jayway does not compile: it selects
	// nothing.
	refused bool
}

type stepKind int

const (
	stepKey stepKind = iota
	stepDeep
	stepStar
	stepFilter
	stepIndex
	stepIndexList
	stepSlice
	stepRootBracket
	stepFunction
)

type step struct {
	kind   stepKind
	key    string // stepKey, stepDeep; the name for stepFunction
	index  int    // stepIndex
	list   []int  // stepIndexList
	lo, hi *int   // stepSlice
	filter predicate
	// reads holds the keys of the members a filter reads, "" for the
	// element itself.
	reads []string
}

// word is the class of characters a key holds besides its punctuation:
// Unicode letters, digits, and _. space is the one character Jayway accepts
// around a filter operator.
const (
	word  = `\p{L}\p{N}_`
	space = ` `
)

var (
	filterToken = `\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\]|\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\])*\)\])*\)\]`
	// A bracket step may follow a dot, as in .[*] and .['key'].
	tokenRE = regexp.MustCompile(`\.(?:length|min|max|avg|sum|first|last|keys)\(\)$` +
		`|\.\.[` + word + `:$~@!&|-]+` +
		`|\.[` + word + `:$~@!&|-][` + word + `:$~@!&|*-]*` +
		`|\.?` + filterToken +
		`|\.?\[[^\]]*\]`)
	bracketKeyRE = regexp.MustCompile(`^\['([^']*)'\]$`)
	indexListRE  = regexp.MustCompile(`^\[-?\p{Nd}+(?:, ?-?\p{Nd}+)+\]$`)
	sliceRE      = regexp.MustCompile(`^\[(-?\p{Nd}*):(-?\p{Nd}*)\]$`)
	indexRE      = regexp.MustCompile(`^\[(-?\p{Nd}+)\]$`)
)

// Compile parses path. It returns an error that wraps [ErrUnsupported] for a
// path outside the subset, such as a filter whose regular expression Go
// cannot match as java.util.regex does. A path that Jayway does not compile
// compiles to a path that selects nothing, as the legacy service reads it as
// absent, also where such a filter pattern comes first: [:], an index or a
// slice bound beyond the int range, and a decimal digit outside the Basic
// Multilingual Plane in an index, a slice bound, a filter's number literal,
// or a size.
func Compile(path string) (*Path, error) {
	toks := tokenRE.FindAllString(path, -1)
	if strings.Join(toks, "") != path {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, path)
	}
	p := &Path{steps: make([]step, 0, len(toks))}
	deep := false
	var unsupported error
	for pos, t := range toks {
		s, err := parseStep(t, pos)
		if errors.Is(err, errJaywayRefuses) {
			return &Path{refused: true}, nil
		}
		if errors.Is(err, errGoRegex) {
			// Jayway compiles the pattern, so a later step it does not
			// compile still decides
			if unsupported == nil {
				unsupported = fmt.Errorf("%w: %q: %w", ErrUnsupported, path, err)
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrUnsupported, path, err)
		}
		deep = deep || s.kind == stepDeep
		if deep && s.kind == stepFunction {
			// Jayway computes a function after a deep scan over more values
			// than the scan selects; the path leaves the subset before any
			// later step is read.
			return nil, fmt.Errorf("%w: %q: a function after a deep scan", ErrUnsupported, path)
		}
		p.steps = append(p.steps, s)
	}
	if unsupported != nil {
		return nil, unsupported
	}
	return p, nil
}

func parseStep(t string, pos int) (step, error) {
	if strings.HasPrefix(t, ".[") {
		// .['key'] is a key wherever it stands; only a path that starts
		// with [ is read as KindBracket.
		t, pos = t[1:], -1
	}
	if m := bracketKeyRE.FindStringSubmatch(t); m != nil {
		if pos == 0 {
			return step{kind: stepRootBracket}, nil
		}
		key, err := quotedText(m[1])
		return step{kind: stepKey, key: key}, err
	}
	switch {
	case strings.HasSuffix(t, "()"):
		return step{kind: stepFunction, key: t[1 : len(t)-2]}, nil
	case strings.HasPrefix(t, ".."):
		return step{kind: stepDeep, key: t[2:]}, nil
	case strings.HasPrefix(t, "."):
		return step{kind: stepKey, key: t[1:]}, nil
	case t == "[*]":
		return step{kind: stepStar}, nil
	case strings.HasPrefix(t, "[?(") && strings.HasSuffix(t, ")]"):
		var reads []string
		f, err := parseFilter(t[3:len(t)-2], &reads)
		slices.Sort(reads)
		return step{kind: stepFilter, filter: f, reads: slices.Compact(reads)}, err
	case indexListRE.MatchString(t):
		var list []int
		for part := range strings.SplitSeq(t[1:len(t)-1], ",") {
			n, err := parseInt(strings.TrimPrefix(part, " "))
			if err != nil {
				return step{}, err
			}
			list = append(list, n)
		}
		return step{kind: stepIndexList, list: list}, nil
	}
	if m := sliceRE.FindStringSubmatch(t); m != nil {
		if m[1] == "" && m[2] == "" {
			return step{}, fmt.Errorf("slice %q has no bound: %w", t, errJaywayRefuses)
		}
		s := step{kind: stepSlice}
		for i, bound := range []**int{&s.lo, &s.hi} {
			if m[i+1] == "" {
				continue
			}
			n, err := parseInt(m[i+1])
			if err != nil {
				return step{}, err
			}
			*bound = &n
		}
		return s, nil
	}
	if m := indexRE.FindStringSubmatch(t); m != nil {
		n, err := parseInt(m[1])
		return step{kind: stepIndex, index: n}, err
	}
	return step{}, fmt.Errorf("step %q", t)
}

// parseInt reads an optional minus and Unicode decimal digits as Java's
// Integer.parseInt does. A value outside the int range and a digit outside
// the Basic Multilingual Plane, which Integer.parseInt refuses, are an error
// that wraps errJaywayRefuses.
func parseInt(s string) (int, error) {
	if strings.ContainsFunc(s, func(r rune) bool { return r > 0xFFFF && unicode.IsDigit(r) }) {
		return 0, fmt.Errorf("index %q has a digit outside the Basic Multilingual Plane: %w", s, errJaywayRefuses)
	}
	d, ok := jsonvalue.ParseDecimal(s)
	if !ok || strings.ContainsAny(s, "+.eE") {
		return 0, fmt.Errorf("index %q", s)
	}
	n, err := strconv.ParseInt(d.String(), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("index %q: %w", s, errBeyondInt)
	}
	return int(n), nil
}

// Select applies the path to doc. The selected values are parts of doc, not
// copies. Select gives [KindTooLarge] once its work exceeds a fixed multiple
// of the size of doc: each value a step visits, each member a filter reads,
// and the size of the final selection, counting a value as often as a step
// reaches it.
func (p *Path) Select(doc jsonvalue.Value) Result {
	if p.refused {
		return Result{Kind: KindMissing}
	}
	if doc == nil && (len(p.steps) == 0 || p.steps[0].kind != stepRootBracket) {
		// Jayway refuses a null document. A path that starts with ['key']
		// never reaches Jayway, so its kind does not depend on the document.
		return Result{Kind: KindMissing}
	}
	many := false
	cur := []jsonvalue.Value{doc}
	b := budget{doc: doc}
	tooLarge := Result{Kind: KindTooLarge}
	for pos, s := range p.steps {
		var next []jsonvalue.Value
		switch s.kind {
		case stepFunction:
			for _, v := range cur {
				if !b.charge(functionInput(v)) {
					return tooLarge
				}
			}
			return function(s.key, cur, many)
		case stepRootBracket:
			return Result{Kind: KindBracket}
		case stepDeep:
			many = true
			for _, v := range cur {
				var ok bool
				if next, ok = walk(v, s.key, next, &b); !ok {
					return tooLarge
				}
			}
		case stepKey:
			for _, v := range cur {
				if obj, ok := v.(*jsonvalue.Object); ok {
					if m, ok := obj.Get(s.key); ok {
						next = append(next, m)
						continue
					}
				}
				if many {
					continue
				}
				// A key the document itself lacks is missing even where the
				// document is null or an empty object.
				if pos == 0 {
					return Result{Kind: KindMissing}
				}
				if obj, ok := v.(*jsonvalue.Object); v == nil || ok && obj.Len() == 0 {
					return Result{Kind: KindNullParent}
				}
				return Result{Kind: KindMissing}
			}
		case stepStar:
			many = true
			for _, v := range cur {
				switch x := v.(type) {
				case []jsonvalue.Value:
					if !b.charge(len(x)) {
						return tooLarge
					}
					next = append(next, x...)
				case *jsonvalue.Object:
					if !b.charge(x.Len()) {
						return tooLarge
					}
					next = appendMembers(next, x)
				}
			}
		case stepFilter:
			for _, v := range cur {
				var tested []jsonvalue.Value
				switch x := v.(type) {
				case []jsonvalue.Value:
					tested = x
				case *jsonvalue.Object:
					tested = []jsonvalue.Value{x}
				default:
					if !many {
						// Jayway refuses a filter over one value that is
						// neither a list nor an object.
						return Result{Kind: KindMissing}
					}
				}
				for _, e := range tested {
					for _, key := range s.reads {
						if !b.chargeWeight(member(e, key)) {
							return tooLarge
						}
					}
					if s.filter(e) {
						next = append(next, e)
					}
				}
			}
			many = true
		case stepIndexList, stepSlice:
			if !many {
				if _, ok := cur[0].([]jsonvalue.Value); !ok {
					return Result{Kind: KindMissing}
				}
			}
			many = true
			for _, v := range cur {
				list, ok := v.([]jsonvalue.Value)
				// An index list selects at most one element per index; a
				// slice, at most the whole list.
				appended := len(list)
				if s.kind == stepIndexList {
					appended = len(s.list)
				}
				if ok && !b.charge(appended) {
					return tooLarge
				}
				switch {
				case !ok:
				case s.kind == stepIndexList:
					for _, i := range s.list {
						if i >= -len(list) && i < len(list) {
							next = append(next, list[(i+len(list))%len(list)])
						}
					}
				default:
					next = append(next, slice(list, s.lo, s.hi)...)
				}
			}
		case stepIndex:
			for _, v := range cur {
				list, ok := v.([]jsonvalue.Value)
				switch {
				case ok && s.index >= -len(list) && s.index < len(list):
					next = append(next, list[(s.index+len(list))%len(list)])
				case many:
				case ok:
					return Result{Kind: KindIndexOutOfBounds}
				default:
					return Result{Kind: KindMissing}
				}
			}
		}
		cur = next
	}
	if many {
		for _, v := range cur {
			if !b.chargeWeight(v) {
				return tooLarge
			}
		}
		if cur == nil {
			cur = []jsonvalue.Value{}
		}
		return Result{Kind: KindMany, Value: cur}
	}
	return Result{Kind: KindOne, Value: cur[0]}
}

func appendMembers(next []jsonvalue.Value, obj *jsonvalue.Object) []jsonvalue.Value {
	for _, k := range obj.Keys() {
		v, _ := obj.Get(k)
		next = append(next, v)
	}
	return next
}

// walk appends to out every member named key under v and returns the
// extended slice. An object gives its own member first and then the members
// inside each of its values, in document order. walk charges b one unit for
// each value it visits and reports false once b is spent.
func walk(v jsonvalue.Value, key string, out []jsonvalue.Value, b *budget) ([]jsonvalue.Value, bool) {
	if !b.charge(1) {
		return out, false
	}
	var ok bool
	switch x := v.(type) {
	case *jsonvalue.Object:
		if m, found := x.Get(key); found {
			out = append(out, m)
		}
		for _, k := range x.Keys() {
			m, _ := x.Get(k)
			if out, ok = walk(m, key, out, b); !ok {
				return out, false
			}
		}
	case []jsonvalue.Value:
		for _, e := range x {
			if out, ok = walk(e, key, out, b); !ok {
				return out, false
			}
		}
	}
	return out, true
}

// slice returns the elements of list from lo up to but not including hi. A
// missing bound is the edge of the list, a negative bound counts from the
// end, and a bound beyond the list stops at its edge, so [-4:1] over five
// elements selects nothing and [-2:] the last two. In [lo:hi], Jayway 2.9.0
// wraps a negative lo around the list and does not count a negative hi from
// the end.
func slice(list []jsonvalue.Value, lo, hi *int) []jsonvalue.Value {
	n := len(list)
	clamp := func(b *int, def int) int {
		if b == nil {
			return def
		}
		i := *b
		if i < 0 {
			i += n
		}
		return max(0, min(n, i))
	}
	a, b := clamp(lo, 0), clamp(hi, n)
	if a >= b {
		return nil
	}
	return list[a:b]
}

// outcome is how a function over one value ends.
type outcome int

const (
	computed outcome = iota
	// empty is .first() or .last() of an empty list, which has no value.
	// After [*], Jayway 2.9.0 drops .first() of an empty list element, but
	// throws for an empty object member and for .last(); the package drops
	// each of them.
	empty
	// thrown is a function Jayway throws on, such as .min() of a list with
	// no number.
	thrown
)

// function computes the value of a last step such as .length(). After a step
// that selects several values, it computes the function for each value, and
// the path selects the results; a value with no result, .first() or .last()
// of an empty list, is dropped, and where Jayway throws for one value, the
// path selects nothing.
func function(name string, cur []jsonvalue.Value, many bool) Result {
	if !many {
		v, o := apply(name, cur[0])
		if o != computed {
			return Result{Kind: KindMissing}
		}
		return Result{Kind: KindOne, Value: v}
	}
	out := []jsonvalue.Value{}
	for _, x := range cur {
		v, o := apply(name, x)
		switch o {
		case computed:
			out = append(out, v)
		case thrown:
			return Result{Kind: KindMissing}
		}
	}
	return Result{Kind: KindMany, Value: out}
}

// apply computes function name over one value, as Jayway does.
//
//   - length() is the number of elements of a list or members of an object,
//     and null for anything else, a string included.
//   - keys() of an object is one string, the text the legacy service compares
//     the set of keys Jayway returns by: [a, b]. keys() of anything else is
//     null.
//   - first() and last() are the first and the last element of a list. Jayway
//     2.9.0 throws for last() of a one-element list; the package gives the
//     element.
//   - min(), max(), sum(), and avg() compute over the numbers of a list as
//     float64 values, adding from first to last, and print the result as
//     Java's Double.toString does, so min() of [1] is 1.0 and max() of [-1]
//     is -1.0. Jayway 2.9.0 starts max() at Double.MIN_VALUE and min() at
//     Double.MAX_VALUE instead, which the package does not repeat. Jayway
//     throws for a list with no number and for anything but a list.
func apply(name string, x jsonvalue.Value) (jsonvalue.Value, outcome) {
	list, isList := x.([]jsonvalue.Value)
	switch name {
	case "length":
		switch v := x.(type) {
		case []jsonvalue.Value:
			return jsonvalue.Number(strconv.Itoa(len(v))), computed
		case *jsonvalue.Object:
			return jsonvalue.Number(strconv.Itoa(v.Len())), computed
		}
		return nil, computed
	case "keys":
		if obj, ok := x.(*jsonvalue.Object); ok {
			return "[" + strings.Join(obj.Keys(), ", ") + "]", computed
		}
		return nil, computed
	case "first", "last":
		switch {
		case !isList:
			return nil, thrown
		case len(list) == 0:
			return nil, empty
		case name == "first":
			return list[0], computed
		}
		return list[len(list)-1], computed
	}
	if !isList {
		return nil, thrown
	}
	var nums []float64
	for _, e := range list {
		if n, ok := e.(jsonvalue.Number); ok {
			// A number beyond the float64 range counts as an infinity, as
			// Java reads it. Java reads -0 and -0.0 of a document as 0, so
			// adding 0 drops the sign of a zero.
			f, _ := strconv.ParseFloat(string(n), 64)
			nums = append(nums, f+0)
		}
	}
	if len(nums) == 0 {
		return nil, thrown
	}
	acc := nums[0]
	switch name {
	case "sum", "avg":
		acc = 0
		for _, f := range nums {
			acc += f
		}
		if name == "avg" {
			acc /= float64(len(nums))
		}
	case "max":
		for _, f := range nums[1:] {
			if f > acc {
				acc = f
			}
		}
	default:
		for _, f := range nums[1:] {
			if f < acc {
				acc = f
			}
		}
	}
	return jsonvalue.Number(jsonvalue.DoubleText(acc)), computed
}

// isSpace reports whether r is the space a filter may hold around its
// operators.
func isSpace(r rune) bool {
	return r == ' '
}
