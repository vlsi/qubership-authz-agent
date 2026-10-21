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
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// Access-control joins the predicates of the rules that apply to a filter request
// in an order that differs from one run to the next, at every level of the
// expression: the terms of one OR, the terms of one AND, and the bracketed groups
// of nested sets and of simplified policies. The functions here rewrite each
// filter dialect into a form in which the terms of every operator are sorted, so
// that two answers that differ in that order alone compare equal. The form is
// for comparison only; the golden on disk keeps the text the stand answered.
//
// The canonical text is not the dialect's own syntax: separators are rejoined
// without the stand's spacing, and a chain of method calls is written back in
// the same chain order after sorting. Both sides of a comparison pass through
// the same rewrite, so only the difference between them matters.

// normalizeFilterOrder applies the order rewrite to every dialect of a filter
// answer, and returns v unchanged for any other golden type.
func normalizeFilterOrder(v any) any {
	switch typed := v.(type) {
	case *model.OldFilterEvaluationResult:
		clone := *typed
		normalizeOldFilterResultOrder(&clone)
		return &clone
	case *model.FilterOutcome:
		clone := *typed
		normalizeOldFilterResultOrder(&clone.Result)
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		normalizeOldFilterResultOrder(&clone.Result)
		return &clone
	case *model.FilterResponse:
		clone := *typed
		clone.FilterCondition = clone.FilterCondition.Map(canonicalMethodChain)
		clone.MongodbFilterCondition = clone.MongodbFilterCondition.Map(infixCanon(mongodbSeparators))
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(infixCanon(rsqlSeparators))
		clone.SqlFilterCondition = clone.SqlFilterCondition.Map(infixCanon(sqlSeparators))
		clone.CustomFilterCondition = canonicalJSON(clone.CustomFilterCondition)
		return &clone
	default:
		return v
	}
}

func normalizeOldFilterResultOrder(r *model.OldFilterEvaluationResult) {
	r.FilterCondition = r.FilterCondition.Map(canonicalMethodChain)
	r.MongodbFilterCondition = r.MongodbFilterCondition.Map(infixCanon(mongodbSeparators))
	r.RsqlFilterCondition = r.RsqlFilterCondition.Map(infixCanon(rsqlSeparators))
	r.SqlFilterCondition = r.SqlFilterCondition.Map(infixCanon(sqlSeparators))
	r.CustomFilterCondition = canonicalJSON(r.CustomFilterCondition)
}

// The separators of the infix dialects, from the loosest-binding operator to the
// tightest: the split at one level of brackets is tried in this order, and the
// first separator that splits decides the terms of that level. The comma of the
// SQL dialect is the one inside an IN list, whose elements the stand permutes as
// it does the terms of an operator.
var (
	rsqlSeparators    = []string{",", ";"}
	sqlSeparators     = []string{" OR ", " AND ", ","}
	mongodbSeparators = []string{","}
	// methodArgumentSeparators split the arguments of one call in the method
	// chain dialect, such as the elements of an in list.
	methodArgumentSeparators = []string{","}
)

// canonicalInfix sorts the terms of every operator in an infix expression. At
// each bracket level the text is split at the first separator of seps that
// occurs outside brackets and quotes; the parts are canonicalized in turn,
// trimmed, sorted, and rejoined with that separator. A level that no separator
// splits keeps its text, with every bracketed group inside it canonicalized.
func canonicalInfix(expr string, seps []string) string {
	for _, sep := range seps {
		parts := splitOutsideBrackets(expr, sep)
		if len(parts) < 2 {
			continue
		}
		for i := range parts {
			parts[i] = canonicalInfix(strings.TrimSpace(parts[i]), seps)
		}
		sort.Strings(parts)
		return strings.Join(parts, sep)
	}
	return rewriteBracketGroups(expr, func(inner string) string {
		return canonicalInfix(strings.TrimSpace(inner), seps)
	})
}

// infixCanon returns canonicalInfix with the separators seps, the form
// [model.FilterText.Map] applies to a dialect's text.
func infixCanon(seps []string) func(string) string {
	return func(expr string) string { return canonicalInfix(expr, seps) }
}

// canonicalMethodChain sorts the operands of a chain of .and( ) or .or( ) calls,
// the form of filterCondition: first.and(second).and(third). The chain is split
// at every .and( and .or( outside brackets and quotes. Each operand is stripped
// of the brackets that enclose it whole, since the stand brackets the first
// operand of a chain and not the others, and is canonicalized in turn. When
// every call in the chain is the same method the operands are sorted, and a
// chain that mixes the two keeps its order; either way the chain is written
// back with its methods. Text with no such call keeps its text, with every
// bracketed group inside it canonicalized; a group holding a comma list, the
// arguments of an in call, has its elements sorted.
func canonicalMethodChain(expr string) string {
	operands, methods := splitMethodChain(expr)
	if len(operands) < 2 {
		return rewriteBracketGroups(expr, func(inner string) string {
			return canonicalInfix(strings.TrimSpace(inner), methodArgumentSeparators)
		})
	}
	for i := range operands {
		operands[i] = canonicalMethodChain(stripEnclosingBrackets(strings.TrimSpace(operands[i])))
	}
	sameMethod := true
	for _, method := range methods[1:] {
		sameMethod = sameMethod && method == methods[0]
	}
	if sameMethod {
		sort.Strings(operands)
	}
	var out strings.Builder
	out.WriteString(operands[0])
	for i, method := range methods {
		out.WriteString("." + method + "(" + operands[i+1] + ")")
	}
	return out.String()
}

// stripEnclosingBrackets removes one pair of round brackets that encloses the
// whole of expr, and repeats until none does. Brackets inside quotes do not
// count.
func stripEnclosingBrackets(expr string) string {
	for strings.HasPrefix(expr, "(") {
		depth := 0
		var quote byte
		closesAt := -1
		for i := 0; i < len(expr) && closesAt < 0; i++ {
			c := expr[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '(' || c == '[' || c == '{':
				depth++
			case c == ')' || c == ']' || c == '}':
				depth--
				if depth == 0 {
					closesAt = i
				}
			}
		}
		if closesAt != len(expr)-1 {
			return expr
		}
		expr = strings.TrimSpace(expr[1:closesAt])
	}
	return expr
}

// splitMethodChain splits expr at every .and( and .or( outside brackets and
// quotes into the operands of the chain, with the closing bracket of each call
// removed, and returns beside them the method of each call, one fewer than the
// operands. Text with no such call returns no operands.
func splitMethodChain(expr string) (operands, methods []string) {
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && c == '.':
			for _, name := range []string{"and", "or"} {
				call := "." + name + "("
				if !strings.HasPrefix(expr[i:], call) {
					continue
				}
				operand := expr[start:i]
				if len(operands) > 0 {
					operand = strings.TrimSuffix(operand, ")")
				}
				operands = append(operands, operand)
				methods = append(methods, name)
				start = i + len(call)
				i += len(call) - 1
				depth++
				break
			}
		}
	}
	if len(operands) == 0 {
		return nil, nil
	}
	operands = append(operands, strings.TrimSuffix(expr[start:], ")"))
	return operands, methods
}

// splitOutsideBrackets splits expr at every occurrence of sep that is outside
// brackets and quotes. A sep that never occurs there yields one part.
func splitOutsideBrackets(expr, sep string) []string {
	var parts []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && strings.HasPrefix(expr[i:], sep):
			parts = append(parts, expr[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, expr[start:])
}

// rewriteBracketGroups replaces the text inside every outermost bracket group of
// expr, ( ), [ ], or { }, with rewrite of that text, and keeps everything outside
// the groups as it is. Brackets inside quotes do not open a group.
func rewriteBracketGroups(expr string, rewrite func(string) string) string {
	var out strings.Builder
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			if depth == 0 {
				out.WriteString(expr[start : i+1])
				start = i + 1
			}
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
			if depth == 0 {
				out.WriteString(rewrite(expr[start:i]))
				start = i
			}
		}
	}
	out.WriteString(expr[start:])
	return out.String()
}

// canonicalJSON rewrites a customFilterCondition into compact JSON with every
// array sorted by the JSON text of its elements, at every depth. The golden is
// written with indentation and the stand answers compact, so the two never
// compare equal as bytes; and the apply array of a logic node lists its
// operands in the same unstable order as the text dialects. Text that is not
// JSON, and a null or absent value, are returned as they are.
func canonicalJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return raw
	}
	compact, err := json.Marshal(sortJSONArrays(v))
	if err != nil {
		return raw
	}
	return compact
}

func sortJSONArrays(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			typed[key] = sortJSONArrays(value)
		}
		return typed
	case []any:
		return sortByJSONText(typed, sortJSONArrays)
	default:
		return v
	}
}
