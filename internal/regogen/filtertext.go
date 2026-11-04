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
	"encoding/json"
	"regexp"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
)

// fexpr is a predicate expression of the answer: a rule's predicate (leaf),
// its negation (not), an OR or an AND of parts, a group of groups (grp),
// which renders as groups joined by OR in their own parentheses.
type fexpr struct {
	kind  string
	term  *fterm
	parts []*fexpr
}

// fterm is the predicate of one rule with its placeholders substituted.
type fterm struct {
	// key names the rule in customFilterCondition.
	key string
	// text is the substituted template of each dialect it has; template the
	// template as written, and subst the text each placeholder became, which
	// the negation of an RSQL template reads.
	text, template map[policyir.Dialect]string
	subst          map[policyir.Dialect]map[string]string
	custom         *customTerm
}

// customTerm is a customPredicate with its parameters resolved.
type customTerm struct {
	Predicate string
	// Params holds each parameter's JSON value by name.
	Params map[string]jsonvalue.Value
}

func hasPredicate(p policyir.Predicates) bool { return len(p.Text) > 0 || p.Custom != nil }

// orOf is the OR of terms, the term alone where there is one.
func orOf(terms []*fexpr) *fexpr {
	if len(terms) == 1 {
		return terms[0]
	}
	return &fexpr{kind: "or", parts: terms}
}

// key identifies x by its structure and its predicates.
func (x *fexpr) key() string {
	if x.kind == "leaf" {
		return "leaf:" + x.term.key + "\x00" + jsonText(x.term.textObject())
	}
	parts := make([]string, len(x.parts))
	for i, p := range x.parts {
		parts[i] = p.key()
	}
	return x.kind + "(" + strings.Join(parts, "\x01") + ")"
}

func (t *fterm) textObject() *jsonvalue.Object {
	o := jsonvalue.NewObject()
	for _, d := range sortedKeys(t.text) {
		o.Set(string(d), t.text[d])
	}
	return o
}

// distinct returns xs without the repeats of an expression.
func distinct(xs []*fexpr) []*fexpr {
	seen := map[string]bool{}
	var out []*fexpr
	for _, x := range xs {
		if k := x.key(); !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}

// andOf is the AND of parts, an AND among them spliced into it, a part that
// repeats another dropped, and an OR dropped where one of its operands is
// another part: x AND (x OR y) is x.
func andOf(parts []*fexpr) *fexpr {
	var flat []*fexpr
	for _, p := range parts {
		if p.kind == "and" {
			flat = append(flat, p.parts...)
		} else {
			flat = append(flat, p)
		}
	}
	flat = distinct(flat)
	keys := map[string]bool{}
	for _, p := range flat {
		keys[bare(p).key()] = true
	}
	var kept []*fexpr
	for _, p := range flat {
		if !absorbed(bare(p), keys) {
			kept = append(kept, p)
		}
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return &fexpr{kind: "and", parts: kept}
}

// bare is x without the OR of one operand that keeps a predicate in its
// parentheses.
func bare(x *fexpr) *fexpr {
	for x.kind == "or" && len(x.parts) == 1 {
		x = x.parts[0]
	}
	return x
}

// absorbed reports whether x is an OR or a group with an operand whose key is
// in keys.
func absorbed(x *fexpr, keys map[string]bool) bool {
	if x.kind != "or" && x.kind != "grp" {
		return false
	}
	for _, p := range x.parts {
		if keys[bare(p).key()] {
			return true
		}
	}
	return false
}

// negate is the negation of x by De Morgan, down to its predicates.
func negate(x *fexpr) *fexpr {
	switch x.kind {
	case "leaf":
		return &fexpr{kind: "not", parts: []*fexpr{x}}
	case "not":
		return x.parts[0]
	case "and":
		parts := make([]*fexpr, len(x.parts))
		for i, p := range x.parts {
			parts[i] = negate(p)
		}
		return &fexpr{kind: "or", parts: parts}
	}
	// or, grp
	parts := make([]*fexpr, len(x.parts))
	for i, p := range x.parts {
		parts[i] = negate(p)
	}
	return andOf(parts)
}

// The fields of the answer per dialect.
var filterFields = []struct {
	d     policyir.Dialect
	field string
}{
	{policyir.DialectQueryDSL, "filterCondition"},
	{policyir.DialectMongoDB, "mongodbFilterCondition"},
	{policyir.DialectRSQL, "rsqlFilterCondition"},
	{policyir.DialectSQL, "sqlFilterCondition"},
}

// render returns the text of x in dialect d, and false where x has none: an
// OR keeps the parts that have the dialect, which only drops rows, and an AND
// needs every part, since an operand left out would add rows the others
// exclude.
func render(x *fexpr, d policyir.Dialect) (string, bool) {
	switch x.kind {
	case "grp":
		var texts []string
		for _, g := range x.parts {
			if t, ok := render(g, d); ok {
				texts = append(texts, t)
			}
		}
		return joinGroups(texts, d)
	case "leaf":
		t, ok := x.term.text[d]
		if !ok {
			return "", false
		}
		if d == policyir.DialectMongoDB {
			if strings.Contains(x.term.template[d], "${") {
				return "{ " + t + " }", true
			}
			return "{" + t + "}", true
		}
		return t, true
	case "not":
		leaf := x.parts[0]
		inner, ok := render(leaf, d)
		if !ok {
			return "", false
		}
		switch d {
		case policyir.DialectRSQL:
			return negateRSQLTerm(leaf.term)
		case policyir.DialectSQL:
			return "NOT (" + inner + ")", true
		case policyir.DialectQueryDSL:
			return "(" + inner + ").not()", true
		}
		return negateMongo(leaf.term.text[d], inner), true
	}
	type part struct {
		x    *fexpr
		text string
	}
	var parts []part
	for _, p := range x.parts {
		t, ok := render(p, d)
		if !ok {
			if x.kind == "and" {
				return "", false
			}
			continue
		}
		parts = append(parts, part{p, t})
	}
	switch len(parts) {
	case 0:
		return "", false
	case 1:
		return parts[0].text, true
	}
	texts := make([]string, len(parts))
	for i, p := range parts {
		texts[i] = p.text
	}
	switch d {
	case policyir.DialectRSQL, policyir.DialectSQL:
		sep := map[bool]string{true: ",", false: ";"}[x.kind == "or"]
		if d == policyir.DialectSQL {
			sep = map[bool]string{true: " OR ", false: " AND "}[x.kind == "or"]
		}
		for i, p := range parts {
			if (p.x.kind == "or" || p.x.kind == "and" || p.x.kind == "grp") && p.x.kind != x.kind {
				texts[i] = "(" + texts[i] + ")"
			}
		}
		return strings.Join(texts, sep), true
	case policyir.DialectQueryDSL:
		m := map[bool]string{true: ".or(", false: ".and("}[x.kind == "or"]
		acc := "(" + texts[0] + ")"
		for _, t := range texts[1:] {
			acc += m + t + ")"
		}
		return acc, true
	}
	return `{ "$` + x.kind + `": [ ` + strings.Join(texts, ", ") + " ] }", true
}

// joinGroups joins the texts of groups by OR, each in its own parentheses,
// and returns false for none.
func joinGroups(texts []string, d policyir.Dialect) (string, bool) {
	switch len(texts) {
	case 0:
		return "", false
	case 1:
		return texts[0], true
	}
	switch d {
	case policyir.DialectRSQL:
		return "(" + strings.Join(texts, "),(") + ")", true
	case policyir.DialectSQL:
		return "(" + strings.Join(texts, ") or (") + ")", true
	case policyir.DialectQueryDSL:
		acc := "(" + texts[0] + ")"
		for _, t := range texts[1:] {
			acc += ".or(" + t + ")"
		}
		return acc, true
	}
	return `{ "$or": [ ` + strings.Join(texts, ",") + " ] }", true
}

// negateRSQLTerm is the RSQL text of the negation of t: its template
// negated, and then each placeholder replaced by the text it became, so that
// a value goes into the negation as it went into the predicate. It returns
// false where the template has no negation.
func negateRSQLTerm(t *fterm) (string, bool) {
	neg, ok := negateRSQL(t.template[policyir.DialectRSQL])
	if !ok {
		return "", false
	}
	subst := t.subst[policyir.DialectRSQL]
	return placeholderRE.ReplaceAllStringFunc(neg, func(m string) string {
		if v, ok := subst[m[2:len(m)-1]]; ok {
			return v
		}
		return m
	}), true
}

// mongoOps maps each MongoDB operator to its opposite.
var mongoOps = map[string]string{"$eq": "$ne", "$ne": "$eq", "$in": "$nin", "$nin": "$in", "$lt": "$gte",
	"$gte": "$lt", "$gt": "$lte", "$lte": "$gt", "$and": "$or", "$or": "$and"}

var mongoOpRE = regexp.MustCompile(`"(\$[a-z]+)"`)

// negateMongo is the MongoDB text of the negation of the rendered predicate
// s, whose predicate text is t: s with each operator replaced by its opposite
// where that negates t, and { "$nor": [ s ] } where it does not, such as for
// a field matched by a bare value, a field with two operators, or an
// operator without an opposite. The braces render puts around t make s
// itself no JSON, so the test reads t.
func negateMongo(t, s string) string {
	if v, err := jsonvalue.Decode([]byte(t)); err == nil && mongoInvertible(v) {
		return mongoOpRE.ReplaceAllStringFunc(s, func(m string) string {
			if op, ok := mongoOps[m[1:len(m)-1]]; ok {
				return `"` + op + `"`
			}
			return m
		})
	}
	return `{ "$nor": [ ` + s + " ] }"
}

// mongoInvertible reports whether swapping each operator of the filter
// document v for its opposite negates it: v names one field, or is one $and
// or $or of such documents, and the field holds one operator that has an
// opposite.
func mongoInvertible(v jsonvalue.Value) bool {
	o, ok := v.(*jsonvalue.Object)
	if !ok || o.Len() != 1 {
		return false
	}
	k := o.Keys()[0]
	x, _ := o.Get(k)
	if k == "$and" || k == "$or" {
		l, ok := x.([]jsonvalue.Value)
		if !ok || len(l) == 0 {
			return false
		}
		for _, e := range l {
			if !mongoInvertible(e) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(k, "$") {
		return false
	}
	f, ok := x.(*jsonvalue.Object)
	if !ok || f.Len() != 1 {
		return false
	}
	_, ok = mongoOps[f.Keys()[0]]
	if !ok || f.Keys()[0] == "$and" || f.Keys()[0] == "$or" {
		return false
	}
	// an operator inside the value would be swapped too
	y, _ := f.Get(f.Keys()[0])
	return !strings.Contains(jsonText(y), `"$`) || onlyUUIDs(y)
}

// onlyUUIDs reports whether v, an operand of a field's operator, holds no
// operator but $uuid, which names a value.
func onlyUUIDs(v jsonvalue.Value) bool {
	switch x := v.(type) {
	case *jsonvalue.Object:
		for _, k := range x.Keys() {
			if k != "$uuid" {
				return false
			}
		}
	case []jsonvalue.Value:
		for _, e := range x {
			if !onlyUUIDs(e) {
				return false
			}
		}
	}
	return true
}

// FilterAnswer is the answer of check/filter. Text holds the text of each
// dialect a predicate of the answer has; Custom is customFilterCondition,
// nil for none.
type FilterAnswer struct {
	Result string
	Text   map[policyir.Dialect]string
	Custom *jsonvalue.Object
}

// The values of [FilterAnswer.Result].
const (
	FilterAllow     = "ALLOW"
	FilterDeny      = "DENY"
	FilterCondition = "USE_FILTER_CONDITION"
)

// MarshalJSON writes the answer as legacy does: each field of a dialect
// without a predicate is null.
func (a FilterAnswer) MarshalJSON() ([]byte, error) {
	o := jsonvalue.NewObject()
	o.Set("calculationResult", a.Result)
	for _, f := range filterFields {
		if t, ok := a.Text[f.d]; ok {
			o.Set(f.field, t)
		} else {
			o.Set(f.field, nil)
		}
	}
	if a.Custom != nil {
		o.Set("customFilterCondition", a.Custom)
	} else {
		o.Set("customFilterCondition", nil)
	}
	return []byte(jsonText(o)), nil
}

var _ json.Marshaler = FilterAnswer{}

// filterAnswer is the answer whose allowed rows are a.
func filterAnswer(a rows) FilterAnswer {
	switch a.kind {
	case rowsAll:
		return FilterAnswer{Result: FilterAllow}
	case rowsSome:
	default:
		return FilterAnswer{Result: FilterDeny}
	}
	out := FilterAnswer{Result: FilterCondition, Text: map[policyir.Dialect]string{}}
	for _, f := range filterFields {
		var texts []string
		for _, g := range a.groups {
			if t, ok := render(g, f.d); ok {
				texts = append(texts, t)
			}
		}
		if t, ok := joinGroups(texts, f.d); ok {
			out.Text[f.d] = t
		}
	}
	var logic []jsonvalue.Value
	data := jsonvalue.NewObject()
	for _, g := range a.groups {
		if l := renderCustom(g); l != nil {
			logic = append(logic, l)
		}
		collectCustom(g, data)
	}
	switch len(logic) {
	case 0:
	case 1:
		out.Custom = customObject(logic[0], data)
	default:
		out.Custom = customObject(opObject("OR", logic), data)
	}
	if len(out.Text) == 0 && out.Custom == nil {
		// every group needs a subtraction no dialect can write
		return FilterAnswer{Result: FilterDeny}
	}
	return out
}

func customObject(logic jsonvalue.Value, data *jsonvalue.Object) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set("logic", logic)
	o.Set("data", data)
	return o
}

func opObject(op string, apply []jsonvalue.Value) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set("op", op)
	o.Set("apply", apply)
	return o
}

// renderCustom is the logic of customFilterCondition over x, nil where x
// has none: as in render, an AND needs every part and an OR keeps the parts
// that have one.
func renderCustom(x *fexpr) jsonvalue.Value {
	switch x.kind {
	case "leaf":
		if x.term.custom == nil {
			return nil
		}
		o := jsonvalue.NewObject()
		o.Set("path", x.term.key)
		return o
	case "not":
		inner := renderCustom(x.parts[0])
		if inner == nil {
			return nil
		}
		return opObject("NOT", []jsonvalue.Value{inner})
	}
	var parts []jsonvalue.Value
	for _, p := range x.parts {
		l := renderCustom(p)
		if l == nil {
			if x.kind == "and" {
				return nil
			}
			continue
		}
		parts = append(parts, l)
	}
	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	}
	op := "OR"
	if x.kind == "and" {
		op = "AND"
	}
	return opObject(op, parts)
}

func collectCustom(x *fexpr, data *jsonvalue.Object) {
	if x.kind == "leaf" {
		if c := x.term.custom; c != nil {
			o := jsonvalue.NewObject()
			o.Set("predicate", c.Predicate)
			params := jsonvalue.NewObject()
			for _, k := range sortedKeys(c.Params) {
				params.Set(k, c.Params[k])
			}
			o.Set("params", params)
			data.Set(x.term.key, o)
		}
		return
	}
	for _, p := range x.parts {
		collectCustom(p, data)
	}
}
