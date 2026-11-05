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

package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"authz-agent/internal/policyir"
)

// conditionRefusal returns why access-control refuses the condition of a
// simplified policy, or "". declared holds the names of the PIPs the tenant
// declared; a nil declared skips the checks that read it. An absent or null
// condition and a boolean are accepted; a boolean binds as its text. The text
// is cut of the characters up to U+0020 around it, unless it is blank
// throughout, and then has to pass every check of [conditionTextRefusal].
func conditionRefusal(condition any, declared map[string]bool) string {
	var text string
	switch c := condition.(type) {
	case nil:
		return ""
	case bool:
		text = jsonText(c)
	case string:
		if c == "" {
			return "condition is empty"
		}
		text = c
		if trimmed := javaTrim(c); trimmed != "" {
			text = trimmed
		}
	default:
		return "condition is a JSON number, array, or object, want a text"
	}
	if why := conditionTextRefusal(text, declared); why != "" {
		return fmt.Sprintf("condition %q: %s", text, why)
	}
	return ""
}

// conditionTextRefusal returns why access-control refuses the condition text,
// or "". The agent's parser accepts more than access-control stores, so the
// checks after the parse refuse the operands an operator may not take, true
// or false beside a connective, a boolean in a list, and the subject
// attributes a simplified policy may not read.
func conditionTextRefusal(text string, declared map[string]bool) string {
	switch strings.ToLower(text) {
	case "true", "false":
		if !slices.Contains([]string{"true", "TRUE", "false", "FALSE"}, text) {
			return "a whole-condition boolean is written true, TRUE, false, or FALSE"
		}
	}
	c, err := policyir.ParseCondition(text, policyir.PlaceSimplified, "")
	if err != nil {
		return "does not parse: " + err.Error()
	}
	if why := splitTokenRefusal(text); why != "" {
		return why
	}
	var atoms []policyir.Atom
	for _, d := range c.Disjuncts {
		atoms = append(atoms, d...)
	}
	for _, a := range atoms {
		if _, ok := a.(policyir.Const); ok && len(atoms) > 1 {
			return "true or false stands only as the whole condition, not beside AND or OR"
		}
	}
	for _, a := range atoms {
		cmp, ok := a.(policyir.Compare)
		if !ok {
			continue
		}
		if why := operandKindRefusal(cmp); why != "" {
			return why
		}
		if why := booleanListRefusal(cmp); why != "" {
			return why
		}
	}
	for _, a := range atoms {
		cmp, ok := a.(policyir.Compare)
		if !ok {
			continue
		}
		for _, o := range []policyir.Operand{cmp.Left, cmp.Right} {
			if why := operandRefusal(o, declared); why != "" {
				return why
			}
		}
	}
	return ""
}

// splitTokenRefusal returns why access-control refuses text for a tab, a line
// feed, or a carriage return inside an operator of several words or inside a
// list, or "". The agent's parser takes them as spaces there; access-control
// takes only spaces, and a tab or a line break only between two tokens.
func splitTokenRefusal(text string) string {
	masked := quotedPattern.ReplaceAllString(text, "''")
	for _, re := range splitOperatorPatterns {
		if m := re.FindString(masked); m != "" {
			return fmt.Sprintf("operator %q holds a tab or a line break between its words", m)
		}
	}
	if splitListPattern.MatchString(masked) {
		return "a list holds a tab or a line break around a comma"
	}
	return ""
}

var (
	quotedPattern         = regexp.MustCompile(`'[^']*'`)
	splitOperatorPatterns = func() []*regexp.Regexp {
		var out []*regexp.Regexp
		for _, pair := range [][2]string{
			{"GREATER", "THAN"}, {"LESS", "THAN"}, {"THAN", "OR"}, {"OR", "EQUAL"}, {"EQUAL", "TO"},
			{"IS", "NOT"}, {"IS", "NULL"}, {"NOT", "NULL"}, {"IS", "EMPTY"}, {"NOT", "EMPTY"},
			{"IS", "SUBSET"}, {"NOT", "SUBSET"}, {"NOT", "CONTAINS"}, {"CONTAINS", "ANY"},
			{"NOT", "IN"}, {"NOT", "MATCH"}, {"NOT", "EQUALS"},
		} {
			out = append(out, regexp.MustCompile(`\b`+pair[0]+`[ \t\n\r]*[\t\n\r][ \t\n\r]*`+pair[1]+`\b`))
		}
		return out
	}()
	splitListPattern = regexp.MustCompile(`,[ \t\n\r]*[\t\n\r]|[\t\n\r][ \t\n\r]*,`)
)

// The operand kinds of [operandKind], grouped by where an operator takes
// them.
var (
	singleSubjectKinds = []string{"subject.id", "subject.name", "subject.type", "subject.serviceAccount"}
	multiSubjectKinds  = []string{"subject.roles", "subject.scopes", "subject.permissions", "entitledResources"}
	eqLeftKinds        = concat(singleSubjectKinds, []string{"attribute", "resourceType", "resource", "operation", "pip"})
	singleKinds        = concat(singleSubjectKinds, []string{
		"pip", "attribute", "string", "number", "boolean", "operation", "resourceType", "resource",
	})
	multiKinds = concat(multiSubjectKinds, []string{"subject.permissionScope", "pip", "attribute"})
	arithKinds = []string{"attribute", "resource", "number"}
	listKinds  = []string{"string list", "number list"}
)

func concat(a, b []string) []string { return append(slices.Clone(a), b...) }

// operandKindRefusal returns why access-control refuses the operands of cmp
// for its operator, or "".
func operandKindRefusal(cmp policyir.Compare) string {
	l, r := operandKind(cmp.Left), operandKind(cmp.Right)
	// A list of one literal also stands where a single literal does.
	r1 := r
	if list, ok := cmp.Right.(policyir.List); ok && len(list.Items) == 1 {
		r1 = map[string]string{"string list": "string", "number list": "number"}[r]
	}
	in := slices.Contains[[]string]
	var ok bool
	switch cmp.Op {
	case policyir.OpEQ, policyir.OpNE:
		ok = in(eqLeftKinds, l) && in(singleKinds, r) || in(singleKinds, l) && in(eqLeftKinds, r)
	case policyir.OpLT, policyir.OpLE, policyir.OpGT, policyir.OpGE:
		ok = in(arithKinds, l) && in(arithKinds, r) || in(singleKinds, l) && in(singleKinds, r)
	case policyir.OpIsNull, policyir.OpIsNotNull:
		ok = in(singleKinds, l) || l == "subject.permissionScope"
	case policyir.OpIsEmpty, policyir.OpIsNotEmpty:
		ok = in(multiKinds, l)
	case policyir.OpContains, policyir.OpNotContains:
		ok = in(multiKinds, l) && (in(singleKinds, r) || in(singleKinds, r1))
	case policyir.OpContainsAny, policyir.OpNotContainsAny, policyir.OpIsSubset, policyir.OpIsNotSubset:
		ok = in(multiKinds, l) && (in(listKinds, r) || in(multiKinds, r))
	case policyir.OpMatch, policyir.OpNotMatch:
		ok = in(eqLeftKinds, l) && (r == "pattern" || r == "attribute")
	case policyir.OpIn, policyir.OpNotIn:
		ok = in(singleKinds, l) && (in(listKinds, r) || in(multiKinds, r))
	default:
		ok = true
	}
	if ok {
		return ""
	}
	if cmp.Op.Unary() {
		return fmt.Sprintf("%s does not take %s", cmp.Op, describeKind(l))
	}
	return fmt.Sprintf("%s does not take %s on the left and %s on the right", cmp.Op, describeKind(l), describeKind(r))
}

// operandKind returns the kind of operand o that decides which operators take
// it.
func operandKind(o policyir.Operand) string {
	switch o := o.(type) {
	case policyir.String:
		return "string"
	case policyir.Number:
		return "number"
	case policyir.Bool:
		return "boolean"
	case policyir.List:
		for _, item := range o.Items {
			if _, ok := item.(policyir.Number); !ok {
				return "string list"
			}
		}
		return "number list"
	case policyir.Resource:
		if o.Path == "" {
			return "resource"
		}
		return "attribute"
	case policyir.Unsupported:
		return "attribute"
	case policyir.Subject:
		return "subject." + string(o.Attr)
	case policyir.PIPRef:
		return "pip"
	case policyir.Entitled:
		return "entitledResources"
	case policyir.Operation:
		return "operation"
	case policyir.ResourceType:
		return "resourceType"
	case policyir.Pattern:
		return "pattern"
	}
	return fmt.Sprintf("%T", o)
}

func describeKind(kind string) string {
	switch kind {
	case "attribute":
		return "a resource attribute"
	case "resource":
		return "the whole resource"
	case "pip":
		return "a PIP"
	case "string", "number", "boolean", "string list", "number list", "pattern":
		return "a " + kind
	}
	return kind
}

// booleanListRefusal returns why access-control refuses a boolean on the
// right of cmp, or "": a list operator other than IN takes none.
func booleanListRefusal(cmp policyir.Compare) string {
	list, ok := cmp.Right.(policyir.List)
	if !ok || cmp.Op == policyir.OpIn {
		return ""
	}
	for _, item := range list.Items {
		if _, ok := item.(policyir.Bool); ok {
			return fmt.Sprintf("%s does not take a boolean in its list", cmp.Op)
		}
	}
	return ""
}

// operandRefusal returns why a simplified policy may not read operand o, or
// "". It refuses the operation and a PIP named subject.permissions.<name>.
// Unless declared is nil, it also refuses the permission scope where the
// tenant declares no subject.permissionScope, and a PIP name that no PIP of
// the tenant declares.
func operandRefusal(o policyir.Operand, declared map[string]bool) string {
	switch o := o.(type) {
	case policyir.Operation:
		return "a simplified policy does not read the operation"
	case policyir.Subject:
		if o.Attr == policyir.SubjectPermissionScope && declared != nil && !declared["subject.permissionScope"] {
			return "subject.permissionScope needs a PIP of that name declared in the tenant"
		}
	case policyir.PIPRef:
		switch {
		case strings.HasPrefix(o.Name, "subject.permissions."):
			return fmt.Sprintf("%s: a condition reads subject.permissions only as a whole", o.Name)
		case declared == nil:
		case o.Name == "subject.permissionScope":
			if !declared[o.Name] {
				return "subject.permissionScope needs a PIP of that name declared in the tenant"
			}
		case !declared[o.Name] && pipNamePattern.MatchString(o.Name) && !strings.Contains(o.Name, "-"):
			return fmt.Sprintf("%s is not a PIP of the tenant", o.Name)
		}
	}
	return ""
}
