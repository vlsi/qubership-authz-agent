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
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Dump returns the tree as text, one node per line, indented by depth: the PIP
// declarations, then the simplified groups, then the sets, each in tree order.
// Equal trees give equal text: map keys are sorted, dialects follow
// [Dialects], and strings are Go-quoted. An absent condition, iterate,
// predicate, or optional PIP field prints no text, and an absent algorithm or
// effect prints as "absent". The text is meant for golden files of the
// generator, and no parser reads it back.
func (t *Tree) Dump() string {
	var b strings.Builder
	line := func(depth int, format string, args ...any) {
		b.WriteString(strings.Repeat("  ", depth))
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	for _, p := range t.PIPs {
		line(0, "pip %q%s", p.Name, pipFields(p))
	}
	for _, g := range t.Simplified {
		line(0, "simplified %q name=%q domain=%q component=%q resourceType=%q%s", g.ID, g.Name, g.Domain, g.Component,
			g.ResourceType, externalID(g.ExternalID))
		for _, p := range g.Policies {
			line(1, "policy %q operation=%q roles=%s%s", p.ID, p.Operation, quoteAll(p.Roles), frontend(p.Frontend))
			dumpCondition(line, 2, "condition", p.Condition)
			dumpPredicates(line, 2, p.Predicates)
		}
	}
	var set func(depth int, s *PolicySet)
	set = func(depth int, s *PolicySet) {
		line(depth, "set %q name=%q domain=%q algorithm=%s%s", s.ID, s.Name, s.Domain, algorithm(s.Algorithm),
			externalID(s.ExternalID))
		if s.AlwaysFails != "" {
			line(depth+1, "always fails: %q", s.AlwaysFails)
		}
		if s.Isolated != "" {
			line(depth+1, "isolated: %q", s.Isolated)
		}
		dumpCondition(line, depth+1, "target", s.Target)
		if s.Iterate != nil {
			line(depth+1, "iterate var=%q algorithm=%s", s.Iterate.Var, s.Iterate.Algorithm)
		}
		for _, p := range s.Policies {
			line(depth+1, "policy %q name=%q algorithm=%s", p.ID, p.Name, algorithm(p.Algorithm))
			dumpCondition(line, depth+2, "target", p.Target)
			for _, r := range p.Rules {
				effect := string(r.Effect)
				if r.Effect == EffectAbsent {
					effect = "absent"
				}
				line(depth+2, "rule %q name=%q effect=%s%s", r.ID, r.Name, effect, frontend(r.Frontend))
				dumpCondition(line, depth+3, "target", r.Target)
				dumpCondition(line, depth+3, "condition", r.Condition)
				dumpPredicates(line, depth+3, r.Predicates)
			}
		}
		for _, c := range s.Sets {
			set(depth+1, c)
		}
	}
	for _, s := range t.Sets {
		set(0, s)
	}
	return b.String()
}

func externalID(id string) string {
	if id == "" {
		return ""
	}
	return fmt.Sprintf(" externalId=%q", id)
}

func frontend(f bool) string {
	if f {
		return " frontend"
	}
	return ""
}

func algorithm(a Algorithm) string {
	if a == AlgorithmAbsent {
		return "absent"
	}
	return string(a)
}

func pipFields(p *PIP) string {
	if p.Isolated != "" {
		return fmt.Sprintf(" isolated=%q", p.Isolated)
	}
	var b strings.Builder
	str := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, " %s=%q", k, v)
		}
	}
	raw := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	fmt.Fprintf(&b, " type=%s", p.Type)
	str("claim", p.Claim)
	str("header", p.Header)
	raw("defaultValue", p.DefaultValue)
	str("url", p.URL)
	str("httpMethod", p.HTTPMethod)
	str("beanName", p.BeanName)
	str("jsonPath", p.JSONPath)
	str("returnType", p.ReturnType)
	str("headers", p.Headers)
	str("resourceType", p.ResourceType)
	str("domain", p.Domain)
	if len(p.RequestAttributes) > 0 {
		fmt.Fprintf(&b, " requestAttributes=%s", sortedMap(p.RequestAttributes))
	}
	raw("productMapping", p.ProductMapping)
	raw("customMapping", p.CustomMapping)
	raw("cacheable", p.Cacheable)
	raw("cachePeriod", p.CachePeriod)
	str("unsupported", p.Unsupported)
	return b.String()
}

func dumpPredicates(line func(int, string, ...any), depth int, p Predicates) {
	for _, d := range dialects {
		if text, ok := p.Text[d]; ok {
			line(depth, "predicate %s %q", d, text)
		}
	}
	if p.Custom != nil {
		line(depth, "customPredicate %q params=%s", p.Custom.Predicate, sortedMap(p.Custom.Params))
	}
}

func dumpCondition(line func(int, string, ...any), depth int, label string, c *Condition) {
	if c == nil {
		return
	}
	line(depth, "%s[%s]: %s", label, c.Place, FormatCondition(c))
}

// FormatCondition returns the condition as one line: atoms joined by AND,
// disjuncts by OR, operators in their [Operator] spelling, and operands as
// [FormatOperand] prints them. Since the language has no parentheses, the
// line is unambiguous without them.
func FormatCondition(c *Condition) string {
	ors := make([]string, len(c.Disjuncts))
	for i, d := range c.Disjuncts {
		ands := make([]string, len(d))
		for j, a := range d {
			ands[j] = formatAtom(a)
		}
		ors[i] = strings.Join(ands, " AND ")
	}
	return strings.Join(ors, " OR ")
}

func formatAtom(a Atom) string {
	switch v := a.(type) {
	case Const:
		return strings.ToUpper(strconv.FormatBool(v.Value))
	case IsM2M:
		return "subject.isM2M"
	case Access:
		verb := "allowed"
		if v.Denied {
			verb = "denied"
		}
		return fmt.Sprintf("subject %s %q on resource", verb, v.Operation)
	case Compare:
		if v.Right == nil {
			return FormatOperand(v.Left) + " " + string(v.Op)
		}
		return FormatOperand(v.Left) + " " + string(v.Op) + " " + FormatOperand(v.Right)
	case Unsupported:
		return formatUnsupported(v)
	default:
		return fmt.Sprintf("<%T>", a)
	}
}

// FormatOperand returns the operand as the dump prints it. An attribute keeps
// its source spelling, such as resource.a or subject.roles; a literal, a PIP
// name, and a key are Go-quoted, so a literal is told apart from an attribute.
// A resource path with a character outside printable ASCII is Go-quoted too,
// as resource"['a\nb']", so the dump keeps one node per line. A list of
// several items also prints its raw token.
func FormatOperand(o Operand) string {
	switch v := o.(type) {
	case Operation:
		return "operation"
	case ResourceType:
		return "resourceType"
	case Resource:
		path := v.Path
		if v.TrailingDot {
			path += "."
		}
		if strings.ContainsFunc(path, func(r rune) bool { return r < ' ' || r > '~' }) {
			return "resource" + strconv.Quote(path)
		}
		return "resource" + path
	case Subject:
		if v.Key != "" {
			return fmt.Sprintf("subject.%s[%q]", v.Attr, v.Key)
		}
		return "subject." + string(v.Attr)
	case PIPRef:
		s := fmt.Sprintf("pip(%q)", v.Name)
		if v.Filtered {
			s += fmt.Sprintf(" FILTERED %q", v.FilteredOperation)
		}
		return s
	case Entitled:
		return fmt.Sprintf("subject.entitledResources.of(%q).as%s", v.ResourceType, quoteAll(v.As))
	case PassValue:
		if v.Key != "" {
			return fmt.Sprintf("pass(%q)[%q]", v.Var, v.Key)
		}
		return fmt.Sprintf("pass(%q)", v.Var)
	case String:
		return strconv.Quote(v.Value)
	case Number:
		return v.Text
	case Bool:
		return strconv.FormatBool(v.Value)
	case List:
		items := make([]string, len(v.Items))
		for i, it := range v.Items {
			items[i] = FormatOperand(it)
		}
		s := "[" + strings.Join(items, ", ") + "]"
		if v.Raw != "" {
			s += fmt.Sprintf(" raw=%q", v.Raw)
		}
		return s
	case Pattern:
		return fmt.Sprintf("pattern(%q)", v.Text)
	case Unsupported:
		return formatUnsupported(v)
	default:
		return fmt.Sprintf("<%T>", o)
	}
}

func formatUnsupported(u Unsupported) string {
	return fmt.Sprintf("unsupported(%s %q)", u.Form, u.Text)
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func sortedMap(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = strconv.Quote(k) + ": " + m[k]
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
