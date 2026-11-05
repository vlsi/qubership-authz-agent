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
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"authz-agent/internal/policyir"
)

// The checks in this file refuse uploads that access-control refuses with
// 400, so that a test seeding the stub cannot load a declaration no
// access-control installation would hold. They are a subset of
// access-control's checks: an upload they accept may still be one
// access-control refuses.

// pipNamePattern is the PIP name access-control accepts: subject. followed by
// one or more dot-separated attributes, each a letter or an underscore
// followed by letters, digits, and underscores.
var pipNamePattern = regexp.MustCompile(`^subject\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// fieldShape is the JSON shape access-control binds a field to.
type fieldShape int

const (
	// scalar is a text, number, or boolean field, which access-control
	// refuses to bind an array or an object to.
	scalar fieldShape = iota
	// object is a field that holds a JSON object.
	object
)

// pipFields lists the PIP fields the stub checks, with the shape of each.
// headers is a scalar: the comma-separated names of the incoming headers a
// GENERAL or FILTERED PIP forwards, as one text.
var pipFields = []struct {
	name  string
	shape fieldShape
}{
	{"name", scalar}, {"pipType", scalar}, {"type", scalar}, {"description", scalar}, {"url", scalar},
	{"beanName", scalar}, {"cacheable", scalar}, {"jsonPath", scalar}, {"httpMethod", scalar},
	{"header", scalar}, {"claim", scalar}, {"defaultValue", scalar}, {"cachePeriod", scalar},
	{"resourceType", scalar}, {"deprecated", scalar}, {"headers", scalar},
	{"requestAttributes", object}, {"productMapping", object}, {"customMapping", object},
}

// validatePIPs returns the reason access-control refuses the PIP upload raw,
// or "" when none of the stub's checks refuses it. items is raw decoded.
func validatePIPs(raw []byte, items []simplifiedPIP) string {
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err.Error()
	}
	for i, item := range fields {
		for _, f := range pipFields {
			if why := checkShape(item[f.name], f.shape); why != "" {
				return fmt.Sprintf("PIP %d: field %s %s", i, f.name, why)
			}
		}
		if name := items[i].Name; !pipNamePattern.MatchString(name) {
			return fmt.Sprintf("PIP %d: name %q is not subject.<attribute>, where each dot-separated attribute "+
				"starts with a letter or an underscore and holds only letters, digits, and underscores", i, name)
		}
	}
	return ""
}

// validatePolicies returns the reason access-control refuses the simplified
// policy upload items, or "" when none of the stub's checks refuses it.
func validatePolicies(items []simplifiedPolicy) string {
	for i, p := range items {
		if why := conditionRefusal(p.Condition); why != "" {
			return fmt.Sprintf("policy %d (%s %s %s): %s", i, p.Component, p.ResourceType, p.Operation, why)
		}
	}
	return ""
}

// conditionRefusal returns why access-control refuses the condition of a
// simplified policy, or "". An absent or null condition and a boolean are
// accepted; a boolean binds as its text. Any other value that is not a text
// is refused, as are the empty text and a text the condition parser refuses.
func conditionRefusal(condition any) string {
	switch c := condition.(type) {
	case nil, bool:
		return ""
	case string:
		if c == "" {
			return "condition is empty"
		}
		// access-control removes the characters up to U+0020 around the
		// text before it parses it, as Java's String.trim does, and parses
		// a text that is blank throughout as it is.
		if trimmed := strings.TrimFunc(c, func(r rune) bool { return r <= ' ' }); trimmed != "" {
			c = trimmed
		}
		if _, err := policyir.ParseCondition(c, policyir.PlaceSimplified, ""); err != nil {
			return "condition does not parse: " + err.Error()
		}
		return ""
	default:
		return "condition is a JSON number, array, or object, want a text"
	}
}

// checkShape returns why the JSON value v does not have shape, or "". An
// absent field and null are accepted.
func checkShape(v json.RawMessage, shape fieldShape) string {
	v = bytes.TrimSpace(v)
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	switch shape {
	case scalar:
		if v[0] == '[' || v[0] == '{' {
			return "is a JSON array or object, want a text, a number, or a boolean"
		}
	case object:
		if v[0] != '{' {
			return "is not a JSON object"
		}
	}
	return ""
}
