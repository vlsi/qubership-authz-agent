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
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// The checks in this file and in condition.go refuse the uploads that
// access-control 6.1.6 refuses, with the status it answers, so that a test
// seeding the stub cannot load a declaration no access-control installation
// would hold. They run in the order access-control runs its own, and the
// first one that fails decides the status.

// refusal is the answer to an upload that access-control refuses.
type refusal struct {
	status int
	reason string
}

func badRequest(format string, args ...any) *refusal {
	return &refusal{status: http.StatusBadRequest, reason: fmt.Sprintf(format, args...)}
}

func conflict(format string, args ...any) *refusal {
	return &refusal{status: http.StatusConflict, reason: fmt.Sprintf(format, args...)}
}

// decodeUpload returns the items of an upload body, which is a JSON array of
// objects, with each number kept as a [json.Number]. A null item reads as an
// empty object.
func decodeUpload(raw []byte) ([]map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var items []map[string]any
	if err := dec.Decode(&items); err != nil {
		return nil, err
	}
	for i := range items {
		if items[i] == nil {
			items[i] = map[string]any{}
		}
	}
	return items, nil
}

// coerceTexts returns the upload items as JSON, with a number or a boolean in
// one of the fields named by texts replaced by its text, the way
// access-control binds a scalar to a text field. It returns raw itself when
// no field changes and changed is false; changed reports that the caller
// already changed items.
func coerceTexts(raw []byte, items []map[string]any, texts []string, changed bool) ([]byte, error) {
	for _, item := range items {
		for _, f := range texts {
			switch v := item[f].(type) {
			case json.Number:
				item[f] = v.String()
				changed = true
			case bool:
				item[f] = strconv.FormatBool(v)
				changed = true
			}
		}
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(items)
}

// pipTexts and policyTexts are the text fields of simplifiedPIP and
// simplifiedPolicy.
var (
	pipTexts = []string{
		"name", "pipType", "url", "httpMethod", "header", "claim", "beanName", "domain", "type", "jsonPath",
	}
	policyTexts = []string{
		"component", "resourceType", "operation", "rsqlPredicate", "sqlPredicate", "mongodbPredicate", "predicate",
	}
)

// fieldKind is the type access-control binds a field to.
type fieldKind int

const (
	// text takes a text, a number, or a boolean.
	text fieldKind = iota
	// flag takes a boolean, a number, or true or false as a text in one of
	// the cases true, True, and TRUE, with any characters up to U+0020
	// around it.
	flag
	// integer takes a number, or a text of decimal digits with an optional
	// sign that fits a 64-bit integer.
	integer
	object
	list
)

var (
	pipFieldKinds = map[string]fieldKind{
		"name": text, "pipType": text, "type": text, "description": text, "url": text, "beanName": text,
		"cacheable": flag, "requestAttributes": object, "jsonPath": text, "httpMethod": text, "header": text,
		"claim": text, "defaultValue": text, "cachePeriod": integer, "productMapping": object,
		"customMapping": object, "resourceType": text, "deprecated": flag, "headers": text,
	}
	policyFieldKinds = map[string]fieldKind{
		"component": text, "reason": text, "resourceType": text, "operation": text, "condition": text,
		"rsqlPredicate": text, "predicates": object, "roles": list, "applicableForFrontend": flag, "id": text,
	}
)

// fieldRefusal returns why access-control refuses to bind the fields of item
// to the kinds in kinds, or "". A null field binds to every kind, and a flag
// or an integer also binds a text that is blank up to U+0020, as null.
func fieldRefusal(item map[string]any, kinds map[string]fieldKind) string {
	for _, name := range slices.Sorted(maps.Keys(kinds)) {
		v, ok := item[name]
		if !ok || v == nil {
			continue
		}
		s, isText := v.(string)
		if isText && javaTrim(s) == "" && (kinds[name] == flag || kinds[name] == integer) {
			continue
		}
		switch kinds[name] {
		case text:
			switch v.(type) {
			case string, json.Number, bool:
				continue
			}
			return fmt.Sprintf("field %s is a JSON array or object, want a text", name)
		case flag:
			switch v.(type) {
			case bool, json.Number:
				continue
			}
			if isText && slices.Contains([]string{"true", "True", "TRUE", "false", "False", "FALSE"}, javaTrim(s)) {
				continue
			}
			return fmt.Sprintf("field %s is %s, want a boolean", name, jsonText(v))
		case integer:
			if _, ok := v.(json.Number); ok {
				continue
			}
			if isText && longPattern.MatchString(s) {
				if _, err := strconv.ParseInt(s, 10, 64); err == nil {
					continue
				}
			}
			return fmt.Sprintf("field %s is %s, want an integer", name, jsonText(v))
		case object:
			if _, ok := v.(map[string]any); !ok {
				return fmt.Sprintf("field %s is %s, want a JSON object", name, jsonText(v))
			}
		case list:
			if _, ok := v.([]any); !ok {
				return fmt.Sprintf("field %s is %s, want a JSON array", name, jsonText(v))
			}
		}
	}
	return ""
}

var longPattern = regexp.MustCompile(`^[+-]?[0-9]+$`)

// ── PIP uploads ───────────────────────────────────────────────────────────────

// The PIP types and the return types access-control knows. An absent pipType
// is GENERAL.
var (
	pipTypes    = []string{"GENERAL", "FILTERED", "HEADER", "TOKEN", "MAPPING", "PERMISSION_SCOPE"}
	returnTypes = []string{"UUID", "REGULAR", "JSON"}
)

// pipNamePattern is the PIP name access-control accepts, apart from the dash,
// which it refuses later than the other characters: subject. followed by one
// or more dot-separated attributes, each a letter or an underscore followed by
// letters, digits, underscores, and dashes.
var pipNamePattern = regexp.MustCompile(`^subject\.[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`)

// reservedHeaders are the request headers, in lower case, that a HEADER PIP
// may not read and a GENERAL or FILTERED PIP may not forward.
var reservedHeaders = []string{"authorization", "tenant"}

// subjectRefPattern matches a ${subject.<name>} reference in a url or in a
// request attribute.
var subjectRefPattern = regexp.MustCompile(`\$\{(subject\.[^}]*)\}`)

// requestAttributeBuiltins are the subject attributes a request attribute
// may reference without a PIP.
var requestAttributeBuiltins = []string{"id", "isM2M", "name", "roles", "scopes", "serviceAccount", "type"}

// mappingKeyBuiltins are the subject attributes, by the text before the
// first dot, that a MAPPING table may be keyed by without a PIP, besides
// subject.roles.
var mappingKeyBuiltins = []string{"id", "name", "type", "scopes", "serviceAccount", "entitledResources", "isM2M"}

// validatePIPs returns the refusal access-control answers to the PIP upload
// items for domain, or nil when it would store them. items are trimmed by
// [trimPIPEnums]. tenantPIPs holds what the same tenant declared before the
// upload, keyed by domain, domain itself included.
func validatePIPs(items []map[string]any, domain string, tenantPIPs map[string][]simplifiedPIP) *refusal {
	for i, p := range items {
		if pipType(p) == "HEADER" {
			if why := headerRefusal(p["header"]); why != "" {
				return badRequest("PIP %d (%s): %s", i, jsonText(p["name"]), why)
			}
		}
	}
	kinds := declaredKinds(tenantPIPs, items)
	for i, p := range items {
		if why := pipRefusal(p, items, domain, tenantPIPs, kinds); why != nil {
			why.reason = fmt.Sprintf("PIP %d (%s): %s", i, jsonText(p["name"]), why.reason)
			return why
		}
	}
	return nil
}

// trimPIPEnums cuts pipType and type of items of the characters up to U+0020
// around them, unless the cut leaves them empty, and drops an empty
// httpMethod from a PIP that is not GENERAL, the way access-control stores
// them. It reports whether it changed an item.
func trimPIPEnums(items []map[string]any) bool {
	changed := false
	for _, p := range items {
		for _, f := range []string{"pipType", "type"} {
			if s, ok := p[f].(string); ok && javaTrim(s) != "" && javaTrim(s) != s {
				p[f] = javaTrim(s)
				changed = true
			}
		}
		if p["httpMethod"] == "" && pipType(p) != "GENERAL" {
			delete(p, "httpMethod")
			changed = true
		}
	}
	return changed
}

func cloneItem(p map[string]any) map[string]any {
	q := make(map[string]any, len(p))
	for k, v := range p {
		q[k] = v
	}
	return q
}

// pipType returns the pipType of p as text, GENERAL when it is absent.
func pipType(p map[string]any) string {
	if p["pipType"] == nil {
		return "GENERAL"
	}
	return jsonText(p["pipType"])
}

// headerRefusal returns why access-control refuses header as the header a
// HEADER PIP reads, or "".
func headerRefusal(header any) string {
	if header == nil || javaBlank(jsonText(header)) {
		return "header is absent or blank"
	}
	if slices.Contains(reservedHeaders, strings.ToLower(jsonText(header))) {
		return fmt.Sprintf("header %q is reserved", jsonText(header))
	}
	return ""
}

// declaredKinds maps each PIP name the tenant declared, or the upload items
// declare, to its pipType, GENERAL when it is absent. An item overrides a
// stored declaration of its name.
func declaredKinds(tenantPIPs map[string][]simplifiedPIP, items []map[string]any) map[string]string {
	kinds := map[string]string{}
	for _, pips := range tenantPIPs {
		for _, q := range pips {
			kinds[q.Name] = cmp.Or(q.PipType, "GENERAL")
		}
	}
	for _, q := range items {
		kinds[jsonText(q["name"])] = pipType(q)
	}
	return kinds
}

// pipRefusal returns why access-control refuses the PIP p of the upload
// items, or nil.
func pipRefusal(p map[string]any, items []map[string]any, domain string,
	tenantPIPs map[string][]simplifiedPIP, kinds map[string]string,
) *refusal {
	name, t := jsonText(p["name"]), pipType(p)
	if p["name"] == nil || unicodeBlank(name) {
		return badRequest("name is absent or blank")
	}
	if !pipNamePattern.MatchString(name) {
		return badRequest("name %q is not subject.<attribute>, where each dot-separated attribute "+
			"starts with a letter or an underscore and holds only letters, digits, and underscores", name)
	}
	if !slices.Contains(pipTypes, t) {
		return badRequest("pipType %q is not one of %s", t, strings.Join(pipTypes, ", "))
	}
	if rt := p["type"]; rt != nil {
		if !slices.Contains(returnTypes, jsonText(rt)) {
			return badRequest("type %q is not one of %s", jsonText(rt), strings.Join(returnTypes, ", "))
		}
		if jsonText(rt) == "JSON" && t != "GENERAL" {
			return badRequest("type JSON is allowed only for a GENERAL PIP")
		}
	}
	if falsy(p["url"]) && (t == "FILTERED" || t == "PERMISSION_SCOPE" || t == "GENERAL" && falsy(p["beanName"])) {
		return badRequest("url is absent or empty")
	}
	if jsonText(p["type"]) == "JSON" && falsy(p["jsonPath"]) {
		return badRequest("type JSON needs a jsonPath")
	}
	if s, ok := p["jsonPath"].(string); ok && s != "" && javaBlank(s) {
		return badRequest("jsonPath is blank")
	}
	if m := p["httpMethod"]; t == "GENERAL" && m != nil && m != "GET" && m != "POST" {
		return badRequest("httpMethod %q is not GET or POST", jsonText(m))
	}
	if s, ok := p["headers"].(string); ok && s != "" && (t == "GENERAL" || t == "FILTERED") {
		for _, h := range javaSplit(s, ",") {
			if slices.Contains(reservedHeaders, strings.ToLower(h)) {
				return badRequest("headers forwards %q, which is reserved", h)
			}
			if javaBlank(h) {
				return badRequest("headers %q holds a blank name", s)
			}
		}
	}
	if t == "PERMISSION_SCOPE" && name != "subject.permissionScope" {
		return badRequest("a PERMISSION_SCOPE PIP is named subject.permissionScope")
	}
	if t == "MAPPING" && name != "subject.permissions" && !strings.HasPrefix(name, "subject.permissions.") {
		return badRequest("a MAPPING PIP is named subject.permissions or subject.permissions.<name>")
	}
	if t == "GENERAL" {
		for _, ref := range subjectRefPattern.FindAllStringSubmatch(jsonText(p["url"]), -1) {
			if ref[1] != "subject.id" {
				return badRequest("url references ${%s}; a url may reference only ${subject.id}", ref[1])
			}
		}
	}
	if attrs, ok := p["requestAttributes"].(map[string]any); ok {
		if why := requestAttributeRefusal(attrs, kinds); why != "" {
			return badRequest("%s", why)
		}
	}
	twice := 0
	for _, q := range items {
		if jsonText(q["name"]) == name {
			twice++
		}
	}
	if twice > 1 {
		return conflict("name is declared more than once in the upload")
	}
	if other := otherDomainOf(name, domain, tenantPIPs); other != "" && t != "GENERAL" {
		return conflict("name is declared in domain %q of the same tenant", other)
	}
	if t == "GENERAL" {
		if _, isObject := p["headers"].(map[string]any); isObject {
			return badRequest("field headers is a JSON object, want a comma-separated text")
		}
	}
	if why := fieldRefusal(p, pipFieldKinds); why != "" {
		return badRequest("%s", why)
	}
	if strings.Contains(name, "-") {
		return badRequest("name %q holds a dash", name)
	}
	switch t {
	case "FILTERED":
		if falsy(p["resourceType"]) {
			return badRequest("a FILTERED PIP needs a resourceType")
		}
	case "TOKEN":
		if p["claim"] == nil || p["claim"] == "" {
			return badRequest("a TOKEN PIP needs a claim")
		}
	case "MAPPING":
		if why := mappingRefusal(p, kinds); why != "" {
			return badRequest("%s", why)
		}
	case "GENERAL":
		if other := otherDomainOf(name, domain, tenantPIPs); other != "" {
			return conflict("name is declared in domain %q of the same tenant", other)
		}
	}
	return nil
}

// requestAttributeRefusal returns why access-control refuses the request
// attributes attrs of a PIP, or "". Only a value that is a whole
// ${subject.<name>} reference is checked: it names a built-in subject
// attribute, or a TOKEN or HEADER PIP of the tenant.
func requestAttributeRefusal(attrs map[string]any, kinds map[string]string) string {
	for _, key := range slices.Sorted(maps.Keys(attrs)) {
		s, ok := attrs[key].(string)
		if !ok {
			continue
		}
		m := subjectRefPattern.FindStringSubmatch(s)
		if m == nil || m[0] != s {
			continue
		}
		ref := m[1]
		switch kind, declared := kinds[ref]; {
		case declared && kind != "TOKEN" && kind != "HEADER":
			return fmt.Sprintf("request attribute %s references ${%s}, a %s PIP; "+
				"a request attribute may reference only a TOKEN or a HEADER PIP", key, ref, kind)
		case !declared && !slices.Contains(requestAttributeBuiltins, strings.TrimPrefix(ref, "subject.")):
			return fmt.Sprintf("request attribute %s references ${%s}, which is neither a PIP of the tenant "+
				"nor one of subject.%s", key, ref, strings.Join(requestAttributeBuiltins, ", subject."))
		}
	}
	return ""
}

// mappingRefusal returns why access-control refuses the tables of the MAPPING
// PIP p, or "". Each table is a JSON object, keyed by subject.roles, by a
// built-in subject attribute, or by a TOKEN or HEADER PIP of the tenant.
func mappingRefusal(p map[string]any, kinds map[string]string) string {
	for _, field := range []string{"customMapping", "productMapping"} {
		tables, ok := p[field].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(tables)) {
			if _, ok := tables[key].(map[string]any); !ok {
				return fmt.Sprintf("%s %s is %s, want a JSON object", field, key, jsonText(tables[key]))
			}
		}
	}
	for _, field := range []string{"customMapping", "productMapping"} {
		tables, _ := p[field].(map[string]any)
		for _, key := range slices.Sorted(maps.Keys(tables)) {
			if kind := mappingKeyKind(key, kinds); kind != "roles" && kind != "builtin" &&
				kind != "TOKEN" && kind != "HEADER" {
				return fmt.Sprintf("%s is keyed by %s, %s; a key is subject.roles, a built-in subject attribute, "+
					"or a TOKEN or HEADER PIP", field, key, kind)
			}
		}
	}
	return ""
}

// mappingKeyKind returns what the MAPPING key names: roles, builtin, the
// pipType of a declared PIP, or a description of a key that is none of them.
func mappingKeyKind(key string, kinds map[string]string) string {
	name, ok := strings.CutPrefix(key, "subject.")
	switch {
	case !ok:
		return "which does not start with subject."
	case name == "roles":
		return "roles"
	case name == "permissions" || strings.HasPrefix(name, "permissions."):
		return "a MAPPING PIP"
	case name == "permissionScope" || strings.HasPrefix(name, "permissionScope."):
		return "the permission scope"
	case slices.Contains(mappingKeyBuiltins, strings.Split(name, ".")[0]):
		return "builtin"
	}
	if kind, declared := kinds[key]; declared {
		return kind
	}
	return "which no PIP of the tenant declares"
}

// otherDomainOf returns a domain other than domain where the tenant declared
// a PIP named name, or "".
func otherDomainOf(name, domain string, tenantPIPs map[string][]simplifiedPIP) string {
	for _, d := range slices.Sorted(maps.Keys(tenantPIPs)) {
		if d == domain {
			continue
		}
		for _, q := range tenantPIPs[d] {
			if q.Name == name {
				return d
			}
		}
	}
	return ""
}

// ── Simplified policy uploads ─────────────────────────────────────────────────

// uuidPattern is the policy id access-control accepts.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validatePolicies returns the refusal access-control answers to the
// simplified policy upload items, or nil when it would store them. declared
// holds the names of the PIPs the tenant declared in any domain; a nil
// declared accepts a condition that reads a PIP the tenant has not declared.
func validatePolicies(items []map[string]any, declared map[string]bool) *refusal {
	for i, p := range items {
		if s, ok := p["predicates"].(string); ok && javaBlank(s) {
			return badRequest("policy %d: predicates is a blank text", i)
		}
	}
	for i, p := range items {
		if why := policyRefusal(p, declared); why != "" {
			return badRequest("policy %d (%s %s %s): %s", i,
				jsonText(p["component"]), jsonText(p["resourceType"]), jsonText(p["operation"]), why)
		}
	}
	return nil
}

// policyRefusal returns why access-control refuses the simplified policy p,
// or "". A predicates text is read as {"mongodbPredicate": text}.
func policyRefusal(p map[string]any, declared map[string]bool) string {
	predicates := p["predicates"]
	if s, ok := predicates.(string); ok {
		predicates = map[string]any{"mongodbPredicate": s}
		p = cloneItem(p)
		p["predicates"] = predicates
	}
	if p["resourceType"] == "ALL" && (p["component"] != "ALL" || p["operation"] != "ALL" ||
		!falsy(p["condition"]) || !falsy(p["rsqlPredicate"]) || predicates != nil) {
		return "a policy of resourceType ALL has component and operation ALL, " +
			"and no condition, rsqlPredicate, or predicates"
	}
	for _, f := range []string{"component", "resourceType", "operation"} {
		if p[f] == nil {
			return f + " is absent"
		}
	}
	if m, ok := predicates.(map[string]any); ok {
		if len(m) == 0 {
			return "predicates is an empty object"
		}
		mongo := m["mongodbPredicate"]
		if s, isText := mongo.(string); mongo == nil || isText && javaBlank(s) {
			return "predicates has no mongodbPredicate"
		}
	}
	if id := p["id"]; id != nil && !uuidPattern.MatchString(jsonText(id)) {
		return fmt.Sprintf("id %q is not a UUID", jsonText(id))
	}
	if why := fieldRefusal(p, policyFieldKinds); why != "" {
		return why
	}
	if falsy(p["roles"]) {
		return "roles is absent or empty"
	}
	return conditionRefusal(p["condition"], declared)
}

// ── Java text idioms ──────────────────────────────────────────────────────────

// javaTrim cuts the characters up to U+0020 around s, as Java's String.trim.
func javaTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// javaBlank reports whether s holds only whitespace as Java's
// Character.isWhitespace defines it: the Unicode space, line, and paragraph
// separators other than the no-break spaces, the ASCII controls tab to
// carriage return, and U+001C to U+001F.
func javaBlank(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f:
			return true
		case 0xa0, 0x2007, 0x202f:
			return false
		}
		return unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp)
	}) == ""
}

// unicodeBlank reports whether s holds only Unicode whitespace, the no-break
// spaces and U+0085 included.
func unicodeBlank(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }) == ""
}

// javaSplit splits s at sep as Java's String.split does with a literal
// separator: the empty parts at the end are dropped.
func javaSplit(s, sep string) []string {
	parts := strings.Split(s, sep)
	for len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// jsonText returns v as the text access-control binds it to: a text as it
// is, a number as written, a boolean as true or false, and anything else as
// its JSON.
func jsonText(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// falsy reports whether v is absent, null, false, zero, or an empty text,
// array, or object.
func falsy(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case string:
		return v == ""
	case bool:
		return !v
	case json.Number:
		f, err := v.Float64()
		return err == nil && f == 0
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}
