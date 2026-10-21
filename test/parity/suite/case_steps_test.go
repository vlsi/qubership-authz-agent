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
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"authz-agent/test/parity/suite/model"
)

// papOperationsJSON is the operation table testdata/pap-operations.json, which
// the spec repository generates from its own vocabulary (pap_ops.py export).
//
//go:embed testdata/pap-operations.json
var papOperationsJSON []byte

// papOperation is one PAP operation a step names: a write, a delete, or a
// read, and the endpoints that perform it, by binding name.
type papOperation struct {
	Kind     string                `json:"kind"`
	Bindings map[string]papBinding `json:"bindings"`
}

// papBinding is one endpoint of an operation. Path holds {name} for each path
// parameter; Query names the query parameters it takes; Args, when it lists a
// parameter, holds the values that parameter may take. Golden is the golden
// kind a write's status is recorded under. Tier is contract, primary, or
// variant.
type papBinding struct {
	Method string              `json:"method"`
	Path   string              `json:"path"`
	Query  []string            `json:"query"`
	Tier   string              `json:"tier"`
	Golden string              `json:"golden"`
	Args   map[string][]string `json:"args"`
}

var (
	papOperationsOnce sync.Once
	papOperationsByOp map[string]papOperation
)

// papOperations returns the operation table by operation name.
func papOperations() map[string]papOperation {
	papOperationsOnce.Do(func() {
		var table struct {
			Ops map[string]papOperation `json:"ops"`
		}
		if err := json.Unmarshal(papOperationsJSON, &table); err != nil {
			panic(fmt.Sprintf("testdata/pap-operations.json: %v", err)) // embedded, so a bad file fails every test
		}
		papOperationsByOp = table.Ops
	})
	return papOperationsByOp
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// bindingOf returns the binding called name of op, or, when name is empty, its
// primary binding, else its contract binding.
func bindingOf(op papOperation, name string) (papBinding, string, bool) {
	if name != "" {
		b, ok := op.Bindings[name]
		return b, name, ok
	}
	for _, tier := range []string{"primary", "contract"} {
		for _, n := range slices.Sorted(maps.Keys(op.Bindings)) {
			if op.Bindings[n].Tier == tier {
				return op.Bindings[n], n, true
			}
		}
	}
	return papBinding{}, "", false
}

// stepSpec is one step of a case: a call to the PAP operation Op through the
// binding Binding, its primary one when empty, followed by the observations
// Observe names, in order:
//
//   - status: the status of the call, under the binding's golden kind;
//   - error-class: the status and the error body of the call, under pap-error-v1;
//   - read:<op>: a GET through the read operation op with the step's Args,
//     under pap-read;
//   - read-raw:<op>: the same GET recorded whole, not narrowed, under
//     pap-read-raw-v1;
//   - decide:<name>: the request called name of Requests, recorded as a
//     case's requests are;
//   - pip-call:<route>: what route received from the call to the observation,
//     under pip-call.
//
// A step whose operation is a read sends no call of its own, takes no
// Binding, and observes read:<its op> when Observe is empty; a write or delete
// step observes status when Observe is empty, and its Observe starts with
// status, followed by error-class when it has one. When the PAP refuses the
// call, OnRefusal stop, the default, records status and error-class and ends
// the case; continue goes on with the step's other observations and the steps
// after it. Golden paths are <kind>/<group>/<case>/<step>, where the group is
// regular or sequence, so a step's name differs from every request name of
// its case and, in a case with sets, from upload-1 and declare-the-domain.
type stepSpec struct {
	Name    string `json:"name"`
	Op      string `json:"op"`
	Binding string `json:"binding"`
	// Args holds the path and query parameters of the binding, strings or
	// booleans; strings take the resource type placeholders.
	Args map[string]any `json:"args"`
	// Body, when present, is the body of the call, sent with the resource type
	// placeholders replaced; JSON null is sent as null.
	Body      json.RawMessage `json:"body"`
	Observe   []string        `json:"observe"`
	OnRefusal string          `json:"onRefusal"`
	Requests  []requestSpec   `json:"requests"`
	// Markers narrows the body of a read observation: an array keeps the
	// elements whose JSON text contains one of them. The step's case id, its
	// resource type, and its string Args are markers too.
	Markers []string `json:"markers"`
	// Tenant, when present, is the tenant_id of every call the step sends in
	// place of the case's tenant: the call, its reads, and the requests of its
	// decide observations that set no tenantId of their own. A read-raw
	// observation keeps the elements of this tenant. The steps after it run in
	// the case's tenant again. Only a step of a sequence case takes a tenant,
	// and an empty string is not a tenant.
	Tenant *string `json:"tenant"`
}

// observation is one entry of stepSpec.Observe: its kind and its argument.
type observation struct{ kind, arg string }

func parseObservation(text string) observation {
	kind, arg, _ := strings.Cut(text, ":")
	return observation{kind, arg}
}

// stepObserve returns the observations of st, its Observe or the default of
// its operation's kind.
func stepObserve(st stepSpec, op papOperation) []string {
	switch {
	case len(st.Observe) > 0:
		return st.Observe
	case op.Kind == "read":
		return []string{"read:" + st.Op}
	}
	return []string{"status"}
}

// argText returns the text of a step argument as the call sends it, with the
// resource type placeholders of rt replaced.
func argText(v any, rt string) string {
	switch x := v.(type) {
	case string:
		return resourceTypeReplacer(rt).Replace(x)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// bindingCall returns the call b makes with args: each {param} of its path
// replaced by the argument, escaped as one path segment, and each query
// parameter the args give.
func bindingCall(b papBinding, args map[string]any, rt string) (papCall, error) {
	var missing []string
	path := pathParam.ReplaceAllStringFunc(b.Path, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := args[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return url.PathEscape(argText(v, rt))
	})
	if len(missing) > 0 {
		return papCall{}, fmt.Errorf("no argument for the path parameter %s", strings.Join(missing, ", "))
	}
	query := url.Values{}
	for _, name := range b.Query {
		if v, ok := args[name]; ok {
			query.Set(name, argText(v, rt))
		}
	}
	return papCall{method: b.Method, path: path, query: query}, nil
}

// goldenEndpoint returns the endpoint whose golden directory is dir.
func goldenEndpoint(dir string) (ParityEndpointID, bool) {
	for id, m := range rowMetas {
		if m.GoldenDir == dir {
			return id, true
		}
	}
	return 0, false
}

// stepCall returns the call st makes for a case whose resource type is rt, and
// the endpoint its status is recorded under; a read step returns no call.
func stepCall(st stepSpec, rt string) (*papCall, ParityEndpointID, error) {
	op, ok := papOperations()[st.Op]
	if !ok {
		return nil, 0, fmt.Errorf("names the operation %q, which testdata/pap-operations.json does not hold", st.Op)
	}
	b, name, ok := bindingOf(op, st.Binding)
	if !ok {
		return nil, 0, fmt.Errorf("names the binding %q, which the operation %s does not have", st.Binding, st.Op)
	}
	if op.Kind == "read" {
		return nil, 0, nil
	}
	if strings.Contains(b.Path, "*") {
		return nil, 0, fmt.Errorf("calls %s/%s, whose path %s names no single endpoint", st.Op, name, b.Path)
	}
	call, err := bindingCall(b, st.Args, rt)
	if err != nil {
		return nil, 0, err
	}
	if st.Body != nil {
		call.body = withResourceType(decodeRaw(st.Body), rt)
		if call.body == nil {
			call.body = json.RawMessage("null") // a nil body would send no body at all
		}
	}
	golden, ok := goldenEndpoint(b.Golden)
	if !ok {
		return nil, 0, fmt.Errorf("records its status under %q, which no endpoint of the catalog files goldens under", b.Golden)
	}
	return &call, golden, nil
}

// readCall returns the GET the observation read:<op> sends with the step's
// args.
func readCall(op string, args map[string]any, rt string) (papCall, error) {
	o, ok := papOperations()[op]
	if !ok || o.Kind != "read" {
		return papCall{}, fmt.Errorf("reads through %q, which is no read operation of testdata/pap-operations.json", op)
	}
	b, name, _ := bindingOf(o, "")
	if b.Method != "GET" || strings.Contains(b.Path, "*") {
		return papCall{}, fmt.Errorf("reads through %s/%s, which is no GET of a single endpoint", op, name)
	}
	return bindingCall(b, args, rt)
}

// stepMarkers returns the markers a read observation of st narrows its body
// by: Markers, the case id, the resource type, and every string argument.
func stepMarkers(caseID, rt string, st stepSpec) []string {
	markers := append([]string{caseID, rt}, st.Markers...)
	for _, name := range slices.Sorted(maps.Keys(st.Args)) {
		if s, ok := st.Args[name].(string); ok {
			markers = append(markers, resourceTypeReplacer(rt).Replace(s))
		}
	}
	return markers
}

// narrowStepRead turns the answer to a step's read into its golden shape:
// narrowPAPRead of the body, with hash and lastModificationTimestamp removed
// from an object body first, and the distinct tenantId values of the narrowed
// 2xx body, sorted. The tenants come from the elements the markers keep, not
// from the whole body: a v3 export lists the elements of every tenant of the
// stand, so a list over the whole body would depend on what the cases before
// this one left there.
func narrowStepRead(status int, body []byte, markers []string) *model.PapReadOutcome {
	var decoded any
	if status < 200 || status > 299 || json.Unmarshal(body, &decoded) != nil {
		return narrowPAPRead(status, body, markers)
	}
	if envelope, ok := decoded.(map[string]any); ok {
		for _, field := range configExportEnvelopeFields {
			delete(envelope, field)
		}
		body, _ = json.Marshal(envelope)
	}
	outcome := narrowPAPRead(status, body, markers)
	tenants := map[string]bool{}
	collectTenants(outcome.Body, tenants)
	outcome.KeptTenants = slices.Sorted(maps.Keys(tenants))
	return outcome
}

func collectTenants(v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if s, ok := value.(string); ok && key == "tenantId" {
				into[s] = true
			}
			collectTenants(value, into)
		}
	case []any:
		for _, e := range x {
			collectTenants(e, into)
		}
	}
}

// rawReadEnvelopeFields are the top-level members of a read that change on
// every write or every call: the export's hash and modification time, and an
// error body's timestamp.
var rawReadEnvelopeFields = append([]string{"timestamp"}, configExportEnvelopeFields...)

// rawStepRead returns the golden shape of a read-raw observation: the status
// and the whole body, decoded when it is JSON, and kept as text otherwise.
// Nothing is narrowed by the case's markers: every element of the outermost
// lists, the body itself when it is an array and every array member of a body
// that is an object, is kept, sorted by its JSON text as the nested lists are,
// since the order the PAP sends them in changes from one stand to the next,
// except an element whose tenantId names a tenant other than tenant, the one
// the step runs in.
// A v3 export lists the elements of every tenant of the stand, and a golden
// that held them would depend on what other cases left there; an empty tenant
// keeps them all. A raw read therefore cannot show an element that leaked in
// from another tenant; a read observation shows one only when it holds one of
// the step's markers. What changes from one read or one upload to the next is
// removed, as narrowConfigExport removes it: rawReadEnvelopeFields from a
// top-level object, and inside each element canonicalExportValue drops the
// write stamps and sorts the nested lists, whose order the PAP does not keep.
// The body of a non-2xx answer goes through withoutServerNames, as the body of
// an error-class observation does.
func rawStepRead(status int, body []byte, tenant string) *model.PapReadRawOutcome {
	out := &model.PapReadRawOutcome{Status: status}
	failed := status < 200 || status > 299
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		out.Body = string(body)
		if failed {
			out.Body = withoutServerNames(string(body))
		}
		return out
	}
	if failed {
		decoded = mapStrings(decoded, withoutServerNames)
	}
	switch typed := decoded.(type) {
	case []any:
		decoded = rawElements(typed, tenant)
	case map[string]any:
		for _, field := range rawReadEnvelopeFields {
			delete(typed, field)
		}
		for key, value := range typed {
			if elements, ok := value.([]any); ok {
				typed[key] = rawElements(elements, tenant)
			} else {
				typed[key] = canonicalExportValue(value)
			}
		}
	}
	out.Body = decoded
	return out
}

// rawElements returns the elements of an outermost list that tenant keeps,
// each canonicalized, sorted by their JSON text.
func rawElements(elements []any, tenant string) []any {
	kept := []any{}
	for _, element := range elements {
		if object, ok := element.(map[string]any); ok && tenant != "" {
			if other, ok := object["tenantId"].(string); ok && other != tenant {
				continue
			}
		}
		kept = append(kept, element)
	}
	return sortByJSONText(kept, canonicalExportValue)
}

// generatedUUID stands in a recorded read for an id the PAP generated.
const generatedUUID = "<generated UUID>"

// idMembers are the members that identify a set, a policy, and a rule.
var idMembers = []string{"policySetId", "policyId", "ruleId"}

// uuidPattern matches a UUID in either case.
const uuidPattern = `[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`

var (
	anyUUID   = regexp.MustCompile(uuidPattern)
	wholeUUID = regexp.MustCompile(`^` + uuidPattern + `$`)
	// writtenID matches an id a write names: a UUID, or a customization path
	// of UUIDs, each followed by "/".
	writtenID = regexp.MustCompile(`^` + uuidPattern + `(?:/(?:` + uuidPattern + `)?)*$`)
)

// generatedIDs tells, for one case, which ids in a read of the PAP the PAP
// generated: the PAP stores a set, a policy, or a rule written without a UUID
// in its id member (the member absent, null, blank, or another value) under a
// random UUID of its own, which differs from one stand to the next.
type generatedIDs struct {
	// unnamed maps an id member to the names of the elements the case wrote
	// without a UUID in it.
	unnamed map[string]map[string]bool
	// written holds, in lower case, every UUID the bodies of the case hold.
	written map[string]bool
}

// caseGeneratedIDs returns the generatedIDs of a case that sends bodies. An
// element written without a name is never masked: nothing in a read ties an
// element to it, so a read of such an element differs between stands.
func caseGeneratedIDs(bodies []any) generatedIDs {
	ids := generatedIDs{unnamed: map[string]map[string]bool{}, written: map[string]bool{}}
	for _, body := range bodies {
		text, err := json.Marshal(body)
		if err != nil {
			continue
		}
		for _, id := range anyUUID.FindAllString(string(text), -1) {
			ids.written[strings.ToLower(id)] = true
		}
		ids.collect(decodeRaw(text), false)
	}
	return ids
}

// collect records in ids.unnamed the elements of v that name no UUID in their
// id member. An element of a list under rules is a rule; an element with
// policies or policySets is a set; an element with rules is a policy.
func (ids generatedIDs) collect(v any, inRules bool) {
	switch x := v.(type) {
	case map[string]any:
		if name, ok := x["name"].(string); ok {
			implied := map[string]bool{
				"policySetId": x["policies"] != nil || x["policySets"] != nil,
				"policyId":    x["rules"] != nil,
				"ruleId":      inRules,
			}
			for _, member := range idMembers {
				value, present := x[member]
				text, _ := value.(string)
				if present && !writtenID.MatchString(text) || !present && implied[member] {
					if ids.unnamed[member] == nil {
						ids.unnamed[member] = map[string]bool{}
					}
					ids.unnamed[member][name] = true
				}
			}
		}
		for key, value := range x {
			ids.collect(value, key == "rules")
		}
	case []any:
		for _, e := range x {
			ids.collect(e, inRules)
		}
	}
}

// mask returns body with generatedUUID in place of every id the PAP
// generated: the value of an id member of an element whose name the case
// wrote without a UUID in that member, when the value is a UUID none of the
// case's bodies holds. An id the case wrote stays as the PAP returns it. A body
// with nothing to mask is returned as it is.
func (ids generatedIDs) mask(body []byte) []byte {
	if len(ids.unnamed) == 0 {
		return body
	}
	decoded := decodeRaw(body)
	if _, isRaw := decoded.(json.RawMessage); isRaw || !ids.replace(decoded) {
		return body
	}
	masked, err := json.Marshal(decoded)
	if err != nil {
		return body
	}
	return masked
}

// replace masks the generated ids of v in place and reports whether it masked
// any.
func (ids generatedIDs) replace(v any) bool {
	masked := false
	switch x := v.(type) {
	case map[string]any:
		if name, ok := x["name"].(string); ok {
			for _, member := range idMembers {
				value, _ := x[member].(string)
				if ids.unnamed[member][name] && wholeUUID.MatchString(value) && !ids.written[strings.ToLower(value)] {
					x[member] = generatedUUID
					masked = true
				}
			}
		}
		for _, value := range x {
			masked = ids.replace(value) || masked
		}
	case []any:
		for _, e := range x {
			masked = ids.replace(e) || masked
		}
	}
	return masked
}

// duplicatingPolicy stands in a recorded refusal for the policy the PAP names
// in an entry of its "duplicates in rules" list.
const duplicatingPolicy = "<one of the duplicating policies>"

// duplicateRuleEntry matches an entry of the "duplicates in rules" list,
// {RuleId=<rule>, policyId=<policy>, policySetId=<set>}, up to the policy; the
// groups are the text before the policy, the rule, and the policy.
var duplicateRuleEntry = regexp.MustCompile(`(\{RuleId=(` + uuidPattern + `), policyId=)(` + uuidPattern + `)`)

// duplicatedRules holds, in lower case, the ruleIds that one body of a case
// writes into more than one policy. The PAP refuses such a body with
// "duplicates in rules" and names the policy in which it met the rule second;
// it keeps the policies of a set in an order that differs from one stand to
// the next, so which of them it names differs too.
type duplicatedRules map[string]bool

// caseDuplicatedRules returns the duplicatedRules of the bodies a case sends.
// A policy is an element with rules; a rule in it counts once however often
// the policy lists it.
func caseDuplicatedRules(bodies []any) duplicatedRules {
	rules := duplicatedRules{}
	for _, body := range bodies {
		text, err := json.Marshal(body)
		if err != nil {
			continue
		}
		policies := map[string]int{}
		countRulePolicies(decodeRaw(text), policies)
		for rule, n := range policies {
			if n > 1 {
				rules[rule] = true
			}
		}
	}
	return rules
}

// countRulePolicies adds to policies, for each ruleId in v, the number of
// policies of v that hold it.
func countRulePolicies(v any, policies map[string]int) {
	switch x := v.(type) {
	case map[string]any:
		if rules, ok := x["rules"].([]any); ok {
			seen := map[string]bool{}
			for _, rule := range rules {
				object, _ := rule.(map[string]any)
				if id, ok := object["ruleId"].(string); ok && !seen[strings.ToLower(id)] {
					seen[strings.ToLower(id)] = true
					policies[strings.ToLower(id)]++
				}
			}
		}
		for _, value := range x {
			countRulePolicies(value, policies)
		}
	case []any:
		for _, e := range x {
			countRulePolicies(e, policies)
		}
	}
}

// mask returns body, the answer to a write, with duplicatingPolicy in place of
// the policyId of every entry of a "duplicates in rules" list whose ruleId is
// one of rules. The ruleId and the policySetId stay. A body with nothing to
// mask is returned as it is.
func (rules duplicatedRules) mask(body []byte) []byte {
	if len(rules) == 0 || !strings.Contains(string(body), "duplicates in rules") {
		return body
	}
	return duplicateRuleEntry.ReplaceAllFunc(body, func(entry []byte) []byte {
		m := duplicateRuleEntry.FindSubmatch(entry)
		if !rules[strings.ToLower(string(m[2]))] {
			return entry
		}
		return append(slices.Clone(m[1]), duplicatingPolicy...)
	})
}

// errorOutcome returns the golden shape of an error-class observation: the
// status, and for a non-2xx answer its body, decoded when it is JSON, with
// every top-level timestamp member removed, since it changes on every call.
// A text body, and every string inside a JSON one, go through
// withoutServerNames, which removes what names the server's internals.
func errorOutcome(status int, body []byte) *model.PapErrorOutcome {
	out := &model.PapErrorOutcome{Status: status}
	if status >= 200 && status <= 299 {
		return out
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		out.Body = withoutServerNames(string(body))
		return out
	}
	if object, ok := decoded.(map[string]any); ok {
		delete(object, "timestamp")
	}
	out.Body = mapStrings(decoded, withoutServerNames)
	return out
}

// mapStrings applies f to every string v holds, at any depth, and returns the
// result. It changes the objects and arrays of v in place; object keys stay as
// they are.
func mapStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case map[string]any:
		for key, value := range x {
			x[key] = mapStrings(value, f)
		}
	case []any:
		for i, value := range x {
			x[i] = mapStrings(value, f)
		}
	}
	return v
}

// referenceChain opens the tail the server adds to the message about a body
// it cannot read: " (through reference chain: <its classes and fields>)".
const referenceChain = " (through reference chain: "

// sourcePosition matches the tail the server's JSON reader adds to the message
// about a body it cannot read, " at [Source: <what was read>; line: 1, column:
// 27]", with the spaces or the line break before it. The part in brackets
// names one of the reader's settings, and may quote a bracket of the body.
var sourcePosition = regexp.MustCompile(`\s*\bat \[Source: (?:(?s:.*?); line: \d+, column: \d+|[^\]]*)\]`)

// frameworkCode matches the error code the server's HTTP framework puts at the
// start of a message, such as "ABCDEF001234: ".
var frameworkCode = regexp.MustCompile(`^[A-Z]{3,}\d{3,}:\s*`)

// urlOrigin matches the scheme, host, and port of an absolute URL.
var urlOrigin = regexp.MustCompile("\\bhttps?://[^/\\s\"'`]+")

// redactedMarker stands in a recorded body for a name of a class, a package, or
// a stack frame.
const redactedMarker = "<redacted>"

// stackFrame matches a frame of a stack trace, at a.b.C.m(C.java:12), with any
// method name, <init> included, and any source, such as Unknown Source.
var stackFrame = regexp.MustCompile(`\bat [\w$.<>]+\([^)\n]*\)`)

// nameToken matches a dotted run of identifiers, such as com.example.Thing,
// resource.o.Id, or Parser$State, with a :line suffix where one follows.
var nameToken = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?::\d+)?`)

// quotedName matches a name that fills a pair of backticks, double quotes, or
// single quotes: identifiers joined by dots, followed by type parameters, an
// argument list, and array brackets where they occur, as in `a.b.C<a.b.D>`,
// "C.m()", or `C.CONSTANT`.
var quotedName = func() *regexp.Regexp {
	const ident = `[A-Za-z_$][\w$]*`
	const typeParams = `<[^<>]*(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>[^<>]*)*>`
	name := ident + `(?:\.` + ident + `)*(?:` + typeParams + `)?(?:\([^()]*\))?(?:\[\])*`
	return regexp.MustCompile("`" + name + "`|\"" + name + "\"|'" + name + "'")
}()

// classSuffix matches a bare name that ends in a suffix classes are named by,
// such as ParityWidgetEntity or ParityWidgetException.
var classSuffix = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*(?:Entity|Dto|DTO|Exception|Error|Impl|Service|Controller|Repository|Mapper|Handler|Validator|Converter|Request|Response)$`)

// withoutServerNames returns message without what names the server's
// internals, so that a recorded body names none of them. It cuts the reference
// chain tail and the source position tail. When the message starts with a
// framework code, it drops the code and the scheme, host, and port of every URL
// in the message: such a message comes from the framework, and its URL is the
// one the server itself was called at. Every quoted name isQuotedServerName
// reports, every stack frame, and every name isServerName reports becomes
// redactedMarker. The rest of the text stays: it is the PAP's reason for the
// refusal.
func withoutServerNames(message string) string {
	if i := strings.Index(message, referenceChain); i >= 0 {
		message = message[:i]
	}
	message = sourcePosition.ReplaceAllString(message, "")
	if code := frameworkCode.FindString(message); code != "" {
		message = urlOrigin.ReplaceAllString(message[len(code):], "")
	}
	message = quotedName.ReplaceAllStringFunc(message, func(quoted string) string {
		quote := quoted[:1]
		if !isQuotedServerName(quoted[1:len(quoted)-1], quote == "`") {
			return quoted
		}
		return quote + redactedMarker + quote
	})
	message = stackFrame.ReplaceAllString(message, "at "+redactedMarker)
	var out strings.Builder
	last := 0
	for _, m := range nameToken.FindAllStringIndex(message, -1) {
		var before byte
		if m[0] > 0 {
			before = message[m[0]-1]
		}
		out.WriteString(message[last:m[0]])
		if isServerName(message[m[0]:m[1]], before) {
			out.WriteString(redactedMarker)
		} else {
			out.WriteString(message[m[0]:m[1]])
		}
		last = m[1]
	}
	out.WriteString(message[last:])
	return out.String()
}

// isQuotedServerName reports whether name, the text of a quotedName match
// inside its quotes, names a type, a constant, or a method, of the server or
// of its runtime alike: a dotted name with an argument list (C.m(), a.b.C.m(x));
// a dotted name with a part that starts with an upper-case letter, with or
// without type parameters (C.CONSTANT, a.b.C<a.b.D>); and, in backticks, a
// single name that starts with an upper-case letter and holds a lower-case one
// (Thing). An attribute of the condition language (subject.x, resource.o.Id), a
// JSON path, a dotted name of lower-case parts (parity.a.b), and, in any quotes,
// an upper-case word (PERMITX) stay.
func isQuotedServerName(name string, backticks bool) bool {
	for _, kept := range []string{"resource.", "subject.", "$"} {
		if strings.HasPrefix(name, kept) {
			return false
		}
	}
	base, _, _ := strings.Cut(name, "<")
	base, _, hasArgs := strings.Cut(base, "(")
	base = strings.TrimRight(base, "[]")
	parts := strings.Split(base, ".")
	if len(parts) == 1 {
		return backticks && base[0] >= 'A' && base[0] <= 'Z' && strings.ContainsFunc(base, unicode.IsLower)
	}
	if hasArgs {
		return true
	}
	return slices.ContainsFunc(parts, func(part string) bool { return part[0] >= 'A' && part[0] <= 'Z' })
}

// isServerName reports whether token, a match of nameToken that follows the
// byte before (0 at the start of the text), names a class or a package of the
// server: a .java or .kt source position; a dotted name whose first part
// starts with a lower-case letter and a later part with an upper-case one
// (a.b.C, a.b.C.m, dto.Thing, and also an unprefixed attribute such as
// owner.Id); a package under com, org, net, or io; a name holding a $ (C$Inner);
// or a bare name classSuffix matches. A JDK name under java or javax stays,
// and a bare JDK exception name is replaced like any other, since nothing
// tells it apart. An attribute of the condition language (resource.o.Id,
// subject.parityX), a JSON path ($.store.Book), and a member after a dot or a
// bracket stay.
func isServerName(token string, before byte) bool {
	if before == '.' || before == ']' {
		return false
	}
	name, _, _ := strings.Cut(token, ":")
	for _, kept := range []string{"java.", "javax.", "resource.", "subject.", "$"} {
		if strings.HasPrefix(name, kept) {
			return false
		}
	}
	parts := strings.Split(name, ".")
	if len(parts) > 1 {
		if tail := parts[len(parts)-1]; tail == "java" || tail == "kt" {
			return true
		}
		first := parts[0]
		if first[0] >= 'a' && first[0] <= 'z' {
			for _, part := range parts[1:] {
				if part[0] >= 'A' && part[0] <= 'Z' {
					return true
				}
			}
		}
		switch first {
		case "com", "org", "net", "io":
			return true
		}
	}
	return strings.Contains(name, "$") || classSuffix.MatchString(name)
}

// caseStepProblems returns the problems of st, a step of the case c, by
// itself; caseFileProblems checks it against the rest of the case.
func caseStepProblems(c caseSpec, st stepSpec) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("case %s step %s ", c.ID, st.Name)+fmt.Sprintf(format, args...))
	}
	op, known := papOperations()[st.Op]
	if !known {
		report("names the operation %q, which testdata/pap-operations.json does not hold", st.Op)
		return problems
	}
	b, bname, ok := bindingOf(op, st.Binding)
	if !ok {
		report("names the binding %q, which the operation %s does not have", st.Binding, st.Op)
		return problems
	}
	if strings.HasPrefix(st.Op, "decide") {
		report("names the decision %s, which a request of decide: observes", st.Op)
		return problems
	}
	if _, _, err := stepCall(st, "RT"); err != nil {
		report("%v", err)
	}
	params := pathParam.FindAllStringSubmatch(b.Path, -1)
	takes := slices.Clone(b.Query)
	for _, p := range params {
		takes = append(takes, p[1])
	}
	for _, name := range slices.Sorted(maps.Keys(st.Args)) {
		v := st.Args[name]
		if !slices.Contains(takes, name) {
			report("sets the argument %s, which %s/%s does not take", name, st.Op, bname)
			continue
		}
		switch v.(type) {
		case string, bool:
		default:
			report("sets the argument %s to %v, which is neither a string nor a boolean", name, v)
		}
		if allowed := b.Args[name]; len(allowed) > 0 && !slices.Contains(allowed, argText(v, "RT")) {
			report("sets the argument %s to %v, which is none of %s", name, v, strings.Join(allowed, ", "))
		}
	}
	read := op.Kind == "read"
	if read && (st.Body != nil || st.OnRefusal != "" || st.Binding != "") {
		report("sets body, onRefusal, or binding on the read %s, which sends no call of its own", st.Op)
	}
	if st.OnRefusal != "" && st.OnRefusal != "stop" && st.OnRefusal != "continue" {
		report("sets onRefusal %q, which is neither stop nor continue", st.OnRefusal)
	}
	observe := stepObserve(st, op)
	if !read && observe[0] != "status" {
		report("observes %s first, where a write starts with status", observe[0])
	}
	for i, text := range observe {
		o := parseObservation(text)
		if (o.kind == "status" || o.kind == "error-class") && (text != o.kind || (o.kind == "error-class" && i != 1)) {
			report("observes %q at %d, where error-class comes right after status and neither takes an argument", text, i+1)
		}
	}
	seen := map[string]bool{}
	decided := map[string]bool{}
	for _, text := range observe {
		o := parseObservation(text)
		golden := o.kind
		switch o.kind {
		case "status", "error-class":
			if read {
				report("observes %s on the read %s, which sends no call of its own", o.kind, st.Op)
			}
		case "read", "read-raw":
			if _, err := readCall(o.arg, st.Args, "RT"); err != nil {
				report("%v", err)
			}
		case "decide":
			golden = "decide:" + o.arg
			if !slices.ContainsFunc(st.Requests, func(r requestSpec) bool { return r.Name == o.arg }) {
				report("observes decide:%s, and no request of the step has that name", o.arg)
			}
			decided[o.arg] = true
		case "pip-call":
			golden = "pip-call"
			if o.arg == "" {
				report("observes pip-call with no route")
			}
		default:
			report("observes %q, which is none of status, error-class, read:<op>, read-raw:<op>, decide:<request>, "+
				"pip-call:<route>", text)
		}
		if seen[golden] {
			report("observes %s twice, and both would record the same golden", golden)
		}
		seen[golden] = true
	}
	for _, r := range st.Requests {
		if !decided[r.Name] {
			report("has the request %s, which no decide: observation sends", r.Name)
		}
	}
	return problems
}

// stepRoutes returns the routes of the pip-call observations of st.
func stepRoutes(st stepSpec) []string {
	var out []string
	for _, text := range st.Observe {
		if o := parseObservation(text); o.kind == "pip-call" {
			out = append(out, o.arg)
		}
	}
	return out
}

// sequenceProblems returns the problems of c, a case with steps and no sets,
// and of its tenant: such a case reads its steps and pins only.
func sequenceProblems(c caseSpec) []string {
	var problems []string
	if c.Condition != "" || c.Operation != "" || c.PIPs != nil || c.Requests != nil || c.Roles != nil ||
		c.Domain != "" || c.PolicyOmit != nil || c.Policy != nil || c.PoliciesQuery != "" || c.Customize != nil ||
		c.ReadsRoutes != nil || c.PIPCalls != "" || c.RuleIDsOf != "" {
		problems = append(problems, fmt.Sprintf("case %s has steps and no sets, and sets a field other than "+
			"id, about, resourceType, tenant, pins, and steps, which such a case does not read", c.ID))
	}
	if len(c.Steps) == 0 {
		problems = append(problems, fmt.Sprintf("case %s sets steps to an empty list", c.ID))
	}
	return problems
}
