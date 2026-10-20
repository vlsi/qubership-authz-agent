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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"authz-agent/test/parity/suite/model"
)

// caseFile is one file under testdata/cases: the cases one test function runs
// on one stand, as data rather than Go, so that a generator can write them and
// a reader outside the suite can read them without running it.
//
// A case with sets is a regular case: its sets form one upload under the
// external id parity-<id>. A case without sets is an isolated case: one
// simplified policy with condition, on operation (READ when empty), for the
// reader, unless operation names another. The text {{resourceType}} in a condition, a target, or a string of a
// request's resource stands for the case's resource type: resourceType when
// the case sets it, and otherwise resourceTypePrefix followed by the id in
// upper case with - turned into _. {{resourceTypeLowerCase}} stands for the
// same in lower case.
type caseFile struct {
	// About says what the file asks, for the reader of the file; nothing reads it.
	About              string `json:"about"`
	ResourceTypePrefix string `json:"resourceTypePrefix"`
	// Pins maps a pip-mock route to the answer it is pinned to before the first case.
	Pins map[string]PipStubResponse `json:"pins"`
	// UserManagement maps a route of user-management-mock to the answer it is
	// pinned to before the first case. The route * (DefaultRoute) answers
	// every path that has no route of its own; see userManagementRoutes.
	UserManagement map[string]PipStubResponse `json:"userManagement"`
	// PIPs holds the PIP declarations the cases name by key.
	PIPs  map[string]any `json:"pips"`
	Cases []caseSpec     `json:"cases"`
	// Entitlements, when present, is the answer entitlements-mock gives to the
	// user-entitlements lookup of parity-reader from before the first case to
	// the end of the function. The runner also pins /api-version of
	// entitlements-mock to major 3, so that access-control reads that lookup.
	Entitlements *PipStubResponse `json:"entitlements"`
	// StandVersion, when true, makes the function first record what the stand
	// says about itself: GET /api-version, filed under
	// api-version/<test function>, so the answers of the file carry the version
	// that gave them.
	StandVersion bool `json:"standVersion"`
	// Tenant is the tenant_id every call of a case with steps and no sets
	// sends, unless the case names its own; the stand's tenant when empty. A
	// file with a tenant holds only such cases; an empty string is not a tenant.
	Tenant *string `json:"tenant"`
	// StandProperties names access-control properties, by their name in the
	// service's configuration, with the value the stand has to run with for
	// the file's goldens to mean what they say, such as
	// access-control.obligations.enabled. The runner neither sets nor checks
	// them: the stand's owner sets them before the run, and the request for
	// the round names them. A property the file does not name keeps the
	// stand's default.
	StandProperties map[string]string `json:"standProperties"`
}

// standProperties holds the values each property a case file may name in
// StandProperties can take.
var standProperties = map[string][]string{
	"access-control.obligations.enabled":        {"true", "false"},
	"access-control.obligations.merge.strategy": {"weak", "strict"},
}

type caseSpec struct {
	ID string `json:"id"`
	// ResourceType, when not empty, is the case's resource type in place of the
	// one derived from resourceTypePrefix and the id. It keeps the resource type
	// of a case first written in Go, whose goldens were recorded with it.
	ResourceType string `json:"resourceType"`
	// ReadsRoutes names pip-mock routes the file or the case pins, each of
	// which has to receive at least one call while the case runs. The runner
	// clears the call log when the case starts and, once the case's uploads
	// were accepted and its requests sent, fails the case, with no golden of
	// its own, when a route received none: a false answer is then a
	// declaration the stand ignored rather than a PIP it read. No request of
	// the case may clear the log again, so none of them sets pipCalls,
	// classifyBy, or readsRoutes.
	ReadsRoutes []string `json:"readsRoutes"`
	// PIPCalls names a pip-mock route the file or the case pins. The runner
	// clears the call log when the case starts and, after the case's requests
	// and steps, records what the route received over the whole case as a
	// pip-call golden under the case's own name. No request of the case may
	// clear the log again, so none of them sets pipCalls, classifyBy, or
	// readsRoutes.
	PIPCalls string `json:"pipCalls"`
	// Pins maps a pip-mock route to the answer it is pinned to when the case
	// starts, before its uploads. The answer stays until something pins the
	// route again: a later case or request, in the order the cases run, which
	// puts the cases without sets first.
	Pins map[string]PipStubResponse `json:"pins"`
	// UserManagement pins routes of user-management-mock when the case starts,
	// as Pins does for pip-mock.
	UserManagement map[string]PipStubResponse `json:"userManagement"`
	// About says what the case asks where its id and condition do not; nothing
	// reads it.
	About     string        `json:"about"`
	Condition string        `json:"condition"`
	Operation string        `json:"operation"`
	PIPs      []string      `json:"pips"`
	Sets      []setSpec     `json:"sets"`
	Requests  []requestSpec `json:"requests"`
	// Roles replaces the roles of an isolated case's policy, which are
	// ROLE_PARITY_READER when the field is absent; an empty list uploads the
	// policy with no role.
	Roles []string `json:"roles"`
	// Domain names the domain an isolated case uploads its PIPs and policy
	// into, isolatedCaseDomain when empty. The function empties every domain its
	// cases named when it ends.
	Domain string `json:"domain"`
	// RuleIDsOf names an earlier case with sets in the same file. The rule ids
	// of this case are then derived from that case's id rather than its own, so
	// a rule whose key an earlier rule also has uploads with that rule's id.
	RuleIDsOf string `json:"ruleIdsOf"`
	// PolicyOmit names members the simplified policy of a case without sets is
	// uploaded without, such as applicableForFrontend.
	PolicyOmit []string `json:"policyOmit"`
	// Policy is merged into the simplified policy of a case without sets after
	// PolicyOmit is applied, so it adds a member, replaces one, or sets one to
	// null. Its strings take the resource type placeholders.
	Policy map[string]any `json:"policy"`
	// PoliciesQuery is appended as written, after &, to the query of the upload
	// that carries the simplified policy of a case without sets. The uploads
	// before it, which empty the policies and replace the PIPs, keep the plain
	// query.
	PoliciesQuery string `json:"policiesQuery"`
	// Customize holds the customization steps of a case with sets, which run in
	// order after the upload and the case's own requests; see customizeStep.
	Customize []customizeStep `json:"customize"`
	// Steps holds the PAP operations the case performs, each with the
	// observations recorded after it; see stepSpec. A case with sets runs them
	// after its upload and its requests, in place of customize. A case with
	// steps and no sets is a sequence case: it uploads nothing of its own and
	// runs after the file's cases with sets, in the tenant Tenant names.
	Steps []stepSpec `json:"steps"`
	// Tenant is the tenant_id every call of a sequence case sends, in place of
	// the file's tenant and the stand's; an empty string is not a tenant.
	Tenant *string `json:"tenant"`
}

// customizeStep is one call to the customization API of the PAP, recorded as a
// status golden under the step's name, followed by the requests that observe
// its effect. A step with Delete deletes the customization of one set or one
// PIP; a step with PIPs or PIPBody imports PIP customizations; any other step
// imports the policy customizations Sets builds, or Body in their place.
//
// Before the upload of the case and after its last step, the runner deletes,
// with no golden, the customization of every set that a step's Sets names at
// its top level and of every PIP that an object of a step's PIPs or PIPBody
// names. It deletes each at the level of the step, or at both PROJECT and
// CUSTOMER where the step names another level or sets OmitLevel, so that a
// customization an earlier run left behind does not reach the goldens. It
// deletes at CUSTOMER before PROJECT: the PAP refuses to delete a PROJECT
// customization while a CUSTOMER one stands on it, and the PROJECT one then
// outlives the case and the set it customizes, and every later read of the
// policy sets on the stand answers 500.
type customizeStep struct {
	Name string `json:"name"`
	// Level is the level query parameter, sent as written; see OmitLevel.
	Level *string `json:"level"`
	// OmitLevel sends the step with no level parameter at all.
	OmitLevel bool `json:"omitLevel"`
	// Sets holds the customization entries, in the shape of setSpec. The key of
	// an entry, a policy, or a rule is replaced by the id the upload derives
	// from it, so a key the case's sets use names that object; algorithm, sets,
	// iterate, and predicates are renamed or merged as the upload does; every
	// other member is sent as written, with the resource type placeholders
	// replaced. An entry that is not an object, and a sets, policies, or rules
	// member that is not a list, are sent as written.
	Sets []any `json:"sets"`
	// Body, when present, is the whole import body, sent exactly as written,
	// JSON null included, in place of the list Sets builds. The cleanup does not
	// read it.
	Body json.RawMessage `json:"body"`
	// PIPs holds PIP customization entries in the form the PAP reads, sent
	// with the resource type placeholders replaced. Each names the PIP it
	// customizes in name.
	PIPs []any `json:"pips"`
	// PIPBody, when present, is the whole body of a PIP customization import,
	// sent with the resource type placeholders replaced, in place of the list
	// PIPs builds. It may be something other than a list, such as a single
	// entry. The cleanup reads the name of the object it holds, or of each
	// object of the list it holds.
	PIPBody json.RawMessage `json:"pipBody"`
	// Delete deletes the customization of the set with key Delete.Key, or of
	// the PIP named Delete.PIP.
	Delete   *customizeDelete `json:"delete"`
	Requests []requestSpec    `json:"requests"`
}

// customizeDelete names the set or the PIP whose customization a step deletes:
// the set with key Key, or the PIP named PIP, whose resource type placeholders
// are replaced. Recursive is the recursive query parameter of a set's delete,
// which also deletes the customizations of the set's policies and rules; nil
// sends no parameter.
type customizeDelete struct {
	Key       string `json:"key"`
	PIP       string `json:"pip"`
	Recursive *bool  `json:"recursive"`
}

type setSpec struct {
	Key       string       `json:"key"`
	Target    string       `json:"target"`
	Algorithm string       `json:"algorithm"`
	Iterate   *iterateSpec `json:"iterate"`
	Policies  []policySpec `json:"policies"`
	Sets      []setSpec    `json:"sets"`
	// Status is the set's status, ACTIVE when empty.
	Status string `json:"status"`
	// OmitStatus uploads the set with no status member.
	OmitStatus bool `json:"omitStatus"`
	// Fields is merged last into the set; see mergeFields.
	Fields map[string]any `json:"fields"`
	// OmitFields names members the set is uploaded without, removed after
	// Fields is merged.
	OmitFields []string `json:"omitFields"`
}

// iterateSpec is the iterate member of a set, sent as foreach and
// combiningAlgorithm. An algorithm that is JSON null or absent is sent as
// null.
type iterateSpec struct {
	Foreach   string  `json:"foreach"`
	Algorithm *string `json:"algorithm"`
}

type policySpec struct {
	Key       string     `json:"key"`
	Target    string     `json:"target"`
	Algorithm string     `json:"algorithm"`
	Rules     []ruleSpec `json:"rules"`
	// Fields is merged last into the policy; see mergeFields.
	Fields map[string]any `json:"fields"`
	// OmitFields names members the policy is uploaded without, removed after
	// Fields is merged, such as policyId.
	OmitFields []string `json:"omitFields"`
}

type ruleSpec struct {
	Key       string `json:"key"`
	Target    string `json:"target"`
	Condition string `json:"condition"`
	Effect    string `json:"effect"`
	// Predicates holds the rule's predicate fields by name: a string for each
	// dialect, and an object for customPredicate.
	Predicates map[string]any `json:"predicates"`
	// Fields is merged last into the rule, after Predicates; see mergeFields.
	Fields map[string]any `json:"fields"`
	// OmitFields names members the rule is uploaded without, removed after
	// Fields is merged, such as effect or ruleId.
	OmitFields []string `json:"omitFields"`
}

type requestSpec struct {
	Name      string            `json:"name"`
	Operation string            `json:"operation"`
	Type      string            `json:"type"`
	Resource  any               `json:"resource"`
	Headers   map[string]string `json:"headers"`
	Filter    bool              `json:"filter"`
	// Subject "m2m" sends the M2M token alone; "user:<username>" sends the
	// token of that user of the parity realm beside the M2M token; empty sends
	// parity-reader. "m2m@<client>" and "user:<username>@<client>" take the
	// token from a client of
	// testdata/realm-clients/token-subject-clients.json instead (see
	// Config.TokenSubject): the service account's token alone, or the user's
	// beside the M2M token.
	Subject string `json:"subject"`
	// SubjectClaims holds claim values the token of a "user:", "m2m" or "m2m@"
	// subject must carry, such as sub and preferred_username, in their JSON
	// form; null requires the claim to be absent. The suite decodes the token
	// and fails before sending the request when a claim differs, so a stand
	// whose realm lacks the user or the client, or gives them other claims,
	// records nothing.
	SubjectClaims map[string]any `json:"subjectClaims"`
	// ClassifyBy names a pip-mock route. The request's golden is then recorded
	// under <name>-when-the-pip-was-read when the route received a call while
	// the request ran, and under <name>-when-the-pip-was-skipped when it did
	// not, so that an answer that depends on the order access-control evaluates
	// the children of a node or the operands of a condition in is filed with
	// that order.
	ClassifyBy string `json:"classifyBy"`
	// TenantID replaces the stand's tenant in the tenant_id query parameter
	// when present; an empty string sends tenant_id with an empty value.
	TenantID *string `json:"tenantId"`
	// PIPCalls names a pip-mock route. The call log is cleared before the
	// request, and what the route received while the request ran is recorded
	// as a pip-call golden under the request's own name.
	PIPCalls string `json:"pipCalls"`
	// PIPHeaders names headers, beside PIPCalls, whose values in the first call
	// on the route the pip-call golden records; see forwardedHeaders. The names
	// authorization:subject and authorization:issuer, which no header can have,
	// record whose token the call's Authorization is and who issued it; see
	// tokenSubject and tokenIssuer.
	PIPHeaders []string `json:"pipHeaders"`
	// UserID is sent as the userId query parameter of the check, the filter,
	// or the bulk request; "" sends it with an empty value.
	UserID *string `json:"userId"`
	// EmptyOperation sends the operation with an empty value: operation= on a
	// filter request, "operation": "" in a check body.
	EmptyOperation bool `json:"emptyOperation"`
	// Pins maps a pip-mock route to the answer it is pinned to before the
	// request is sent, before its call log is cleared and its pause starts.
	// The answer stays for the requests and cases after it until something
	// pins the route again.
	Pins map[string]PipStubResponse `json:"pins"`
	// UserManagement pins routes of user-management-mock before the request
	// is sent, as Pins does for pip-mock.
	UserManagement map[string]PipStubResponse `json:"userManagement"`
	// UserManagementCalls clears the call log of user-management-mock before
	// the request and records every call it received while the request ran as
	// a user-management-call golden under the request's own name; see
	// userManagementCallOutcome.
	UserManagementCalls bool `json:"userManagementCalls"`
	// ReadsRoutes names pip-mock routes each of which has to receive at least
	// one call while the request runs. The runner clears the call log before
	// the request and fails a check of its own, which records no golden, when
	// a route received none; the request's golden is compared all the same.
	ReadsRoutes []string `json:"readsRoutes"`
	// OmitOperation sends a filter request with no operation parameter at all,
	// where a request without operation sends LIST.
	OmitOperation bool `json:"omitOperation"`
	// PauseMs is how many milliseconds the runner waits before sending the
	// request, after the call log of PIPCalls, ClassifyBy, or ReadsRoutes is
	// cleared.
	PauseMs int `json:"pauseMs"`
	// Bulk sends the request as check/resource/bulk with these items; see
	// bulkItems. The golden records the status and the sorted allowed ids.
	Bulk []any `json:"bulk"`
	// BulkOperations sends the request as check/resource/bulk/operations with
	// these items; see bulkItems. The golden records the status and, per
	// operation, the sorted allowed ids.
	BulkOperations []any `json:"bulkOperations"`
	// V2 sends the request through the v2 endpoint of its kind,
	// check/resource, check/filter, or check/resource/bulk/operations, and
	// records the obligations member of the answer beside the decision; see
	// v2Spec. A bulk request has no v2 endpoint.
	V2 *v2Spec `json:"v2"`
}

// v2Spec is how a case's request goes through a v2 endpoint. Obligations is
// the value of the obligations query parameter, sent as written; when it is
// absent the request sends no obligations parameter at all. The golden is
// check-resource-v2-outcome, check-filter-v2-outcome, or
// check-resource-bulk-operations-v2-outcome, under the request's name, and
// holds what the v1 outcome of the same request holds plus the obligations
// member, written only when the answer had one.
type v2Spec struct {
	Obligations *string `json:"obligations"`
}

// errorBodiesFromRound is the first round whose case files record, beside the
// status of a 400 or 409 answer, its response body. The goldens of the earlier
// rounds hold the status alone, and stay so when they are recorded again.
const errorBodiesFromRound = 44

// recordsErrorBodies reports whether the case file name, a path under
// testdata/cases such as round44/spell-data.json, belongs to round
// errorBodiesFromRound or a later one. A file outside a roundNN directory does
// not.
func recordsErrorBodies(name string) bool {
	dir, _, found := strings.Cut(filepath.ToSlash(name), "/")
	digits, isRound := strings.CutPrefix(dir, "round")
	if !found || !isRound {
		return false
	}
	round, err := strconv.Atoi(digits)
	return err == nil && round >= errorBodiesFromRound
}

// refusalMessage returns the Message of an outcome whose answer had status and
// body: when record is set and the status is 400 or 409, the body as an
// error-class observation records it (see errorOutcome), and nil otherwise.
func refusalMessage(record bool, status int, body []byte) any {
	if !record || (status != http.StatusBadRequest && status != http.StatusConflict) {
		return nil
	}
	return errorOutcome(status, body).Body
}

// readCaseFile reads testdata/cases/<name>. Numbers in a resource keep their
// JSON spelling, so 5.0 is sent as 5.0 and not as 5.
func readCaseFile(name string) (caseFile, error) {
	var f caseFile
	raw, err := os.ReadFile(filepath.Join("testdata", "cases", name))
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("read %s: %w", name, err)
	}
	return f, nil
}

// resourceTypeReplacer replaces {{resourceType}} and {{resourceTypeLowerCase}}
// with rt.
func resourceTypeReplacer(rt string) *strings.Replacer {
	return strings.NewReplacer("{{resourceType}}", rt, "{{resourceTypeLowerCase}}", strings.ToLower(rt))
}

// withResourceType returns v with {{resourceType}} and
// {{resourceTypeLowerCase}} replaced in every string.
func withResourceType(v any, rt string) any {
	switch x := v.(type) {
	case string:
		return resourceTypeReplacer(rt).Replace(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = withResourceType(e, rt)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = withResourceType(e, rt)
		}
		return out
	default:
		return v
	}
}

// derivedID derives the id of the object at path, such as set/outer or
// rule/allow, of the case caseID: the first 16 bytes of the SHA-256 of
// caseID/path, grouped as a UUID is. A rerun derives the same id, so an upload
// replaces what the last run of the case uploaded.
func derivedID(caseID, path string) string {
	sum := sha256.Sum256([]byte(caseID + "/" + path))
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// mergeFields sets each member of fields in object, the wire form of a set, a
// policy, a rule, or a simplified policy, with the resource type placeholders
// of rt replaced in its strings. A member already in object is replaced, and
// a member fields sets to null is set to null rather than removed.
func mergeFields(object, fields map[string]any, rt string) {
	for name, value := range fields {
		object[name] = withResourceType(value, rt)
	}
}

// customKinds maps a kind of customization entry to the member that holds its
// id and the prefix of the path its id is derived from.
var customKinds = map[string]struct {
	idMember, prefix string
}{
	"set":    {"policySetId", "set/"},
	"policy": {"policyId", "policy/"},
	"rule":   {"ruleId", "rule/"},
}

// customChildren maps the member of a customization entry that lists children
// to the kind of the children and the member the wire form lists them under.
var customChildren = map[string]struct{ kind, wire string }{
	"sets":     {"set", "policySets"},
	"policies": {"policy", "policies"},
	"rules":    {"rule", "rules"},
}

// customEntry returns the wire form of e, a customization entry of kind set,
// policy, or rule of the case caseID, as customizeStep.Sets describes it. A
// rule's id is derived from ruleIDsOf when it is not empty, as the upload
// derives it.
func customEntry(caseID, ruleIDsOf, kind string, e any, rt string) any {
	entry, ok := e.(map[string]any)
	if !ok {
		return e
	}
	idCase := caseID
	if kind == "rule" && ruleIDsOf != "" {
		idCase = ruleIDsOf
	}
	key, _ := entry["key"].(string)
	out := map[string]any{customKinds[kind].idMember: derivedID(idCase, customKinds[kind].prefix+key)}
	for name, value := range entry {
		switch name {
		case "key":
		case "algorithm":
			out["combiningAlgorithm"] = value
		case "sets", "policies", "rules":
			child := customChildren[name]
			list, ok := value.([]any)
			if !ok {
				out[child.wire] = value
				continue
			}
			wire := make([]any, len(list))
			for i, c := range list {
				wire[i] = customEntry(caseID, ruleIDsOf, child.kind, c, rt)
			}
			out[child.wire] = wire
		case "predicates":
			predicates, _ := value.(map[string]any)
			for field, predicate := range predicates {
				out[field] = predicate
			}
		case "iterate":
			iterate, _ := value.(map[string]any)
			out["iterate"] = map[string]any{"foreach": iterate["foreach"], "combiningAlgorithm": iterate["algorithm"]}
		default:
			out[name] = withResourceType(value, rt)
		}
	}
	return out
}

// readsPermissionScope reports whether f declares a PERMISSION_SCOPE PIP or
// pins a permission scope route, anywhere in its PIPs, pins or steps.
func readsPermissionScope(f caseFile) bool {
	raw, err := json.Marshal(f)
	return err != nil || bytes.Contains(raw, []byte(`"PERMISSION_SCOPE"`)) || bytes.Contains(raw, []byte("/permission-scope/"))
}

// customizationLevels are the levels a cleanup deletes at when a step names
// no level of them, lower level first; see customizationCleanup.
var customizationLevels = []string{"PROJECT", "CUSTOMER"}

// cleanupLevels returns the levels the cleanup of st deletes at: its own when
// it is PROJECT or CUSTOMER, and both otherwise.
func cleanupLevels(st customizeStep) []string {
	if !st.OmitLevel && st.Level != nil && slices.Contains(customizationLevels, *st.Level) {
		return []string{*st.Level}
	}
	return customizationLevels
}

// customizationCleanup returns the deletes, as customizeStep describes them,
// that the runner sends, in reverse order, before the upload of the case
// caseID and after its last step: the set customizations first, each level and
// set once, then the PIP customizations, each group lower level first, so that
// the runner deletes at the upper level first. They record no golden.
func customizationCleanup(caseID string, steps []customizeStep, rt string) []papCall {
	var sets, pips []papCall
	seen := map[string]bool{}
	for _, st := range steps {
		for _, level := range cleanupLevels(st) {
			for _, e := range st.Sets {
				entry, ok := e.(map[string]any)
				if !ok {
					continue
				}
				key, _ := entry["key"].(string)
				path := "/access/v1/config/customization/policySet/" + derivedID(caseID, "set/"+key)
				if seen[level+" "+path] {
					continue
				}
				seen[level+" "+path] = true
				sets = append(sets, papCall{method: http.MethodDelete, path: path,
					query: url.Values{"level": {level}, "recursive": {"true"}}})
			}
			for _, e := range stepPIPEntries(st) {
				entry, ok := e.(map[string]any)
				if !ok {
					continue
				}
				name, _ := entry["name"].(string)
				path := "/access/v1/pip/customization/pip/" + url.PathEscape(resourceTypeReplacer(rt).Replace(name))
				if seen[level+" "+path] {
					continue
				}
				seen[level+" "+path] = true
				pips = append(pips, papCall{method: http.MethodDelete, path: path, query: url.Values{"level": {level}}})
			}
		}
	}
	lowerFirst := func(a, b papCall) int {
		return slices.Index(customizationLevels, a.query.Get("level")) - slices.Index(customizationLevels, b.query.Get("level"))
	}
	slices.SortStableFunc(sets, lowerFirst)
	slices.SortStableFunc(pips, lowerFirst)
	return append(sets, pips...)
}

// stepPIPEntries returns the PIP customization entries of st: its PIPs, or
// the object PIPBody holds, or the members of the list it holds. A body that
// is neither yields none.
func stepPIPEntries(st customizeStep) []any {
	if st.PIPBody == nil {
		return st.PIPs
	}
	switch body := decodeRaw(st.PIPBody).(type) {
	case []any:
		return body
	case map[string]any:
		return []any{body}
	}
	return nil
}

// decodeRaw returns raw decoded as the case file is, numbers as json.Number,
// or raw itself when it is not valid JSON.
func decodeRaw(raw json.RawMessage) any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	return v
}

// customizeStepCall returns the call st sends for the case caseID, whose rule
// ids come from ruleIDsOf when it is not empty, and the endpoint its status
// golden is filed under.
func customizeStepCall(caseID, ruleIDsOf string, st customizeStep, rt string) (papCall, ParityEndpointID) {
	query := url.Values{}
	if !st.OmitLevel && st.Level != nil {
		query.Set("level", *st.Level)
	}
	switch {
	case st.Delete != nil && st.Delete.PIP != "":
		return papCall{method: http.MethodDelete, query: query,
			path: "/access/v1/pip/customization/pip/" + url.PathEscape(resourceTypeReplacer(rt).Replace(st.Delete.PIP)),
		}, PSUITE_DELETE_PIP_CUSTOMIZATION
	case st.Delete != nil:
		if st.Delete.Recursive != nil {
			query.Set("recursive", strconv.FormatBool(*st.Delete.Recursive))
		}
		return papCall{method: http.MethodDelete, query: query,
			path: "/access/v1/config/customization/policySet/" + derivedID(caseID, "set/"+st.Delete.Key),
		}, PSUITE_DELETE_CUSTOMIZATION
	case st.PIPBody != nil:
		return papCall{method: http.MethodPost, path: Meta(PSUITE_IMPORT_PIP_CUSTOMIZATION).PathTmpl, query: query,
			body: withResourceType(decodeRaw(st.PIPBody), rt)}, PSUITE_IMPORT_PIP_CUSTOMIZATION
	case st.PIPs != nil:
		return papCall{method: http.MethodPost, path: Meta(PSUITE_IMPORT_PIP_CUSTOMIZATION).PathTmpl, query: query,
			body: withResourceType(st.PIPs, rt)}, PSUITE_IMPORT_PIP_CUSTOMIZATION
	}
	var body any = st.Body
	if st.Body == nil {
		entries := make([]any, len(st.Sets))
		for i, e := range st.Sets {
			entries[i] = customEntry(caseID, ruleIDsOf, "set", e, rt)
		}
		body = entries
	}
	return papCall{method: http.MethodPost, path: Meta(PSUITE_IMPORT_CUSTOMIZATION).PathTmpl, query: query, body: body},
		PSUITE_IMPORT_CUSTOMIZATION
}

// checkOperation returns the operation of a check request: operation, READ
// when operation is empty, and "" when emptyOperation is set.
func checkOperation(operation string, emptyOperation bool) string {
	switch {
	case emptyOperation:
		return ""
	case operation == "":
		return "READ"
	}
	return operation
}

// bulkItems returns the body of a bulk request of a case whose resource type
// is rt: each item as written, with the resource type placeholders replaced,
// and with type rt where the item names none.
func bulkItems(items []any, rt string) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = withResourceType(item, rt)
		if entry, ok := out[i].(map[string]any); ok {
			if _, named := entry["type"]; !named {
				entry["type"] = rt
			}
		}
	}
	return out
}

// sentHeaders returns the headers a request sent with tokens and opts
// carries, keyed by lower-case name, as buildRequest sets them: the tokens,
// then the headers of opts that the thin client passes through, which replace
// a token header of the same name.
func sentHeaders(tokens TokenBundle, opts PerCallOptions) map[string]string {
	req, err := buildRequest(context.Background(), http.MethodPost, "http://parity.invalid/", nil, tokens, opts)
	if err != nil {
		panic(err) // the fixed URL always parses
	}
	out := make(map[string]string, len(req.Header))
	for name, values := range req.Header {
		out[strings.ToLower(name)] = strings.Join(values, ",")
	}
	return out
}

// authorizationSubject is the name in pipHeaders that records whose token the
// Authorization of a PIP call is rather than the header itself. A header name
// is a token of RFC 9110, which admits no colon, so no header has this name.
const authorizationSubject = "authorization:subject"

// authorizationIssuer is the name in pipHeaders, and the member of a
// user-management-call golden's headers, that records who issued the
// Authorization of a call; see tokenIssuer.
const authorizationIssuer = "authorization:issuer"

// forwardedHeaders returns the headers named in names that the first call to
// route in calls carried, keyed by lower-case name, as a pip-call golden
// records them. sent holds the headers of the request that caused the call,
// as sentHeaders returns them, and tenant its tenant_id. A header the call did
// not carry is null. A value equal to the request's Authorization or
// Incoming-Token, either one with or without Bearer, is the label <m2m token>
// or <user token>; any other authorization value is <other token>; a tenant
// value is <tenant_id> when it equals tenant and <other> otherwise. The names
// authorizationSubject and authorizationIssuer record the call's Authorization
// as tokenSubject and tokenIssuer class it. Any other value is recorded as it
// is.
func forwardedHeaders(calls []PipStubCall, route string, names []string, sent map[string]string, tenant string) map[string]any {
	var first *PipStubCall
	for i := range calls {
		if calls[i].Path == route {
			first = &calls[i]
			break
		}
	}
	out := make(map[string]any, len(names))
	for _, n := range names {
		name := strings.ToLower(n)
		header := name
		if name == authorizationSubject || name == authorizationIssuer {
			header = "authorization"
		}
		value, carried := "", false
		if first != nil {
			value, carried = first.Headers[header]
		}
		switch {
		case !carried:
			out[name] = nil
		case name == authorizationSubject:
			out[name] = tokenSubject(value, sent["incoming-token"])
		case name == authorizationIssuer:
			out[name] = tokenIssuer(value)
		case sent["authorization"] != "" && withoutBearer(value) == withoutBearer(sent["authorization"]):
			out[name] = "<m2m token>"
		case sent["incoming-token"] != "" && withoutBearer(value) == withoutBearer(sent["incoming-token"]):
			out[name] = "<user token>"
		case name == "authorization":
			out[name] = "<other token>"
		case name == "tenant" && value == tenant:
			out[name] = "<tenant_id>"
		case name == "tenant":
			out[name] = "<other>"
		default:
			out[name] = value
		}
	}
	return out
}

// tokenSubject returns whose token value is, by its claims and never by the
// token itself: <service account> when its preferred_username starts with
// service-account-, as a client's token in Keycloak does; <the request's user>
// when its sub equals the sub of incoming, the Incoming-Token of the request;
// <another user> for any other token with a sub; and <not a token> when value,
// with or without Bearer, is no JWT whose payload holds one of those claims.
func tokenSubject(value, incoming string) string {
	claims := jwtClaims(withoutBearer(value))
	if name, _ := claims["preferred_username"].(string); strings.HasPrefix(name, "service-account-") {
		return "<service account>"
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "<not a token>"
	}
	if mine, _ := jwtClaims(withoutBearer(incoming))["sub"].(string); mine == sub {
		return "<the request's user>"
	}
	return "<another user>"
}

// tokenIssuer returns who issued value, by its claims and never by the token
// itself: <kubernetes> when its payload has a kubernetes.io member, as a
// projected service account token of a pod does; <idp> when its iss is a
// Keycloak realm, ending in /realms/<name>, as the tokens of the stand's IdP
// are; <other> for any other JWT; and <not a token> when value, with or without
// Bearer, is no JWT. The host of iss is not compared, because access-control
// reaches the IdP by an address inside the cluster, which the suite does not
// see.
func tokenIssuer(value string) string {
	claims := jwtClaims(withoutBearer(value))
	if claims == nil {
		return "<not a token>"
	}
	if _, ok := claims["kubernetes.io"]; ok {
		return "<kubernetes>"
	}
	iss, _ := claims["iss"].(string)
	if _, realm, ok := strings.Cut(iss, "/realms/"); ok && realm != "" && !strings.Contains(realm, "/") {
		return "<idp>"
	}
	return "<other>"
}

// userManagementCallOutcome returns calls, the call log of user-management-
// mock over one request, as a user-management-call golden records it. sent
// holds the headers of the request, as sentHeaders returns them, tenant its
// tenant_id, and userID its userId, nil when it sent none. Of the headers of a
// call, the golden holds the value of authorization, incoming-token, tenant,
// accept, and content-type only, since another header may carry a value that
// differs from run to run. A token is the label userManagementTokenLabel gives
// it; a tenant equal to tenant is <tenant_id>. A call with an authorization also
// records its issuer under authorizationIssuer, as tokenIssuer classes it.
func userManagementCallOutcome(calls []PipStubCall, sent map[string]string, tenant string, userID *string) *model.UserManagementCallOutcome {
	outcome := &model.UserManagementCallOutcome{Calls: []model.UserManagementCall{}}
	for _, call := range calls {
		names := slices.Sorted(maps.Keys(call.Headers))
		headers := map[string]any{}
		for _, name := range names {
			value := call.Headers[name]
			switch name {
			case "authorization", "incoming-token":
				headers[name] = userManagementTokenLabel(value, sent, userID)
				if name == "authorization" {
					headers[authorizationIssuer] = tokenIssuer(value)
				}
			case "tenant":
				if value == tenant {
					headers[name] = "<tenant_id>"
				} else {
					headers[name] = value
				}
			case "accept", "content-type":
				headers[name] = value
			}
		}
		outcome.Calls = append(outcome.Calls, model.UserManagementCall{
			Method: call.Method, RequestURI: call.RequestURI, HeaderNames: names, Headers: headers, Body: call.BodyRaw,
		})
	}
	return outcome
}

// userManagementTokenLabel returns whose token value is, never the token
// itself: <m2m token> or <user token> when it is the request's Authorization
// or Incoming-Token, with or without Bearer; otherwise the label tokenSubject
// gives it, except that a token whose sub equals userID is <the user asked
// for> rather than <another user>.
func userManagementTokenLabel(value string, sent map[string]string, userID *string) string {
	token := withoutBearer(value)
	switch {
	case sent["authorization"] != "" && token == withoutBearer(sent["authorization"]):
		return "<m2m token>"
	case sent["incoming-token"] != "" && token == withoutBearer(sent["incoming-token"]):
		return "<user token>"
	}
	label := tokenSubject(value, sent["incoming-token"])
	if sub, _ := jwtClaims(token)["sub"].(string); label == "<another user>" && userID != nil && sub == *userID {
		return "<the user asked for>"
	}
	return label
}

// jwtClaims returns the claims of the payload of token, a JWT, without checking
// its signature, or nil when token is no JWT with a JSON object as payload.
func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

// withoutBearer returns value without a leading Bearer and space, in any case.
func withoutBearer(value string) string {
	if len(value) >= 7 && strings.EqualFold(value[:7], "bearer ") {
		return value[7:]
	}
	return value
}

// TestCaseFilesAreWellFormed reads every file under testdata/cases the way
// runCaseFile does, so that a file caseFileProblems rejects fails here rather
// than on a stand spent recording it. Case ids are golden paths, so they are
// unique across files as well as within one.
func TestCaseFilesAreWellFormed(t *testing.T) {
	root := filepath.Join("testdata", "cases")
	seen := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		name, _ := filepath.Rel(root, path)
		f, err := readCaseFile(name)
		if err != nil {
			t.Error(err)
			return nil
		}
		checkKeepsPIPNames(t, name, f)
		for _, problem := range caseFileProblems(f) {
			t.Errorf("%s: %s", name, problem)
		}
		for _, c := range f.Cases {
			if other, ok := seen[c.ID]; ok {
				t.Errorf("%s: case id %s is also used in %s", name, c.ID, other)
			}
			seen[c.ID] = name
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatalf("no case under %s", root)
	}
}

// caseResourceType returns the resource type of case c of f: its own
// resourceType, else the file's prefix followed by its id in upper case, with
// each hyphen turned into an underscore.
func caseResourceType(f caseFile, c caseSpec) string {
	if c.ResourceType != "" {
		return c.ResourceType
	}
	return f.ResourceTypePrefix + strings.ToUpper(strings.ReplaceAll(c.ID, "-", "_"))
}

// caseFileProblems returns one message for each part of f that runCaseFile
// would not run as written: a PIP a case names and f does not declare, a field
// the kind of case or request does not read, two fields that contradict each
// other or of which the runner sends only one, a route f does not pin, and two
// requests or steps of a case that would record the same golden. The field
// comments of caseSpec, setSpec, requestSpec, and customizeStep say where each
// field applies. TestCaseFilesAreWellFormed checks that case ids are unique
// across files.
func caseFileProblems(f caseFile) []string {
	var problems []string
	report := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	earlierRegular := map[string]bool{}
	problems = append(problems, userManagementRouteProblems("the file", f.UserManagement)...)
	for _, name := range slices.Sorted(maps.Keys(f.StandProperties)) {
		if values, ok := standProperties[name]; !ok {
			report("names the stand property %s, which is none of %v", name, slices.Sorted(maps.Keys(standProperties)))
		} else if !slices.Contains(values, f.StandProperties[name]) {
			report("sets the stand property %s to %q, which is none of %q", name, f.StandProperties[name], values)
		}
	}
	for _, c := range f.Cases {
		problems = append(problems, userManagementRouteProblems("case "+c.ID, c.UserManagement)...)
		sequence := len(c.Sets) == 0 && c.Steps != nil
		if (c.Tenant != nil || f.Tenant != nil) && !sequence {
			report("case %s runs in a tenant the case or its file names, which only a case with steps and no sets does", c.ID)
		}
		if (c.Tenant != nil && *c.Tenant == "") || (f.Tenant != nil && *f.Tenant == "") {
			report("case %s runs in the tenant \"\", which is no tenant: leave tenant out for the stand's", c.ID)
		}
		if c.Steps != nil && c.Customize != nil {
			report("case %s sets both steps and customize, and the runner sends only one of them", c.ID)
		}
		if sequence {
			problems = append(problems, sequenceProblems(c)...)
		} else if len(c.Sets) > 0 {
			if c.Roles != nil || c.Domain != "" || c.PolicyOmit != nil || c.Policy != nil || c.PoliciesQuery != "" {
				report("case %s sets roles, domain, policyOmit, policy, or policiesQuery, which only a case without sets reads", c.ID)
			}
			if c.RuleIDsOf != "" && !earlierRegular[c.RuleIDsOf] {
				report("case %s takes its rule ids from %q, which is no earlier case with sets of the file", c.ID, c.RuleIDsOf)
			}
			earlierRegular[c.ID] = true
			for _, set := range c.Sets {
				problems = append(problems, setProblems(c.ID, set)...)
			}
		} else {
			if c.RuleIDsOf != "" {
				report("case %s sets ruleIdsOf, which only a case with sets reads", c.ID)
			}
			if c.Customize != nil {
				report("case %s sets customize, which only a case with sets reads", c.ID)
			}
		}
		// pinned holds the routes pinned when the case starts; each request adds
		// its own pins before it is checked, in the order the requests run.
		pinned := map[string]bool{}
		for route := range f.Pins {
			pinned[route] = true
		}
		for route := range c.Pins {
			pinned[route] = true
		}
		allRequests := slices.Clone(c.Requests)
		for _, st := range c.Customize {
			allRequests = append(allRequests, st.Requests...)
		}
		for _, st := range c.Steps {
			allRequests = append(allRequests, st.Requests...)
		}
		for _, route := range c.ReadsRoutes {
			if !pinned[route] {
				report("case %s expects calls to %s, which nothing pins before it", c.ID, route)
			}
		}
		if c.ReadsRoutes != nil {
			for _, r := range allRequests {
				if r.PIPCalls != "" || r.ClassifyBy != "" || r.ReadsRoutes != nil {
					report("case %s expects calls over the whole case, and its request %s clears the call log with pipCalls, classifyBy, or readsRoutes", c.ID, r.Name)
				}
			}
		}
		for _, key := range c.PIPs {
			if _, ok := f.PIPs[key]; !ok {
				report("case %s names the PIP %q, which the file does not declare", c.ID, key)
			}
		}
		if c.PIPCalls != "" {
			if !pinned[c.PIPCalls] {
				report("case %s records the calls to %s, which nothing pins before it", c.ID, c.PIPCalls)
			}
			for _, r := range allRequests {
				if r.PIPCalls != "" || r.ClassifyBy != "" || r.ReadsRoutes != nil {
					report("case %s records the calls of the whole case, and its request %s clears the call log with pipCalls, classifyBy, or readsRoutes", c.ID, r.Name)
				}
			}
		}
		requests := map[string]bool{}
		checkRequests := func(list []requestSpec) {
			for _, r := range list {
				if requests[r.Name] {
					report("case %s has two requests named %s, which share a golden", c.ID, r.Name)
				}
				requests[r.Name] = true
				for route := range r.Pins {
					pinned[route] = true
				}
				problems = append(problems, requestProblems(c, r, pinned, caseResourceType(f, c))...)
			}
		}
		checkRequests(c.Requests)
		steps := map[string]bool{}
		for _, st := range c.Customize {
			if steps[st.Name] || st.Name == "" {
				report("case %s has a customize step named %q, which is empty or names another step", c.ID, st.Name)
			}
			steps[st.Name] = true
			problems = append(problems, stepProblems(c.ID, st)...)
			checkRequests(st.Requests)
		}
		for _, st := range c.Steps {
			if steps[st.Name] || st.Name == "" {
				report("case %s has a step named %q, which is empty or names another step", c.ID, st.Name)
			}
			steps[st.Name] = true
			problems = append(problems, caseStepProblems(c, st)...)
			switch {
			case st.Tenant == nil:
			case !sequence:
				report("case %s step %s runs in a tenant of its own, which only a step of a case with steps and no sets does", c.ID, st.Name)
			case *st.Tenant == "":
				report("case %s step %s runs in the tenant \"\", which is no tenant: leave tenant out for the case's", c.ID, st.Name)
			case (c.Tenant != nil && *st.Tenant == *c.Tenant) || (c.Tenant == nil && f.Tenant != nil && *st.Tenant == *f.Tenant):
				report("case %s step %s names the tenant %s, which the case runs in already: leave tenant out", c.ID, st.Name, *st.Tenant)
			}
			// the step's goldens share <group>/<case>/<name> with the case's upload, when it has sets, and its requests
			if (len(c.Sets) > 0 && (st.Name == "upload-1" || st.Name == "declare-the-domain")) || requests[st.Name] ||
				slices.ContainsFunc(allRequests, func(r requestSpec) bool { return r.Name == st.Name }) {
				report("case %s has a step named %s, which a request or the case's upload records a golden under too", c.ID, st.Name)
			}
			routes := stepRoutes(st)
			if len(routes) > 0 && (c.PIPCalls != "" || c.ReadsRoutes != nil) {
				report("case %s counts the calls of the whole case, and its step %s clears the call log with pip-call", c.ID, st.Name)
			}
			for _, r := range st.Requests {
				if len(routes) > 0 && (r.PIPCalls != "" || r.ClassifyBy != "" || r.ReadsRoutes != nil) {
					report("case %s step %s records its calls with pip-call, and its request %s clears the call log with pipCalls, classifyBy, or readsRoutes", c.ID, st.Name, r.Name)
				}
			}
			// the observations in the order the runner makes them, so that a request's pins count from where it is sent
			for _, text := range st.Observe {
				switch o := parseObservation(text); o.kind {
				case "decide":
					for _, r := range st.Requests {
						if r.Name == o.arg {
							checkRequests([]requestSpec{r})
						}
					}
				case "pip-call":
					if !pinned[o.arg] {
						report("case %s step %s records the calls to %s, which nothing pins before it", c.ID, st.Name, o.arg)
					}
				}
			}
		}
	}
	return problems
}

// setProblems returns the problems of set, a set of the case caseID, and of
// its nested sets.
func setProblems(caseID string, set setSpec) []string {
	var problems []string
	if set.OmitStatus && set.Status != "" {
		problems = append(problems, fmt.Sprintf("case %s set %s sets both status and omitStatus", caseID, set.Key))
	}
	for _, nested := range set.Sets {
		problems = append(problems, setProblems(caseID, nested)...)
	}
	return problems
}

// stepProblems returns the problems of st, a customize step of the case
// caseID.
func stepProblems(caseID string, st customizeStep) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("case %s step %s ", caseID, st.Name)+fmt.Sprintf(format, args...))
	}
	if st.Level == nil && !st.OmitLevel {
		report("names no level and does not set omitLevel")
	}
	kinds := 0
	if st.Delete != nil {
		kinds++
		switch {
		case st.Delete.Key == "" && st.Delete.PIP == "":
			report("deletes the customization of a set with no key, or of a PIP with no name")
		case st.Delete.Key != "" && st.Delete.PIP != "":
			report("deletes the customization of both a set and a PIP, and sends only the PIP's delete")
		case st.Delete.PIP != "" && st.Delete.Recursive != nil:
			report("sets recursive on the delete of a PIP customization, which does not send it")
		}
	}
	if st.PIPs != nil || st.PIPBody != nil {
		kinds++
	}
	if st.PIPs != nil && st.PIPBody != nil {
		report("sets both pips and pipBody, and sends only pipBody")
	}
	if st.Sets != nil || st.Body != nil {
		kinds++
	}
	if kinds > 1 {
		report("sets more than one of delete, pips or pipBody, and sets or body, and sends only one of them")
	}
	for _, e := range stepPIPEntries(st) {
		entry, ok := e.(map[string]any)
		if !ok {
			continue // sent as written, like a set entry that is not an object
		}
		if _, named := entry["name"].(string); !named {
			report("imports a PIP customization %v with no name, which the cleanup deletes by name", e)
		}
	}
	for _, e := range st.Sets {
		for _, p := range customEntryProblems("set", e) {
			report("%s", p)
		}
	}
	return problems
}

// customEntryProblems returns the problems of e, a customization entry of
// kind set, policy, or rule, and of its children: an object entry has a key,
// predicates is an object, iterate is an object with foreach and algorithm,
// and no two members write the same member of the wire form, such as
// algorithm beside combiningAlgorithm, since customEntry would then keep
// whichever it wrote last. An entry that is not an object is sent as written
// and has none.
func customEntryProblems(kind string, e any) []string {
	entry, ok := e.(map[string]any)
	if !ok {
		return nil
	}
	var problems []string
	if key, _ := entry["key"].(string); key == "" {
		problems = append(problems, fmt.Sprintf("has a %s entry with no key", kind))
	}
	if predicates, set := entry["predicates"]; set {
		if _, ok := predicates.(map[string]any); !ok {
			problems = append(problems, fmt.Sprintf("has a %s entry whose predicates is not an object", kind))
		}
	}
	if _, set := entry["omitFields"]; set {
		problems = append(problems, fmt.Sprintf("has a %s entry with omitFields, which only an upload reads and a customization sends as written", kind))
	}
	if iterate, set := entry["iterate"]; set {
		it, ok := iterate.(map[string]any)
		_, foreach := it["foreach"]
		_, algorithm := it["algorithm"]
		if !ok || !foreach || !algorithm {
			problems = append(problems, fmt.Sprintf("has a %s entry whose iterate is not an object with foreach and algorithm", kind))
		}
	}
	writers := map[string][]string{}
	for name, value := range entry {
		switch name {
		case "key":
		case "algorithm":
			writers["combiningAlgorithm"] = append(writers["combiningAlgorithm"], name)
		case "sets":
			writers["policySets"] = append(writers["policySets"], name)
		case "predicates":
			predicates, _ := value.(map[string]any)
			for field := range predicates {
				writers[field] = append(writers[field], "predicates."+field)
			}
		default:
			writers[name] = append(writers[name], name)
		}
	}
	for wire, names := range writers {
		if len(names) > 1 {
			slices.Sort(names)
			problems = append(problems, fmt.Sprintf("has a %s entry whose members %s write the same member %s", kind, strings.Join(names, " and "), wire))
		}
	}
	for member, child := range customChildren {
		if list, ok := entry[member].([]any); ok {
			for _, c := range list {
				problems = append(problems, customEntryProblems(child.kind, c)...)
			}
		}
	}
	return problems
}

// subjectProblem returns why a request cannot send the subject s, or "" when
// it can: s is empty, m2m, user:<username>, or one of those two followed by
// @<client> with a client of tokenSubjectClients, which for m2m has to have a
// service account.
func subjectProblem(s string) string {
	who, client, at := strings.Cut(s, "@")
	if at {
		service, ok := tokenSubjectClients[client]
		if !ok {
			return fmt.Sprintf("names the subject %q, whose client is none of "+
				"testdata/realm-clients/token-subject-clients.json", s)
		}
		if who == "m2m" && !service {
			return fmt.Sprintf("names the subject %q, whose client has no service account", s)
		}
	}
	if s == "" || who == "m2m" || strings.HasPrefix(who, "user:") && who != "user:" {
		return ""
	}
	return fmt.Sprintf("names the subject %q, which is neither m2m nor user:<username>", s)
}

// requestProblems returns the problems of r, a request of the case c. pinned
// holds the routes pinned before r is sent: the file's, the case's, and those
// r and the requests before it pin.
func requestProblems(c caseSpec, r requestSpec, pinned map[string]bool, rt string) []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("case %s request %s ", c.ID, r.Name)+fmt.Sprintf(format, args...))
	}
	if problem := subjectProblem(r.Subject); problem != "" {
		report("%s", problem)
	}
	if len(r.SubjectClaims) > 0 && r.Subject != "m2m" && !strings.HasPrefix(r.Subject, "user:") &&
		!strings.HasPrefix(r.Subject, "m2m@") {
		report("sets subjectClaims without a user:, m2m or m2m@ subject")
	}
	if r.PIPCalls != "" {
		if !pinned[r.PIPCalls] {
			report("records the calls to %s, which nothing pins before it", r.PIPCalls)
		}
		if r.ClassifyBy != "" {
			report("sets both pipCalls and classifyBy, which each clear the call log")
		}
	} else if r.PIPHeaders != nil {
		report("sets pipHeaders without pipCalls, whose golden records them")
	}
	for _, name := range r.PIPHeaders {
		if lower := strings.ToLower(name); strings.Contains(name, ":") && lower != authorizationSubject && lower != authorizationIssuer {
			report("names %q in pipHeaders, which no header has, and which is neither %s nor %s", name, authorizationSubject,
				authorizationIssuer)
		}
	}
	if r.ClassifyBy != "" {
		if !pinned[r.ClassifyBy] {
			report("is classified by %s, which nothing pins before it", r.ClassifyBy)
		}
	}
	for _, route := range r.ReadsRoutes {
		if !pinned[route] {
			report("expects calls to %s, which nothing pins before it", route)
		}
	}
	if r.PauseMs < 0 {
		report("pauses for %d ms", r.PauseMs)
	}
	for _, problem := range userManagementRouteProblems("", r.UserManagement) {
		report("%s", problem)
	}
	if r.EmptyOperation && r.Operation != "" {
		report("sets both operation and emptyOperation")
	}
	if r.OmitOperation && (!r.Filter || r.Operation != "" || r.EmptyOperation) {
		report("sets omitOperation, which only a filter request with no operation and no emptyOperation reads")
	}
	if r.V2 != nil && r.Bulk != nil {
		report("sets v2 beside bulk, which has no v2 endpoint")
	}
	if r.V2 != nil && r.BulkOperations != nil {
		if _, err := v2BulkOperationsBody(bulkItems(r.BulkOperations, rt), rt); err != nil {
			report("sends bulkOperations through v2, but %v", err)
		}
	}
	if r.Bulk != nil || r.BulkOperations != nil {
		if r.Bulk != nil && r.BulkOperations != nil {
			report("sets both bulk and bulkOperations")
		}
		if r.Filter || r.Resource != nil || r.Operation != "" || r.Type != "" || r.EmptyOperation || r.ClassifyBy != "" {
			report("sets filter, resource, operation, type, emptyOperation, or classifyBy beside a bulk request, which reads them from its items")
		}
		for _, item := range append(append([]any{}, r.Bulk...), r.BulkOperations...) {
			if _, ok := item.(map[string]any); !ok {
				report("has the bulk item %v, which is not an object", item)
			}
		}
	}
	return problems
}

// userManagementRouteProblems returns one message for each route of pins, the
// userManagement member of owner, that is neither DefaultRoute nor a path:
// pipstub matches a route against the path of a request, which starts with /.
func userManagementRouteProblems(owner string, pins map[string]PipStubResponse) []string {
	var problems []string
	for _, route := range slices.Sorted(maps.Keys(pins)) {
		if route != DefaultRoute && !strings.HasPrefix(route, "/") {
			problems = append(problems, strings.TrimSpace(fmt.Sprintf("%s pins the user-management route %q, which is neither %s nor a path", owner, route, DefaultRoute)))
		}
	}
	return problems
}

// dropsPIPNamesOnPurpose lists the case files that let a case declare fewer PIP
// names than the cases before it, because the file asks what that does.
var dropsPIPNamesOnPurpose = map[string]bool{"round19/stand-rule.json": true}

// checkKeepsPIPNames fails a file of round 19 or later in which a case with
// sets names PIPs without naming every PIP name that an earlier case with sets
// of the file named. A PIP upload replaces the whole declaration of the
// suite's domain, the sets of earlier cases stay loaded, and while a loaded set
// reads a PIP the declaration no longer names, access-control answers every
// check with 400. Cases without sets run before any set is loaded.
func checkKeepsPIPNames(t *testing.T, name string, f caseFile) {
	t.Helper()
	var round int
	if _, err := fmt.Sscanf(name, "round%d/", &round); err != nil || round < 19 || dropsPIPNamesOnPurpose[filepath.ToSlash(name)] {
		return
	}
	pipName := func(key string) string {
		if decl, ok := f.PIPs[key].(map[string]any); ok {
			if n, ok := decl["name"].(string); ok {
				return n
			}
		}
		return key
	}
	declared := map[string]bool{}
	for _, c := range f.Cases {
		if len(c.Sets) == 0 || len(c.PIPs) == 0 {
			continue
		}
		names := map[string]bool{}
		for _, key := range c.PIPs {
			names[pipName(key)] = true
		}
		for n := range declared {
			if !names[n] {
				t.Errorf("%s: case %s declares its PIPs without %s, which an earlier case declared", name, c.ID, n)
			}
		}
		for n := range names {
			declared[n] = true
		}
	}
}
