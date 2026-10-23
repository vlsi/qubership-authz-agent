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

//go:build integration

package paritysuite

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// The export documents of the v3 configuration API, as a raw read of a
// sequence case records them.
const (
	exportDocSets = "policySets"
	exportDocPIPs = "pips"
)

// exportDocsWritten maps a PAP operation that changes the configuration to the
// export documents it can change. An operation of kind write or delete that
// it does not list is taken to change both.
var exportDocsWritten = map[string][]string{
	"write-domain-policies":    {exportDocSets},
	"write-external-id-sets":   {exportDocSets},
	"import-sets":              {exportDocSets},
	"change-set-status":        {exportDocSets},
	"delete-set":               {exportDocSets},
	"customize-sets":           {exportDocSets},
	"delete-set-customization": {exportDocSets},
	"write-domain-pips":        {exportDocPIPs},
	"import-pips":              {exportDocPIPs},
	"customize-pips":           {exportDocPIPs},
	"delete-pip-customization": {exportDocPIPs},
}

// legacyExportCase is a sequence case whose decisions part A of the
// export-fed profile compares: the decisions the case recorded at a point
// where its raw reads show the whole v3 export legacy access-control held.
type legacyExportCase struct {
	file, id, resourceType, tenant string
	pins, userManagement           map[string]PipStubResponse
	points                         []legacyExportPoint
	// uncompared holds, per decision of the case that no raw read covers, why
	// not, keyed by the golden path the decision is recorded under.
	uncompared map[string]string
}

// legacyExportPoint is a run of decisions of a case between which the export
// did not change, with that export.
type legacyExportPoint struct {
	step       string
	decisions  []legacyDecision
	policySets []any
	pips       []any
	// evidence names, per tenant and document, the raw read that shows it,
	// or "unwritten" for a document no accepted step of the case changed in a
	// tenant of its own.
	evidence []string
	// features lists what the export and the case's accepted writes hold that
	// the agent's conversion drops or ignores; see exportFeatures.
	features []string
}

// legacyDecision is a decide observation of a step: the request, the tenant
// the step runs in, whose tenant_id the request sends unless it names its
// own, and the golden path it was recorded under, with no order-class suffix.
type legacyDecision struct {
	request isolatedRequest
	tenant  string
	path    string
}

// legacyExportCases returns the cases of the case file name that part A can
// compare, from the goldens under goldenRoot: those with steps and no sets
// and no customize list. The decisions of a case that records no raw read of
// the policy sets or the PIPs are all uncompared. A case's pins are the
// file's and those of every case before it in the file, then its own,
// because the recorded run pinned them in that order and cleared none
// between the cases.
func legacyExportCases(name string, f caseFile, goldenRoot string) ([]legacyExportCase, error) {
	users := map[string]int{}
	for _, c := range f.Cases {
		for t := range caseTenants(c, f) {
			users[t]++
		}
	}
	pins, userManagement := maps.Clone(f.Pins), maps.Clone(f.UserManagement)
	var out []legacyExportCase
	for _, c := range f.Cases {
		pins, userManagement = mergedPins(pins, c.Pins), mergedPins(userManagement, c.UserManagement)
		if len(c.Sets) > 0 || len(c.Customize) > 0 || c.Steps == nil {
			continue
		}
		if !readsRawExport(c.Steps) {
			out = append(out, unreadCase(name, c))
			continue
		}
		shared := map[string]bool{}
		for t := range caseTenants(c, f) {
			shared[t] = users[t] > 1
		}
		lc, err := legacyExportCaseOf(name, f, c, goldenRoot, shared)
		if err != nil {
			return nil, fmt.Errorf("%s case %s: %w", name, c.ID, err)
		}
		lc.pins, lc.userManagement = maps.Clone(pins), maps.Clone(userManagement)
		out = append(out, lc)
	}
	return out, nil
}

// caseTenants returns the tenants a case of f runs in: its own and those its
// steps and requests name.
func caseTenants(c caseSpec, f caseFile) map[string]bool {
	out := map[string]bool{caseTenant(c, f): true}
	for _, st := range c.Steps {
		if st.Tenant != nil {
			out[*st.Tenant] = true
		}
		for _, r := range st.Requests {
			if r.TenantID != nil {
				out[*r.TenantID] = true
			}
		}
	}
	return out
}

// unreadCase returns the sequence case c, which reads no export, with every
// decision it records uncompared.
func unreadCase(name string, c caseSpec) legacyExportCase {
	lc := legacyExportCase{file: name, id: c.ID, uncompared: map[string]string{}}
	for _, st := range c.Steps {
		for _, o := range st.Observe {
			if d, ok := strings.CutPrefix(o, "decide:"); ok {
				lc.uncompared["sequence/"+c.ID+"/"+d] = "the case records no raw read of the export at step " + st.Name
			}
		}
	}
	return lc
}

func readsRawExport(steps []stepSpec) bool {
	for _, st := range steps {
		if slices.Contains(st.Observe, "read-raw:read-config-sets") || slices.Contains(st.Observe, "read-raw:read-config-pips") {
			return true
		}
	}
	return false
}

// legacyEvent is one entry of legacyExportCaseOf's walk over the steps of a
// case: an accepted write, a raw read of one export document, or a decision.
type legacyEvent struct {
	kind   string // "write", "raw", "decide"
	tenant string
	step   string
	docs   []string // write: the documents it changes; raw: the one it read
	body   []any    // raw: the elements read
	failed int      // raw: the status of a read not answered with 200 and the document, else 0
	op     string
	args   map[string]any
	dec    legacyDecision
}

// legacyExportCaseOf builds the points of the sequence case c. shared marks
// the tenants c runs in that another case of the file runs in too.
func legacyExportCaseOf(name string, f caseFile, c caseSpec, goldenRoot string, shared map[string]bool) (legacyExportCase, error) {
	rt := caseResourceType(f, c)
	lc := legacyExportCase{file: name, id: c.ID, resourceType: rt, tenant: caseTenant(c, f), uncompared: map[string]string{}}
	steps, err := caseSteps(c, rt)
	if err != nil {
		return lc, err
	}
	group := "sequence/" + c.ID
	var events []legacyEvent
	for i, st := range c.Steps {
		tenant := lc.tenant
		if st.Tenant != nil {
			tenant = *st.Tenant
		}
		op := papOperations()[st.Op]
		if op.Kind != "read" {
			status, known, err := stepStatus(goldenRoot, steps[i].golden, group+"/"+st.Name)
			if err != nil {
				return lc, err
			}
			if !known || (status >= http.StatusOK && status < http.StatusMultipleChoices) {
				docs, ok := exportDocsWritten[st.Op]
				if !ok {
					docs = []string{exportDocSets, exportDocPIPs}
				}
				events = append(events, legacyEvent{kind: "write", tenant: tenant, step: st.Name, docs: docs, op: st.Op, args: st.Args})
			}
		}
		// caseSteps builds one observation per entry of stepObserve, in order,
		// and steps[i] is c.Steps[i] because a case with a customize list,
		// whose steps caseSteps puts first, is not built here.
		for j, text := range stepObserve(st, op) {
			o := parseObservation(text)
			switch {
			case o.kind == "read-raw" && (o.arg == "read-config-sets" || o.arg == "read-config-pips"):
				doc := exportDocSets
				if o.arg == "read-config-pips" {
					doc = exportDocPIPs
				}
				body, recorded, failed, err := rawExportRead(goldenRoot, group+"/"+st.Name, doc)
				if err != nil {
					return lc, err
				}
				if recorded {
					events = append(events, legacyEvent{kind: "raw", tenant: tenant, step: st.Name, docs: []string{doc}, body: body, failed: failed})
				}
			case o.kind == "decide":
				req := steps[i].observe[j].request
				events = append(events, legacyEvent{kind: "decide", tenant: tenant, step: st.Name,
					dec: legacyDecision{request: req, tenant: tenant, path: group + "/" + req.name}})
			}
		}
	}
	lc.points = legacyPoints(events, lc, shared, &lc.uncompared)
	return lc, nil
}

func mergedPins(file, own map[string]PipStubResponse) map[string]PipStubResponse {
	if len(file) == 0 && len(own) == 0 {
		return nil
	}
	out := maps.Clone(file)
	if out == nil {
		out = map[string]PipStubResponse{}
	}
	maps.Copy(out, own)
	return out
}

// stepStatus reads the status golden of a write step, and reports whether it
// is recorded.
func stepStatus(root string, id ParityEndpointID, subCase string) (int, bool, error) {
	raw, err := os.ReadFile(filepath.Join(root, Meta(id).GoldenDir, subCase+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var out model.PolicyLoadOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, false, fmt.Errorf("decode the status of %s: %w", subCase, err)
	}
	return out.Status, true, nil
}

// rawExportRead reads the raw read golden of subCase and returns the elements
// of doc it holds. It reports whether the golden is recorded, and, for a read
// not answered with 200 and the document, its status (-1 for a 200 without
// the document) in place of the elements.
func rawExportRead(root, subCase, doc string) (elements []any, recorded bool, failed int, err error) {
	raw, err := os.ReadFile(filepath.Join(root, Meta(PSUITE_PAP_READ_RAW).GoldenDir, subCase+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, err
	}
	var out model.PapReadRawOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false, 0, fmt.Errorf("decode the raw read of %s: %w", subCase, err)
	}
	body, _ := out.Body.(map[string]any)
	elements, ok := body[doc].([]any)
	switch {
	case out.Status != http.StatusOK:
		return nil, true, out.Status, nil
	case !ok:
		return nil, true, -1, nil
	}
	return elements, true, 0, nil
}

// legacyPoints groups the decisions of events into points. A document of a
// tenant is known at a decision when a raw read of it, answered with 200,
// lies between the same two accepted writes that change it, before or after
// the decision. It is known to be empty when no accepted write changed it
// yet, no read between answered otherwise, and the tenant is neither the
// stand's nor shared with another case of the file: the suite clears a
// tenant other than the stand's when a function ends, and nothing between
// the cases of one function. A write whose status is not recorded may have
// changed its documents. A decision for which one document of one tenant
// the case ran in is not known is not compared, and a decision whose
// request pins a route or is filed by order class is not compared either:
// the replay pins only the case's routes and reads no call log.
func legacyPoints(events []legacyEvent, lc legacyExportCase, shared map[string]bool, uncompared *map[string]string) []legacyExportPoint {
	type docKey struct{ tenant, doc string }
	var tenants []string
	for _, e := range events {
		for _, t := range []string{e.tenant, requestTenant(e)} {
			if t != "\x00" && !slices.Contains(tenants, t) {
				tenants = append(tenants, t)
			}
		}
	}
	segment := func(i int, k docKey) int {
		n := 0
		for _, e := range events[:i] {
			if e.kind == "write" && e.tenant == k.tenant && slices.Contains(e.docs, k.doc) {
				n++
			}
		}
		return n
	}
	type rawKey struct {
		docKey
		segment int
	}
	raws := map[rawKey]legacyEvent{}
	failedRaws := map[rawKey]legacyEvent{}
	for i, e := range events {
		if e.kind == "raw" {
			k := rawKey{docKey{e.tenant, e.docs[0]}, segment(i, docKey{e.tenant, e.docs[0]})}
			if e.failed != 0 {
				failedRaws[k] = e
			} else {
				raws[k] = e
			}
		}
	}
	var points []legacyExportPoint
	lastKey := ""
	for i, e := range events {
		if e.kind != "decide" {
			continue
		}
		p := legacyExportPoint{step: e.step, policySets: []any{}, pips: []any{}}
		var missing []string
		var key strings.Builder
		for _, t := range tenants {
			for _, doc := range []string{exportDocSets, exportDocPIPs} {
				k := docKey{t, doc}
				s := segment(i, k)
				fmt.Fprintf(&key, "%s/%s/%d;", t, doc, s)
				f, failed := failedRaws[rawKey{k, s}]
				switch r, ok := raws[rawKey{k, s}]; {
				case ok:
					p.evidence = append(p.evidence, fmt.Sprintf("%s %s: raw read of %s", tenantName(t), doc, r.step))
					elements := withUniqueGeneratedIDs(r.body, lc.id+"/"+r.step+"/"+doc)
					if doc == exportDocSets {
						p.policySets = append(p.policySets, elements...)
					} else {
						p.pips = append(p.pips, elements...)
					}
				case failed:
					missing = append(missing, fmt.Sprintf("%s %s (the raw read of %s answered %d)", tenantName(t), doc, f.step, f.failed))
				case s == 0 && t != "" && !shared[t]:
					p.evidence = append(p.evidence, fmt.Sprintf("%s %s: unwritten", tenantName(t), doc))
				default:
					missing = append(missing, fmt.Sprintf("%s %s", tenantName(t), doc))
				}
			}
		}
		if req := e.dec.request; len(req.pins) > 0 || len(req.userManagement) > 0 || req.classifyBy != "" {
			(*uncompared)[e.dec.path] = "the request pins a route or is filed by order class at step " + e.step
			lastKey = ""
			continue
		}
		if len(missing) > 0 {
			var docs []string
			for _, m := range missing {
				doc := exportDocSets
				if strings.Contains(m, " "+exportDocPIPs) {
					doc = exportDocPIPs
				}
				if !slices.Contains(docs, doc) {
					docs = append(docs, doc)
				}
			}
			slices.Sort(docs)
			(*uncompared)[e.dec.path] = "no raw read of " + strings.Join(docs, " and ") + " at step " + e.step + ": " + strings.Join(missing, ", ")
			lastKey = ""
			continue
		}
		p.features = exportFeatures(p.policySets, p.pips, events[:i], requestTenant(e))
		if key.String() == lastKey && len(points) > 0 && slices.Equal(points[len(points)-1].features, p.features) {
			last := &points[len(points)-1]
			last.decisions = append(last.decisions, e.dec)
			continue
		}
		p.decisions = []legacyDecision{e.dec}
		points = append(points, p)
		lastKey = key.String()
	}
	return points
}

// requestTenant returns the tenant a decision's request names of its own, or
// "\x00" when it names none or e is no decision.
func requestTenant(e legacyEvent) string {
	if e.kind != "decide" || e.dec.request.tenantID == nil {
		return "\x00"
	}
	return *e.dec.request.tenantID
}

func tenantName(t string) string {
	if t == "" {
		return "the stand's tenant"
	}
	return "tenant " + t
}

// withUniqueGeneratedIDs returns elements with every generatedUUID the raw
// read put in place of an id the PAP generated replaced by a UUID of its own,
// derived from seed and the position of the id in a walk over the
// members in key order, so that two such elements do
// not share an id in the agent.
func withUniqueGeneratedIDs(elements []any, seed string) []any {
	n := 0
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for _, k := range slices.Sorted(maps.Keys(x)) {
				out[k] = walk(x[k])
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, val := range x {
				out[i] = walk(val)
			}
			return out
		case string:
			if x == generatedUUID {
				n++
				return seededUUID(fmt.Sprintf("%s#%d", seed, n))
			}
		}
		return v
	}
	out := make([]any, len(elements))
	for i, e := range elements {
		out[i] = walk(e)
	}
	return out
}

func seededUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// exportFeatures lists the features of an export the agent's conversion
// drops or ignores, as internal/acconfig documents it, the customizations
// and status changes the accepted writes before the point made, and the
// features of the export that the agent evaluates differently from legacy
// by decision. request is the tenant the decision's request names, as
// requestTenant returns it. The order is the order a difference is
// classified in.
//
//   - set-type:<type>: a policy set whose type is not SIMPLIFIED, at any
//     depth; "none" for a set with no type;
//   - status:<depth>:<status>: a set whose status is not ACTIVE, depth top or
//     nested, or a status change before the point;
//   - rule-effect:DENY: a DENY rule of a SIMPLIFIED set;
//   - customization:<level>: a set or PIP customization, or its delete, at
//     that level;
//   - tenant: elements of more than one tenant, or of a tenant other than
//     the one request names;
//   - pip-kind:<kind>: a PIP of a kind the conversion drops: MAPPING,
//     FILTERED, PERMISSION_SCOPE, ENTITLEMENT, GENERAL with a beanName, or no
//     pipType ("none");
//   - undeclared-pip:<attribute>: a target or condition of a SIMPLIFIED set
//     reads subject.<attribute>, which is neither in
//     subjectAttributesWithoutPIP nor the first segment of a PIP name of the
//     export.
func exportFeatures(policySets, pips []any, before []legacyEvent, request string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	tenants := map[string]bool{}
	var sets func(list []any, depth string)
	var statuses, effects, reads []string
	var types []string
	sets = func(list []any, depth string) {
		for _, v := range list {
			set, _ := v.(map[string]any)
			if set == nil {
				continue
			}
			if t, ok := set["tenantId"].(string); ok {
				tenants[t] = true
			}
			typ, _ := set["type"].(string)
			if typ != "SIMPLIFIED" {
				types = append(types, "set-type:"+cmpOr(typ, "none"))
			}
			if st, _ := set["status"].(string); st != "ACTIVE" {
				statuses = append(statuses, "status:"+depth+":"+cmpOr(st, "none"))
			}
			if typ == "SIMPLIFIED" {
				for _, pv := range asList(set["policies"]) {
					policy, _ := pv.(map[string]any)
					reads = append(reads, subjectAttributes(policy)...)
					for _, rv := range asList(policy["rules"]) {
						rule, _ := rv.(map[string]any)
						if rule["effect"] == "DENY" {
							effects = append(effects, "rule-effect:DENY")
						}
						reads = append(reads, subjectAttributes(rule)...)
					}
				}
			}
			sets(asList(set["policySets"]), "nested")
		}
	}
	sets(policySets, "top")
	for _, f := range types {
		add(f)
	}
	for _, f := range statuses {
		add(f)
	}
	for _, e := range before {
		if e.kind == "write" && e.op == "change-set-status" {
			add("status:change")
		}
	}
	for _, f := range effects {
		add(f)
	}
	for _, e := range before {
		if e.kind == "write" && (strings.Contains(e.op, "customization") || e.op == "customize-sets" || e.op == "customize-pips") {
			level, _ := e.args["level"].(string)
			add("customization:" + cmpOr(level, "none"))
		}
	}
	var kinds []string
	declared := maps.Clone(subjectAttributesWithoutPIP)
	for _, v := range pips {
		pip, _ := v.(map[string]any)
		if pip == nil {
			continue
		}
		if t, ok := pip["tenantId"].(string); ok {
			tenants[t] = true
		}
		if name, ok := strings.CutPrefix(asString(pip["name"]), "subject."); ok {
			alias, _, _ := strings.Cut(name, ".")
			declared[alias] = true
		}
		kind, _ := pip["pipType"].(string)
		switch {
		case kind == "":
			kinds = append(kinds, "pip-kind:none")
		case kind == "MAPPING", kind == "FILTERED", kind == "PERMISSION_SCOPE", kind == "ENTITLEMENT":
			kinds = append(kinds, "pip-kind:"+kind)
		case kind == "GENERAL" && pip["beanName"] != nil:
			kinds = append(kinds, "pip-kind:GENERAL-beanName")
		}
	}
	otherTenant := len(tenants) > 1
	if request != "\x00" {
		for t := range tenants {
			otherTenant = otherTenant || t != request
		}
	}
	if otherTenant {
		add("tenant")
	}
	for _, f := range kinds {
		add(f)
	}
	for _, a := range reads {
		if !declared[a] {
			add("undeclared-pip:" + a)
		}
	}
	return out
}

// subjectAttributesWithoutPIP holds the attributes of the subject the agent
// resolves with no PIP of the export: the claims of the token, and the
// entitlements the agent's own configuration declares.
var subjectAttributesWithoutPIP = map[string]bool{
	"id": true, "name": true, "type": true, "roles": true, "scopes": true, "entitledResources": true,
}

var (
	subjectPlaceholder = regexp.MustCompile(`\$\{subject\.([^}.]+)`)
	quotedLiteral      = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)
	subjectReference   = regexp.MustCompile(`(?:^|[^\w.$])subject\.([^\s()=!<>,'".]+)`)
)

// subjectAttributes returns the first segment of every subject.<attribute>
// that the target or the condition of element reads: a reference outside a
// quoted literal, or a ${subject.<attribute>} placeholder anywhere.
func subjectAttributes(element map[string]any) []string {
	var out []string
	for _, field := range []string{"target", "condition"} {
		text := asString(element[field])
		for _, m := range subjectPlaceholder.FindAllStringSubmatch(text, -1) {
			out = append(out, m[1])
		}
		for _, m := range subjectReference.FindAllStringSubmatch(quotedLiteral.ReplaceAllString(text, "''"), -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func cmpOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func asList(v any) []any {
	list, _ := v.([]any)
	return list
}

// featureFamilies maps the features of a point to the report families of the
// export-fed profile; a point with none is family simplified.
func featureFamilies(features []string) []string {
	set := map[string]bool{}
	for _, f := range features {
		switch prefix, _, _ := strings.Cut(f, ":"); prefix {
		case "set-type":
			set["policy-set"] = true
		case "status":
			set["status"] = true
		case "customization":
			set["customization"] = true
		case "tenant":
			set["tenant"] = true
		case "pip-kind":
			set["pip-kind"] = true
		case "rule-effect":
			set["rule-effect"] = true
		}
	}
	if len(set) == 0 {
		return []string{"simplified"}
	}
	return slices.Sorted(maps.Keys(set))
}

// legacyClass is the difference class of a golden at point p: pull-failure
// when the agent did not load the point's export, else the first feature of
// the point, else "agent": nothing the conversion is known to drop explains
// the difference.
func legacyClass(p legacyExportPoint, loaded bool) string {
	if !loaded {
		return "pull-failure"
	}
	if len(p.features) > 0 {
		return p.features[0]
	}
	return "agent"
}

// acceptedLegacyDifference returns the entry of acceptedExportDivergences
// that covers a difference of class at a point of part A, keyed by the kind
// of the class (set-type for set-type:DEFAULT). A wrong allow is covered only
// by an entry whose AllowsMore is set.
func acceptedLegacyDifference(class string, wrongAllow bool) (AcceptedDivergence, bool) {
	kind, _, _ := strings.Cut(class, ":")
	accepted, ok := acceptedExportDivergences[kind]
	if !ok || wrongAllow && !accepted.AllowsMore {
		return AcceptedDivergence{}, false
	}
	return accepted, true
}

// legacyCanaryType is the resource type of the canary set mounted beside the
// export of the n-th point of a run.
func legacyCanaryType(n int) string { return fmt.Sprintf("PARITY_EXPORT_CANARY_%d", n) }

// legacyCanarySet is a SIMPLIFIED set that allows ROLE_PARITY_READER to READ
// the resource type rt. The run mounts one with a type of its own beside each
// export and checks it before the decisions: a pull that failed keeps the
// previous export, whose canary has another type, so the check denies.
func legacyCanarySet(rt string) map[string]any {
	return map[string]any{
		"type": "SIMPLIFIED", "status": "ACTIVE", "domain": "PARITY", "component": "PARITY",
		"name": rt + "_PolicySet", "policySetId": seededUUID(rt), "combiningAlgorithm": "DENY_UNLESS_PERMIT",
		"target": "resourceType == '" + rt + "'", "policySets": []any{},
		"policies": []any{map[string]any{
			"name": rt + "_READ_Policy", "policyId": seededUUID(rt + "/policy"), "combiningAlgorithm": "DENY_UNLESS_PERMIT",
			"target": "operation == 'READ'",
			"rules": []any{map[string]any{
				"name": rt + " canary", "ruleId": seededUUID(rt + "/rule"), "effect": "ALLOW", "ruleType": "DEFAULT",
				"target": "subject.roles CONTAINS ANY 'ROLE_PARITY_READER'",
			}},
		}},
	}
}

// legacyExportDocuments returns the two documents the source serves for p,
// with the canary set of type canary appended to the policy sets.
func legacyExportDocuments(p legacyExportPoint, canary string) (json.RawMessage, json.RawMessage, error) {
	sets := append(slices.Clone(p.policySets), legacyCanarySet(canary))
	ps, err := json.Marshal(map[string]any{exportDocSets: sets})
	if err != nil {
		return nil, nil, err
	}
	pips, err := json.Marshal(map[string]any{exportDocPIPs: p.pips})
	if err != nil {
		return nil, nil, err
	}
	return ps, pips, nil
}

// legacyGoldenPaths returns the golden paths a decision of row id under
// subCase is compared with: the golden itself when it is recorded, else the
// variants of its order class that are.
func legacyGoldenPaths(root string, id ParityEndpointID, subCase string) []string {
	dir := Meta(id).GoldenDir
	exists := func(sub string) bool {
		_, err := os.Stat(filepath.Join(root, dir, sub+".json"))
		return err == nil
	}
	if exists(subCase) {
		return []string{dir + "/" + subCase + ".json"}
	}
	var out []string
	for _, suffix := range []string{"-when-the-pip-was-read", "-when-the-pip-was-skipped"} {
		if exists(subCase + suffix) {
			out = append(out, dir+"/"+subCase+suffix+".json")
		}
	}
	return out
}

// legacyResult is the verdict of one decision golden of part A, with the
// class and the features of its point.
type legacyResult struct {
	exportResult
	Features   []string
	WrongAllow bool
}

// legacyExportReport counts, per family, the decisions compared with legacy
// exports and their verdicts, and the decisions no raw read covers by reason;
// counts the differences per class; and lists the wrong allows first, then
// the other differences, each with the features of its point.
func legacyExportReport(results []legacyResult, uncompared map[string]string) string {
	type key struct{ family, verdict string }
	counts := map[key]int{}
	families := map[string]bool{}
	classes := map[string][2]int{}
	var differs []legacyResult
	for _, r := range results {
		for _, f := range r.Families {
			counts[key{f, string(r.Verdict)}]++
			families[f] = true
		}
		if r.Verdict == verdictDiffers || r.Verdict == verdictAccepted {
			c := classes[r.Class]
			c[0]++
			if r.WrongAllow {
				c[1]++
			}
			classes[r.Class] = c
		}
		if r.Verdict == verdictDiffers {
			differs = append(differs, r)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "export-fed agent, legacy exports: %d goldens compared, %d decisions without a legacy export\n",
		len(results), len(uncompared))
	for _, f := range slices.Sorted(maps.Keys(families)) {
		fmt.Fprintf(&b, "  family %-14s match %d, accepted %d, differs %d, skipped %d\n", f,
			counts[key{f, string(verdictMatch)}], counts[key{f, string(verdictAccepted)}],
			counts[key{f, string(verdictDiffers)}], counts[key{f, string(verdictSkipped)}])
	}
	for _, c := range slices.Sorted(maps.Keys(classes)) {
		fmt.Fprintf(&b, "  class %-30s differs %d, wrong allows %d\n", c, classes[c][0], classes[c][1])
	}
	reasons := map[string]int{}
	for _, why := range uncompared {
		reasons[strings.SplitN(why, " at step ", 2)[0]]++
	}
	type kv struct {
		k string
		v int
	}
	var rs []kv
	for k, v := range reasons {
		rs = append(rs, kv{k, v})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].v > rs[j].v || rs[i].v == rs[j].v && rs[i].k < rs[j].k })
	for _, r := range rs {
		fmt.Fprintf(&b, "  uncompared %d: %s\n", r.v, r.k)
	}
	sort.SliceStable(differs, func(i, j int) bool { return differs[i].WrongAllow && !differs[j].WrongAllow })
	for _, r := range differs {
		label := "DIFFERS"
		if r.WrongAllow {
			label = "WRONG ALLOW"
		}
		fmt.Fprintf(&b, "%s %s (%s, class %s, features [%s])\n", label, r.Path, r.Test, r.Class, strings.Join(r.Features, " "))
	}
	return b.String()
}
