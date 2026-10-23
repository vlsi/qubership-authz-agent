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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// The kinds of export form that legacy access-control accepts into its
// configuration and then fails every decision on, each with the status legacy
// answers such a decision with.
const (
	// formNeverEvaluated is an iterate block whose foreach is not
	// subject.permissionScope, or that has no combiningAlgorithm: legacy
	// answers 500 to every decision that reaches the set.
	formNeverEvaluated = "never-evaluated"
	// formUndeclaredPIP is a target or condition that reads
	// subject.<attribute> with no PIP of that name in the export: legacy
	// answers 400 to every check.
	formUndeclaredPIP = "undeclared-pip"
)

// legacyFailureStatus maps a form kind to the status legacy answers a
// decision with when the form fails it.
var legacyFailureStatus = map[string]int{
	formNeverEvaluated: http.StatusInternalServerError,
	formUndeclaredPIP:  http.StatusBadRequest,
}

// exportForm is one form of kind formNeverEvaluated or formUndeclaredPIP in
// an export.
type exportForm struct {
	kind string
	// what describes the form for the failure message, such as
	// "foreach over subject.roles".
	what string
	// tenant is the tenantId of the policy set that holds the form.
	tenant string
	// sets holds the policySetId and the name of the set that holds the form
	// and of every set above it, top level first. The agent's /health names
	// the failed set when it names any of them.
	sets []string
}

// exportForms returns the forms of kind formNeverEvaluated and
// formUndeclaredPIP in an export, in the order a walk of the policy sets,
// depth first, meets them. A subject attribute is declared when it is one the
// agent resolves without a PIP (subjectAttributesWithoutPIP) or the first
// segment of the name of a PIP of pips.
func exportForms(policySets, pips []any) []exportForm {
	declared := maps.Clone(subjectAttributesWithoutPIP)
	for _, v := range pips {
		pip, _ := v.(map[string]any)
		if name, ok := strings.CutPrefix(asString(pip["name"]), "subject."); ok {
			alias, _, _ := strings.Cut(name, ".")
			declared[alias] = true
		}
	}
	var out []exportForm
	var walk func(list []any, above []string)
	walk = func(list []any, above []string) {
		for _, v := range list {
			set, _ := v.(map[string]any)
			if set == nil {
				continue
			}
			chain := slices.Clone(above)
			for _, k := range []string{"policySetId", "name"} {
				if s := asString(set[k]); s != "" {
					chain = append(chain, s)
				}
			}
			form := func(kind, what string) {
				out = append(out, exportForm{kind: kind, what: what, tenant: asString(set["tenantId"]), sets: chain})
			}
			if it, ok := set["iterate"].(map[string]any); ok {
				switch foreach := asString(it["foreach"]); {
				case foreach != "subject.permissionScope":
					form(formNeverEvaluated, fmt.Sprintf("foreach over %q", foreach))
				case asString(it["combiningAlgorithm"]) == "":
					form(formNeverEvaluated, "iterate without combiningAlgorithm")
				}
			}
			reads := subjectAttributes(set)
			for _, pv := range asList(set["policies"]) {
				policy, _ := pv.(map[string]any)
				reads = append(reads, subjectAttributes(policy)...)
				for _, rv := range asList(policy["rules"]) {
					rule, _ := rv.(map[string]any)
					reads = append(reads, subjectAttributes(rule)...)
				}
			}
			var undeclared []string
			for _, a := range reads {
				if !declared[a] && !slices.Contains(undeclared, a) {
					undeclared = append(undeclared, a)
				}
			}
			for _, a := range undeclared {
				form(formUndeclaredPIP, "subject."+a+" with no PIP declared")
			}
			walk(asList(set["policySets"]), chain)
		}
	}
	walk(policySets, nil)
	return out
}

// ownerDecisionCase is an export that holds forms of exportForms, as legacy
// access-control accepted it, with the decisions legacy failed because of
// those forms.
type ownerDecisionCase struct {
	// name is <case file>/<case id>, and /<step> for a point of a sequence
	// case.
	name         string
	resourceType string
	// tenant is the tenant the case ran in, "" for the stand's; the canary
	// is checked in it.
	tenant               string
	pins, userManagement map[string]PipStubResponse
	policySets, pips     []any
	forms                []exportForm
	decisions            []ownerDecision
}

// ownerDecision is a decision of an ownerDecisionCase: the request, the
// tenant it is sent in ("" for the stand's), and the legacy golden that shows
// the decision failed.
type ownerDecision struct {
	request isolatedRequest
	tenant  string
	path    string
	status  int
}

// allOwnerDecisionCases returns the ownerDecisionCases of every case file
// under testdata/cases: the regular cases of regularOwnerDecisionCases, then
// the points of part A of legacyOwnerDecisionCases. standTenant is the tenant
// the regular cases ran in.
func allOwnerDecisionCases(goldenRoot, standTenant string) ([]ownerDecisionCase, error) {
	names, err := caseFileNames()
	if err != nil {
		return nil, err
	}
	var out []ownerDecisionCase
	for _, name := range names {
		f, err := readCaseFile(name)
		if err != nil {
			return nil, err
		}
		cases, err := regularOwnerDecisionCases(name, f, goldenRoot, standTenant)
		if err != nil {
			return nil, err
		}
		out = append(out, cases...)
	}
	legacy, err := allLegacyExportCases(goldenRoot)
	if err != nil {
		return nil, err
	}
	for _, lc := range legacy {
		cases, err := legacyOwnerDecisionCases(lc, goldenRoot, standTenant)
		if err != nil {
			return nil, fmt.Errorf("%s case %s: %w", lc.file, lc.id, err)
		}
		out = append(out, cases...)
	}
	return out, nil
}

// regularOwnerDecisionCases returns the cases of the case file name that have
// sets, whose upload legacy accepted, and whose sets hold a form of
// exportForms. The
// export of such a case is the one the upload leaves in standTenant: the sets
// as uploaded, of type DEFAULT, and the PIPs the case declares in
// isolatedCaseDomain. Its decisions are the requests of the case that
// dependsOnForms selects; the steps and the customizations of the case run
// after the requests, and their decisions are left out.
func regularOwnerDecisionCases(name string, f caseFile, goldenRoot, standTenant string) ([]ownerDecisionCase, error) {
	pins, userManagement := maps.Clone(f.Pins), maps.Clone(f.UserManagement)
	var out []ownerDecisionCase
	for _, c := range f.Cases {
		pins, userManagement = mergedPins(pins, c.Pins), mergedPins(userManagement, c.UserManagement)
		if len(c.Sets) == 0 {
			continue
		}
		group := "regular/" + c.ID
		accepted, err := acceptedUpload(goldenRoot, group, len(c.PIPs) > 0)
		if err != nil {
			return out, err
		}
		if !accepted {
			continue
		}
		rt := caseResourceType(f, c)
		b := regularBuilder{caseID: c.ID}
		ruleIDs := regularBuilder{caseID: valueOr(c.RuleIDsOf, c.ID)}
		var built []any
		for _, set := range c.Sets {
			built = append(built, asLegacyExportSet(buildSet(b, ruleIDs, set, rt), standTenant))
		}
		// The export holds the sets as JSON decodes them, as a raw read
		// does: buildSet writes an iterate algorithm as a *string.
		sets, err := decodedJSON(built)
		if err != nil {
			return out, fmt.Errorf("%s case %s: %w", name, c.ID, err)
		}
		pips := []any{}
		for _, key := range c.PIPs {
			pip, _ := f.PIPs[key].(map[string]any)
			pip = maps.Clone(pip)
			if pip == nil {
				return out, fmt.Errorf("%s case %s names the PIP %q, which the file does not declare", name, c.ID, key)
			}
			pip["domain"], pip["tenantId"] = isolatedCaseDomain, standTenant
			pips = append(pips, pip)
		}
		forms := exportForms(sets, pips)
		if len(forms) == 0 {
			continue
		}
		oc := ownerDecisionCase{name: name + "/" + c.ID, resourceType: rt, pins: maps.Clone(pins),
			userManagement: maps.Clone(userManagement), policySets: sets, pips: pips, forms: forms}
		for _, req := range caseRequests(c.Requests, rt) {
			d := ownerDecision{request: req, path: group + "/" + req.name}
			if status, ok, err := decisionStatus(goldenRoot, d.path); err != nil {
				return out, err
			} else if ok {
				d.status = status
				if dependsOnForms(d, rt, forms, standTenant) {
					oc.decisions = append(oc.decisions, d)
				}
			}
		}
		if oc.forms = confirmedForms(forms, oc.decisions, standTenant); len(oc.forms) > 0 {
			out = append(out, oc)
		}
	}
	return out, nil
}

func decodedJSON(v []any) ([]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []any
	return out, json.Unmarshal(raw, &out)
}

// confirmedForms returns the forms of kind formNeverEvaluated, and those of
// kind formUndeclaredPIP when one of decisions failed with 400 in the tenant
// of the form. Legacy fails every decision on an iterate block it never
// evaluates, so the form alone shows it; an attribute the agent would need a
// PIP for may be one legacy resolves without one, so only a check legacy
// refused shows that it did not. The refusal confirms every such form of its
// tenant: legacy refuses every check there, whichever set caused it.
func confirmedForms(forms []exportForm, decisions []ownerDecision, standTenant string) []exportForm {
	return slices.DeleteFunc(slices.Clone(forms), func(f exportForm) bool {
		return f.kind == formUndeclaredPIP && !slices.ContainsFunc(decisions, func(d ownerDecision) bool {
			return d.status == legacyFailureStatus[formUndeclaredPIP] &&
				decisionTenant(d, standTenant) == valueOr(f.tenant, standTenant)
		})
	})
}

// legacyOwnerDecisionCases returns the points of the sequence case lc whose
// export, as the raw reads recorded it, holds a form of exportForms, with the
// decisions of the point that dependsOnForms selects.
func legacyOwnerDecisionCases(lc legacyExportCase, goldenRoot, standTenant string) ([]ownerDecisionCase, error) {
	var out []ownerDecisionCase
	for _, p := range lc.points {
		forms := exportForms(p.policySets, p.pips)
		if len(forms) == 0 {
			continue
		}
		oc := ownerDecisionCase{name: lc.file + "/" + lc.id + "/" + p.step, resourceType: lc.resourceType, tenant: lc.tenant,
			pins: lc.pins, userManagement: lc.userManagement, policySets: p.policySets, pips: p.pips, forms: forms}
		for _, ld := range p.decisions {
			d := ownerDecision{request: ld.request, tenant: ld.tenant, path: ld.path}
			if status, ok, err := decisionStatus(goldenRoot, d.path); err != nil {
				return out, err
			} else if ok {
				d.status = status
				if dependsOnForms(d, lc.resourceType, forms, standTenant) {
					oc.decisions = append(oc.decisions, d)
				}
			}
		}
		if oc.forms = confirmedForms(forms, oc.decisions, standTenant); len(oc.forms) > 0 {
			out = append(out, oc)
		}
	}
	return out, nil
}

// acceptedUpload reports whether legacy accepted the upload of the regular
// case whose golden group is group: its upload-1 status golden is 2xx, and so
// is the declare-the-domain golden of a case that declares PIPs. A golden
// that is not recorded counts as a refusal.
func acceptedUpload(root, group string, declaresPIPs bool) (bool, error) {
	steps := []struct {
		id   ParityEndpointID
		name string
	}{{PSUITE_LOAD_POLICY_SETS, "upload-1"}}
	if declaresPIPs {
		steps = append(steps, struct {
			id   ParityEndpointID
			name string
		}{PSUITE_LOAD_SIMPLIFIED_POLICIES, "declare-the-domain"})
	}
	for _, st := range steps {
		status, known, err := stepStatus(root, st.id, group+"/"+st.name)
		if err != nil || !known || status < http.StatusOK || status >= http.StatusMultipleChoices {
			return false, err
		}
	}
	return true, nil
}

// asLegacyExportSet returns the uploaded regular set as the v3 export of
// legacy carries it: type DEFAULT on the set and every nested one, and
// tenantId on every set, policy, and rule.
func asLegacyExportSet(set map[string]any, tenant string) map[string]any {
	out := maps.Clone(set)
	out["type"], out["tenantId"] = "DEFAULT", tenant
	var policies []any
	for _, pv := range asList(set["policies"]) {
		policy, _ := pv.(map[string]any)
		policy = maps.Clone(policy)
		var rules []any
		for _, rv := range asList(policy["rules"]) {
			rule, _ := rv.(map[string]any)
			rule = maps.Clone(rule)
			rule["tenantId"] = tenant
			rules = append(rules, rule)
		}
		policy["rules"], policy["tenantId"] = emptyIfNil(rules), tenant
		policies = append(policies, policy)
	}
	out["policies"] = emptyIfNil(policies)
	var nested []any
	for _, nv := range asList(set["policySets"]) {
		n, _ := nv.(map[string]any)
		nested = append(nested, asLegacyExportSet(n, tenant))
	}
	out["policySets"] = emptyIfNil(nested)
	return out
}

// decisionStatus returns the status of the decision golden recorded under
// subCase in a directory of decision outcomes (one whose name ends in
// -outcome), and reports whether one is recorded.
func decisionStatus(root, subCase string) (int, bool, error) {
	matches, err := filepath.Glob(filepath.Join(root, "*-outcome", subCase+".json"))
	if err != nil || len(matches) == 0 {
		return 0, false, err
	}
	raw, err := os.ReadFile(matches[0])
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var out struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, false, fmt.Errorf("decode the status of %s: %w", matches[0], err)
	}
	return out.Status, true, nil
}

// dependsOnForms reports whether the decision d failed in legacy because of
// one of forms: d asks about resourceType, the type of the case, in the
// tenant of a form, legacy answered it with the status that form fails a
// decision with, and the request is well formed, so that legacy's
// validation, which also answers 400, did not refuse it first. A request
// that pins a route or is filed by order class is left out, as part A leaves
// it out.
func dependsOnForms(d ownerDecision, resourceType string, forms []exportForm, standTenant string) bool {
	req := d.request
	if valueOr(req.typ, resourceType) != resourceType || !wellFormed(req) ||
		len(req.pins) > 0 || len(req.userManagement) > 0 || req.classifyBy != "" {
		return false
	}
	tenant := decisionTenant(d, standTenant)
	for _, f := range forms {
		if valueOr(f.tenant, standTenant) == tenant && legacyFailureStatus[f.kind] == d.status {
			return true
		}
	}
	return false
}

// decisionTenant returns the tenant d is sent in: the one its request names,
// else the one its step runs in, with "" read as standTenant.
func decisionTenant(d ownerDecision, standTenant string) string {
	if d.request.tenantID != nil {
		return valueOr(*d.request.tenantID, standTenant)
	}
	return valueOr(d.tenant, standTenant)
}

// wellFormed reports whether req passes the validation legacy applies to a
// request before it evaluates any set: an operation is present, and every
// item of a bulk request names its operation or operations.
func wellFormed(req isolatedRequest) bool {
	if req.emptyOperation || req.omitOperation {
		return false
	}
	for _, v := range req.bulk {
		item, _ := v.(map[string]any)
		if asString(item["operation"]) == "" {
			return false
		}
	}
	for _, v := range req.bulkOperations {
		item, _ := v.(map[string]any)
		if len(asList(item["operations"])) == 0 {
			return false
		}
	}
	return true
}

// refusalProblem returns "" when outcome, the agent's answer to a decision,
// is 200 and allows nothing, and otherwise what it is instead.
func refusalProblem(outcome any) string {
	status, allows := 0, false
	switch o := outcome.(type) {
	case *model.CheckResourceOutcome:
		status, allows = o.Status, o.Decision
	case *model.CheckResourceBulkOutcome:
		status, allows = o.Status, o.Allowed != nil && len(*o.Allowed) > 0
	case *model.CheckResourceBulkOperationsOutcome:
		status, allows = o.Status, o.Decision != nil && anyAllowed(*o.Decision)
	case *model.FilterOutcome:
		status, allows = o.Status, filterRank(o.Result.CalculationResult) > 0
	case *model.CheckResourceV2Outcome:
		status, allows = o.Status, o.Decision
	case *model.CheckResourceBulkOperationsV2Outcome:
		status, allows = o.Status, o.Decision != nil && anyAllowed(*o.Decision)
	case *model.FilterV2Outcome:
		status, allows = o.Status, filterRank(o.Result.CalculationResult) > 0
	default:
		return fmt.Sprintf("an answer of type %T, which this test cannot judge", outcome)
	}
	raw, _ := json.Marshal(outcome)
	switch {
	case status != http.StatusOK:
		return fmt.Sprintf("status %d: %s", status, raw)
	case allows:
		return fmt.Sprintf("an allow: %s", raw)
	}
	return ""
}

func anyAllowed(decision map[string][]string) bool {
	for _, ids := range decision {
		if len(ids) > 0 {
			return true
		}
	}
	return false
}

// healthNames reports whether the body of the agent's /health names one of
// the sets of form, by policySetId or by name.
func healthNames(body string, form exportForm) bool {
	return slices.ContainsFunc(form.sets, func(s string) bool { return strings.Contains(body, s) })
}
