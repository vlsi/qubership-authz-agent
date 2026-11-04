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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Export is the configuration of every tenant that a v3 configuration export
// carries.
type Export struct {
	// Trees maps a tenant ID, exactly as the export writes it, to the tree of
	// that tenant.
	Trees map[string]*Tree
	// Failed maps a tenant ID to the reason no tree of that tenant could be
	// built. Such a tenant has no entry in Trees.
	Failed map[string]error
	// Orphans lists the elements that name no tenant, which belong to no
	// tree.
	Orphans []error
	// Dropped maps a tenant ID to what its tree leaves out by the rules of
	// [FromRegular], one line per dropped set, unknown key, isolated set, or
	// isolated PIP name, naming it and the rule.
	Dropped map[string][]string
}

// FromRegular reads the documents of GET /access/v3/config/policySets and GET
// /access/v3/config/pips into one tree per tenant. It returns an error only
// when a document is not a JSON object with the array policySets or pips; an
// element that cannot be read fails its own tenant and no other. A key
// matches a field only when spelled exactly as the export spells it, so
// "STATUS" is an unknown key. An unknown key of a set or of a PIP declaration
// that the tree reads is ignored and listed in [Export.Dropped]. A top-level
// set or a PIP declaration whose tenantId is absent, empty, or not a string is
// an orphan; inside a set, an absent or empty tenantId names no tenant.
//
// The export can show a tenant the sets and the PIP declarations of another
// tenant under its own tenantId, and nothing in the export tells them apart
// from the tenant's own. The tree keeps such an element apart instead of
// failing the tenant. A top-level set becomes [PolicySet.Isolated] when another
// top-level set of the tenant has the same policySetId, whatever the status of
// the other, or when a policy, a rule, or a nested set in it names another
// tenant. A PIP name the tenant declares more than once becomes one
// declaration with [PIP.Isolated]. Each isolation is listed in
// [Export.Dropped].
//
// Every top-level set applies except one whose status is INACTIVE, DRAFT, or
// ARCHIVED, whatever its type; a nested set applies in any status. A set of
// type SIMPLIFIED in the shape the PAP writes for simplified policies becomes
// a [SimplifiedGroup] again. That shape is a set with the target
// resourceType == 'T', never true, the algorithm DENY_UNLESS_PERMIT, and neither iterate
// nor nested sets; a policy per operation with the same algorithm and the
// target operation == 'O', or true for ALL; and, for each simplified policy of
// that operation, an ALLOW rule with the target
// subject.roles CONTAINS ANY 'r1','r2', its condition, and its predicates,
// with no customPredicate and no predicate field. Each target is
// the exact text the PAP writes, so a policy target operation == 'ALL' or
// operation EQUALS 'O' is another shape. A SIMPLIFIED set of any other shape is
// read as a regular set. A rule keeps its querydsl template in the field
// predicate; the export has no field querydslPredicate. A PIP without a
// pipType is GENERAL. A dropped set is listed in [Export.Dropped].
func FromRegular(policySets, pips []byte) (*Export, error) {
	var setsDoc struct {
		PolicySets *[]json.RawMessage `json:"policySets"`
	}
	if err := decodeExact(policySets, &setsDoc); err != nil {
		return nil, fmt.Errorf("policy sets export: %w", err)
	}
	if setsDoc.PolicySets == nil {
		return nil, errors.New("policy sets export: no policySets array")
	}
	var pipsDoc struct {
		PIPs *[]json.RawMessage `json:"pips"`
	}
	if err := decodeExact(pips, &pipsDoc); err != nil {
		return nil, fmt.Errorf("PIP export: %w", err)
	}
	if pipsDoc.PIPs == nil {
		return nil, errors.New("PIP export: no pips array")
	}

	type tenant struct {
		simplified []*SimplifiedGroup
		sets       []*PolicySet
		pips       []*PIP
		// pipCount counts the declarations of each PIP name.
		pipCount map[string]int
		// setCount counts the top-level sets of each policySetId.
		setCount map[string]int
		vars     int
		err      error
	}
	tenants := map[string]*tenant{}
	var order []string
	out := &Export{Trees: map[string]*Tree{}, Failed: map[string]error{}, Dropped: map[string][]string{}}
	get := func(kind string, i int, head *exportHead) *tenant {
		if head.TenantID == nil || *head.TenantID == "" {
			out.Orphans = append(out.Orphans, fmt.Errorf("%s %d: tenantId absent, empty, or not a string", kind, i))
			return nil
		}
		t, ok := tenants[*head.TenantID]
		if !ok {
			t = &tenant{pipCount: map[string]int{}, setCount: map[string]int{}}
			tenants[*head.TenantID] = t
			order = append(order, *head.TenantID)
		}
		return t
	}

	heads := make([]*exportHead, len(*setsDoc.PolicySets))
	for i, raw := range *setsDoc.PolicySets {
		heads[i] = readHead(raw)
		if t := get("policy set", i, heads[i]); t != nil {
			t.setCount[heads[i].ID]++
		}
	}
	for i, raw := range *setsDoc.PolicySets {
		head := heads[i]
		if head.TenantID == nil || *head.TenantID == "" {
			continue
		}
		t := tenants[*head.TenantID]
		if t.err != nil {
			continue
		}
		if !topLevelApplies(head.Status) {
			id := *head.TenantID
			out.Dropped[id] = append(out.Dropped[id], fmt.Sprintf("policy set %d %q: status %s", i, head.ID, head.Status))
			continue
		}
		var s exportSet
		unknown, err := decodeReporting(raw, &s)
		if err != nil {
			t.err = fmt.Errorf("policy set %d: %w", i, err)
			continue
		}
		for _, key := range unknown {
			id := *head.TenantID
			out.Dropped[id] = append(out.Dropped[id], fmt.Sprintf("policy set %d %q: unknown key %s", i, head.ID, key))
		}
		reason := ""
		if n := t.setCount[head.ID]; n > 1 {
			reason = fmt.Sprintf("the tenant has %d top-level sets with this policySetId", n)
		} else {
			reason = foreignElement(&s, *head.TenantID)
		}
		if reason != "" {
			id := *head.TenantID
			out.Dropped[id] = append(out.Dropped[id], fmt.Sprintf("policy set %d %q: isolated: %s", i, head.ID, reason))
			t.sets = append(t.sets, &PolicySet{
				ID: s.PolicySetID, Name: s.Name, Domain: s.Domain, ExternalID: s.ExternalID,
				Target: condition(s.Target, PlaceSetTarget, ""), Isolated: reason,
			})
			continue
		}
		if g, ok := simplifiedGroup(&s); ok {
			t.simplified = append(t.simplified, g)
			continue
		}
		b := setBuilder{vars: &t.vars}
		ps, err := b.set(&s, "")
		if err != nil {
			t.err = fmt.Errorf("policy set %q: %w", s.PolicySetID, err)
			continue
		}
		t.sets = append(t.sets, ps)
	}
	for i, raw := range *pipsDoc.PIPs {
		head := readHead(raw)
		t := get("pip", i, head)
		if t == nil || t.err != nil {
			continue
		}
		p, unknown, err := readPIP(raw)
		if err != nil {
			t.err = fmt.Errorf("pip %d: %w", i, err)
			continue
		}
		for _, key := range unknown {
			id := *head.TenantID
			out.Dropped[id] = append(out.Dropped[id], fmt.Sprintf("pip %d %q: unknown key %s", i, p.Name, key))
		}
		t.pips = append(t.pips, p)
		t.pipCount[p.Name]++
	}
	for _, id := range order {
		t := tenants[id]
		if t.err != nil {
			out.Failed[id] = t.err
			delete(out.Dropped, id)
			continue
		}
		pips := t.pips[:0:0]
		for _, p := range t.pips {
			switch n := t.pipCount[p.Name]; {
			case n == 1:
				pips = append(pips, p)
			case n > 1:
				reason := fmt.Sprintf("declared %d times", n)
				out.Dropped[id] = append(out.Dropped[id], fmt.Sprintf("pip %q: isolated: %s", p.Name, reason))
				pips = append(pips, &PIP{Name: p.Name, Isolated: reason})
				t.pipCount[p.Name] = 0
			}
		}
		tree, err := NewTree(t.simplified, t.sets, pips)
		if err != nil {
			out.Failed[id] = err
			delete(out.Dropped, id)
			continue
		}
		out.Trees[id] = tree
	}
	return out, nil
}

// exportHead is what [FromRegular] reads of an element before the element
// itself: the tenant, and the ID and status of a set.
type exportHead struct {
	TenantID *string
	ID       string
	Status   string
}

// readHead reads the head of raw. A field of the wrong type reads as absent,
// so a set whose status is not a string fails its tenant when the set itself
// is read.
func readHead(raw json.RawMessage) *exportHead {
	var fields struct {
		TenantID    json.RawMessage `json:"tenantId"`
		PolicySetID json.RawMessage `json:"policySetId"`
		Status      json.RawMessage `json:"status"`
	}
	h := &exportHead{}
	if decodeExact(raw, &fields) != nil {
		return h
	}
	var tenant string
	if json.Unmarshal(fields.TenantID, &tenant) == nil && !isNull(fields.TenantID) {
		h.TenantID = &tenant
	}
	_ = json.Unmarshal(fields.PolicySetID, &h.ID)
	_ = json.Unmarshal(fields.Status, &h.Status)
	return h
}

// topLevelApplies reports whether a top-level set of status applies: every
// status except INACTIVE, DRAFT, and ARCHIVED, including an absent one.
func topLevelApplies(status string) bool {
	switch status {
	case "INACTIVE", "DRAFT", "ARCHIVED":
		return false
	default:
		return true
	}
}

type exportSet struct {
	TenantID           *string        `json:"tenantId"`
	PolicySetID        string         `json:"policySetId"`
	Name               string         `json:"name"`
	Type               string         `json:"type"`
	Domain             string         `json:"domain"`
	Component          *string        `json:"component"`
	Status             string         `json:"status"`
	Target             *string        `json:"target"`
	CombiningAlgorithm string         `json:"combiningAlgorithm"`
	Iterate            *exportIterate `json:"iterate"`
	Policies           []exportPolicy `json:"policies"`
	PolicySets         []exportSet    `json:"policySets"`
	ExternalID         string         `json:"externalId"`
}

// ignoredKeys lists the legacy keys of a set that the export carries and no
// decision reads; the reader skips them without listing them as unknown. The
// ignoredKeys methods of exportPolicy, exportRule, and exportPIP do the same
// for their types.
func (exportSet) ignoredKeys() []string {
	return []string{"description", "deprecated", "uiTarget", "previousStatus"}
}

type exportIterate struct {
	Foreach            string `json:"foreach"`
	CombiningAlgorithm string `json:"combiningAlgorithm"`
}

type exportPolicy struct {
	TenantID           *string      `json:"tenantId"`
	PolicyID           string       `json:"policyId"`
	Name               string       `json:"name"`
	Target             *string      `json:"target"`
	CombiningAlgorithm string       `json:"combiningAlgorithm"`
	Rules              []exportRule `json:"rules"`
}

func (exportPolicy) ignoredKeys() []string { return []string{"description", "deprecated", "uiTarget"} }

type exportRule struct {
	TenantID         *string       `json:"tenantId"`
	RuleID           string        `json:"ruleId"`
	Name             string        `json:"name"`
	RuleType         string        `json:"ruleType"`
	Target           *string       `json:"target"`
	Condition        *string       `json:"condition"`
	Effect           string        `json:"effect"`
	RSQLPredicate    string        `json:"rsqlPredicate"`
	SQLPredicate     string        `json:"sqlPredicate"`
	MongoDBPredicate string        `json:"mongodbPredicate"`
	Predicate        string        `json:"predicate"`
	CustomPredicate  *exportCustom `json:"customPredicate"`
}

func (exportRule) ignoredKeys() []string {
	return []string{"description", "deprecated", "uiTarget", "uiCondition"}
}

type exportCustom struct {
	Predicate string                     `json:"predicate"`
	Params    map[string]json.RawMessage `json:"params"`
}

const ruleTypeFrontend = "APPLICABLE_FOR_FRONTEND"

// condition parses text at place, and turns text the parser refuses into a
// condition of one [Unsupported] atom of [FormSyntax].
func condition(text *string, place Place, iterVar string) *Condition {
	if text == nil {
		return nil
	}
	c, err := ParseCondition(*text, place, iterVar)
	if err != nil {
		return &Condition{Place: place, Disjuncts: [][]Atom{{Unsupported{Form: FormSyntax, Text: *text}}}}
	}
	return c
}

func algorithmOf(a string) (Algorithm, error) {
	if !slices.Contains(algorithms, Algorithm(a)) {
		return "", fmt.Errorf("combiningAlgorithm %q unknown", a)
	}
	return Algorithm(a), nil
}

type setBuilder struct {
	vars *int
}

// foreignElement names the first policy, rule, or nested set in s whose
// tenantId names a tenant other than tenant, or returns empty when there is
// none. An empty tenantId names no tenant.
func foreignElement(s *exportSet, tenant string) string {
	foreign := func(id *string) bool { return id != nil && *id != "" && *id != tenant }
	for i := range s.Policies {
		p := &s.Policies[i]
		if foreign(p.TenantID) {
			return fmt.Sprintf("policy %q has tenantId %q", p.PolicyID, *p.TenantID)
		}
		for j := range p.Rules {
			if r := &p.Rules[j]; foreign(r.TenantID) {
				return fmt.Sprintf("rule %q has tenantId %q", r.RuleID, *r.TenantID)
			}
		}
	}
	for i := range s.PolicySets {
		k := &s.PolicySets[i]
		if foreign(k.TenantID) {
			return fmt.Sprintf("policy set %q has tenantId %q", k.PolicySetID, *k.TenantID)
		}
		if reason := foreignElement(k, tenant); reason != "" {
			return reason
		}
	}
	return ""
}

// set builds s. iterVar is the var of the innermost iterate around s, which
// its own target reads; its children read the var of its own iterate.
func (b setBuilder) set(s *exportSet, iterVar string) (*PolicySet, error) {
	alg, err := algorithmOf(s.CombiningAlgorithm)
	if err != nil {
		return nil, err
	}
	ps := &PolicySet{
		ID: s.PolicySetID, Name: s.Name, Domain: s.Domain, ExternalID: s.ExternalID, Algorithm: alg,
		Target: condition(s.Target, PlaceSetTarget, iterVar),
	}
	inner := iterVar
	if it := s.Iterate; it != nil {
		ia, err := algorithmOf(it.CombiningAlgorithm)
		switch {
		case it.Foreach != "subject.permissionScope":
			ps.AlwaysFails = fmt.Sprintf("iterate foreach %q", it.Foreach)
		case it.CombiningAlgorithm == "":
			ps.AlwaysFails = "iterate without a combiningAlgorithm"
		case err != nil:
			ps.AlwaysFails = "iterate " + err.Error()
		default:
			*b.vars++
			inner = fmt.Sprintf("iterate%d", *b.vars)
			ps.Iterate = &Iterate{Var: inner, Algorithm: ia}
		}
		if ps.AlwaysFails != "" {
			return ps, nil
		}
	}
	for i := range s.Policies {
		p, err := b.policy(&s.Policies[i], inner)
		if err != nil {
			return nil, within(fmt.Sprintf("policy %q", s.Policies[i].PolicyID), err)
		}
		ps.Policies = append(ps.Policies, p)
	}
	for i := range s.PolicySets {
		k, err := b.set(&s.PolicySets[i], inner)
		if err != nil {
			return nil, within(fmt.Sprintf("policy set %q", s.PolicySets[i].PolicySetID), err)
		}
		ps.Sets = append(ps.Sets, k)
	}
	return ps, nil
}

// nodeError is an error inside a policy or a nested set. labels name the nodes
// that hold it, innermost first, and Error prints them outermost first, each
// followed by ": ", as wrapping err once per node would. The labels are
// collected rather than wrapped so that an error from a deep chain of sets is
// formatted once instead of once per level.
type nodeError struct {
	labels []string
	err    error
}

func (e *nodeError) Error() string {
	var b strings.Builder
	for _, l := range slices.Backward(e.labels) {
		b.WriteString(l)
		b.WriteString(": ")
	}
	b.WriteString(e.err.Error())
	return b.String()
}

func (e *nodeError) Unwrap() error { return e.err }

// within returns err as an error inside the node label: err itself, with label
// added, when err already is a *nodeError.
func within(label string, err error) error {
	if e, ok := err.(*nodeError); ok {
		e.labels = append(e.labels, label)
		return e
	}
	return &nodeError{labels: []string{label}, err: err}
}

func (b setBuilder) policy(p *exportPolicy, iterVar string) (*Policy, error) {
	alg, err := algorithmOf(p.CombiningAlgorithm)
	if err != nil {
		return nil, err
	}
	out := &Policy{
		ID: p.PolicyID, Name: p.Name, Algorithm: alg,
		Target: condition(p.Target, PlacePolicyTarget, iterVar),
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !slices.Contains(effects, Effect(r.Effect)) {
			return nil, fmt.Errorf("rule %q: effect %q unknown", r.RuleID, r.Effect)
		}
		preds := predicates(r)
		out.Rules = append(out.Rules, &Rule{
			ID: r.RuleID, Name: r.Name, Effect: Effect(r.Effect),
			Frontend:   r.RuleType == ruleTypeFrontend,
			Target:     condition(r.Target, PlaceRuleTarget, iterVar),
			Condition:  condition(r.Condition, PlaceRuleCondition, iterVar),
			Predicates: preds,
		})
	}
	return out, nil
}

// predicates reads the predicates of r. The field predicate is the template of
// the querydsl dialect, which only a rule of a regular set has.
func predicates(r *exportRule) Predicates {
	var p Predicates
	for d, text := range map[Dialect]string{
		DialectRSQL: r.RSQLPredicate, DialectSQL: r.SQLPredicate, DialectMongoDB: r.MongoDBPredicate,
		DialectQueryDSL: r.Predicate,
	} {
		if text != "" {
			if p.Text == nil {
				p.Text = map[Dialect]string{}
			}
			p.Text[d] = text
		}
	}
	if c := r.CustomPredicate; c != nil {
		cp := &CustomPredicate{Predicate: c.Predicate}
		for k, v := range c.Params {
			if cp.Params == nil {
				cp.Params = map[string]string{}
			}
			cp.Params[k] = compact(v)
		}
		p.Custom = cp
	}
	return p
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return string(raw)
	}
	return b.String()
}

// simplifiedGroup returns the simplified policies s holds, and false when s is
// not a set of type SIMPLIFIED in the shape the PAP writes for them.
func simplifiedGroup(s *exportSet) (*SimplifiedGroup, bool) {
	if s.Type != "SIMPLIFIED" || s.Iterate != nil || len(s.PolicySets) > 0 || s.Target == nil ||
		s.CombiningAlgorithm != string(AlgorithmDenyUnlessPermit) {
		return nil, false
	}
	rt, ok := onlyEquality(*s.Target, ResourceType{})
	if !ok || *s.Target != resourceTypeTarget(rt) {
		return nil, false
	}
	g := &SimplifiedGroup{
		ID: s.PolicySetID, Name: s.Name, ExternalID: s.ExternalID, Domain: s.Domain, ResourceType: rt,
	}
	if s.Component != nil {
		g.Component = *s.Component
	}
	for _, p := range s.Policies {
		if p.Target == nil || p.CombiningAlgorithm != string(AlgorithmDenyUnlessPermit) {
			return nil, false
		}
		op := "ALL"
		if *p.Target != "true" {
			if op, ok = onlyEquality(*p.Target, Operation{}); !ok || *p.Target != operationTarget(op) {
				return nil, false
			}
		}
		for i := range p.Rules {
			r := &p.Rules[i]
			if r.Effect != string(EffectAllow) || r.Predicate != "" || r.CustomPredicate != nil ||
				r.Target == nil {
				return nil, false
			}
			roles, ok := rolesOf(*r.Target)
			if !ok || *r.Target != rolesTarget(roles) {
				return nil, false
			}
			preds := predicates(r)
			g.Policies = append(g.Policies, &SimplifiedPolicy{
				ID: r.RuleID, Frontend: r.RuleType == ruleTypeFrontend, Operation: op, Roles: roles,
				Condition: condition(r.Condition, PlaceSimplified, ""), Predicates: preds,
			})
		}
	}
	return g, true
}

// resourceTypeTarget is the set target the PAP writes for the simplified
// policies of resource type rt. For a global simplified policy the PAP writes
// true instead.
func resourceTypeTarget(rt string) string {
	return "resourceType == '" + rt + "'"
}

// operationTarget is the policy target the PAP writes for the simplified
// policies of operation op. For ALL it is true, never operation == 'ALL'.
func operationTarget(op string) string {
	if op == "ALL" {
		return "true"
	}
	return "operation == '" + op + "'"
}

// rolesTarget is the rule target the PAP writes for a simplified policy of
// roles.
func rolesTarget(roles []string) string {
	return "subject.roles CONTAINS ANY '" + strings.Join(roles, "','") + "'"
}

// onlyEquality returns the string s in text when text is exactly left == 's'.
func onlyEquality(text string, left Operand) (string, bool) {
	c, err := ParseCondition(text, PlaceSetTarget, "")
	if err != nil || len(c.Disjuncts) != 1 || len(c.Disjuncts[0]) != 1 {
		return "", false
	}
	cmp, ok := c.Disjuncts[0][0].(Compare)
	if !ok || cmp.Op != OpEQ || cmp.Left != left {
		return "", false
	}
	s, ok := cmp.Right.(String)
	return s.Value, ok
}

// rolesOf returns the roles of text when text is exactly
// subject.roles CONTAINS ANY 'r1','r2'.
func rolesOf(text string) ([]string, bool) {
	c, err := ParseCondition(text, PlaceRuleTarget, "")
	if err != nil || len(c.Disjuncts) != 1 || len(c.Disjuncts[0]) != 1 {
		return nil, false
	}
	cmp, ok := c.Disjuncts[0][0].(Compare)
	if !ok || cmp.Op != OpContainsAny || cmp.Left != (Subject{Attr: SubjectRoles}) {
		return nil, false
	}
	list, ok := cmp.Right.(List)
	if !ok {
		return nil, false
	}
	roles := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		s, ok := it.(String)
		if !ok {
			return nil, false
		}
		roles = append(roles, s.Value)
	}
	return roles, true
}

type exportPIP struct {
	TenantID          *string                    `json:"tenantId"`
	Name              *string                    `json:"name"`
	PipType           string                     `json:"pipType"`
	Type              string                     `json:"type"`
	Domain            string                     `json:"domain"`
	URL               string                     `json:"url"`
	HTTPMethod        string                     `json:"httpMethod"`
	Header            string                     `json:"header"`
	Claim             string                     `json:"claim"`
	BeanName          string                     `json:"beanName"`
	JSONPath          string                     `json:"jsonPath"`
	ResourceType      string                     `json:"resourceType"`
	DefaultValue      json.RawMessage            `json:"defaultValue"`
	Headers           json.RawMessage            `json:"headers"`
	RequestAttributes map[string]json.RawMessage `json:"requestAttributes"`
	ProductMapping    json.RawMessage            `json:"productMapping"`
	CustomMapping     json.RawMessage            `json:"customMapping"`
	Cacheable         json.RawMessage            `json:"cacheable"`
	CachePeriod       json.RawMessage            `json:"cachePeriod"`

	// The fields of the agent's own PIP extension, which the legacy service
	// does not have.
	Query          json.RawMessage `json:"query"`
	Body           json.RawMessage `json:"body"`
	TimeoutSeconds json.RawMessage `json:"timeoutSeconds"`
	Response       json.RawMessage `json:"response"`
}

func (exportPIP) ignoredKeys() []string { return []string{"description", "deprecated"} }

// readPIP reads one PIP declaration of the export, and returns the paths of
// the unknown keys it ignores.
func readPIP(raw json.RawMessage) (p *PIP, unknown []string, err error) {
	var e exportPIP
	if unknown, err = decodeReporting(raw, &e); err != nil {
		return nil, nil, err
	}
	if e.Name == nil {
		return nil, nil, errors.New("no name")
	}
	p = &PIP{
		Name: *e.Name, Type: PIPType(e.PipType), ReturnType: e.Type, Domain: e.Domain, URL: e.URL,
		HTTPMethod: e.HTTPMethod, Header: e.Header, Claim: e.Claim, BeanName: e.BeanName, JSONPath: e.JSONPath,
		ResourceType: e.ResourceType, DefaultValue: present(e.DefaultValue),
		ProductMapping: present(e.ProductMapping), CustomMapping: present(e.CustomMapping),
		Cacheable: present(e.Cacheable), CachePeriod: present(e.CachePeriod),
	}
	if p.Type == "" {
		p.Type = PIPGeneral
	}
	if !slices.Contains(pipTypes, p.Type) {
		return nil, nil, fmt.Errorf("%q: pipType %q unknown", p.Name, p.Type)
	}
	var unsupported []string
	switch h := present(e.Headers); {
	case h == "":
	case strings.HasPrefix(h, `"`):
		if err := json.Unmarshal(e.Headers, &p.Headers); err != nil {
			return nil, nil, fmt.Errorf("%q: headers: %w", p.Name, err)
		}
	case strings.HasPrefix(h, "["):
		var names []string
		if err := json.Unmarshal(e.Headers, &names); err != nil {
			return nil, nil, fmt.Errorf("%q: headers: %w", p.Name, err)
		}
		p.Headers = strings.Join(names, ",")
	case strings.HasPrefix(h, "{"):
		unsupported = append(unsupported, "headers object")
	default:
		return nil, nil, fmt.Errorf("%q: headers %s is neither a string, a list, nor an object", p.Name, h)
	}
	if e.RequestAttributes != nil {
		p.RequestAttributes = make(map[string]string, len(e.RequestAttributes))
	}
	for k, v := range e.RequestAttributes {
		p.RequestAttributes[k] = compact(v)
	}
	for _, f := range []struct {
		name string
		raw  json.RawMessage
	}{{"query", e.Query}, {"body", e.Body}, {"timeoutSeconds", e.TimeoutSeconds}, {"response", e.Response}} {
		if present(f.raw) != "" {
			unsupported = append(unsupported, f.name)
		}
	}
	p.Unsupported = strings.Join(unsupported, ", ")
	return p, unknown, nil
}

// present returns raw as compact JSON, or empty when raw is absent or null:
// the export writes an absent field as null.
func present(raw json.RawMessage) string {
	if len(raw) == 0 || isNull(raw) {
		return ""
	}
	return compact(raw)
}

// decodeExact decodes data into v as [json.Unmarshal] does, except that an
// object key fills a struct field only when it equals the field's JSON name:
// json.Unmarshal also matches a key that differs in letter case. Any other key
// is ignored, as an unknown key is, and of a key written twice in one object
// the last value counts. The time is linear in the length of data, however
// deep the objects nest.
func decodeExact(data []byte, v any) error {
	_, err := decodeReporting(data, v)
	return err
}

// decodeReporting decodes data into v as [decodeExact] does, and returns the
// path of each key it ignores, such as policies[0].rules[1].querydslPredicate,
// in the order the keys appear.
func decodeReporting(data []byte, v any) (unknown []string, err error) {
	if !json.Valid(data) {
		return nil, json.Unmarshal(data, v)
	}
	f := exactFilter{data: data, ends: containerEnds(data), fields: map[reflect.Type][]exactField{}}
	f.value(skipSpace(data, 0), reflect.TypeOf(v), nil)
	if err := json.Unmarshal(f.out.Bytes(), v); err != nil {
		return nil, err
	}
	slices.SortFunc(f.unknown, func(a, b unknownKey) int { return a.at - b.at })
	for _, k := range f.unknown {
		unknown = append(unknown, k.path)
	}
	return unknown, nil
}

// keyPath is the position of a value in a JSON document, held as its last step
// and a link to the position of the value that holds it. A nil keyPath is the
// document itself.
type keyPath struct {
	parent *keyPath
	key    string // the member key, for a member
	index  int    // the element index, for an array element
	elem   bool   // whether the step is an array element
}

// String returns the path as keys joined by dots, with each array index in
// brackets: policies[0].rules[1].name.
func (p *keyPath) String() string {
	var steps []*keyPath
	for ; p != nil; p = p.parent {
		steps = append(steps, p)
	}
	var b strings.Builder
	for _, s := range slices.Backward(steps) {
		switch {
		case s.elem:
			fmt.Fprintf(&b, "[%d]", s.index)
		case b.Len() > 0:
			b.WriteString("." + s.key)
		default:
			b.WriteString(s.key)
		}
	}
	return b.String()
}

var rawMessageType = reflect.TypeFor[json.RawMessage]()

// exactFilter writes data, valid JSON, to out with every object key dropped
// that no struct field of the target type, or of the types it holds, names
// exactly. Values it keeps are written as they are, with whitespace outside
// strings removed.
type exactFilter struct {
	data []byte
	// ends maps the offset of each { and [ in data to the offset just past
	// the bracket that closes it, so a value is skipped without reading it.
	ends   map[int]int
	fields map[reflect.Type][]exactField
	out    bytes.Buffer
	// unknown holds the path of each key the filter dropped.
	unknown []unknownKey
}

// unknownKey is a key the filter dropped: its offset in data and its path.
type unknownKey struct {
	at   int
	path string
}

// exactField is a struct field that a JSON key fills.
type exactField struct {
	name string
	typ  reflect.Type
}

// value writes the value at offset i, which stands at path at, filtered for
// type t.
func (f *exactFilter) value(i int, t reflect.Type, at *keyPath) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t.Kind() == reflect.Struct && f.data[i] == '{':
		f.object(i, t, at)
	case t.Kind() == reflect.Slice && t != rawMessageType && f.data[i] == '[':
		f.array(i, t.Elem(), at)
	default:
		// The value is valid JSON, so Compact cannot fail.
		_ = json.Compact(&f.out, f.data[i:f.valueEnd(i)])
	}
}

// object writes the object at offset i with the members whose key names a
// field of t, the last member of each such key only, and records the path of
// every other key.
func (f *exactFilter) object(i int, t reflect.Type, at *keyPath) {
	fields := f.fieldsOf(t)
	last := make([]int, len(fields))
	for k := range last {
		last[k] = -1
	}
	for j := skipSpace(f.data, i+1); f.data[j] != '}'; {
		keyEnd := stringEnd(f.data, j)
		name := f.key(j, keyEnd)
		j = skipSpace(f.data, skipSpace(f.data, keyEnd)+1)
		if k := slices.IndexFunc(fields, func(e exactField) bool { return e.name == name }); k >= 0 {
			last[k] = j
		} else if !slices.Contains(ignoredKeysOf(t), name) {
			f.unknown = append(f.unknown, unknownKey{at: j, path: (&keyPath{parent: at, key: name}).String()})
		}
		j = f.next(j)
	}
	f.out.WriteByte('{')
	first := true
	for k, j := range last {
		if j < 0 {
			continue
		}
		if !first {
			f.out.WriteByte(',')
		}
		first = false
		f.out.WriteString(`"` + fields[k].name + `":`)
		f.value(j, fields[k].typ, &keyPath{parent: at, key: fields[k].name})
	}
	f.out.WriteByte('}')
}

// array writes the array at offset i with each element filtered for elem.
func (f *exactFilter) array(i int, elem reflect.Type, at *keyPath) {
	f.out.WriteByte('[')
	start := skipSpace(f.data, i+1)
	for j, n := start, 0; f.data[j] != ']'; j, n = f.next(j), n+1 {
		if j != start {
			f.out.WriteByte(',')
		}
		f.value(j, elem, &keyPath{parent: at, index: n, elem: true})
	}
	f.out.WriteByte(']')
}

// next returns the offset of the member or element after the value at offset
// i, or of the bracket that closes the container.
func (f *exactFilter) next(i int) int {
	j := skipSpace(f.data, f.valueEnd(i))
	if f.data[j] == ',' {
		j = skipSpace(f.data, j+1)
	}
	return j
}

// key returns the object key whose quoted text spans data[start:end], with
// its escapes decoded.
func (f *exactFilter) key(start, end int) string {
	raw := f.data[start:end]
	if !bytes.ContainsRune(raw, '\\') {
		return string(raw[1 : len(raw)-1])
	}
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// valueEnd returns the offset just past the value at offset i.
func (f *exactFilter) valueEnd(i int) int {
	switch f.data[i] {
	case '{', '[':
		return f.ends[i]
	case '"':
		return stringEnd(f.data, i)
	}
	j := i
	for j < len(f.data) && !bytes.ContainsRune([]byte(",]} \t\n\r"), rune(f.data[j])) {
		j++
	}
	return j
}

// ignoredKeysOf returns the keys that t, an export type, skips without listing
// them as unknown.
func ignoredKeysOf(t reflect.Type) []string {
	if k, ok := reflect.Zero(t).Interface().(interface{ ignoredKeys() []string }); ok {
		return k.ignoredKeys()
	}
	return nil
}

// fieldsOf returns the fields of the struct type t that a JSON key fills,
// sorted by name. The kept members are written in that order, so of two
// members json.Unmarshal cannot decode it reports the one whose key sorts
// first.
func (f *exactFilter) fieldsOf(t reflect.Type) []exactField {
	if fields, ok := f.fields[t]; ok {
		return fields
	}
	var fields []exactField
	for i := range t.NumField() {
		sf := t.Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if sf.IsExported() && name != "" && name != "-" {
			fields = append(fields, exactField{name: name, typ: sf.Type})
		}
	}
	slices.SortFunc(fields, func(a, b exactField) int { return strings.Compare(a.name, b.name) })
	f.fields[t] = fields
	return fields
}

// containerEnds maps the offset of each { and [ in data, valid JSON, to the
// offset just past the bracket that closes it.
func containerEnds(data []byte) map[int]int {
	ends := map[int]int{}
	var open []int
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			i = stringEnd(data, i) - 1
		case '{', '[':
			open = append(open, i)
		case '}', ']':
			ends[open[len(open)-1]] = i + 1
			open = open[:len(open)-1]
		}
	}
	return ends
}

// stringEnd returns the offset just past the string that starts at
// data[start], valid JSON.
func stringEnd(data []byte, start int) int {
	i := start + 1
	for data[i] != '"' {
		if data[i] == '\\' {
			i++
		}
		i++
	}
	return i + 1
}

// skipSpace returns the offset of the first byte at or after i that is not
// JSON whitespace.
func skipSpace(data []byte, i int) int {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return i
}
