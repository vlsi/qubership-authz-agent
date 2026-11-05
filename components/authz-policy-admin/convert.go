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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ── Simplified input types ────────────────────────────────────────────────────

// simplifiedPolicy is an access-control simplified policy, with the fields
// the stub uses for v3 export conversion.
//
// Predicate is not a field of an access-control simplified policy: it is the
// querydsl template that access-control keeps in the predicate field of a v3
// rule. The stub accepts it here and writes it to the v3 rule unchanged, so a
// test can deliver a querydsl predicate without a regular policy set, which
// the stub has no endpoint for.
type simplifiedPolicy struct {
	// Tenant is the tenant that uploaded the policy, from the request.
	Tenant           string `json:"-"`
	Component        string `json:"component"`
	ResourceType     string `json:"resourceType"`
	Operation        string `json:"operation"`
	Condition        any    `json:"condition,omitempty"`
	RSQLPredicate    string `json:"rsqlPredicate,omitempty"`
	SQLPredicate     string `json:"sqlPredicate,omitempty"`
	MongoDBPredicate string `json:"mongodbPredicate,omitempty"`
	Predicate        string `json:"predicate,omitempty"`
	Roles            []any  `json:"roles,omitempty"`
}

// simplifiedPIP is an access-control simplified PIP, with the fields the
// stub uses for v3 export conversion.
type simplifiedPIP struct {
	// Tenant is the tenant that uploaded the PIP, from the request.
	Tenant            string            `json:"-"`
	Name              string            `json:"name"`
	PipType           string            `json:"pipType,omitempty"`
	URL               string            `json:"url,omitempty"`
	HTTPMethod        string            `json:"httpMethod,omitempty"`
	Header            string            `json:"header,omitempty"`
	Claim             string            `json:"claim,omitempty"`
	BeanName          string            `json:"beanName,omitempty"`
	DefaultValue      json.RawMessage   `json:"defaultValue,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	RequestAttributes map[string]string `json:"requestAttributes,omitempty"`
	Headers           json.RawMessage   `json:"headers,omitempty"`
	Type              string            `json:"type,omitempty"`
	JsonPath          string            `json:"jsonPath,omitempty"`

	// ── PDP contract extension (authz-agent-ADR-0066..0069) ──────────────
	// These four fields do NOT exist in access-control: its authoritative
	// PolicyInformationPointJson has no query/body/timeoutSeconds/response, and
	// its thick client sends requestAttributes as the body, extracts with
	// jsonPath and applies one global timeout. They are authz-agent's
	// generalisation of PIP invocation.
	//
	// The stub carries them anyway, deliberately: it is the only policy source a
	// test can drive end to end, and without them the extension has no delivery
	// path to be tested over. That makes the stub a SUPERSET of access-control
	// here — an intentional divergence, and the one place in this repo where the
	// stub is knowingly not a faithful double. Anything asserted through these
	// fields proves the agent works, not that access-control would agree.
	//
	// Kept as raw JSON where the shape is polymorphic so the stub neither
	// validates nor reshapes them: it is a pipe, and the agent owns the contract.
	Query          map[string]string `json:"query,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
	TimeoutSeconds *int              `json:"timeoutSeconds,omitempty"`
	Response       json.RawMessage   `json:"response,omitempty"`
}

// ── V3 export shapes ──────────────────────────────────────────────────────────

type v3PolicySetsResponse struct {
	Hash                      string        `json:"hash"`
	LastModificationTimestamp string        `json:"lastModificationTimestamp"`
	PolicySets                []v3PolicySet `json:"policySets"`
}

type v3PolicySet struct {
	PolicySetID        string     `json:"policySetId"`
	Name               string     `json:"name"`
	Type               string     `json:"type"`
	Domain             string     `json:"domain"`
	Status             string     `json:"status"`
	Target             string     `json:"target"`
	CombiningAlgorithm string     `json:"combiningAlgorithm"`
	TenantID           string     `json:"tenantId"`
	Policies           []v3Policy `json:"policies"`
}

type v3Policy struct {
	PolicyID           string   `json:"policyId"`
	Target             string   `json:"target"`
	CombiningAlgorithm string   `json:"combiningAlgorithm"`
	Rules              []v3Rule `json:"rules"`
}

type v3Rule struct {
	RuleID           string  `json:"ruleId"`
	Name             string  `json:"name"`
	Target           string  `json:"target"`
	Condition        *string `json:"condition"`
	Effect           string  `json:"effect"`
	RSQLPredicate    string  `json:"rsqlPredicate,omitempty"`
	SQLPredicate     string  `json:"sqlPredicate,omitempty"`
	MongoDBPredicate string  `json:"mongodbPredicate,omitempty"`
	Predicate        string  `json:"predicate,omitempty"`
}

type v3PIPsResponse struct {
	Hash                      string  `json:"hash"`
	LastModificationTimestamp string  `json:"lastModificationTimestamp"`
	PIPs                      []v3PIP `json:"pips"`
}

type v3PIP struct {
	Name              string            `json:"name"`
	PipType           string            `json:"pipType"`
	URL               string            `json:"url,omitempty"`
	HTTPMethod        string            `json:"httpMethod,omitempty"`
	Header            string            `json:"header,omitempty"`
	Claim             string            `json:"claim,omitempty"`
	BeanName          string            `json:"beanName,omitempty"`
	DefaultValue      json.RawMessage   `json:"defaultValue,omitempty"`
	Domain            string            `json:"domain"`
	TenantID          string            `json:"tenantId"`
	Type              string            `json:"type,omitempty"`
	JsonPath          string            `json:"jsonPath,omitempty"`
	RequestAttributes map[string]string `json:"requestAttributes,omitempty"`
	Headers           json.RawMessage   `json:"headers,omitempty"`

	// Extension fields, mirrored from the northbound shape — see the note on
	// simplifiedPIP. Real access-control never emits these.
	Query          map[string]string `json:"query,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
	TimeoutSeconds *int              `json:"timeoutSeconds,omitempty"`
	Response       json.RawMessage   `json:"response,omitempty"`
}

// ── Conversion: simplified → v3 ──────────────────────────────────────────────

// toV3PolicySets converts simplified policies into v3 policy sets.
// Policies are grouped by (component, resourceType) → PolicySet,
// then by (roles) → Policy, then each (operation, condition, rsqlPredicate)
// becomes one Rule.  This mirrors what access-control creates when a SIMPLIFIED
// policy is uploaded via the simplified API.
func toV3PolicySets(items []simplifiedPolicy, defaultTenantID string) []v3PolicySet {
	// Group by (domain/component, resourceType).
	type psKey struct{ tenant, domain, resourceType string }
	type pKey struct{ roles string }
	type ruleVal struct {
		operation        string
		condition        string
		rsqlPredicate    string
		sqlPredicate     string
		mongodbPredicate string
		predicate        string
	}

	// Collect in insertion order.
	var psOrder []psKey
	psMap := make(map[psKey]map[pKey][]ruleVal)

	for _, p := range items {
		pk := psKey{tenant: exportTenant(p.Tenant, defaultTenantID), domain: p.Component, resourceType: p.ResourceType}
		if _, seen := psMap[pk]; !seen {
			psOrder = append(psOrder, pk)
			psMap[pk] = make(map[pKey][]ruleVal)
		}
		rk := pKey{roles: rolesKey(p.Roles)}
		psMap[pk][rk] = append(psMap[pk][rk], ruleVal{
			operation:        p.Operation,
			condition:        conditionString(p.Condition),
			rsqlPredicate:    p.RSQLPredicate,
			sqlPredicate:     p.SQLPredicate,
			mongodbPredicate: p.MongoDBPredicate,
			predicate:        p.Predicate,
		})
	}

	result := make([]v3PolicySet, 0, len(psMap))
	for _, pk := range psOrder {
		policyMap := psMap[pk]

		// Sort policy keys for deterministic output.
		var pKeys []pKey
		for k := range policyMap {
			pKeys = append(pKeys, k)
		}
		sort.Slice(pKeys, func(i, j int) bool { return pKeys[i].roles < pKeys[j].roles })

		var v3Policies []v3Policy
		for pi, prk := range pKeys {
			rules := policyMap[prk]
			var v3Rules []v3Rule
			for ri, rule := range rules {
				target := operationTarget(rule.operation)
				var condPtr *string
				if rule.condition != "" {
					c := rule.condition
					condPtr = &c
				}
				v3Rules = append(v3Rules, v3Rule{
					RuleID:           fmt.Sprintf("rule-%d-%d", pi, ri),
					Name:             fmt.Sprintf("rule-%s-%s", rule.operation, rule.condition),
					Target:           target,
					Condition:        condPtr,
					Effect:           "ALLOW",
					RSQLPredicate:    rule.rsqlPredicate,
					SQLPredicate:     rule.sqlPredicate,
					MongoDBPredicate: rule.mongodbPredicate,
					Predicate:        rule.predicate,
				})
			}
			policyTarget := rolesTarget(prk.roles)
			v3Policies = append(v3Policies, v3Policy{
				PolicyID:           fmt.Sprintf("policy-%d", pi),
				Target:             policyTarget,
				CombiningAlgorithm: "DENY_UNLESS_PERMIT",
				Rules:              v3Rules,
			})
		}

		result = append(result, v3PolicySet{
			PolicySetID:        fmt.Sprintf("ps-%s-%s", pk.domain, pk.resourceType),
			Name:               fmt.Sprintf("%s-%s policy set", pk.domain, pk.resourceType),
			Type:               "SIMPLIFIED",
			Domain:             pk.domain,
			Status:             "ACTIVE",
			Target:             resourceTypeTarget(pk.resourceType),
			CombiningAlgorithm: "DENY_UNLESS_PERMIT",
			TenantID:           pk.tenant,
			Policies:           v3Policies,
		})
	}
	return result
}

// toV3PIPs converts simplified PIPs to v3 export shape.
func toV3PIPs(items []simplifiedPIP, defaultTenantID string) []v3PIP {
	result := make([]v3PIP, 0, len(items))
	for _, p := range items {
		domain := p.Domain
		if domain == "" {
			domain = "default"
		}
		result = append(result, v3PIP{
			Name:              p.Name,
			PipType:           p.PipType,
			URL:               p.URL,
			HTTPMethod:        p.HTTPMethod,
			Header:            p.Header,
			Claim:             p.Claim,
			BeanName:          p.BeanName,
			DefaultValue:      p.DefaultValue,
			Domain:            domain,
			TenantID:          exportTenant(p.Tenant, defaultTenantID),
			Type:              p.Type,
			JsonPath:          p.JsonPath,
			RequestAttributes: p.RequestAttributes,
			Headers:           p.Headers,
			Query:             p.Query,
			Body:              p.Body,
			TimeoutSeconds:    p.TimeoutSeconds,
			Response:          p.Response,
		})
	}
	return result
}

// exportTenant is the tenantId the export gives an item of tenant: the
// default tenant, and an item no upload stamped, take defaultTenantID.
func exportTenant(tenant, defaultTenantID string) string {
	if tenant == "" || tenant == defaultTenant {
		return defaultTenantID
	}
	return tenant
}

// resourceTypeTarget converts a simplified resourceType to a v3 target expression.
func resourceTypeTarget(rt string) string {
	if strings.EqualFold(rt, "ALL") || rt == "*" {
		return "true"
	}
	return fmt.Sprintf("resourceType == '%s'", rt)
}

// operationTarget converts a simplified operation to a v3 target expression.
func operationTarget(op string) string {
	if strings.EqualFold(op, "ALL") || op == "*" {
		return "true"
	}
	return fmt.Sprintf("operation == '%s'", op)
}

// rolesTarget converts a serialised roles key back to a v3 policy target.
// The PolicySetExportExpressionConverter rewrites subject.isM2M to
// subject.roles CONTAINS 'ROLE_M2M', so we do the same.
//
// Multi-role targets are emitted as a CONTAINS ANY operand list, which is what
// the access-control export on cloud-platform-security-dev-4 serves: 506 of the
// 1325 CONTAINS ANY clauses in the captured payload carry a comma-separated
// list. Until 2026-08-01 this function emitted only the first role, on the
// stated assumption that access-control never produces multi-role targets — so
// a multi-role policy loaded into the stub silently lost every role but one and
// no local test could catch a multi-role defect.
func rolesTarget(rolesKey string) string {
	if rolesKey == "" {
		return "true"
	}
	// rolesKey is a comma-separated list (see rolesKey helper below).
	parts := strings.Split(rolesKey, ",")
	if len(parts) == 1 {
		return fmt.Sprintf("subject.roles CONTAINS '%s'", parts[0])
	}
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = fmt.Sprintf("'%s'", p)
	}
	return "subject.roles CONTAINS ANY " + strings.Join(quoted, ",")
}

// rolesKey serialises a []any roles list to a stable string for use as a map key.
func rolesKey(roles []any) string {
	strs := make([]string, 0, len(roles))
	for _, r := range roles {
		strs = append(strs, fmt.Sprintf("%v", r))
	}
	sort.Strings(strs)
	return strings.Join(strs, ",")
}

// conditionString converts a condition value (any) to a string.
// A nil/absent condition maps to "".
func conditionString(cond any) string {
	if cond == nil {
		return ""
	}
	switch v := cond.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", cond)
	}
}
