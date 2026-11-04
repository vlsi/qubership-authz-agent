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
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Algorithm is a combining algorithm.
type Algorithm string

// The combining algorithms. AlgorithmAbsent is a node that names none; the
// specification's profile decides how such a node combines its children.
const (
	AlgorithmAbsent           Algorithm = ""
	AlgorithmDenyOverrides    Algorithm = "DENY_OVERRIDES"
	AlgorithmPermitOverrides  Algorithm = "PERMIT_OVERRIDES"
	AlgorithmDenyUnlessPermit Algorithm = "DENY_UNLESS_PERMIT"
	AlgorithmPermitUnlessDeny Algorithm = "PERMIT_UNLESS_DENY"
)

var algorithms = []Algorithm{
	AlgorithmAbsent, AlgorithmDenyOverrides, AlgorithmPermitOverrides, AlgorithmDenyUnlessPermit,
	AlgorithmPermitUnlessDeny,
}

// Effect is the effect of a rule as written. Only ALLOW and DENY name an
// outcome; the specification's profile decides what the others and an absent
// effect do.
type Effect string

// The effects the PAP accepts, and EffectAbsent for a rule that names none.
const (
	EffectAbsent             Effect = ""
	EffectAllow              Effect = "ALLOW"
	EffectDeny               Effect = "DENY"
	EffectNotApplicable      Effect = "NOT_APPLICABLE"
	EffectUseFilterCondition Effect = "USE_FILTER_CONDITION"
)

var effects = []Effect{EffectAbsent, EffectAllow, EffectDeny, EffectNotApplicable, EffectUseFilterCondition}

// Dialect is a dialect of filter predicates.
type Dialect string

// The dialects, each read from its own field of a rule: rsqlPredicate,
// sqlPredicate, mongodbPredicate, and predicate for querydsl.
const (
	DialectRSQL     Dialect = "rsql"
	DialectSQL      Dialect = "sql"
	DialectMongoDB  Dialect = "mongodb"
	DialectQueryDSL Dialect = "querydsl"
)

var dialects = []Dialect{DialectRSQL, DialectSQL, DialectMongoDB, DialectQueryDSL}

// Dialects returns every dialect, in the order a dump prints them, in a slice
// the caller owns.
func Dialects() []Dialect { return slices.Clone(dialects) }

// Predicates are the filter predicates of a rule or a simplified policy.
type Predicates struct {
	// Text maps a dialect to its template as written, placeholders unexpanded.
	// A dialect without a template is not a key.
	Text map[Dialect]string
	// Custom is the customPredicate, or nil.
	Custom *CustomPredicate
}

// CustomPredicate is a customPredicate: the predicate name and its parameters.
// Each parameter value is the JSON value as written, compacted, which the PAP
// accepts as any JSON type.
type CustomPredicate struct {
	Predicate string
	Params    map[string]string
}

// Tree is the effective policy configuration of one tenant. [NewTree] builds
// it.
type Tree struct {
	Simplified []*SimplifiedGroup
	Sets       []*PolicySet
	PIPs       []*PIP
}

// SimplifiedGroup is the simplified policies of one component that share a
// resource type, as one top-level node. ResourceType is the resource type the
// set target names, and "ALL" names the resource type ALL, not every resource
// type: the PAP writes the set target resourceType == 'ALL' only for a resource
// type given as ALL with spaces around it. A global simplified policy, which
// applies to every resource type, has the set target true, and [FromRegular]
// reads its set as a regular [PolicySet].
//
// ID, Name, and ExternalID are those of the set that holds the group.
type SimplifiedGroup struct {
	ID   string
	Name string
	// ExternalID is the externalId as written, empty when absent.
	ExternalID   string
	Domain       string
	Component    string
	ResourceType string
	Policies     []*SimplifiedPolicy
}

// SimplifiedPolicy is one simplified policy. Its effect is ALLOW.
type SimplifiedPolicy struct {
	ID string
	// Frontend marks a policy applicable for the frontend: in the export, a
	// rule of ruleType APPLICABLE_FOR_FRONTEND.
	Frontend bool
	// Operation is the operation as written, possibly "ALL", or empty when the
	// policy names none.
	Operation string
	Roles     []string
	// Condition is at [PlaceSimplified], or nil.
	Condition  *Condition
	Predicates Predicates
}

// PolicySet is a policy set: top-level, or nested in another one.
type PolicySet struct {
	ID     string
	Name   string
	Domain string
	// ExternalID is the externalId as written, empty when absent.
	ExternalID string
	Algorithm  Algorithm
	// Target is at [PlaceSetTarget], or nil when the set applies to any request.
	Target *Condition
	// Iterate is the set's iterate, or nil.
	Iterate *Iterate
	// AlwaysFails is the reason the legacy service never evaluates this set,
	// whatever the request; empty for a set it evaluates. Such a set is a
	// permanent source failure under its target and holds no policies, no sets,
	// and no iterate.
	AlwaysFails string
	// Isolated is the reason the agent does not evaluate this set,
	// although the legacy service does: the export shows it damaged, and which
	// of its elements belong to it cannot be told. Empty for a set the agent
	// evaluates. Like a set with AlwaysFails, an isolated set is a permanent
	// source failure under its target, holds no policies, no sets, and no
	// iterate, and fails no other set of the tenant.
	Isolated string
	Policies []*Policy
	Sets     []*PolicySet
}

// Iterate is the iterate of a set: the set is evaluated once per assignment of
// subject.permissionScope, and Algorithm combines the passes. Var names the
// pass for [PassValue] and is unique in the tree.
//
// The legacy service evaluates only iterate over subject.permissionScope with
// an algorithm, so a frontend turns any other iterate into
// [PolicySet.AlwaysFails].
type Iterate struct {
	Var       string
	Algorithm Algorithm
}

// Policy is a policy of a policy set.
type Policy struct {
	ID        string
	Name      string
	Algorithm Algorithm
	// Target is at [PlacePolicyTarget], or nil.
	Target *Condition
	Rules  []*Rule
}

// Rule is a rule of a policy.
type Rule struct {
	ID     string
	Name   string
	Effect Effect
	// Frontend marks a rule of ruleType APPLICABLE_FOR_FRONTEND.
	Frontend bool
	// Target is at [PlaceRuleTarget], or nil.
	Target *Condition
	// Condition is at [PlaceRuleCondition], or nil.
	Condition  *Condition
	Predicates Predicates
}

// PIPType is the pipType of a PIP declaration.
type PIPType string

// The PIP types the PAP accepts. A frontend reads an absent pipType as
// GENERAL.
const (
	PIPGeneral         PIPType = "GENERAL"
	PIPFiltered        PIPType = "FILTERED"
	PIPHeader          PIPType = "HEADER"
	PIPToken           PIPType = "TOKEN"
	PIPMapping         PIPType = "MAPPING"
	PIPPermissionScope PIPType = "PERMISSION_SCOPE"
)

var pipTypes = []PIPType{PIPGeneral, PIPFiltered, PIPHeader, PIPToken, PIPMapping, PIPPermissionScope}

// PIP is a PIP declaration of the tenant. Each field holds the value as
// written, empty when absent; which fields a type reads is the specification's.
type PIP struct {
	// Name is the declared name, starting with "subject.".
	Name string
	Type PIPType

	// Claim is the token claim of a TOKEN PIP.
	Claim string
	// Header is the request header of a HEADER PIP.
	Header string
	// DefaultValue is the JSON value of defaultValue as written, compacted,
	// and empty when the field is absent.
	DefaultValue string

	URL        string
	HTTPMethod string
	BeanName   string
	JSONPath   string
	// ReturnType is the type field: UUID, REGULAR, JSON, or empty.
	ReturnType string
	// Headers names the request headers the call forwards, as the
	// comma-separated text the export writes.
	Headers string
	// ResourceType is the resource type of a FILTERED PIP.
	ResourceType string
	// Domain is the domain that declares the PIP.
	Domain string
	// RequestAttributes maps an attribute name to its JSON value as written,
	// compacted; nil for a declaration without requestAttributes or with null
	// there, and empty for {}, which a call sends as written.
	RequestAttributes map[string]string

	// ProductMapping and CustomMapping are the JSON objects of a MAPPING PIP as
	// written, compacted, or empty.
	ProductMapping string
	CustomMapping  string

	// Cacheable and CachePeriod are the JSON values of cacheable and
	// cachePeriod as written, compacted, or empty.
	Cacheable   string
	CachePeriod string

	// Unsupported names what the declaration carries that the agent cannot
	// execute yet, such as a field of an extension the legacy service does
	// not have; empty when there is nothing.
	Unsupported string

	// Isolated is the reason the tenant has no usable declaration of Name,
	// such as two declarations of it in the export, of which the agent cannot
	// tell the tenant's own; empty for a usable declaration. An isolated
	// declaration has no other field set, Type included, and a condition that
	// reads it reads a failed PIP.
	Isolated string
}

// PIP returns the declaration named name, and false when the tree declares
// none. The declaration may be one with [PIP.Isolated], which has no type.
func (t *Tree) PIP(name string) (*PIP, bool) {
	for _, p := range t.PIPs {
		if p.Name == name {
			return p, true
		}
	}
	return nil, false
}

// NewTree returns the tree of simplified groups, sets, and PIP declarations,
// which it shares rather than copies. It returns an error that names the
// offending node when any of these is violated:
//
//   - every node is non-nil, and every algorithm, effect, dialect, and PIP type
//     is one this package declares;
//   - every condition is valid as [NewCondition] checks it, and stands at the
//     place of its position: a set target at [PlaceSetTarget], and so on;
//   - every [Iterate.Var] is non-empty and unique in the tree, the algorithm of
//     an iterate is not absent, and every [PassValue] names the var of an
//     enclosing set;
//   - no condition inside an iterate reads [SubjectPermissionScope], which a
//     [PassValue] reads there;
//   - a set with [PolicySet.AlwaysFails] or [PolicySet.Isolated] has no
//     policies, sets, or iterate, and no set has both;
//   - PIP names start with "subject." and are unique, and a declaration with
//     [PIP.Isolated] has no other field set;
//   - every field that holds JSON as written holds one compacted JSON value.
func NewTree(simplified []*SimplifiedGroup, sets []*PolicySet, pips []*PIP) (*Tree, error) {
	t := &Tree{Simplified: simplified, Sets: sets, PIPs: pips}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

type checker struct {
	vars map[string]bool
	// bound holds the vars of the iterates around the node being checked.
	bound map[string]bool
}

// node is a path from the root of the tree, held as a label and a link to the
// parent path. Its text is built only when an error or a finding names it, so
// a check of a deep tree or of a set with a long ID does not copy the
// ancestors' labels at every node.
type node struct {
	parent *node
	label  string
}

func (n *node) child(label string) *node { return &node{parent: n, label: label} }

// String returns the labels from the root to n, joined by " > ", or empty for
// a nil n.
func (n *node) String() string {
	var labels []string
	for ; n != nil; n = n.parent {
		labels = append(labels, n.label)
	}
	slices.Reverse(labels)
	return strings.Join(labels, " > ")
}

func (t *Tree) validate() error {
	names := map[string]bool{}
	for i, p := range t.PIPs {
		if p == nil {
			return fmt.Errorf("pip %d: nil", i)
		}
		if !strings.HasPrefix(p.Name, "subject.") {
			return fmt.Errorf("pip %q: name lacks the subject. prefix", p.Name)
		}
		if names[p.Name] {
			return fmt.Errorf("pip %q: declared twice", p.Name)
		}
		names[p.Name] = true
		if p.Isolated != "" {
			if !reflect.DeepEqual(*p, PIP{Name: p.Name, Isolated: p.Isolated}) {
				return fmt.Errorf("pip %q: an isolated declaration has other fields", p.Name)
			}
			continue
		}
		if !slices.Contains(pipTypes, p.Type) {
			return fmt.Errorf("pip %q: pipType %q unknown", p.Name, p.Type)
		}
		for _, f := range []struct{ name, value string }{
			{"defaultValue", p.DefaultValue}, {"productMapping", p.ProductMapping}, {"customMapping", p.CustomMapping},
			{"cacheable", p.Cacheable}, {"cachePeriod", p.CachePeriod},
		} {
			if f.value != "" {
				if err := checkJSON(f.value); err != nil {
					return fmt.Errorf("pip %q: %s: %w", p.Name, f.name, err)
				}
			}
		}
		for k, v := range p.RequestAttributes {
			if err := checkJSON(v); err != nil {
				return fmt.Errorf("pip %q: requestAttributes %q: %w", p.Name, k, err)
			}
		}
	}
	c := checker{vars: map[string]bool{}, bound: map[string]bool{}}
	if i := slices.Index(t.Simplified, nil); i >= 0 {
		return fmt.Errorf("simplified group %d: nil", i)
	}
	groups := labels(t.Simplified, groupLabel)
	for i, g := range t.Simplified {
		if j := slices.Index(g.Policies, nil); j >= 0 {
			return fmt.Errorf("%s: policy %d: nil", groups[i], j)
		}
		group := (*node)(nil).child(groups[i])
		for j, l := range labels(g.Policies, simplifiedPolicyLabel) {
			p := g.Policies[j]
			here := group.child(l)
			if err := c.condition(here.child("condition"), p.Condition, PlaceSimplified); err != nil {
				return err
			}
			if err := checkPredicates(here, p.Predicates); err != nil {
				return err
			}
		}
	}
	return c.sets(nil, t.Sets)
}

func (c *checker) sets(parent *node, sets []*PolicySet) error {
	if i := slices.Index(sets, nil); i >= 0 {
		return fmt.Errorf("%s: set %d: nil", parent.child("sets"), i)
	}
	for i, l := range labels(sets, setLabel) {
		if err := c.set(parent.child(l), sets[i]); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) set(here *node, s *PolicySet) error {
	if !slices.Contains(algorithms, s.Algorithm) {
		return fmt.Errorf("%s: algorithm %q unknown", here, s.Algorithm)
	}
	if s.AlwaysFails != "" && (s.Iterate != nil || len(s.Policies) > 0 || len(s.Sets) > 0) {
		return fmt.Errorf("%s: a set that always fails has children or an iterate", here)
	}
	if s.Isolated != "" && (s.AlwaysFails != "" || s.Iterate != nil || len(s.Policies) > 0 || len(s.Sets) > 0) {
		return fmt.Errorf("%s: an isolated set always fails, has children, or has an iterate", here)
	}
	if err := c.condition(here.child("target"), s.Target, PlaceSetTarget); err != nil {
		return err
	}
	if it := s.Iterate; it != nil {
		switch {
		case it.Var == "":
			return fmt.Errorf("%s: iterate: no var", here)
		case c.vars[it.Var]:
			return fmt.Errorf("%s: iterate: var %q bound twice in the tree", here, it.Var)
		case it.Algorithm == AlgorithmAbsent || !slices.Contains(algorithms, it.Algorithm):
			return fmt.Errorf("%s: iterate: algorithm %q is not one of the four", here, it.Algorithm)
		}
		c.vars[it.Var] = true
		c.bound[it.Var] = true
		defer delete(c.bound, it.Var)
	}
	if i := slices.Index(s.Policies, nil); i >= 0 {
		return fmt.Errorf("%s: policy %d: nil", here, i)
	}
	for i, l := range labels(s.Policies, policyLabel) {
		if err := c.policy(here.child(l), s.Policies[i]); err != nil {
			return err
		}
	}
	return c.sets(here, s.Sets)
}

func (c *checker) policy(here *node, p *Policy) error {
	if !slices.Contains(algorithms, p.Algorithm) {
		return fmt.Errorf("%s: algorithm %q unknown", here, p.Algorithm)
	}
	if err := c.condition(here.child("target"), p.Target, PlacePolicyTarget); err != nil {
		return err
	}
	if i := slices.Index(p.Rules, nil); i >= 0 {
		return fmt.Errorf("%s: rule %d: nil", here, i)
	}
	for i, l := range labels(p.Rules, ruleLabel) {
		r := p.Rules[i]
		rp := here.child(l)
		if !slices.Contains(effects, r.Effect) {
			return fmt.Errorf("%s: effect %q unknown", rp, r.Effect)
		}
		if err := c.condition(rp.child("target"), r.Target, PlaceRuleTarget); err != nil {
			return err
		}
		if err := c.condition(rp.child("condition"), r.Condition, PlaceRuleCondition); err != nil {
			return err
		}
		if err := checkPredicates(rp, r.Predicates); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) condition(where *node, cond *Condition, place Place) error {
	if cond == nil {
		return nil
	}
	if err := validateCondition(cond); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if cond.Place != place {
		return fmt.Errorf("%s: place %q, want %q", where, cond.Place, place)
	}
	for _, d := range cond.Disjuncts {
		for _, a := range d {
			cmp, ok := a.(Compare)
			if !ok {
				continue
			}
			for _, o := range []Operand{cmp.Left, cmp.Right} {
				if pv, ok := o.(PassValue); ok && !c.bound[pv.Var] {
					return fmt.Errorf("%s: pass value of var %q outside its iterate", where, pv.Var)
				}
				if s, ok := o.(Subject); ok && s.Attr == SubjectPermissionScope && len(c.bound) > 0 {
					return fmt.Errorf("%s: subject.permissionScope inside an iterate, where a pass value reads it", where)
				}
			}
		}
	}
	return nil
}

func checkPredicates(where *node, p Predicates) error {
	for d := range p.Text {
		if !slices.Contains(dialects, d) {
			return fmt.Errorf("%s: predicate dialect %q unknown", where, d)
		}
	}
	if p.Custom != nil {
		for k, v := range p.Custom.Params {
			if err := checkJSON(v); err != nil {
				return fmt.Errorf("%s: customPredicate param %q: %w", where, k, err)
			}
		}
	}
	return nil
}

// checkJSON returns an error when value is not one JSON value written
// compactly, as the fields that hold JSON as written keep it.
func checkJSON(value string) error {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(value)); err != nil {
		return fmt.Errorf("%q is not JSON: %w", value, err)
	}
	if b.String() != value {
		return fmt.Errorf("%q is not compact JSON", value)
	}
	return nil
}
