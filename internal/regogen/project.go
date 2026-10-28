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

package regogen

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/regogen/spectables"
)

// Resolved is the value of one operand on a request, as the specification's
// Ctx.resolve gives it: a state and, in state VALUE, the value.
type Resolved struct {
	State      spectables.State
	Value      jsonvalue.Value
	HeaderList bool // a HEADER or GENERAL list, class hl
}

// Request is what the projection reads of a check/resource request. Resolving
// the operands (reading the token, calling PIPs, walking the resource) is not
// the generator's job; the prototype takes the values the specification
// resolved.
type Request struct {
	Operation, ResourceType string
	Roles                   []string
	M2M                     bool
	// Values holds the resolved value of each operand, by [Ref.Key].
	Values map[string]Resolved
	// Nodes holds the interval of each iterate set, by set ID: lo and hi,
	// each P, N, or D.
	Nodes map[string][2]string
}

// Record is the value record of a reference, as the module reads it.
type Record struct {
	S    string
	T    string
	K    *string
	KS   []string
	Raw  *string
	Segs []string
	// N0 is set for a list that holds a null element; its keys leave the
	// null out.
	N0 bool
	// TK is the key of a list's or an object's Java text, which a string
	// equals it by.
	TK *string
	// O is the key two lists are equal by: their typed elements as a set.
	O *string
}

// Input is the projection of a request into the input of a module.
type Input struct {
	Records map[string]Record // by reference ID, network PIPs included
	SRoles  []string
	M2M     bool
	G       []string
	nodes   map[string][2]string
	refs    []*Ref
}

func record(r *Ref, v Resolved) Record {
	rec := Record{S: string(v.State)}
	if v.State == spectables.StateSingleOdd {
		// a one-element GENERAL list of null, a boolean, or an object: the
		// collection operators read it as a list
		lv := legacyvalue.Of(v.Value)
		rec.KS = lv.Keys
		if rec.KS == nil {
			rec.KS = []string{}
		}
		rec.N0 = lv.State == legacyvalue.StateNullElement
		return rec
	}
	if v.State != spectables.StateValue {
		return rec
	}
	lv := legacyvalue.Of(v.Value)
	cl := string(lv.Class)
	if lv.Class == legacyvalue.ClassList && v.HeaderList {
		cl = string(spectables.ClassHeaderList)
	}
	rec.T = cl
	switch cl {
	case "s", "n":
		rec.K = lv.Key
		rec.KS = []string{*lv.Key}
	case "l", "hl", "x":
		rec.KS = lv.Keys
		if rec.KS == nil {
			rec.KS = []string{}
		}
		rec.N0 = lv.State == legacyvalue.StateNullElement
		rec.TK = lv.Key
		rec.O = lv.Structure
	}
	if s, ok := v.Value.(string); ok {
		rec.Raw = &s
		if r.Segments {
			rec.Segs = strings.Split(s, "/")
		}
	}
	return rec
}

// Project builds the input of the module for a request. It fails when the
// request lacks the value of an operand the module reads.
func Project(m *Module, req Request) (*Input, error) {
	in := &Input{Records: map[string]Record{}, M2M: req.M2M, nodes: req.Nodes, refs: m.Refs}
	for _, r := range req.Roles {
		in.SRoles = append(in.SRoles, legacyvalue.Fold(r))
	}
	for _, r := range m.Refs {
		var v Resolved
		switch r.ID {
		case "op":
			v = Resolved{State: spectables.StateValue, Value: req.Operation}
		case "rt":
			v = Resolved{State: spectables.StateValue, Value: req.ResourceType}
		default:
			var ok bool
			if v, ok = req.Values[r.Key]; !ok {
				return nil, fmt.Errorf("no resolved value of %s (%s)", r.Key, r.ID)
			}
		}
		in.Records[r.ID] = record(r, v)
	}
	for _, id := range m.IterateSets {
		if _, ok := req.Nodes[id]; !ok {
			return nil, fmt.Errorf("no interval of the iterate set %s", id)
		}
	}
	in.G = EvalGroups(m, in)
	return in, nil
}

func strTerm(s string) *ast.Term { return ast.StringTerm(s) }

func strsTerm(ss []string) *ast.Term {
	ts := make([]*ast.Term, len(ss))
	for i, s := range ss {
		ts[i] = ast.StringTerm(s)
	}
	return ast.ArrayTerm(ts...)
}

func (r Record) term() *ast.Term {
	o := ast.NewObject([2]*ast.Term{strTerm("s"), strTerm(r.S)})
	if r.T != "" {
		o.Insert(strTerm("t"), strTerm(r.T))
	}
	if r.K != nil {
		o.Insert(strTerm("k"), strTerm(*r.K))
	}
	if r.KS != nil {
		o.Insert(strTerm("ks"), strsTerm(r.KS))
	}
	if r.Raw != nil {
		o.Insert(strTerm("raw"), strTerm(*r.Raw))
	}
	if r.N0 {
		o.Insert(strTerm("n0"), ast.BooleanTerm(true))
	}
	if r.TK != nil {
		o.Insert(strTerm("tk"), strTerm(*r.TK))
	}
	if r.O != nil {
		o.Insert(strTerm("o"), strTerm(*r.O))
	}
	return ast.NewTerm(o)
}

// Value returns the input as a Rego value: maps s, t, k, ks, raw, seg, eseg,
// nseg, n0, tk, and o from a reference ID to a field of its record, then
// sroles, m2m, and g. A network PIP's record is not in it: nc.pip returns it.
func (in *Input) Value() ast.Value {
	fields := map[string]ast.Object{}
	for _, f := range []string{"s", "t", "k", "ks", "raw", "seg", "eseg", "nseg", "n0", "tk", "o"} {
		fields[f] = ast.NewObject()
	}
	for _, r := range in.refs {
		if r.Network {
			continue
		}
		rec := in.Records[r.ID]
		id := strTerm(r.ID)
		fields["s"].Insert(id, strTerm(rec.S))
		if rec.T != "" {
			fields["t"].Insert(id, strTerm(rec.T))
		}
		if rec.K != nil {
			fields["k"].Insert(id, strTerm(*rec.K))
		}
		if rec.KS != nil {
			fields["ks"].Insert(id, strsTerm(rec.KS))
		}
		if rec.Raw != nil {
			fields["raw"].Insert(id, strTerm(*rec.Raw))
		}
		if rec.N0 {
			fields["n0"].Insert(id, ast.BooleanTerm(true))
		}
		if rec.TK != nil {
			fields["tk"].Insert(id, strTerm(*rec.TK))
		}
		if rec.O != nil {
			fields["o"].Insert(id, strTerm(*rec.O))
		}
		if rec.Segs != nil {
			fields["seg"].Insert(id, strsTerm(rec.Segs))
			rev := slices.Clone(rec.Segs)
			slices.Reverse(rev)
			fields["eseg"].Insert(id, strsTerm(rev))
			fields["nseg"].Insert(id, ast.IntNumberTerm(len(rec.Segs)))
		}
	}
	o := ast.NewObject()
	for f, v := range fields {
		o.Insert(strTerm(f), ast.NewTerm(v))
	}
	o.Insert(strTerm("sroles"), strsTerm(in.SRoles))
	o.Insert(strTerm("m2m"), ast.BooleanTerm(in.M2M))
	o.Insert(strTerm("g"), strsTerm(in.G))
	return o
}

// PIPRecord returns the record nc.pip returns for a network reference, and
// false for an unknown one.
func (in *Input) PIPRecord(id string) (*ast.Term, bool) {
	r, ok := in.Records[id]
	if !ok {
		return nil, false
	}
	return r.term(), true
}

// NodeInterval returns the record nc.node returns for an iterate set: lo and
// hi, each P, N, or D.
func (in *Input) NodeInterval(id string) (*ast.Term, bool) {
	iv, ok := in.nodes[id]
	if !ok {
		return nil, false
	}
	return ast.ObjectTerm([2]*ast.Term{strTerm("lo"), strTerm(iv[0])},
		[2]*ast.Term{strTerm("hi"), strTerm(iv[1])}), true
}
