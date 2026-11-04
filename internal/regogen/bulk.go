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
	"github.com/open-policy-agent/opa/v1/ast"

	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// Bulk is the projection of what the items of a bulk request share: the
// subject, the PIPs, the permission scope, and the subject groups. Each item
// adds its operation, its resource type, and the operands of its resource
// ([Bulk.Item]). A Bulk is safe for concurrent use once built.
type Bulk struct {
	in *Input
	// items holds the references each item resolves from its body.
	items []*Ref
	// fields holds the maps of [fieldMaps] over the shared records, and top
	// the members sroles, m2m, g, ps, and psf of the input.
	fields map[string]*ast.Term
	top    [][2]*ast.Term
}

// itemOperand reports whether each item of a bulk request resolves r from
// its own body.
func itemOperand(r *Ref) bool {
	return r.Kind == spectables.KindOperation || r.Kind == spectables.KindResourceType || resourceOperand(r)
}

// NewBulk projects the part of a bulk request that its items share. req
// holds the resolved value of each operand the module reads that is not the
// operation, the resource type, or an operand of the resource; its Body is
// not read. NewBulk fails as [Project] does on a missing value.
func NewBulk(m *Module, req Request) (*Bulk, error) {
	shared := req
	shared.Body = Body{}
	values := make(map[string]Resolved, len(req.Values))
	for k, v := range req.Values {
		values[k] = v
	}
	b := &Bulk{}
	for _, r := range m.Refs {
		if !r.Pass && r.Path == "" && itemOperand(r) {
			b.items = append(b.items, r)
			// a placeholder Project reads in place of the item's value, dropped below
			values[r.Key] = Resolved{State: spectables.StateAbsent}
		}
	}
	shared.Values = values
	in, err := Project(m, shared)
	if err != nil {
		return nil, err
	}
	for _, r := range b.items {
		delete(in.Records, r.ID)
	}
	b.in = in
	b.fields = make(map[string]*ast.Term, len(recordFields))
	for f, o := range fieldObjects(m.Refs, func(r *Ref) (Record, bool) {
		rec, ok := in.Records[r.ID]
		return rec, ok && !r.Network && !r.Pass
	}) {
		b.fields[f] = ast.NewTerm(o)
	}
	b.top = in.subjectMembers()
	return b, nil
}

// Item returns the input of one item of the bulk request, whose body is
// body. The input shares the subject's part with every other item: its
// Records hold the item's records only, and its Value reuses the shared
// terms.
func (b *Bulk) Item(body Body) *Input {
	in := &Input{
		Records:     make(map[string]Record, len(b.items)),
		SRoles:      b.in.SRoles,
		M2M:         b.in.M2M,
		G:           b.in.G,
		Passes:      b.in.Passes,
		ScopeFailed: b.in.ScopeFailed,
		refs:        b.in.refs,
		docs:        regobuiltins.NewDocuments(),
		bulk:        b,
	}
	if body.HasResource {
		in.resource = body.Resource
	}
	for _, r := range b.items {
		var v Resolved
		switch r.Kind {
		case spectables.KindOperation:
			v = Resolved{State: spectables.StateValue, Value: body.Operation}
		case spectables.KindResourceType:
			v = Resolved{State: spectables.StateValue, Value: body.ResourceType}
		default:
			v = body.resolve(r)
		}
		in.Records[r.ID] = record(r, v)
	}
	return in
}

// value is the [Input.Value] of the item in: each map of a field joins the
// shared entries and the item's, and a map the item adds nothing to is the
// shared term itself.
func (b *Bulk) value(in *Input) ast.Value {
	type entry struct{ id, v *ast.Term }
	own := map[string][]entry{}
	for _, r := range b.items {
		id := strTerm(r.ID)
		in.Records[r.ID].fields(func(f string, v *ast.Term) { own[f] = append(own[f], entry{id, v}) })
	}
	o := ast.NewObjectWithCapacity(len(recordFields) + len(b.top) + 1)
	for _, f := range recordFields {
		t := b.fields[f]
		if add := own[f]; len(add) > 0 {
			shared := t.Value.(ast.Object)
			j := ast.NewObjectWithCapacity(shared.Len() + len(add))
			shared.Foreach(j.Insert)
			for _, e := range add {
				j.Insert(e.id, e.v)
			}
			t = ast.NewTerm(j)
		}
		o.Insert(strTerm(f), t)
	}
	for _, kv := range b.top {
		o.Insert(kv[0], kv[1])
	}
	if b.in.resourceMember() {
		res := ast.NullTerm()
		if in.resource != nil {
			// a jsonvalue.Value always has a term
			res, _ = in.docs.Term(in.resource)
		}
		o.Insert(strTerm("resource"), res)
	}
	return o
}
