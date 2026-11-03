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
	"errors"
	"fmt"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// Body is what the projection reads of the body of a check/resource request:
// the operation, the resource type, and the resource. Each holds the JSON
// value the request sent, so an operation that is a number or absent reaches
// the module as that number or as null.
type Body struct {
	Operation    jsonvalue.Value
	ResourceType jsonvalue.Value
	// Resource is the member resource; HasResource tells a body without
	// it from one whose resource is null.
	Resource    jsonvalue.Value
	HasResource bool
}

// ReadBody reads the body of a check/resource request, which must be a JSON
// object. The resource type is the member type, or the member resourceType
// where type is absent, null, false, or an empty string, list, or object.
// A number in type is the resource type whatever its value.
func ReadBody(data []byte) (Body, error) {
	v, err := jsonvalue.Decode(data)
	if err != nil {
		return Body{}, err
	}
	o, ok := v.(*jsonvalue.Object)
	if !ok {
		return Body{}, errors.New("the body of the request is not a JSON object")
	}
	return BodyOf(o), nil
}

// BodyOf returns the body that the object o of a request holds, as
// [ReadBody] reads it.
func BodyOf(o *jsonvalue.Object) Body {
	var b Body
	b.Operation, _ = o.Get("operation")
	b.ResourceType, _ = o.Get("type")
	if empty(b.ResourceType) {
		b.ResourceType, _ = o.Get("resourceType")
	}
	b.Resource, b.HasResource = o.Get("resource")
	return b
}

// empty reports whether the member type gives way to resourceType. The rule
// is the truth of a value in the specification's model, where a number is
// its text and so never empty.
func empty(v jsonvalue.Value) bool {
	switch v := v.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case []jsonvalue.Value:
		return len(v) == 0
	case *jsonvalue.Object:
		return v.Len() == 0
	}
	return false
}

// Resolve sets in values the value of each operand of the resource that m
// reads before the query, on the request whose body is b: the resource, a
// path of kind res:path or res:nested, null, and a path of kind res:jsonpath
// that ends in a dot. A path of kind res:jsonpath without that dot is read
// lazily, and Resolve leaves it out.
func (m *Module) Resolve(b Body, values map[string]Resolved) {
	for _, r := range m.Refs {
		if resourceOperand(r) {
			values[r.Key] = b.resolve(r)
		}
	}
}

// resourceOperand reports whether r is an operand that [Module.Resolve]
// resolves.
func resourceOperand(r *Ref) bool {
	switch r.Kind {
	case spectables.KindResource, spectables.KindResPath, spectables.KindResNested, spectables.KindNull:
		return true
	case spectables.KindResJSONPath:
		return r.Path == ""
	}
	return false
}

// resolve returns the value of a resource operand, r of kind resource,
// res:path, res:nested, null, or a path of kind res:jsonpath that ends in a
// dot, on the request whose body is b.
func (b *Body) resolve(r *Ref) Resolved {
	if r.Kind == spectables.KindNull {
		// null is the attribute resource.null where the resource has that member
		if o, ok := b.Resource.(*jsonvalue.Object); ok && b.HasResource {
			if _, ok := o.Get("null"); ok {
				return b.resolvePath(r)
			}
		}
		return Resolved{State: spectables.StateAbsent}
	}
	return b.resolvePath(r)
}

func (b *Body) resolvePath(r *Ref) Resolved {
	switch {
	case !b.HasResource:
		return Resolved{State: spectables.StateAbsent}
	case r.Kind == spectables.KindResource:
		return Resolved{State: spectables.StateValue, Value: b.Resource}
	case r.dotState != "":
		return Resolved{State: r.dotState}
	}
	return selection(b.Resource, r.sel)
}

// selection returns the value of path p over the resource doc, in the state
// the specification's resolve_resource gives the selection under the agent
// profile. A document without the path, a path through null or an empty
// object, a null document, and a path that starts with a bracket are ABSENT.
// An index past the end is INDEX_OOB; a path that selects several values and
// none is EMPTY_SEL; one value null is NULL and an empty list EMPTY_COLL. A
// selection the package stops as too large, which the specification does not
// have, is ERROR.
func selection(doc jsonvalue.Value, p *jsonpath.Path) Resolved {
	if doc == nil {
		return Resolved{State: spectables.StateAbsent}
	}
	r := p.Select(doc)
	switch r.Kind {
	case jsonpath.KindMissing, jsonpath.KindNullParent, jsonpath.KindBracket:
		return Resolved{State: spectables.StateAbsent}
	case jsonpath.KindIndexOutOfBounds:
		return Resolved{State: spectables.StateIndexOOB}
	case jsonpath.KindMany:
		if l, ok := r.Value.([]jsonvalue.Value); ok && len(l) == 0 {
			return Resolved{State: spectables.StateEmptySel}
		}
		return Resolved{State: spectables.StateValue, Value: r.Value}
	case jsonpath.KindOne:
		switch x := r.Value.(type) {
		case nil:
			return Resolved{State: spectables.StateNull}
		case []jsonvalue.Value:
			if len(x) == 0 {
				return Resolved{State: spectables.StateEmptyColl}
			}
		}
		return Resolved{State: spectables.StateValue, Value: r.Value}
	}
	return Resolved{State: spectables.StateError}
}

// compileResourcePath sets what [Body.resolve] reads of a resource operand
// with path, the path as the specification keeps it: the state of a path
// that ends in one dot, which the knob trailing_dot_path names, and the
// compiled path of any other.
func (g *gen) compileResourcePath(r *Ref, path string, dot bool) error {
	if dot {
		v, err := g.stringKnob("trailing_dot_path")
		if err != nil {
			return err
		}
		r.dotState = spectables.State(v)
		return nil
	}
	if r.Kind == spectables.KindResource {
		return nil
	}
	p, err := jsonpath.Compile(path)
	if err != nil {
		return fmt.Errorf("resource path %q: %w", path, err)
	}
	r.sel = p
	return nil
}
