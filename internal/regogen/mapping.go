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
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// permissions is the value of subject.permissions on req: the permissions
// the tenant's MAPPING PIPs grant the subject, as the specification's
// permissions and resolve_subject compute them under the agent profile.
//
// Each key of a mapping table names a subject attribute, and each value of
// the attribute that equals a key of the table, as == compares a string,
// grants the permissions listed under it, each once, in the order the tables
// list them. productMapping counts only when no MAPPING PIP has a
// customMapping that is an object, empty or not, or any other value Python
// counts true; such a value grants nothing itself. A tenant without a MAPPING
// PIP gives ABSENT, and one whose tables grant nothing EMPTY_COLL. A key
// whose attribute is ERROR, or a list or a scalar the PIP's type does not
// give, makes the whole value ERROR; a key without a value grants nothing.
//
// The knobs of the agent profile this follows: assigned_grants=mapping (the
// export lists assigned permissions as MAPPING), mapping_names=any,
// mapping_key_kinds=any, mapping_self_key=EMPTY, mapping_key_error=ERR,
// mapping_key_nonvalue=EMPTY, permissions_without_mapping=ABSENT,
// product_mapping_only_without_custom=true, custom_mapping_empty_counts=true,
// roles_empty=ABSENT, scope_outside_iterate=SCOPE_OUTSIDE.
func (m *Module) permissions(req *Request) Resolved {
	if len(m.mappings) == 0 {
		return Resolved{State: spectables.StateAbsent}
	}
	hasCustom := false
	var sources [][]jsonvalue.Value
	for _, decl := range m.mappings {
		custom := decodeMapping(decl.CustomMapping)
		if _, ok := custom.(*jsonvalue.Object); ok || truthy(custom) {
			hasCustom = true
		}
		sources = append(sources, []jsonvalue.Value{custom, decodeMapping(decl.ProductMapping)})
	}
	failed := false
	var perms []jsonvalue.Value
	for _, s := range sources {
		tables := s[:1]
		if !hasCustom {
			tables = s
		}
		for _, src := range tables {
			obj, ok := src.(*jsonvalue.Object)
			if !ok {
				continue
			}
			for _, key := range obj.Keys() {
				vals, fail := m.mappingKeyValues(key, req)
				failed = failed || fail
				t, _ := obj.Get(key)
				table, ok := t.(*jsonvalue.Object)
				if !ok {
					continue
				}
				for _, val := range table.Keys() {
					if !anyEqualsText(vals, val) {
						continue
					}
					granted, _ := table.Get(val)
					list, ok := granted.([]jsonvalue.Value)
					if !ok {
						continue
					}
					for _, g := range list {
						if !containsPy(perms, g) {
							perms = append(perms, g)
						}
					}
				}
			}
		}
	}
	switch {
	case failed:
		return Resolved{State: spectables.StateError}
	case len(perms) == 0:
		return Resolved{State: spectables.StateEmptyColl}
	}
	return Resolved{State: spectables.StateValue, Value: perms}
}

// decodeMapping reads a customMapping or productMapping as policyir keeps
// it, nil for an empty or unreadable one.
func decodeMapping(text string) jsonvalue.Value {
	if text == "" {
		return nil
	}
	v, err := jsonvalue.Decode([]byte(text))
	if err != nil {
		return nil
	}
	return v
}

// mappingErrorStates are the states of a key's attribute that make
// subject.permissions ERROR (mapping_key_error=ERR); any other state
// without a value grants nothing (mapping_key_nonvalue=EMPTY).
var mappingErrorStates = map[spectables.State]bool{
	spectables.StateError: true, spectables.StateScalarOdd: true, spectables.StateSingleOdd: true,
	spectables.StateScopeOutside: true,
}

// mappingKeyValues returns the values of the subject attribute a mapping
// key names, and whether its state makes subject.permissions fail.
func (m *Module) mappingKeyValues(key string, req *Request) ([]jsonvalue.Value, bool) {
	name, ok := strings.CutPrefix(key, "subject.")
	if !ok {
		return nil, false
	}
	var v Resolved
	switch {
	case name == "permissions" || strings.HasPrefix(name, "permissions."):
		return nil, false
	case name == "permissionScope" || strings.HasPrefix(name, "permissionScope."):
		// read outside an iterate's pass
		v = Resolved{State: spectables.StateScopeOutside}
	case builtinSubject[strings.Split(name, ".")[0]]:
		var ok bool
		if v, ok = req.Values[specKey("subj", name)]; !ok {
			v = Resolved{State: spectables.StateAbsent}
		}
		if name == "isM2M" {
			v = Resolved{State: spectables.StateValue, Value: req.M2M}
		}
	default:
		decl, ok := m.pips(key)
		switch {
		case !ok || decl.Isolated != "":
			if ok {
				v = Resolved{State: spectables.StateError}
			} else {
				v = Resolved{State: spectables.StateAbsent}
			}
		case decl.Type == policyir.PIPMapping:
			return nil, false
		case decl.Type == policyir.PIPToken:
			v = tokenPIP(decl, req.Claims)
		case decl.Type == policyir.PIPHeader:
			v = headerPIP(decl, req.Headers)
		default:
			// a GENERAL or FILTERED PIP, which the export refuses as a key,
			// and a PERMISSION_SCOPE PIP, which a reference cannot read
			v = Resolved{State: spectables.StateError}
		}
	}
	if name == "roles" && v.State == spectables.StateValue {
		if l, ok := v.Value.([]jsonvalue.Value); ok && len(l) == 0 {
			v = Resolved{State: spectables.StateAbsent}
		}
	}
	switch v.State {
	case spectables.StateValue:
		if l, ok := v.Value.([]jsonvalue.Value); ok {
			return l, false
		}
		return []jsonvalue.Value{v.Value}, false
	case spectables.StateEmptyColl:
		return nil, false
	}
	return nil, mappingErrorStates[v.State]
}

// builtinSubject holds the subject attributes the token gives without a
// PIP, which a mapping key reads without looking up a declaration.
var builtinSubject = map[string]bool{
	"id": true, "name": true, "type": true, "scopes": true, "serviceAccount": true, "entitledResources": true,
	"isM2M": true, "roles": true,
}

// anyEqualsText reports whether one of vals equals the table key text as
// == compares a value with a string: by its text, ignoring case as Java's
// equalsIgnoreCase does; a list or an object by its Java text, and null
// never.
func anyEqualsText(vals []jsonvalue.Value, text string) bool {
	folded := legacyvalue.Fold(text)
	for _, v := range vals {
		if v != nil && legacyvalue.Fold(legacyvalue.Text(v)) == folded {
			return true
		}
	}
	return false
}
