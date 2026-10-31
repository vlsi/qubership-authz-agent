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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Operand is one side of a comparison. Its dynamic type is one of [Operation],
// [ResourceType], [Resource], [Subject], [PIPRef], [Entitled], [PassValue],
// [String], [Number], [Bool], [List], [Pattern], or [Unsupported].
type Operand interface {
	operand()
}

// Literal is an element of a [List]: a [String], a [Number], or a [Bool].
type Literal interface {
	Operand
	literal()
}

// Operation is the operation of the request.
type Operation struct{}

// ResourceType is the resource type of the request.
type ResourceType struct{}

// Resource reads the resource of the request. Path is the path as written after
// the word resource: empty for the whole resource, otherwise starting with a dot
// or a bracket, such as ".a.b", "['x']", "[0]", "..id", or
// ".items[?(@.k == 'v')].length()". A path written without the resource prefix,
// and a subject token that is neither a built-in attribute, a PIP name, nor
// subject.permissionScope.<key>, are resource paths too, and a frontend writes
// them here with their leading dot: ".a.b", ".subject.l[0]", ".subject.x-y".
//
// Path is one that package jsonpath compiles; [NewCompare] checks it.
// TrailingDot reports a path written with one dot at its end, such as
// resource.a. or resource.l[0].: Path leaves the dot out, and legacy reads such a
// path as a state of its own instead of the path without the dot.
type Resource struct {
	Path        string
	TrailingDot bool
}

// SubjectAttr names a built-in attribute of the subject.
type SubjectAttr string

// The built-in subject attributes an operand reads. subject.entitledResources is
// read through [Entitled] only.
const (
	SubjectID              SubjectAttr = "id"
	SubjectName            SubjectAttr = "name"
	SubjectType            SubjectAttr = "type"
	SubjectServiceAccount  SubjectAttr = "serviceAccount"
	SubjectRoles           SubjectAttr = "roles"
	SubjectScopes          SubjectAttr = "scopes"
	SubjectPermissions     SubjectAttr = "permissions"
	SubjectIsM2M           SubjectAttr = "isM2M"
	SubjectPermissionScope SubjectAttr = "permissionScope"
)

var subjectAttrs = []SubjectAttr{
	SubjectID, SubjectName, SubjectType, SubjectServiceAccount, SubjectRoles, SubjectScopes,
	SubjectPermissions, SubjectIsM2M, SubjectPermissionScope,
}

// Subject reads a built-in subject attribute. Key is set for permissionScope
// and only for it, and is the text after "subject.permissionScope." as written:
// subject.permissionScope.a.b reads the key "a.b", and
// subject.permissionScope.a[0] the key "a[0]". Inside a pass of
// iterate a frontend writes subject.permissionScope.<key> as a [PassValue]
// instead. subject.permissionScope without a key is a [PIPRef].
type Subject struct {
	Attr SubjectAttr
	Key  string
}

// PIPRef reads the value of the PIP declared under Name, such as
// "subject.region". The name is the whole operand: subject.region.code reads
// the PIP named "subject.region.code", not a path into "subject.region".
//
// Filtered marks the right operand "subject.X FILTERED 'OP'": Name is then the
// declared "subject.X.filtered", and FilteredOperation is OP as written,
// possibly empty. FilteredOperation is empty when Filtered is unset.
//
// Name need not be declared: a reference to a PIP the tenant does not declare
// is a valid tree, and [Tree.PIP] reports it as missing.
type PIPRef struct {
	Name              string
	Filtered          bool
	FilteredOperation string
}

// Entitled is subject.entitledResources.of('ResourceType').as('As[0]', ...).
// As holds at least one name.
type Entitled struct {
	ResourceType string
	As           []string
}

// PassValue reads the value the current pass of an iterate binds:
// subject.permissionScope inside the set whose [Iterate.Var] is Var, or inside
// a set nested in it. Key is the key of the assignment, as [Subject.Key] holds
// it.
type PassValue struct {
	Var string
	Key string
}

// String is a quoted string literal, without its quotes.
type String struct {
	Value string
}

// Number is a number literal. Text is the literal as written, so a decimal keeps
// its digits: "005", "-0.5", "12.30". [NewNumber] checks the syntax.
type Number struct {
	Text string
}

// Bool is a boolean literal.
type Bool struct {
	Value bool
}

// List is the right operand of IN, NOT IN, CONTAINS ANY, NOT CONTAINS ANY,
// IS SUBSET, and IS NOT SUBSET when it is written as literals. A single
// literal there is a list of one. Items are all strings, all numbers, or all
// booleans, and Raw is the list token as written when it has two or more
// items, empty otherwise. [NewList] checks both.
type List struct {
	Items []Literal
	Raw   string
}

// Pattern is the right operand of MATCH and NOT MATCH, as written: "/api/*",
// or the text of an attribute, such as "resource.*" or "subject.l[0]", which is
// not read.
type Pattern struct {
	Text string
}

func (Operation) operand()    {}
func (ResourceType) operand() {}
func (Resource) operand()     {}
func (Subject) operand()      {}
func (PIPRef) operand()       {}
func (Entitled) operand()     {}
func (PassValue) operand()    {}
func (String) operand()       {}
func (Number) operand()       {}
func (Bool) operand()         {}
func (List) operand()         {}
func (Pattern) operand()      {}
func (Unsupported) operand()  {}

func (String) literal() {}
func (Number) literal() {}
func (Bool) literal()   {}

// numberSyntax is the number literal the PAP accepts: 005 and -0.5 are numbers,
// -05, -0.0, -0.50, .5, 5., and 5e0 are not.
var numberSyntax = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?|-[1-9][0-9]*(?:\.[0-9]+)?|-0\.[0-9]*[1-9])$`)

// NewNumber returns the number literal written as text, or an error when the
// PAP refuses text as a number.
func NewNumber(text string) (Number, error) {
	if !numberSyntax.MatchString(text) {
		return Number{}, fmt.Errorf("number literal %q: not a number the PAP accepts", text)
	}
	return Number{Text: text}, nil
}

// NewList returns the list of items with its token raw. It returns an error
// when items is empty, mixes kinds, or holds an invalid number, and when raw is
// empty for two or more items or set for one.
func NewList(raw string, items ...Literal) (List, error) {
	l := List{Items: append([]Literal(nil), items...), Raw: raw}
	if err := validateList(l); err != nil {
		return List{}, err
	}
	return l, nil
}

func validateList(l List) error {
	if len(l.Items) == 0 {
		return errors.New("list: no items")
	}
	if len(l.Items) == 1 && l.Raw != "" {
		return fmt.Errorf("list: raw token %q on a list of one", l.Raw)
	}
	if len(l.Items) > 1 && l.Raw == "" {
		return errors.New("list: no raw token on a list of several items")
	}
	kind := ""
	for i, it := range l.Items {
		var k string
		switch v := it.(type) {
		case String:
			k = "string"
		case Number:
			k = "number"
			if _, err := NewNumber(v.Text); err != nil {
				return fmt.Errorf("list item %d: %w", i, err)
			}
		case Bool:
			k = "bool"
		default:
			return fmt.Errorf("list item %d: %T is not a literal", i, it)
		}
		if kind != "" && k != kind {
			return fmt.Errorf("list item %d: a %s in a list of %ss", i, k, kind)
		}
		kind = k
	}
	return nil
}

func validatePath(what, path string) error {
	if path == "" || path[0] == '.' || path[0] == '[' {
		return nil
	}
	return fmt.Errorf("%s path %q: starts with neither a dot nor a bracket", what, path)
}

func validateOperand(o Operand) error {
	switch v := o.(type) {
	case nil:
		return errors.New("operand: nil")
	case Operation, ResourceType, String, Bool:
		return nil
	case Resource:
		return validatePath("resource", v.Path)
	case Subject:
		return validateSubject(v)
	case PIPRef:
		if v.Name == "" {
			return errors.New("PIP reference: no name")
		}
		if v.Filtered && !strings.HasSuffix(v.Name, ".filtered") {
			return fmt.Errorf("PIP reference %q FILTERED: the name does not end with .filtered", v.Name)
		}
		if !v.Filtered && v.FilteredOperation != "" {
			return fmt.Errorf("PIP reference %q: an operation without FILTERED", v.Name)
		}
		return nil
	case Entitled:
		if len(v.As) == 0 {
			return errors.New("entitledResources: no names in as()")
		}
		return nil
	case PassValue:
		if v.Var == "" {
			return errors.New("pass value: no variable")
		}
		if v.Key == "" {
			return errors.New("pass value: no key")
		}
		return nil
	case Number:
		_, err := NewNumber(v.Text)
		return err
	case List:
		return validateList(v)
	case Pattern:
		if v.Text == "" {
			return errors.New("pattern: empty")
		}
		return nil
	case Unsupported:
		return validateUnsupported(v)
	default:
		return fmt.Errorf("operand: unknown type %T", o)
	}
}

func validateSubject(s Subject) error {
	if !slices.Contains(subjectAttrs, s.Attr) {
		return fmt.Errorf("subject attribute %q: not a built-in attribute", s.Attr)
	}
	if s.Key != "" && s.Attr != SubjectPermissionScope {
		return fmt.Errorf("subject.%s: takes no key, got %q", s.Attr, s.Key)
	}
	if s.Key == "" && s.Attr == SubjectPermissionScope {
		return errors.New("subject.permissionScope: no key")
	}
	return nil
}
