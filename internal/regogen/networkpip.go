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
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

// PIPDecl is nc.pip, which returns the record of a network reference other
// than a GENERAL or FILTERED PIP, such as subject.entitledResources, from
// the input the query was given ([Input.PIPRecord]).
var PIPDecl = &ast.Builtin{
	Name: "nc.pip",
	Decl: types.NewFunction(types.Args(types.Named("id", types.S)),
		types.Named("record", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)))),
}

type inputKey struct{}

// pipFunction is the implementation of nc.pip: it reads the record from the
// input that [Input.Context] put into the query's context.
func pipFunction() func(*rego.Rego) {
	return rego.Function1(&rego.Function{Name: PIPDecl.Name, Decl: PIPDecl.Decl},
		func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			in, ok := bctx.Context.Value(inputKey{}).(*Input)
			if !ok {
				return nil, fmt.Errorf("nc.pip: the query carries no input of the module")
			}
			id, ok := a.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("nc.pip: the reference %v is not a string", a)
			}
			t, ok := in.PIPRecord(string(id))
			if !ok {
				return nil, fmt.Errorf("nc.pip: no record of %s", id)
			}
			return t, nil
		})
}

// Context returns ctx with what nc.jsonpath needs to read input.resource as
// the document it was built from, and what nc.pip returns; evaluate the
// module's query with it.
func (in *Input) Context(ctx context.Context) context.Context {
	return context.WithValue(in.docs.Context(ctx), inputKey{}, in)
}
