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

package policies

import (
	"strings"
	"testing"
)

// TestModules_ProductPoliciesOnly: the two product packages are embedded
// and no test module is, so the service never carries fixtures.
func TestModules_ProductPoliciesOnly(t *testing.T) {
	modules, err := Modules()
	if err != nil {
		t.Fatalf("Modules: %v", err)
	}
	for _, want := range []string{"identity.rego", "authorize_internals.rego"} {
		if _, ok := modules[want]; !ok {
			t.Errorf("embedded policies lack %s; got %d modules", want, len(modules))
		}
	}
	for name, src := range modules {
		if strings.HasSuffix(name, "_test.rego") {
			t.Errorf("test module %s must not be embedded", name)
		}
		if !strings.Contains(src, "package ") {
			t.Errorf("module %s carries no package clause", name)
		}
	}
}
