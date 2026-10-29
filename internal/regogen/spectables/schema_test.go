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

package spectables

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// schema.json is what the exporter writes against, so each enumeration in it
// must list the same values as the Go enumeration the loader checks. When this
// test fails, update schema.json and the Go list together.
func TestSchemaListsTheValuesTheLoaderAccepts(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Enum     []string `json:"enum"`
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema.json: %v", err)
	}
	var unary []Operator
	for _, o := range Operators {
		if o.Unary() {
			unary = append(unary, o)
		}
	}
	agent, _ := Outcomes(ProfileAgent)
	legacy, _ := Outcomes(ProfileLegacy)
	tests := []struct {
		def  string
		want []string
	}{
		{"operator", names(Operators)},
		{"unaryOperator", names(unary)},
		{"kind", names(Kinds)},
		{"state", names(States)},
		{"class", names(Classes)},
		{"place", names(Places)},
		{"effect", names(Effects)},
		{"agentOutcome", names(agent)},
		{"legacyOutcome", names(legacy)},
		{"agentValueOutcome", names(valueOutcomes(ProfileAgent))},
		{"legacyValueOutcome", names(valueOutcomes(ProfileLegacy))},
		{"valueRule", names(ValueRules)},
		{"nodeOutcome", names(NodeOutcomes)},
		{"algorithm", Algorithms},
		{"ruleEffect", RuleEffects},
		{"absentEffect", AbsentEffects},
	}
	for _, tt := range tests {
		if got := schema.Defs[tt.def].Enum; !slices.Equal(got, tt.want) {
			t.Errorf("schema.json $defs.%s.enum = %q, want %q", tt.def, got, tt.want)
		}
	}
	if got := schema.Defs["knobs"].Required; !slices.Equal(got, RequiredKnobs) {
		t.Errorf("schema.json $defs.knobs.required = %q, want %q", got, RequiredKnobs)
	}
}

func names[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}
