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
	"strings"

	"authz-agent/internal/policyir"
)

// Rejection is one form of a tenant's tree that the legacy service executes
// and the agent cannot: a form [policyir.Tree.Unsupported] lists, or a
// comparison the generator has no translation for.
type Rejection struct {
	// Where places the form: for a form the tree lists, the path of
	// [policyir.Finding.Where], such as
	// `set "s1" > policy "p1" > rule "r1" > condition`; for a comparison,
	// the innermost set, the policy, the rule, and the place of its condition,
	// such as `set "s1" > policy "p1" > rule "r1" > rule_condition`, and the
	// operation of the copy of the tree that subject allowed reads.
	Where string
	// Form names the kind of form: a [policyir.Form], FormGenerator, or
	// FormSpecification.
	Form policyir.Form
	// Text quotes the form, or says what the generator lacks.
	Text string
}

// The forms of a [Rejection] for a comparison: FormGenerator for a cell whose
// outcome the values decide and no template of the generator answers,
// FormSpecification for a cell the specification answers unsupported or bad
// request.
const (
	FormGenerator     policyir.Form = "generator"
	FormSpecification policyir.Form = "specification"
)

// gapError is a comparison the generator cannot translate, of form.
type gapError struct {
	form policyir.Form
	err  error
}

func gap(form policyir.Form, err error) error { return &gapError{form: form, err: err} }

func (e *gapError) Error() string { return e.err.Error() }
func (e *gapError) Unwrap() error { return e.err }

// RejectedError is the error [Generate] returns for a tree with a form the
// agent cannot execute: the candidate snapshot of the tenant is rejected as a
// whole, and none of its forms is executed in part. It lists every form
// [policyir.Tree.Unsupported] finds, or else the first comparison the
// generator cannot translate. A defect of the export, such as a missing cell
// or knob, is another error: it is no form of the tenant's.
type RejectedError struct {
	Rejections []Rejection
}

func (e *RejectedError) Error() string {
	parts := make([]string, len(e.Rejections))
	for i, r := range e.Rejections {
		parts[i] = fmt.Sprintf("%s: %s: %s", r.Where, r.Form, r.Text)
	}
	return "the tenant has a form the agent cannot execute: " + strings.Join(parts, "; ")
}

// Failure is a part of the tenant that the module reads as a permanent
// failure of its source: a set the legacy service never evaluates
// ([policyir.PolicySet.AlwaysFails]), a set or a PIP declaration a damaged
// export leaves unusable ([policyir.PolicySet.Isolated],
// [policyir.PIP.Isolated]), or a PIP a condition reads and the tenant does not
// declare. The module answers such a part as a failed source does, and the
// tenant stays in service; the list is what a health check reports.
type Failure struct {
	// Set is the ID of the failing set, or of the innermost set whose
	// condition reads the failing PIP.
	Set string
	// PIP is the name of the failing PIP, empty for a failing set.
	PIP string
	// Reason says why the part fails.
	Reason string
}

// fail records a failure once.
func (g *gen) fail(f Failure) {
	for _, x := range g.failures {
		if x == f {
			return
		}
	}
	g.failures = append(g.failures, f)
}

// whereText places the condition the generator translates, as
// [Rejection.Where] describes.
func (g *gen) whereText() string {
	var parts []string
	if g.where.set != "" {
		parts = append(parts, fmt.Sprintf("set %q", g.where.set))
	}
	if g.where.policy != "" {
		parts = append(parts, fmt.Sprintf("policy %q", g.where.policy))
	}
	if g.where.rule != "" {
		parts = append(parts, fmt.Sprintf("rule %q", g.where.rule))
	}
	if g.where.place != "" {
		parts = append(parts, string(g.where.place))
	}
	if g.fixedOp != nil {
		parts = append(parts, fmt.Sprintf("(subject allowed %q)", *g.fixedOp))
	}
	return strings.Join(parts, " > ")
}
