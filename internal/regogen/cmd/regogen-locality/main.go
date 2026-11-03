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

// Regogen-locality measures how far a small edit of one policy set spreads
// through the generated module.
//
// It reads the bundles regogen-corpus reads and takes the tenants with at
// least -min-sets policy sets. In each it picks one set, the touched set, and
// makes four edits of it, each on its own: a rule's condition gains a
// conjunct, a rule's target gains a conjunct, a policy is copied under a new
// id with another operation in its target, and a policy is removed. For each
// edit it generates the module before and after and counts the lines git diff
// adds and removes. It also generates the module of a tenant that holds the
// touched set alone, before and after the edit; the lines that diff changes
// are the edit's own, and the rest of the tenant's diff is the spread:
//
//	outside = max(0, changed - own)
//
// It prints one JSON line per bundle and edit and, at the end, the totals.
//
//	regogen-locality -bundles bundles.jsonl [-min-sets 3] [-max-sets 60] [-limit 40] [-groups] [-keep DIR]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen"
	"authz-agent/internal/regogen/spectables"
)

type bundle struct {
	Key        string          `json:"key"`
	Tenant     string          `json:"tenant"`
	PolicySets json.RawMessage `json:"policySets"`
	PIPs       json.RawMessage `json:"pips"`
}

// export is the part of a v3 export the edits change; the sets stay raw JSON
// objects, so that every other field is kept as it is.
type export struct {
	PolicySets []map[string]any `json:"policySets"`
}

type result struct {
	Key     string `json:"key"`
	Edit    string `json:"edit"`
	Set     string `json:"set,omitempty"`
	Lines   int    `json:"lines"`
	Changed int    `json:"changed"`
	Own     int    `json:"own"`
	Outside int    `json:"outside"`
	Error   string `json:"error,omitempty"`
}

func main() {
	path := flag.String("bundles", "", "bundles.jsonl")
	minSets := flag.Int("min-sets", 3, "fewest policy sets of a tenant")
	maxSets := flag.Int("max-sets", 60, "most policy sets of a tenant")
	limit := flag.Int("limit", 40, "tenants to measure, 0 for all")
	groups := flag.Bool("groups", false, "subject groups")
	keep := flag.String("keep", "", "directory to keep the modules in")
	flag.Parse()
	tab, err := regogen.DefaultTable()
	if err != nil {
		fail(err)
	}
	opt := regogen.DefaultOptions()
	opt.Groups = *groups
	dir := *keep
	if dir == "" {
		if dir, err = os.MkdirTemp("", "regogen-locality"); err != nil {
			fail(err)
		}
		defer os.RemoveAll(dir)
	}
	f, err := os.Open(*path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	enc := json.NewEncoder(os.Stdout)
	totals := map[string]*result{}
	var order []string
	measured := 0
	for dec.More() && (*limit == 0 || measured < *limit) {
		var b bundle
		if err := dec.Decode(&b); err != nil {
			fail(err)
		}
		var exp export
		if err := json.Unmarshal(b.PolicySets, &exp); err != nil {
			fail(fmt.Errorf("%s: %w", b.Key, err))
		}
		if n := len(exp.PolicySets); n < *minSets || n > *maxSets {
			continue
		}
		at := touched(exp.PolicySets)
		if at < 0 {
			continue
		}
		measured++
		for _, e := range edits {
			r := measure(b, exp, at, e, tab, opt, dir)
			_ = enc.Encode(r)
			t, ok := totals[e.name]
			if !ok {
				t = &result{Key: "total", Edit: e.name}
				totals[e.name] = t
				order = append(order, e.name)
			}
			if r.Error == "" {
				t.Lines += r.Lines
				t.Changed += r.Changed
				t.Own += r.Own
				t.Outside += r.Outside
			}
		}
	}
	for _, name := range order {
		_ = enc.Encode(totals[name])
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// touched returns the index of the set the edits change: the middle one of
// the sets that hold a rule with a condition, so that sets precede and follow
// it; -1 when no set holds such a rule.
func touched(sets []map[string]any) int {
	var with []int
	for i, s := range sets {
		if firstRule(s) != nil {
			with = append(with, i)
		}
	}
	if len(with) == 0 {
		return -1
	}
	return with[len(with)/2]
}

func policies(s map[string]any) []any {
	ps, _ := s["policies"].([]any)
	return ps
}

// firstRule returns the first rule of s that has a condition.
func firstRule(s map[string]any) map[string]any {
	for _, p := range policies(s) {
		rs, _ := p.(map[string]any)["rules"].([]any)
		for _, r := range rs {
			r := r.(map[string]any)
			if c, _ := r["condition"].(string); c != "" {
				return r
			}
		}
	}
	return nil
}

type edit struct {
	name  string
	apply func(s map[string]any)
}

const probe = "subject.id == 'locality-probe'"

var edits = []edit{
	{"condition", func(s map[string]any) {
		r := firstRule(s)
		r["condition"] = r["condition"].(string) + " AND " + probe
	}},
	{"target", func(s map[string]any) {
		r := firstRule(s)
		if t, _ := r["target"].(string); t != "" {
			r["target"] = t + " AND " + probe
		} else {
			r["target"] = probe
		}
	}},
	{"add-policy", func(s map[string]any) {
		ps := policies(s)
		p := clone(ps[len(ps)-1]).(map[string]any)
		p["policyId"] = fmt.Sprint(p["policyId"]) + "-locality-probe"
		p["target"] = "operation == 'LOCALITY_PROBE'"
		s["policies"] = append(ps, p)
	}},
	{"remove-policy", func(s map[string]any) {
		ps := policies(s)
		s["policies"] = slices.Delete(slices.Clone(ps), 0, 1)
	}},
}

func clone(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// measure generates the modules of the tenant and of the touched set alone,
// before and after edit e, and counts the lines that differ.
func measure(b bundle, exp export, at int, e edit, tab *spectables.Table, opt regogen.Options,
	dir string) result {
	r := result{Key: b.Key, Edit: e.name, Set: fmt.Sprint(exp.PolicySets[at]["policySetId"])}
	after := clone(exp.PolicySets).([]any)
	e.apply(after[at].(map[string]any))
	before := clone(exp.PolicySets).([]any)
	base := filepath.Join(dir, strings.ReplaceAll(b.Key, "/", "_")+"."+e.name)
	var err error
	texts := map[string]string{}
	for name, sets := range map[string][]any{"before": before, "after": after,
		"own-before": {before[at]}, "own-after": {after[at]}} {
		if texts[name], err = module(b, sets, tab, opt); err != nil {
			r.Error = name + ": " + err.Error()
			return r
		}
		if err := os.WriteFile(base+"."+name+".rego", []byte(texts[name]), 0o644); err != nil {
			fail(err)
		}
	}
	r.Lines = strings.Count(texts["after"], "\n")
	if r.Changed, err = changed(base+".before.rego", base+".after.rego"); err != nil {
		r.Error = err.Error()
		return r
	}
	if r.Own, err = changed(base+".own-before.rego", base+".own-after.rego"); err != nil {
		r.Error = err.Error()
		return r
	}
	r.Outside = max(0, r.Changed-r.Own)
	return r
}

// module generates the module of the tenant b with these policy sets.
func module(b bundle, sets []any, tab *spectables.Table, opt regogen.Options) (string, error) {
	raw, err := json.Marshal(map[string]any{"policySets": sets})
	if err != nil {
		return "", err
	}
	exp, err := policyir.FromRegular(raw, b.PIPs)
	if err != nil {
		return "", err
	}
	tree, ok := exp.Trees[b.Tenant]
	if !ok {
		return "", fmt.Errorf("no tree of tenant %s: failed %v", b.Tenant, exp.Failed[b.Tenant])
	}
	m, err := regogen.Generate(tree, tab, opt)
	if err != nil {
		return "", err
	}
	return m.Text, nil
}

// changed returns the lines git diff adds and removes between two files.
func changed(a, b string) (int, error) {
	out, err := exec.Command("git", "diff", "--no-index", "--numstat", "--histogram", a, b).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			return 0, fmt.Errorf("git diff: %w", err)
		}
	}
	fields := strings.Fields(string(bytes.TrimSpace(out)))
	if len(fields) < 2 {
		return 0, nil
	}
	add, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, err
	}
	del, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, err
	}
	return add + del, nil
}
