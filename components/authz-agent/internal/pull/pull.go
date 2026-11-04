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

// Package pull keeps the policies in step with their source, the v3
// configuration API of the policy source, fetched every interval: the
// per-tenant snapshots of [Config.Snapshots], built from the documents as
// sent, and data.policies and data.pips, the documents converted to the
// simplified model that the embedded policies of check/filter read.
// [Puller.Status] reports the first successful load, which
// readiness waits for, and the counts of the last conversion.
package pull

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/util"

	"authz-agent/internal/acconfig"
	"authz-agent/internal/pips"
	"authz-agent/internal/simplifiedpolicies"
)

// Defaults of Config.
const (
	DefaultInterval    = 30 * time.Second
	DefaultHTTPTimeout = 30 * time.Second
	// tokenWait bounds how long the first pull waits for the m2m token.
	tokenWait = 15 * time.Second
)

// Config selects the source. A zero Interval or an empty SourceURL
// disables the pull; the status then reports the policies as loaded, so
// that readiness does not wait for a load that never comes.
type Config struct {
	// SourceURL is the base URL of the policy source, whose
	// /access/v3/config/policySets and /access/v3/config/pips are fetched.
	SourceURL string
	// Interval is the pull period.
	Interval time.Duration
	// HTTPTimeout bounds one fetch from the source.
	HTTPTimeout time.Duration
	// Entitlements is the entitlements PIP pinned by the deployment; nil
	// adds none.
	Entitlements *pips.EntitlementsConfig
	// Snapshots receives the fetched documents as the source sent them,
	// before they are converted for the embedded policies; nil sends them
	// nowhere.
	Snapshots SnapshotLoader
}

// SnapshotLoader builds the per-tenant policies from the documents of
// /access/v3/config/policySets and /access/v3/config/pips. An error means
// the documents could not be read at all, and nothing was published.
type SnapshotLoader interface {
	LoadSnapshots(ctx context.Context, policySets, pips []byte) error
}

// Putter receives the documents.
type Putter interface {
	Put(ctx context.Context, path []string, value any) error
}

// Tokens supplies the bearer token the source is fetched with; nil fetches
// without one. When Bearer returns an error, such as for a token that has
// expired, the pull sends no request and fails with that error.
type Tokens interface {
	Bearer() (string, error)
	Ready() <-chan struct{}
}

// Logger receives the diagnostics.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Conversion counts what the last conversion of the source's policy sets
// produced. A pull that fetched every policy set and converted none is a
// successful pull by every other measure, and it is what an authorization
// outage looks like from outside.
type Conversion struct {
	PolicySets        int `json:"policySets"`
	PolicySetsSkipped int `json:"policySetsSkipped"`
	Rules             int `json:"rules"`
	RulesSkipped      int `json:"rulesSkipped"`
	RulesDenySkipped  int `json:"rulesDenySkipped"`
	Policies          int `json:"policies"`
}

// Status reports the pull. PoliciesLoaded is set by the first successful
// load and never cleared: a source that becomes unreachable leaves the
// documents already in the store, which are better than none. Reason
// explains a PoliciesLoaded set without a load because the pull is
// disabled.
type Status struct {
	PoliciesLoaded bool        `json:"policiesLoaded"`
	FirstSuccessAt string      `json:"firstSuccessAt,omitempty"`
	LastSuccessAt  string      `json:"lastSuccessAt,omitempty"`
	Reason         string      `json:"reason,omitempty"`
	Conversion     *Conversion `json:"conversion,omitempty"`
}

// Puller loads the documents into one store.
type Puller struct {
	cfg    Config
	store  Putter
	tokens Tokens
	log    Logger
	client *http.Client

	mu             sync.Mutex
	status         Status
	firstSuccess   time.Time
	lastConversion *Conversion
}

// New returns a puller for cfg; an HTTPTimeout that is zero or negative
// and a negative Interval take the defaults.
func New(cfg Config, store Putter, tokens Tokens, logger Logger) *Puller {
	if cfg.Interval < 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	return &Puller{
		cfg:    cfg,
		store:  store,
		tokens: tokens,
		log:    logger,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// Status is the state of the pull.
func (p *Puller) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Run loads the documents from the source every interval until ctx ends,
// starting with an immediate load. A failed load keeps the previous
// documents and is retried on the next tick.
func (p *Puller) Run(ctx context.Context) {
	if strings.TrimSpace(p.cfg.SourceURL) == "" {
		p.log.Infof("policies: pull disabled, no source URL")
		p.disabled("pull disabled: source URL empty")
		return
	}
	if p.cfg.Interval == 0 {
		p.log.Infof("policies: pull disabled, interval is 0")
		p.disabled("pull disabled: interval is 0")
		return
	}
	p.log.Infof("policies: pulling from %s every %s", p.cfg.SourceURL, p.cfg.Interval)
	p.waitForToken(ctx)
	p.pull(ctx)
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pull(ctx)
		}
	}
}

func (p *Puller) pull(ctx context.Context) {
	if err := p.PullOnce(ctx); err != nil {
		p.log.Warnf("policies: pull failed, keeping the previous documents: %v", err)
		return
	}
	p.loaded()
}

// waitForToken gives the token source a bounded time to obtain the first
// token, so the first pull is not a foreseeable 401.
func (p *Puller) waitForToken(ctx context.Context) {
	if p.tokens == nil {
		return
	}
	select {
	case <-p.tokens.Ready():
	case <-ctx.Done():
	case <-time.After(tokenWait):
		p.log.Warnf("policies: no m2m token after %s, pulling without one", tokenWait)
	}
}

// PullOnce fetches the policy sets and the PIPs from the source and loads
// them into the snapshots and into the documents of the store, each apart:
// the documents are untouched when a step of their conversion fails, and
// a failure of either is returned.
//
// The load is reported at info until [Puller.Run] has recorded a first
// success, and at debug from then on, so a caller that drives PullOnce
// itself reports every load at info.
func (p *Puller) PullOnce(ctx context.Context) error {
	token := ""
	if p.tokens != nil {
		var err error
		if token, err = p.tokens.Bearer(); err != nil {
			return fmt.Errorf("fetch policySets: no token to present: %w", err)
		}
	}
	policySets, err := p.fetch(ctx, p.cfg.SourceURL+"/access/v3/config/policySets", token)
	if err != nil {
		return fmt.Errorf("fetch policySets: %w", err)
	}
	pipsRaw, err := p.fetch(ctx, p.cfg.SourceURL+"/access/v3/config/pips", token)
	if err != nil {
		return fmt.Errorf("fetch pips: %w", err)
	}
	var snapErr error
	if p.cfg.Snapshots != nil {
		if err := p.cfg.Snapshots.LoadSnapshots(ctx, policySets, pipsRaw); err != nil {
			snapErr = fmt.Errorf("load snapshots: %w", err)
		}
	}
	// the documents of check/filter load whether or not the snapshots did
	fail := func(err error) error { return errors.Join(snapErr, err) }
	policyList, stats, err := acconfig.ConvertPolicySets(policySets, p.log)
	if err != nil {
		return fail(fmt.Errorf("convert policySets: %w", err))
	}
	conversion := Conversion(stats)
	if stats.RulesSkipped > 0 || stats.PolicySetsSkipped > 0 {
		p.log.Warnf("policies: conversion dropped data: %d/%d policy sets and %d/%d rules could not be converted (%d policies produced)",
			stats.PolicySetsSkipped, stats.PolicySets, stats.RulesSkipped, stats.Rules, stats.Policies)
	}
	pipList, err := acconfig.ConvertPIPs(pipsRaw, p.log)
	if err != nil {
		return fail(fmt.Errorf("convert pips: %w", err))
	}
	policies, err := simplifiedpolicies.NormalizePolicies(policyList)
	if err != nil {
		return fail(fmt.Errorf("normalize policies: %w", err))
	}
	pipDoc, _, err := pips.NormalizeItems(pipList)
	if err != nil {
		return fail(fmt.Errorf("normalize pips: %w", err))
	}
	if err := p.load(ctx, policies, pipDoc); err != nil {
		return fail(err)
	}
	p.mu.Lock()
	p.lastConversion = &conversion
	first := p.firstSuccess.IsZero()
	p.mu.Unlock()
	// Every tick loads the source again, changed or not, so after the first
	// load this line only repeats itself: 2880 identical lines a day at the
	// default 30-second interval.
	report := p.log.Debugf
	if first {
		report = p.log.Infof
	}
	report("policies: updated (%d policies, %d PIPs)", stats.Policies, len(pipList))
	return snapErr
}

// load completes the PIP document with the pinned entitlements and the
// activation index of the general PIPs, then stores both documents in the
// form [roundTrip] gives them.
func (p *Puller) load(ctx context.Context, policies map[string]any, pipDoc *pips.PIPDocument) error {
	pips.ApplyEntitlementsOverride(pipDoc, p.cfg.Entitlements)
	pipDoc.Normalized.Activation.GeneralByResourceTypeOperation = pips.BuildActivationIndexFromPolicies(pipDoc.Normalized.Remote.General, policies)
	policiesDoc, err := roundTrip(policies)
	if err != nil {
		return fmt.Errorf("encode policies: %w", err)
	}
	pipsDoc, err := roundTrip(pipDoc.Normalized)
	if err != nil {
		return fmt.Errorf("encode pips: %w", err)
	}
	if err := p.store.Put(ctx, []string{"policies"}, policiesDoc); err != nil {
		return fmt.Errorf("store policies: %w", err)
	}
	if err := p.store.Put(ctx, []string{"pips"}, pipsDoc); err != nil {
		return fmt.Errorf("store pips: %w", err)
	}
	return nil
}

func (p *Puller) fetch(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (p *Puller) loaded() {
	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.firstSuccess.IsZero() {
		p.firstSuccess = now
	}
	p.status = Status{
		PoliciesLoaded: true,
		FirstSuccessAt: p.firstSuccess.Format(time.RFC3339),
		LastSuccessAt:  now.Format(time.RFC3339),
		Conversion:     p.lastConversion,
	}
}

func (p *Puller) disabled(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = Status{PoliciesLoaded: true, Reason: reason}
}

// roundTrip converts a Go value to the JSON values the store holds, with
// numbers as json.Number, as OPA's own JSON decoding produces them.
func roundTrip(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := util.UnmarshalJSON(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
