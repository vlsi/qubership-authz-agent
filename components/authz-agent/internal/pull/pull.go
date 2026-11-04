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
// sent. [Puller.Status] reports the first successful load, which readiness
// waits for.
package pull

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
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
	// Snapshots receives the fetched documents as the source sent them; nil
	// sends them nowhere.
	Snapshots SnapshotLoader
}

// SnapshotLoader builds the per-tenant policies from the documents of
// /access/v3/config/policySets and /access/v3/config/pips. An error means
// the documents could not be read at all, and nothing was published.
type SnapshotLoader interface {
	LoadSnapshots(ctx context.Context, policySets, pips []byte) error
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

// Status reports the pull. PoliciesLoaded is set by the first successful
// load and never cleared: a source that becomes unreachable leaves the
// snapshots already published, which are better than none. Reason
// explains a PoliciesLoaded set without a load because the pull is
// disabled.
type Status struct {
	PoliciesLoaded bool   `json:"policiesLoaded"`
	FirstSuccessAt string `json:"firstSuccessAt,omitempty"`
	LastSuccessAt  string `json:"lastSuccessAt,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// Puller loads the documents into the snapshots.
type Puller struct {
	cfg    Config
	tokens Tokens
	log    Logger
	client *http.Client

	mu           sync.Mutex
	status       Status
	firstSuccess time.Time
}

// New returns a puller for cfg; an HTTPTimeout that is zero or negative
// and a negative Interval take the defaults.
func New(cfg Config, tokens Tokens, logger Logger) *Puller {
	if cfg.Interval < 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	return &Puller{
		cfg:    cfg,
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
// snapshots and is retried on the next tick.
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
		p.log.Warnf("policies: pull failed, keeping the previous snapshots: %v", err)
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
// them into the snapshots.
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
	if p.cfg.Snapshots != nil {
		if err := p.cfg.Snapshots.LoadSnapshots(ctx, policySets, pipsRaw); err != nil {
			return fmt.Errorf("load snapshots: %w", err)
		}
	}
	p.mu.Lock()
	first := p.firstSuccess.IsZero()
	p.mu.Unlock()
	// Every tick loads the source again, changed or not, so after the first
	// load this line only repeats itself: 2880 identical lines a day at the
	// default 30-second interval.
	report := p.log.Debugf
	if first {
		report = p.log.Infof
	}
	report("policies: updated from %s", p.cfg.SourceURL)
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
	}
}

func (p *Puller) disabled(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = Status{PoliciesLoaded: true, Reason: reason}
}
