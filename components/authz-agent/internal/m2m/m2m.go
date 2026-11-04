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

// Package m2m keeps the agent's own bearer token current: the token the
// policy pull presents to the policy source, and the token the PIP calls
// present through data.m2m.bearerToken until data.m2m.expiresAtNs. A
// [Source] either obtains the token from the identity provider with client
// credentials and refreshes it before it expires, or reads it from a file
// another party keeps current, such as a projected service account token.
package m2m

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Defaults of Config.
const (
	DefaultClientIDFile     = "/etc/secret/username"
	DefaultClientSecretFile = "/etc/secret/password"
	// DefaultTokenFile is where the platform's charts mount the projected
	// token of the netcracker audience, one directory per audience under
	// /var/run/secrets/tokens.
	DefaultTokenFile     = "/var/run/secrets/tokens/netcracker/token"
	DefaultRenewBefore   = 60 * time.Second
	DefaultWatchInterval = 15 * time.Second

	initialBackoff = 2 * time.Second
	maxBackoff     = 5 * time.Minute
)

// Config selects the source of the token. TokenURL selects client
// credentials: the id and the secret are read from their files on every
// fetch, and the token is refreshed RenewBefore its expiry, at the expiry
// itself when RenewBefore is zero. An empty TokenURL selects the file:
// TokenFile is read every WatchInterval, the default interval when zero or
// negative, and a changed content is published.
type Config struct {
	TokenURL         string
	ClientIDFile     string
	ClientSecretFile string
	RenewBefore      time.Duration

	TokenFile     string
	WatchInterval time.Duration
}

// Putter receives the m2m document.
type Putter interface {
	Put(ctx context.Context, path []string, value any) error
}

// Logger receives the diagnostics.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Errors of [Source.Bearer].
var (
	ErrNoToken      = errors.New("m2m token: no token yet")
	ErrTokenExpired = errors.New("m2m token: expired")
)

// Source holds the current token. Bearer is safe to call from any
// goroutine while Run refreshes it.
type Source struct {
	cfg    Config
	store  Putter
	log    Logger
	client *http.Client
	now    func() time.Time

	mu    sync.RWMutex
	token string
	// expires is when token stops being valid, zero when that is unknown:
	// a token from the file that is not a JWT with an exp claim.
	expires time.Time
	hash    string
	ready   chan struct{}
	once    sync.Once
}

// New returns a source for cfg, with the defaults in place of the empty
// files, a negative RenewBefore, and a WatchInterval that is zero or
// negative; Run has to be started for it to hold a token.
func New(cfg Config, store Putter, log Logger) *Source {
	if cfg.ClientIDFile == "" {
		cfg.ClientIDFile = DefaultClientIDFile
	}
	if cfg.ClientSecretFile == "" {
		cfg.ClientSecretFile = DefaultClientSecretFile
	}
	if cfg.RenewBefore < 0 {
		cfg.RenewBefore = DefaultRenewBefore
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = DefaultTokenFile
	}
	if cfg.WatchInterval <= 0 {
		cfg.WatchInterval = DefaultWatchInterval
	}
	return &Source{
		cfg:    cfg,
		store:  store,
		log:    log,
		client: &http.Client{Timeout: 30 * time.Second},
		now:    time.Now,
		ready:  make(chan struct{}),
	}
}

// Bearer returns the token a call presents. It returns [ErrNoToken] before
// the first token arrived, and [ErrTokenExpired] once the current token is
// past its expiry: the expires_in of the grant or, without it and for a token
// from the file, the token's exp claim. A refresh that fails keeps the
// current token until then.
func (s *Source) Bearer() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch {
	case s.token == "":
		return "", ErrNoToken
	case !s.expires.IsZero() && !s.now().Before(s.expires):
		return "", fmt.Errorf("%w at %s", ErrTokenExpired, s.expires.UTC().Format(time.RFC3339))
	}
	return s.token, nil
}

// Ready is closed once the first token has been published.
func (s *Source) Ready() <-chan struct{} { return s.ready }

// Run keeps the token current until ctx ends.
func (s *Source) Run(ctx context.Context) {
	if s.cfg.TokenURL != "" {
		s.log.Infof("m2m token: client credentials from %s, refreshed %s before expiry", s.cfg.TokenURL, s.cfg.RenewBefore)
		s.runClientCredentials(ctx)
		return
	}
	s.log.Infof("m2m token: watching %s every %s", s.cfg.TokenFile, s.cfg.WatchInterval)
	s.runFile(ctx)
}

// runClientCredentials fetches a token, publishes it, and sleeps until the
// renewal is due: RenewBefore before the expiry, no later than half the
// lifetime, and never sooner than one second. A failed fetch is retried
// with a backoff that doubles up to five minutes.
func (s *Source) runClientCredentials(ctx context.Context) {
	backoff := initialBackoff
	for {
		var sleep time.Duration
		lifetime, err := s.fetchAndPublish(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warnf("m2m token: fetch failed: %v; retrying in %s", err, backoff)
			sleep, backoff = backoff, min(backoff*2, maxBackoff)
		} else {
			sleep = renewal(lifetime, s.cfg.RenewBefore)
			backoff = initialBackoff
			s.log.Infof("m2m token: refreshed; next refresh in %s", sleep)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
	}
}

// renewal is the wait before the next fetch for a token that lives
// lifetime.
func renewal(lifetime, renewBefore time.Duration) time.Duration {
	sleep := lifetime - renewBefore
	if half := lifetime / 2; sleep < half {
		sleep = half
	}
	if sleep < time.Second {
		sleep = time.Second
	}
	return sleep
}

func (s *Source) fetchAndPublish(ctx context.Context) (time.Duration, error) {
	clientID, err := readFile(s.cfg.ClientIDFile)
	if err != nil {
		return 0, fmt.Errorf("read client id: %w", err)
	}
	clientSecret, err := readFile(s.cfg.ClientSecretFile)
	if err != nil {
		return 0, fmt.Errorf("read client secret: %w", err)
	}
	token, lifetime, err := fetchToken(ctx, s.client, s.cfg.TokenURL, clientID, clientSecret)
	if err != nil {
		return 0, err
	}
	if err := s.publish(ctx, token, s.now().Add(lifetime)); err != nil {
		return 0, err
	}
	return lifetime, nil
}

// runFile publishes the file's content whenever it changes; a missing
// file is waited for.
func (s *Source) runFile(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.WatchInterval)
	defer ticker.Stop()
	for {
		if err := s.checkFile(ctx); err != nil {
			s.log.Warnf("m2m token: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Source) checkFile(ctx context.Context) error {
	raw, err := os.ReadFile(s.cfg.TokenFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", s.cfg.TokenFile, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	s.mu.RLock()
	unchanged := hash == s.hash
	s.mu.RUnlock()
	if unchanged {
		return nil
	}
	// a token that is not a JWT with exp, such as an opaque one, does not expire here
	expires, _ := jwtExpiry(token)
	if err := s.publish(ctx, token, expires); err != nil {
		return err
	}
	s.mu.Lock()
	s.hash = hash
	s.mu.Unlock()
	s.log.Infof("m2m token: updated from %s", s.cfg.TokenFile)
	return nil
}

// publish stores the token as data.m2m.bearerToken, with its expiry in Unix
// nanoseconds as data.m2m.expiresAtNs (0 for none), and makes it the current
// token, valid until expires, or with no known expiry when expires is zero.
func (s *Source) publish(ctx context.Context, token string, expires time.Time) error {
	var expiresAtNs int64
	if !expires.IsZero() {
		expiresAtNs = expires.UnixNano()
	}
	doc := map[string]any{"bearerToken": token, "expiresAtNs": expiresAtNs}
	if err := s.store.Put(ctx, []string{"m2m"}, doc); err != nil {
		return fmt.Errorf("publish data.m2m: %w", err)
	}
	s.mu.Lock()
	s.token, s.expires = token, expires
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
	return nil
}

// fetchToken posts a client_credentials grant and returns the access token
// with its lifetime: expires_in when the response carries it, otherwise
// the time left until the token's exp claim.
func fetchToken(ctx context.Context, client *http.Client, tokenURL, clientID, clientSecret string) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("POST %s: %w", tokenURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, errors.New("empty access_token in response")
	}
	if tr.ExpiresIn > 0 {
		return tr.AccessToken, time.Duration(tr.ExpiresIn * float64(time.Second)), nil
	}
	exp, err := jwtExpiry(tr.AccessToken)
	if err != nil {
		return "", 0, fmt.Errorf("expires_in absent and JWT exp unreadable: %w", err)
	}
	lifetime := time.Until(exp)
	if lifetime < 0 {
		return "", 0, fmt.Errorf("JWT exp is in the past: %v", exp)
	}
	return tr.AccessToken, lifetime, nil
}

// jwtExpiry reads the exp claim of a token without verifying it; the token
// was just issued by the provider the service trusts.
func jwtExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, errors.New("not a JWT: too few parts")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, errors.New("exp claim absent or zero")
	}
	return time.Unix(int64(claims.Exp), 0), nil
}

func readFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
