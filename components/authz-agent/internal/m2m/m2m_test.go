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

package m2m

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type store struct {
	mu     sync.Mutex
	tokens []string
	// expires holds data.m2m.expiresAtNs of each published token.
	expires []int64
	// err, when set, is what Put returns, and the token is not recorded.
	err error
}

func (s *store) Put(_ context.Context, path []string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if !reflect.DeepEqual(path, []string{"m2m"}) {
		return fmt.Errorf("unexpected path %v", path)
	}
	doc := value.(map[string]any)
	s.tokens = append(s.tokens, doc["bearerToken"].(string))
	s.expires = append(s.expires, doc["expiresAtNs"].(int64))
	return nil
}

func (s *store) published() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tokens...)
}

// current returns the token src holds, expired or not, "" before the first.
func current(src *Source) string {
	src.mu.RLock()
	defer src.mu.RUnlock()
	return src.token
}

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after 2s waiting for %s", what)
}

// TestClientCredentials_PublishesTheToken: the grant is posted with the id
// and secret read from their files, and the token comes back through Token
// and as data.m2m.bearerToken.
func TestClientCredentials_PublishesTheToken(t *testing.T) {
	var form map[string][]string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		form = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"tok1","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{
		TokenURL:         idp.URL + "/token",
		ClientIDFile:     writeFile(t, "username", "agent\n"),
		ClientSecretFile: writeFile(t, "password", "s3cret"),
	}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	select {
	case <-src.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("no token within 2s")
	}
	if got := current(src); got != "tok1" {
		t.Errorf("current token = %q, want tok1", got)
	}
	if got := st.published(); !reflect.DeepEqual(got, []string{"tok1"}) {
		t.Errorf("published %v, want [tok1]", got)
	}
	want := map[string][]string{"grant_type": {"client_credentials"}, "client_id": {"agent"}, "client_secret": {"s3cret"}}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("grant form = %v, want %v", form, want)
	}
}

// TestClientCredentials_RefreshesBeforeExpiry: a token that lives two
// seconds and is renewed one second before its expiry is fetched again
// within that second, and the new token replaces the old one.
func TestClientCredentials_RefreshesBeforeExpiry(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		_, _ = fmt.Fprintf(w, `{"access_token":"tok%d","expires_in":2}`, fetches)
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b"), RenewBefore: time.Second}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	waitFor(t, "the first token", func() bool { return current(src) == "tok1" })
	waitFor(t, "the refreshed token", func() bool { return current(src) == "tok2" })
	if got := st.published(); !reflect.DeepEqual(got, []string{"tok1", "tok2"}) {
		t.Errorf("published %v, want [tok1 tok2]", got)
	}
}

// TestClientCredentials_RetriesAfterAFailure: a fetch the provider refuses
// is retried, and the token arrives once the provider answers.
func TestClientCredentials_RetriesAfterAFailure(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		if fetches == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	deadline := time.Now().Add(initialBackoff + 2*time.Second)
	for time.Now().Before(deadline) && current(src) == "" {
		time.Sleep(20 * time.Millisecond)
	}
	if got := current(src); got != "tok" || fetches != 2 {
		t.Errorf("current token = %q after %d fetches, want tok after the retry", got, fetches)
	}
}

// TestFetchAndPublish_AFailedFetchKeepsTheCurrentToken: a fetch the
// provider refuses returns its error and publishes nothing, so the token
// published before it stays in data.m2m and in Token.
func TestFetchAndPublish_AFailedFetchKeepsTheCurrentToken(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		if fetches > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok1","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}, st, quiet{})
	if _, err := src.fetchAndPublish(context.Background()); err != nil {
		t.Fatalf("fetchAndPublish() of the first token: error = %v", err)
	}

	if _, err := src.fetchAndPublish(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("fetchAndPublish() with the provider answering 500: error = %v, want one naming HTTP 500", err)
	}
	if got := current(src); got != "tok1" {
		t.Errorf("current token = %q, want tok1", got)
	}
	if got := st.published(); !reflect.DeepEqual(got, []string{"tok1"}) {
		t.Errorf("published %v, want [tok1]", got)
	}
}

// TestFetchAndPublish_AFailedPublishIsAnError: a token the store refuses is
// reported as an error, and Token stays empty.
func TestFetchAndPublish_AFailedPublishIsAnError(t *testing.T) {
	idp := tokenEndpoint(t, http.StatusOK, `{"access_token":"tok1","expires_in":300}`)
	refused := errors.New("store unavailable")
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}, &store{err: refused}, quiet{})

	if _, err := src.fetchAndPublish(context.Background()); !errors.Is(err, refused) {
		t.Errorf("fetchAndPublish() error = %v, want %v", err, refused)
	}
	if got := current(src); got != "" {
		t.Errorf("current token = %q, want none", got)
	}
}

// TestFetchAndPublish_AnUnreadableClientFilePostsNoGrant: a client id or
// client secret file that cannot be read is an error, and the token
// endpoint receives no request.
func TestFetchAndPublish_AnUnreadableClientFilePostsNoGrant(t *testing.T) {
	tests := []struct {
		name    string
		missing func(cfg *Config, path string)
	}{
		{"client id file missing", func(cfg *Config, path string) { cfg.ClientIDFile = path }},
		{"client secret file missing", func(cfg *Config, path string) { cfg.ClientSecretFile = path }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetches int
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fetches++
				_, _ = w.Write([]byte(`{"access_token":"tok1","expires_in":300}`))
			}))
			defer idp.Close()
			cfg := Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}
			tt.missing(&cfg, filepath.Join(t.TempDir(), "missing"))
			st := &store{}
			src := New(cfg, st, quiet{})

			if _, err := src.fetchAndPublish(context.Background()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("fetchAndPublish() error = %v, want %v", err, os.ErrNotExist)
			}
			if fetches != 0 {
				t.Errorf("requests at the token endpoint = %d, want 0", fetches)
			}
			if got := st.published(); len(got) != 0 {
				t.Errorf("published %v, want nothing", got)
			}
		})
	}
}

func TestRenewal(t *testing.T) {
	cases := []struct {
		name                  string
		lifetime, renewBefore time.Duration
		want                  time.Duration
	}{
		{"the margin before expiry", 300 * time.Second, 60 * time.Second, 240 * time.Second},
		{"no later than half the lifetime", 100 * time.Second, 60 * time.Second, 50 * time.Second},
		{"never sooner than one second", time.Second, 60 * time.Second, time.Second},
		{"at the expiry when RenewBefore is zero", 300 * time.Second, 0, 300 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewal(tc.lifetime, tc.renewBefore); got != tc.want {
				t.Errorf("renewal(%s, %s) = %s, want %s", tc.lifetime, tc.renewBefore, got, tc.want)
			}
		})
	}
}

func jwt(claims string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
}

// tokenEndpoint answers every request with status and body, as the identity
// provider's token endpoint would.
func tokenEndpoint(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchToken_Refuses: every answer the token endpoint can give that is
// not a token the service can use is refused, with the reason in the error.
// A token whose lifetime cannot be established is one of them: the source
// would otherwise have nothing to schedule its renewal from.
func TestFetchToken_Refuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		err    string
	}{
		{"exp in the past", 200, fmt.Sprintf(`{"access_token":%q}`, jwt(`{"exp":1}`)), "JWT exp is in the past"},
		{"no exp and no expires_in", 200, fmt.Sprintf(`{"access_token":%q}`, jwt(`{}`)), "exp claim absent"},
		{"an empty token", 200, `{"access_token":""}`, "empty access_token"},
		{"a body that is not JSON", 200, `nope`, "parse token response"},
		{"a refusal", 401, `{"error":"invalid_client"}`, "HTTP 401"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := tokenEndpoint(t, tc.status, tc.body)
			_, _, err := fetchToken(context.Background(), idp.Client(), idp.URL, "id", "secret")
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("fetchToken() error = %v, want it to contain %q", err, tc.err)
			}
		})
	}
}

// TestFetchToken_ReadsTheLifetimeFromExpiresIn: expires_in gives the
// lifetime, and it is seconds rather than an integer count of them, since a
// provider may answer with a fraction.
func TestFetchToken_ReadsTheLifetimeFromExpiresIn(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		lifetime time.Duration
	}{
		{"whole seconds", `{"access_token":"t","expires_in":120}`, 120 * time.Second},
		{"a decimal", `{"access_token":"t","expires_in":1.5}`, 1500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := tokenEndpoint(t, 200, tc.body)
			token, lifetime, err := fetchToken(context.Background(), idp.Client(), idp.URL, "id", "secret")
			if err != nil || token != "t" {
				t.Fatalf("fetchToken() = %q, %v; want %q", token, err, "t")
			}
			if lifetime != tc.lifetime {
				t.Errorf("lifetime = %s, want %s", lifetime, tc.lifetime)
			}
		})
	}
}

// TestFetchToken_ReadsTheLifetimeFromExp: a provider that sends no
// expires_in leaves the token's own exp as the only thing to renew against,
// so the lifetime is taken from there.
func TestFetchToken_ReadsTheLifetimeFromExp(t *testing.T) {
	token := jwt(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(90*time.Second).Unix()))
	idp := tokenEndpoint(t, 200, fmt.Sprintf(`{"access_token":%q}`, token))

	got, lifetime, err := fetchToken(context.Background(), idp.Client(), idp.URL, "id", "secret")
	if err != nil || got != token {
		t.Fatalf("fetchToken() = %q, %v; want the token from the body", got, err)
	}
	if lifetime < 80*time.Second || lifetime > 90*time.Second {
		t.Errorf("lifetime from exp = %s, want about 90s", lifetime)
	}
}

// TestFile_PublishesEachChange: the file's content is published when it
// appears and whenever it changes, and not otherwise. A file emptied after
// that keeps the current token.
func TestFile_PublishesEachChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	st := &store{}
	src := New(Config{TokenFile: file, WatchInterval: 20 * time.Millisecond}, st, quiet{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)

	time.Sleep(60 * time.Millisecond)
	if got := current(src); got != "" || len(st.published()) != 0 {
		t.Fatalf("before the file exists: current token = %q and %d published, want none", got, len(st.published()))
	}
	if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first token", func() bool { return current(src) == "a" })
	if err := os.WriteFile(file, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the changed token", func() bool { return current(src) == "b" })
	if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if got := st.published(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("published %v, want [a b], once per change", got)
	}
	if got := current(src); got != "b" {
		t.Errorf("current token after the file was emptied = %q, want b", got)
	}
	select {
	case <-src.Ready():
	default:
		t.Error("Ready() is not closed after the first token")
	}
}

func TestJWTExpiry(t *testing.T) {
	cases := []struct {
		name, token string
		want        int64
		err         string
	}{
		{"a token with exp", jwt(`{"exp":1700000000}`), 1700000000, ""},
		{"not a JWT", "abc", 0, "too few parts"},
		{"a payload that is not base64url", "a.@@@.c", 0, "decode JWT payload"},
		{"no exp claim", jwt(`{"sub":"x"}`), 0, "exp claim absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jwtExpiry(tc.token)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("jwtExpiry(%q) error = %v, want it to contain %q", tc.token, err, tc.err)
				}
				return
			}
			if err != nil || got.Unix() != tc.want {
				t.Errorf("jwtExpiry(%q) = %v, %v; want exp %d", tc.token, got, err, tc.want)
			}
		})
	}
}

// TestBearer_ClientCredentials: a call gets no token before the first grant,
// the granted token until its expires_in passes, and none after that, also
// when the refresh at that point fails.
func TestBearer_ClientCredentials(t *testing.T) {
	var fetches int
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		if fetches > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok1","expires_in":300}`))
	}))
	defer idp.Close()
	st := &store{}
	src := New(Config{TokenURL: idp.URL, ClientIDFile: writeFile(t, "id", "a"), ClientSecretFile: writeFile(t, "secret", "b")}, st, quiet{})
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }

	if tok, err := src.Bearer(); !errors.Is(err, ErrNoToken) {
		t.Errorf("Bearer() before the first grant = %q, %v; want %v", tok, err, ErrNoToken)
	}
	if _, err := src.fetchAndPublish(context.Background()); err != nil {
		t.Fatalf("fetchAndPublish() of the first token: error = %v", err)
	}
	// the policies stop presenting the token at the same instant
	if want := now.Add(300 * time.Second).UnixNano(); !reflect.DeepEqual(st.expires, []int64{want}) {
		t.Errorf("data.m2m.expiresAtNs = %v, want [%d]", st.expires, want)
	}
	now = now.Add(299 * time.Second)
	if tok, err := src.Bearer(); tok != "tok1" || err != nil {
		t.Errorf("Bearer() a second before expires_in passes = %q, %v; want tok1", tok, err)
	}
	now = now.Add(time.Second)
	if _, err := src.fetchAndPublish(context.Background()); err == nil {
		t.Fatal("fetchAndPublish() with the provider answering 500: no error")
	}
	if tok, err := src.Bearer(); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("Bearer() once expires_in passed and the refresh failed = %q, %v; want %v", tok, err, ErrTokenExpired)
	}
}

// TestBearer_File: a call gets no token while the file is missing, a token
// from the file until its exp claim passes, and a token that is not a JWT
// with exp for as long as the file holds it.
func TestBearer_File(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tests := []struct {
		name    string
		content string // "" leaves the file missing
		want    string
		err     error
		// expiresAtNs is what data.m2m.expiresAtNs holds, nil for no publish
		expiresAtNs []int64
	}{
		{"no file", "", "", ErrNoToken, nil},
		{"a JWT before its exp", jwt(`{"exp":1700000001}`), jwt(`{"exp":1700000001}`), nil, []int64{1700000001e9}},
		{"a JWT at its exp", jwt(`{"exp":1700000000}`), "", ErrTokenExpired, []int64{1700000000e9}},
		{"a JWT without exp", jwt(`{"sub":"x"}`), jwt(`{"sub":"x"}`), nil, []int64{0}},
		{"an opaque token", "opaque", "opaque", nil, []int64{0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "token")
			if tt.content != "" {
				if err := os.WriteFile(file, []byte(tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			st := &store{}
			src := New(Config{TokenFile: file}, st, quiet{})
			src.now = func() time.Time { return now }
			if err := src.checkFile(context.Background()); err != nil {
				t.Fatalf("checkFile() error = %v", err)
			}

			tok, err := src.Bearer()
			if tok != tt.want || !errors.Is(err, tt.err) {
				t.Errorf("Bearer() = %q, %v; want %q, %v", tok, err, tt.want, tt.err)
			}
			if !reflect.DeepEqual(st.expires, tt.expiresAtNs) {
				t.Errorf("data.m2m.expiresAtNs = %v, want %v", st.expires, tt.expiresAtNs)
			}
		})
	}
}
