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

package regobuiltins

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// pipServer answers each request with handler and counts the requests.
func pipServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func ownToken() (string, error) { return "own-token", nil }

// sendEval evaluates x := <query> in ctx with the built-in functions
// registered, without strict built-in errors, and returns x, or the errors
// of the built-in functions the query called.
func sendEval(t *testing.T, ctx context.Context, query string) (*ast.Term, error) {
	t.Helper()
	errs := &[]topdown.Error{}
	opts := append([]func(*rego.Rego){
		rego.Query("x := " + query),
		rego.Capabilities(Capabilities()),
		rego.BuiltinErrorList(errs),
	}, Options()...)
	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return builtinResult(t, query, rs, *errs)
}

// cancellableEval is sendEval for a query whose context may end: it returns
// the error of the evaluation instead of failing the test.
func cancellableEval(ctx context.Context, query string) error {
	opts := append([]func(*rego.Rego){
		rego.Query("x := " + query),
		rego.Capabilities(Capabilities()),
		rego.StrictBuiltinErrors(true),
	}, Options()...)
	_, err := rego.New(opts...).Eval(ctx)
	return err
}

func builtinResult(t *testing.T, query string, rs rego.ResultSet, errs []topdown.Error) (*ast.Term, error) {
	t.Helper()
	if len(errs) > 0 {
		return nil, errors.New(errs[0].Message)
	}
	if len(rs) != 1 {
		t.Fatalf("%s: %d results, want 1", query, len(rs))
	}
	v, err := ast.InterfaceToValue(rs[0].Bindings["x"])
	if err != nil {
		t.Fatal(err)
	}
	return ast.NewTerm(v), nil
}

func TestHTTPSend_SendsTheRequestWithTheOwnToken(t *testing.T) {
	var got struct {
		method, path, auth, tenant, ctype, body string
	}
	srv, _ := pipServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.path, got.body = r.Method, r.URL.RequestURI(), string(b)
		got.auth, got.tenant, got.ctype = r.Header.Get("Authorization"), r.Header.Get("Tenant"), r.Header.Get("Content-Type")
		w.Header().Set("X-Answer", "a")
		_, _ = w.Write([]byte(`["acc-7"]`))
	})
	ctx := (&HTTP{Token: ownToken}).Context(context.Background())

	resp, err := sendEval(t, ctx, `nc.http.send({"method": "post", "url": "`+srv.URL+`/pip?u=1",
		"headers": {"Tenant": "t1", "Authorization": "Bearer caller"}, "body": {"requestAttributes": {"id": "u1"}}})`)
	if err != nil {
		t.Fatal(err)
	}

	wantResp := ast.MustParseTerm(`{"status_code": 200, "raw_body": "[\"acc-7\"]", "body": ["acc-7"]}`)
	for _, k := range []string{"status_code", "raw_body", "body"} {
		if g, w := resp.Get(ast.StringTerm(k)), wantResp.Get(ast.StringTerm(k)); g == nil || !g.Equal(w) {
			t.Errorf("response %s = %v, want %v", k, g, w)
		}
	}
	if h := resp.Get(ast.StringTerm("headers")).Get(ast.StringTerm("x-answer")); h == nil || !h.Equal(ast.MustParseTerm(`["a"]`)) {
		t.Errorf("response headers x-answer = %v, want [\"a\"]", h)
	}
	want := struct {
		method, path, auth, tenant, ctype, body string
	}{"POST", "/pip?u=1", "Bearer own-token", "t1", "application/json", `{"requestAttributes":{"id":"u1"}}`}
	if got != want {
		t.Errorf("the PIP received %+v, want %+v", got, want)
	}
}

// TestHTTPSend_FailsWithoutACall: a call that fails reaches the PIP at most
// once and is an error of the function, or, with raise_error false, a
// response with status_code 0 and the error's code.
func TestHTTPSend_FailsWithoutACall(t *testing.T) {
	tests := []struct {
		name    string
		token   func() (string, error)
		handler http.HandlerFunc
		timeout string
		code    string
		calls   int32
		message string
	}{
		{
			name:    "no token",
			token:   func() (string, error) { return "", errors.New("m2m token: no token yet") },
			code:    codeNoToken,
			message: "no token of the agent to present: m2m token: no token yet",
		},
		{
			name:  "an expired token",
			token: func() (string, error) { return "", errors.New("m2m token: expired at 2026-11-04T12:00:00Z") },
			code:  codeNoToken, message: "m2m token: expired",
		},
		{
			name:  "no response within the timeout",
			token: ownToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			},
			timeout: "50ms", code: codeTimeout, calls: 1, message: "no response within 50ms",
		},
	}
	for _, tt := range tests {
		for _, raise := range []bool{true, false} {
			name := tt.name + ", raise_error true"
			if !raise {
				name = tt.name + ", raise_error false"
			}
			t.Run(name, func(t *testing.T) {
				h := tt.handler
				if h == nil {
					h = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`1`)) }
				}
				srv, calls := pipServer(t, h)
				ctx := (&HTTP{Token: tt.token}).Context(context.Background())
				req := `{"url": "` + srv.URL + `", "pip": "subject.accounts", "timeout": "` + tt.timeout + `"`
				if !raise {
					req += `, "raise_error": false`
				}

				resp, err := sendEval(t, ctx, "nc.http.send("+req+"})")

				if raise {
					if err == nil || !strings.Contains(err.Error(), tt.message) || !strings.Contains(err.Error(), "for PIP subject.accounts") {
						t.Errorf("error = %v, want one with %q naming the PIP", err, tt.message)
					}
				} else {
					if err != nil {
						t.Fatalf("error = %v, want a response", err)
					}
					if g := resp.Get(ast.StringTerm("status_code")); !g.Equal(ast.IntNumberTerm(0)) {
						t.Errorf("status_code = %v, want 0", g)
					}
					e := resp.Get(ast.StringTerm("error"))
					if g := e.Get(ast.StringTerm("code")); !g.Equal(ast.StringTerm(tt.code)) {
						t.Errorf("error code = %v, want %q", g, tt.code)
					}
					if g := e.Get(ast.StringTerm("message")); !strings.Contains(g.String(), tt.message) {
						t.Errorf("error message = %v, want one with %q", g, tt.message)
					}
				}
				if got := calls.Load(); got != tt.calls {
					t.Errorf("requests at the PIP = %d, want %d", got, tt.calls)
				}
			})
		}
	}
}

// TestHTTPSend_AStatusIsAResponse: a status code of a failure, a body that
// is not JSON, and an empty body are each a response for the caller to
// read.
func TestHTTPSend_AStatusIsAResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"503", 503, `{"error": "down"}`, `{"status_code": 503, "raw_body": "{\"error\": \"down\"}", "body": {"error": "down"}}`},
		{"a text body", 200, `acc-7`, `{"status_code": 200, "raw_body": "acc-7"}`},
		{"an empty body", 200, ``, `{"status_code": 200, "raw_body": ""}`},
		{"NaN", 200, `NaN`, `{"status_code": 200, "raw_body": "NaN"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := pipServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			ctx := (&HTTP{Token: ownToken}).Context(context.Background())

			resp, err := sendEval(t, ctx, `object.remove(nc.http.send({"url": "`+srv.URL+`"}), ["headers"])`)

			if err != nil {
				t.Fatal(err)
			}
			if want := ast.MustParseTerm(tt.want); !resp.Equal(want) {
				t.Errorf("response = %v, want %v", resp, want)
			}
		})
	}
}

// TestHTTPSend_OneCallPerRequestOfADecision: within one context of
// WithCalls, an equal request, whatever the order of its members, is
// answered from the first call; another request, and the same request
// under a new context, go to the PIP.
func TestHTTPSend_OneCallPerRequestOfADecision(t *testing.T) {
	srv, calls := pipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`"` + r.URL.Query().Get("u") + `"`))
	})
	h := &HTTP{Token: ownToken}
	ctx := WithCalls(h.Context(context.Background()))
	a := `{"url": "` + srv.URL + `?u=1", "headers": {"Tenant": "t1", "X": "y"}}`
	reordered := `{"headers": {"X": "y", "Tenant": "t1"}, "url": "` + srv.URL + `?u=1"}`
	b := `{"url": "` + srv.URL + `?u=2"}`

	resp, err := sendEval(t, ctx, `[nc.http.send(`+a+`).body, nc.http.send(`+reordered+`).body, nc.http.send(`+b+`).body]`)
	if err != nil {
		t.Fatal(err)
	}
	if want := ast.MustParseTerm(`["1", "1", "2"]`); !resp.Equal(want) {
		t.Errorf("bodies = %v, want %v", resp, want)
	}
	if _, err := sendEval(t, ctx, `nc.http.send(`+a+`).body`); err != nil {
		t.Fatal(err)
	}
	if got, sent := calls.Load(), Sent(ctx); got != 2 || sent != 2 {
		t.Errorf("requests at the PIP = %d and Sent = %d under one context, want 2 and 2", got, sent)
	}
	if _, err := sendEval(t, WithCalls(h.Context(context.Background())), `nc.http.send(`+a+`).body`); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("requests at the PIP after a new context = %d, want 3", got)
	}
}

func TestHTTPSend_RefusesARequestOfAnotherShape(t *testing.T) {
	ctx := (&HTTP{Token: ownToken}).Context(context.Background())
	tests := []struct{ name, req, want string }{
		{"no url", `{"method": "GET"}`, "the request has no url"},
		{"a timeout that is not a duration", `{"url": "http://pip", "timeout": "2"}`, `timeout "2" is not a positive Go duration`},
		{"headers that are not strings", `{"url": "http://pip", "headers": {"Tenant": 1}}`, "the request is not an object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sendEval(t, ctx, `nc.http.send(object.union(`+tt.req+`, {"raise_error": false}))`)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one with %q, also with raise_error false", err, tt.want)
			}
		})
	}
}

// TestHTTPSend_MergesConcurrentEqualCalls: queries of one decision request
// that send an equal request while the first call is in flight get its
// answer, and the PIP sees one request.
func TestHTTPSend_MergesConcurrentEqualCalls(t *testing.T) {
	release := make(chan struct{})
	srv, calls := pipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`"acc-7"`))
	})
	ctx := WithCalls((&HTTP{Token: ownToken}).Context(context.Background()))
	const queries = 8
	bodies := make(chan string, queries)
	for range queries {
		go func() {
			resp, err := sendEval(t, ctx, `nc.http.send({"url": "`+srv.URL+`"}).body`)
			if err != nil {
				bodies <- "error: " + err.Error()
				return
			}
			bodies <- resp.String()
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	// the other queries reach the cache while the first call waits
	time.Sleep(50 * time.Millisecond)
	close(release)
	for range queries {
		if got := <-bodies; got != `"acc-7"` {
			t.Errorf("body = %s, want \"acc-7\"", got)
		}
	}
	if got, sent := calls.Load(), Sent(ctx); got != 1 || sent != 1 {
		t.Errorf("requests at the PIP = %d and Sent = %d for %d concurrent queries, want 1 and 1", got, sent, queries)
	}
}

// TestHTTPSend_AFailedCallIsAnAnswer: within a decision request, a request
// whose call failed fails again without a call.
func TestHTTPSend_AFailedCallIsAnAnswer(t *testing.T) {
	srv, calls := pipServer(t, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx := WithCalls((&HTTP{Token: ownToken}).Context(context.Background()))
	req := `nc.http.send({"url": "` + srv.URL + `", "timeout": "20ms", "raise_error": false}).error.code`

	for i := range 2 {
		resp, err := sendEval(t, ctx, req)
		if err != nil || !resp.Equal(ast.StringTerm(codeTimeout)) {
			t.Errorf("query %d: error code = %v, %v; want %q", i+1, resp, err, codeTimeout)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests at the PIP = %d, want 1: the second query reads the failure", got)
	}
}

// TestHTTPSend_AQueryThatEndsLeavesNoAnswer: when the query that makes a
// call is cancelled, another query waiting for the call stops at its own
// cancellation, and a later query of the decision calls again.
func TestHTTPSend_AQueryThatEndsLeavesNoAnswer(t *testing.T) {
	block := make(chan struct{})
	srv, calls := pipServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(`"acc-7"`))
	})
	ctx := WithCalls((&HTTP{Token: ownToken}).Context(context.Background()))
	req := `nc.http.send({"url": "` + srv.URL + `", "raise_error": false}).status_code`

	leader, cancelLeader := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cancellableEval(leader, req)
	}()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	waiter, cancelWaiter := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelWaiter()
	if err := cancellableEval(waiter, req); err == nil {
		t.Error("a waiting query whose context ended: no error, want its cancellation")
	}
	cancelLeader()
	<-done

	close(block)
	resp, err := sendEval(t, ctx, req)
	if err != nil || !resp.Equal(ast.IntNumberTerm(200)) {
		t.Errorf("status_code after the cancelled call = %v, %v; want 200 from a new call", resp, err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("requests at the PIP = %d, want 2: the cancelled call is no answer", got)
	}
}

// TestFailedPIPs_NamesThePIPsWhoseCallFailed: a call that ends in an error
// of the function, one without a response, and one answered with a failure
// status each name their PIP; an answered call does not.
func TestFailedPIPs_NamesThePIPsWhoseCallFailed(t *testing.T) {
	srv, _ := pipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write([]byte(`1`))
	})
	noToken := func() (string, error) { return "", errors.New("m2m token: no token yet") }
	for _, tt := range []struct {
		name, req string
		token     func() (string, error)
		want      []string
	}{
		{"an error of the function", `{"url": "` + srv.URL + `", "pip": "subject.a"}`, noToken, []string{"subject.a"}},
		{"no response", `{"url": "` + srv.URL + `", "pip": "subject.a", "raise_error": false}`, noToken, []string{"subject.a"}},
		{"a failure status", `{"url": "` + srv.URL + `/fail", "pip": "subject.a", "raise_error": false}`, ownToken, []string{"subject.a"}},
		{"an answer", `{"url": "` + srv.URL + `", "pip": "subject.a", "raise_error": false}`, ownToken, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithCalls((&HTTP{Token: tt.token}).Context(context.Background()))

			_, _ = sendEval(t, ctx, "nc.http.send("+tt.req+")")

			if got := FailedPIPs(ctx); strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("FailedPIPs = %q, want %q", got, tt.want)
			}
		})
	}
}
