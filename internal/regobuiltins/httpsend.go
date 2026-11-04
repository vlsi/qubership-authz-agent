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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/open-policy-agent/opa/v1/util"
)

// DefaultTimeout bounds a call of nc.http.send whose request names no
// timeout, where [HTTP.Timeout] is zero.
const DefaultTimeout = 2 * time.Second

// HTTP is how nc.http.send reaches the network: the client, the agent's own
// token, and the timeout of a call. A query reaches the network only through
// the HTTP that [HTTP.Context] put into its context; without one, every call
// fails.
type HTTP struct {
	Client *http.Client
	// Token returns the agent's own token, which every call presents in
	// Authorization. When it returns an error, the call is not made and
	// fails with that error.
	Token func() (string, error)
	// Timeout bounds a call whose request names no timeout; zero means
	// [DefaultTimeout].
	Timeout time.Duration
}

type httpKey struct{}

// Context returns a copy of ctx that carries h.
func (h *HTTP) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, httpKey{}, h)
}

type callsKey struct{}

// calls is the cache of nc.http.send for one decision request.
type calls struct {
	mu sync.Mutex
	m  map[string]*call
	// sent counts the requests that went to the network.
	sent int
}

type call struct {
	done chan struct{}
	resp *ast.Term
	err  error
	// abandoned is set when the query that made the call ended before the
	// call did, so the call has no answer for anyone.
	abandoned bool
}

// WithCalls returns a copy of ctx in which nc.http.send answers a request
// it has answered before from that answer, and a request another query
// sends at the same moment with the one answer both get. A failed call is an
// answer too: within the decision request the same request fails again
// without a call. A call whose own query ended first, such as one cancelled,
// is not: the next query that sends the request calls again. Pass the same
// context to every query of one decision request, such as each item of a
// bulk request, and a new one to the next decision request: no answer
// outlives the request.
func WithCalls(ctx context.Context) context.Context {
	return context.WithValue(ctx, callsKey{}, &calls{m: map[string]*call{}})
}

// Sent returns how many requests nc.http.send sent to the network under the
// cache of ctx, zero for a context without one.
func Sent(ctx context.Context) int {
	c, ok := ctx.Value(callsKey{}).(*calls)
	if !ok {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

var httpSendDecl = &ast.Builtin{
	Name: "nc.http.send",
	Decl: types.NewFunction(types.Args(types.Named("request", record)), types.Named("response", record)),
	// a compiler must not fold a call whose answer changes between queries
	Nondeterministic: true,
}

// sendRequest is the request object of nc.http.send.
type sendRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       any               `json:"body"`
	Timeout    string            `json:"timeout"`
	RaiseError *bool             `json:"raise_error"`
	PIP        string            `json:"pip"`
}

// Failure codes in the error member of a response of nc.http.send.
const (
	codeNoToken   = "no_token"
	codeTimeout   = "timeout"
	codeTransport = "transport"
)

// httpSend sends one HTTP request and returns its response as http.send
// does: status_code, headers (each name in lower case, with the list of its
// values), raw_body, and body where raw_body parses as JSON.
//
// A failed call (no token, a timeout, or a transport error) is an error of
// the function, or, with raise_error false, a response with status_code 0
// and error {code, message}. A status code of any value is a response, not
// a failure: the caller reads it. A request that is not an object of the
// documented shape is always an error.
func httpSend(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	c, _ := bctx.Context.Value(callsKey{}).(*calls)
	if c == nil {
		return send(bctx.Context, a)
	}
	doc, err := ast.JSON(a.Value)
	if err != nil {
		return nil, fmt.Errorf("nc.http.send: %w", err)
	}
	// json.Marshal sorts the members of a map, so equal requests share a key
	text, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("nc.http.send: %w", err)
	}
	key := string(text)
	for {
		c.mu.Lock()
		e, ok := c.m[key]
		if !ok {
			e = &call{done: make(chan struct{})}
			c.m[key] = e
		}
		c.mu.Unlock()
		if !ok {
			e.resp, e.err = send(bctx.Context, a)
			if bctx.Context.Err() != nil {
				c.mu.Lock()
				delete(c.m, key)
				c.mu.Unlock()
				e.abandoned = true
			}
			close(e.done)
			return e.resp, e.err
		}
		select {
		case <-e.done:
		case <-bctx.Context.Done():
			return nil, fmt.Errorf("nc.http.send: %w", bctx.Context.Err())
		}
		if !e.abandoned {
			return e.resp, e.err
		}
	}
}

func send(ctx context.Context, a *ast.Term) (*ast.Term, error) {
	var req sendRequest
	if err := util.UnmarshalJSON([]byte(a.String()), &req); err != nil {
		return nil, fmt.Errorf("nc.http.send: the request is not an object of method, url, headers, body, timeout, "+
			"raise_error, and pip: %w", err)
	}
	if req.URL == "" {
		return nil, errors.New("nc.http.send: the request has no url")
	}
	var timeout time.Duration
	if req.Timeout != "" {
		var err error
		if timeout, err = time.ParseDuration(req.Timeout); err != nil || timeout <= 0 {
			return nil, fmt.Errorf("nc.http.send: timeout %q is not a positive Go duration such as 500ms", req.Timeout)
		}
	}
	raise := req.RaiseError == nil || *req.RaiseError
	resp, code, err := do(ctx, req, timeout)
	if err == nil {
		return resp, nil
	}
	err = fmt.Errorf("nc.http.send %s %s%s: %w", req.method(), req.URL, req.pipText(), err)
	if raise {
		return nil, err
	}
	return ast.ObjectTerm(
		ast.Item(ast.InternedTerm("status_code"), ast.InternedTerm(0)),
		ast.Item(ast.InternedTerm("error"), ast.ObjectTerm(
			ast.Item(ast.InternedTerm("code"), ast.StringTerm(code)),
			ast.Item(ast.InternedTerm("message"), ast.StringTerm(err.Error()))))), nil
}

func (r *sendRequest) method() string {
	if r.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(r.Method)
}

func (r *sendRequest) pipText() string {
	if r.PIP == "" {
		return ""
	}
	return " for PIP " + r.PIP
}

// do sends req within timeout, or within the timeout of the HTTP in ctx
// where timeout is zero, and returns its response, or the code and the error
// of a failed call.
func do(ctx context.Context, req sendRequest, timeout time.Duration) (*ast.Term, string, error) {
	h, _ := ctx.Value(httpKey{}).(*HTTP)
	if h == nil {
		return nil, codeTransport, errors.New("no HTTP client in the query's context")
	}
	token, err := h.Token()
	if err != nil {
		return nil, codeNoToken, fmt.Errorf("no token of the agent to present: %w", err)
	}
	if timeout == 0 {
		timeout = h.Timeout
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if req.Body != nil {
		b, err := json.Marshal(req.Body)
		if err != nil {
			return nil, codeTransport, err
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, req.method(), req.URL, body)
	if err != nil {
		return nil, codeTransport, err
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	// the agent's own token wins over any Authorization the request names
	hr.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	hc := h.Client
	if hc == nil {
		hc = http.DefaultClient
	}
	if c, ok := ctx.Value(callsKey{}).(*calls); ok {
		c.mu.Lock()
		c.sent++
		c.mu.Unlock()
	}
	resp, err := hc.Do(hr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, codeTimeout, fmt.Errorf("no response within %s", timeout)
		}
		return nil, codeTransport, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, codeTimeout, fmt.Errorf("no complete response within %s", timeout)
		}
		return nil, codeTransport, fmt.Errorf("read the response: %w", err)
	}
	return response(resp, raw), "", nil
}

func response(resp *http.Response, raw []byte) *ast.Term {
	headers := make([][2]*ast.Term, 0, len(resp.Header))
	for k, vs := range resp.Header {
		terms := make([]*ast.Term, len(vs))
		for i, v := range vs {
			terms[i] = ast.StringTerm(v)
		}
		headers = append(headers, ast.Item(ast.StringTerm(strings.ToLower(k)), ast.ArrayTerm(terms...)))
	}
	items := [][2]*ast.Term{
		ast.Item(ast.InternedTerm("status_code"), ast.InternedTerm(resp.StatusCode)),
		ast.Item(ast.InternedTerm("headers"), ast.ObjectTerm(headers...)),
		ast.Item(ast.InternedTerm("raw_body"), ast.StringTerm(string(raw))),
	}
	var x any
	if json.Valid(raw) && util.UnmarshalJSON(raw, &x) == nil {
		if v, err := ast.InterfaceToValue(x); err == nil {
			items = append(items, ast.Item(ast.InternedTerm("body"), ast.NewTerm(v)))
		}
	}
	return ast.ObjectTerm(items...)
}
