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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/v1/util"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regogen/spectables"
)

// ReplayTransport returns a transport that answers the call of each GENERAL
// or FILTERED PIP of the input in with a response that nc.pip.record reads
// back as the value [Project] was given for the PIP's operand. It replays
// values a recording resolved, such as those of the corpus, through the
// generated functions. A call it has no response for, or whose value no
// response gives, such as ABSENT, which only an anonymous request gives
// without a call, fails as a transport error, so its record reads ERROR;
// the errors name each value of a call that no response gives. Two PIPs
// whose calls are one HTTP request, with different values recorded, are an
// error too: one service gives one request one answer, so no replay
// reproduces the recording, and the request fails for both. So is a url Go
// does not parse, such as one with a port that is not a number: the call
// fails before it reaches the transport.
func ReplayTransport(in *Input) (http.RoundTripper, []error) {
	t := replay{}
	if in.calls == nil {
		return t, nil
	}
	var errs []error
	owner := map[string]string{}
	for _, r := range in.refs {
		q := in.calls.Get(strTerm(r.ID))
		v, ok := in.pipValues[r.ID]
		if r.pip == nil || q == nil || !ok || q.Get(strTerm("s")) != nil {
			continue
		}
		var req struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Body   any    `json:"body"`
		}
		if err := util.UnmarshalJSON([]byte(q.String()), &req); err != nil {
			continue
		}
		u, err := url.Parse(req.URL)
		if err != nil {
			// nc.http.send fails before the transport, whatever was recorded
			errs = append(errs, fmt.Errorf("%s: replay: the call fails before it is sent: %w", r.ID, err))
			continue
		}
		// the url as RoundTrip reads it back from the request
		key, err := replayKey(req.Method, u.String(), req.Body)
		if err != nil {
			continue
		}
		status, body, err := pipAnswer(v, r.pipPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.ID, err))
		}
		a := replayAnswer{status, body, err}
		if prev, ok := t[key]; ok && prev != a {
			err = fmt.Errorf("replay: %s and %s send one request %s with different values recorded", owner[key], r.ID, key)
			errs = append(errs, err)
			a = replayAnswer{err: err}
		}
		owner[key] = r.ID
		t[key] = a
	}
	return t, errs
}

type replayAnswer struct {
	status int
	body   string
	err    error
}

type replay map[string]replayAnswer

func (t replay) RoundTrip(r *http.Request) (*http.Response, error) {
	var body any
	if r.Body != nil {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err := util.UnmarshalJSON(raw, &body); err != nil {
				return nil, err
			}
		}
	}
	key, err := replayKey(r.Method, r.URL.String(), body)
	if err != nil {
		return nil, err
	}
	a, ok := t[key]
	switch {
	case !ok:
		return nil, fmt.Errorf("replay: no recorded value for %s", key)
	case a.err != nil:
		return nil, a.err
	}
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(strings.NewReader(a.body)),
		Header: http.Header{}, Request: r}, nil
}

func replayKey(method, url string, body any) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return method + " " + url + " " + string(b), nil
}

var simplePathRE = regexp.MustCompile(`^(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// pipAnswer returns the status and the body of a response that
// [pipResolve] reads as v, with path jp, which [pipPath] gives, selecting the
// value from the body. A value no response gives is an error.
func pipAnswer(v Resolved, jp string) (int, string, error) {
	var body jsonvalue.Value
	switch v.State {
	case spectables.StateError:
		return http.StatusServiceUnavailable, "", nil
	case spectables.StatePIPNull:
		return http.StatusOK, "null", nil
	case spectables.StatePIPEmpty:
		body = []jsonvalue.Value{}
	case spectables.StateScalarOdd, spectables.StateSingleOdd:
		body = v.Value
	case spectables.StateValue:
		switch x := v.Value.(type) {
		case string:
			// a string as the whole body reads as a null body, a list of one
			// string as the string
			body = x
			if jp == "" {
				body = []jsonvalue.Value{x}
			}
		case []jsonvalue.Value:
			if len(x) < 2 {
				return 0, "", fmt.Errorf("replay: no body gives the list %s", jsonText(x))
			}
			body = x
		case *jsonvalue.Object:
			if jp == "" {
				return 0, "", fmt.Errorf("replay: no body without jsonPath gives the object %s", jsonText(x))
			}
			body = x
		default:
			return 0, "", fmt.Errorf("replay: no body gives the value %s in state VALUE", jsonText(x))
		}
	default:
		return 0, "", fmt.Errorf("replay: no response gives the state %s", v.State)
	}
	if jp != "" {
		if !simplePathRE.MatchString(jp) {
			return 0, "", fmt.Errorf("replay: the path %q is not a chain of names", jp)
		}
		names := strings.Split(jp[1:], ".")
		for i := len(names) - 1; i >= 0; i-- {
			o := jsonvalue.NewObject()
			o.Set(names[i], body)
			body = o
		}
	}
	return http.StatusOK, jsonText(body), nil
}
