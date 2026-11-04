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
	"regexp"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// A GENERAL or FILTERED PIP is a function of the module, pip_<Var>, which a
// clause binds the PIP's record from where it reads the PIP:
//
//	pip_<Var> := nc.pip.record(q, pip_send(q), {...}) if q := input.pq[<ID>]
//
// Go builds q before the query: the request nc.http.send sends, or {"s":
// <state>} where the agent makes no call, so the network is reached only from
// a clause that needs the PIP. nc.pip.record reads the response as the
// specification's general_value and resolve_pip do under the agent profile
// and returns the record. The rules of the request and of the response follow
// the specification's knobs of the agent profile, which the export of the
// tables does not carry; pipKnobs names each.

// pipSendText is the function every module with a GENERAL or FILTERED PIP
// carries, after a blank line.
const pipSendText = `pip_send(q) := null if q.s

pip_send(q) := nc.http.send(q) if not q.s
`

// pipText returns the function of the PIP of r.
func pipText(r *Ref) string {
	jp := "null"
	if r.pipPath != "" {
		jp = lit(r.pipPath)
	}
	return fmt.Sprintf("pip_%s := nc.pip.record(q, pip_send(q), {\"read\": %d, \"seg\": %t, \"subset\": %t, \"jp\": %s}) "+
		"if q := input.pq[%s]\n\n", r.Var, r.read, r.Segments, r.Subset, jp, lit(r.ID))
}

// pipPath returns the path nc.pip.record selects from the body of the
// response of decl, without the $: the jsonPath of a declaration of type JSON
// (ECFG jsonpath_types JSON), where a path without $ starts at the root
// (jsonpath_no_dollar ROOT); "" for a declaration whose body is the value. It
// fails for a path outside the subset [jsonpath] accepts.
func pipPath(decl *policyir.PIP) (string, error) {
	jp := decl.JSONPath
	if jp == "" || decl.ReturnType != "JSON" {
		return "", nil
	}
	switch {
	case strings.HasPrefix(jp, "$"):
		jp = jp[1:]
	case !strings.HasPrefix(jp, "["):
		jp = "." + jp
	}
	if _, err := jsonpath.Compile(jp); err != nil {
		return "", fmt.Errorf("jsonPath %q of PIP %s: %w", decl.JSONPath, decl.Name, err)
	}
	return jp, nil
}

var (
	placeholderRE     = regexp.MustCompile(`\$\{([^}]+)\}`)
	fullPlaceholderRE = regexp.MustCompile(`^\$\{([^}]+)\}$`)
	// a resource placeholder in a url fails the call (ECFG
	// url_resource_placeholder ERROR)
	urlResourceRE = regexp.MustCompile(`\$\{resource[.\[]`)
)

// The knobs of the specification's agent profile that the request and the
// response of a GENERAL or FILTERED PIP follow, with their values in this
// file, so that a search finds what a change of the profile touches:
//
//	remote_pip_subjects=observed, remote_pip_anonymous=ABSENT, remote_pip_refused=ERROR,
//	absent_request_attributes=null, request_attr_other_source=text, request_attr_in_text=as_written,
//	request_attr_list=as_written, request_attr_is_m2m=value,
//	request_attr_roles_empty=null, request_attr_resource_type=text,
//	request_attr_empty_pip=null, request_attr_empty_coll=empty, request_attr_local_raw=HEADER,
//	pip_http_method=doc, absent_url=NULL, url_null_value=as_written, url_resource_placeholder=ERROR,
//	url_reading=JAVA_URI, idiom_url_value_text=java, pip_forward_auth=own, pip_forward_tenant=param,
//	pip_forward_declared=present, pip_forward_trim=true, pip_forward_reserved=fixed,
//	header_lookup=fold, idiom_general_json=strict, jsonpath_types=JSON, json_without_jsonpath=body,
//	jsonpath_no_dollar=ROOT, jsonpath_selects_null=NULL, jsonpath_number_is_value=false,
//	general_object_state=PIP_NULL, general_string_state=PIP_NULL, raw_json_string=BODY,
//	general_bool_is_error=true, general_number_is_error=true, general_scalar_subset_value=true,
//	general_single_non_string_is_error=true, general_single_number_is_odd=true,
//	general_single_list_is_odd=true, pip_set_dedupe=true, idiom_pip_set_key=value,
//	pip_single_as_scalar=true, pip_one_call_per_request=false
//
// The functions do not follow pip_one_call_per_request=false: nc.http.send
// answers an equal request of one decision request from its cache, so a PIP
// that two operands read is called once. The profile's cache across
// decision requests (cacheable_absent, cacheable_ttl_ms) has no counterpart.

// pipPlaceholders returns the keys of the subject's operands that the url or
// the requestAttributes of decl put into its request, which [Project] needs
// in [Request.Values]: a HEADER PIP is read from [Request.Headers] instead.
func pipPlaceholders(decl *policyir.PIP, pips func(string) (*policyir.PIP, bool)) []string {
	texts := []string{decl.URL}
	for _, v := range decl.RequestAttributes {
		texts = append(texts, v)
	}
	var keys []string
	for _, t := range texts {
		for _, m := range placeholderRE.FindAllStringSubmatch(t, -1) {
			attr, ok := strings.CutPrefix(m[1], "subject.")
			if !ok || attr == "isM2M" {
				continue
			}
			if p, ok := pips(m[1]); ok && p.Type == policyir.PIPHeader {
				continue
			}
			if k := specKey("subj", attr); !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// pipCall returns the q of the PIP of r on req: the request object of
// nc.http.send, or {"s": state} for a call the agent does not make.
func pipCall(r *Ref, req *Request, pips func(string) (*policyir.PIP, bool)) *ast.Term {
	decl := r.pip
	if st, refused := remoteRefused(req); refused {
		return stateCall(st)
	}
	body := ast.NullTerm()
	if decl.RequestAttributes != nil {
		ra := ast.NewObject()
		for _, k := range slices.Sorted(mapsKeys(decl.RequestAttributes)) {
			v, err := jsonvalue.Decode([]byte(decl.RequestAttributes[k]))
			if err != nil {
				// policyir keeps a value as compacted JSON
				return stateCall(spectables.StateError)
			}
			ra.Insert(ast.StringTerm(k), jsonTerm(substituteAttr(v, req, pips)))
		}
		body = ast.NewTerm(ra)
	}
	method := strings.ToUpper(decl.HTTPMethod)
	if method == "" {
		method = "POST"
	}
	if decl.URL == "" {
		// no url, no call: the state of a null body
		return stateCall(spectables.StatePIPNull)
	}
	if urlResourceRE.MatchString(decl.URL) {
		return stateCall(spectables.StateError)
	}
	url := placeholderRE.ReplaceAllStringFunc(decl.URL, func(m string) string {
		expr := m[2 : len(m)-1]
		if !strings.HasPrefix(expr, "subject.") && !strings.HasPrefix(expr, "resource") {
			return m
		}
		v, ok := placeholderValue(expr, req, pips)
		if !ok || v == nil {
			return m
		}
		if s, ok := v.(string); ok {
			return s
		}
		return legacyvalue.Text(v)
	})
	// java.net.URI refuses these in a url, and the call fails before it is made
	if strings.ContainsAny(url, " \"<>\\^`{|}") {
		return stateCall(spectables.StateError)
	}
	headers := ast.NewObject()
	if req.Tenant != "" {
		headers.Insert(ast.StringTerm("Tenant"), ast.StringTerm(req.Tenant))
	}
	for _, name := range strings.Split(decl.Headers, ",") {
		name = strings.TrimFunc(name, func(r rune) bool { return r <= ' ' })
		low := strings.ToLower(name)
		if name == "" || low == "authorization" || low == "tenant" {
			continue
		}
		if v, ok := req.Headers[low]; ok {
			headers.Insert(ast.StringTerm(low), ast.StringTerm(v))
		}
	}
	items := [][2]*ast.Term{
		ast.Item(ast.StringTerm("method"), ast.StringTerm(method)),
		ast.Item(ast.StringTerm("url"), ast.StringTerm(url)),
		ast.Item(ast.StringTerm("headers"), ast.NewTerm(headers)),
		ast.Item(ast.StringTerm("raise_error"), ast.BooleanTerm(false)),
		ast.Item(ast.StringTerm("pip"), ast.StringTerm(decl.Name)),
	}
	if method != "GET" {
		items = append(items, ast.Item(ast.StringTerm("body"),
			ast.ObjectTerm(ast.Item(ast.StringTerm("requestAttributes"), body))))
	}
	return ast.ObjectTerm(items...)
}

func mapsKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func stateCall(st spectables.State) *ast.Term {
	return ast.ObjectTerm(ast.Item(ast.StringTerm("s"), ast.StringTerm(string(st))))
}

// remoteRefused returns the state of a GENERAL or FILTERED PIP the agent
// does not call for the subject of req: ABSENT for an anonymous request,
// ERROR for a service account or a token whose claim level is m2m or
// external in any case.
func remoteRefused(req *Request) (spectables.State, bool) {
	if req.Anonymous {
		return spectables.StateAbsent, true
	}
	claims := req.Claims
	if claims == nil {
		claims = jsonvalue.NewObject()
	}
	t := token{claims: claims}
	level, _ := claims.Get("level")
	s, _ := level.(string)
	if t.service() || strings.EqualFold(s, "external") {
		return spectables.StateError, true
	}
	return "", false
}

// substituteAttr returns the value v of requestAttributes with a string that
// is one placeholder of the subject or the resource replaced by its value. A
// placeholder of another source, a string with a placeholder among other
// text, and a list stay as written.
func substituteAttr(v jsonvalue.Value, req *Request, pips func(string) (*policyir.PIP, bool)) jsonvalue.Value {
	switch x := v.(type) {
	case string:
		m := fullPlaceholderRE.FindStringSubmatch(x)
		if m == nil || !strings.HasPrefix(m[1], "subject.") && !strings.HasPrefix(m[1], "resource") {
			return x
		}
		val, _ := placeholderValue(m[1], req, pips)
		return val
	case *jsonvalue.Object:
		o := jsonvalue.NewObject()
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			o.Set(k, substituteAttr(e, req, pips))
		}
		return o
	}
	return v
}

// placeholderValue returns the value expr, which starts with subject. or
// resource, puts into a request, nil for none, as the specification's
// lookup_placeholder and substitute read it; false where req has no value of
// the subject's operand.
func placeholderValue(expr string, req *Request, pips func(string) (*policyir.PIP, bool)) (jsonvalue.Value, bool) {
	var v Resolved
	switch {
	case expr == "subject.isM2M":
		return req.M2M, true
	case strings.HasPrefix(expr, "subject."):
		if p, ok := pips(expr); ok && p.Type == policyir.PIPHeader {
			// the header as it stands, unsplit, or the default
			h := req.Headers[strings.ToLower(p.Header)]
			if h != "" {
				return h, true
			}
			if p.DefaultValue == "" {
				return nil, true
			}
			d, err := jsonvalue.Decode([]byte(p.DefaultValue))
			if err != nil {
				return nil, true
			}
			return d, true
		}
		var ok bool
		if v, ok = req.Values[specKey("subj", strings.TrimPrefix(expr, "subject."))]; !ok {
			return nil, false
		}
		if expr == "subject.roles" && v.State == spectables.StateEmptyColl {
			return nil, true
		}
	case expr == "resourceType":
		return "${resourceType}", true
	default:
		v = resourcePlaceholder(strings.TrimPrefix(expr, "resource"), req.Body)
		if o, ok := v.Value.(*jsonvalue.Object); ok && v.State == spectables.StateValue && o != nil {
			return nil, true
		}
	}
	switch v.State {
	case spectables.StateValue:
		return v.Value, true
	case spectables.StateEmptyColl, spectables.StateEmptySel:
		return []jsonvalue.Value{}, true
	}
	return nil, true
}

// resourcePlaceholder returns the value of the resource path p over the
// resource of b, ABSENT for a path outside the subset [jsonpath] accepts.
func resourcePlaceholder(p string, b Body) Resolved {
	if !b.HasResource {
		return Resolved{State: spectables.StateAbsent}
	}
	if p == "" {
		return Resolved{State: spectables.StateValue, Value: b.Resource}
	}
	c, err := regobuiltins.CompilePath(p)
	if err != nil {
		return Resolved{State: spectables.StateAbsent}
	}
	return selection(b.Resource, c)
}

// jsonTerm returns the term of a JSON value.
func jsonTerm(v jsonvalue.Value) *ast.Term {
	switch x := v.(type) {
	case nil:
		return ast.NullTerm()
	case bool:
		return ast.BooleanTerm(x)
	case jsonvalue.Number:
		return ast.NumberTerm(json.Number(x))
	case string:
		return ast.StringTerm(x)
	case []jsonvalue.Value:
		terms := make([]*ast.Term, len(x))
		for i, e := range x {
			terms[i] = jsonTerm(e)
		}
		return ast.ArrayTerm(terms...)
	case *jsonvalue.Object:
		o := ast.NewObject()
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			o.Insert(ast.StringTerm(k), jsonTerm(e))
		}
		return ast.NewTerm(o)
	}
	return ast.NullTerm()
}

// PIPRecordDecl declares nc.pip.record as generated modules call it.
var PIPRecordDecl = &ast.Builtin{
	Name: "nc.pip.record",
	Decl: types.NewFunction(types.Args(
		types.Named("q", types.A), types.Named("response", types.A), types.Named("opts", types.A)),
		types.Named("record", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)))),
}

func pipRecordFunction() func(*rego.Rego) {
	return rego.Function3(&rego.Function{Name: PIPRecordDecl.Name, Decl: PIPRecordDecl.Decl},
		func(bctx rego.BuiltinContext, q, resp, opts *ast.Term) (*ast.Term, error) {
			r, jp, err := pipOptions(opts)
			if err != nil {
				return nil, err
			}
			if s := q.Get(ast.StringTerm("s")); s != nil {
				st, ok := s.Value.(ast.String)
				if !ok {
					return nil, fmt.Errorf("nc.pip.record: the state %v is not a string", s)
				}
				return record(r, Resolved{State: spectables.State(st)}).term(), nil
			}
			v, err := pipResolve(bctx, resp, jp)
			if err != nil {
				return nil, err
			}
			return record(r, v).term(), nil
		})
}

// pipOptions reads the options of nc.pip.record: the fields read, seg, and
// subset of the reference whose record it builds, and jp, the path of
// [pipPath] or null.
func pipOptions(opts *ast.Term) (*Ref, string, error) {
	o, ok := opts.Value.(ast.Object)
	if !ok {
		return nil, "", fmt.Errorf("nc.pip.record: the options %v are not an object", opts)
	}
	r := &Ref{}
	if n, ok := o.Get(ast.StringTerm("read")).Value.(ast.Number); ok {
		i, ok := n.Int64()
		if !ok {
			return nil, "", fmt.Errorf("nc.pip.record: read %v is not an integer", n)
		}
		r.read = fieldSet(i)
	}
	if b, ok := o.Get(ast.StringTerm("seg")).Value.(ast.Boolean); ok {
		r.Segments = bool(b)
	}
	if b, ok := o.Get(ast.StringTerm("subset")).Value.(ast.Boolean); ok {
		r.Subset = bool(b)
	}
	jp, _ := o.Get(ast.StringTerm("jp")).Value.(ast.String)
	return r, string(jp), nil
}

// pipResolve returns the value of a GENERAL or FILTERED PIP whose call
// answered resp, an object of nc.http.send: ERROR for a failed call or a
// status of 400 or more; otherwise the value the body or its path jp
// selects, read as the specification's resolve_pip reads it. A response
// without raw_body, which a mock gives, reads its body.
func pipResolve(bctx rego.BuiltinContext, resp *ast.Term, jp string) (Resolved, error) {
	o, ok := resp.Value.(ast.Object)
	if !ok {
		return Resolved{}, fmt.Errorf("nc.pip.record: the response %v is not an object", resp)
	}
	if o.Get(ast.StringTerm("error")) != nil {
		return Resolved{State: spectables.StateError}, nil
	}
	status, _ := o.Get(ast.StringTerm("status_code")).Value.(ast.Number)
	if code, ok := status.Int(); !ok || code >= 400 || code <= 0 {
		return Resolved{State: spectables.StateError}, nil
	}
	var body jsonvalue.Value
	if raw, ok := o.Get(ast.StringTerm("raw_body")).Value.(ast.String); ok {
		var err error
		if body, err = jsonvalue.Decode([]byte(raw)); err != nil {
			// a body that is not JSON reads as a JSON string body does
			body = string(raw)
		}
	} else if b := o.Get(ast.StringTerm("body")); b != nil {
		var err error
		if body, err = regobuiltins.JSONOf(bctx, b); err != nil {
			return Resolved{}, err
		}
	}
	var v jsonvalue.Value
	switch x := body.(type) {
	case nil:
		return Resolved{State: spectables.StatePIPNull}, nil
	default:
		if jp != "" {
			p, err := regobuiltins.CompilePath(jp)
			if err != nil {
				return Resolved{}, err
			}
			sel := p.Select(x)
			if sel.Kind != jsonpath.KindOne || sel.Value == nil {
				return Resolved{State: spectables.StatePIPNull}, nil
			}
			v = sel.Value
			break
		}
		switch x.(type) {
		case *jsonvalue.Object, string:
			// an object or a string as the whole body reads as a null body
			return Resolved{State: spectables.StatePIPNull}, nil
		}
		v = x
	}
	switch x := v.(type) {
	case bool, jsonvalue.Number:
		return Resolved{State: spectables.StateScalarOdd, Value: x}, nil
	case []jsonvalue.Value:
		if len(x) == 1 {
			switch x[0].(type) {
			case nil, bool, *jsonvalue.Object, jsonvalue.Number, []jsonvalue.Value:
				// [null], [true], [{"k": "v"}], [5], [[1]]: a collection operator
				// reads the list, any other operator a failed PIP
				return Resolved{State: spectables.StateSingleOdd, Value: x}, nil
			}
		}
		l := dedupe(x)
		switch len(l) {
		case 0:
			return Resolved{State: spectables.StatePIPEmpty}, nil
		case 1:
			return Resolved{State: spectables.StateValue, Value: l[0]}, nil
		}
		return Resolved{State: spectables.StateValue, Value: l, HeaderList: true}, nil
	}
	return Resolved{State: spectables.StateValue, Value: v}, nil
}

// dedupe returns l without the repeats of an element: numbers are one by
// value, 5 and 5.0, and any other element by its JSON type and text.
func dedupe(l []jsonvalue.Value) []jsonvalue.Value {
	seen := make(map[string]bool, len(l))
	out := make([]jsonvalue.Value, 0, len(l))
	for _, e := range l {
		var k string
		if n, ok := e.(jsonvalue.Number); ok {
			if d, ok := jsonvalue.ParseDecimal(string(n)); ok {
				k = "n" + d.String()
			}
		}
		if k == "" {
			k = "j" + jsonText(e)
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}
