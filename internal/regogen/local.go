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
	"regexp"
	"strings"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
	"authz-agent/internal/policyir"
	"authz-agent/internal/regogen/spectables"
)

// ResolveSubject sets in req.Values the value of each operand of m that
// the subject's token, the request's headers, and the tenant's mapping
// tables give without a call, as the specification's resolve_subject does
// under the agent profile: a TOKEN PIP from req.Claims, a HEADER PIP from
// req.Headers, and subject.permissions from the MAPPING PIPs
// ([Module.permissions]). A MAPPING PIP read by its own name is ABSENT
// (mapping_own_name=ABSENT), and a PIP of type PERMISSION_SCOPE read as a
// value is ERROR, as a failed PIP is. subject.entitledResources is left to
// the module, which calls the entitlements service, unless req names no
// such service: then it is ERROR. It returns the keys of the operands set to
// ERROR for want of a source, which the reason of a denial names. A
// placeholder a PIP's request reads and nothing gives is ABSENT. An operand
// req.Values already holds is left as it is.
//
// The knobs of the agent profile these follow, which the export of the
// tables does not carry: header_lookup=fold, header_charset=latin1,
// header_value_ows_trim=true, header_empty_string_is_absent=true,
// header_default_on_empty=true, header_split_comma=true,
// idiom_header_item_split=java, split_drops_trailing_empty=true,
// idiom_header_item_trim=unicode, token_odd_claim=ERROR,
// jsonpath_root_bracket=KEY, token_default_split_comma=true,
// token_absent_state=PIP_EMPTY, on_behalf_token_default=apply,
// pip_set_dedupe=true, idiom_pip_set_key=value, pip_single_as_scalar=true.
func (m *Module) ResolveSubject(req *Request) []string {
	if req.Values == nil {
		req.Values = map[string]Resolved{}
	}
	var unread []string
	for _, r := range m.Refs {
		if r.Pass || r.Path != "" {
			continue
		}
		if _, ok := req.Values[r.Key]; ok {
			continue
		}
		var v Resolved
		switch r.Kind {
		case spectables.KindPIPToken, spectables.KindPIPHeader:
			decl, ok := m.pips(pipName(r.Key))
			if !ok {
				continue
			}
			if r.Kind == spectables.KindPIPToken {
				v = tokenPIP(decl, req.Claims)
			} else {
				v = headerPIP(decl, req.Headers)
			}
		case spectables.KindPIPGeneral, spectables.KindPIPFiltered:
			// the module calls them itself
			continue
		case spectables.KindSubjPermissions:
			v = m.permissions(req)
		case spectables.KindPIPMapping:
			v = Resolved{State: spectables.StateAbsent}
		case spectables.KindSubjPermissionScope:
			v = Resolved{State: spectables.StateError}
			unread = append(unread, r.Key)
		case spectables.KindEntitled:
			if req.Entitlements != "" {
				// the module calls the service itself
				continue
			}
			v = Resolved{State: spectables.StateError}
			unread = append(unread, r.Key)
		default:
			continue
		}
		req.Values[r.Key] = v
	}
	for _, k := range m.placeholders {
		if _, ok := req.Values[k]; !ok {
			req.Values[k] = Resolved{State: spectables.StateAbsent}
		}
	}
	return unread
}

// pipName is the declared name of the PIP whose operand key is key,
// ["subj", "<name without subject.>"].
func pipName(key string) string {
	var parts []string
	if json.Unmarshal([]byte(key), &parts) != nil || len(parts) != 2 {
		return ""
	}
	return "subject." + parts[1]
}

// headerPIP is the value of a HEADER PIP: the request header the
// declaration names, by its name in any case, or else the declaration's
// default value, split at commas into a list of trimmed items.
func headerPIP(decl *policyir.PIP, headers map[string]string) Resolved {
	hv, ok := headers[strings.ToLower(decl.Header)]
	if ok {
		hv = latin1(hv)
		hv = strings.Trim(hv, " \t")
	}
	if hv == "" {
		hv, ok = defaultText(decl.DefaultValue)
	}
	if !ok || hv == "" {
		return Resolved{State: spectables.StatePIPEmpty}
	}
	r := pipList(splitItems(hv))
	if r.State == spectables.StateValue {
		_, list := r.Value.([]jsonvalue.Value)
		r.HeaderList = list
	}
	return r
}

// latin1 reads the bytes of a header value as ISO-8859-1, each byte one
// character, as the legacy service's servlet container reads them.
func latin1(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(rune(s[i]))
	}
	return b.String()
}

// tokenRootBracket is a leading ['key'] step, which a TOKEN PIP's claim
// reads as .key.
var tokenRootBracket = regexp.MustCompile(`^\['([^']*)'\]`)

// tokenPIP is the value of a TOKEN PIP: the claim the declaration names,
// read as a jsonPath over the claims of the subject's token, or else its
// default value split at commas. A claim that is blank or outside the
// jsonPath subset is ERROR.
func tokenPIP(decl *policyir.PIP, claims *jsonvalue.Object) Resolved {
	claim := decl.Claim
	if strings.TrimSpace(claim) == "" {
		return Resolved{State: spectables.StateError}
	}
	path := "." + claim
	if strings.HasPrefix(claim, "$") {
		path = claim[1:]
	}
	if m := tokenRootBracket.FindStringSubmatch(path); m != nil {
		path = "." + m[1] + path[len(m[0]):]
	}
	p, err := jsonpath.Compile(path)
	if err != nil {
		return Resolved{State: spectables.StateError}
	}
	var doc jsonvalue.Value = jsonvalue.NewObject()
	if claims != nil {
		doc = claims
	}
	sel := p.Select(doc)
	missing := false
	switch sel.Kind {
	case jsonpath.KindMissing, jsonpath.KindNullParent, jsonpath.KindIndexOutOfBounds, jsonpath.KindBracket:
		missing = true
	case jsonpath.KindMany:
		l, _ := sel.Value.([]jsonvalue.Value)
		missing = len(l) == 0
	case jsonpath.KindOne:
		missing = sel.Value == nil
	default:
		return Resolved{State: spectables.StateError}
	}
	if missing {
		dv, ok := defaultText(decl.DefaultValue)
		if !ok || dv == "" {
			return Resolved{State: spectables.StatePIPEmpty}
		}
		return pipList(splitItems(dv))
	}
	if l, ok := sel.Value.([]jsonvalue.Value); ok {
		return pipList(l)
	}
	return Resolved{State: spectables.StateValue, Value: sel.Value}
}

// defaultText is the text of a declaration's defaultValue, the compacted
// JSON policyir keeps, as the specification's str() gives it; ok is false
// for an absent or null default.
func defaultText(raw string) (string, bool) {
	if raw == "" || raw == "null" {
		return "", false
	}
	v, err := jsonvalue.Decode([]byte(raw))
	if err != nil {
		return "", false
	}
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "True", true
		}
		return "False", true
	}
	return legacyvalue.Text(v), true
}

// splitItems splits a comma-separated value as Java's String.split does,
// trailing empty items dropped, and trims each item of white space.
func splitItems(s string) []jsonvalue.Value {
	parts := strings.Split(s, ",")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	out := make([]jsonvalue.Value, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimFunc(p, isPySpace)
	}
	return out
}

// pipList is a list a PIP gives, its repeats dropped: PIP_EMPTY for none,
// the value itself for one, the list for more.
func pipList(l []jsonvalue.Value) Resolved {
	l = dedupe(l)
	switch len(l) {
	case 0:
		return Resolved{State: spectables.StatePIPEmpty}
	case 1:
		return Resolved{State: spectables.StateValue, Value: l[0]}
	}
	return Resolved{State: spectables.StateValue, Value: l}
}
