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

package main

import (
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

// uploadCase is one upload and, for a refused one, the text its error has to
// contain.
type uploadCase struct {
	name, body, wantError string
}

// assertRefused fails unless the upload of tc to path answers 400 with a JSON
// error that contains tc.wantError, and the domain still reads empty.
func assertRefused(t *testing.T, path string, tc uploadCase) {
	t.Helper()
	assertRefusedOn(t, newTestServer(t, t.TempDir()), path, tc, http.StatusBadRequest)
}

// assertRefusedOn fails unless the upload of tc to path on mux answers status
// with a JSON error that contains tc.wantError, and path reads the same after
// it as before.
func assertRefusedOn(t *testing.T, mux *http.ServeMux, path string, tc uploadCase, status int) {
	t.Helper()
	before := do(t, mux, http.MethodGet, path, "").Body.String()
	rec := do(t, mux, http.MethodPut, path, tc.body)
	if rec.Code != status {
		t.Fatalf("PUT %s %s = %d %s, want %d", path, tc.body, rec.Code, rec.Body, status)
	}
	var resp struct{ Error string }
	decode(t, rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, tc.wantError) {
		t.Errorf("PUT %s %s: error %q, want it to contain %q", path, tc.body, resp.Error, tc.wantError)
	}
	if after := do(t, mux, http.MethodGet, path, "").Body.String(); after != before {
		t.Errorf("after the refused PUT %s %s the domain reads %s, want %s", path, tc.body, after, before)
	}
}

// assertAccepted fails unless the upload of tc to path answers 200.
func assertAccepted(t *testing.T, path string, tc uploadCase) {
	t.Helper()
	assertAcceptedOn(t, newTestServer(t, t.TempDir()), path, tc)
}

// assertAcceptedOn fails unless the upload of tc to path on mux answers 200.
func assertAcceptedOn(t *testing.T, mux *http.ServeMux, path string, tc uploadCase) {
	t.Helper()
	if rec := do(t, mux, http.MethodPut, path, tc.body); rec.Code != http.StatusOK {
		t.Errorf("PUT %s %s = %d %s, want 200", path, tc.body, rec.Code, rec.Body)
	}
}

// policyWith returns a policy upload of one policy whose condition is the
// JSON value condition.
func policyWith(condition string) string {
	return `[{"component":"BILLING","resourceType":"INVOICE","operation":"READ","roles":["R"],"condition":` +
		condition + `}]`
}

// A PIP name is subject. followed by dot-separated attributes of letters,
// digits, and underscores, none starting with a digit.
func TestPIPNameIsRefusedUnlessItIsASubjectAttribute(t *testing.T) {
	for _, tc := range []uploadCase{
		{"without the subject prefix", `[{"name":"department","pipType":"TOKEN","claim":"dept"}]`, `"department"`},
		{"absent", `[{"pipType":"TOKEN","claim":"dept"}]`, "name is absent or blank"},
		{"an attribute starting with a digit", `[{"name":"subject.1dept","pipType":"TOKEN","claim":"dept"}]`, `"subject.1dept"`},
		{"a dash", `[{"name":"subject.my-dept","pipType":"TOKEN","claim":"dept"}]`, `"subject.my-dept"`},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"one attribute", `[{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}]`, ""},
		{"a path starting with an underscore", `[{"name":"subject._org.dept_2","pipType":"TOKEN","claim":"dept"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// headers is one text of comma-separated header names, and a mapping field
// is a JSON object.
func TestPIPFieldOfTheWrongJSONShapeIsRefused(t *testing.T) {
	const url = `"url":"http://pip/allowed"`
	for _, tc := range []uploadCase{
		{"headers as an object", `[{"name":"subject.ids",` + url + `,"headers":{"X-Trace":"1"}}]`, "field headers"},
		{"headers as an array", `[{"name":"subject.ids",` + url + `,"headers":["X-Trace","X-Org"]}]`, "field headers"},
		{"defaultValue as an array", `[{"name":"subject.ids",` + url + `,"defaultValue":["none"]}]`, "field defaultValue"},
		{"customMapping as a text", `[{"name":"subject.permissions","pipType":"MAPPING","customMapping":"r"}]`, "field customMapping"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"headers as a text", `[{"name":"subject.ids",` + url + `,"headers":"X-Trace, X-Org"}]`, ""},
		{"defaultValue as a number", `[{"name":"subject.ids",` + url + `,"defaultValue":5}]`, ""},
		{"customMapping as an object", `[{"name":"subject.permissions","pipType":"MAPPING","customMapping":{}}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// A simplified policy's condition is a text the condition parser accepts, a
// boolean, or absent.
func TestPolicyConditionIsRefusedUnlessItParses(t *testing.T) {
	for _, tc := range []uploadCase{
		{"MATCH with a number", policyWith(`"subject.x MATCH 5 OR resource.a == 'y'"`), "number as a MATCH pattern"},
		{"empty", policyWith(`""`), "condition is empty"},
		{"blank", policyWith(`"   "`), "blank"},
		{"a number", policyWith(`5`), "want a text"},
		{"an array", policyWith(`["resource.a == 'y'"]`), "want a text"},
		{"an object", policyWith(`{"text":"resource.a == 'y'"}`), "want a text"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, policiesPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"MATCH with a pattern", policyWith(`"subject.x MATCH abc OR resource.a == 'y'"`), ""},
		{"padded with a form feed", policyWith(`"\fresource.a == 'y'"`), ""},
		{"true", policyWith(`true`), ""},
		{"false", policyWith(`false`), ""},
		{"null", policyWith(`null`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, policiesPath+"billing", tc) })
	}
}

// pipType and type name a kind access-control knows, and type JSON is a
// GENERAL PIP's.
func TestPIPTypeIsRefusedUnlessAccessControlKnowsIt(t *testing.T) {
	const general = `"name":"subject.ids","url":"http://pip/ids"`
	for _, tc := range []uploadCase{
		{"an unknown pipType", `[{"name":"subject.dept","pipType":"LDAP","claim":"dept"}]`, `pipType "LDAP"`},
		{"an unknown type", `[{` + general + `,"type":"XML"}]`, `type "XML"`},
		{"type JSON on a TOKEN PIP", `[{"name":"subject.dept","pipType":"TOKEN","claim":"dept","type":"JSON","jsonPath":"$.a"}]`,
			"type JSON is allowed only for a GENERAL PIP"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"a pipType padded with spaces", `[{"name":"subject.dept","pipType":" TOKEN ","claim":"dept"}]`, ""},
		{"type JSON on a GENERAL PIP", `[{` + general + `,"type":"JSON","jsonPath":"$.ids"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// Each pipType has the fields it reads: a url, a resourceType, a claim, a
// jsonPath for type JSON.
func TestPIPIsRefusedWithoutTheFieldsItsTypeReads(t *testing.T) {
	for _, tc := range []uploadCase{
		{"GENERAL without url or beanName", `[{"name":"subject.ids"}]`, "url is absent or empty"},
		{"FILTERED without url", `[{"name":"subject.ids","pipType":"FILTERED","resourceType":"Customer"}]`,
			"url is absent or empty"},
		{"FILTERED without resourceType", `[{"name":"subject.ids","pipType":"FILTERED","url":"http://pip/ids"}]`,
			"a FILTERED PIP needs a resourceType"},
		{"TOKEN with an empty claim", `[{"name":"subject.dept","pipType":"TOKEN","claim":""}]`, "a TOKEN PIP needs a claim"},
		{"type JSON without jsonPath", `[{"name":"subject.ids","url":"http://pip/ids","type":"JSON"}]`,
			"type JSON needs a jsonPath"},
		{"a blank jsonPath", `[{"name":"subject.ids","url":"http://pip/ids","jsonPath":" "}]`, "jsonPath is blank"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"GENERAL with a beanName and no url", `[{"name":"subject.ids","beanName":"idsProvider"}]`, ""},
		{"FILTERED with url and resourceType",
			`[{"name":"subject.ids","pipType":"FILTERED","url":"http://pip/ids","resourceType":"Customer"}]`, ""},
		{"TOKEN with a claim", `[{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// A PERMISSION_SCOPE PIP is subject.permissionScope, and a MAPPING PIP is
// subject.permissions or a name under it.
func TestPIPNameIsRefusedUnlessItsTypeAllowsIt(t *testing.T) {
	for _, tc := range []uploadCase{
		{"PERMISSION_SCOPE under another name", `[{"name":"subject.scope","pipType":"PERMISSION_SCOPE","url":"http://pip/s"}]`,
			"a PERMISSION_SCOPE PIP is named subject.permissionScope"},
		{"MAPPING under another name", `[{"name":"subject.roleMap","pipType":"MAPPING","customMapping":{}}]`,
			"a MAPPING PIP is named subject.permissions"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"PERMISSION_SCOPE as subject.permissionScope",
			`[{"name":"subject.permissionScope","pipType":"PERMISSION_SCOPE","url":"http://pip/s"}]`, ""},
		{"MAPPING under subject.permissions.",
			`[{"name":"subject.permissions.billing","pipType":"MAPPING","customMapping":{}}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// A GENERAL PIP calls with GET or POST, no PIP forwards or reads the
// Authorization or Tenant header, and a header name is not blank.
func TestPIPHTTPMethodAndHeadersAreRefusedUnlessAllowed(t *testing.T) {
	const general = `"name":"subject.ids","url":"http://pip/ids"`
	for _, tc := range []uploadCase{
		{"httpMethod PUT", `[{` + general + `,"httpMethod":"PUT"}]`, `httpMethod "PUT" is not GET or POST`},
		{"httpMethod in lower case", `[{` + general + `,"httpMethod":"get"}]`, `httpMethod "get" is not GET or POST`},
		{"headers forwarding Authorization", `[{` + general + `,"headers":"X-Trace,Authorization"}]`,
			`headers forwards "Authorization", which is reserved`},
		{"headers with an empty name", `[{` + general + `,"headers":"X-Trace,,X-Org"}]`, "holds a blank name"},
		{"a HEADER PIP reading Tenant", `[{"name":"subject.tenant","pipType":"HEADER","header":"tenant"}]`,
			`header "tenant" is reserved`},
		{"a HEADER PIP without header", `[{"name":"subject.org","pipType":"HEADER"}]`, "header is absent or blank"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"httpMethod POST", `[{` + general + `,"httpMethod":"POST"}]`, ""},
		{"headers of two names", `[{` + general + `,"headers":"X-Trace,X-Org"}]`, ""},
		{"a HEADER PIP reading X-Org", `[{"name":"subject.org","pipType":"HEADER","header":"X-Org"}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// A GENERAL url references only ${subject.id}, and a request attribute that
// is a whole ${subject.<name>} names a built-in subject attribute or a TOKEN
// or HEADER PIP.
func TestPIPSubjectReferenceIsRefusedUnlessResolvable(t *testing.T) {
	const token = `{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}`
	attrs := func(value string) string {
		return `{"name":"subject.ids","url":"http://pip/ids","requestAttributes":{"org":` + value + `}}`
	}
	for _, tc := range []uploadCase{
		{"a url referencing subject.name", `[{"name":"subject.ids","url":"http://pip/${subject.name}"}]`,
			"url references ${subject.name}"},
		{"an undeclared attribute", `[` + attrs(`"${subject.dept}"`) + `]`,
			"request attribute org references ${subject.dept}, which is neither a PIP of the tenant"},
		{"a GENERAL PIP", `[` + attrs(`"${subject.ids}"`) + `]`, "references ${subject.ids}, a GENERAL PIP"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"a url referencing subject.id", `[{"name":"subject.ids","url":"http://pip/${subject.id}"}]`, ""},
		{"a built-in attribute", `[` + attrs(`"${subject.name}"`) + `]`, ""},
		{"a TOKEN PIP of the upload", `[` + token + `,` + attrs(`"${subject.dept}"`) + `]`, ""},
		{"a reference inside a longer text", `[` + attrs(`"org-${subject.dept}"`) + `]`, ""},
		{"a list", `[` + attrs(`["a","b"]`) + `]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// Each table of a MAPPING PIP is a JSON object keyed by subject.roles, a
// built-in subject attribute, or a TOKEN or HEADER PIP.
func TestMappingTableIsRefusedUnlessKeyedByASubjectAttribute(t *testing.T) {
	const token = `{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}`
	const general = `{"name":"subject.dept","url":"http://pip/dept"}`
	mapping := func(tables string) string {
		return `{"name":"subject.permissions","pipType":"MAPPING","customMapping":` + tables + `}`
	}
	for _, tc := range []uploadCase{
		{"a table that is a text", `[` + mapping(`{"subject.roles":"R"}`) + `]`,
			"customMapping subject.roles is R, want a JSON object"},
		{"a key without subject.", `[` + mapping(`{"roles":{}}`) + `]`, "which does not start with subject."},
		{"an undeclared key", `[` + mapping(`{"subject.dept":{}}`) + `]`, "which no PIP of the tenant declares"},
		{"a GENERAL PIP as the key", `[` + general + `,` + mapping(`{"subject.dept":{}}`) + `]`,
			"customMapping is keyed by subject.dept, GENERAL"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, pipsPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"subject.roles", `[` + mapping(`{"subject.roles":{"R":["read"]}}`) + `]`, ""},
		{"a built-in attribute", `[` + mapping(`{"subject.id":{}}`) + `]`, ""},
		{"a TOKEN PIP of the upload", `[` + token + `,` + mapping(`{"subject.dept":{}}`) + `]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, pipsPath+"billing", tc) })
	}
}

// pipType and type are stored trimmed, so a later upload reads a padded
// TOKEN PIP as a TOKEN PIP.
func TestPaddedPIPTypeIsStoredTrimmed(t *testing.T) {
	mux := newTestServer(t, t.TempDir())
	assertAcceptedOn(t, mux, pipsPath+"billing",
		uploadCase{body: `[{"name":"subject.dept","pipType":" TOKEN ","claim":"dept"}]`})
	assertAcceptedOn(t, mux, pipsPath+"orders", uploadCase{
		body: `[{"name":"subject.ids","url":"http://pip/ids","requestAttributes":{"org":"${subject.dept}"}}]`,
	})
}

// A PIP name is declared once per tenant: twice in one upload, or in another
// domain of the same tenant, is a conflict.
func TestPIPNameDeclaredTwiceInATenantIsAConflict(t *testing.T) {
	const token = `{"name":"subject.dept","pipType":"TOKEN","claim":"dept"}`
	const general = `{"name":"subject.ids","url":"http://pip/ids"}`
	withBilling := func(t *testing.T) *http.ServeMux {
		t.Helper()
		mux := newTestServer(t, t.TempDir())
		assertAcceptedOn(t, mux, pipsPath+"billing", uploadCase{body: `[` + token + `,` + general + `]`})
		return mux
	}
	t.Run("twice in the upload", func(t *testing.T) {
		assertRefusedOn(t, newTestServer(t, t.TempDir()), pipsPath+"billing",
			uploadCase{body: `[` + token + `,` + token + `]`, wantError: "declared more than once in the upload"},
			http.StatusConflict)
	})
	for _, tc := range []uploadCase{
		{"a TOKEN PIP in another domain", `[` + token + `]`, `declared in domain "billing" of the same tenant`},
		{"a GENERAL PIP in another domain", `[` + general + `]`, `declared in domain "billing" of the same tenant`},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefusedOn(t, withBilling(t), pipsPath+"orders", tc, http.StatusConflict) })
	}
	t.Run("uploads racing for one name", func(t *testing.T) {
		// Each upload checks the tenant's PIPs and stores its own under one
		// lock, so of two uploads of one name to two domains one sees the other.
		for range 20 {
			mux := newTestServer(t, "")
			codes := make(chan int, 2)
			var wg sync.WaitGroup
			for _, domain := range []string{"billing", "orders"} {
				wg.Go(func() { codes <- do(t, mux, http.MethodPut, pipsPath+domain, `[`+token+`]`).Code })
			}
			wg.Wait()
			close(codes)
			got := []int{<-codes, <-codes}
			slices.Sort(got)
			if !slices.Equal(got, []int{http.StatusOK, http.StatusConflict}) {
				t.Fatalf("two concurrent uploads of %s answered %v, want [200 409]", token, got)
			}
		}
	})
	t.Run("the same domain again", func(t *testing.T) {
		assertAcceptedOn(t, withBilling(t), pipsPath+"billing", uploadCase{body: `[` + token + `]`})
	})
	t.Run("another tenant", func(t *testing.T) {
		mux := withBilling(t)
		if rec := doWithTenantHeader(t, mux, http.MethodPut, pipsPath+"orders", `[`+token+`]`, "t2"); rec.Code != http.StatusOK {
			t.Errorf("PUT %sorders as tenant t2 = %d %s, want 200", pipsPath, rec.Code, rec.Body)
		}
	})
}

// A policy has component, resourceType, operation, and roles; predicates
// carries a mongodbPredicate; an id is a UUID; and a policy of resourceType
// ALL is the global one, with no condition or predicates.
func TestPolicyIsRefusedUnlessItsFieldsAreComplete(t *testing.T) {
	policy := func(fields string) string {
		return `[{"component":"BILLING","resourceType":"INVOICE","operation":"READ","roles":["R"]` + fields + `}]`
	}
	for _, tc := range []uploadCase{
		{"operation absent", `[{"component":"BILLING","resourceType":"INVOICE","roles":["R"]}]`, "operation is absent"},
		{"roles empty", `[{"component":"BILLING","resourceType":"INVOICE","operation":"READ","roles":[]}]`,
			"roles is absent or empty"},
		{"predicates an empty object", policy(`,"predicates":{}`), "predicates is an empty object"},
		{"predicates without mongodbPredicate", policy(`,"predicates":{"sqlPredicate":"a = 1"}`),
			"predicates has no mongodbPredicate"},
		{"predicates a blank text", policy(`,"predicates":" "`), "predicates is a blank text"},
		{"an id that is no UUID", policy(`,"id":"42"`), `id "42" is not a UUID`},
		{"resourceType ALL in one component",
			`[{"component":"BILLING","resourceType":"ALL","operation":"ALL","roles":["R"]}]`,
			"a policy of resourceType ALL has component and operation ALL"},
		{"roles as a text", policy(`,"roles":"R"`), "field roles"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, policiesPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"predicates a text", policy(`,"predicates":"{\"a\": 1}"`), ""},
		{"predicates with mongodbPredicate", policy(`,"predicates":{"mongodbPredicate":"{}"}`), ""},
		{"a UUID id", policy(`,"id":"0b5e6f3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"`), ""},
		{"the global policy", `[{"component":"ALL","resourceType":"ALL","operation":"ALL","roles":["R"]}]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, policiesPath+"billing", tc) })
	}
}

// Each operator takes the operands access-control pairs with it, a boolean
// stands in a list only under IN, TRUE and FALSE stand alone, and a
// multi-word operator is written with spaces.
func TestPolicyConditionIsRefusedForAFormAccessControlDoesNotStore(t *testing.T) {
	for _, tc := range []uploadCase{
		{"a list attribute compared with ==", policyWith(`"subject.roles == 'R'"`), "EQ does not take subject.roles"},
		{"a single attribute under CONTAINS", policyWith(`"subject.id CONTAINS 'a'"`), "CONTAINS does not take subject.id"},
		{"a list attribute under IS NULL", policyWith(`"subject.roles IS NULL"`), "IS_NULL does not take subject.roles"},
		{"a boolean under NOT IN", policyWith(`"resource.a NOT IN true"`), "NOT_IN does not take a boolean in its list"},
		{"a boolean under CONTAINS ANY", policyWith(`"subject.roles CONTAINS ANY true"`),
			"CONTAINS_ANY does not take a boolean in its list"},
		{"TRUE beside AND", policyWith(`"TRUE AND resource.a == 'y'"`), "true or false stands only as the whole condition"},
		{"True in mixed case", policyWith(`"True"`), "a whole-condition boolean is written"},
		{"a tab inside IS NULL", policyWith(`"resource.a IS \tNULL"`), "holds a tab or a line break between its words"},
		{"a line feed after a list comma", policyWith(`"resource.a IN 'x', \n'y'"`), "a list holds a tab or a line break"},
		{"the operation", policyWith(`"operation == 'READ'"`), "a simplified policy does not read the operation"},
		{"subject.isM2M as an operand", policyWith(`"subject.isM2M == true"`), "EQ does not take subject.isM2M"},
		{"a permission under subject.permissions.", policyWith(`"subject.permissions.billing CONTAINS 'read'"`),
			"reads subject.permissions only as a whole"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertRefused(t, policiesPath+"billing", tc) })
	}
	for _, tc := range []uploadCase{
		{"a literal IN a list attribute", policyWith(`"'R' IN subject.roles"`), ""},
		{"a list attribute under CONTAINS", policyWith(`"subject.roles CONTAINS 'R'"`), ""},
		{"an attribute under IS NULL", policyWith(`"resource.a IS NULL"`), ""},
		{"one boolean under IN", policyWith(`"resource.a IN true"`), ""},
		{"TRUE alone", policyWith(`"TRUE"`), ""},
		{"a tab beside a space between tokens", policyWith(`"resource.a \t== 'y'"`), ""},
		{"subject.isM2M alone", policyWith(`"subject.isM2M"`), ""},
		{"subject.permissions", policyWith(`"subject.permissions CONTAINS 'read'"`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) { assertAccepted(t, policiesPath+"billing", tc) })
	}
}

// With requireDeclaredPIPs set, a condition reads only the PIPs the tenant
// declared in some domain, and the permission scope only where it declared
// subject.permissionScope. Unset, the policies may come before their PIPs.
func TestPolicyConditionReadingAnUndeclaredPIPIsRefusedWhenRequired(t *testing.T) {
	requiring := func(t *testing.T) *http.ServeMux {
		t.Helper()
		st, err := newStore("")
		if err != nil {
			t.Fatalf("newStore: %v", err)
		}
		mux := http.NewServeMux()
		(&server{st: st, defaultTenantID: defaultTenant, requireDeclaredPIPs: true}).routes(mux)
		return mux
	}
	const pips = `[{"name":"subject.dept","pipType":"TOKEN","claim":"dept"},` +
		`{"name":"subject.permissionScope","pipType":"PERMISSION_SCOPE","url":"http://pip/s"}]`
	reads := []uploadCase{
		{"an undeclared PIP", policyWith(`"subject.dept == 'x'"`), "subject.dept is not a PIP of the tenant"},
		{"the permission scope", policyWith(`"subject.permissionScope IS NOT EMPTY"`),
			"subject.permissionScope needs a PIP of that name declared in the tenant"},
	}
	for _, tc := range reads {
		t.Run(tc.name, func(t *testing.T) {
			assertRefusedOn(t, requiring(t), policiesPath+"billing", tc, http.StatusBadRequest)
		})
		t.Run(tc.name+" declared in another domain", func(t *testing.T) {
			mux := requiring(t)
			assertAcceptedOn(t, mux, pipsPath+"orders", uploadCase{body: pips})
			assertAcceptedOn(t, mux, policiesPath+"billing", tc)
		})
		t.Run(tc.name+" not required", func(t *testing.T) { assertAccepted(t, policiesPath+"billing", tc) })
	}
}
