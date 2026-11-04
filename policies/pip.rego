# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package pip

import rego.v1

# resolve_all computes all PIP values for the current request context.
# TOKEN PIPs: extracted from JWT payload (subject context).
# HEADER PIPs: extracted from input.requestHeaders.
# GENERAL PIPs: resolved via http.send for active PIPs only, with the extended
# request/response contract (authz-agent-ADR-0066..0069): ${...} substitution of
# subject/resource values into url/query/headers/body, a shared jsonPath subset
# for both substitution and response.extract, coerce/onMissing post-processing,
# and an agent-injected x-request-id header. Failure isolation is operand-local:
# a PIP that cannot resolve leaves its alias ABSENT (undefined), never a runtime
# error — the caller's AST leaf then simply does not match.

token_pip_config := data.pips.local.token
default token_pip_config := {}

header_pip_config := data.pips.local.header
default header_pip_config := {}

general_pip_config := data.pips.remote.general
default general_pip_config := {}

general_pip_activation := data.pips.activation.generalByResourceTypeOperation
default general_pip_activation := {}

# m2m_bearer_token is the M2M token the agent publishes while it is current:
# until data.m2m.expiresAtNs, or with no known expiry when that is 0 or
# absent. Empty before the first token and once the token has expired; a
# GENERAL PIP that would then present it is not called (build_headers).
#
# It lives under its own document root, data.m2m, NOT under data.pips beside the
# PIP configuration: the pull loop replaces data.pips wholesale on every tick,
# so a token stored there is erased within one tick.  See ADR-0076.
m2m_bearer_token := token if {
	token := data.m2m.bearerToken
	m2m_token_current
}

default m2m_bearer_token := ""

m2m_token_current if object.get(data.m2m, "expiresAtNs", 0) == 0

m2m_token_current if time.now_ns() < data.m2m.expiresAtNs

# ── x-request-id correlation (ADR-0069) ──────────────────────────────────
# OPA owns the id: use the inbound input.requestId when present, else generate
# one with a FIXED key so nd_builtin_cache (ADR-0063) returns the same id across
# every PIP call site in this evaluation. A canonical request whose input
# carries no requestId brings no id, so generation must live here.

request_id := id if {
	id := trim_space(object.get(input, "requestId", ""))
	id != ""
} else := uuid.rfc4122("authz-agent-x-request-id")

# ── Top-level resolution ─────────────────────────────────────────────────

resolve_all(subject_ctx, request_headers, resource_type, operation) := {} if {
	not pip_entries_configured
}

resolve_all(subject_ctx, request_headers, resource_type, operation) := merged_values if {
	pip_entries_configured
	request_base := resolve_request_level(subject_ctx, request_headers)
	# Substitution subject scope = canonical subject + request-level PIP values
	# (O-8); no GENERAL-PIP outputs (no PIP→PIP graph). Resource is empty here —
	# resolve_all is the request-level entry; per-resource resolution threads the
	# resource in via resolve_general_values directly.
	sub_scope := object.union(subject_ctx, request_base)
	general_vals := resolve_general_values(resource_type, operation, {}, sub_scope)
	merged_values := object.union(request_base, general_vals)
}

default resolve_all(_, _, _, _) := {}

resolve_request_level(subject_ctx, request_headers) := merged if {
	pip_entries_configured
	token_vals := resolve_token_values(subject_ctx)
	header_vals := resolve_header_values(request_headers)
	merged := object.union(token_vals, header_vals)
}

default resolve_request_level(_, _) := {}

# ── TOKEN PIP values ─────────────────────────────────────────────────────

resolve_token_values(subject_ctx) := result if {
	result := {alias: value |
		some pip_name
		cfg := token_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
		claim := cfg.claim
		claim != ""
		raw_value := object.get(subject_ctx, claim, null)
		default_value := object.get(cfg, "defaultValue", null)
		value := coalesce(raw_value, default_value)
		value != null
	}
}

default resolve_token_values(_) := {}

# ── HEADER PIP values ────────────────────────────────────────────────────

resolve_header_values(request_headers) := result if {
	result := {alias: value |
		some pip_name
		cfg := header_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
		header_name := lower(cfg.header)
		header_name != ""
		raw_value := object.get(request_headers, header_name, null)
		default_value := object.get(cfg, "defaultValue", null)
		value := coalesce(raw_value, default_value)
		value != null
	}
}

default resolve_header_values(_) := {}

# ── GENERAL PIP values ───────────────────────────────────────────────────
# For each active GENERAL PIP, build the fully-substituted request, issue the
# call, and post-process the response into the alias value. A PIP whose value
# cannot be produced (substitution fail, http error/timeout, coerce mismatch,
# onMissing:error) is simply omitted from the result set unless a defaultValue
# rescues it (soft default) — the alias is then absent and the leaf that uses it
# does not match. Identical resolved requests are memoized by nd_builtin_cache,
# so a resource-independent PIP fires a single http.send across a bulk decision
# (O-9 dedup-by-signature).

resolve_general_values(resource_type, operation, resource, sub_ctx) := result if {
	active_names := active_general_pips(resource_type, operation)
	result := {alias: value |
		some pip_name
		active_names[pip_name]
		cfg := general_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
		value := general_pip_value(cfg, resource, sub_ctx)
	}
}

default resolve_general_values(_, _, _, _) := {}

# general_pip_hard_failures classifies active GENERAL PIPs whose alias is ABSENT
# for a HARD reason (NEW-2 / ADR-0068). A soft-defaulted alias is present
# (general_pip_value is defined and returns the default) and is EXCLUDED — the
# present-vs-missing distinction. Returns {alias: kind} for deny-reason
# enrichment. Kinds:
#   "no_token"     — no authorization to present: no header of the PIP's own
#                    and no current M2M token, so the PIP is not called
#   "substitution" — the request could not be built (non-scalar / missing
#                    embedded source, incl. an anonymous subject.id used embedded)
#   "http_error"   — non-200 / timeout with no defaultValue
#   "response"     — 200 but extraction/coerce failed under onMissing:error
general_pip_hard_failures(resource_type, operation, resource, sub_ctx) := failures if {
	active_names := active_general_pips(resource_type, operation)
	# Selecting hard failures by ABSENCE from the resolved map (not
	# `not general_pip_value(...)`, which would also fire on a legitimate
	# boolean-false value from defaultValue:false / onMissing:empty+coerce:bool).
	resolved := resolve_general_values(resource_type, operation, resource, sub_ctx)
	failures := {alias: kind |
		some pip_name
		active_names[pip_name]
		cfg := general_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
		object.get(resolved, alias, _hf_absent) == _hf_absent
		kind := hard_failure_kind(cfg, resource, sub_ctx)
	}
}

default general_pip_hard_failures(_, _, _, _) := {}

# A set sentinel that can never be a resolved alias value.
_hf_absent := {"__hf_absent__"}

hard_failure_kind(cfg, resource, sub_ctx) := "no_token" if {
	headers := pip_headers(cfg, sub_ctx, resource)
	object.get(headers, "authorization", "") == ""
} else := "substitution" if {
	not build_pip_request(cfg, resource, sub_ctx)
} else := "http_error" if {
	general_pip_call(build_pip_request(cfg, resource, sub_ctx)).status_code != 200
} else := "response"

# general_pip_value resolves a single GENERAL PIP to its alias value, or is
# UNDEFINED when the value cannot be produced (operand-local failure) unless a
# defaultValue applies.
general_pip_value(cfg, resource, sub_ctx) := value if {
	req := build_pip_request(cfg, resource, sub_ctx)
	resp := general_pip_call(req)
	value := response_value(cfg, resp)
}

# build_pip_request assembles the http.send input from the config with all
# ${...} placeholders expanded. Undefined (→ operand fail) if any substitution
# fails (non-scalar embedded / missing embedded source).
build_pip_request(cfg, resource, sub_ctx) := req if {
	url := expand_url(cfg.url, sub_ctx, resource)
	method := upper(object.get(cfg, "httpMethod", "POST"))
	query := expand_query(object.get(cfg, "query", {}), sub_ctx, resource)
	headers := build_headers(cfg, sub_ctx, resource)
	timeout := sprintf("%ds", [object.get(cfg, "timeoutSeconds", 5)])
	req := {
		"method": method,
		"url": with_query(url, query),
		"headers": headers,
		"body": build_body(cfg, sub_ctx, resource),
		"timeout": timeout,
	}
}

# general_pip_call issues the request. raise_error:false so a network error /
# timeout returns a response object with status_code 0 rather than aborting the
# query (ADR-0052: no caching; ADR-0069: x-request-id injected, winning over any
# user-declared header).
general_pip_call(req) := http.send(send_request(req))

# send_request assembles the http.send input, injecting x-request-id (winning
# over any user-declared header) and omitting the body when there is none (GET).
send_request(req) := _send_base(req) if {
	req.body == ""
} else := object.union(_send_base(req), {"body": req.body})

_send_base(req) := {
	"method": req.method,
	"url": req.url,
	"headers": object.union(req.headers, {"x-request-id": request_id}),
	"timeout": req.timeout,
	"raise_error": false,
}

# with_query appends URL-encoded query params to the url (values already
# URL-encoded during expansion). Empty query → url unchanged.
with_query(url, query) := url if {
	count(query) == 0
}

with_query(url, query) := sprintf("%s?%s", [url, qs]) if {
	count(query) > 0
	pairs := sort([sprintf("%s=%s", [k, v]) | some k, v in query])
	qs := concat("&", pairs)
}

# build_headers merges forwarded inbound header names + explicit set headers,
# then injects the M2M Bearer token as `authorization` when:
#   (a) data.m2m.bearerToken is non-empty, AND
#   (b) neither forwardHeaders nor setHeaders already supply an `authorization` key.
# Priority: setHeaders > forwardHeaders > M2M token injection (ADR-0076).
# Undefined, so the PIP is not called, when the headers carry no
# authorization: no header of the PIP's own and no current M2M token.
build_headers(cfg, sub_ctx, resource) := headers if {
	headers := pip_headers(cfg, sub_ctx, resource)
	object.get(headers, "authorization", "") != ""
}

# pip_headers is build_headers without the authorization check.
pip_headers(cfg, sub_ctx, resource) := headers if {
	forwarded := {lower(name): v |
		some name in object.get(cfg, "forwardHeaders", [])
		v := object.get(request_headers_input, lower(name), "")
		v != ""
	}
	explicit := {lower(k): strip_crlf(ev) |
		some k, v in object.get(cfg, "setHeaders", {})
		ev := expand_string(v, sub_ctx, resource)
	}
	# every explicit header must expand (all-or-nothing)
	count(explicit) == count(object.get(cfg, "setHeaders", {}))
	base := object.union(forwarded, explicit)
	# Inject M2M Bearer token only when:
	#   - a token is available, AND
	#   - the merged headers do not already carry an `authorization` key.
	m2m := m2m_authorization_header(base)
	headers := add_content_type(object.union(base, m2m), cfg)
}

# m2m_authorization_header returns {"authorization": "Bearer <token>"} when the
# M2M token is available and the supplied header map has no `authorization` key.
# Returns {} otherwise (via else) so the caller's object.union is a no-op.
m2m_authorization_header(merged_headers) := {"authorization": concat("", ["Bearer ", m2m_bearer_token])} if {
	m2m_bearer_token != ""
	not object.get(merged_headers, "authorization", false)
} else := {}

request_headers_input := object.get(input, "requestHeaders", {})

add_content_type(headers, cfg) := object.union({"content-type": "application/json"}, headers) if {
	is_object(object.get(cfg, "body", null))
	object.get(headers, "content-type", "") == ""
} else := headers

# build_body expands ${...} inside the configured body at the Rego OBJECT level
# (not the serialized string) so it is immune to JSON-injection from substituted
# values and does no double-substitution: walk() finds every string leaf,
# expand_string is applied to each, and json.patch replaces them in place (both
# non-recursive). A whole-value leaf keeps its native type; an embedded leaf
# becomes a string (OPA marshals it correctly when the request is sent). If ANY
# leaf fails to expand (non-scalar / missing embedded source), the op is dropped
# and the count guard makes build_body UNDEFINED → the operand fails locally
# (never a silent empty body). Absent body → "".
build_body(cfg, sub_ctx, resource) := "" if {
	object.get(cfg, "body", null) == null
}

build_body(cfg, sub_ctx, resource) := body if {
	raw := object.get(cfg, "body", null)
	raw != null
	leaves := [[wpath, sval] |
		walk(raw, [wpath, sval])
		is_string(sval)
	]
	ops := [{"op": "replace", "path": json_pointer(pair[0]), "value": expand_string(pair[1], sub_ctx, resource)} |
		some pair in leaves
	]
	count(ops) == count(leaves) # all-or-nothing (a failed leaf → operand fail)
	body := json.patch(raw, ops)
}

# json_pointer builds an RFC-6901 pointer from a walk path (array of keys). Empty
# path → "" (the whole document).
json_pointer(path) := "" if {
	count(path) == 0
}

json_pointer(path) := concat("", segs) if {
	count(path) > 0
	segs := [sprintf("/%s", [jp_escape(path[i])]) | some i; path[i]]
}

jp_escape(k) := sprintf("%d", [k]) if is_number(k)
jp_escape(k) := replace(replace(k, "~", "~0"), "/", "~1") if is_string(k)

# ── Response post-processing (ADR-0068) ──────────────────────────────────

# response_value applies extract → coerce → onMissing. UNDEFINED when the value
# is not produced and onMissing is error/absent (operand-local); the configured
# defaultValue rescues it under onMissing:defaultValue or on http error.
response_value(cfg, resp) := value if {
	resp.status_code == 200
	body := parsed_body(resp)
	extracted := extract_response(cfg, body)
	value := extracted
} else := dv if {
	# soft default: http error/non-200/timeout OR extract miss, and a default
	# is configured via onMissing:defaultValue.
	dv := soft_default(cfg, resp)
} else := ev if {
	# onMissing:empty on an http error / non-200 / non-JSON body: bind the empty
	# value for the coerce shape, uniform with the 200 extract-miss path. Without
	# this clause `empty` silently degraded to `error` (alias absent) on any
	# failed call, and a "give me [] on failure" config became a hard failure.
	on_missing_of(cfg) == "empty"
	ev := empty_for(coerce_of(cfg))
}

# parsed_body returns the response body parsed as JSON (v1 always JSON).
# http.send already decodes a JSON response into `body` (an object/array/scalar);
# a string body is json.unmarshal'd ONLY when it is valid JSON (json.is_valid
# guards against a runtime error on a non-JSON body — null-pointer-safety). A
# non-JSON string yields UNDEFINED so the caller routes through onMissing.
parsed_body(resp) := raw if {
	raw := object.get(resp, "body", null)
	not is_string(raw)
	raw != null
}

parsed_body(resp) := body if {
	raw := object.get(resp, "body", null)
	is_string(raw)
	json.is_valid(raw)
	body := json.unmarshal(raw)
}

# extract_response applies response.extract (string or map form) + coerce +
# onMissing to the parsed body. No response block → whole body.
extract_response(cfg, body) := value if {
	resp_cfg := object.get(cfg, "response", null)
	resp_cfg == null
	value := body
}

extract_response(cfg, body) := value if {
	resp_cfg := object.get(cfg, "response", null)
	resp_cfg != null
	value := extract_with_response(cfg, resp_cfg, body)
}

# String-form extract → the alias value directly.
extract_with_response(cfg, resp_cfg, body) := value if {
	spec := object.get(resp_cfg, "extract", null)
	is_string(spec)
	value := apply_coerce_or_default(cfg, resp_cfg, extract_or_miss(body, spec), object.get(resp_cfg, "coerce", ""), object.get(resp_cfg, "onMissing", ""))
}

# Absent extract → whole body (coerce/onMissing still apply).
extract_with_response(cfg, resp_cfg, body) := value if {
	object.get(resp_cfg, "extract", null) == null
	value := apply_coerce_or_default(cfg, resp_cfg, body, object.get(resp_cfg, "coerce", ""), object.get(resp_cfg, "onMissing", ""))
}

# Map-form extract → an object bound under the alias; policies read
# subject.<alias>.<name>. Per-entry coerce/onMissing fall back to block-level.
# A per-entry miss routes only that entry to its onMissing; siblings unaffected.
extract_with_response(cfg, resp_cfg, body) := value if {
	spec := object.get(resp_cfg, "extract", null)
	is_object(spec)
	value := {name: v |
		some name, entry in spec
		v := extract_map_entry(cfg, resp_cfg, body, entry)
	}
}

extract_map_entry(cfg, resp_cfg, body, entry) := v if {
	is_string(entry)
	v := apply_coerce_or_default(cfg, resp_cfg, extract_or_miss(body, entry), object.get(resp_cfg, "coerce", ""), object.get(resp_cfg, "onMissing", ""))
}

extract_map_entry(cfg, resp_cfg, body, entry) := v if {
	is_object(entry)
	coerce := object.get(entry, "coerce", object.get(resp_cfg, "coerce", ""))
	on_missing := object.get(entry, "onMissing", object.get(resp_cfg, "onMissing", ""))
	v := apply_coerce_or_default(cfg, resp_cfg, extract_or_miss(body, entry.path), coerce, on_missing)
}

# extract_or_miss returns the extracted value or a distinct miss sentinel, so a
# non-wildcard miss (json_extract undefined) still routes uniformly through
# onMissing (incl. `empty`) rather than making the whole rule undefined.
extract_or_miss(body, path) := v if {
	v := json_extract(body, path)
} else := _pip_miss

# A SET sentinel — a JSON response body is never a set, so it cannot collide
# with a real extracted value (unlike an object sentinel).
_pip_miss := {"__pip_miss__"}

# apply_coerce_or_default: coerce the present value; on a miss (sentinel / null /
# coerce mismatch) route to onMissing. UNDEFINED (operand fail) when onMissing is
# error/absent and no value is produced.
apply_coerce_or_default(cfg, resp_cfg, raw, coerce, on_missing) := out if {
	is_present(raw)
	out := coerce_value(raw, coerce) # undefined on a coerce mismatch → falls to onMissing
} else := out if {
	on_missing == "defaultValue"
	out := object.get(cfg, "defaultValue", null)
} else := out if {
	on_missing == "empty"
	out := empty_for(coerce)
}

# is_present distinguishes a real extracted value from a miss (null ≡ missing;
# the sentinel marks a non-wildcard extract miss).
is_present(raw) if {
	raw != null
	raw != _pip_miss
}

# ── coerce (ADR-0068 / ADR-0053) ─────────────────────────────────────────
# Returns the coerced value or is UNDEFINED on a type mismatch (→ onMissing).

coerce_value(v, "") := v

coerce_value(v, "string") := v if is_string(v)
coerce_value(v, "string") := sprintf("%v", [v]) if is_number(v)
coerce_value(v, "string") := sprintf("%v", [v]) if is_boolean(v)

coerce_value(v, "number") := v if is_number(v)

coerce_value(v, "bool") := v if is_boolean(v)

coerce_value(v, "string[]") := out if {
	is_array(v)
	out := [s | some e in v; s := scalar_to_string(e)]
	count(out) == count(v)
}

coerce_value(v, "number[]") := v if {
	is_array(v)
	count([1 | some e in v; is_number(e)]) == count(v)
}

scalar_to_string(v) := v if is_string(v)
scalar_to_string(v) := sprintf("%v", [v]) if is_number(v)
scalar_to_string(v) := sprintf("%v", [v]) if is_boolean(v)

empty_for("string[]") := []
empty_for("number[]") := []
empty_for("string") := ""
empty_for("number") := 0
empty_for("bool") := false
empty_for("") := []

# soft_default rescues a non-200/error response (or an extract miss) with the
# configured defaultValue when onMissing:defaultValue. Otherwise UNDEFINED.
soft_default(cfg, resp) := dv if {
	on_missing_of(cfg) == "defaultValue"
	dv := object.get(cfg, "defaultValue", null)
	dv != null
}

on_missing_of(cfg) := object.get(object.get(cfg, "response", {}), "onMissing", "")

coerce_of(cfg) := object.get(object.get(cfg, "response", {}), "coerce", "")

# ── Activation: determine which GENERAL PIPs are needed ──────────────────

active_general_pips(resource_type, operation) := names if {
	rt_obj := object.get(general_pip_activation, resource_type, {})
	all_rt_obj := object.get(general_pip_activation, "ALL", {})
	exact := object.get(rt_obj, operation, [])
	rt_all := object.get(rt_obj, "ALL", [])
	all_op := object.get(all_rt_obj, operation, [])
	all_all := object.get(all_rt_obj, "ALL", [])
	names := {name |
		name := exact[_]
	} | {name |
		name := rt_all[_]
	} | {name |
		name := all_op[_]
	} | {name |
		name := all_all[_]
	}
}

default active_general_pips(_, _) := set()

pip_entries_configured if {
	count(object.get(data.pips, "byName", {})) > 0
}

pip_entries_configured if {
	count(object.get(object.get(data.pips, "local", {}), "token", {})) > 0
}

pip_entries_configured if {
	count(object.get(object.get(data.pips, "local", {}), "header", {})) > 0
}

pip_entries_configured if {
	count(object.get(object.get(data.pips, "remote", {}), "general", {})) > 0
}

# ── Known PIP aliases (for deny-reason classification) ────────────────────

known_pip_aliases := data.pips.aliasSet if {
	count(object.get(data.pips, "aliasSet", {})) > 0
}

known_pip_aliases := aliases if {
	count(object.get(data.pips, "aliasSet", {})) == 0
	aliases := {alias |
		some pip_name
		cfg := token_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
	} | {alias |
		some pip_name
		cfg := header_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
	} | {alias |
		some pip_name
		cfg := general_pip_config[pip_name]
		alias := cfg.alias
		alias != ""
	}
}

default known_pip_aliases := set()

# ── Helpers ──────────────────────────────────────────────────────────────

coalesce(value, default_val) := value if {
	value != null
}

coalesce(value, default_val) := default_val if {
	value == null
}

trim_space(s) := trim(s, " \t\r\n")

strip_crlf(s) := replace(replace(s, "\r", ""), "\n", "")

# ── ${...} template expansion (ADR-0067) ─────────────────────────────────
# Substitution scope: subject.* (canonical subject + request-level PIP values)
# and resource.{type,id,operation,attrs.*}. A whole-value placeholder keeps the
# native type; an embedded placeholder coerces a scalar to string and, on a
# non-scalar or missing embedded source, makes expand_string UNDEFINED so the
# whole request fails operand-locally.

# expand_string: whole-value placeholder → native value (missing → null,
# parity); embedded → interpolated string (or undefined on non-scalar/miss).
expand_string(s, sub_ctx, resource) := v if {
	not is_string(s)
	v := s
}

expand_string(s, sub_ctx, resource) := v if {
	is_string(s)
	whole_placeholder(s)
	inner := substring(s, 2, count(s) - 3)
	v := resolve_scope_or_null(inner, sub_ctx, resource)
}

expand_string(s, sub_ctx, resource) := v if {
	is_string(s)
	not whole_placeholder(s)
	v := interpolate(s, sub_ctx, resource)
}

whole_placeholder(s) if regex.match(`^\$\{[^}]+\}$`, s)

# interpolate replaces every embedded ${...} with the scalar string form of its
# resolved value (strings.replace_n does all at once — Rego forbids recursion).
# UNDEFINED if any placeholder resolves to a non-scalar or a missing source (the
# count check), so the operand fails rather than emitting a broken request.
interpolate(s, sub_ctx, resource) := out if {
	matches := regex.find_all_string_submatch_n(`\$\{([^}]+)\}`, s, -1)
	reps := {m[0]: scalar_to_string(resolve_scope(m[1], sub_ctx, resource)) | some m in matches}
	count(reps) == count({m[0] | some m in matches})
	out := strings.replace_n(reps, s)
}

# expand_url is expand_string for the `url` field: a whole-value placeholder is
# a full URL used as-is (not encoded); embedded placeholders are URL-encoded so a
# substituted value cannot inject path/query structure (O-11).
expand_url(s, sub_ctx, resource) := v if {
	whole_placeholder(s)
	inner := substring(s, 2, count(s) - 3)
	v := resolve_scope(inner, sub_ctx, resource)
	# A URL must be a string. A whole-value placeholder resolving to a non-string
	# (array/object/number/bool) or a missing source makes expand_url UNDEFINED so
	# the request fails operand-locally (substitution) rather than issuing an
	# http.send with a malformed url that only surfaces as a status-0 http_error.
	is_string(v)
}

expand_url(s, sub_ctx, resource) := v if {
	not whole_placeholder(s)
	v := interpolate_enc(s, sub_ctx, resource)
}

interpolate_enc(s, sub_ctx, resource) := out if {
	matches := regex.find_all_string_submatch_n(`\$\{([^}]+)\}`, s, -1)
	reps := {m[0]: urlquery.encode(scalar_to_string(resolve_scope(m[1], sub_ctx, resource))) | some m in matches}
	count(reps) == count({m[0] | some m in matches})
	out := strings.replace_n(reps, s)
}

# resolve_scope resolves ${subject.<path>} / ${resource.<path>} to its value, or
# is UNDEFINED on a miss. resolve_scope_or_null returns null on a miss (whole-
# value parity). URL/query encoding is applied by the caller where needed.
resolve_scope(inner, sub_ctx, resource) := v if {
	startswith(inner, "subject.")
	v := json_extract(sub_ctx, sprintf("$.%s", [substring(inner, 8, -1)]))
}

resolve_scope(inner, sub_ctx, resource) := v if {
	startswith(inner, "resource.")
	v := json_extract(resource, sprintf("$.%s", [substring(inner, 9, -1)]))
}

resolve_scope_or_null(inner, sub_ctx, resource) := v if {
	v := resolve_scope(inner, sub_ctx, resource)
} else := null

# expand_query URL-encodes each substituted value; all-or-nothing. A query value
# must resolve to a SCALAR (string/number/bool). A whole-value placeholder that
# resolves to an array/object (or a missing source → null) has no sensible query
# form, so it is dropped, the count check fails, and the request fails operand-
# locally (parity with the header path via strip_crlf) rather than emitting a
# URL-encoded stringification of the array/object.
expand_query(query, sub_ctx, resource) := out if {
	out := {k: urlquery_encode(val) |
		some k, v in query
		val := expand_string(v, sub_ctx, resource)
		is_query_scalar(val)
	}
	count(out) == count(query)
}

is_query_scalar(v) if is_string(v)

is_query_scalar(v) if is_number(v)

is_query_scalar(v) if is_boolean(v)

# The value is always a scalar here (is_query_scalar / interpolate_enc guard the
# callers); sprintf("%v") is identity for strings, so no double-encoding.
urlquery_encode(v) := urlquery.encode(sprintf("%v", [v]))

# ── Shared jsonPath evaluator (ADR-0067 subset: $, dot, [n], [*]) ─────────
# Used by both ${...} path resolution and response.extract. Total over arbitrary
# JSON: any wrong-type / missing / null traversal yields UNDEFINED (a miss),
# never a runtime error (the null-pointer-safety requirement).

# json_extract returns a single value for a wildcard-free path (exactly one
# match), or the collected array (document order) for a path containing [*].
# UNDEFINED on a miss. Implemented with walk() (Rego forbids recursion): every
# node's [path, value] is enumerated and matched against the parsed segments, so
# any wrong-type / missing / null traversal simply yields no match (never an
# error — the null-pointer-safety requirement).
json_extract(doc, path) := out if {
	contains(path, "[*]")
	segs := jp_parse(path)
	matches := [[wpath, value] |
		walk(doc, [wpath, value])
		jp_path_matches(segs, wpath)
	]
	out := [pair[1] | some pair in sort(matches)]
}

json_extract(doc, path) := out if {
	not contains(path, "[*]")
	segs := jp_parse(path)
	vals := [value |
		walk(doc, [wpath, value])
		jp_path_matches(segs, wpath)
	]
	count(vals) == 1
	out := vals[0]
}

# jp_parse tokenizes `$.a.b[0][*].c` into an ordered list of segment objects.
jp_parse(path) := segs if {
	body := trim_prefix(path, "$")
	matches := regex.find_all_string_submatch_n(`\.([^.\[]+)|\[([0-9]+)\]|(\[\*\])`, body, -1)
	segs := [jp_seg(matches[i]) | some i; matches[i]]
}

jp_seg(m) := {"field": m[1]} if m[1] != ""
jp_seg(m) := {"index": to_number(m[2])} if m[2] != ""
jp_seg(m) := {"wildcard": true} if m[3] != ""

# jp_path_matches: a walk-path matches the segments iff same length and every
# segment matches the corresponding key (field=string key, index=number key,
# wildcard=any array-index key).
jp_path_matches(segs, wpath) if {
	count(segs) == count(wpath)
	every i, seg in segs {
		jp_seg_matches(seg, wpath[i])
	}
}

jp_seg_matches(seg, key) if object.get(seg, "field", null) == key
jp_seg_matches(seg, key) if object.get(seg, "index", null) == key
jp_seg_matches(seg, key) if {
	object.get(seg, "wildcard", false) == true
	is_number(key)
}

# ── ENTITLEMENT PIP resolution (ADR-0054 / D-AG-11 / D-AG-13) ────────────
#
# The container-pinned entitlements entry lives at
# `data.pips.remote.entitlements`. When present, `resolve_entitlements_map`
# issues a single GET against
#
#   ${entitlements.url}/api/v3/user-entitlements/user/{subject.id}
#
# per authorize request (D-AG-13 — one EA endpoint only), pivots the
# response body into `{resourceType: {name: [resourceId, ...]}}`, and
# returns the map. authorize.rego merges the map into `enriched_subject`
# under the alias `entitledResources` so rls.rego's entitlements-scope
# AST ref can read buckets by `(resourceType, name)` pair.
#
# ADR-0052 binding: no cache. Each call issues a fresh http.send; the
# aggregator's own caching (if any) is the operator's concern. The rego
# layer carries zero request-scoped or process-scoped state across
# authorize calls.
#
# When the resolver is not configured, the subject has no id, or the
# aggregator call fails (non-200, network error), the map is empty —
# rls.rego's CONTAINS / CONTAINS ANY / IN / NOT CONTAINS / IS EMPTY
# operators then evaluate against an empty set which yields the legacy
# aggregator-unavailability behaviour (CONTAINS = false / IS EMPTY =
# true), matching the deny-by-default semantics described by D-AG-17.

entitlements_pip_config := cfg if {
	cfg := data.pips.remote.entitlements
	cfg.url
	cfg.url != ""
}

default entitlements_pip_config := null

resolve_entitlements_map(subject_ctx) := {} if {
	entitlements_pip_config == null
}

resolve_entitlements_map(subject_ctx) := {} if {
	cfg := entitlements_pip_config
	cfg != null
	user_id := trim(object.get(subject_ctx, "id", ""), " \t\r\n")
	user_id == ""
}

resolve_entitlements_map(subject_ctx) := ent_map if {
	cfg := entitlements_pip_config
	cfg != null
	user_id := trim(object.get(subject_ctx, "id", ""), " \t\r\n")
	user_id != ""
	url := sprintf("%s/api/v3/user-entitlements/user/%s", [cfg.url, user_id])
	resp := entitlements_http_call(url, cfg)
	resp.status_code == 200
	body := object.get(resp, "body", null)
	body != null
	ent_map := build_entitlements_map(body)
}

resolve_entitlements_map(subject_ctx) := {} if {
	cfg := entitlements_pip_config
	cfg != null
	user_id := trim(object.get(subject_ctx, "id", ""), " \t\r\n")
	user_id != ""
	url := sprintf("%s/api/v3/user-entitlements/user/%s", [cfg.url, user_id])
	resp := entitlements_http_call(url, cfg)
	resp.status_code != 200
}

default resolve_entitlements_map(_) := {}

entitlements_http_call(url, cfg) := http.send({
	"method": "GET",
	"url": url,
	"headers": {"Accept": "application/json", "x-request-id": request_id},
	"timeout": sprintf("%ds", [object.get(cfg, "httpTimeoutSeconds", 5)]),
	"raise_error": false,
	# ADR-0052: no caching at any layer; every authorize request that
	# references `subject.entitledResources.of(...).as(...)` issues a
	# fresh EA call. Matches the canonical stateless-per-request
	# contract from ADR-0027 + ADR-0048. ADR-0069: x-request-id injected.
})

# build_entitlements_map pivots the EA v3 direct-user response shape
# (see tests/parity/suite/model/entitlements.go) into the compact
# {resourceType: {name: [resourceId, ...]}} form rls.rego consumes.
build_entitlements_map(body) := result if {
	entitlements := object.get(body, "entitlements", [])
	result := {rt: names |
		some bidx
		block := entitlements[bidx]
		rt := object.get(block, "resourceType", "")
		rt != ""
		references := object.get(block, "references", [])
		names := {name: ids |
			some ridx
			ref := references[ridx]
			name := object.get(ref, "name", "")
			name != ""
			resources := object.get(ref, "resources", [])
			ids := [id |
				some rsidx
				resource := resources[rsidx]
				id := object.get(resource, "resourceId", "")
				id != ""
			]
		}
	}
}

default build_entitlements_map(_) := {}
