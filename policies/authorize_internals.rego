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

package authorize_internals

import rego.v1

default canonical := {
  "rlsIgnored": false,
  "results": []
}

# ── Admission gate (authorizationToken) ──────────────────────────────────

_admission_token := object.get(input, "authorizationToken", "")

_has_admission_token if {
  object.get(input, "authorizationToken", "__missing__") != "__missing__"
}

_admission_validation := data.identity.validate_token_with_reason(_admission_token) if {
  _has_admission_token
}

_admission_ok if {
  not _has_admission_token
}

_admission_ok if {
  _has_admission_token
  _admission_validation.valid
}

canonical := {
  "authError": {
    "status": 401,
    "message": _admission_validation.reason,
    "reason": _admission_validation.reason,
  },
} if {
  _has_admission_token
  not _admission_validation.valid
}

# ── Admission alone, for the agent's own decision path ───────────────────
#
# admission is the outcome of the caller and subject checks without any
# decision: authError when the admission token is refused, subjectError
# with the reason when the subject's token is, and otherwise in
# tokenPayload the verified claims the subject is read from: those of the
# subject's token, or for an anonymous request those of the admission
# token, whose roles the legacy service grants the anonymous subject ({}
# without one). The agent decides check/resource with the generated module of
# the request's tenant and asks this package only who the subject is.

admission := {"authError": {
  "status": 401,
  "message": _admission_validation.reason,
  "reason": _admission_validation.reason,
}} if {
  _has_admission_token
  not _admission_validation.valid
}

admission := {"subjectError": object.get(object.get(auth, "error", {}), "reason", "unauthorized")} if {
  _admission_ok
  auth := authentication_context
  not auth.authenticated
}

admission := {"tokenPayload": _subject_claims(auth)} if {
  _admission_ok
  auth := authentication_context
  auth.authenticated
}

_subject_claims(auth) := object.get(_admission_validation, "payload", {}) if {
  data.identity.anonymous_mode(input)
  _has_admission_token
} else := object.get(auth, "tokenPayload", {})

# ── Subject deny (valid admission, invalid subject) ──────────────────────

canonical := _subject_deny_response if {
  _admission_ok
  auth := authentication_context
  not auth.authenticated
}

_subject_deny_response := {
  "rlsIgnored": ignore_rls,
  "results": results,
} if {
  auth := authentication_context
  error_obj := object.get(auth, "error", {})
  reason := object.get(error_obj, "reason", "unauthorized")

  raw_resources := object.get(input, "resources", [])
  ignore_rls := bool_or_default(object.get(input, "ignoreRls", false), false)
  idxs := indices(count(raw_resources))

  results := [{
    "resourceType": object.get(raw_resources[idx], "resourceType", ""),
    "operation": object.get(raw_resources[idx], "operation", ""),
    "isAllowed": false,
    "reason": reason,
  } |
    idx := idxs[_]
  ]
}

# ── Canonical response (valid admission + valid subject) ─────────────────

canonical := canonical_response(eval) if {
  _admission_ok
  authenticated_subject
  eval := authorization_evaluation
}

_can_reuse_admission_subject if {
  _has_admission_token
  _admission_validation.valid
  not data.identity.anonymous_mode(input)
  object.get(input, "subject", "") == _admission_token
}

authentication_context := {
  "authenticated": true,
  "subject": data.identity.subject_from_verification(_admission_validation),
  "tokenPayload": object.get(_admission_validation, "payload", {}),
} if {
  _can_reuse_admission_subject
}

authentication_context := data.identity.authenticate(input) if {
  not _can_reuse_admission_subject
}

authenticated_subject := auth.subject if {
  auth := authentication_context
  auth.authenticated
}

_request_headers := object.get(input, "requestHeaders", {})

_token_payload := object.get(authentication_context, "tokenPayload", {})

authorization_evaluation := {
  "rlsIgnored": req.ignoreRls,
  "results": canonical_results,
} if {
  subject_ctx := authenticated_subject
  req := normalized_request(subject_ctx)
  wa_summary := _build_wildcard_summary(req.subjectRoles)
  idxs := indices(count(req.resources))

  decisions := [decision_for_resource(idx, req.resources[idx], req, wa_summary) |
    idx := idxs[_]
  ]

  canonical_results := [canonical_result(decisions[idx], req.ignoreRls) |
    idx := idxs[_]
  ]
}

_request_pip_base := data.pip.resolve_request_level(_token_payload, _request_headers)

normalized_request(subject_ctx) := {
  "resources": resources,
  "subject": subject_ctx,
  "subjectRoles": subject_roles,
  "ignoreRls": ignore_rls
} if {
  raw_resources := object.get(input, "resources", [])
  idxs := indices(count(raw_resources))
  resources := [normalize_resource_ref(raw_resources[idx]) |
    idx := idxs[_]
  ]

  subject_roles := subject_roles_set(subject_ctx)
  ignore_rls := bool_or_default(object.get(input, "ignoreRls", false), false)
}

# ── Wildcard-access summary (ADR-0040) ──────────────────────────────────

_global_access_by_role := by_role if {
  gar := object.get(data.policies, "globalAccessRoles", {})
  by_role := object.get(gar, "byRole", {})
}

default _global_access_by_role := {}

# Fast path: if any subject role has all=true, skip building operations/resourceTypes.
_build_wildcard_summary(subject_roles) := {"all": true, "operations": {}, "resourceTypes": {}} if {
  gar := _global_access_by_role
  some role
  subject_roles[role]
  object.get(gar, role, {})["all"] == true
}

# General path: no all=true match, build scoped operations/resourceTypes.
_build_wildcard_summary(subject_roles) := summary if {
  gar := _global_access_by_role
  count(gar) > 0
  count({1 | role := subject_roles[_]; object.get(gar, role, {})["all"] == true}) == 0

  ops := {op: true |
    role := subject_roles[_]
    entry := object.get(gar, role, {})
    some op
    object.get(entry, "operations", {})[op] == true
  }

  rts := {rt: true |
    role := subject_roles[_]
    entry := object.get(gar, role, {})
    some rt
    object.get(entry, "resourceTypes", {})[rt] == true
  }

  summary := {
    "all": false,
    "operations": ops,
    "resourceTypes": rts,
  }
}

default _build_wildcard_summary(_) := {"all": false, "operations": {}, "resourceTypes": {}}

_wildcard_matches_resource(wa_summary, _, _) if {
  wa_summary.all == true
}

_wildcard_matches_resource(wa_summary, _, operation_key) if {
  wa_summary.operations[operation_key]
}

_wildcard_matches_resource(wa_summary, resource_type_key, _) if {
  wa_summary.resourceTypes[resource_type_key]
}

# ── Per-resource decision (wildcard short-circuit + normal path) ────────

_wildcard_summary_empty(wa_summary) if {
  not wa_summary.all
  count(wa_summary.operations) == 0
  count(wa_summary.resourceTypes) == 0
}

decision_for_resource(index, resource_ref, req, wa_summary) := {
  "index": index,
  "resourceType": resource_ref.resourceType,
  "operation": resource_ref.operation,
  "resource": object.get(resource_ref, "resource", {}),
  "allow": true,
  "olsAllow": true,
  "rlsChecked": false,
  "rlsPredicate": "",
} if {
  not _wildcard_summary_empty(wa_summary)
  _wildcard_matches_resource(wa_summary, resource_ref.resourceTypeKey, resource_ref.operationKey)
} else := decision if {
  resource := object.get(resource_ref, "resource", {})
  ols_decision := data.ols.evaluate(resource_ref.resourceTypeKey, resource_ref.operationKey, req.subjectRoles)
  decision := decision_from_ols(index, resource_ref, resource, req, ols_decision)
}

decision_from_ols(index, resource_ref, resource, req, ols_decision) := {
  "index": index,
  "resourceType": resource_ref.resourceType,
  "operation": resource_ref.operation,
  "resource": resource,
  "allow": false,
  "olsAllow": false,
  "rlsChecked": false,
  "rlsPredicate": "",
  "reason": "No user roles associated with resource and operation",
} if {
  not ols_decision.allow
} else := {
  "index": index,
  "resourceType": resource_ref.resourceType,
  "operation": resource_ref.operation,
  "resource": resource,
  "allow": true,
  "olsAllow": true,
  "rlsChecked": false,
  "rlsPredicate": ""
} if {
  req.ignoreRls
} else := decision if {
  rls_ctx := rls_decision_context(resource_ref.resourceTypeKey, resource_ref.operationKey, resource, req, ols_decision)
  decision := rls_result(index, resource_ref, resource, req, ols_decision, rls_ctx)
}

rls_decision_context(resource_type_key, operation_key, resource, req, ols_decision) := {
  "enrichedSubject": enriched_subject,
  "rlsDecision": rls_decision,
} if {
  # ADR-0066/0067: thread the per-resource `resource` and the substitution
  # subject scope (canonical subject + request-level TOKEN/HEADER PIP values,
  # O-8) into GENERAL resolution so ${subject.*}/${resource.*} expand. Not the
  # general PIP outputs themselves (no PIP→PIP graph).
  sub_scope := object.union(req.subject, _request_pip_base)
  general_pip_values := data.pip.resolve_general_values(resource_type_key, operation_key, resource, sub_scope)
  pip_values := object.union(_request_pip_base, general_pip_values)
  # ADR-0054: resolve the container-pinned entitlements PIP per request
  # (no caching, ADR-0052) and land the pivoted map under the canonical
  # `entitledResources` alias so rls.rego's entitlements-scope AST ref
  # can evaluate CONTAINS / CONTAINS ANY / IN / NOT CONTAINS / IS EMPTY
  # against the resolved bucket. Empty map when resolver unconfigured
  # or aggregator unavailable — yields deny-by-default semantics on
  # policies that reference `subject.entitledResources.of(...)`.
  ent_values := _entitlement_pip_values(req.subject)
  enriched_subject := object.union(object.union(req.subject, pip_values), ent_values)
  rls_decision := data.rls.evaluate(resource_type_key, operation_key, resource, enriched_subject, ols_decision.roles, req.subjectRoles)
}

# _entitlement_pip_values keeps the `entitledResources` key present in
# enriched_subject even when the resolved map is empty so `IS EMPTY`
# condition evaluation remains deterministic (the key is always there;
# the bucket is either an object or an empty map). The caller always
# merges via object.union so a non-empty map overrides the empty
# placeholder.
_entitlement_pip_values(subject_ctx) := {"entitledResources": ent_map} if {
  ent_map := data.pip.resolve_entitlements_map(subject_ctx)
}

default _entitlement_pip_values(_) := {"entitledResources": {}}

rls_result(index, resource_ref, resource, req, ols_decision, rls_ctx) := {
  "index": index,
  "resourceType": resource_ref.resourceType,
  "operation": resource_ref.operation,
  "resource": resource,
  "allow": true,
  "olsAllow": true,
  "rlsChecked": true,
  "rlsPredicate": predicate,
  "typedPredicates": typed_predicates,
} if {
  rls_ctx.rlsDecision.allow
  predicate := _substitute_predicate(object.get(rls_ctx.rlsDecision, "predicate", ""), rls_ctx.enrichedSubject)

  raw_typed := object.get(rls_ctx.rlsDecision, "typed_predicates", {})
  typed_predicates := {k: _substitute_predicate_for_type(k, v, enriched_subject) |
    some k
    raw_typed[k] != ""
    v := _substitute_resource_type(k, raw_typed[k], resource_ref.resourceType)
    enriched_subject := rls_ctx.enrichedSubject
  }
} else := {
  "index": index,
  "resourceType": resource_ref.resourceType,
  "operation": resource_ref.operation,
  "resource": resource,
  "allow": false,
  "olsAllow": true,
  "rlsChecked": true,
  "rlsPredicate": "",
  "reason": rls_reason,
} if {
  display_roles := _deny_display_roles(ols_decision.roles, req.subjectRoles)
  # NEW-2 (ADR-0068): thread the per-resource `resource` and the substitution
  # subject scope (same as rls_decision_context) into the deny path so the
  # GENERAL hard-failure classifier can attach a `kind` to each failed alias.
  sub_scope := object.union(req.subject, _request_pip_base)
  deny_extras := _deny_resolution_extras(resource_ref.resourceTypeKey, resource_ref.operationKey, resource, sub_scope, rls_ctx.enrichedSubject)
  rls_reason := _build_rls_deny_reason(display_roles, deny_extras)
}

# In rsql, querydsl, mongodb, and sql predicates, ${resourceType} renders as
# the resource type of the request, spelled as the request spells it and
# without quotes. It is replaced before the ${subject.*} placeholders, as
# legacy does in querydsl. Legacy has no such placeholder in custom predicates.
_substitute_resource_type("custom", pred_str, _) := pred_str

_substitute_resource_type(ptype, pred_str, resource_type) := replace(pred_str, "${resourceType}", resource_type) if {
  ptype != "custom"
}

# Type-aware predicate substitution dispatcher.
# SQL predicates use SQL-appropriate single-quote escaping; all other types
# use the standard double-quote formatter (_format_subject_value).
_substitute_predicate_for_type("sql", pred_str, subject_ctx) := _substitute_sql_predicate(pred_str, subject_ctx)

_substitute_predicate_for_type(ptype, pred_str, subject_ctx) := _substitute_predicate(pred_str, subject_ctx) if {
  ptype != "sql"
}

# ── canonical_result: single canonical output form ───────────────────────

canonical_result(decision, ignore_rls) := {
  "resourceType": decision.resourceType,
  "operation": decision.operation,
  "isAllowed": false,
  "reason": object.get(decision, "reason", ""),
} if {
  not decision.allow
}

canonical_result(decision, true) := {
  "resourceType": decision.resourceType,
  "operation": decision.operation,
  "isAllowed": true
} if {
  decision.allow
}

canonical_result(decision, false) := {
  "resourceType": decision.resourceType,
  "operation": decision.operation,
  "isAllowed": true
} if {
  decision.allow
  predicates_arr := _build_predicates_array(decision)
  count(predicates_arr) == 0
}

canonical_result(decision, false) := {
  "resourceType": decision.resourceType,
  "operation": decision.operation,
  "isAllowed": true,
  "predicates": predicates_arr,
} if {
  decision.allow
  predicates_arr := _build_predicates_array(decision)
  count(predicates_arr) > 0
}

# Fixed order for deterministic canonical output (ADR-0029).
_predicate_type_order := ["rsql", "querydsl", "mongodb", "sql", "custom"]

_build_predicates_array(decision) := arr if {
  typed := object.get(decision, "typedPredicates", {})
  order := _predicate_type_order
  idxs := numbers.range(0, count(order) - 1)
  arr := [{"predicate": typed[order[idx]], "predicateType": order[idx]} |
    idx := idxs[_]
    typed[order[idx]] != ""
  ]
}

default _build_predicates_array(_) := []

canonical_response(eval) := {
  "rlsIgnored": eval.rlsIgnored,
  "results": eval.results
}

normalize_resource_ref(resource_ref) := {
  "resourceType": rt,
  "operation": op,
  "resourceTypeKey": upper(rt),
  "operationKey": upper(op),
  "resource": object.get(resource_ref, "resource", {})
} if {
  rt := object.get(resource_ref, "resourceType", "")
  op := object.get(resource_ref, "operation", "")
}

subject_roles_set(subject) := {upper(role) |
  some idx
  role := object.get(subject, "roles", [])[idx]
  role != ""
}

bool_or_default(value, fallback) := value if {
  is_boolean(value)
}

bool_or_default(value, fallback) := fallback if {
  not is_boolean(value)
}

indices(total) := [] if {
  total <= 0
}

indices(total) := numbers.range(0, total - 1) if {
  total > 0
}

direct_and_all_keys(value) := array.concat(lookup_keys(value), ["ALL"]) if {
  upper(value) != "ALL"
}

direct_and_all_keys(value) := ["ALL"] if {
  upper(value) == "ALL"
}

lookup_keys(value) := [value] if {
  value != ""
  upper(value) == value
}

lookup_keys(value) := [value, upper(value)] if {
  value != ""
  upper(value) != value
}

normalize_array(value) := value if {
  is_array(value)
}

normalize_array(value) := [] if {
  not is_array(value)
}

normalize_object(value) := value if {
  is_object(value)
}

normalize_object(value) := {} if {
  not is_object(value)
}

_deny_display_roles(ols_roles, _) := ols_roles

_substitute_predicate("", _) := ""

_substitute_predicate(pred_str, _) := pred_str if {
  pred_str != ""
  not contains(pred_str, "${subject.")
}

_substitute_predicate(pred_str, subject_ctx) := result if {
  pred_str != ""
  contains(pred_str, "${subject.")
  starts := indexof_n(pred_str, "${subject.")
  count(starts) > 0
  replacements := {placeholder: _format_subject_value(key, value) |
    some idx
    pos := starts[idx]
    after_prefix := substring(pred_str, pos + 10, -1)
    close := indexof(after_prefix, "}")
    close >= 0
    key := substring(after_prefix, 0, close)
    placeholder := sprintf("${subject.%s}", [key])
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) > 0
  result := strings.replace_n(replacements, pred_str)
}

_substitute_predicate(pred_str, subject_ctx) := pred_str if {
  pred_str != ""
  contains(pred_str, "${subject.")
  starts := indexof_n(pred_str, "${subject.")
  count(starts) > 0
  replacements := {placeholder: _format_subject_value(key, value) |
    some idx
    pos := starts[idx]
    after_prefix := substring(pred_str, pos + 10, -1)
    close := indexof(after_prefix, "}")
    close >= 0
    key := substring(after_prefix, 0, close)
    placeholder := sprintf("${subject.%s}", [key])
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) == 0
}

default _substitute_predicate(_, _) := ""

# Pre-computed variant: uses placeholderKeys from normalized data instead of
# runtime string scanning. Not yet wired into rls_result because rls.evaluate
# aggregates predicates and loses per-rule placeholderKeys. See handover for
# the upgrade path (requires rls.rego changes).
_substitute_predicate_from_keys(pred_str, subject_ctx, placeholder_keys) := result if {
  pred_str != ""
  count(placeholder_keys) > 0
  replacements := {sprintf("${subject.%s}", [key]): _format_subject_value(key, value) |
    some idx
    key := placeholder_keys[idx]
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) > 0
  result := strings.replace_n(replacements, pred_str)
}

_substitute_predicate_from_keys(pred_str, subject_ctx, placeholder_keys) := pred_str if {
  pred_str != ""
  count(placeholder_keys) > 0
  replacements := {sprintf("${subject.%s}", [key]): _format_subject_value(key, value) |
    some idx
    key := placeholder_keys[idx]
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) == 0
}

default _substitute_predicate_from_keys(_, _, _) := ""

# D-AF-R (2026-04-15, OQ-AF-6 owner resolution): scalar string values
# and string array elements resolved from PIPs / TOKEN PIPs / HEADER
# PIPs are JSON-quoted when rendered into RSQL / SQL / MongoDB /
# generic predicate templates so the output matches the legacy
# predicate contract. Numbers, booleans, and null render verbatim
# (bare form); arrays render per-element with the same rule,
# comma-joined.
#
# Canonical subject attributes derived directly from the JWT per
# ADR-0046 (`id`, `name`, `type`, `roles`, `scopes`) are rendered
# UNQUOTED to match legacy's canonical-subject projection — parity
# goldens like `check-filter-v1/rls-happy.json` pin
# `ownerId==<uuid>` (subject.id) as unquoted, while
# `check-filter-v1/token-pip.json` pins `department=="finance"`
# (subject.parityDepartment via TOKEN PIP) as quoted. The
# legacy boundary applies `@JsonIgnore` / canonical-shape handling
# that preserves UUIDs / enum-like scalars verbatim while wrapping
# PIP-resolved strings.
#
# The helper is reached from every predicate-substitution call site
# (canonical authorize + every legacy / v2 check endpoint that
# projects `predicates[]`), so the quoting rule applies uniformly
# across the canonical path — D-AF-A grep stays empty. Pre-existing
# rego unit tests under
# policies/pip_resolution_test.rego that asserted the
# unquoted form are updated in lockstep per D-AF-R.
_canonical_subject_key("id")
_canonical_subject_key("name")
_canonical_subject_key("type")
_canonical_subject_key("roles")
_canonical_subject_key("scopes")

# Canonical array: quote each element, comma-joined without space
# (matches legacy `subject.roles`/`subject.scopes` projection).
_format_subject_value(key, value) := concat(",", [sprintf("\"%v\"", [v]) | some idx; v := value[idx]]) if {
  is_array(value)
  _canonical_subject_key(key)
}

# Non-canonical (PIP / TOKEN / HEADER-resolved) array: quote each
# element, comma-joined with a trailing space per the legacy
# `access-control` aggregator output for PIP-backed arrays. The
# space matters for parity — `check-filter-v1/general-pip-list.json`
# pins `id=in=("row2-pip-other", "row2-pip-allow")` byte-for-byte.
_format_subject_value(key, value) := concat(", ", [sprintf("\"%v\"", [v]) | some idx; v := value[idx]]) if {
  is_array(value)
  not _canonical_subject_key(key)
}

# Scalar canonical subject attribute: emit verbatim (unquoted).
# UUIDs / enum-like scalars preserved as-is per legacy's canonical-
# subject shape.
_format_subject_value(key, value) := sprintf("%v", [value]) if {
  not is_array(value)
  _canonical_subject_key(key)
}

# Scalar non-canonical attribute (PIP / TOKEN / HEADER PIP
# resolution): double-quoted per the legacy parity contract, even
# when the value is numeric or boolean. `sprintf("\"%v\"", ...)`
# emits the value without JSON-escape processing, matching
# `check-filter-v1/general-scalar-number-substitution.json`'s
# `amount=lt="1000"` and
# `check-filter-v1/general-scalar-boolean-substitution.json`'s
# `archived=="false"`.
_format_subject_value(key, value) := sprintf("\"%v\"", [value]) if {
  not is_array(value)
  not _canonical_subject_key(key)
}

# ── SQL predicate substitution (single-quote escaping for SQL) ──────────
#
# SQL predicates use single-quoted string values to match the legacy
# access-control rendering of SQL filter conditions:
#   - Non-canonical scalar:  'value'  (single-quoted)
#   - Non-canonical array:   'v1', 'v2'  (comma-space, each single-quoted)
#   - Canonical scalar:      value  (unquoted, same as RSQL; UUIDs/enums)
#   - Canonical array:       v1,v2  (comma-joined, unquoted)
#
# Parity goldens that anchor this behaviour:
#   check-filter-v1/token-scalar-into-sql.json   → department=''finance''
#   check-filter-v1/general-array-into-sql.json  → id IN ('row6-sql-1', 'row6-sql-2')

# Non-canonical (PIP / TOKEN / HEADER-resolved) array: single-quoted per
# element, comma-space separated — matches legacy access-control's SQL
# array rendering for the `id IN (${subject.allowed})` pattern.
_format_sql_value(key, value) := concat(", ", [sprintf("'%v'", [v]) | some idx; v := value[idx]]) if {
  is_array(value)
  not _canonical_subject_key(key)
}

# Canonical array (roles, scopes): comma-joined without quotes.
_format_sql_value(key, value) := concat(",", [sprintf("%v", [v]) | some idx; v := value[idx]]) if {
  is_array(value)
  _canonical_subject_key(key)
}

# Canonical scalar (id, name, type …): emit verbatim — UUIDs / enum-like
# values are SQL-safe without quoting and match the legacy contract.
_format_sql_value(key, value) := sprintf("%v", [value]) if {
  not is_array(value)
  _canonical_subject_key(key)
}

# Non-canonical scalar: single-quoted. The surrounding single quotes in a
# SQL template (e.g. `department='${subject.dept}'`) then produce the
# double-single-quote form `department=''finance''` that access-control emits.
_format_sql_value(key, value) := sprintf("'%v'", [value]) if {
  not is_array(value)
  not _canonical_subject_key(key)
}

_substitute_sql_predicate("", _) := ""

_substitute_sql_predicate(pred_str, _) := pred_str if {
  pred_str != ""
  not contains(pred_str, "${subject.")
}

_substitute_sql_predicate(pred_str, subject_ctx) := result if {
  pred_str != ""
  contains(pred_str, "${subject.")
  starts := indexof_n(pred_str, "${subject.")
  count(starts) > 0
  replacements := {placeholder: _format_sql_value(key, value) |
    some idx
    pos := starts[idx]
    after_prefix := substring(pred_str, pos + 10, -1)
    close := indexof(after_prefix, "}")
    close >= 0
    key := substring(after_prefix, 0, close)
    placeholder := sprintf("${subject.%s}", [key])
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) > 0
  result := strings.replace_n(replacements, pred_str)
}

_substitute_sql_predicate(pred_str, subject_ctx) := pred_str if {
  pred_str != ""
  contains(pred_str, "${subject.")
  starts := indexof_n(pred_str, "${subject.")
  count(starts) > 0
  replacements := {placeholder: _format_sql_value(key, value) |
    some idx
    pos := starts[idx]
    after_prefix := substring(pred_str, pos + 10, -1)
    close := indexof(after_prefix, "}")
    close >= 0
    key := substring(after_prefix, 0, close)
    placeholder := sprintf("${subject.%s}", [key])
    value := object.get(subject_ctx, key, null)
    value != null
  }
  count(replacements) == 0
}

default _substitute_sql_predicate(_, _) := ""

# ── DENY reason enrichment ───────────────────────────────────────────────

_deny_resolution_extras(resource_type, operation, resource, sub_scope, enriched_subject) := {
  "pip_failures": pip_list,
  "missing_attrs": attr_list,
} if {
  known_aliases := data.pip.known_pip_aliases
  all_missing := _find_missing_rls_refs(resource_type, operation, enriched_subject)
  # NEW-2 (ADR-0068): {alias: kind} for GENERAL hard failures only. Re-resolution
  # is free in prod (nd_builtin_cache memoizes the identical http.send); in unit
  # tests http.send is mocked. Soft-defaulted aliases are present, hence not in
  # all_missing, hence never annotated here.
  hard_kinds := data.pip.general_pip_hard_failures(resource_type, operation, resource, sub_scope)
  pip_list := sort([_format_pip_failure(alias, hard_kinds) |
    all_missing[alias]
    known_aliases[alias]
  ])
  attr_list := sort([r | all_missing[r]; not known_aliases[r]])
}

default _deny_resolution_extras(_, _, _, _, _) := {"pip_failures": [], "missing_attrs": []}

# Annotate a hard PIP failure with its classified kind (substitution / http_error
# / response) when the GENERAL classifier produced one; a TOKEN/HEADER alias or an
# unclassified GENERAL failure renders bare. The bare form keeps existing
# substring deny-reason assertions ("PIP resolution failed: <alias>") valid.
_format_pip_failure(alias, hard_kinds) := sprintf("%v (%v)", [alias, kind]) if {
  kind := hard_kinds[alias]
} else := alias

_find_missing_rls_refs(resource_type, operation, enriched_subject) := refs if {
  indexed_refs := indexed_rls_subject_refs(resource_type, operation)
  count(indexed_refs) > 0
  refs := {attr |
    some idx
    attr := indexed_refs[idx]
    object.get(enriched_subject, attr, "__missing__") == "__missing__"
  }
}

# Fallback: only fires when refIndex is absent (unit-test data without Go normalizer).
# In production the Go normalizer always generates refIndex, so this path is never taken.
_find_missing_rls_refs(resource_type, operation, enriched_subject) := refs if {
  not data.policies.refIndex
  rls_data := object.get(data.policies, "rls", {})

  pred_refs := {attr |
    some rt_key
    _rls_key_match(resource_type, rt_key)
    rt_obj := rls_data[rt_key]
    some op_key
    _rls_key_match(operation, op_key)
    op_obj := rt_obj[op_key]
    some role_key
    rule_list := op_obj[role_key]
    some rule_idx
    rule := rule_list[rule_idx]
    some pidx
    pred_obj := object.get(rule, "predicates", [])[pidx]
    pred_str := object.get(pred_obj, "predicate", "")
    matches := regex.find_all_string_submatch_n(`\$\{subject\.([^}]+)\}`, pred_str, -1)
    some midx
    match := matches[midx]
    attr := match[1]
    not enriched_subject[attr]
  }

  cond_refs := {attr |
    some rt_key
    _rls_key_match(resource_type, rt_key)
    rt_obj := rls_data[rt_key]
    some op_key
    _rls_key_match(operation, op_key)
    op_obj := rt_obj[op_key]
    some role_key
    rule_list := op_obj[role_key]
    some rule_idx
    rule := rule_list[rule_idx]
    cond_ast := object.get(rule, "conditionAst", null)
    cond_ast != null
    walk(cond_ast, [_, node])
    is_object(node)
    ref_obj := object.get(node, "ref", null)
    ref_obj != null
    ref_obj.scope == "subject"
    ref_path := ref_obj.path
    count(ref_path) > 0
    attr := ref_path[0]
    not enriched_subject[attr]
  }

  refs := pred_refs | cond_refs
}

default _find_missing_rls_refs(_, _, _) := set()

indexed_rls_subject_refs(resource_type, operation) := refs if {
  ref_index := object.get(data.policies, "refIndex", {})
  by_rt_op := object.get(ref_index, "subjectRefsByResourceTypeOperation", {})
  resource_keys := direct_and_all_keys(resource_type)
  operation_keys := direct_and_all_keys(operation)

  ref_set := {attr |
    some rt_idx
    some op_idx
    rt_key := resource_keys[rt_idx]
    op_key := operation_keys[op_idx]
    ref_list := object.get(object.get(by_rt_op, rt_key, {}), op_key, [])
    some idx
    attr := ref_list[idx]
    attr != ""
  }

  refs := sort([attr |
    attr := ref_set[_]
  ])
}

default indexed_rls_subject_refs(_, _) := []

_rls_key_match(value, key) if {
  key == "ALL"
}

_rls_key_match(value, key) if {
  upper(key) == upper(value)
}

_build_rls_deny_reason(display_roles, extras) := reason if {
  base := sprintf("ABAC validations failed for roles {%v}", [concat(", ", display_roles)])
  count(extras.pip_failures) > 0
  count(extras.missing_attrs) > 0
  pip_part := sprintf("PIP resolution failed: %v", [concat(", ", extras.pip_failures)])
  attr_part := sprintf("subject attribute not found: %v", [concat(", ", extras.missing_attrs)])
  reason := concat("; ", [base, pip_part, attr_part])
}

_build_rls_deny_reason(display_roles, extras) := reason if {
  base := sprintf("ABAC validations failed for roles {%v}", [concat(", ", display_roles)])
  count(extras.pip_failures) > 0
  count(extras.missing_attrs) == 0
  pip_part := sprintf("PIP resolution failed: %v", [concat(", ", extras.pip_failures)])
  reason := concat("; ", [base, pip_part])
}

_build_rls_deny_reason(display_roles, extras) := reason if {
  base := sprintf("ABAC validations failed for roles {%v}", [concat(", ", display_roles)])
  count(extras.pip_failures) == 0
  count(extras.missing_attrs) > 0
  attr_part := sprintf("subject attribute not found: %v", [concat(", ", extras.missing_attrs)])
  reason := concat("; ", [base, attr_part])
}

_build_rls_deny_reason(display_roles, extras) := reason if {
  count(extras.pip_failures) == 0
  count(extras.missing_attrs) == 0
  reason := sprintf("ABAC validations failed for roles {%v}", [concat(", ", display_roles)])
}
