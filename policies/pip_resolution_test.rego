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

package pip_resolution_test

import rego.v1

# m2m_token is a current token of the agent: without one no GENERAL PIP is called.
m2m_token := {"bearerToken": "test-token"}

# ── TOKEN PIP resolution ─────────────────────────────────────────────────

test_token_pip_resolves_claim if {
	token_payload := {"sub": "user1", "preferred_username": "tester", "realm_access": {"roles": ["ROLE_USER"]}, "customer-id": "C123"}
	pip_config := {
		"local": {
			"token": {
				"subject.customerId": {
					"name": "subject.customerId",
					"alias": "customerId",
					"claim": "customer-id"
				}
			},
			"header": {}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	result := data.pip.resolve_all(token_payload, {}, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	result.customerId == "C123"
}

test_token_pip_uses_default_when_claim_absent if {
	token_payload := {"sub": "user1", "preferred_username": "tester", "realm_access": {"roles": ["ROLE_USER"]}}
	pip_config := {
		"local": {
			"token": {
				"subject.customerId": {
					"name": "subject.customerId",
					"alias": "customerId",
					"claim": "customer-id",
					"defaultValue": "DEFAULT_CUSTOMER"
				}
			},
			"header": {}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	result := data.pip.resolve_all(token_payload, {}, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	result.customerId == "DEFAULT_CUSTOMER"
}

# ── HEADER PIP resolution ────────────────────────────────────────────────

test_header_pip_resolves_from_request_headers if {
	token_payload := {"sub": "user1"}
	request_headers := {"x-tenant-id": "T456"}
	pip_config := {
		"local": {
			"token": {},
			"header": {
				"subject.tenantId": {
					"name": "subject.tenantId",
					"alias": "tenantId",
					"header": "x-tenant-id"
				}
			}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	result := data.pip.resolve_all(token_payload, request_headers, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	result.tenantId == "T456"
}

test_header_pip_uses_default_when_header_absent if {
	token_payload := {"sub": "user1"}
	pip_config := {
		"local": {
			"token": {},
			"header": {
				"subject.tenantId": {
					"name": "subject.tenantId",
					"alias": "tenantId",
					"header": "x-tenant-id",
					"defaultValue": "DEFAULT_TENANT"
				}
			}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	result := data.pip.resolve_all(token_payload, {}, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	result.tenantId == "DEFAULT_TENANT"
}

# ── Combined TOKEN + HEADER ──────────────────────────────────────────────

test_combined_token_and_header_pips if {
	token_payload := {"sub": "user1", "customer-id": "C999"}
	request_headers := {"x-region": "EU"}
	pip_config := {
		"local": {
			"token": {
				"subject.customerId": {
					"name": "subject.customerId",
					"alias": "customerId",
					"claim": "customer-id"
				}
			},
			"header": {
				"subject.region": {
					"name": "subject.region",
					"alias": "region",
					"header": "x-region"
				}
			}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	result := data.pip.resolve_all(token_payload, request_headers, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	result.customerId == "C999"
	result.region == "EU"
}

# ── Empty PIP config ─────────────────────────────────────────────────────

test_no_pip_config_returns_empty if {
	token_payload := {"sub": "user1"}
	result := data.pip.resolve_all(token_payload, {}, "ORDER", "READ")
	count(result) == 0
}

# ── GENERAL PIP activation ───────────────────────────────────────────────

test_general_pip_not_activated_for_unmatched_resource if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.allowed": {
					"name": "subject.allowed",
					"alias": "allowed",
					"url": "http://unreachable:9999/never-called",
					"httpMethod": "GET"
				}
			}
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {
					"READ": ["subject.allowed"]
				}
			}
		}
	}

	result := data.pip.resolve_all(
		{"sub": "user1"},
		{},
		"ORDER",
		"READ",
	) with data.pips as pip_config with data.m2m as m2m_token

	not result.allowed
}

# ── PIP values merged into subject for RLS evaluation ────────────────────

test_pip_enriched_subject_used_in_rls if {
	policies := {
		"ols": {
			"ORDER": {
				"READ": ["ROLE_USER"]
			}
		},
		"rls": {
			"ORDER": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "eq",
							"args": [
								{"ref": {"scope": "subject", "path": ["customerId"]}},
								{"ref": {"scope": "resource", "path": ["ownerId"]}}
							]
						},
						"predicates": [{"predicate": "ownerId==${subject.customerId}", "type": "rsql"}]
					}]
				}
			}
		}
	}

	pip_config := {
		"local": {
			"token": {
				"subject.customerId": {
					"name": "subject.customerId",
					"alias": "customerId",
					"claim": "customer-id"
				}
			},
			"header": {}
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}}
	}

	token_payload := {"sub": "user1", "preferred_username": "tester", "realm_access": {"roles": ["ROLE_USER"]}, "customer-id": "OWNER1"}
	subject := {
		"id": "user1",
		"name": "tester",
		"type": "USER",
		"roles": ["ROLE_USER"],
		"scopes": []
	}

	resource_type := "ORDER"
	operation := "READ"
	resource := {"ownerId": "OWNER1"}
	subject_roles := {"ROLE_USER"}

	pip_values := data.pip.resolve_all(token_payload, {}, resource_type, operation)
		with data.pips as pip_config with data.m2m as m2m_token

	enriched := object.union(subject, pip_values)

	ols_result := data.ols.evaluate(resource_type, operation, subject_roles)
		with data.policies as policies

	ols_result.allow

	rls_result := data.rls.evaluate(
		resource_type, operation, resource, enriched, ols_result.roles, subject_roles
	) with data.policies as policies

	rls_result.allow
}

# ── PIP value substitution in predicates ──────────────────────────────────

test_pip_values_substituted_in_predicate if {
	policies := {
		"ols": {
			"ORDER": {
				"READ": ["ROLE_USER"]
			}
		},
		"rls": {
			"ORDER": {
				"READ": {
					"ROLE_USER": [{
						"condition": true,
						"predicates": [{
							"predicate": "customerId=in=(${subject.customerIds})",
							"type": "rsql",
						}],
					}],
				},
			},
		},
	}

	pip_config := {
		"local": {
			"token": {
				"subject.customerIds": {
					"name": "subject.customerIds",
					"alias": "customerIds",
					"claim": "customer-ids",
				},
			},
			"header": {},
		},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}},
	}

	token_payload := {"sub": "user1", "realm_access": {"roles": ["ROLE_USER"]}, "customer-ids": ["C1", "C2", "C3"]}
	subject := {
		"id": "user1",
		"roles": ["ROLE_USER"]
	}

	pip_values := data.pip.resolve_all(token_payload, {}, "ORDER", "READ")
		with data.pips as pip_config with data.m2m as m2m_token

	pip_values.customerIds == ["C1", "C2", "C3"]

	enriched := object.union(subject, pip_values)
	subject_roles := {"ROLE_USER"}

	ols_result := data.ols.evaluate("ORDER", "READ", subject_roles)
		with data.policies as policies

	ols_result.allow

	rls_result := data.rls.evaluate(
		"ORDER", "READ", {}, enriched, ols_result.roles, subject_roles,
	) with data.policies as policies

	rls_result.allow
	rls_result.predicate == "customerId=in=(${subject.customerIds})"

	substituted := data.authorize_internals._substitute_predicate(
		rls_result.predicate, enriched,
	)
	# D-AF-R (OQ-AF-6, 2026-04-15): PIP-resolved array elements are
	# JSON-quoted and comma-space-joined so the rendered RSQL
	# predicate matches the legacy parity contract — see
	# `check-filter-v1/general-pip-list.json`. Canonical subject
	# arrays (`roles`, `scopes`) use no-space joining to match their
	# separate legacy projection.
	substituted == `customerId=in=("C1", "C2", "C3")`
}

test_pip_scalar_value_substituted_in_predicate if {
	enriched := {"tenantId": "T-123", "id": "user1"}
	raw := "tenantId==${subject.tenantId}"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	# D-AF-R: non-canonical (PIP / TOKEN / HEADER-resolved) scalar
	# strings render JSON-quoted per the legacy parity contract.
	# `tenantId` is not in the canonical subject field set
	# ({id, name, type, roles, scopes}) so quoting applies.
	result == `tenantId=="T-123"`
}

test_subject_id_substituted_in_predicate if {
	enriched := {"id": "user-42", "roles": ["ROLE_USER"]}
	raw := "ownerId==${subject.id}"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	# D-AF-R (OQ-AF-6, 2026-04-15): canonical subject attributes
	# (`id`, `name`, `type`, `roles`, `scopes` per ADR-0046) render
	# UNQUOTED in predicates — legacy treats them as canonical-shape
	# projections and preserves UUID / enum-like scalars verbatim.
	# The parity golden `check-filter-v1/rls-happy.json` pins this.
	# Non-canonical (PIP-resolved) strings render quoted; see
	# `test_pip_scalar_value_substituted_in_predicate` below.
	result == "ownerId==user-42"
}

test_no_matching_keys_predicate_unchanged if {
	enriched := {"id": "user1"}
	raw := "ownerId==${subject.unknownKey}"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	result == "ownerId==${subject.unknownKey}"
}

# ── DENY reason: PIP resolution failed ───────────────────────────────────

test_deny_reason_pip_resolution_failed if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.brokenPip": {
					"name": "subject.brokenPip",
					"alias": "brokenPip",
					"url": "http://localhost:1/nonexistent",
					"httpMethod": "GET",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"PIPTEST": {"READ": ["subject.brokenPip"]},
			},
		},
	}

	policies := {
		"ols": {"PIPTEST": {"READ": ["ROLE_USER"]}},
		"rls": {
			"PIPTEST": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "eq",
							"args": [
								{"ref": {"scope": "resource", "path": ["ownerId"]}},
								{"ref": {"scope": "subject", "path": ["brokenPip"]}},
							],
						},
						"predicates": [{"predicate": "ownerId==${subject.brokenPip}", "type": "rsql"}],
					}],
				},
			},
		},
	}

	subject := {"id": "user1", "roles": ["ROLE_USER"]}
	input_data := {
		"resources": [{"resourceType": "PIPTEST", "operation": "READ", "resource": {"ownerId": "X"}}],
		"subject": subject,
		"ignoreRls": false,
	}

	result := data.authorize_internals.authorization_evaluation
		with input as input_data
		with data.pips as pip_config with data.m2m as m2m_token
		with data.policies as policies
		with data.authorize_internals.authenticated_subject as subject

	count(result.results) == 1
	decision := result.results[0]
	decision.isAllowed == false

	contains(decision.reason, "PIP resolution failed: brokenPip")
	not contains(decision.reason, "subject attribute not found")
}

# NEW-2 (ADR-0068): the deny reason annotates each hard GENERAL failure with its
# classified kind. brokenPip points at a dead url (GET, buildable request, non-200
# response) → kind "http_error". Reuses the same config/policy as above.
test_deny_reason_pip_failure_annotated_with_kind if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.brokenPip": {
					"name": "subject.brokenPip",
					"alias": "brokenPip",
					"url": "http://localhost:1/nonexistent",
					"httpMethod": "GET",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"PIPTEST": {"READ": ["subject.brokenPip"]},
			},
		},
	}

	policies := {
		"ols": {"PIPTEST": {"READ": ["ROLE_USER"]}},
		"rls": {
			"PIPTEST": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "eq",
							"args": [
								{"ref": {"scope": "resource", "path": ["ownerId"]}},
								{"ref": {"scope": "subject", "path": ["brokenPip"]}},
							],
						},
						"predicates": [{"predicate": "ownerId==${subject.brokenPip}", "type": "rsql"}],
					}],
				},
			},
		},
	}

	subject := {"id": "user1", "roles": ["ROLE_USER"]}
	input_data := {
		"resources": [{"resourceType": "PIPTEST", "operation": "READ", "resource": {"ownerId": "X"}}],
		"subject": subject,
		"ignoreRls": false,
	}

	result := data.authorize_internals.authorization_evaluation
		with input as input_data
		with data.pips as pip_config with data.m2m as m2m_token
		with data.policies as policies
		with data.authorize_internals.authenticated_subject as subject

	decision := result.results[0]
	decision.isAllowed == false
	contains(decision.reason, "brokenPip (http_error)")
}

# ── DENY reason: subject attribute not found ──────────────────────────────

test_deny_reason_missing_subject_attribute if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}},
	}

	policies := {
		"ols": {"ATTRTEST": {"READ": ["ROLE_USER"]}},
		"rls": {
			"ATTRTEST": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "eq",
							"args": [
								{"ref": {"scope": "resource", "path": ["ownerId"]}},
								{"ref": {"scope": "subject", "path": ["nonExistentAttr"]}},
							],
						},
						"predicates": [{"predicate": "ownerId==${subject.nonExistentAttr}", "type": "rsql"}],
					}],
				},
			},
		},
	}

	subject := {"id": "user1", "roles": ["ROLE_USER"]}
	input_data := {
		"resources": [{"resourceType": "ATTRTEST", "operation": "READ", "resource": {"ownerId": "X"}}],
		"subject": subject,
		"ignoreRls": false,
	}

	result := data.authorize_internals.authorization_evaluation
		with input as input_data
		with data.pips as pip_config with data.m2m as m2m_token
		with data.policies as policies
		with data.authorize_internals.authenticated_subject as subject

	count(result.results) == 1
	decision := result.results[0]
	decision.isAllowed == false

	contains(decision.reason, "subject attribute not found: nonExistentAttr")
	not contains(decision.reason, "PIP resolution failed")
}

# ── DENY reason: both PIP failure and missing attr ────────────────────────

test_deny_reason_pip_failure_and_missing_attr if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.brokenPip": {
					"name": "subject.brokenPip",
					"alias": "brokenPip",
					"url": "http://localhost:1/nonexistent",
					"httpMethod": "GET",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"BOTHTEST": {"READ": ["subject.brokenPip"]},
			},
		},
	}

	policies := {
		"ols": {"BOTHTEST": {"READ": ["ROLE_USER"]}},
		"rls": {
			"BOTHTEST": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "and",
							"args": [
								{
									"op": "eq",
									"args": [
										{"ref": {"scope": "subject", "path": ["brokenPip"]}},
										{"const": "X"},
									],
								},
								{
									"op": "eq",
									"args": [
										{"ref": {"scope": "subject", "path": ["unknownField"]}},
										{"const": "Y"},
									],
								},
							],
						},
						"predicates": [{"predicate": "true", "type": "rsql"}],
					}],
				},
			},
		},
	}

	subject := {"id": "user1", "roles": ["ROLE_USER"]}
	input_data := {
		"resources": [{"resourceType": "BOTHTEST", "operation": "READ", "resource": {}}],
		"subject": subject,
		"ignoreRls": false,
	}

	result := data.authorize_internals.authorization_evaluation
		with input as input_data
		with data.pips as pip_config with data.m2m as m2m_token
		with data.policies as policies
		with data.authorize_internals.authenticated_subject as subject

	count(result.results) == 1
	decision := result.results[0]
	decision.isAllowed == false

	contains(decision.reason, "PIP resolution failed: brokenPip")
	contains(decision.reason, "subject attribute not found: unknownField")
}

# ── DENY reason: no extras when subject attr exists ───────────────────────

test_deny_reason_no_extras_when_condition_has_existing_subject_ref if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {"general": {}},
		"activation": {"generalByResourceTypeOperation": {}},
	}

	policies := {
		"ols": {"ORDER": {"READ": ["ROLE_USER"]}},
		"rls": {
			"ORDER": {
				"READ": {
					"ROLE_USER": [{
						"conditionAst": {
							"op": "eq",
							"args": [
								{"ref": {"scope": "resource", "path": ["ownerId"]}},
								{"ref": {"scope": "subject", "path": ["id"]}},
							],
						},
						"predicates": [{"predicate": "ownerId==${subject.id}", "type": "rsql"}],
					}],
				},
			},
		},
	}

	subject := {"id": "user1", "roles": ["ROLE_USER"]}
	input_data := {
		"resources": [{"resourceType": "ORDER", "operation": "READ", "resource": {"ownerId": "someone-else"}}],
		"subject": subject,
		"ignoreRls": false,
	}

	result := data.authorize_internals.authorization_evaluation
		with input as input_data
		with data.pips as pip_config with data.m2m as m2m_token
		with data.policies as policies
		with data.authorize_internals.authenticated_subject as subject

	count(result.results) == 1
	decision := result.results[0]
	decision.isAllowed == false

	not contains(decision.reason, "PIP resolution failed")
	not contains(decision.reason, "subject attribute not found")
	contains(decision.reason, "ABAC validations failed")
}

# ── GENERAL PIP jsonPath extraction (D-AF-U) ─────────────────────────────

test_general_pip_jsonpath_extracts_scalar if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityStatus": {
					"name": "subject.parityStatus",
					"alias": "parityStatus",
					"url": "http://pip-mock:8090/api/v1/pip/status-scalar",
					"httpMethod": "POST",
					"response": {"extract": "$.value"},
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityStatus"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": {"value": "ACTIVE"},
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	result.parityStatus == "ACTIVE"
}

test_general_pip_jsonpath_extracts_array if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityIds": {
					"name": "subject.parityIds",
					"alias": "parityIds",
					"url": "http://pip-mock:8090/api/v1/pip/meta",
					"httpMethod": "POST",
					"response": {"extract": "$.ids"},
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityIds"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": {"department": "finance", "ids": ["id-1", "id-2", "id-3"]},
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	result.parityIds == ["id-1", "id-2", "id-3"]
}

test_general_pip_jsonpath_miss_falls_back_to_raw_body if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityMissing": {
					"name": "subject.parityMissing",
					"alias": "parityMissing",
					"url": "http://pip-mock:8090/api/v1/pip/meta",
					"httpMethod": "POST",
					"type": "JSON",
					"jsonPath": "$.not_present",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityMissing"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": {"value": "ACTIVE"},
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	# Fallback: raw body when the jsonPath does not resolve.
	result.parityMissing == {"value": "ACTIVE"}
}

test_general_pip_type_text_returns_raw_body if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityRaw": {
					"name": "subject.parityRaw",
					"alias": "parityRaw",
					"url": "http://pip-mock:8090/api/v1/pip/raw",
					"httpMethod": "POST",
					"type": "TEXT",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityRaw"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": {"value": "ACTIVE"},
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	result.parityRaw == {"value": "ACTIVE"}
}

test_general_pip_type_absent_returns_raw_body if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityLegacy": {
					"name": "subject.parityLegacy",
					"alias": "parityLegacy",
					"url": "http://pip-mock:8090/api/v1/pip/legacy",
					"httpMethod": "GET",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityLegacy"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": ["L1", "L2"],
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	result.parityLegacy == ["L1", "L2"]
}

# D-AF-W item 5a (2026-04-17): an explicit "dict-return without type: JSON"
# case pins the current extraction semantics so future refactors don't
# silently collapse dict bodies into partial extractions when the
# simplified PIP did not opt in to jsonPath extraction.
test_general_pip_dict_return_without_type_returns_raw_dict if {
	pip_config := {
		"local": {"token": {}, "header": {}},
		"remote": {
			"general": {
				"subject.parityDict": {
					"name": "subject.parityDict",
					"alias": "parityDict",
					"url": "http://pip-mock:8090/api/v1/pip/dict",
					"httpMethod": "POST",
				},
			},
		},
		"activation": {
			"generalByResourceTypeOperation": {
				"CUSTOMER": {"READ": ["subject.parityDict"]},
			},
		},
	}

	mock_response := {
		"status_code": 200,
		"body": {"department": "finance", "maxAmount": 1000, "ids": ["D1", "D2"]},
	}

	result := data.pip.resolve_all(
		{"sub": "user1"}, {}, "CUSTOMER", "READ",
	) with data.pips as pip_config with data.m2m as m2m_token with http.send as mock_response

	# No `type` / `jsonPath` declared → subject.parityDict is the raw dict.
	# Any future regression where `extract_general_value` accidentally
	# coerces the dict into a scalar leaf (hypothesis D-AF-W 5a.ii/iii)
	# would flip this assertion.
	result.parityDict == {"department": "finance", "maxAmount": 1000, "ids": ["D1", "D2"]}
}

# ── ADR-0052 caching-off extraction matrix (D-AF-Y 2026-04-18) ───────────
# The following cases pin the canonical predicate-rendering contract for
# GENERAL-PIP array substitution under the caching-free baseline, so a
# future regression that re-introduces cross-request state can't silently
# re-bake cached values into the rendered RSQL. Each test mimics one of
# the three still-red parity leaves on the caching-off baseline
# (`TestRow06CheckFilterV1GeneralPipList`,
# `TestRow10CheckFilterV2GeneralPipList`,
# `TestRow10CheckFilterV2GeneralPipDict`) and asserts that
# `_substitute_predicate` emits the fresh-pin values in array-index
# order with quoted comma-space separators per D-AF-R.

test_pip_general_array_substituted_in_predicate_row06_pattern if {
	enriched := {"parityAllowed": ["row6-list-1", "row6-list-2"], "id": "user1"}
	raw := "id=in=(${subject.parityAllowed})"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	result == `id=in=("row6-list-1", "row6-list-2")`
}

test_pip_general_array_substituted_in_predicate_row10_list_pattern if {
	enriched := {"parityAllowed": ["row10-list-1", "row10-list-2"], "id": "user1"}
	raw := "id=in=(${subject.parityAllowed})"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	result == `id=in=("row10-list-1", "row10-list-2")`
}

test_pip_general_dict_substituted_in_predicate_row10_pattern if {
	enriched := {
		"parityMetaIds": ["row10-dict-1", "row10-dict-2"],
		"parityMetaMaxAmount": 1000,
		"id": "user1",
	}
	raw := "id=in=(${subject.parityMetaIds});amount=le=${subject.parityMetaMaxAmount}"
	result := data.authorize_internals._substitute_predicate(raw, enriched)
	result == `id=in=("row10-dict-1", "row10-dict-2");amount=le="1000"`
}
