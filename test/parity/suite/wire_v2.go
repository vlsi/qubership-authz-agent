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

package paritysuite

import (
	"context"
	"net/http"
	"net/url"

	"authz-agent/test/parity/suite/model"
)

// v2 path templates — hard-coded against AbstractRemoteACCommon (v2):18-27.
const (
	v2PathCheckResource               = "/access/v2/check/resource"
	v2PathCheckResourceBulkOperations = "/access/v2/check/resource/bulk/operations"
	v2PathCheckFilter                 = "/access/v2/check/filter"
	v2PathPreviewBulkOperations       = "/preview/v2/check/resource/bulk/operations"
)

// v2Flags carries the per-call flag decisions. Parity always sends
// obligations=false per D-E; Preview toggles the path template between
// /access/v2 and /preview/v2 (Flags.withPreview() — AbstractRemoteACCommon
// (v2):45-61).
type v2Flags struct {
	Preview bool
}

// v2QueryExtra returns the query params v2 helpers append on top of
// tenant_id + optional userId. obligations=false is unconditional per D-E
// / D-V item 9.
func v2QueryExtra() url.Values {
	extra := url.Values{}
	extra.Set("obligations", "false")
	return extra
}

// HelperCheckResourceV2 drives parity-contract row 7
// (POST /access/v2/check/resource). Parity suite never uses the preview
// path for row 7; rows 5/9 that need preview use the bulk helpers instead.
func HelperCheckResourceV2(ctx context.Context, cfg Config, body model.CheckResourceRequest, tokens TokenBundle, opts PerCallOptions) (int, model.CheckResourceResponse, []byte, error) {
	target := buildURL(cfg.ACBaseURL, v2PathCheckResource, buildQuery(cfg, opts, v2QueryExtra()))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, model.CheckResourceResponse{}, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, model.CheckResourceResponse{}, raw, err
	}
	var decoded model.CheckResourceResponse
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, decoded, raw, err
	}
	return status, decoded, raw, nil
}

// HelperCheckResourcesV2 drives row 8
// (POST /access/v2/check/resource/bulk/operations). flags.Preview routes to
// row 9's /preview path template instead.
func HelperCheckResourcesV2(ctx context.Context, cfg Config, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions, flags v2Flags) (int, model.CheckResourcesResponse, []byte, error) {
	path := v2PathCheckResourceBulkOperations
	if flags.Preview {
		path = v2PathPreviewBulkOperations
	}
	target := buildURL(cfg.ACBaseURL, path, buildQuery(cfg, opts, v2QueryExtra()))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, model.CheckResourcesResponse{}, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, model.CheckResourcesResponse{}, raw, err
	}
	var decoded model.CheckResourcesResponse
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, decoded, raw, err
	}
	return status, decoded, raw, nil
}

// HelperPreviewCheckResourcesV2 is a thin wrapper that forces
// flags.Preview=true so row 9 tests don't need to remember the flag field.
func HelperPreviewCheckResourcesV2(ctx context.Context, cfg Config, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions) (int, model.CheckResourcesResponse, []byte, error) {
	return HelperCheckResourcesV2(ctx, cfg, body, tokens, opts, v2Flags{Preview: true})
}

// HelperFilterV2 drives row 10 (POST /access/v2/check/filter). Body is
// empty; the query string carries resourceType (required), operation,
// userId, and obligations=false.
func HelperFilterV2(ctx context.Context, cfg Config, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) (int, model.FilterResponse, []byte, error) {
	extra := v2QueryExtra()
	if resourceType != "" {
		extra.Set("resourceType", resourceType)
	}
	if operation != "" {
		extra.Set("operation", operation)
	}
	target := buildURL(cfg.ACBaseURL, v2PathCheckFilter, buildQuery(cfg, opts, extra))
	req, err := buildRequest(ctx, http.MethodPost, target, nil, tokens, opts)
	if err != nil {
		return 0, model.FilterResponse{}, nil, err
	}
	status, raw, err := doRequest(req)
	if err != nil {
		return status, model.FilterResponse{}, raw, err
	}
	var decoded model.FilterResponse
	if err := decodeJSON(raw, &decoded); err != nil {
		return status, decoded, raw, err
	}
	return status, decoded, raw, nil
}

// HelperPostV2 posts body, nil for none, to the v2 path of access-control
// with the tenant, the userId, and the headers of opts and the query
// parameters extra, and returns the status and the raw body without decoding
// it. Unlike the row helpers it sends no obligations parameter of its own:
// extra carries one when the caller wants one.
func HelperPostV2(ctx context.Context, cfg Config, path string, extra url.Values, body any, tokens TokenBundle, opts PerCallOptions) (int, []byte, error) {
	target := buildURL(cfg.ACBaseURL, path, buildQuery(cfg, opts, extra))
	req, err := buildRequest(ctx, http.MethodPost, target, body, tokens, opts)
	if err != nil {
		return 0, nil, err
	}
	return doRequest(req)
}
