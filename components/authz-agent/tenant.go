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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// tenantLookupPath resolves a tenant's display name to its ID; the
// endpoint answers with the ID as a bare text body.
const tenantLookupPath = "/api/v4/tenant-manager/registration/tenants"

// tenantID is the accepted shape of an ID tenant-manager answers with.
var tenantID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// defaultTenant is the tenant a check request that names none is decided
// in. It starts as the configured display name and becomes the tenant's ID
// once tenant-manager resolves the name; until then a request without a
// tenant is decided in a tenant named by the display name, which the
// export normally does not carry, and is denied.
type defaultTenant struct {
	name    string
	baseURL string
	client  *http.Client
	id      atomic.Pointer[string]
}

func newDefaultTenant(name, tenantManagerURL string) *defaultTenant {
	d := &defaultTenant{name: name, baseURL: strings.TrimRight(strings.TrimSpace(tenantManagerURL), "/"),
		client: &http.Client{Timeout: 10 * time.Second}}
	d.id.Store(&name)
	return d
}

// Get returns the ID of the default tenant, or its display name before it
// is resolved.
func (d *defaultTenant) Get() string { return *d.id.Load() }

// Run resolves the display name every interval until tenant-manager
// answers or ctx ends. Without a tenant-manager URL the name is the ID.
func (d *defaultTenant) Run(ctx context.Context, interval time.Duration) {
	if d.baseURL == "" || d.name == "" {
		return
	}
	reported := false
	for {
		id, err := d.lookup(ctx)
		if err == nil {
			d.id.Store(&id)
			logger.Infof("default tenant: %q resolved to %q via tenant-manager", d.name, id)
			return
		}
		if !reported {
			logger.Warnf("default tenant: %q not resolved via tenant-manager, retrying every %s; "+
				"a check request without tenant_id or Tenant is denied until then: %v", d.name, interval, err)
			reported = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (d *defaultTenant) lookup(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s%s?dns=%s", d.baseURL, tenantLookupPath, url.QueryEscape(d.name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", endpoint, resp.StatusCode)
	}
	id := strings.TrimSpace(string(body))
	if !tenantID.MatchString(id) {
		return "", fmt.Errorf("%s: the answer %.80q is not a tenant ID", endpoint, id)
	}
	return id, nil
}
