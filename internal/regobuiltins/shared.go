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
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
)

// DefaultSharedEntries bounds the answers a [Shared] holds when its limit is
// zero.
const DefaultSharedEntries = 100_000

// Shared keeps the answers of nc.http.send by the cache_key of the request,
// each for TTL after it arrived, across decision requests. Only an answer
// the network gave is kept, whatever its status: a call that failed before
// a response, such as one without the agent's token or one that timed out,
// is sent again by the next decision request. It is safe for concurrent
// use.
type Shared struct {
	ttl   time.Duration
	limit int
	now   func() time.Time

	mu sync.Mutex
	m  map[string]sharedEntry
}

type sharedEntry struct {
	resp *ast.Term
	at   time.Time
}

// NewShared returns an empty cache whose answers live for ttl and which
// holds at most limit of them; a limit of zero or less means
// [DefaultSharedEntries]. A full cache drops its expired answers, and,
// when none has expired, every answer.
func NewShared(ttl time.Duration, limit int) *Shared {
	if limit <= 0 {
		limit = DefaultSharedEntries
	}
	return &Shared{ttl: ttl, limit: limit, now: time.Now, m: map[string]sharedEntry{}}
}

func (s *Shared) get(key string) (*ast.Term, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return nil, false
	}
	if s.now().Sub(e.at) >= s.ttl {
		delete(s.m, key)
		return nil, false
	}
	return e.resp, true
}

func (s *Shared) put(key string, resp *ast.Term) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, ok := s.m[key]; !ok && len(s.m) >= s.limit {
		for k, e := range s.m {
			if now.Sub(e.at) >= s.ttl {
				delete(s.m, k)
			}
		}
		if len(s.m) >= s.limit {
			clear(s.m)
		}
	}
	s.m[key] = sharedEntry{resp: resp, at: now}
}
