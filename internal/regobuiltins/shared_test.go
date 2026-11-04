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
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
)

func clockedShared(ttl time.Duration, limit int) (*Shared, *time.Time) {
	s := NewShared(ttl, limit)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestShared_AnAnswerLivesForTheTTL(t *testing.T) {
	s, now := clockedShared(time.Minute, 0)
	s.put("k", ast.StringTerm("a"))

	*now = now.Add(time.Minute - time.Nanosecond)
	if got, ok := s.get("k"); !ok || !got.Equal(ast.StringTerm("a")) {
		t.Errorf("get just before the TTL = %v, %t; want \"a\", true", got, ok)
	}
	*now = now.Add(time.Nanosecond)
	if got, ok := s.get("k"); ok {
		t.Errorf("get at the TTL = %v, true; want no answer", got)
	}
}

// A full cache first drops its expired answers, and keeps the live ones
// when that makes room.
func TestShared_AFullCacheDropsExpiredAnswersFirst(t *testing.T) {
	s, now := clockedShared(time.Minute, 2)
	s.put("old", ast.StringTerm("o"))
	*now = now.Add(time.Minute)
	s.put("live", ast.StringTerm("l"))
	s.put("new", ast.StringTerm("n"))

	for _, k := range []string{"live", "new"} {
		if _, ok := s.get(k); !ok {
			t.Errorf("get(%s) after an expired answer was dropped: no answer, want one", k)
		}
	}
}

// A full cache with no expired answer drops all of them.
func TestShared_AFullCacheOfLiveAnswersStartsOver(t *testing.T) {
	s, _ := clockedShared(time.Minute, 2)
	s.put("a", ast.StringTerm("a"))
	s.put("b", ast.StringTerm("b"))
	s.put("c", ast.StringTerm("c"))

	got := map[string]bool{}
	for _, k := range []string{"a", "b", "c"} {
		_, got[k] = s.get(k)
	}
	if want := map[string]bool{"a": false, "b": false, "c": true}; !mapsEqual(got, want) {
		t.Errorf("answers kept = %v, want %v", got, want)
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
