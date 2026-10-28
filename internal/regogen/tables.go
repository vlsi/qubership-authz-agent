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
	"bytes"
	_ "embed"
	"sync"

	"authz-agent/internal/regogen/spectables"
)

// agentTables is the export of the specification's leaf-outcome tables,
// written by the specification's exporter and copied here unchanged.
//
//go:embed agent-tables.json
var agentTables []byte

var defaultTable = sync.OnceValues(func() (*spectables.Table, error) {
	return spectables.Load(bytes.NewReader(agentTables))
})

// DefaultTable returns the embedded tables, loaded and validated once.
func DefaultTable() (*spectables.Table, error) { return defaultTable() }
