// Package schema embeds the tenant backup document schema.
package schema

import _ "embed"

// Backup is the JSON Schema for lcm tenant backup export/import documents.
//
//go:embed backup.schema.json
var Backup []byte
