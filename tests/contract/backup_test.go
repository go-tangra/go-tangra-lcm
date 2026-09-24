package contract

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-tangra/go-tangra-lcm/v4/api/schema"
)

// TestBackupSchemaValid proves the embedded backup schema compiles and accepts
// a minimal valid document and rejects a bad one.
func TestBackupSchemaValid(t *testing.T) {
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(strings_NewReader(string(schema.Backup)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("backup.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("backup.json")
	if err != nil {
		t.Fatalf("schema does not compile: %v", err)
	}
	good := mustJSON(t, `{"version":1,"exported_at":"2026-01-01T00:00:00Z","tenant":"t","issuers":[],"certificates":[],"permissions":[]}`)
	if err := sch.Validate(good); err != nil {
		t.Errorf("valid document rejected: %v", err)
	}
	bad := mustJSON(t, `{"version":2,"exported_at":"x","tenant":"t","issuers":[],"certificates":[],"permissions":[]}`)
	if err := sch.Validate(bad); err == nil {
		t.Error("version 2 accepted")
	}
}
