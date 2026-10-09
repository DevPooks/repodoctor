package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DevPooks/repodoctor/internal/model"
)

func TestJSONHasStableSchemaFields(t *testing.T) {
	value := model.Report{SchemaVersion: "1.0", Repository: "/repo", Findings: []model.Finding{}}
	var output bytes.Buffer
	if err := JSON(&output, value); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "repository", "summary", "findings", "vulnerability_lookup"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing JSON key %s", key)
		}
	}
}
