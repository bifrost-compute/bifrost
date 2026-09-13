package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// The catalog lists marshal as `[]`/`{}`, never `null`, and the status
// enums reject unknown values like the other strict catalog enums.
func TestEnvironmentMarshalSubstitutesEmptyCollections(t *testing.T) {
	raw, err := json.Marshal(Environment{Name: "ml-base"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"packages":[]`, `"projects":[]`, `"env_vars":{}`} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled %s, want it to contain %s", s, want)
		}
	}
	if strings.Contains(s, `"packages":null`) || strings.Contains(s, `"env_vars":null`) {
		t.Errorf("nil collections must never marshal as null: %s", s)
	}
}

func TestEnvironmentStatusRoundTripAndStrictness(t *testing.T) {
	if (EnvironmentStatus("")).OrDefault() != EnvironmentStatusDraft {
		t.Error("absent status must default to draft")
	}
	var e Environment
	if err := json.Unmarshal([]byte(`{"name":"e","status":"published"}`), &e); err != nil || e.Status != EnvironmentStatusPublished {
		t.Errorf("published: %v %v", e.Status, err)
	}
	if err := json.Unmarshal([]byte(`{"name":"e","status":"bogus"}`), &e); err == nil {
		t.Error("unknown status accepted")
	}
	var sc EnvironmentScan
	if err := json.Unmarshal([]byte(`{"status":"clean"}`), &sc); err != nil || sc.Status != EnvironmentScanClean {
		t.Errorf("clean: %v %v", sc.Status, err)
	}
	if err := json.Unmarshal([]byte(`{"status":"bogus"}`), &sc); err == nil {
		t.Error("unknown scan status accepted")
	}
}
