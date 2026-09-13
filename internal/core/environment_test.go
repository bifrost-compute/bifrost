package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

// The pinned resolution (#55) round-trips through spec_json like
// ResolvedStorage does, and a spec written before the field existed
// decodes with it nil.
func TestResolvedEnvironmentRoundTripsOnSpecs(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	res := &ResolvedEnvironment{
		Name:           "ml-base",
		BaseImage:      "rayproject/ray:2.9.0",
		RuntimeEnvYaml: "pip:\n- numpy==1.26.4\n",
		ResolvedAt:     &at,
	}
	job := RayJobSpec{Project: "team-a", Entrypoint: "python -c 1", Image: "rayproject/ray:2.9.0", EnvironmentResolved: res}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var out RayJobSpec
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	r := out.EnvironmentResolved
	if r == nil || r.Name != "ml-base" || r.BaseImage != res.BaseImage || r.RuntimeEnvYaml != res.RuntimeEnvYaml ||
		r.ResolvedAt == nil || !r.ResolvedAt.Equal(at) {
		t.Errorf("job environment_resolved did not round-trip: %+v", r)
	}

	cs := ClusterSpec{Name: "c1", Project: "team-a", EnvironmentResolved: res}
	raw, err = json.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	var cout ClusterSpec
	if err := json.Unmarshal(raw, &cout); err != nil {
		t.Fatal(err)
	}
	if cout.EnvironmentResolved == nil || cout.EnvironmentResolved.Name != "ml-base" {
		t.Errorf("cluster environment_resolved did not round-trip: %+v", cout.EnvironmentResolved)
	}

	// A pre-#55 spec (no environment_resolved key) decodes with it nil.
	var legacy RayJobSpec
	if err := json.Unmarshal([]byte(`{"project":"team-a","entrypoint":"python -c 1","image":"rayproject/ray:2.9.0"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.EnvironmentResolved != nil {
		t.Errorf("legacy spec decoded environment_resolved = %+v, want nil", legacy.EnvironmentResolved)
	}
}
