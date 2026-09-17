package core

import (
	"encoding/json"
	"testing"
)

func TestImageEntryMarshalsEmptyProjects(t *testing.T) {
	b, _ := json.Marshal(ImageEntry{Name: "i", Ref: "r", RayVersion: "1"})
	if string(b) != `{"name":"i","description":null,"ref":"r","digest":"","ray_version":"1","python_version":"","projects":[]}` {
		t.Errorf("image entry = %s", b)
	}
}

func TestImageEntryMatchesAndRepository(t *testing.T) {
	d := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	e := ImageEntry{Ref: "localhost:32000/ray/team:2.56.0", Digest: d}
	for img, want := range map[string]bool{
		"localhost:32000/ray/team:2.56.0": true,
		"localhost:32000/ray/team@" + d:   true,
		"localhost:32000/ray/team:2.57.0": false,
		"localhost:32000/ray/team":        false,
		"":                                false,
		"rayproject/ray:2.56.0":           false,
	} {
		if got := e.Matches(img); got != want {
			t.Errorf("Matches(%q) = %v, want %v", img, got, want)
		}
	}
	if e.PinnedRef() != "localhost:32000/ray/team@"+d {
		t.Errorf("PinnedRef = %q", e.PinnedRef())
	}
	unpinned := ImageEntry{Ref: "rayproject/ray:2.56.0"}
	if unpinned.PinnedRef() != "rayproject/ray:2.56.0" || !unpinned.Matches("rayproject/ray:2.56.0") || unpinned.Matches("rayproject/ray@"+d) {
		t.Error("unpinned entry matches its ref only")
	}
	for ref, want := range map[string]string{
		"localhost:32000/ray/team:2.56.0": "localhost:32000/ray/team",
		"rayproject/ray@" + d:             "rayproject/ray",
		"rayproject/ray":                  "rayproject/ray",
		"ghcr.io/x/y:1@" + d:              "ghcr.io/x/y",
	} {
		if got := ImageRepository(ref); got != want {
			t.Errorf("ImageRepository(%q) = %q, want %q", ref, got, want)
		}
	}
}
