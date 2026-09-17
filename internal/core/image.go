package core

import (
	"encoding/json"
	"strings"
)

// --- Image catalog (#7, #10) ---

// ImageEntry is a catalog entry for an approved container image: a
// reference an administrator has vetted, with what a scheduler needs to
// know about it (engine, Ray version) spelled out instead of guessed from
// the tag. Specs keep carrying `image` as a string; the catalog pins what
// that string may be when a project's admission rule says catalog_only,
// and fills ray_version when a spec leaves it empty.
type ImageEntry struct {
	// Name is the catalog name clients show and pick.
	Name string `json:"name"`
	// Description is a human-readable summary shown by clients; nil = none.
	Description *string `json:"description"`
	// Ref is the image reference the pods run: `registry/repo:tag` or
	// `registry/repo@sha256:…`.
	Ref string `json:"ref"`
	// Digest is the manifest digest Ref is pinned to, `sha256:…`; "" =
	// unpinned (the tag is followed).
	Digest string `json:"digest"`
	// Engine is the compute engine the image carries; absent in JSON =
	// ray.
	Engine Engine `json:"engine,omitempty"`
	// RayVersion is the Ray version inside the image (ray engine only).
	RayVersion string `json:"ray_version"`
	// PythonVersion is the interpreter version inside the image, for
	// clients matching a notebook kernel; "" = unknown.
	PythonVersion string `json:"python_version"`
	// Projects that may use this image; empty = every project.
	Projects []string `json:"projects"`
}

// imageEntryAlias breaks the recursion MarshalJSON would otherwise cause
// by re-entering ImageEntry's own MarshalJSON.
type imageEntryAlias ImageEntry

// MarshalJSON substitutes an empty slice for a nil Projects (nil is not a
// valid Vec: `[]`, never `null`).
func (e ImageEntry) MarshalJSON() ([]byte, error) {
	a := imageEntryAlias(e)
	if a.Projects == nil {
		a.Projects = []string{}
	}
	return json.Marshal(a)
}

// EngineOrDefault is the entry's engine, Ray when unset.
func (e ImageEntry) EngineOrDefault() Engine {
	if e.Engine == "" {
		return DefaultEngine
	}
	return e.Engine
}

// Matches reports whether image (a spec's image string) is this entry:
// the exact Ref, or — when the entry is pinned — the Ref's repository at
// the pinned digest. A spec's tag never matches an entry's different tag;
// what runs is exactly what the administrator vetted.
func (e ImageEntry) Matches(image string) bool {
	if image == "" {
		return false
	}
	if image == e.Ref {
		return true
	}
	if e.Digest != "" && image == ImageRepository(e.Ref)+"@"+e.Digest {
		return true
	}
	return false
}

// PinnedRef is the reference clients should send: `repo@digest` when the
// entry is pinned, else Ref.
func (e ImageEntry) PinnedRef() string {
	if e.Digest != "" {
		return ImageRepository(e.Ref) + "@" + e.Digest
	}
	return e.Ref
}

// ImageRepository strips the tag and/or digest from an image reference,
// leaving `registry/repo`. A `:` in the last path component is a tag; a
// `:` before the first `/` is a registry port and left alone.
func ImageRepository(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndexByte(ref, '/')
	if colon := strings.LastIndexByte(ref, ':'); colon > slash {
		ref = ref[:colon]
	}
	return ref
}
