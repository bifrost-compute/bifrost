// Image catalog (requirements 7 and 10): administrator-vetted image
// references with their engine and Ray version spelled out, listed to
// clients filtered by project, enforced by the per-project `catalog_only`
// admission rule, and inspected straight from the registry — manifest,
// config, per-layer build history — without pulling. The catalog rides
// the policy row (settings.go: PUT /settings/policy `images` section).
package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/registry"
)

// openToAny reports whether an entry scoped to entryProjects (empty =
// every project) is open to at least one of the caller's projects.
func openToAny(entryProjects, callers []string) bool {
	if len(entryProjects) == 0 {
		return true
	}
	for _, proj := range callers {
		if containsString(entryProjects, proj) {
			return true
		}
	}
	return false
}

// availableTo reports whether project may use an entry scoped to
// entryProjects (empty = every project).
func availableTo(entryProjects []string, project string) bool {
	return len(entryProjects) == 0 || containsString(entryProjects, project)
}

// defaultRegistry is the anonymous registry client used when a Server is
// built without one (Images == nil): public registries, loopback
// registries over plain HTTP, and any registry that issues anonymous pull
// tokens.
var defaultRegistry = registry.New(nil)

func (s *Server) imageInspector() *registry.Client {
	if s.Images != nil {
		return s.Images
	}
	return defaultRegistry
}

// ListImages lists the catalog entries the caller may use — the same gate
// and project narrowing as list_profiles and list_environments.
func (s *Server) ListImages(ctx context.Context, _ ListImagesRequestObject) (ListImagesResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	out := make([]ImageEntry, 0)
	if p == nil {
		return ListImages200JSONResponse(out), nil
	}
	_, projects := readScope(ctx, s.Store, identity)
	for i := range p.Images {
		e := &p.Images[i]
		if len(projects) > 0 && !openToAny(e.Projects, projects) {
			continue
		}
		out = append(out, imageEntryToWire(e))
	}
	return ListImages200JSONResponse(out), nil
}

// InspectImage describes a catalog entry from its registry. 404 for a
// name the catalog lacks or one not open to the caller's projects (they
// never learn it exists, the tenant-read rule); 502 when the registry
// cannot be read. A pinned entry is inspected at its digest, an unpinned
// one at whatever the tag serves now.
func (s *Server) InspectImage(ctx context.Context, req InspectImageRequestObject) (InspectImageResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	var entry *core.ImageEntry
	if p != nil {
		for i := range p.Images {
			if p.Images[i].Name == req.Name {
				entry = &p.Images[i]
				break
			}
		}
	}
	_, projects := readScope(ctx, s.Store, identity)
	if entry == nil || (len(projects) > 0 && !openToAny(entry.Projects, projects)) {
		return nil, notFound("no such image: " + req.Name)
	}
	doc, err := s.imageInspector().Inspect(ctx, entry.PinnedRef())
	if err != nil {
		return nil, HTTPError{Status: http.StatusBadGateway, Code: "registry_error", Message: "inspect " + entry.Ref + ": " + err.Error()}
	}
	return InspectImage200JSONResponse(inspectToWire(doc)), nil
}

func inspectToWire(d *registry.Inspect) ImageInspect {
	out := ImageInspect{
		Reference: d.Reference,
		Digest:    d.Digest,
		SizeBytes: d.SizeBytes,
		Source:    "registry",
		Platforms: make([]ImagePlatform, 0, len(d.Platforms)),
		History:   make([]ImageHistoryEntry, 0, len(d.History)),
		Layers:    make([]ImageLayer, 0, len(d.Layers)),
		Config: ImageConfig{
			Env:          nonNilStringMap(d.Config.Env),
			Entrypoint:   nonNilStrings(d.Config.Entrypoint),
			Cmd:          nonNilStrings(d.Config.Cmd),
			User:         d.Config.User,
			WorkingDir:   d.Config.WorkingDir,
			ExposedPorts: nonNilStrings(d.Config.ExposedPorts),
			Labels:       nonNilStringMap(d.Config.Labels),
		},
	}
	for _, p := range d.Platforms {
		out.Platforms = append(out.Platforms, ImagePlatform{Os: p.OS, Architecture: p.Architecture, Variant: strPtrOrNil(p.Variant)})
	}
	for _, h := range d.History {
		e := ImageHistoryEntry{CreatedBy: h.CreatedBy, EmptyLayer: h.EmptyLayer, Created: strPtrOrNil(h.Created), Comment: strPtrOrNil(h.Comment)}
		if !h.EmptyLayer && h.LayerDigest != "" {
			digest, size := h.LayerDigest, h.SizeBytes
			e.LayerDigest, e.SizeBytes = &digest, &size
		}
		out.History = append(out.History, e)
	}
	for _, l := range d.Layers {
		out.Layers = append(out.Layers, ImageLayer{Digest: l.Digest, MediaType: l.MediaType, SizeBytes: l.SizeBytes})
	}
	return out
}

func nonNilStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}

func imageEntryToWire(e *core.ImageEntry) ImageEntry {
	projects := make([]string, len(e.Projects))
	copy(projects, e.Projects)
	ref, digest, rayVersion, pyVersion := e.Ref, e.Digest, e.RayVersion, e.PythonVersion
	engine := Engine(e.EngineOrDefault())
	return ImageEntry{
		Name:          e.Name,
		Description:   e.Description,
		Ref:           ref,
		Digest:        &digest,
		Engine:        &engine,
		RayVersion:    &rayVersion,
		PythonVersion: &pyVersion,
		Projects:      &projects,
	}
}

// imagesToWire never returns nil: the contract's catalog is `[]`, not
// `null`, when empty.
func imagesToWire(in []core.ImageEntry) []ImageEntry {
	out := make([]ImageEntry, 0, len(in))
	for i := range in {
		out = append(out, imageEntryToWire(&in[i]))
	}
	return out
}

// imagesFromWire converts an incoming catalog and validates it as a unit:
// unique non-empty names, a reference that parses, a well-formed digest
// when pinned (and not doubled up with a `@digest` in ref), a known
// engine, a ray_version for every Ray image (the whole point: never
// guessed from the tag again), non-empty project names.
func imagesFromWire(in []ImageEntry) ([]core.ImageEntry, error) {
	out := make([]core.ImageEntry, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i := range in {
		w := &in[i]
		what := fmt.Sprintf("invalid image %q: ", w.Name)
		if w.Name == "" {
			return nil, badRequest(fmt.Sprintf("invalid image at index %d: name must not be empty", i))
		}
		if seen[w.Name] {
			return nil, badRequest(what + "duplicate name")
		}
		seen[w.Name] = true
		if w.Ref == "" {
			return nil, badRequest(what + "ref must not be empty")
		}
		ref, err := registry.Parse(w.Ref)
		if err != nil {
			return nil, badRequest(what + "ref: " + err.Error())
		}
		e := core.ImageEntry{Name: w.Name, Description: w.Description, Ref: w.Ref}
		if w.Digest != nil && *w.Digest != "" {
			if !registry.ValidDigest(*w.Digest) {
				return nil, badRequest(what + "digest must be sha256: followed by 64 hex characters")
			}
			if ref.Digest != "" && ref.Digest != *w.Digest {
				return nil, badRequest(what + "ref carries a different digest than the digest field")
			}
			e.Digest = *w.Digest
		} else if ref.Digest != "" {
			e.Digest = ref.Digest
		}
		e.Engine = core.DefaultEngine
		if w.Engine != nil {
			switch *w.Engine {
			case Ray:
				e.Engine = core.EngineRay
			case Dask:
				e.Engine = core.EngineDask
			default:
				return nil, badRequest(fmt.Sprintf("%sinvalid engine %q", what, string(*w.Engine)))
			}
		}
		if w.RayVersion != nil {
			e.RayVersion = *w.RayVersion
		}
		if e.Engine == core.EngineRay && e.RayVersion == "" {
			return nil, badRequest(what + "ray_version must not be empty for a ray image")
		}
		if w.PythonVersion != nil {
			e.PythonVersion = *w.PythonVersion
		}
		if w.Projects != nil {
			for _, proj := range *w.Projects {
				if proj == "" {
					return nil, badRequest(what + "projects must not contain an empty name")
				}
			}
			e.Projects = append([]string(nil), (*w.Projects)...)
		}
		out = append(out, e)
	}
	return out, nil
}

// imagesAvailableTo is the slice of the catalog project may use.
func imagesAvailableTo(catalog []core.ImageEntry, project string) []core.ImageEntry {
	var out []core.ImageEntry
	for i := range catalog {
		if availableTo(catalog[i].Projects, project) {
			out = append(out, catalog[i])
		}
	}
	return out
}
