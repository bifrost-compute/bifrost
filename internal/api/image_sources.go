package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/registry"
)

// --- Image sources (#10): browse a registry repository for catalog candidates ---
//
// An image source names a registry repository the console may list live,
// so a build pipeline's or Artifact Keeper's pushes appear as a pick-list
// instead of a reference somebody types. Same discipline as the catalog:
// a policy-row section, section-replace, validated as a unit,
// project-scoped reads. A source approves nothing — only a catalog entry
// makes a tag runnable — so browsing is a read the tenant-read rule gates
// like the catalog itself.

// isSourceName reports whether s is usable as a source name: an RFC 1123
// label.
func isSourceName(s string) bool {
	return core.IsK8sName(s) && !strings.Contains(s, ".") && len(s) <= 63
}

// isRepositoryPath reports whether s is a plausible OCI repository path:
// lowercase path components joined by `/`, each of `[a-z0-9]` with
// `._-` separators (the distribution spec's <name> grammar, loosely).
func isRepositoryPath(s string) bool {
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			b := part[i]
			isAlnum := b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
			if !isAlnum && b != '.' && b != '_' && b != '-' {
				return false
			}
		}
		leading := part[0]
		if (leading < 'a' || leading > 'z') && (leading < '0' || leading > '9') {
			return false
		}
	}
	return true
}

func imageSourceToWire(e *core.ImageSource) ImageSource {
	projects := append([]string{}, e.Projects...)
	repo := e.Repository
	return ImageSource{Name: e.Name, Description: e.Description, Registry: e.Registry, Repository: &repo, Projects: &projects}
}

// imageSourcesToWire never returns nil: the contract's list is `[]`.
func imageSourcesToWire(in []core.ImageSource) []ImageSource {
	out := make([]ImageSource, 0, len(in))
	for i := range in {
		out = append(out, imageSourceToWire(&in[i]))
	}
	return out
}

// imageSourcesFromWire converts and validates the section as a unit.
func imageSourcesFromWire(in []ImageSource) ([]core.ImageSource, error) {
	out := make([]core.ImageSource, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i := range in {
		w := &in[i]
		what := fmt.Sprintf("invalid image source %q: ", w.Name)
		if !isSourceName(w.Name) {
			return nil, badRequest(fmt.Sprintf("invalid image source at index %d: name %q must be an RFC 1123 label", i, w.Name))
		}
		if seen[w.Name] {
			return nil, badRequest(what + "duplicate name")
		}
		seen[w.Name] = true
		// The registry is validated by parsing a reference on it: the same
		// grammar image refs use, so `ghcr.io`, `localhost:32000` and a
		// Service address with a port all pass and a URL does not.
		if w.Registry == "" || strings.Contains(w.Registry, "/") || strings.Contains(w.Registry, "://") {
			return nil, badRequest(what + "registry must be a host[:port], not a URL or a path")
		}
		if _, err := registry.Parse(w.Registry + "/probe:latest"); err != nil {
			return nil, badRequest(what + "registry: " + err.Error())
		}
		e := core.ImageSource{Name: w.Name, Description: w.Description, Registry: w.Registry}
		if w.Repository != nil && *w.Repository != "" {
			if !isRepositoryPath(*w.Repository) {
				return nil, badRequest(what + "repository must be a lowercase OCI repository path such as ray/team")
			}
			e.Repository = *w.Repository
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

// ListImageSources lists the sources the caller's projects may browse —
// the same gate and narrowing as the catalog.
func (s *Server) ListImageSources(ctx context.Context, _ ListImageSourcesRequestObject) (ListImageSourcesResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	out := make([]ImageSource, 0)
	if p == nil {
		return ListImageSources200JSONResponse(out), nil
	}
	_, projects := readScope(ctx, s.Store, identity)
	for i := range p.ImageSources {
		e := &p.ImageSources[i]
		if len(projects) > 0 && !openToAny(e.Projects, projects) {
			continue
		}
		out = append(out, imageSourceToWire(e))
	}
	return ListImageSources200JSONResponse(out), nil
}

// ListImageSourceTags reads a source's repositories and tags from its
// registry. 404 for a name the section lacks or one not open to the
// caller's projects; 502 when the registry cannot be read. A source with
// a repository lists that one; without, every repository the catalog
// answers with.
func (s *Server) ListImageSourceTags(ctx context.Context, req ListImageSourceTagsRequestObject) (ListImageSourceTagsResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	var src *core.ImageSource
	if p != nil {
		for i := range p.ImageSources {
			if p.ImageSources[i].Name == req.Name {
				src = &p.ImageSources[i]
				break
			}
		}
	}
	_, projects := readScope(ctx, s.Store, identity)
	if src == nil || (len(projects) > 0 && !openToAny(src.Projects, projects)) {
		return nil, notFound("no such image source: " + req.Name)
	}
	client := s.imageInspector()
	repos := []string{src.Repository}
	if src.Repository == "" {
		repos, err = client.ListRepositories(ctx, src.Registry)
		if err != nil {
			return nil, HTTPError{Status: http.StatusBadGateway, Code: "registry_error", Message: "list repositories on " + src.Registry + ": " + err.Error()}
		}
	}
	out := ImageSourceTags{Name: src.Name, Registry: src.Registry, Repositories: make([]ImageSourceRepository, 0, len(repos))}
	for _, repo := range repos {
		tags, err := client.ListTags(ctx, src.Registry, repo)
		if err != nil {
			return nil, HTTPError{Status: http.StatusBadGateway, Code: "registry_error", Message: "list tags of " + src.Registry + "/" + repo + ": " + err.Error()}
		}
		refs := make([]string, 0, len(tags))
		for _, t := range tags {
			refs = append(refs, src.Registry+"/"+repo+":"+t)
		}
		out.Repositories = append(out.Repositories, ImageSourceRepository{Repository: repo, Tags: tags, Refs: refs})
	}
	return ListImageSourceTags200JSONResponse(out), nil
}
