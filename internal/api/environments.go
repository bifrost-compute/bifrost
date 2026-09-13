// Environment catalog (#52): named, governed compute environments — base
// image, pinned packages, env vars — a job or cluster spec refers to by
// name (`RayJobSpec.environment`, `ClusterSpec.environment`; both inert
// here: accepted and stored, resolution arrives with the catalog issues
// #54/#55). The catalog rides the policy row like the profile (#7) and
// storage (#12) catalogs; this file is the read side (list_environments,
// mirroring profiles.go) and the wire<->core conversion and validation
// settings.go's policy PUT runs on the `environments` section.
package api

import (
	"context"
	"fmt"
	"regexp"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/core"
)

// environmentNameRe is the contract's RFC 1123 label pattern for
// EnvironmentSpec.name, restated here so the seed path (which never passes
// the request-validation middleware) enforces it identically.
var environmentNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ListEnvironments lists the environments the caller may use: the same
// gate and the same per-project narrowing as ListProfiles — a
// project-scoped caller sees the environments open to every project plus
// those naming one of theirs; admins and global roles see the whole
// catalog. The catalog is `[]`, never `null`, when empty.
func (s *Server) ListEnvironments(ctx context.Context, _ ListEnvironmentsRequestObject) (ListEnvironmentsResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	out := make([]EnvironmentSpec, 0)
	if p == nil {
		return ListEnvironments200JSONResponse(out), nil
	}
	_, projects := readScope(ctx, s.Store, identity)
	for i := range p.Environments {
		env := &p.Environments[i]
		if len(projects) > 0 && !environmentOpenToAny(env, projects) {
			continue
		}
		out = append(out, environmentToWire(env))
	}
	return ListEnvironments200JSONResponse(out), nil
}

// environmentOpenToAny reports whether e is visible to a caller holding
// projects: every caller when e.Projects is empty, else only those naming
// one of the caller's projects.
func environmentOpenToAny(e *core.Environment, projects []string) bool {
	if len(e.Projects) == 0 {
		return true
	}
	for _, proj := range projects {
		if containsString(e.Projects, proj) {
			return true
		}
	}
	return false
}

func environmentToWire(e *core.Environment) EnvironmentSpec {
	packages := make([]string, len(e.Packages))
	copy(packages, e.Packages)
	projects := make([]string, len(e.Projects))
	copy(projects, e.Projects)
	envVars := make(map[string]string, len(e.EnvVars))
	for k, v := range e.EnvVars {
		envVars[k] = v
	}
	status := EnvironmentSpecStatus(e.Status.OrDefault())
	out := EnvironmentSpec{
		Name:        e.Name,
		Description: e.Description,
		Packages:    &packages,
		Projects:    &projects,
		EnvVars:     &envVars,
		Status:      &status,
		PublishedBy: e.PublishedBy,
		PublishedAt: e.PublishedAt,
	}
	if e.BaseImage != "" {
		out.BaseImage = &e.BaseImage
	}
	if e.RuntimeEnvYaml != "" {
		out.RuntimeEnvYaml = &e.RuntimeEnvYaml
	}
	if e.Scan != nil {
		out.Scan = &EnvironmentScan{
			Status:    EnvironmentScanStatus(e.Scan.Status),
			Scanner:   e.Scan.Scanner,
			ScannedAt: e.Scan.ScannedAt,
		}
	}
	return out
}

// environmentsToWire never returns nil: the contract's catalog is `[]`,
// not `null`, when empty.
func environmentsToWire(in []core.Environment) []EnvironmentSpec {
	out := make([]EnvironmentSpec, 0, len(in))
	for i := range in {
		out = append(out, environmentToWire(&in[i]))
	}
	return out
}

// environmentsFromWire converts an incoming environment catalog and
// validates it as a unit — like profilesFromWire, the edit is refused with
// a precise 400 rather than every later resolution failing on a fault the
// administrator could have been told about at the edit. Checks: unique
// RFC 1123 names; every package pinned to an exact version (the same
// pinnedPackageRe the #53 validator enforces); the runtime_env_yaml escape
// hatch passing the governed default validator; non-empty project and
// env-var names; known status/scan-status values (the generated types are
// plain strings, and the seed path never passes the validation middleware).
func environmentsFromWire(in []EnvironmentSpec) ([]core.Environment, error) {
	out := make([]core.Environment, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i := range in {
		w := &in[i]
		what := fmt.Sprintf("invalid environment %q: ", w.Name)
		if w.Name == "" {
			return nil, badRequest(fmt.Sprintf("invalid environment at index %d: name must not be empty", i))
		}
		if !environmentNameRe.MatchString(w.Name) || len(w.Name) > 63 {
			return nil, badRequest(what + "name must be an RFC 1123 label (lowercase alphanumerics and '-', 63 characters at most)")
		}
		if seen[w.Name] {
			return nil, badRequest(what + "duplicate name")
		}
		seen[w.Name] = true
		e := core.Environment{
			Name:        w.Name,
			Description: w.Description,
			Status:      core.EnvironmentStatusDraft,
			PublishedBy: w.PublishedBy,
			PublishedAt: w.PublishedAt,
		}
		if w.Status != nil {
			if !w.Status.Valid() {
				return nil, badRequest(what + fmt.Sprintf("status %q is not one of draft, published, deprecated", string(*w.Status)))
			}
			e.Status = core.EnvironmentStatus(*w.Status)
		}
		if w.BaseImage != nil {
			e.BaseImage = *w.BaseImage
		}
		if w.Packages != nil {
			for _, pkg := range *w.Packages {
				if !pinnedPackageRe.MatchString(pkg) {
					return nil, badRequest(what + fmt.Sprintf("packages entry %q is not pinned to an exact version (name[extras]==version); an unpinned entry installs whatever an index serves", pkg))
				}
			}
			e.Packages = append([]string(nil), (*w.Packages)...)
		}
		if w.EnvVars != nil {
			for k := range *w.EnvVars {
				if k == "" {
					return nil, badRequest(what + "env_vars must not contain an empty variable name")
				}
			}
			e.EnvVars = make(map[string]string, len(*w.EnvVars))
			for k, v := range *w.EnvVars {
				e.EnvVars[k] = v
			}
		}
		if w.RuntimeEnvYaml != nil && *w.RuntimeEnvYaml != "" {
			if err := (RuntimeEnvPolicy{}).Validate(*w.RuntimeEnvYaml); err != nil {
				return nil, badRequest(what + "runtime_env_yaml: " + err.Error())
			}
			e.RuntimeEnvYaml = *w.RuntimeEnvYaml
		}
		if w.Projects != nil {
			for _, proj := range *w.Projects {
				if proj == "" {
					return nil, badRequest(what + "projects must not contain an empty name")
				}
			}
			e.Projects = append([]string(nil), (*w.Projects)...)
		}
		if w.Scan != nil {
			if !w.Scan.Status.Valid() {
				return nil, badRequest(what + fmt.Sprintf("scan status %q is not one of clean, failed, pending", string(w.Scan.Status)))
			}
			e.Scan = &core.EnvironmentScan{
				Status:    core.EnvironmentScanStatus(w.Scan.Status),
				Scanner:   w.Scan.Scanner,
				ScannedAt: w.Scan.ScannedAt,
			}
		}
		out = append(out, e)
	}
	return out, nil
}
