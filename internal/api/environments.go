// Environment catalog (#52): named, governed compute environments — base
// image, pinned packages, env vars — a job or cluster spec refers to by
// name (`RayJobSpec.environment`, `ClusterSpec.environment`). The catalog
// rides the policy row like the profile (#7) and storage (#12) catalogs;
// this file is the read side (list_environments, mirroring profiles.go),
// the wire<->core conversion and validation settings.go's policy PUT runs
// on the `environments` section, and the resolution (#55) finishJobSpec and
// CreateCluster run when a spec names an environment.
package api

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
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
			if err := environmentEscapeHatchDisjoint(e, *w.RuntimeEnvYaml); err != nil {
				return nil, badRequest(what + err.Error())
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

// environmentEscapeHatchDisjoint refuses the one ambiguity an environment
// definition can carry: the structured fields (packages, env_vars) and the
// runtime_env_yaml escape hatch both fixing the same thing. The catalog is
// validated at the edit (the storage/profile rule), so the overlap is a
// 400 here rather than a silently-arbitrary merge winner at every later
// resolution. pip overlaps when packages is non-empty and the hatch sets
// pip at all; env_vars overlaps per key.
func environmentEscapeHatchDisjoint(e core.Environment, hatch string) error {
	var doc map[string]interface{}
	if err := yaml.NewDecoder(strings.NewReader(hatch)).Decode(&doc); err != nil {
		return fmt.Errorf("runtime_env_yaml is not a valid YAML mapping: %v", err)
	}
	if len(e.Packages) > 0 {
		if _, dup := doc["pip"]; dup {
			return fmt.Errorf("runtime_env_yaml sets pip while packages is non-empty; fix the package list in one place, not both")
		}
	}
	if hatchVars, ok := doc["env_vars"].(map[string]interface{}); ok {
		for k := range hatchVars {
			if _, dup := e.EnvVars[k]; dup {
				return fmt.Errorf("runtime_env_yaml env_vars[%q] duplicates env_vars[%q]; fix the variable in one place, not both", k, k)
			}
		}
	}
	return nil
}

// environmentAvailableTo reports whether project may reference e: an empty
// project list means every project (storageAvailableTo's rule).
func environmentAvailableTo(e *core.Environment, project string) bool {
	if len(e.Projects) == 0 {
		return true
	}
	return containsString(e.Projects, project)
}

// compileEnvironment renders e into the governed runtime_env YAML document
// a reference resolves to (#55): packages become the pip list, env_vars the
// env_vars mapping, and the runtime_env_yaml escape hatch merges in the
// fields the structured form cannot express (working_dir, py_modules,
// config — and pip/env_vars only where the structured fields leave them
// unset, an overlap the catalog edit refuses). Should a catalog row carry
// an overlap anyway (a hand-written policy seed never passed the edit
// validation), the structured field wins: packages override the hatch's
// pip, env_vars override its env_vars per key. "" when the environment
// carries no runtime env at all.
func compileEnvironment(e *core.Environment) (string, error) {
	doc := map[string]interface{}{}
	if strings.TrimSpace(e.RuntimeEnvYaml) != "" {
		if err := yaml.NewDecoder(strings.NewReader(e.RuntimeEnvYaml)).Decode(&doc); err != nil {
			return "", fmt.Errorf("environment %q runtime_env_yaml is not a valid YAML mapping: %v", e.Name, err)
		}
	}
	if len(e.Packages) > 0 {
		pip := make([]interface{}, len(e.Packages))
		for i, pkg := range e.Packages {
			pip[i] = pkg
		}
		doc["pip"] = pip
	}
	if len(e.EnvVars) > 0 {
		vars, _ := doc["env_vars"].(map[string]interface{})
		if vars == nil {
			vars = make(map[string]interface{}, len(e.EnvVars))
		}
		for k, v := range e.EnvVars {
			vars[k] = v
		}
		doc["env_vars"] = vars
	}
	if len(doc) == 0 {
		return "", nil
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("environment %q does not compile: %v", e.Name, err)
	}
	return string(out), nil
}

// resolveEnvironment resolves name against the effective policy's
// environment catalog for project (#55), mirroring resolveStorage: an
// unknown name, an entry the project may not use, or an entry that is not
// published (a draft is not selectable yet; a deprecated one stays
// resolvable for already-admitted specs but takes no new references) is a
// 400, never a workload that silently runs without its environment. The
// environment's base image fills *image the way a profile's image fills the
// shape (plan ruling D4): an empty *image takes it, a differing one is the
// whole-or-nothing conflict 400; the admission image allowlist then applies
// to it as to any spec image. The compiled runtime_env passes the same
// governance validation a hand-written runtime_env_yaml gets — under the
// project's admission-rule knobs — before the resolution is returned.
// Store failures surface as 5xx through wrapStoreErr.
func (s *Server) resolveEnvironment(ctx context.Context, project, name string, image *string) (*core.ResolvedEnvironment, error) {
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	var env *core.Environment
	if p != nil {
		for i := range p.Environments {
			if p.Environments[i].Name == name {
				env = &p.Environments[i]
				break
			}
		}
	}
	if env == nil {
		return nil, badRequest(fmt.Sprintf("no such environment %q", name))
	}
	if !environmentAvailableTo(env, project) {
		return nil, badRequest(fmt.Sprintf("environment %q is not available to project %q", name, project))
	}
	switch env.Status.OrDefault() {
	case core.EnvironmentStatusPublished:
	case core.EnvironmentStatusDraft:
		return nil, badRequest(fmt.Sprintf("environment %q is a draft; only published environments can be referenced", name))
	default:
		return nil, badRequest(fmt.Sprintf("environment %q is deprecated; stored resolutions keep working but new references are refused", name))
	}
	if env.BaseImage != "" {
		switch {
		case *image == "":
			*image = env.BaseImage
		case *image != env.BaseImage:
			return nil, badRequest(fmt.Sprintf("environment %q fixes image %q; leave image empty or omit the environment", name, env.BaseImage))
		}
	}
	compiled, err := compileEnvironment(env)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	if !s.RuntimeEnvUngoverned {
		pol, perr := s.runtimeEnvPolicyFor(ctx, project)
		if perr != nil {
			return nil, wrapStoreErr(perr)
		}
		if verr := pol.Validate(compiled); verr != nil {
			return nil, badRequest(fmt.Sprintf("environment %q compiles to a runtime_env the platform rule set refuses: %v", name, verr))
		}
		// #56: the pinned resolution carries the bounded setup timeout too —
		// a cluster's pinned default and a job's compiled document both.
		compiled, err = pol.EnforceSetupTimeout(compiled)
		if err != nil {
			return nil, badRequest(err.Error())
		}
	}
	at := time.Unix(int64(controller.NowUnix()), 0).UTC()
	return &core.ResolvedEnvironment{
		Name:           env.Name,
		BaseImage:      env.BaseImage,
		RuntimeEnvYaml: compiled,
		ResolvedAt:     &at,
	}, nil
}
