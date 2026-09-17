// Settings API (api-v1.md §5.16): the store-backed, API-editable governance
// policy — price sheet (cost estimates), per-project quota limits,
// per-project time-windowed budgets, and (plan ruling D7) the profile,
// admission and private-storage catalogs. Ported from the Rust predecessor's settings.rs.
//
// Precedence: the `--policy` boot-time seed is the DEFAULT; the store wins
// once a row exists (seeded lazily on first read, or written by PUT).
// Handlers read the effective policy per request via effectivePolicy, so
// edits apply without a restart. Both routes are Admin-only (governance is
// platform configuration, like pools); the permission target is
// auth.TargetCluster (same convention as the registry/access surfaces).
package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
)

// PolicyConfig is the boot-time `--policy` seed (the Rust predecessor's clusters.rs
// PolicyConfig) — NOT the effective policy. Handlers load the effective
// (store-backed) policy per request via effectivePolicy; this value is
// consulted only until the store holds a policy row.
//
// GPUDefaultSharing (#58) is different: it is boot-time config only, never
// seeded into the store — the per-pool gpu_sharing knob is the
// tenant-visible override, and this is just the platform-wide fallback when
// a pool spec leaves it unset.
type PolicyConfig struct {
	Prices  policy.PriceSheet
	Quotas  map[string]policy.ResourceMap
	Budgets map[string]policy.Budget
	// Profiles is the profile catalog seed (requirement 7, plan ruling
	// D7): named cluster shapes a spec picks by name (`--profiles`).
	Profiles []core.Profile
	// Admission maps project (or "*" for every project) to its admission
	// limits (requirement 7). The `--allowed-images`/`--max-workers` flags
	// arrive here as the "*" rule (Admission.SeedRules), so a deployment
	// that never touches the policy API keeps exactly its old behaviour
	// while an administrator can tighten one project via PUT.
	Admission map[string]core.AdmissionRule
	// Environments is the environment catalog seed (#52): named governed
	// environments a spec may refer to, riding the policy row like the
	// profile and storage catalogs.
	Environments []core.Environment
	// GPUDefaultSharing defaults to core.DefaultGpuSharing (whole-gpu) at
	// the zero value only when read through EffectiveGPUDefaultSharing —
	// a bare PolicyConfig{} leaves this "" (core.GpuSharing's zero value),
	// which is deliberately not core.DefaultGpuSharing so a caller that
	// forgets to set it fails the isValid() check rather than silently
	// picking a default with no seam to override it.
	GPUDefaultSharing core.GpuSharing
}

// EffectiveGPUDefaultSharing returns c.GPUDefaultSharing, or
// core.DefaultGpuSharing when unset — the platform-wide GPU-sharing
// fallback pools without an explicit gpu_sharing resolve to (#58).
func (c PolicyConfig) EffectiveGPUDefaultSharing() core.GpuSharing {
	if c.GPUDefaultSharing == "" {
		return core.DefaultGpuSharing
	}
	return c.GPUDefaultSharing
}

// seedFromConfig converts the in-flight PolicyConfig seed into a storable
// row, or nil when the seed is empty (no --policy given) — an empty seed
// never materializes a row, so source stays "none". Ported from settings.rs's
// seed_from_config.
func seedFromConfig(cfg *PolicyConfig) *controller.StoredPolicy {
	if cfg.Prices == nil && len(cfg.Quotas) == 0 && len(cfg.Budgets) == 0 &&
		len(cfg.Profiles) == 0 && len(cfg.Admission) == 0 && len(cfg.Environments) == 0 {
		return nil
	}
	quotas := make(map[string]map[string]float64, len(cfg.Quotas))
	for k, v := range cfg.Quotas {
		quotas[k] = map[string]float64(v)
	}
	budgets := make(map[string]controller.StoredBudget, len(cfg.Budgets))
	for k, b := range cfg.Budgets {
		budgets[k] = controller.StoredBudget{WindowSecs: b.WindowSecs, Limits: b.Limits}
	}
	var prices map[string]float64
	if cfg.Prices != nil {
		prices = map[string]float64(cfg.Prices)
	}
	return &controller.StoredPolicy{
		Prices:       prices,
		Quotas:       quotas,
		Budgets:      budgets,
		Profiles:     cloneProfiles(cfg.Profiles),
		Admission:    cloneAdmission(cfg.Admission),
		Environments: cloneEnvironments(cfg.Environments),
		FromFileSeed: true,
	}
}

// cloneEnvironments copies the seed's environment catalog the way
// cloneProfiles copies its profile catalog.
func cloneEnvironments(in []core.Environment) []core.Environment {
	if in == nil {
		return nil
	}
	out := make([]core.Environment, len(in))
	copy(out, in)
	return out
}

func cloneProfiles(in []core.Profile) []core.Profile {
	if in == nil {
		return nil
	}
	out := make([]core.Profile, len(in))
	copy(out, in)
	return out
}

func cloneAdmission(in map[string]core.AdmissionRule) map[string]core.AdmissionRule {
	if in == nil {
		return nil
	}
	out := make(map[string]core.AdmissionRule, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// configFromStored converts a stored row back into the in-flight
// PolicyConfig shape the policy package consumes. gpuDefaultSharing is
// boot-time-only config, never part of the stored row (see PolicyConfig's
// doc comment) — callers that need it read it from the seed, not from here.
// Ported from settings.rs's config_from_stored.
func configFromStored(p *controller.StoredPolicy) PolicyConfig {
	quotas := make(map[string]policy.ResourceMap, len(p.Quotas))
	for k, v := range p.Quotas {
		quotas[k] = policy.ResourceMap(v)
	}
	budgets := make(map[string]policy.Budget, len(p.Budgets))
	for k, b := range p.Budgets {
		budgets[k] = policy.Budget{WindowSecs: b.WindowSecs, Limits: b.Limits}
	}
	var prices policy.PriceSheet
	if p.Prices != nil {
		prices = policy.PriceSheet(p.Prices)
	}
	return PolicyConfig{
		Prices:       prices,
		Quotas:       quotas,
		Budgets:      budgets,
		Profiles:     cloneProfiles(p.Profiles),
		Admission:    cloneAdmission(p.Admission),
		Environments: cloneEnvironments(p.Environments),
	}
}

// effectivePolicy is the effective governance policy: the store row when
// one exists (seeded or edited), else the --policy boot seed, which is then
// persisted insert-if-absent so it becomes the row. nil = no policy
// configured at all (no row and an empty seed). Ported from settings.rs's
// effective_policy.
func effectivePolicy(ctx context.Context, store controller.Store, seed *PolicyConfig) (*controller.StoredPolicy, error) {
	if p, err := store.GetPolicy(ctx); err != nil {
		return nil, err
	} else if p != nil {
		return p, nil
	}
	seeded := seedFromConfig(seed)
	if seeded == nil {
		return nil, nil
	}
	// Insert-if-absent: a concurrent PUT that landed first is not
	// clobbered; a concurrent seeder wrote the same values. When the
	// insert loses the race, read back the row that actually won so this
	// request never answers with a stale seed.
	inserted, err := store.SeedPolicy(ctx, seeded)
	if err != nil {
		return nil, err
	}
	if inserted {
		return seeded, nil
	}
	return store.GetPolicy(ctx)
}

// policyView converts a stored policy + its provenance into the wire
// PolicyView response.
func policyView(p *controller.StoredPolicy, source string) PolicyView {
	budgets := make(map[string]BudgetView, len(p.Budgets))
	for k, b := range p.Budgets {
		budgets[k] = BudgetView{WindowSecs: int64(b.WindowSecs), AdditionalProperties: b.Limits}
	}
	quotas := p.Quotas
	if quotas == nil {
		quotas = map[string]map[string]float64{}
	}
	var prices *map[string]float64
	if p.Prices != nil {
		prices = &p.Prices
	}
	profiles := profilesToWire(p.Profiles)
	admission := admissionToWire(p.Admission)
	storage := storageToWire(p.Storage)
	environments := environmentsToWire(p.Environments)
	images := imagesToWire(p.Images)
	workloadIdentity := workloadIdentityToWire(p.WorkloadIdentity)
	namespaces := namespacesToWire(p.Namespaces)
	return PolicyView{
		Images:           &images,
		WorkloadIdentity: &workloadIdentity,
		Namespaces:       &namespaces,
		Prices:           prices,
		Quotas:           quotas,
		Budgets:          budgets,
		Profiles:         &profiles,
		Admission:        &admission,
		Storage:          &storage,
		Environments:     &environments,
		Source:           source,
		Editable:         true,
	}
}

// --- Profile catalog and admission rules: wire <-> core (#7) ---

func profileToWire(p *core.Profile) ProfileSpec {
	projects := make([]string, len(p.Projects))
	copy(projects, p.Projects)
	storage := make([]string, len(p.Storage))
	copy(storage, p.Storage)
	out := ProfileSpec{
		Name:         p.Name,
		Description:  p.Description,
		Image:        p.Image,
		RayVersion:   p.RayVersion,
		HeadCpu:      p.HeadCpu,
		HeadMemory:   p.HeadMemory,
		WorkerGroups: workerGroupsToWire(p.WorkerGroups),
		Projects:     &projects,
		Storage:      &storage,
	}
	if p.MaxWorkers != nil {
		v := int32(*p.MaxWorkers)
		out.MaxWorkers = &v
	}
	if p.TtlSeconds != nil {
		v := int64(*p.TtlSeconds)
		out.TtlSeconds = &v
	}
	if p.IdleTimeoutSecs != nil {
		v := int64(*p.IdleTimeoutSecs)
		out.IdleTimeoutSecs = &v
	}
	return out
}

// profilesToWire never returns nil: the contract's catalog is `[]`, not
// `null`, when empty.
func profilesToWire(in []core.Profile) []ProfileSpec {
	out := make([]ProfileSpec, 0, len(in))
	for i := range in {
		out = append(out, profileToWire(&in[i]))
	}
	return out
}

func workerGroupsToWire(in []core.WorkerGroup) []WorkerGroup {
	out := make([]WorkerGroup, 0, len(in))
	for _, g := range in {
		out = append(out, WorkerGroup{
			Name:        g.Name,
			Cpu:         g.Cpu,
			Memory:      g.Memory,
			Gpu:         g.Gpu,
			MinReplicas: int32(g.MinReplicas),
			MaxReplicas: int32(g.MaxReplicas),
			Replicas:    int32(g.Replicas),
		})
	}
	return out
}

// profilesFromWire converts an incoming catalog and validates it as a
// unit — the edit is refused with a precise 400 rather than every later
// create failing with a 403 nobody can act on (the Rust predecessor's rule: validate at
// the edit). Checks: unique non-empty names; complete shape (image,
// ray_version, head_cpu, head_memory); quantities and replica bounds that
// parse (policy.ClusterDemand on a synthetic spec, the same check a
// create runs); worker groups within the profile's own max_workers;
// non-negative caps and timeouts; non-empty project names.
func profilesFromWire(in []ProfileSpec) ([]core.Profile, error) {
	out := make([]core.Profile, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i := range in {
		w := &in[i]
		what := fmt.Sprintf("invalid profile %q: ", w.Name)
		if w.Name == "" {
			return nil, badRequest(fmt.Sprintf("invalid profile at index %d: name must not be empty", i))
		}
		if seen[w.Name] {
			return nil, badRequest(what + "duplicate name")
		}
		seen[w.Name] = true
		for field, v := range map[string]string{"image": w.Image, "ray_version": w.RayVersion, "head_cpu": w.HeadCpu, "head_memory": w.HeadMemory} {
			if v == "" {
				return nil, badRequest(what + field + " must not be empty")
			}
		}
		groups, err := workerGroupsFromWire(w.WorkerGroups)
		if err != nil {
			return nil, badRequest(what + httpMessage(err))
		}
		p := core.Profile{
			Name:         w.Name,
			Description:  w.Description,
			Image:        w.Image,
			RayVersion:   w.RayVersion,
			HeadCpu:      w.HeadCpu,
			HeadMemory:   w.HeadMemory,
			WorkerGroups: groups,
		}
		if w.MaxWorkers != nil {
			if *w.MaxWorkers < 0 {
				return nil, badRequest(what + "max_workers must be non-negative")
			}
			v := uint32(*w.MaxWorkers)
			p.MaxWorkers = &v
		}
		if w.TtlSeconds != nil {
			if *w.TtlSeconds < 0 {
				return nil, badRequest(what + "ttl_seconds must be non-negative")
			}
			v := uint64(*w.TtlSeconds)
			p.TtlSeconds = &v
		}
		if w.IdleTimeoutSecs != nil {
			if *w.IdleTimeoutSecs < 0 {
				return nil, badRequest(what + "idle_timeout_secs must be non-negative")
			}
			v := uint64(*w.IdleTimeoutSecs)
			p.IdleTimeoutSecs = &v
		}
		if w.Projects != nil {
			for _, proj := range *w.Projects {
				if proj == "" {
					return nil, badRequest(what + "projects must not contain an empty name")
				}
			}
			p.Projects = append([]string(nil), (*w.Projects)...)
		}
		if w.Storage != nil {
			seenStorage := make(map[string]bool, len(*w.Storage))
			for _, name := range *w.Storage {
				if name == "" {
					return nil, badRequest(what + "storage names must not be empty")
				}
				if seenStorage[name] {
					return nil, badRequest(what + fmt.Sprintf("storage %q is listed twice", name))
				}
				seenStorage[name] = true
			}
			p.Storage = append([]string(nil), *w.Storage...)
		}
		// The shape a cluster gets from this profile must itself be
		// buildable: run the create-time shape validation on it. Profiles
		// are Ray-shaped (they fix ray_version), so the synthetic spec is
		// engine=ray and the Ray memory floor applies to it.
		synthetic := core.ClusterSpec{Engine: core.EngineRay, HeadCpu: p.HeadCpu, HeadMemory: p.HeadMemory, WorkerGroups: p.WorkerGroups}
		if err := validateClusterShape(&synthetic); err != nil {
			return nil, badRequest(what + httpMessage(err))
		}
		if p.MaxWorkers != nil && *p.MaxWorkers > 0 && totalMaxWorkers(&synthetic) > int(*p.MaxWorkers) {
			return nil, badRequest(fmt.Sprintf("%sworker groups ask for up to %d workers but max_workers is %d",
				what, totalMaxWorkers(&synthetic), *p.MaxWorkers))
		}
		out = append(out, p)
	}
	return out, nil
}

// httpMessage is the caller-facing text of an HTTPError, or err.Error().
func httpMessage(err error) string {
	if he, ok := err.(HTTPError); ok {
		return he.Message
	}
	return err.Error()
}

func admissionRuleToWire(r core.AdmissionRule) AdmissionRule {
	images := make([]string, len(r.AllowedImages))
	copy(images, r.AllowedImages)
	max := int32(r.MaxWorkers)
	out := AdmissionRule{AllowedImages: &images, MaxWorkers: &max}
	if r.CatalogOnly {
		out.CatalogOnly = &r.CatalogOnly
	}
	if r.AllowPyExecutable {
		out.AllowPyExecutable = &r.AllowPyExecutable
	}
	if r.AllowImageURI {
		out.AllowImageUri = &r.AllowImageURI
	}
	if r.AllowConda {
		out.AllowConda = &r.AllowConda
	}
	if r.AllowUnpinnedPackages {
		out.AllowUnpinnedPackages = &r.AllowUnpinnedPackages
	}
	if r.PackageDenylist != nil {
		v := append([]string{}, r.PackageDenylist...)
		out.PackageDenylist = &v
	}
	if r.AllowedIndexHosts != nil {
		v := append([]string{}, r.AllowedIndexHosts...)
		out.AllowedIndexHosts = &v
	}
	if r.AllowedRemoteSchemes != nil {
		v := append([]string{}, r.AllowedRemoteSchemes...)
		out.AllowedRemoteSchemes = &v
	}
	if r.AllowedRemoteHosts != nil {
		v := append([]string{}, r.AllowedRemoteHosts...)
		out.AllowedRemoteHosts = &v
	}
	if r.MaxSetupTimeoutSeconds > 0 {
		out.MaxSetupTimeoutSeconds = &r.MaxSetupTimeoutSeconds
	}
	if r.MaxDocumentBytes > 0 {
		out.MaxDocumentBytes = &r.MaxDocumentBytes
	}
	if r.RequireScannedEnvironments {
		out.RequireScannedEnvironments = &r.RequireScannedEnvironments
	}
	return out
}

// admissionToWire never returns nil: the contract's map is `{}`, not
// `null`, when empty.
func admissionToWire(in map[string]core.AdmissionRule) map[string]AdmissionRule {
	out := make(map[string]AdmissionRule, len(in))
	for k, v := range in {
		out[k] = admissionRuleToWire(v)
	}
	return out
}

// admissionFromWire converts an incoming admission map and validates it:
// non-empty project keys, non-empty image prefixes, non-negative caps. The
// runtime-env governance knobs (#52) are copied verbatim onto the stored
// rule — they make the #53 validator's hardcoded defaults API-editable;
// the validator reads them through runtimeEnvPolicyFor (#55). The scan-gate
// toggle (#58) rides the same way; environment resolution reads it through
// requireScannedEnvironmentsFor.
func admissionFromWire(in map[string]AdmissionRule) (map[string]core.AdmissionRule, error) {
	out := make(map[string]core.AdmissionRule, len(in))
	for project, w := range in {
		what := fmt.Sprintf("invalid admission rule for project %q: ", project)
		if project == "" {
			return nil, badRequest("invalid admission rule: project must not be empty (use \"*\" for every project)")
		}
		var r core.AdmissionRule
		if w.AllowedImages != nil {
			for _, img := range *w.AllowedImages {
				if img == "" {
					return nil, badRequest(what + "allowed_images must not contain an empty prefix")
				}
			}
			r.AllowedImages = append([]string(nil), (*w.AllowedImages)...)
		}
		if w.MaxWorkers != nil {
			if *w.MaxWorkers < 0 {
				return nil, badRequest(what + "max_workers must be non-negative")
			}
			r.MaxWorkers = uint32(*w.MaxWorkers)
		}
		if w.CatalogOnly != nil {
			r.CatalogOnly = *w.CatalogOnly
		}
		if w.AllowPyExecutable != nil {
			r.AllowPyExecutable = *w.AllowPyExecutable
		}
		if w.AllowImageUri != nil {
			r.AllowImageURI = *w.AllowImageUri
		}
		if w.AllowConda != nil {
			r.AllowConda = *w.AllowConda
		}
		if w.AllowUnpinnedPackages != nil {
			r.AllowUnpinnedPackages = *w.AllowUnpinnedPackages
		}
		copyList := func(field string, list *[]string, dst *[]string) error {
			if list == nil {
				return nil
			}
			for _, entry := range *list {
				if entry == "" {
					return badRequest(what + field + " must not contain an empty entry")
				}
			}
			*dst = append([]string(nil), (*list)...)
			return nil
		}
		if err := copyList("package_denylist", w.PackageDenylist, &r.PackageDenylist); err != nil {
			return nil, err
		}
		if err := copyList("allowed_index_hosts", w.AllowedIndexHosts, &r.AllowedIndexHosts); err != nil {
			return nil, err
		}
		if err := copyList("allowed_remote_schemes", w.AllowedRemoteSchemes, &r.AllowedRemoteSchemes); err != nil {
			return nil, err
		}
		if err := copyList("allowed_remote_hosts", w.AllowedRemoteHosts, &r.AllowedRemoteHosts); err != nil {
			return nil, err
		}
		if w.MaxSetupTimeoutSeconds != nil {
			if *w.MaxSetupTimeoutSeconds < 0 {
				return nil, badRequest(what + "max_setup_timeout_seconds must be non-negative")
			}
			r.MaxSetupTimeoutSeconds = *w.MaxSetupTimeoutSeconds
		}
		if w.MaxDocumentBytes != nil {
			if *w.MaxDocumentBytes < 0 {
				return nil, badRequest(what + "max_document_bytes must be non-negative")
			}
			r.MaxDocumentBytes = *w.MaxDocumentBytes
		}
		if w.RequireScannedEnvironments != nil {
			r.RequireScannedEnvironments = *w.RequireScannedEnvironments
		}
		out[project] = r
	}
	return out, nil
}

// validateAmounts requires every value to be a non-negative finite number
// (JSON can't carry NaN/inf, but negative values can arrive; the check is
// the contract). Ported from settings.rs's validate_amounts.
func validateAmounts(m map[string]float64, what string) error {
	for k, v := range m {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return HTTPError{Status: http.StatusBadRequest, Code: "bad_request",
				Message: "invalid " + what + " for " + k + ": must be a non-negative finite number"}
		}
	}
	return nil
}

// GetPolicy returns the effective governance policy and its provenance.
// Admin-only (governance is platform configuration).
func (s *Server) GetPolicy(ctx context.Context, _ GetPolicyRequestObject) (GetPolicyResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Admin, auth.TargetCluster); err != nil {
		return nil, err
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if p == nil {
		return GetPolicy200JSONResponse(policyView(&controller.StoredPolicy{}, "none")), nil
	}
	source := "store"
	if p.FromFileSeed {
		source = "file"
	}
	return GetPolicy200JSONResponse(policyView(p, source)), nil
}

// UpdatePolicy replaces sections of the governance policy (section-replace
// semantics — see UpdatePolicy's generated doc comment). Admin-only; emits
// an update_policy audit event on success, plus one publish_environment /
// deprecate_environment row per environment lifecycle change an
// environments-section edit performed (#57).
func (s *Server) UpdatePolicy(ctx context.Context, req UpdatePolicyRequestObject) (UpdatePolicyResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Admin, auth.TargetCluster); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, HTTPError{Status: http.StatusBadRequest, Code: "bad_request", Message: "missing request body"}
	}
	body := req.Body

	// Validate the INCOMING sections only — existing stored/seeded values
	// were accepted by whatever wrote them and must not 400 an unrelated
	// edit.
	//
	// Wire-contract note: the Rust reference distinguishes an ABSENT
	// `prices` key (untouched) from an explicit `"prices": null` (clears
	// the sheet) via Option<Option<T>> (settings.rs's de_present_nullable).
	// The generated Go UpdatePolicy.Prices is a single-level *map, which
	// json.Unmarshal sets to nil for BOTH an absent key and an explicit
	// null — the generated type (frozen; not touched by this task) cannot
	// carry that distinction. This handler therefore treats a nil Prices
	// as "leave the price sheet untouched"; there is currently no wire
	// way to explicitly clear an already-set sheet back to unconfigured
	// (a client can still zero it out with `"prices": {}`). Flagged as a
	// contract-fidelity gap, not silently shipped.
	if body.Prices != nil {
		if err := validateAmounts(*body.Prices, "price"); err != nil {
			return nil, err
		}
	}
	if body.Quotas != nil {
		for project, m := range *body.Quotas {
			if err := validateAmounts(m, "quota for project \""+project+"\""); err != nil {
				return nil, err
			}
		}
	}
	if body.Budgets != nil {
		for project, b := range *body.Budgets {
			if b.WindowSecs <= 0 {
				return nil, HTTPError{Status: http.StatusBadRequest, Code: "bad_request",
					Message: "invalid budget for project \"" + project + "\": window_secs must be > 0"}
			}
			if err := validateAmounts(b.AdditionalProperties, "budget for project \""+project+"\""); err != nil {
				return nil, err
			}
		}
	}
	var profiles []core.Profile
	if body.Profiles != nil {
		var err error
		if profiles, err = profilesFromWire(*body.Profiles); err != nil {
			return nil, err
		}
	}
	var admission map[string]core.AdmissionRule
	if body.Admission != nil {
		var err error
		if admission, err = admissionFromWire(*body.Admission); err != nil {
			return nil, err
		}
	}
	var storage []core.StorageEntry
	if body.Storage != nil {
		var err error
		if storage, err = storageFromWire(*body.Storage); err != nil {
			return nil, err
		}
	}
	var images []core.ImageEntry
	if body.Images != nil {
		var err error
		if images, err = imagesFromWire(*body.Images); err != nil {
			return nil, err
		}
	}
	var environments []core.Environment
	if body.Environments != nil {
		var err error
		if environments, err = environmentsFromWire(*body.Environments); err != nil {
			return nil, err
		}
	}
	var workloadIdentity map[string]core.WorkloadIdentityRule
	if body.WorkloadIdentity != nil {
		var err error
		if workloadIdentity, err = workloadIdentityFromWire(*body.WorkloadIdentity); err != nil {
			return nil, err
		}
	}
	var namespaces map[string]string
	if body.Namespaces != nil {
		if !s.TenantNamespaces {
			return nil, badRequest(tenantNamespacesDisabled)
		}
		var err error
		if namespaces, err = namespacesFromWire(*body.Namespaces); err != nil {
			return nil, err
		}
		if err := s.allocationsAgreeWithNamespaces(ctx, namespaces); err != nil {
			return nil, err
		}
	}

	next, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if next == nil {
		next = &controller.StoredPolicy{}
	}
	if body.Prices != nil {
		next.Prices = *body.Prices
	}
	if body.Quotas != nil {
		next.Quotas = *body.Quotas
	}
	if body.Budgets != nil {
		budgets := make(map[string]controller.StoredBudget, len(*body.Budgets))
		for k, b := range *body.Budgets {
			budgets[k] = controller.StoredBudget{WindowSecs: uint64(b.WindowSecs), Limits: b.AdditionalProperties}
		}
		next.Budgets = budgets
	}
	// Profiles, admission and storage follow the same section-replace rule
	// as the maps above: a present key replaces the whole section
	// (`[]`/`{}` clears it), an absent key leaves it untouched. A storage
	// edit is never retroactive: specs already admitted keep the
	// resolution they were admitted with (core.ResolvedStorage).
	if body.Profiles != nil {
		next.Profiles = profiles
	}
	if body.Admission != nil {
		next.Admission = admission
	}
	if body.Storage != nil {
		next.Storage = storage
	}
	// The image catalog (#10) follows the same section-replace rule; a
	// spec admitted against the old catalog keeps the image it was
	// admitted with.
	if body.Images != nil {
		next.Images = images
	}
	// Workload identity (#20) follows the same section-replace rule and is
	// never retroactive either: a workload keeps the ServiceAccount it was
	// admitted with (core.ClusterSpec.ServiceAccountResolved).
	if body.WorkloadIdentity != nil {
		next.WorkloadIdentity = workloadIdentity
	}
	// Tenant namespaces (#21): section-replace, never retroactive — an
	// admitted workload stays in the namespace it was placed in
	// (core.ClusterSpec.NamespaceResolved).
	if body.Namespaces != nil {
		next.Namespaces = namespaces
	}
	// Environments (#52) follow the same section-replace rule as profiles,
	// admission and storage: a present key replaces the whole catalog (`[]`
	// clears it), an absent key leaves it untouched. References already
	// admitted onto specs are never retroactive, exactly like storage. The
	// replacement additionally passes the lifecycle transition discipline
	// (#57, applyEnvironmentTransitions): publishes are stamped with the
	// caller's identity, and each publish/deprecate becomes an audit row
	// once the edit lands.
	var envEvents []environmentLifecycleEvent
	if body.Environments != nil {
		adjusted, events, err := applyEnvironmentTransitions(next.Environments, environments,
			identitySubject(identity), time.Unix(int64(controller.NowUnix()), 0).UTC())
		if err != nil {
			return nil, err
		}
		next.Environments = adjusted
		envEvents = events
	}
	// A profile's storage must name entries of the catalog it will be
	// resolved against, whichever section this request replaced: a
	// dangling name would surface as a 400 on somebody else's create.
	if err := profilesReferenceKnownStorage(next.Profiles, next.Storage); err != nil {
		return nil, err
	}
	next.FromFileSeed = false

	if err := s.Store.SetPolicy(ctx, next); err != nil {
		return nil, wrapStoreErr(err)
	}
	action := "update_policy"
	status := uint16(http.StatusOK)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts:       controller.NowUnix(),
		Subject:  identitySubject(identity),
		Decision: core.AuditDecisionAllow,
		Action:   &action,
		Status:   &status,
	})
	// One lifecycle row per environment the edit published or deprecated
	// (#57). The row names actor, action and time; the catalog entry itself
	// carries the durable per-environment attribution (published_by /
	// published_at) — AuditEvent has no free-form detail field, and adding
	// one is a schema change the fixed field set deliberately avoids.
	for _, ev := range envEvents {
		a := ev.action
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts:       controller.NowUnix(),
			Subject:  identitySubject(identity),
			Decision: core.AuditDecisionAllow,
			Action:   &a,
			Status:   &status,
		})
	}
	return UpdatePolicy200JSONResponse(policyView(next, "store")), nil
}

// profilesReferenceKnownStorage refuses a catalog whose profiles name
// storage entries the storage catalog does not have.
func profilesReferenceKnownStorage(profiles []core.Profile, storage []core.StorageEntry) error {
	known := make(map[string]bool, len(storage))
	for i := range storage {
		known[storage[i].Name] = true
	}
	for i := range profiles {
		for _, name := range profiles[i].Storage {
			if !known[name] {
				return badRequest(fmt.Sprintf("invalid profile %q: no such storage %q", profiles[i].Name, name))
			}
		}
	}
	return nil
}
