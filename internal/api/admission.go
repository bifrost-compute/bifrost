package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// Admission is what a platform administrator lets self-serve users request
// (requirement 7: profiles, images, CPU/memory/GPU and max worker counts).
// CPU/memory/GPU are governed by quotas and budgets in PolicyConfig; this
// covers the two the policy could not express: which images may run, and
// how many workers one cluster may ask for.
type Admission struct {
	// AllowedImagePrefixes: a requested image must start with one of these
	// (e.g. "rayproject/", "registry.example.com/ml/"). Empty = any image.
	AllowedImagePrefixes []string
	// MaxWorkers caps the sum of max_replicas across a cluster's worker
	// groups. 0 = no cap.
	MaxWorkers int
	// CatalogOnly requires the image to be a Catalog entry (#10); false =
	// the prefix allowlist alone decides.
	CatalogOnly bool
	// Catalog is the image catalog narrowed to the project (#10):
	// consulted by Check when CatalogOnly is set, and by CatalogEntry to
	// fill a spec's ray_version and to refuse an engine mismatch.
	Catalog []core.ImageEntry
}

// CatalogEntry returns the catalog entry image is, or nil.
func (a Admission) CatalogEntry(image string) *core.ImageEntry {
	for i := range a.Catalog {
		if a.Catalog[i].Matches(image) {
			return &a.Catalog[i]
		}
	}
	return nil
}

// SeedRules converts the boot-time flags (`--allowed-images`,
// `--max-workers`) into the policy seed's admission map: the "*" rule that
// applies to every project, or nil when both flags are unset so an empty
// seed never materializes a policy row. The flags keep their meaning; the
// policy API can inspect and replace the rule like any other section.
func (a Admission) SeedRules() map[string]core.AdmissionRule {
	if len(a.AllowedImagePrefixes) == 0 && a.MaxWorkers <= 0 {
		return nil
	}
	rule := core.AdmissionRule{AllowedImages: append([]string(nil), a.AllowedImagePrefixes...)}
	if a.MaxWorkers > 0 {
		rule.MaxWorkers = uint32(a.MaxWorkers)
	}
	return map[string]core.AdmissionRule{AdmissionEveryProject: rule}
}

// AdmissionEveryProject is the admission-map key whose rule applies to
// every project; a project's own rule overrides it field by field.
const AdmissionEveryProject = "*"

// admissionFor is the effective admission for project: the "*" rule's
// fields, each overridden by the project's rule where that rule sets it
// (a non-empty image list, a cap > 0). An unset field inherits, so an
// administrator can cap one project's workers without restating the
// platform image allowlist. Reads the effective policy, so an edit via
// PUT applies to the next create without a restart. Package B's
// submit_job calls the same helper.
func (s *Server) admissionFor(ctx context.Context, project string) (Admission, error) {
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return Admission{}, err
	}
	var out Admission
	if p == nil {
		return out, nil
	}
	for _, key := range []string{AdmissionEveryProject, project} {
		rule, ok := p.Admission[key]
		if !ok {
			continue
		}
		if len(rule.AllowedImages) > 0 {
			out.AllowedImagePrefixes = append([]string(nil), rule.AllowedImages...)
		}
		if rule.MaxWorkers > 0 {
			out.MaxWorkers = int(rule.MaxWorkers)
		}
		if rule.CatalogOnly {
			out.CatalogOnly = true
		}
	}
	out.Catalog = imagesAvailableTo(p.Images, project)
	return out, nil
}

// totalMaxWorkers is the sum of max_replicas across a spec's worker
// groups — the number every worker cap (admission rule, profile) is
// checked against.
func totalMaxWorkers(spec *core.ClusterSpec) int {
	total := 0
	for _, g := range spec.WorkerGroups {
		total += int(g.MaxReplicas)
	}
	return total
}

// admissionError is the reason a spec is refused, in audit-row form
// (reason) and caller form (message).
type admissionError struct {
	reason, message string
}

// Check returns nil when spec is admissible, else the refusal.
func (a Admission) Check(spec *core.ClusterSpec) *admissionError {
	if len(a.AllowedImagePrefixes) > 0 {
		ok := false
		for _, p := range a.AllowedImagePrefixes {
			if p != "" && strings.HasPrefix(spec.Image, p) {
				ok = true
				break
			}
		}
		if !ok {
			return &admissionError{
				reason:  "image_not_allowed",
				message: fmt.Sprintf("image %q is not in the administrator's allowlist (prefixes: %s)", spec.Image, strings.Join(a.AllowedImagePrefixes, ", ")),
			}
		}
	}
	// Image catalog (#10): a catalog image must carry the spec's engine;
	// under catalog_only, only a catalog image runs at all.
	if entry := a.CatalogEntry(spec.Image); entry != nil {
		if engine := entry.EngineOrDefault(); spec.Engine != "" && engine != spec.Engine {
			return &admissionError{
				reason:  "image_engine_mismatch",
				message: fmt.Sprintf("image %q is a %s image; the spec's engine is %s", spec.Image, engine, spec.Engine),
			}
		}
	} else if a.CatalogOnly {
		return &admissionError{
			reason:  "image_not_in_catalog",
			message: fmt.Sprintf("image %q is not in the image catalog for project %q (the project admits catalog images only)", spec.Image, spec.Project),
		}
	}
	if a.MaxWorkers > 0 {
		if total := totalMaxWorkers(spec); total > a.MaxWorkers {
			return &admissionError{
				reason:  "max_workers_exceeded",
				message: fmt.Sprintf("worker groups ask for up to %d workers; the administrator's cap is %d", total, a.MaxWorkers),
			}
		}
	}
	return nil
}

// ParseImagePrefixes splits a comma-separated flag value into prefixes,
// dropping blanks.
func ParseImagePrefixes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
