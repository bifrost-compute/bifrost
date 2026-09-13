package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// Environment catalog (#52): named, governed compute environments — a base
// image, pinned packages and env vars — a job or cluster spec refers to by
// name (`ClusterSpec.Environment`, `RayJobSpec.Environment`). The catalog
// rides the policy row like the profile (#7) and storage (#12) catalogs.
// Pure data: validation of the catalog as a unit is the policy/API edge's
// job. Resolution of a reference into a concrete runtime_env is the
// catalog issue's (#54/#55); until then a stored reference is inert.

// EnvironmentStatus is an environment's lifecycle state: a draft is
// editable and not yet selectable, published is selectable by specs,
// deprecated stays resolvable for existing references but should not be
// picked for new work.
type EnvironmentStatus string

const (
	EnvironmentStatusDraft      EnvironmentStatus = "draft"
	EnvironmentStatusPublished  EnvironmentStatus = "published"
	EnvironmentStatusDeprecated EnvironmentStatus = "deprecated"
)

// DefaultEnvironmentStatus is the status an Environment has when its
// `status` key is absent from JSON input: every environment starts a draft.
const DefaultEnvironmentStatus = EnvironmentStatusDraft

func (s EnvironmentStatus) isValid() bool {
	switch s {
	case EnvironmentStatusDraft, EnvironmentStatusPublished, EnvironmentStatusDeprecated:
		return true
	}
	return false
}

// String returns the wire value ("draft" | "published" | "deprecated").
func (s EnvironmentStatus) String() string { return string(s) }

// OrDefault maps the zero value onto DefaultEnvironmentStatus so an entry
// written before the field existed and one written with "status":"draft"
// compare equal.
func (s EnvironmentStatus) OrDefault() EnvironmentStatus {
	if s == "" {
		return DefaultEnvironmentStatus
	}
	return s
}

// UnmarshalJSON rejects any value other than the known EnvironmentStatus
// variants, mirroring the other strict catalog enums.
func (s *EnvironmentStatus) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	st := EnvironmentStatus(v)
	if !st.isValid() {
		return fmt.Errorf("core: invalid EnvironmentStatus %q", v)
	}
	*s = st
	return nil
}

// EnvironmentScanStatus is the verdict of a recorded environment scan.
type EnvironmentScanStatus string

const (
	EnvironmentScanClean   EnvironmentScanStatus = "clean"
	EnvironmentScanFailed  EnvironmentScanStatus = "failed"
	EnvironmentScanPending EnvironmentScanStatus = "pending"
)

func (s EnvironmentScanStatus) isValid() bool {
	switch s {
	case EnvironmentScanClean, EnvironmentScanFailed, EnvironmentScanPending:
		return true
	}
	return false
}

// String returns the wire value ("clean" | "failed" | "pending").
func (s EnvironmentScanStatus) String() string { return string(s) }

// UnmarshalJSON rejects any value other than the known
// EnvironmentScanStatus variants, mirroring the other strict catalog enums.
func (s *EnvironmentScanStatus) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	st := EnvironmentScanStatus(v)
	if !st.isValid() {
		return fmt.Errorf("core: invalid EnvironmentScanStatus %q", v)
	}
	*s = st
	return nil
}

// EnvironmentScan is the recorded vulnerability-scan verdict for an
// environment (#52): an administrator records the outcome of the offline
// scan workflow (trivy/grype on the base image, pip-audit on the package
// list) here; the control plane does not scan itself.
type EnvironmentScan struct {
	Status    EnvironmentScanStatus `json:"status"`
	Scanner   *string               `json:"scanner"`
	ScannedAt *time.Time            `json:"scanned_at"`
}

// Environment is a catalog entry for a governed compute environment: the
// base image, pinned packages and env vars a job or cluster gets when its
// spec names this entry. Rides the policy row (plan ruling D7, extended by
// #52); validated as a unit at the API edge.
type Environment struct {
	// Name is the catalog name a spec refers to (an RFC 1123 label, so it
	// can ride Kubernetes object names).
	Name string `json:"name"`
	// Description is a human-readable summary shown by clients; nil = none.
	Description *string `json:"description"`
	// BaseImage is the container image the environment builds on; admission
	// image allowlists apply to it as to any spec image.
	BaseImage string `json:"base_image"`
	// Packages are pip requirements, each pinned to an exact version
	// (name[extras]==version) — the same pin rule the runtime_env
	// governance validator (#53) enforces. Empty = the base image alone.
	Packages []string `json:"packages"`
	// EnvVars are the environment variables every workload using this
	// environment runs with; empty = none.
	EnvVars map[string]string `json:"env_vars"`
	// RuntimeEnvYaml is the escape hatch: an extra Ray runtime_env YAML
	// document merged in at resolution time, governed by the same validator
	// (#53) a job's own runtime_env_yaml passes; "" = none.
	RuntimeEnvYaml string `json:"runtime_env_yaml,omitempty"`
	// Projects that may use this environment; empty = every project.
	Projects []string `json:"projects"`
	// Status is the lifecycle state; absent in JSON = draft.
	Status EnvironmentStatus `json:"status,omitempty"`
	// PublishedBy is the identity that published the environment; nil while
	// in draft.
	PublishedBy *string `json:"published_by"`
	// PublishedAt is when the environment was published; nil while in draft.
	PublishedAt *time.Time `json:"published_at"`
	// Scan is the recorded scan verdict; nil = never scanned.
	Scan *EnvironmentScan `json:"scan"`
}

// environmentAlias breaks the recursion MarshalJSON would otherwise cause
// by re-entering Environment's own MarshalJSON.
type environmentAlias Environment

// MarshalJSON substitutes an empty slice for a nil Packages/Projects and an
// empty map for a nil EnvVars (nil is not a valid Vec: `[]`/`{}`, never
// `null`).
func (e Environment) MarshalJSON() ([]byte, error) {
	a := environmentAlias(e)
	if a.Packages == nil {
		a.Packages = []string{}
	}
	if a.Projects == nil {
		a.Projects = []string{}
	}
	if a.EnvVars == nil {
		a.EnvVars = map[string]string{}
	}
	return json.Marshal(a)
}
