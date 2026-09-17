package core

import (
	"encoding/json"
	"fmt"
)

// Ephemeral Ray job domain model (requirement 5). A RayJob is a run-to-
// completion workload: Bifrost provisions a dedicated cluster for it, runs
// Entrypoint there, and tears the cluster down when the job finishes. On
// KubeRay it maps to a RayJob CR; the shape below mirrors that CR so the
// provisioner stays a thin translation (same posture as ClusterSpec vs
// RayCluster).

// DefaultRayJobTtlSecondsAfterFinished is how long a finished job's cluster
// is kept before the backend deletes it when the spec leaves
// TtlSecondsAfterFinished nil (contract: "default 60 when omitted").
const DefaultRayJobTtlSecondsAfterFinished uint32 = 60

// RayJobSpec is the declarative spec for an ephemeral Ray job.
//
// Field names and wire values follow the contract's RayJobSpec schema.
// Shape defaults ("1"/"2Gi" for the head, the Ray version from the image
// tag) are the API edge's job, exactly as for ClusterSpec — core carries
// what the caller asked for.
type RayJobSpec struct {
	Project string `json:"project"`
	// Entrypoint is the shell command Ray runs as the job.
	Entrypoint string `json:"entrypoint"`
	// Image is the container image for the head, the workers and the
	// submitter.
	Image string `json:"image"`
	// RayVersion is the Ray version in Image; "" until the edge fills it
	// from the image tag.
	RayVersion string `json:"ray_version"`
	// RuntimeEnvYaml is the job's Ray runtime_env as a YAML document,
	// passed through verbatim; "" = none.
	RuntimeEnvYaml string        `json:"runtime_env_yaml"`
	HeadCpu        string        `json:"head_cpu"`
	HeadMemory     string        `json:"head_memory"`
	WorkerGroups   []WorkerGroup `json:"worker_groups"`
	// Profile is the profile catalog name (#7) whose shape fills the
	// zero-valued fields here; nil = none.
	Profile *string `json:"profile"`
	// Environment is the environment catalog name (#52) whose image,
	// packages and env vars this job runs with; nil = none. Resolved
	// against the catalog at admission into EnvironmentResolved (#55).
	Environment *string `json:"environment"`
	// EnvironmentResolved is the server-computed resolution of Environment
	// against the catalog at admission time (never retroactive). Persisted,
	// never echoed: RayJobView carries no spec.
	EnvironmentResolved *ResolvedEnvironment `json:"environment_resolved,omitempty"`
	// Storage names storage catalog entries (#12) delivered to the job's
	// pods. Names only — the catalog is resolved server-side into
	// StorageResolved.
	Storage []string `json:"storage"`
	// StorageResolved is the server-computed resolution of Storage against
	// the catalog at admission time (never retroactive). Persisted, never
	// echoed: RayJobView carries no spec.
	StorageResolved []ResolvedStorage `json:"storage_resolved,omitempty"`
	// ServiceAccountResolved is the Kubernetes ServiceAccount the workload's
	// pods run under (#20), resolved from the policy's workload_identity
	// rules for the project at admission and persisted so a later rule
	// edit is never retroactive. nil = the namespace default (no rule).
	// Never echoed: views carry no spec.
	ServiceAccountResolved *string `json:"service_account_resolved,omitempty"`
	// NamespaceResolved is the Kubernetes namespace this workload's objects
	// live in (#21): the project's tenant namespace from the policy's
	// `namespaces` map, resolved at admission and pinned so a later mapping
	// edit never moves a running workload. "" = the control plane's default
	// workload namespace (`serve --namespace`), byte-identical to every
	// spec admitted before tenant namespaces existed. Never echoed.
	NamespaceResolved string `json:"namespace_resolved,omitempty"`
	// TtlSecondsAfterFinished is how long the finished job's cluster is
	// kept before the backend deletes it; nil = DefaultRayJobTtlSecondsAfterFinished.
	TtlSecondsAfterFinished *uint32 `json:"ttl_seconds_after_finished"`
	// Owner is the authenticated identity that submitted the job, stamped
	// control-plane-side from the request identity like ClusterSpec.Owner
	// (never trusted from the client body); nil when unattributed.
	Owner *string `json:"owner"`
}

// TtlSecondsAfterFinishedOrDefault returns the effective TTL: the spec's
// value when set, else DefaultRayJobTtlSecondsAfterFinished.
func (s RayJobSpec) TtlSecondsAfterFinishedOrDefault() uint32 {
	if s.TtlSecondsAfterFinished == nil {
		return DefaultRayJobTtlSecondsAfterFinished
	}
	return *s.TtlSecondsAfterFinished
}

// rayJobSpecAlias breaks the recursion MarshalJSON would otherwise cause
// by re-entering RayJobSpec's own MarshalJSON.
type rayJobSpecAlias RayJobSpec

// MarshalJSON gives WorkerGroups and Storage the package's "nil is not a
// valid Vec" treatment (nil -> `[]`, never `null`), matching ClusterSpec.
func (s RayJobSpec) MarshalJSON() ([]byte, error) {
	a := rayJobSpecAlias(s)
	if a.WorkerGroups == nil {
		a.WorkerGroups = []WorkerGroup{}
	}
	if a.Storage == nil {
		a.Storage = []string{}
	}
	return json.Marshal(a)
}

// RayJobState is Bifrost's normalized lifecycle state of an ephemeral job
// — Ray's own job vocabulary (PENDING | RUNNING | SUCCEEDED | FAILED |
// STOPPED) in the package's snake_case wire form.
type RayJobState string

const (
	RayJobStatePending   RayJobState = "pending"
	RayJobStateRunning   RayJobState = "running"
	RayJobStateSucceeded RayJobState = "succeeded"
	RayJobStateFailed    RayJobState = "failed"
	RayJobStateStopped   RayJobState = "stopped"
)

func (s RayJobState) isValid() bool {
	switch s {
	case RayJobStatePending, RayJobStateRunning, RayJobStateSucceeded,
		RayJobStateFailed, RayJobStateStopped:
		return true
	}
	return false
}

// String returns the wire value (snake_case).
func (s RayJobState) String() string { return string(s) }

// IsTerminal reports whether the job will never change state again.
func (s RayJobState) IsTerminal() bool {
	switch s {
	case RayJobStateSucceeded, RayJobStateFailed, RayJobStateStopped:
		return true
	case RayJobStatePending, RayJobStateRunning:
		return false
	}
	return false
}

// UnmarshalJSON rejects any value other than the known RayJobState
// variants, mirroring serde's strict enum deserialization.
func (s *RayJobState) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	st := RayJobState(v)
	if !st.isValid() {
		return fmt.Errorf("core: invalid RayJobState %q", v)
	}
	*s = st
	return nil
}

// ParseRayJobStatus maps Ray's upper-case job status vocabulary (as
// reported by the Ray Jobs API and echoed in a RayJob CR's
// status.jobStatus) onto RayJobState. The second result is false for
// anything unrecognized, including the "" Ray reports before the job has
// a status at all.
func ParseRayJobStatus(rayStatus string) (RayJobState, bool) {
	switch rayStatus {
	case "PENDING":
		return RayJobStatePending, true
	case "RUNNING":
		return RayJobStateRunning, true
	case "SUCCEEDED":
		return RayJobStateSucceeded, true
	case "FAILED":
		return RayJobStateFailed, true
	case "STOPPED":
		return RayJobStateStopped, true
	}
	return "", false
}
