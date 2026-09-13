// Package core holds the provider-agnostic domain model for the Bifrost
// control plane. Bifrost orchestrates stock Ray clusters through their
// stable seams (KubeRay CRDs, the Jobs REST API via a federating gateway,
// Serve ingress). This package holds the provider-agnostic domain types; it
// must never depend on a cloud SDK or Kubernetes client (see predecessor
// ADR-0002), and it is I/O-free.
//
// Ported from the predecessor's core crate (Rust). Field names and enum wire values follow
// the frozen OpenAPI contract (serde is the wire-format arbiter in the
// Rust reference).
package core

import (
	"encoding/json"
	"fmt"
)

// ClusterId is an opaque identifier for a managed Ray cluster.
//
// Also the routing key for the job gateway: each cluster is exposed at its
// own base URL because the stock `ray job submit` client has no cluster-id
// slot in its paths (PLAN.md, review finding S3).
//
// Marshals/unmarshals as a bare JSON string (mirrors Rust's
// #[serde(transparent)]).
type ClusterId string

// String returns the underlying identifier.
func (c ClusterId) String() string { return string(c) }

// Engine is the compute engine a cluster is provisioned on (multi-engine
// spike). The control plane is engine-neutral above the provisioner seam;
// this discriminator is what the reconciler and the provisioner router
// dispatch on. Ray is the default so specs persisted before multi-engine —
// and any client that omits the field — still deserialize as Ray clusters,
// exactly as before.
type Engine string

const (
	// EngineRay is KubeRay `RayCluster` — full control + interactive +
	// batch (Ray Jobs) + serving (Ray Serve).
	EngineRay Engine = "ray"
	// EngineDask is dask-kubernetes-operator `DaskCluster` — control +
	// interactive only. Batch (no Ray-Jobs-REST equivalent) and serving
	// (no Ray Serve equivalent) are deliberately out of scope for Dask.
	EngineDask Engine = "dask"
)

// DefaultEngine is the Engine used when a ClusterSpec's `engine` field is
// absent from JSON input (mirrors Rust's #[derive(Default)] on Engine).
const DefaultEngine = EngineRay

func (e Engine) isValid() bool {
	switch e {
	case EngineRay, EngineDask:
		return true
	}
	return false
}

// String returns the wire value ("ray" | "dask").
func (e Engine) String() string {
	switch e {
	case EngineRay:
		return "ray"
	case EngineDask:
		return "dask"
	}
	return string(e)
}

// UnmarshalJSON rejects any value other than the known Engine variants,
// mirroring serde's strict enum deserialization.
func (e *Engine) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v := Engine(s)
	if !v.isValid() {
		return fmt.Errorf("core: invalid Engine %q", s)
	}
	*e = v
	return nil
}

// ClusterSpec is the declarative spec for a managed cluster.
//
// Historically Ray-only (fields mirror a RayCluster CR so the KubeRay
// provisioner stays a thin translation). Multi-engine adds Engine; the
// head/scheduler + worker-group shape is generic to both engines. For
// Engine == EngineDask, RayVersion is unused (Dask's version is carried by
// Image); it stays a required field only for back-compat with stored Ray
// specs and existing clients.
type ClusterSpec struct {
	Name    string `json:"name"`
	Project string `json:"project"`
	// Engine is which compute engine backs this cluster. Absent on the
	// wire defaults to Ray, so every pre-multi-engine spec and every Ray
	// client keeps working untouched.
	Engine       Engine        `json:"engine"`
	RayVersion   string        `json:"ray_version"`
	Image        string        `json:"image"`
	HeadCpu      string        `json:"head_cpu"`
	HeadMemory   string        `json:"head_memory"`
	WorkerGroups []WorkerGroup `json:"worker_groups"`
	// TtlSeconds is the absolute max-age cap in seconds: the cluster is
	// reaped this long after creation regardless of activity. nil disables
	// the max-age reaper. (Despite the historical name, this is a
	// wall-clock age cap, not an inactivity window — see IdleTimeoutSecs
	// for that.)
	TtlSeconds *uint64 `json:"ttl_seconds"`
	// IdleTimeoutSecs is the inactivity reap window in seconds (#100): the
	// cluster is reaped once it has been idle — no job activity — for
	// this long, so a busy cluster survives past it while a genuinely
	// unused one is released. Distinct from TtlSeconds, which still caps
	// absolute age independently: whichever fires first reaps the
	// cluster.
	//
	// Activity is derived from the persisted job history (a
	// running/recent gateway job keeps the cluster alive). Limitation:
	// interactive Ray Client / Dask sessions submit no gateway jobs, so
	// their activity is invisible to this signal — an interactive-only
	// cluster looks idle from creation.
	IdleTimeoutSecs *uint64 `json:"idle_timeout_secs"`
	// Owner is the authenticated owner of this cluster (tier-2 owned
	// session clusters): the human identity that requested it — a
	// preferred_username when the OIDC token carries one, else the sub.
	// Set control-plane-side from the request identity (never trusted
	// from the client body); nil for clusters created without an owner
	// (e.g. admin/service paths).
	Owner *string `json:"owner"`
	// Profile is the profile catalog name (#7) whose shape fills this
	// spec's zero-valued shape fields at admission; nil = none.
	Profile *string `json:"profile"`
	// Environment is the environment catalog name (#52) whose image,
	// packages and env vars this cluster runs with; nil = none. Resolved
	// against the catalog at admission into EnvironmentResolved (#55).
	Environment *string `json:"environment"`
	// EnvironmentResolved is the server-computed resolution of Environment
	// against the catalog at admission time (never retroactive). Persisted,
	// never echoed: ClusterView carries no spec.
	//
	// Limitation: Ray has no cluster-level runtime_env on the RayCluster
	// CR, so a cluster's resolution cannot be actuated on the cluster
	// itself. It is persisted as the cluster-wide default the
	// job-submission path applies to jobs submitted to this cluster
	// (epic 2026-09-12-governed-environments, Issue 4 design note);
	// interactive Ray Client sessions carry no runtime_env of Bifrost's at
	// all.
	EnvironmentResolved *ResolvedEnvironment `json:"environment_resolved,omitempty"`
	// Storage names storage catalog entries (#12) delivered to the
	// cluster's pods. Names only — the catalog is resolved server-side
	// into StorageResolved.
	Storage []string `json:"storage"`
	// StorageResolved is the server-computed resolution of Storage against
	// the catalog at admission time (never retroactive). Persisted, never
	// echoed: ClusterView carries no spec.
	StorageResolved []ResolvedStorage `json:"storage_resolved,omitempty"`
}

// clusterSpecAlias breaks the recursion Unmarshal/MarshalJSON would
// otherwise cause by re-entering ClusterSpec's own methods.
type clusterSpecAlias ClusterSpec

// UnmarshalJSON applies Engine's #[serde(default)] behavior: a ClusterSpec
// whose `engine` key is absent from the JSON object deserializes as
// EngineRay, exactly like the Rust reference.
func (c *ClusterSpec) UnmarshalJSON(data []byte) error {
	aux := (*clusterSpecAlias)(c)
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if aux.Engine == "" {
		aux.Engine = DefaultEngine
	}
	return nil
}

// MarshalJSON is UnmarshalJSON's symmetric counterpart: a zero-value
// Engine (a ClusterSpec built as a Go struct literal without setting
// Engine, never having round-tripped through UnmarshalJSON) would
// otherwise marshal as `"engine":""`, which the frozen OpenAPI contract's
// Engine enum schema rejects. WorkerGroups and Storage get the same "nil
// is not a valid Vec" treatment as AuditEvent.GrantedRoles (nil -> `[]`,
// never `null`).
func (c ClusterSpec) MarshalJSON() ([]byte, error) {
	a := clusterSpecAlias(c)
	if a.Engine == "" {
		a.Engine = DefaultEngine
	}
	if a.WorkerGroups == nil {
		a.WorkerGroups = []WorkerGroup{}
	}
	if a.Storage == nil {
		a.Storage = []string{}
	}
	return json.Marshal(a)
}

// WorkerGroup is a homogeneous group of Ray worker nodes.
//
// Autoscaling in v0 is actuated exclusively through these replica bounds,
// which translate to KubeRay worker-group fields — never by reading demand
// from GCS (ADR-0002).
type WorkerGroup struct {
	Name        string  `json:"name"`
	Cpu         string  `json:"cpu"`
	Memory      string  `json:"memory"`
	Gpu         *string `json:"gpu"`
	MinReplicas uint32  `json:"min_replicas"`
	MaxReplicas uint32  `json:"max_replicas"`
	Replicas    uint32  `json:"replicas"`
}

// ClusterState is a lifecycle state of a managed cluster (PLAN.md §3.1).
type ClusterState string

const (
	ClusterStatePending      ClusterState = "pending"
	ClusterStateProvisioning ClusterState = "provisioning"
	ClusterStateRunning      ClusterState = "running"
	ClusterStateDegraded     ClusterState = "degraded"
	ClusterStateUpdating     ClusterState = "updating"
	ClusterStateSuspending   ClusterState = "suspending"
	ClusterStateSuspended    ClusterState = "suspended"
	ClusterStateTerminating  ClusterState = "terminating"
	ClusterStateTerminated   ClusterState = "terminated"
)

func (s ClusterState) isValid() bool {
	switch s {
	case ClusterStatePending, ClusterStateProvisioning, ClusterStateRunning,
		ClusterStateDegraded, ClusterStateUpdating, ClusterStateSuspending,
		ClusterStateSuspended, ClusterStateTerminating, ClusterStateTerminated:
		return true
	}
	return false
}

// String returns the wire value (snake_case).
func (s ClusterState) String() string { return string(s) }

// UnmarshalJSON rejects any value other than the known ClusterState
// variants, mirroring serde's strict enum deserialization.
func (s *ClusterState) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	cs := ClusterState(v)
	if !cs.isValid() {
		return fmt.Errorf("core: invalid ClusterState %q", v)
	}
	*s = cs
	return nil
}

// DriftCondition is a drift/health condition the reconcile engine raises,
// distinct from the observed ClusterState: it records *why* a cluster
// diverges from desired so the control plane alarms instead of silently
// converging (ADR-0004: drift raises alarms, never a silent stomp).
type DriftCondition string

const (
	// DriftConditionSpecDrift: the observed spec diverges from desired at
	// the same generation — an out-of-band edit of a Bifrost-owned field.
	DriftConditionSpecDrift DriftCondition = "spec_drift"
	// DriftConditionDegraded: observed Degraded while desired Running —
	// the cluster is unhealthy for runtime reasons, so re-applying the
	// unchanged spec cannot repair it — surfaced as an alarm rather than
	// a re-apply hot loop.
	DriftConditionDegraded DriftCondition = "degraded"
)

func (d DriftCondition) isValid() bool {
	switch d {
	case DriftConditionSpecDrift, DriftConditionDegraded:
		return true
	}
	return false
}

// String returns the wire value (snake_case).
func (d DriftCondition) String() string { return string(d) }

// UnmarshalJSON rejects any value other than the known DriftCondition
// variants, mirroring serde's strict enum deserialization.
func (d *DriftCondition) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	dc := DriftCondition(v)
	if !dc.isValid() {
		return fmt.Errorf("core: invalid DriftCondition %q", v)
	}
	*d = dc
	return nil
}

// TransitionError reports an illegal cluster state transition. A value
// type, like the package's other nine error types (mirrors Rust's
// thiserror struct-error, which is Copy/Eq over plain fields, not a
// pointer).
type TransitionError struct {
	From ClusterState
	To   ClusterState
}

// clusterStateRustDebug renders a ClusterState the way Rust's derived
// Debug renders the enum: the PascalCase variant name (Pending, Running,
// …), not the snake_case wire value ClusterState.String() returns.
// TransitionError's Rust Display impl is `{from:?} -> {to:?}`, i.e. Debug
// formatting of the enum, so message fidelity requires this instead of the
// wire form.
func clusterStateRustDebug(s ClusterState) string {
	switch s {
	case ClusterStatePending:
		return "Pending"
	case ClusterStateProvisioning:
		return "Provisioning"
	case ClusterStateRunning:
		return "Running"
	case ClusterStateDegraded:
		return "Degraded"
	case ClusterStateUpdating:
		return "Updating"
	case ClusterStateSuspending:
		return "Suspending"
	case ClusterStateSuspended:
		return "Suspended"
	case ClusterStateTerminating:
		return "Terminating"
	case ClusterStateTerminated:
		return "Terminated"
	}
	return string(s)
}

func (e TransitionError) Error() string {
	return fmt.Sprintf("invalid cluster state transition: %s -> %s",
		clusterStateRustDebug(e.From), clusterStateRustDebug(e.To))
}

// CanTransitionTo reports whether self -> next is a legal transition for a
// user-issued lifecycle command against desired state (e.g. you cannot ask
// a Terminated cluster to Suspend).
//
// Never apply this to observed state: observed reality is not validated,
// it is recorded (ADR-0006). Reconcilers reconstruct status from
// observation; drift is a Condition, not an error.
func (s ClusterState) CanTransitionTo(next ClusterState) bool {
	switch s {
	case ClusterStatePending:
		switch next {
		case ClusterStateProvisioning, ClusterStateTerminating:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateProvisioning:
		switch next {
		case ClusterStateRunning, ClusterStateDegraded, ClusterStateTerminating:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateRunning:
		switch next {
		case ClusterStateDegraded, ClusterStateUpdating, ClusterStateSuspending, ClusterStateTerminating:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateDegraded:
		switch next {
		case ClusterStateRunning, ClusterStateTerminating:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateUpdating:
		switch next {
		case ClusterStateRunning, ClusterStateDegraded:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateSuspending:
		switch next {
		case ClusterStateSuspended:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateSuspended:
		switch next {
		case ClusterStateProvisioning, ClusterStateTerminating:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateTerminating:
		switch next {
		case ClusterStateTerminated:
			return true
		default: // membership test; the outer switch is the exhaustive state guard
			return false
		}
	case ClusterStateTerminated:
		return false
	}
	return false
}

// Transition attempts self -> to, returning the new state or a
// TransitionError when the transition is illegal.
func (s ClusterState) Transition(to ClusterState) (ClusterState, error) {
	if s.CanTransitionTo(to) {
		return to, nil
	}
	return s, TransitionError{From: s, To: to}
}

// IsTerminal reports whether the state never leaves via reconciliation.
func (s ClusterState) IsTerminal() bool {
	return s == ClusterStateTerminated
}
