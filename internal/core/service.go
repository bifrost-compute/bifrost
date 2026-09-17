package core

import (
	"encoding/json"
	"fmt"
)

// Ray Serve service domain model. A "service" is a long-lived Serve
// application; on KubeRay it maps to a RayService CR (which wraps a Ray
// cluster + the Serve config and handles zero-downtime upgrades).

// UpgradeStrategy is how to roll out a new version of a service.
type UpgradeStrategy string

const (
	// UpgradeStrategyCanary: KubeRay stands up a new cluster,
	// health-checks it, then switches traffic (zero-downtime; safe
	// rollback if the new version is unhealthy). Maps to RayService
	// upgradeStrategy: NewCluster.
	UpgradeStrategyCanary UpgradeStrategy = "canary"
	// UpgradeStrategyInPlace: update the existing cluster's Serve config.
	// Maps to RayService upgradeStrategy: None.
	UpgradeStrategyInPlace UpgradeStrategy = "in_place"
)

// DefaultUpgradeStrategy is the strategy used when a ServiceSpec's
// `upgrade` field is absent from JSON input.
const DefaultUpgradeStrategy = UpgradeStrategyCanary

func (u UpgradeStrategy) isValid() bool {
	switch u {
	case UpgradeStrategyCanary, UpgradeStrategyInPlace:
		return true
	}
	return false
}

// UnmarshalJSON rejects any value other than the known UpgradeStrategy
// variants, mirroring serde's strict enum deserialization.
func (u *UpgradeStrategy) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v := UpgradeStrategy(s)
	if !v.isValid() {
		return fmt.Errorf("core: invalid UpgradeStrategy %q", s)
	}
	*u = v
	return nil
}

// ServiceSpec is the declarative spec for a managed Serve service.
type ServiceSpec struct {
	Name       string `json:"name"`
	Project    string `json:"project"`
	RayVersion string `json:"ray_version"`
	Image      string `json:"image"`
	// ServeConfigV2 is the Serve application config (KubeRay
	// serveConfigV2), passed through verbatim as a YAML string — Bifrost
	// does not interpret it.
	ServeConfigV2 string `json:"serve_config_v2"`
	HeadCpu       string `json:"head_cpu"`
	HeadMemory    string `json:"head_memory"`
	// WorkerReplicas are the fixed worker replicas backing the service
	// (autoscaling of Serve deployments is Ray Serve's own concern).
	WorkerReplicas uint32          `json:"worker_replicas"`
	WorkerCpu      string          `json:"worker_cpu"`
	WorkerMemory   string          `json:"worker_memory"`
	Upgrade        UpgradeStrategy `json:"upgrade"`
	// Storage names storage catalog entries (#12) delivered to the
	// service's pods. Names only — the catalog is resolved server-side
	// into StorageResolved.
	Storage []string `json:"storage"`
	// StorageResolved is the server-computed resolution of Storage against
	// the catalog at admission time (never retroactive). Persisted, never
	// echoed: ServiceView carries no spec.
	StorageResolved []ResolvedStorage `json:"storage_resolved,omitempty"`
	// ServiceAccountResolved is the Kubernetes ServiceAccount the workload's
	// pods run under (#20), resolved from the policy's workload_identity
	// rules for the project at admission and persisted so a later rule
	// edit is never retroactive. nil = the namespace default (no rule).
	// Never echoed: views carry no spec.
	ServiceAccountResolved *string `json:"service_account_resolved,omitempty"`
}

// serviceSpecAlias breaks the recursion Unmarshal/MarshalJSON would
// otherwise cause by re-entering ServiceSpec's own methods.
type serviceSpecAlias ServiceSpec

// UnmarshalJSON applies Upgrade's #[serde(default = "default_upgrade")]
// behavior: a ServiceSpec whose `upgrade` key is absent from the JSON
// object deserializes as UpgradeStrategyCanary, exactly like the Rust
// reference.
func (s *ServiceSpec) UnmarshalJSON(data []byte) error {
	aux := (*serviceSpecAlias)(s)
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if aux.Upgrade == "" {
		aux.Upgrade = DefaultUpgradeStrategy
	}
	return nil
}

// MarshalJSON is UnmarshalJSON's symmetric counterpart: a zero-value
// Upgrade (a ServiceSpec built as a Go struct literal without setting
// Upgrade) would otherwise marshal as `"upgrade":""`, which the frozen
// OpenAPI contract's UpgradeStrategy enum schema rejects. Storage gets the
// package's "nil is not a valid Vec" treatment (nil -> `[]`, never `null`).
func (s ServiceSpec) MarshalJSON() ([]byte, error) {
	a := serviceSpecAlias(s)
	if a.Upgrade == "" {
		a.Upgrade = DefaultUpgradeStrategy
	}
	if a.Storage == nil {
		a.Storage = []string{}
	}
	return json.Marshal(a)
}
