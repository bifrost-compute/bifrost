package core

import (
	"encoding/json"
	"fmt"
)

// Governance catalogs that ride the policy row (plan ruling D7): the
// profile catalog and per-project admission rules (requirement 7), the
// private-storage catalog (requirement 12), and the pool purpose
// discriminator (requirement 4). Pure data — validation of catalog
// contents as a unit is the policy/API edge's job.

// --- Pool purpose (#4) ---

// PoolPurpose is what a pool's capacity is for. Compute pools admit
// interactive clusters and jobs; serving pools admit only
// RayService-backed services, so long-lived serving replicas never
// compete with notebooks for the same queue.
type PoolPurpose string

const (
	PoolPurposeCompute PoolPurpose = "compute"
	PoolPurposeServing PoolPurpose = "serving"
)

// DefaultPoolPurpose is the purpose a PoolSpec has when its `purpose` key
// is absent from JSON input (or left zero-valued in a Go struct literal):
// every pre-#4 pool is a compute pool.
const DefaultPoolPurpose = PoolPurposeCompute

func (p PoolPurpose) isValid() bool {
	switch p {
	case PoolPurposeCompute, PoolPurposeServing:
		return true
	}
	return false
}

// String returns the wire value ("compute" | "serving").
func (p PoolPurpose) String() string { return string(p) }

// OrDefault maps the zero value onto DefaultPoolPurpose so a spec built as
// a struct literal and one round-tripped through JSON compare equal.
func (p PoolPurpose) OrDefault() PoolPurpose {
	if p == "" {
		return DefaultPoolPurpose
	}
	return p
}

// UnmarshalJSON rejects any value other than the known PoolPurpose
// variants, mirroring serde's strict enum deserialization.
func (p *PoolPurpose) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v := PoolPurpose(s)
	if !v.isValid() {
		return fmt.Errorf("core: invalid PoolPurpose %q", s)
	}
	*p = v
	return nil
}

// --- Private storage catalog (#12) ---

// StorageMode is how a storage entry's source reaches the pods: env
// injects every Secret key as an environment variable; file mounts the
// source at the entry's MountPath (read-only for a Secret, read-write for
// a PersistentVolumeClaim).
type StorageMode string

const (
	StorageModeEnv  StorageMode = "env"
	StorageModeFile StorageMode = "file"
)

func (m StorageMode) isValid() bool {
	switch m {
	case StorageModeEnv, StorageModeFile:
		return true
	}
	return false
}

// String returns the wire value ("env" | "file").
func (m StorageMode) String() string { return string(m) }

// UnmarshalJSON rejects any value other than the known StorageMode
// variants, mirroring serde's strict enum deserialization.
func (m *StorageMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v := StorageMode(s)
	if !v.isValid() {
		return fmt.Errorf("core: invalid StorageMode %q", s)
	}
	*m = v
	return nil
}

// StorageSource is what backs a storage entry: a Kubernetes Secret in the
// workload namespace (the original #12 source, delivered as env vars or a
// file mount) or a PersistentVolumeClaim in the workload namespace. The
// volume source is file-mode only — a volume has no keys to inject as
// environment variables.
type StorageSource string

const (
	StorageSourceSecret                StorageSource = "secret"
	StorageSourcePersistentVolumeClaim StorageSource = "persistent_volume_claim"
)

// DefaultStorageSource is the source a StorageEntry has when its `source`
// key is absent from JSON input: every pre-volume entry is a Secret entry.
const DefaultStorageSource = StorageSourceSecret

func (s StorageSource) isValid() bool {
	switch s {
	case StorageSourceSecret, StorageSourcePersistentVolumeClaim:
		return true
	}
	return false
}

// String returns the wire value ("secret" | "persistent_volume_claim").
func (s StorageSource) String() string { return string(s) }

// OrDefault maps the zero value onto DefaultStorageSource so an entry
// written before volume sources existed and one written with
// "source":"secret" compare equal.
func (s StorageSource) OrDefault() StorageSource {
	if s == "" {
		return DefaultStorageSource
	}
	return s
}

// UnmarshalJSON rejects any value other than the known StorageSource
// variants, mirroring the other strict catalog enums.
func (s *StorageSource) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	src := StorageSource(v)
	if !src.isValid() {
		return fmt.Errorf("core: invalid StorageSource %q", v)
	}
	*s = src
	return nil
}

// StorageEntry is a catalog entry for private storage: a Secret or
// PersistentVolumeClaim Bifrost delivers to the pods of any cluster, job
// or service whose spec names this entry in its `storage` list. The API
// only ever sees names and paths; a Secret's contents never cross it.
type StorageEntry struct {
	// Name is the catalog name a spec refers to.
	Name string `json:"name"`
	// Source is what backs the entry; absent in JSON = secret.
	Source StorageSource `json:"source,omitempty"`
	// SecretName is the Kubernetes Secret in the workload namespace
	// (secret source only).
	SecretName string `json:"secret_name,omitempty"`
	// ClaimName is the PersistentVolumeClaim in the workload namespace
	// (persistent_volume_claim source only). Claims are namespace-local:
	// the claim must live where the pods run.
	ClaimName string      `json:"claim_name,omitempty"`
	Mode      StorageMode `json:"mode"`
	// MountPath is the mount point inside the pods (StorageModeFile
	// only); nil for env mode.
	MountPath *string `json:"mount_path"`
	// Projects that may reference this entry; empty = every project.
	Projects []string `json:"projects"`
}

// storageEntryAlias breaks the recursion MarshalJSON would otherwise cause
// by re-entering StorageEntry's own MarshalJSON.
type storageEntryAlias StorageEntry

// MarshalJSON substitutes an empty slice for a nil Projects (nil is not a
// valid Vec: `[]`, never `null`).
func (e StorageEntry) MarshalJSON() ([]byte, error) {
	a := storageEntryAlias(e)
	if a.Projects == nil {
		a.Projects = []string{}
	}
	return json.Marshal(a)
}

// ResolvedStorage is one Storage name resolved against the catalog at
// admission time: the delivery instructions the provisioner needs, and
// nothing the API should echo. Persisted on the spec so a later catalog
// edit is never retroactive (the predecessor's pod-shaping rule). The
// source fields are omitempty so a resolution persisted before volume
// sources existed keeps its exact shape.
type ResolvedStorage struct {
	Name       string        `json:"name"`
	Source     StorageSource `json:"source,omitempty"`
	SecretName string        `json:"secret_name"`
	ClaimName  string        `json:"claim_name,omitempty"`
	Mode       StorageMode   `json:"mode"`
	MountPath  *string       `json:"mount_path"`
}

// --- Workload identity (#20) ---

// WorkloadKind is which of the three Ray submission paths a pod template
// belongs to. The workload-identity rule may name a distinct
// ServiceAccount per kind, because the cloud IAM role an interactive
// notebook cluster needs (read datasets) is rarely the one a batch job
// (write results) or a Serve deployment (read models, serve) needs.
type WorkloadKind string

const (
	// WorkloadInteractive is a self-serve RayCluster (requirement 6).
	WorkloadInteractive WorkloadKind = "interactive"
	// WorkloadJob is an ephemeral RayJob and its submitter (requirement 5).
	WorkloadJob WorkloadKind = "job"
	// WorkloadServing is a group RayService (requirements 1, 2, 4).
	WorkloadServing WorkloadKind = "serving"
)

// WorkloadIdentityRule is the per-project workload identity (#20): the
// Kubernetes ServiceAccount the pods of a project's clusters, jobs and
// services run under. Keyed by project (or "*" for every project) in the
// policy row, exactly like AdmissionRule.
//
// This is the seam a cloud IAM binding attaches to (EKS Pod Identity /
// IRSA, GKE Workload Identity, Azure workload identity): the platform
// binds an IAM role to the ServiceAccount, Bifrost only names it, and the
// pods obtain cloud credentials from the node's identity agent — no static
// credentials on the pod, none in the storage catalog, none through
// Bifrost. Submission identity (who asked — the audit row's subject) and
// workload identity (what the pods may reach) stay two separate decisions.
//
// Every field is optional. A kind-specific field wins for its kind; an
// empty one falls back to ServiceAccount; an empty ServiceAccount means
// the pods keep the namespace default (today's behaviour).
type WorkloadIdentityRule struct {
	// ServiceAccount is the default for every workload kind.
	ServiceAccount string `json:"service_account,omitempty"`
	// InteractiveServiceAccount overrides ServiceAccount for self-serve
	// clusters.
	InteractiveServiceAccount string `json:"interactive_service_account,omitempty"`
	// JobServiceAccount overrides ServiceAccount for ephemeral RayJobs
	// (the job's cluster pods AND its submitter pod).
	JobServiceAccount string `json:"job_service_account,omitempty"`
	// ServingServiceAccount overrides ServiceAccount for RayServices.
	ServingServiceAccount string `json:"serving_service_account,omitempty"`
}

// For returns the ServiceAccount the rule names for kind: the
// kind-specific field when set, else the default; "" when the rule has
// nothing to say for that kind.
func (r WorkloadIdentityRule) For(kind WorkloadKind) string {
	var specific string
	switch kind {
	case WorkloadInteractive:
		specific = r.InteractiveServiceAccount
	case WorkloadJob:
		specific = r.JobServiceAccount
	case WorkloadServing:
		specific = r.ServingServiceAccount
	}
	if specific != "" {
		return specific
	}
	return r.ServiceAccount
}

// IsZero reports whether the rule names nothing at all.
func (r WorkloadIdentityRule) IsZero() bool {
	return r == WorkloadIdentityRule{}
}

// --- Profile catalog and admission (#7) ---

// Profile is a named cluster shape in the profile catalog: the head/worker
// shape and image a cluster or job gets when its spec names this profile.
// Expansion (plan ruling D4) fills zero-valued shape fields and refuses
// conflicting non-empty ones.
type Profile struct {
	// Name is the catalog name a spec refers to (ClusterSpec.Profile,
	// RayJobSpec.Profile).
	Name string `json:"name"`
	// Description is a human-readable summary shown by clients; nil = none.
	Description  *string       `json:"description"`
	Image        string        `json:"image"`
	RayVersion   string        `json:"ray_version"`
	HeadCpu      string        `json:"head_cpu"`
	HeadMemory   string        `json:"head_memory"`
	WorkerGroups []WorkerGroup `json:"worker_groups"`
	// MaxWorkers caps total worker replicas for clusters using this
	// profile; nil = unlimited.
	MaxWorkers *uint32 `json:"max_workers"`
	// TtlSeconds is the default absolute max-age cap applied to clusters
	// using this profile; nil = none.
	TtlSeconds *uint64 `json:"ttl_seconds"`
	// IdleTimeoutSecs is the default inactivity reap window applied to
	// clusters using this profile; nil = none.
	IdleTimeoutSecs *uint64 `json:"idle_timeout_secs"`
	// Projects that may use this profile; empty = every project.
	Projects []string `json:"projects"`
	// Storage names storage catalog entries (#12) every cluster or job
	// from this profile mounts, on top of any the request names itself;
	// empty = none. Resolved against the project at create time exactly
	// like a request's own storage.
	Storage []string `json:"storage"`
}

// profileAlias breaks the recursion MarshalJSON would otherwise cause by
// re-entering Profile's own MarshalJSON.
type profileAlias Profile

// MarshalJSON substitutes empty slices for nil WorkerGroups/Projects (nil
// is not a valid Vec: `[]`, never `null`).
func (p Profile) MarshalJSON() ([]byte, error) {
	a := profileAlias(p)
	if a.WorkerGroups == nil {
		a.WorkerGroups = []WorkerGroup{}
	}
	if a.Projects == nil {
		a.Projects = []string{}
	}
	if a.Storage == nil {
		a.Storage = []string{}
	}
	return json.Marshal(a)
}

// AdmissionRule is a per-project admission limit. Both fields are
// optional; a zero value means unrestricted. Keyed by project (or "*" for
// every project) in the policy row.
type AdmissionRule struct {
	// AllowedImages are the container images a cluster/job in the project
	// may use; empty = any image.
	AllowedImages []string `json:"allowed_images"`
	// MaxWorkers is the maximum total worker replicas across all worker
	// groups; 0 = unlimited.
	MaxWorkers uint32 `json:"max_workers"`
	// CatalogOnly requires a cluster/job's image to be an image catalog
	// entry (#10) open to the project; false = the prefix allowlist alone
	// decides.
	CatalogOnly bool `json:"catalog_only,omitempty"`

	// The runtime-env governance knobs (#52) the #53 validator
	// (api.RuntimeEnvPolicy) hardcoded, carried here so they are
	// API-editable per project; the validator reads them through
	// api.runtimeEnvPolicyFor (#55). All zero values keep the governed
	// defaults.
	// AllowPyExecutable permits the py_executable field. Default deny.
	AllowPyExecutable bool `json:"allow_py_executable,omitempty"`
	// AllowImageURI permits the image_uri field. Default deny.
	AllowImageURI bool `json:"allow_image_uri,omitempty"`
	// AllowConda permits the conda field. Default deny.
	AllowConda bool `json:"allow_conda,omitempty"`
	// AllowUnpinnedPackages permits pip entries not pinned to an exact
	// version. Default deny.
	AllowUnpinnedPackages bool `json:"allow_unpinned_packages,omitempty"`
	// PackageDenylist holds PyPI-normalized package names (PEP 503) that
	// must never install, pinned or not.
	PackageDenylist []string `json:"package_denylist,omitempty"`
	// AllowedIndexHosts are the hosts pip_install_options may redirect
	// package indexes to; empty = no index redirection at all.
	AllowedIndexHosts []string `json:"allowed_index_hosts,omitempty"`
	// AllowedRemoteSchemes and AllowedRemoteHosts together permit remote
	// working_dir/py_modules URIs; both empty = local uploads only.
	AllowedRemoteSchemes []string `json:"allowed_remote_schemes,omitempty"`
	AllowedRemoteHosts   []string `json:"allowed_remote_hosts,omitempty"`
	// MaxSetupTimeoutSeconds caps config.setup_timeout_seconds; 0 = the
	// platform default.
	MaxSetupTimeoutSeconds int64 `json:"max_setup_timeout_seconds,omitempty"`
	// MaxDocumentBytes caps the raw runtime_env_yaml document size; 0 =
	// the platform default.
	MaxDocumentBytes int64 `json:"max_document_bytes,omitempty"`

	// RequireScannedEnvironments (#58) refuses every environment reference
	// in the project whose catalog entry carries no clean recorded scan
	// verdict: an absent (never scanned), pending or failed `scan` is a
	// 400 at admission. The verdict is a recorded field — the control
	// plane does not scan itself; an administrator sets it after running
	// the offline scan workflow (scripts/scan-environment.py). Default
	// off: any published environment is referenceable.
	RequireScannedEnvironments bool `json:"require_scanned_environments,omitempty"`
}

// admissionRuleAlias breaks the recursion MarshalJSON would otherwise
// cause by re-entering AdmissionRule's own MarshalJSON.
type admissionRuleAlias AdmissionRule

// MarshalJSON substitutes an empty slice for a nil AllowedImages (nil is
// not a valid Vec: `[]`, never `null`).
func (r AdmissionRule) MarshalJSON() ([]byte, error) {
	a := admissionRuleAlias(r)
	if a.AllowedImages == nil {
		a.AllowedImages = []string{}
	}
	return json.Marshal(a)
}
