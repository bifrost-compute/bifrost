package controller

// Deep-copy helpers for MemoryStore.
//
// Fix round 1 (review of commit 23055b9): MemoryStore's methods were
// storing/returning pointer- and container-typed fields (slices, maps,
// *T) by shallow copy, which aliases caller memory into the mutex-guarded
// store state in both directions. A caller mutating a struct after
// passing it to an Upsert/Record/Create method could silently corrupt
// stored state; a caller mutating a struct returned from a Get/List
// method could do the same in reverse. The sharpest instance: mutating a
// core.AuditEvent after RecordAudit changes the stored row's payload
// without touching its already-computed ChainHash, so a later
// VerifyAuditChain reports a spurious tamper — the exact failure mode the
// chain exists to detect, self-inflicted by an aliasing bug rather than a
// real tamper.
//
// Every helper below is explicit (no reflection): each container-typed
// field of a stored/returned type gets its own clone call. clonePtr is a
// small generic helper for scalar/plain-struct pointer fields (no nested
// pointers/slices/maps of their own — true for every *T field on the
// types below, including core.AuditRequired, whose two fields are plain
// strings).

import "github.com/bifrost-compute/bifrost/internal/core"

// clonePtr returns a new pointer to a copy of *p, or nil if p is nil. Only
// safe for T with no nested pointer/slice/map fields of its own — every
// call site below satisfies that (strings, unsigned integers, enum
// string/int types, and core.AuditRequired, which is two plain strings).
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneFloatMap(m map[string]float64) map[string]float64 {
	if m == nil {
		return nil
	}
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneTaints(t []core.TaintSpec) []core.TaintSpec {
	if t == nil {
		return nil
	}
	// core.TaintSpec is three plain strings — no nested pointers/maps/
	// slices — so a shallow element copy is already a full deep copy.
	out := make([]core.TaintSpec, len(t))
	copy(out, t)
	return out
}

func cloneWorkerGroup(w core.WorkerGroup) core.WorkerGroup {
	w.Gpu = clonePtr(w.Gpu)
	return w
}

func cloneWorkerGroups(gs []core.WorkerGroup) []core.WorkerGroup {
	if gs == nil {
		return nil
	}
	out := make([]core.WorkerGroup, len(gs))
	for i, g := range gs {
		out[i] = cloneWorkerGroup(g)
	}
	return out
}

func cloneResolvedStorage(rs []core.ResolvedStorage) []core.ResolvedStorage {
	if rs == nil {
		return nil
	}
	out := make([]core.ResolvedStorage, len(rs))
	for i, r := range rs {
		r.MountPath = clonePtr(r.MountPath)
		out[i] = r
	}
	return out
}

// cloneClusterSpec deep-copies a core.ClusterSpec's container/pointer
// fields: WorkerGroups (and each group's Gpu pointer), TtlSeconds,
// IdleTimeoutSecs, Owner, Profile, Storage, StorageResolved.
func cloneClusterSpec(s core.ClusterSpec) core.ClusterSpec {
	s.WorkerGroups = cloneWorkerGroups(s.WorkerGroups)
	s.TtlSeconds = clonePtr(s.TtlSeconds)
	s.IdleTimeoutSecs = clonePtr(s.IdleTimeoutSecs)
	s.Owner = clonePtr(s.Owner)
	s.Profile = clonePtr(s.Profile)
	s.Storage = cloneStringSlice(s.Storage)
	s.StorageResolved = cloneResolvedStorage(s.StorageResolved)
	return s
}

// cloneServiceSpec deep-copies a core.ServiceSpec's container fields:
// Storage and StorageResolved (everything else is plain scalars).
func cloneServiceSpec(s core.ServiceSpec) core.ServiceSpec {
	s.Storage = cloneStringSlice(s.Storage)
	s.StorageResolved = cloneResolvedStorage(s.StorageResolved)
	return s
}

// cloneRayJobSpec deep-copies a core.RayJobSpec's container/pointer
// fields: WorkerGroups, Profile, Storage, StorageResolved,
// TtlSecondsAfterFinished, Owner.
func cloneRayJobSpec(s core.RayJobSpec) core.RayJobSpec {
	s.WorkerGroups = cloneWorkerGroups(s.WorkerGroups)
	s.Profile = clonePtr(s.Profile)
	s.Storage = cloneStringSlice(s.Storage)
	s.StorageResolved = cloneResolvedStorage(s.StorageResolved)
	s.TtlSecondsAfterFinished = clonePtr(s.TtlSecondsAfterFinished)
	s.Owner = clonePtr(s.Owner)
	return s
}

// cloneStoredService deep-copies a StoredService's Spec plus its
// Owner/ObservedState/ObservedURL/TerminatedAt pointers.
func cloneStoredService(s StoredService) StoredService {
	s.Spec = cloneServiceSpec(s.Spec)
	s.Owner = clonePtr(s.Owner)
	s.ObservedState = clonePtr(s.ObservedState)
	s.ObservedURL = clonePtr(s.ObservedURL)
	s.TerminatedAt = clonePtr(s.TerminatedAt)
	return s
}

// cloneStoredRayJob deep-copies a StoredRayJob's Spec plus its six pointer
// fields.
func cloneStoredRayJob(j StoredRayJob) StoredRayJob {
	j.Spec = cloneRayJobSpec(j.Spec)
	j.Owner = clonePtr(j.Owner)
	j.ClusterName = clonePtr(j.ClusterName)
	j.DashboardURL = clonePtr(j.DashboardURL)
	j.Message = clonePtr(j.Message)
	j.StartedAt = clonePtr(j.StartedAt)
	j.FinishedAt = clonePtr(j.FinishedAt)
	return j
}

// cloneRayJobObservation deep-copies a RayJobObservation's five pointer
// fields (ingress side of RecordRayJobObservation).
func cloneRayJobObservation(o RayJobObservation) RayJobObservation {
	o.ClusterName = clonePtr(o.ClusterName)
	o.DashboardURL = clonePtr(o.DashboardURL)
	o.Message = clonePtr(o.Message)
	o.StartedAt = clonePtr(o.StartedAt)
	o.FinishedAt = clonePtr(o.FinishedAt)
	return o
}

func cloneFlavorSpec(f core.FlavorSpec) core.FlavorSpec {
	f.Resources = cloneStringMap(f.Resources)
	f.NodeLabels = cloneStringMap(f.NodeLabels)
	f.Taints = cloneTaints(f.Taints)
	return f
}

func cloneFlavorSpecs(fs []core.FlavorSpec) []core.FlavorSpec {
	if fs == nil {
		return nil
	}
	out := make([]core.FlavorSpec, len(fs))
	for i, f := range fs {
		out[i] = cloneFlavorSpec(f)
	}
	return out
}

// clonePoolSpec deep-copies a core.PoolSpec's container/pointer fields:
// Flavors (and each flavor's Resources/NodeLabels/Taints) and GpuSharing.
func clonePoolSpec(p core.PoolSpec) core.PoolSpec {
	p.Flavors = cloneFlavorSpecs(p.Flavors)
	p.GpuSharing = clonePtr(p.GpuSharing)
	return p
}

// cloneAllocationSpec deep-copies a core.AllocationSpec's three map
// fields.
func cloneAllocationSpec(a core.AllocationSpec) core.AllocationSpec {
	a.Nominal = cloneStringMap(a.Nominal)
	a.BorrowingLimit = cloneStringMap(a.BorrowingLimit)
	a.LendingLimit = cloneStringMap(a.LendingLimit)
	return a
}

func cloneQuotas(m map[string]map[string]float64) map[string]map[string]float64 {
	if m == nil {
		return nil
	}
	out := make(map[string]map[string]float64, len(m))
	for k, v := range m {
		out[k] = cloneFloatMap(v)
	}
	return out
}

func cloneStoredBudget(b StoredBudget) StoredBudget {
	b.Limits = cloneFloatMap(b.Limits)
	return b
}

func cloneBudgets(m map[string]StoredBudget) map[string]StoredBudget {
	if m == nil {
		return nil
	}
	out := make(map[string]StoredBudget, len(m))
	for k, v := range m {
		out[k] = cloneStoredBudget(v)
	}
	return out
}

func cloneProfiles(ps []core.Profile) []core.Profile {
	if ps == nil {
		return nil
	}
	out := make([]core.Profile, len(ps))
	for i, p := range ps {
		p.Description = clonePtr(p.Description)
		p.WorkerGroups = cloneWorkerGroups(p.WorkerGroups)
		p.MaxWorkers = clonePtr(p.MaxWorkers)
		p.TtlSeconds = clonePtr(p.TtlSeconds)
		p.IdleTimeoutSecs = clonePtr(p.IdleTimeoutSecs)
		p.Projects = cloneStringSlice(p.Projects)
		out[i] = p
	}
	return out
}

func cloneAdmission(m map[string]core.AdmissionRule) map[string]core.AdmissionRule {
	if m == nil {
		return nil
	}
	out := make(map[string]core.AdmissionRule, len(m))
	for k, v := range m {
		v.AllowedImages = cloneStringSlice(v.AllowedImages)
		v.PackageDenylist = cloneStringSlice(v.PackageDenylist)
		v.AllowedIndexHosts = cloneStringSlice(v.AllowedIndexHosts)
		v.AllowedRemoteSchemes = cloneStringSlice(v.AllowedRemoteSchemes)
		v.AllowedRemoteHosts = cloneStringSlice(v.AllowedRemoteHosts)
		out[k] = v
	}
	return out
}

func cloneStorageEntries(es []core.StorageEntry) []core.StorageEntry {
	if es == nil {
		return nil
	}
	out := make([]core.StorageEntry, len(es))
	for i, e := range es {
		e.MountPath = clonePtr(e.MountPath)
		e.Projects = cloneStringSlice(e.Projects)
		out[i] = e
	}
	return out
}

func cloneEnvironments(es []core.Environment) []core.Environment {
	if es == nil {
		return nil
	}
	out := make([]core.Environment, len(es))
	for i, e := range es {
		e.Description = clonePtr(e.Description)
		e.Packages = cloneStringSlice(e.Packages)
		e.EnvVars = cloneStringMap(e.EnvVars)
		e.Projects = cloneStringSlice(e.Projects)
		e.PublishedBy = clonePtr(e.PublishedBy)
		e.PublishedAt = clonePtr(e.PublishedAt)
		if e.Scan != nil {
			scan := *e.Scan
			scan.Scanner = clonePtr(scan.Scanner)
			scan.ScannedAt = clonePtr(scan.ScannedAt)
			e.Scan = &scan
		}
		out[i] = e
	}
	return out
}

// cloneStoredPolicy deep-copies a StoredPolicy's Prices/Quotas/Budgets
// maps (Budgets nested one level further, into each StoredBudget's
// Limits) and its Profiles/Admission/Storage/Environments catalogs.
func cloneStoredPolicy(p StoredPolicy) StoredPolicy {
	p.Prices = cloneFloatMap(p.Prices)
	p.Quotas = cloneQuotas(p.Quotas)
	p.Budgets = cloneBudgets(p.Budgets)
	p.Profiles = cloneProfiles(p.Profiles)
	p.Admission = cloneAdmission(p.Admission)
	p.Storage = cloneStorageEntries(p.Storage)
	p.Environments = cloneEnvironments(p.Environments)
	p.Images = cloneImageEntries(p.Images)
	return p
}

func cloneImageEntries(in []core.ImageEntry) []core.ImageEntry {
	if in == nil {
		return nil
	}
	out := make([]core.ImageEntry, len(in))
	for i, e := range in {
		e.Description = clonePtr(e.Description)
		e.Projects = cloneStringSlice(e.Projects)
		out[i] = e
	}
	return out
}

// cloneAuditEvent deep-copies a core.AuditEvent's nine pointer fields and
// its GrantedRoles slice — see docs/adr/0004-audit-chain-format.md for
// why this type's exact field set/shape matters, and the package doc
// comment above for why cloning it matters for the hash chain
// specifically.
func cloneAuditEvent(e core.AuditEvent) core.AuditEvent {
	e.Subject = clonePtr(e.Subject)
	e.Reason = clonePtr(e.Reason)
	e.Action = clonePtr(e.Action)
	e.Cluster = clonePtr(e.Cluster)
	e.Method = clonePtr(e.Method)
	e.Path = clonePtr(e.Path)
	e.Status = clonePtr(e.Status)
	e.LatencyMs = clonePtr(e.LatencyMs)
	e.Required = clonePtr(e.Required)
	e.GrantedRoles = cloneStringSlice(e.GrantedRoles)
	return e
}

func cloneLocalUserRecord(u core.LocalUserRecord) core.LocalUserRecord {
	u.Email = clonePtr(u.Email)
	u.LockedUntil = clonePtr(u.LockedUntil)
	return u
}

func cloneApiTokenRecord(t core.ApiTokenRecord) core.ApiTokenRecord {
	t.LastUsedAt = clonePtr(t.LastUsedAt)
	return t
}

// cloneJobRecord deep-copies a core.JobRecord's DurationSecs pointer.
func cloneJobRecord(j core.JobRecord) core.JobRecord {
	j.DurationSecs = clonePtr(j.DurationSecs)
	return j
}

// cloneIntentRecord deep-copies an IntentRecord's ResponseJSON/CompletedAt
// pointers. Note: CompleteIntent itself needs no ingress clone — it takes
// responseJSON by value (string) and computes CompletedAt from a local
// NowUnix() call, so the pointers it stores are already self-owned, never
// aliasing a caller's memory. This clone exists for GetIntent's egress
// side: the map lookup there returns a shallow copy whose ResponseJSON/
// CompletedAt pointers still alias the stored record's.
func cloneIntentRecord(r IntentRecord) IntentRecord {
	r.ResponseJSON = clonePtr(r.ResponseJSON)
	r.CompletedAt = clonePtr(r.CompletedAt)
	return r
}

// cloneStoredCluster deep-copies a StoredCluster's Spec plus its
// ObservedState/Condition/TerminatedAt pointers.
func cloneStoredCluster(c StoredCluster) StoredCluster {
	c.Spec = cloneClusterSpec(c.Spec)
	c.ObservedState = clonePtr(c.ObservedState)
	c.Condition = clonePtr(c.Condition)
	c.TerminatedAt = clonePtr(c.TerminatedAt)
	return c
}

// cloneStoredPool deep-copies a StoredPool's Spec plus its
// ObservedJSON/ObservedAt pointers.
func cloneStoredPool(p StoredPool) StoredPool {
	p.Spec = clonePoolSpec(p.Spec)
	p.ObservedJSON = clonePtr(p.ObservedJSON)
	p.ObservedAt = clonePtr(p.ObservedAt)
	return p
}
