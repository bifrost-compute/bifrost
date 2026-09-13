// Cluster lifecycle API (Phase 3). These are Bifrost's own routes (not the
// proxied Ray surface), so they enforce permissions against
// auth.TargetCluster per route (#26): reads need Read, create/terminate
// need Write — which Operator/Admin have and Developer does not.
//
// Handlers only manipulate *desired* state in the Store; the reconcile
// engine converges the actual KubeRay resources. Ported from the Rust predecessor's
// clusters.rs.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
)

// badRequest is the shared 400 constructor every T11 handler file uses for
// domain validation failures (invalid spec, invalid enum, ...).
func badRequest(msg string) error {
	return HTTPError{Status: http.StatusBadRequest, Code: "bad_request", Message: msg}
}

func notFound(msg string) error {
	return HTTPError{Status: http.StatusNotFound, Code: "not_found", Message: msg}
}

func conflict(msg string) error {
	return HTTPError{Status: http.StatusConflict, Code: "conflict", Message: msg}
}

// clusterSpecFromWire converts the generated wire ClusterSpec into
// core.ClusterSpec, validating the Engine enum and worker-group replica
// counts (the generated type's signed integers admit negatives the wire
// contract doesn't). Owner is left unset — CreateCluster stamps it from the
// authenticated identity, never trusting the client body (see
// core.ClusterSpec.Owner's doc comment).
func clusterSpecFromWire(w *ClusterSpec) (core.ClusterSpec, error) {
	engine := core.DefaultEngine
	if w.Engine != nil {
		switch *w.Engine {
		case Ray:
			engine = core.EngineRay
		case Dask:
			engine = core.EngineDask
		default:
			return core.ClusterSpec{}, badRequest(fmt.Sprintf("invalid engine %q", string(*w.Engine)))
		}
	}
	groups, err := workerGroupsFromWire(w.WorkerGroups)
	if err != nil {
		return core.ClusterSpec{}, err
	}
	var ttl, idle *uint64
	if w.TtlSeconds != nil {
		if *w.TtlSeconds < 0 {
			return core.ClusterSpec{}, badRequest("ttl_seconds must be non-negative")
		}
		v := uint64(*w.TtlSeconds)
		ttl = &v
	}
	if w.IdleTimeoutSecs != nil {
		if *w.IdleTimeoutSecs < 0 {
			return core.ClusterSpec{}, badRequest("idle_timeout_secs must be non-negative")
		}
		v := uint64(*w.IdleTimeoutSecs)
		idle = &v
	}
	// Storage names (requirement 12) are copied verbatim; CreateCluster
	// resolves them against the catalog after admission.
	var storage []string
	if w.Storage != nil {
		storage = append([]string(nil), (*w.Storage)...)
	}
	return core.ClusterSpec{
		Name:            w.Name,
		Project:         w.Project,
		Engine:          engine,
		RayVersion:      w.RayVersion,
		Image:           w.Image,
		HeadCpu:         w.HeadCpu,
		HeadMemory:      w.HeadMemory,
		WorkerGroups:    groups,
		TtlSeconds:      ttl,
		IdleTimeoutSecs: idle,
		Profile:         w.Profile,
		Environment:     w.Environment,
		Storage:         storage,
	}, nil
}

// validateClusterShape is the shape check the contract cannot express:
// every quantity parses as a Kubernetes quantity, every worker group's
// replica bounds are coherent, and the engine's startup minimums hold (for
// ray, the per-container memory floor — see policy.AdmitEngineMinimums).
// Shared by create_cluster and the profile catalog's PUT validation, so a
// profile can never define a shape a create would refuse.
func validateClusterShape(spec *core.ClusterSpec) error {
	if _, _, derr := policy.ClusterDemand(spec); derr != nil {
		return badRequest("invalid spec: " + derr.Error())
	}
	if merr := policy.AdmitEngineMinimums(spec); merr != nil {
		return badRequest("invalid spec: " + merr.Error())
	}
	for _, g := range spec.WorkerGroups {
		if g.MinReplicas > g.MaxReplicas || g.Replicas < g.MinReplicas || g.Replicas > g.MaxReplicas {
			return badRequest(fmt.Sprintf("invalid spec: worker group %q replicas=%d must lie within min_replicas=%d..max_replicas=%d",
				g.Name, g.Replicas, g.MinReplicas, g.MaxReplicas))
		}
	}
	return nil
}

func workerGroupsFromWire(in []WorkerGroup) ([]core.WorkerGroup, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]core.WorkerGroup, len(in))
	for i, g := range in {
		if g.MinReplicas < 0 || g.MaxReplicas < 0 || g.Replicas < 0 {
			return nil, badRequest(fmt.Sprintf("worker group %s: replica counts must be non-negative", g.Name))
		}
		out[i] = core.WorkerGroup{
			Name:        g.Name,
			Cpu:         g.Cpu,
			Memory:      g.Memory,
			Gpu:         g.Gpu,
			MinReplicas: uint32(g.MinReplicas),
			MaxReplicas: uint32(g.MaxReplicas),
			Replicas:    uint32(g.Replicas),
		}
	}
	return out, nil
}

// clusterView converts a StoredCluster (+ the effective price sheet, when
// configured) into the wire ClusterView. queue is the project's Kueue
// LocalQueue (nil = none) and gatewayURL the cluster's gateway address
// while registered (nil = not routable) — both resolved by the caller.
func clusterView(c *controller.StoredCluster, prices policy.PriceSheet, queue, gatewayURL *string) ClusterView {
	view := ClusterView{
		Id:                 c.ID.String(),
		Generation:         int64(c.Generation),
		Desired:            c.Desired.AsStr(),
		ObservedGeneration: int64(c.ObservedGeneration),
		Project:            c.Spec.Project,
		Engine:             c.Spec.Engine.String(),
		RayVersion:         c.Spec.RayVersion,
		Owner:              c.Spec.Owner,
		Queue:              queue,
		GatewayUrl:         gatewayURL,
	}
	if c.ObservedState != nil {
		v := c.ObservedState.String()
		view.ObservedState = &v
	}
	if c.Condition != nil {
		v := c.Condition.String()
		view.Condition = &v
	}
	if prices != nil {
		if est, err := prices.Estimate(&c.Spec); err == nil {
			minV, maxV := est.MinHourly, est.MaxHourly
			view.EstMinHourly = &minV
			view.EstMaxHourly = &maxV
		}
	}
	return view
}

// effectivePrices reads the effective policy and returns its price sheet
// (nil when no policy or no price sheet is configured) — the small slice of
// effectivePolicy every read-path handler in this file needs.
func (s *Server) effectivePrices(ctx context.Context) (policy.PriceSheet, error) {
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	return configFromStored(p).Prices, nil
}

func containsString(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// readScope is the read-scoping resolution (ADR-0009 addendum, #49 read
// side): the caller's effective scoped assignments and, when any are
// project-scoped, the projects their cluster visibility is narrowed to. A
// nil/empty projects slice means unrestricted visibility (dev mode, global
// admin, or no project-scoped assignments). Ported from clusters.rs's
// read_scope.
//
// Edge case, pinned down: a caller holding BOTH a global role AND
// project-scoped assignments is narrowed to the scoped projects — the
// presence of a scoped binding defines the projects they operate in, so
// reads follow it. Only a global Admin role is exempt and always sees
// every cluster.
func readScope(ctx context.Context, store controller.Store, id *auth.Identity) (assignments []auth.RoleScope, projects []string) {
	if id == nil {
		return nil, nil
	}
	for _, r := range id.Roles {
		if r == auth.RoleAdmin {
			return nil, nil
		}
	}
	assignments = EffectiveAssignments(ctx, store, id)
	for _, a := range assignments {
		if p, ok := cutPrefix(a.Scope, "project:"); ok {
			projects = append(projects, p)
		}
	}
	return assignments, projects
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// readGate is the shared list-endpoint admission gate: a caller with no
// global read permission, no effective assignment, and neither the Admin nor
// Auditor role can see anything at all, so the request is refused outright
// (deny-by-default, with the denial audited). Callers that pass the gate are
// still filtered per-row by clusterTenantAccess / jobVisible — a global
// viewer/developer/operator role alone does NOT cross tenant boundaries.
func readGate(ctx context.Context, store controller.Store, identity *auth.Identity, target auth.Target) error {
	if identity == nil || hasRole(identity, auth.RoleAdmin, auth.RoleAuditor) ||
		identity.Permits(auth.Read, target) || len(EffectiveAssignments(ctx, store, identity)) > 0 {
		return nil
	}
	return Authorize(ctx, store, identity, auth.Read, target)
}

// ListClusters lists every cluster the caller may read (#49 scoped RBAC +
// tenant read-scoping): Admin and Auditor see all; anyone else sees only
// clusters they own or whose project they hold a scoped assignment for. A
// caller with a global role but zero project ties gets a filtered list —
// never foreign owners' clusters (red-team finding: observability reads
// were globally open).
func (s *Server) ListClusters(ctx context.Context, _ ListClustersRequestObject) (ListClustersResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetCluster); err != nil {
		return nil, err
	}
	clusters, err := s.Store.List(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	prices, err := s.effectivePrices(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	views := make([]ClusterView, 0, len(clusters))
	queues := map[string]*string{}
	for i := range clusters {
		c := &clusters[i]
		if !clusterTenantAccess(ctx, s.Store, identity, c, auth.Read, auth.TargetCluster, true) {
			continue
		}
		q, ok := queues[c.Spec.Project]
		if !ok {
			q = s.queueNameForProject(ctx, c.Spec.Project)
			queues[c.Spec.Project] = q
		}
		views = append(views, clusterView(c, prices, q, s.gatewayURLFor(c.ID)))
	}
	return ListClusters200JSONResponse(views), nil
}

// GetCluster reads one cluster (tenant read-scoping): an out-of-scope
// cluster (not Admin, not Auditor, not the owner, no assignment covering
// its project) 404s rather than 403s — the list hides it, so the by-name
// read must not leak its existence either.
func (s *Server) GetCluster(ctx context.Context, req GetClusterRequestObject) (GetClusterResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	c, err := s.Store.Get(ctx, core.ClusterId(req.Id))
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if c == nil {
		return nil, notFound("no such cluster")
	}
	if !clusterTenantAccess(ctx, s.Store, identity, c, auth.Read, auth.TargetCluster, true) {
		return nil, notFound("no such cluster")
	}
	prices, err := s.effectivePrices(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	return GetCluster200JSONResponse(clusterView(c, prices, s.queueNameForProject(ctx, c.Spec.Project), s.gatewayURLFor(c.ID))), nil
}

// withProjectAdmitLock serializes concurrent same-project cluster creates
// across the whole read-check-write quota-admission section (list -> admit
// -> upsert), so the TOCTOU window can't over-admit (issue #44). Returns an
// unlock func; the caller defers it so the lock stays held past the
// upsert. Projects without a configured quota never call this — they stay
// concurrent.
//
// FOLLOW-UP (multi-replica gap — ledgered, not silently shipped): this lock
// is IN-PROCESS ONLY (a sync.Mutex keyed by project, scoped to this Server
// instance's lifetime). It serializes concurrent requests within ONE
// bifrost-api process. A multi-replica deployment (more than one process
// sharing a Postgres store) is NOT protected: two replicas can still race
// the same list->admit->upsert window against each other and both admit,
// over-committing the quota. The correct multi-replica fix is a single
// Store transaction wrapping the check-and-commit (a new Store method doing
// the list+upsert under one DB transaction/row lock) — not implemented in
// this task; tracked as a follow-up. This mirrors the Rust reference's own
// documented limitation verbatim (clusters.rs's ClusterApiState.admit_locks
// doc comment: "this is in-process only... tracked separately, not
// implemented here").
func (s *Server) withProjectAdmitLock(project string) func() {
	s.admitMu.Lock()
	if s.admitLocks == nil {
		s.admitLocks = make(map[string]*sync.Mutex)
	}
	lock, ok := s.admitLocks[project]
	if !ok {
		lock = &sync.Mutex{}
		s.admitLocks[project] = lock
	}
	s.admitMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func satSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

// windowedConsumption computes a project's cumulative resource-hours over
// [from, to], summed across pools — the budget-admission input (#77).
// Ported from the Rust predecessor's usage.rs windowed_consumption.
func (s *Server) windowedConsumption(ctx context.Context, project string, from, to uint64) (policy.ResourceMap, error) {
	p := project
	samples, err := s.Store.UsageSamples(ctx, &p, nil, nil, 0, to)
	if err != nil {
		return nil, err
	}
	byPoolResource := make(map[policy.PoolResource][]policy.UsageSampleView)
	for _, smp := range samples {
		key := policy.PoolResource{Pool: smp.Pool, Resource: smp.Resource}
		byPoolResource[key] = append(byPoolResource[key], policy.UsageSampleView{TS: smp.Ts, Quantity: smp.Quantity})
	}
	return policy.WindowedResourceHours(byPoolResource, from, to), nil
}

// checkGpuTenantIsolation applies the #58 GPU tenant-isolation rule to the
// compute pool project is allocated to: a policy.GpuSharingViolation when
// the rule refuses spec (callers map it to their 400 + deny-audit shape),
// an already-wrapped store error on a backend failure, nil when the rule
// passes or the project holds no compute allocation at all. Shared by
// CreateCluster and SubmitJob so a job can never claim a GPU shape a
// same-shape cluster would be refused.
func (s *Server) checkGpuTenantIsolation(ctx context.Context, project string, spec *core.ClusterSpec) error {
	pools, err := s.Store.ListPools(ctx)
	if err != nil {
		return wrapStoreErr(err)
	}
	for i := range pools {
		p := &pools[i]
		// A workload is admitted through a compute pool only (requirement
		// 4): a serving pool's sharing mode and tenancy are irrelevant to
		// it, and reading them here would let the serving allocation
		// shape compute admission.
		if p.Spec.Purpose.OrDefault() != core.PoolPurposeCompute {
			continue
		}
		allocs, err := s.Store.ListAllocations(ctx, p.Name)
		if err != nil {
			return wrapStoreErr(err)
		}
		matches := false
		for _, a := range allocs {
			if a.Project == project {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if verr := policy.CheckClusterGpuIsolation(&p.Spec, s.PolicySeed.EffectiveGPUDefaultSharing(), len(allocs), spec); verr != nil {
			return verr
		}
		break
	}
	return nil
}

// CreateCluster records a cluster's desired spec (the reconciler converges
// it). Scoped RBAC (#49): Write on Cluster, globally or via an assignment
// covering the spec's project. Admission order mirrors clusters.rs exactly:
// GPU tenant-isolation (#58) -> quota (#44, under the per-project lock) ->
// time-windowed budget (#77) -> upsert.
func (s *Server) CreateCluster(ctx context.Context, req CreateClusterRequestObject) (CreateClusterResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if req.Body == nil {
		return nil, badRequest("missing request body")
	}
	body := req.Body
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Write, auth.TargetCluster, body.Spec.Project); err != nil {
		return nil, err
	}
	if !core.IsK8sName(body.Id) {
		return nil, badRequest("id must be a valid Kubernetes name (RFC 1123 label): " + body.Id)
	}
	id := core.ClusterId(body.Id)
	spec, err := clusterSpecFromWire(&body.Spec)
	if err != nil {
		return nil, err
	}
	// Profile expansion (requirement 7, plan ruling D4) runs before shape
	// validation: a client picking a profile sends the shape fields empty
	// and the catalog fills them.
	if spec.Profile != nil {
		if perr := s.resolveProfile(ctx, &spec); perr != nil {
			s.denyCreate(ctx, identity, body.Id, "profile_rejected", http.StatusBadRequest)
			return nil, perr
		}
	}
	// Shape validation the contract cannot express: every quantity must
	// parse as a Kubernetes quantity and every worker group's replica bounds
	// must be coherent. Without this a spec such as head_cpu "lots" is
	// accepted with 201 and then fails in the provisioner on every tick — a
	// cluster the user can see but that can never be built (found by
	// r06's TestInvalidSpecIsRefusedWith400, 2026-09-02).
	if verr := validateClusterShape(&spec); verr != nil {
		s.denyCreate(ctx, identity, body.Id, "invalid_spec", http.StatusBadRequest)
		return nil, verr
	}
	// Administrator's allowlist (requirement 7): image and worker cap, the
	// platform-wide "*" rule overridden by the project's own. Checked
	// before quota so a refused image never counts against anything.
	admission, err := s.admissionFor(ctx, spec.Project)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if aerr := admission.Check(&spec); aerr != nil {
		s.denyCreate(ctx, identity, body.Id, aerr.reason, http.StatusBadRequest)
		return nil, badRequest(aerr.message)
	}
	// Private storage (requirement 12): every catalog name the spec lists
	// must exist and be open to the project; the resolution (Secret name,
	// mode, mount path — never the Secret's data) is persisted on the spec
	// so a later catalog edit does not reach into a running cluster.
	resolved, err := s.resolveStorage(ctx, spec.Project, spec.Storage)
	if err != nil {
		if he, ok := err.(HTTPError); ok && he.Status == http.StatusBadRequest {
			s.denyCreate(ctx, identity, body.Id, "storage_rejected", http.StatusBadRequest)
		}
		return nil, err
	}
	spec.StorageResolved = resolved
	// Tier-2 owned session clusters: the authenticated caller is always
	// the recorded owner, overriding any client-supplied value — the body
	// is untrusted (ownership is who asked, not what they claim). nil
	// only when unauthenticated (dev mode), which leaves the cluster
	// ownerless.
	if identity != nil {
		owner := identity.Owner()
		spec.Owner = &owner
	}
	project := spec.Project

	storedPolicy, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	cfg := PolicyConfig{}
	if storedPolicy != nil {
		cfg = configFromStored(storedPolicy)
	}

	idStr := id.String()

	// GPU tenant-isolation admission (#58): when the project's pool is
	// shared by more than one project, fractional GPU requests (and
	// admission into a pool resolving to time-slice at all) are rejected.
	if verr := s.checkGpuTenantIsolation(ctx, project, &spec); verr != nil {
		var viol policy.GpuSharingViolation
		if errors.As(verr, &viol) {
			s.denyCreate(ctx, identity, idStr, "gpu_tenant_isolation", http.StatusBadRequest)
			return nil, badRequest(viol.Error())
		}
		return nil, verr
	}

	// Quota admission (#44): only enforced for projects with a configured
	// limit, checked against max-demand of the project's other live
	// clusters plus this request.
	if limit, ok := cfg.Quotas[project]; ok {
		unlock := s.withProjectAdmitLock(project)
		defer unlock()

		_, requested, derr := policy.ClusterDemand(&spec)
		if derr != nil {
			return nil, badRequest("invalid spec: " + derr.Error())
		}
		clusters, err := s.Store.List(ctx)
		if err != nil {
			return nil, wrapStoreErr(err)
		}
		inUse := policy.ResourceMap{}
		for i := range clusters {
			c := &clusters[i]
			if c.Spec.Project != project || c.ID == id || c.Desired != controller.DesiredRunning {
				continue
			}
			// A stored spec that fails to parse must FAIL CLOSED —
			// zeroing would undercount usage and admit past the limit.
			_, m, derr := policy.ClusterDemand(&c.Spec)
			if derr != nil {
				slog.Error("api: unparseable stored spec blocks quota accounting", "cluster", c.ID, "error", derr)
				return nil, HTTPError{Status: http.StatusInternalServerError, Code: "internal_error",
					Message: "quota accounting failed: an existing cluster has an invalid spec"}
			}
			inUse = inUse.Add(m)
		}
		if aerr := policy.AdmitQuota(project, limit, inUse, requested); aerr != nil {
			s.denyCreate(ctx, identity, idStr, "quota_exceeded", http.StatusConflict)
			return nil, conflict(aerr.Error())
		}
	}

	// Time-windowed budget admission (#77): distinct from quota above —
	// caps CUMULATIVE consumption over a trailing window. No admit-lock
	// needed: consumed is historical, persisted usage, immune to
	// concurrent in-flight creates.
	if budget, ok := cfg.Budgets[project]; ok {
		to := controller.NowUnix()
		from := satSub(to, budget.WindowSecs)
		consumed, cerr := s.windowedConsumption(ctx, project, from, to)
		if cerr != nil {
			return nil, wrapStoreErr(cerr)
		}
		b := budget
		if berr := policy.AdmitBudget(project, &b, consumed); berr != nil {
			s.denyCreate(ctx, identity, idStr, "budget_exceeded", http.StatusConflict)
			return nil, conflict(berr.Error())
		}
	}

	generation, err := s.Store.UpsertDesired(ctx, id, spec)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	_ = generation
	action := "create_cluster"
	status := uint16(http.StatusCreated)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &idStr, Status: &status,
	})

	// Pool admission (ADR-0010): resolve + audit the project's Kueue
	// queue assignment. The reconcile loop re-derives it from the store
	// at apply time; a project with no allocation stays queue-free.
	if q, qerr := controller.QueueAssignmentForProject(ctx, s.Store, project); qerr != nil {
		slog.Warn("api: queue assignment lookup failed", "cluster", idStr, "error", qerr)
	} else if q != nil {
		qaction := "queue_assign"
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionAllow, Action: &qaction, Cluster: &idStr,
		})
	}

	return CreateCluster201Response{}, nil
}

func (s *Server) denyCreate(ctx context.Context, identity *auth.Identity, idStr, reason string, status int) {
	r := reason
	st := uint16(status)
	action := "create_cluster"
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionDeny, Reason: &r, Action: &action, Cluster: &idStr, Status: &st,
	})
}

// DeleteCluster marks a cluster for termination (default) or, with
// ?purge=true, hard-deletes an already-terminated/gone tombstone row
// (Truthful Console). Scoped RBAC (#49): fetch first (the check needs the
// cluster's project), then require Write on Cluster scoped to it. A row
// whose spec_json the current binary can no longer decode fails that
// fetch — see deleteUndecodableCluster for the escape hatch.
func (s *Server) DeleteCluster(ctx context.Context, req DeleteClusterRequestObject) (DeleteClusterResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	id := core.ClusterId(req.Id)
	purge := req.Params.Purge != nil && *req.Params.Purge
	stored, err := s.Store.Get(ctx, id)
	if err != nil {
		if controller.IsSerializationError(err) {
			return s.deleteUndecodableCluster(ctx, identity, id, purge)
		}
		return nil, wrapStoreErr(err)
	}
	if stored == nil {
		return nil, notFound("no such cluster")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Write, auth.TargetCluster, stored.Spec.Project); err != nil {
		return nil, err
	}

	if purge {
		return s.purgeCluster(ctx, identity, id, stored)
	}
	return s.terminateCluster(ctx, identity, id)
}

// deleteUndecodableCluster is the escape hatch for a cluster row whose
// spec_json the current binary can no longer decode (e.g. written before
// an enum value was retired): Store.Get fails on it, so without this path
// the row could never be removed through the API — and its presence must
// not 500 DELETE for everyone. The row's project is unknowable, so only
// GLOBAL (unscoped) Write on Cluster authorizes the call; every operation
// below is keyed on id alone and decodes no spec.
func (s *Server) deleteUndecodableCluster(ctx context.Context, identity *auth.Identity, id core.ClusterId, purge bool) (DeleteClusterResponseObject, error) {
	if err := Authorize(ctx, s.Store, identity, auth.Write, auth.TargetCluster); err != nil {
		return nil, err
	}
	if !purge {
		return s.terminateCluster(ctx, identity, id)
	}
	// The same refuse-if-not-tombstone rule purgeCluster applies, via a
	// check that reads no spec_json.
	desired, observedGone, found, err := s.Store.TombstoneByID(ctx, id)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if !found {
		return nil, notFound("no such cluster")
	}
	if desired != controller.DesiredTerminated || !observedGone {
		return nil, conflict("cannot purge a live cluster: it must be terminated and observed gone first")
	}
	return s.removeClusterRow(ctx, identity, id)
}

// terminateCluster flips id to desired=terminated and audits the 202 —
// DeleteCluster's plain-delete tail, shared with the undecodable-row
// escape hatch (SetDesired is an UPDATE by id, no spec decode).
func (s *Server) terminateCluster(ctx context.Context, identity *auth.Identity, id core.ClusterId) (DeleteClusterResponseObject, error) {
	if err := s.Store.SetDesired(ctx, id, controller.DesiredTerminated); err != nil {
		if storeErrContains(err, "no such cluster") {
			return nil, notFound("no such cluster")
		}
		return nil, wrapStoreErr(err)
	}
	action := "delete_cluster"
	status := uint16(http.StatusAccepted)
	idStr := id.String()
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &idStr, Status: &status,
	})
	return DeleteCluster202Response{}, nil
}

// purgeCluster hard-deletes a terminated cluster's tombstone row. Refuses a
// cluster that is not yet a dead tombstone — it must be desired=Terminated
// AND observed gone (never observed, or observed Terminated) — so purge can
// never race a teardown. The caller is already authorized (Write on
// Cluster, scoped) by DeleteCluster.
func (s *Server) purgeCluster(ctx context.Context, identity *auth.Identity, id core.ClusterId, stored *controller.StoredCluster) (DeleteClusterResponseObject, error) {
	isTombstone := stored.Desired == controller.DesiredTerminated && controller.ObservedGone(stored.ObservedState)
	if !isTombstone {
		return nil, conflict("cannot purge a live cluster: it must be terminated and observed gone first")
	}
	return s.removeClusterRow(ctx, identity, id)
}

// removeClusterRow hard-deletes id's row and audits the 200 — the purge
// tail, shared with the undecodable-row escape hatch (whose tombstone
// check runs on TombstoneByID instead of a decoded StoredCluster).
func (s *Server) removeClusterRow(ctx context.Context, identity *auth.Identity, id core.ClusterId) (DeleteClusterResponseObject, error) {
	removed, err := s.Store.RemoveCluster(ctx, id)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if !removed {
		// Removed between the fetch and here (concurrent purge/sweep).
		return nil, notFound("no such cluster")
	}
	action := "purge_cluster"
	status := uint16(http.StatusOK)
	idStr := id.String()
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &idStr, Status: &status,
	})
	return DeleteCluster200Response{}, nil
}

// lifecycleCmd is the user-issued lifecycle command behind
// POST .../suspend and .../resume (#51): each only flips desired state in
// the store; the reconcile engine actuates it.
type lifecycleCmd struct {
	desired      controller.DesiredState
	action       string
	transitional core.ClusterState
}

var (
	lifecycleSuspend = lifecycleCmd{desired: controller.DesiredSuspended, action: "suspend_cluster", transitional: core.ClusterStateSuspending}
	lifecycleResume  = lifecycleCmd{desired: controller.DesiredRunning, action: "resume_cluster", transitional: core.ClusterStateProvisioning}
)

// lifecycleCommand is the shared implementation of the suspend/resume
// routes: authorization, the Kueue queue-owned-suspend guard (ADR-0010),
// and the observed-state transition-legality check
// (core.ClusterState.CanTransitionTo). Returns nil on success (the desired
// state was flipped) or an *HTTPError describing the refusal.
//
// Authorization is Write on Cluster scoped to the cluster's project — the
// same rule create and delete apply. clusters.rs demanded GLOBAL write
// here, which the port carried over verbatim; on grace (2026-09-02) that
// meant the project operator who had just created a cluster got 403 from
// the suspend/resume buttons bifrost-jupyter shows exactly that user. The
// record is fetched first so the scope is known; a caller with no read on
// the cluster still sees 404 or 403 — the same two answers get_cluster gives.
func (s *Server) lifecycleCommand(ctx context.Context, identity *auth.Identity, id core.ClusterId, cmd lifecycleCmd) error {
	cluster, err := s.Store.Get(ctx, id)
	if err != nil {
		return wrapStoreErr(err)
	}
	if cluster == nil {
		// Existence is not revealed to callers without global write.
		if aerr := Authorize(ctx, s.Store, identity, auth.Write, auth.TargetCluster); aerr != nil {
			return aerr
		}
		return notFound("no such cluster")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Write, auth.TargetCluster, cluster.Spec.Project); err != nil {
		return err
	}
	idStr := id.String()

	// Kueue owns spec.suspend for queue-assigned clusters (ADR-0010): a
	// user suspend/resume would fight the queue's own admission control.
	q, qerr := controller.QueueAssignmentForProject(ctx, s.Store, cluster.Spec.Project)
	if qerr != nil {
		return wrapStoreErr(qerr)
	}
	if q != nil {
		reason := "queue_owned_suspend"
		status := uint16(http.StatusConflict)
		action := cmd.action
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionDeny, Reason: &reason, Action: &action, Cluster: &idStr, Status: &status,
		})
		return conflict(fmt.Sprintf("cluster's project is admitted through queue %q — Kueue owns suspend there", q.QueueName))
	}

	legal := cluster.Desired != controller.DesiredTerminated &&
		cluster.ObservedState != nil && cluster.ObservedState.CanTransitionTo(cmd.transitional)
	if !legal {
		reason := "illegal_state_transition"
		status := uint16(http.StatusConflict)
		action := cmd.action
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionDeny, Reason: &reason, Action: &action, Cluster: &idStr, Status: &status,
		})
		return conflict("illegal state transition")
	}

	if err := s.Store.SetDesired(ctx, id, cmd.desired); err != nil {
		return wrapStoreErr(err)
	}
	status := uint16(http.StatusAccepted)
	action := cmd.action
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &idStr, Status: &status,
	})
	return nil
}

// SuspendCluster sets a cluster's desired state to suspended; the
// reconciler releases compute (spec.suspend=true).
func (s *Server) SuspendCluster(ctx context.Context, req SuspendClusterRequestObject) (SuspendClusterResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := s.lifecycleCommand(ctx, identity, core.ClusterId(req.Id), lifecycleSuspend); err != nil {
		return nil, err
	}
	return SuspendCluster202Response{}, nil
}

// ResumeCluster sets a cluster's desired state back to running; the
// reconciler re-provisions (suspend=false).
func (s *Server) ResumeCluster(ctx context.Context, req ResumeClusterRequestObject) (ResumeClusterResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := s.lifecycleCommand(ctx, identity, core.ClusterId(req.Id), lifecycleResume); err != nil {
		return nil, err
	}
	return ResumeCluster202Response{}, nil
}

// ListJobs lists the persistent, cross-cluster job history, newest
// submitted first — filtered to what the caller may see (tenant
// read-scoping, same rule as the cluster reads): Admin and Auditor see
// everything; anyone else sees jobs they submitted themselves and jobs
// whose cluster they could read (own the cluster or hold a scoped
// assignment covering its project). Jobs whose cluster Bifrost does not
// manage in the store stay visible to any global Read-on-Job role — a
// registry-only cluster carries no owner/project to scope by, mirroring
// the registry-only read path in cluster_obs.go.
func (s *Server) ListJobs(ctx context.Context, _ ListJobsRequestObject) (ListJobsResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := readGate(ctx, s.Store, identity, auth.TargetJob); err != nil {
		return nil, err
	}
	jobs, err := s.Store.ListJobs(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	views := make([]JobView, 0, len(jobs))
	for i := range jobs {
		j := &jobs[i]
		if !s.jobVisible(ctx, identity, j) {
			continue
		}
		var dur *int64
		if j.DurationSecs != nil {
			v := int64(*j.DurationSecs)
			dur = &v
		}
		views = append(views, JobView{
			Id: j.Id, Cluster: j.Cluster, Submitter: j.Submitter, Status: j.Status,
			DurationSecs: dur, SubmittedAt: int64(j.SubmittedAt),
		})
	}
	return ListJobs200JSONResponse(views), nil
}

// jobVisible applies the tenant read-scope to one job history row. A store
// failure fails closed (the row is hidden): an error can never widen what
// a caller sees.
func (s *Server) jobVisible(ctx context.Context, identity *auth.Identity, j *core.JobRecord) bool {
	if identity == nil {
		return true
	}
	if hasRole(identity, auth.RoleAdmin, auth.RoleAuditor) {
		return true
	}
	if j.Submitter == identity.Subject {
		return true
	}
	c, err := s.Store.Get(ctx, core.ClusterId(j.Cluster))
	if err != nil {
		slog.Warn("api: job-scope cluster lookup failed", "cluster", j.Cluster, "error", err)
		return false
	}
	if c == nil {
		return identity.Permits(auth.Read, auth.TargetJob)
	}
	return clusterTenantAccess(ctx, s.Store, identity, c, auth.Read, auth.TargetJob, true)
}
