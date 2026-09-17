// Ray Serve service API (requirement 1: deploy from Jupyter; requirement
// 2: project-scoped). A deploy writes a desired-state row
// (Store.UpsertService) and answers 202; the service reconcile loop
// (internal/controller/service_reconcile.go) owns actuation against the
// ServiceProvisioner and records what it observes, so reads here are the
// store row merged with the last observation — the same observation-first
// shape clusters have. Nothing on this path needs a ServiceProvisioner: a
// control plane without one accepts deploys that simply never converge,
// which the view reports honestly as provisioning.
//
// Permissions are against auth.TargetService (#26): deploying/updating a
// Serve app is "code", so Developer (and Admin) may write; Operator and
// Viewer are read-only. Writes are scoped to the spec's project
// (AuthorizeScoped); reads follow readScope's narrowing, so a
// project-scoped caller never learns another project's service exists
// (404, like clusters).
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
)

// servingQueues memoizes the per-project serving-queue lookup for one
// request: ListServices resolves it once per project, not once per row.
// A lookup failure is logged and read as queue-free — the view is a read
// path, and the reconciler re-derives the queue at apply time anyway.
type servingQueues struct {
	store     controller.Store
	byProject map[string]*string
}

func (s *Server) newServingQueues() *servingQueues {
	return &servingQueues{store: s.Store, byProject: map[string]*string{}}
}

func (q *servingQueues) queue(ctx context.Context, project string) *string {
	if v, ok := q.byProject[project]; ok {
		return v
	}
	var out *string
	qa, err := controller.QueueAssignmentForProjectPurpose(ctx, q.store, project, core.PoolPurposeServing)
	switch {
	case err != nil:
		slog.Warn("api: serving queue lookup failed", "project", project, "error", err)
	case qa != nil:
		name := qa.QueueName
		out = &name
	}
	q.byProject[project] = out
	return out
}

// serviceView merges a stored service with its last observation into the
// wire ServiceView. State is the observed state, except that a service
// whose desired state is terminated reads as terminating until the
// backend confirms it gone (then terminated — the tombstone the reconciler
// reaps); a row nothing has observed yet is provisioning. gateway_url is
// filled only while the reconciler has the service registered as a
// `serve` endpoint and an external base is configured. queue is the
// project's serving-pool LocalQueue (requirement 4) — the queue the
// reconciler stamps on the RayService — or null when the project has no
// serving allocation.
func (s *Server) serviceView(ctx context.Context, svc *controller.StoredService, queues *servingQueues) ServiceView {
	view := ServiceView{Name: svc.Name, Project: svc.Spec.Project, Owner: svc.Owner, Url: svc.ObservedURL}
	if svc.Desired != controller.DesiredTerminated {
		view.Queue = queues.queue(ctx, svc.Spec.Project)
	}
	switch {
	case svc.Desired == controller.DesiredTerminated:
		view.State = core.ClusterStateTerminating.String()
		if svc.ObservedState != nil && *svc.ObservedState == core.ClusterStateTerminated {
			view.State = core.ClusterStateTerminated.String()
		}
		view.Url = nil
	case svc.ObservedState == nil:
		view.State = core.ClusterStateProvisioning.String()
	default:
		view.State = svc.ObservedState.String()
	}
	if s.Registry != nil && s.GatewayExternalBase != "" {
		if ep, ok := s.Registry.ByID(core.ClusterId(svc.Name)); ok && ep.Target == core.RegistryTargetServe {
			u := s.GatewayExternalBase + ep.Hostname
			view.GatewayUrl = &u
		}
	}
	return view
}

// ListServices lists every service the caller may read (#49 scoped RBAC +
// ADR-0009 addendum read-scoping — see readScope; the same shape as
// ListClusters, against Target::Service).
func (s *Server) ListServices(ctx context.Context, _ ListServicesRequestObject) (ListServicesResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	assignments, narrowed := readScope(ctx, s.Store, identity)
	if len(narrowed) == 0 && identity != nil {
		if !identity.Permits(auth.Read, auth.TargetService) && len(assignments) == 0 {
			if err := Authorize(ctx, s.Store, identity, auth.Read, auth.TargetService); err != nil {
				return nil, err
			}
		}
	}
	rows, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	views := make([]ServiceView, 0, len(rows))
	queues := s.newServingQueues()
	for i := range rows {
		svc := &rows[i]
		var visible bool
		switch {
		case len(narrowed) > 0:
			visible = containsString(narrowed, svc.Spec.Project)
		case identity != nil:
			visible = identity.PermitsScoped(auth.Read, auth.TargetService, assignments, svc.Spec.Project)
		default:
			visible = true
		}
		if visible {
			views = append(views, s.serviceView(ctx, svc, queues))
		}
	}
	return ListServices200JSONResponse(views), nil
}

// GetService reads one service. An out-of-scope service (narrowed away by
// project-scoped assignments) 404s rather than 403s, like GetCluster.
func (s *Server) GetService(ctx context.Context, req GetServiceRequestObject) (GetServiceResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	svc, err := s.Store.GetService(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if svc == nil {
		return nil, notFound("no such service")
	}
	_, narrowed := readScope(ctx, s.Store, identity)
	if len(narrowed) > 0 && !containsString(narrowed, svc.Spec.Project) {
		return nil, notFound("no such service")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Read, auth.TargetService, svc.Spec.Project); err != nil {
		return nil, err
	}
	return GetService200JSONResponse(s.serviceView(ctx, svc, s.newServingQueues())), nil
}

// serviceSpecFromWire converts the generated wire ServiceSpec into
// core.ServiceSpec.
func serviceSpecFromWire(w *ServiceSpec) (core.ServiceSpec, error) {
	spec := core.ServiceSpec{
		Name: w.Name, Project: w.Project, RayVersion: w.RayVersion, Image: w.Image,
		HeadCpu: w.HeadCpu, HeadMemory: w.HeadMemory, WorkerCpu: w.WorkerCpu, WorkerMemory: w.WorkerMemory,
		WorkerReplicas: uint32NonNeg(w.WorkerReplicas), ServeConfigV2: w.ServeConfigV2,
		Upgrade: core.DefaultUpgradeStrategy,
	}
	if w.Storage != nil {
		spec.Storage = append([]string(nil), (*w.Storage)...)
	}
	if w.Upgrade != nil {
		switch *w.Upgrade {
		case Canary:
			spec.Upgrade = core.UpgradeStrategyCanary
		case InPlace:
			spec.Upgrade = core.UpgradeStrategyInPlace
		default:
			return core.ServiceSpec{}, badRequest("invalid upgrade strategy " + string(*w.Upgrade))
		}
	}
	return spec, nil
}

func uint32NonNeg(v int32) uint32 {
	if v < 0 {
		return 0
	}
	return uint32(v)
}

// DeployService deploys or updates a service: Write on Target::Service in
// the spec's project (Developer/Admin). The row is upserted — a same-name
// redeploy with a changed spec bumps the generation and the reconciler
// rolls the RayService (canary or in-place per the spec); an unchanged
// spec is a no-op — and the answer is the contract's 202 (plan ruling
// D11): accepted, converging, watch get_service.
func (s *Server) DeployService(ctx context.Context, req DeployServiceRequestObject) (DeployServiceResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if req.Body == nil {
		return nil, badRequest("missing request body")
	}
	name := req.Body.Name
	if !core.IsK8sName(name) {
		return nil, badRequest("service name must be a valid Kubernetes resource name")
	}
	spec, err := serviceSpecFromWire(&req.Body.Spec)
	if err != nil {
		return nil, err
	}
	if spec.Name == "" {
		spec.Name = name
	}
	if spec.Name != name {
		return nil, badRequest("spec.name must match name")
	}
	if spec.Project == "" {
		return nil, badRequest("spec.project is required")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Write, auth.TargetService, spec.Project); err != nil {
		return nil, err
	}
	// A caller whose scoped bindings narrow them to some projects operates
	// only in those (readScope's pinned edge case) — a global Developer
	// role does not let a team-b member deploy into team-a (requirement 2).
	// Reads and delete already follow the same narrowing; deploy is the
	// one write that has no row to 404 on, so it is a plain 403.
	if _, narrowed := readScope(ctx, s.Store, identity); len(narrowed) > 0 && !containsString(narrowed, spec.Project) {
		emitAuthzDenial(ctx, s.Store, identity, auth.Write, auth.TargetService)
		return nil, ErrForbidden
	}

	// Private storage (requirement 12): resolve spec.Storage against the
	// policy catalog — 400 for unknown names or entries the project may
	// not use. Runs before admission so a refused reference never
	// consumes quota; the resolution is persisted on the spec so a later
	// catalog edit is never retroactive.
	if spec.StorageResolved, err = s.resolveStorage(ctx, spec.Project, spec.Storage); err != nil {
		return nil, err
	}
	// Workload identity (#20): the ServiceAccount the project's Serve
	// deployments run under, pinned at admission like storage.
	if spec.ServiceAccountResolved, err = s.resolveWorkloadIdentity(ctx, spec.Project, core.WorkloadServing); err != nil {
		return nil, err
	}

	// One service per project (requirement 2, plan ruling D8): a project
	// shares a single RayService, so a second name in the same project is
	// refused until the first is gone. `--services-per-project` raises the
	// cap. Same name = update (the upsert below); a row already headed for
	// termination no longer counts, so delete-then-redeploy needs no wait.
	if err := s.enforceServicesPerProject(ctx, identity, name, spec.Project); err != nil {
		return nil, err
	}

	// Serving-pool admission (requirement 4): the project's serving
	// allocation nominal is its serving limit; a deploy whose demand plus
	// the project's other live services would exceed it is 409. Compute
	// clusters admit against the policy's quotas and the compute pool and
	// never read this ledger — compute cannot consume serving quota. The
	// serving QueueAssignment itself is re-derived by the reconciler at
	// apply time and by serviceView on read (like clusters).
	if err := s.admitServing(ctx, identity, name, &spec); err != nil {
		return nil, err
	}

	if identity != nil && identity.Subject != "" {
		// Owner is server-stamped from the authenticated identity; the
		// store keeps the first deployer on a same-name update.
		owner := identity.Subject
		if _, err := s.Store.UpsertService(ctx, name, spec, &owner); err != nil {
			return nil, wrapStoreErr(err)
		}
	} else if _, err := s.Store.UpsertService(ctx, name, spec, nil); err != nil {
		return nil, wrapStoreErr(err)
	}

	action := "deploy_service"
	status := uint16(http.StatusAccepted)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &name, Status: &status,
	})
	return DeployService202Response{}, nil
}

// servingAllocation is the project's allocation in a serving pool — the
// first one found, the same allocation whose LocalQueue the service is
// admitted through — or nil when the project has none.
func (s *Server) servingAllocation(ctx context.Context, project string) (*core.AllocationSpec, error) {
	pools, err := s.Store.ListPools(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	for i := range pools {
		if pools[i].Spec.Purpose.OrDefault() != core.PoolPurposeServing {
			continue
		}
		allocs, err := s.Store.ListAllocations(ctx, pools[i].Name)
		if err != nil {
			return nil, wrapStoreErr(err)
		}
		for j := range allocs {
			if allocs[j].Project == project {
				return &allocs[j], nil
			}
		}
	}
	return nil, nil //nolint:nilnil // no serving allocation is a normal answer, not an error
}

// admitServing enforces the serving ledger (requirement 4): the project's
// serving allocation `nominal` map, read as a ResourceMap, caps the summed
// ServiceDemand of the project's live (desired running) services plus this
// deploy. A same-name redeploy replaces its own row, so the existing row
// is excluded from in-use. No serving allocation, or one with an empty
// nominal (no limit declared), admits. Over-commit is 409 with an audit
// deny (`serving_quota_exceeded`).
func (s *Server) admitServing(ctx context.Context, identity *auth.Identity, name string, spec *core.ServiceSpec) error {
	alloc, err := s.servingAllocation(ctx, spec.Project)
	if err != nil {
		return err
	}
	if alloc == nil || len(alloc.Nominal) == 0 {
		return nil
	}
	limit, lerr := policy.LimitFromQuantities(alloc.Nominal)
	if lerr != nil {
		// An allocation the administrator wrote that cannot be read as a
		// limit must fail closed: admitting would make the cap silently
		// void.
		slog.Error("api: serving allocation nominal does not parse; refusing deploy", "pool", alloc.Pool, "project", spec.Project, "error", lerr)
		return HTTPError{Status: http.StatusInternalServerError, Code: "internal_error",
			Message: "serving quota accounting failed: the project's serving allocation has an invalid nominal"}
	}
	requested, derr := policy.ServiceDemand(spec)
	if derr != nil {
		return badRequest("invalid spec: " + derr.Error())
	}

	unlock := s.withProjectAdmitLock("serving/" + spec.Project)
	defer unlock()
	rows, err := s.Store.ListServices(ctx)
	if err != nil {
		return wrapStoreErr(err)
	}
	inUse := policy.ResourceMap{}
	for i := range rows {
		row := &rows[i]
		if row.Spec.Project != spec.Project || row.Name == name || row.Desired != controller.DesiredRunning {
			continue
		}
		// A stored spec that fails to parse must FAIL CLOSED — zeroing
		// would undercount usage and admit past the limit.
		m, derr := policy.ServiceDemand(&row.Spec)
		if derr != nil {
			slog.Error("api: unparseable stored service spec blocks serving quota accounting", "service", row.Name, "error", derr)
			return HTTPError{Status: http.StatusInternalServerError, Code: "internal_error",
				Message: "serving quota accounting failed: an existing service has an invalid spec"}
		}
		inUse = inUse.Add(m)
	}
	if aerr := policy.AdmitQuota(spec.Project, limit, inUse, requested); aerr != nil {
		reason := "serving_quota_exceeded"
		action := "deploy_service"
		status := uint16(http.StatusConflict)
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionDeny, Reason: &reason, Action: &action, Cluster: &name, Status: &status,
		})
		return conflict("serving quota: " + aerr.Error())
	}
	return nil
}

// DeleteService requests teardown: desired → terminated; the reconciler
// deletes the RayService and the row becomes a terminated tombstone. Write
// on Target::Service in the row's project. Idempotent for a row already
// terminating. An unknown or out-of-scope name is 404 for a caller who
// could not have seen it listed; a caller with global write learns 404
// only for a genuinely unknown name.
func (s *Server) DeleteService(ctx context.Context, req DeleteServiceRequestObject) (DeleteServiceResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	svc, err := s.Store.GetService(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if svc == nil {
		if aerr := Authorize(ctx, s.Store, identity, auth.Write, auth.TargetService); aerr != nil {
			return nil, aerr
		}
		return nil, notFound("no such service")
	}
	_, narrowed := readScope(ctx, s.Store, identity)
	if len(narrowed) > 0 && !containsString(narrowed, svc.Spec.Project) {
		return nil, notFound("no such service")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, auth.Write, auth.TargetService, svc.Spec.Project); err != nil {
		return nil, err
	}
	if svc.Desired != controller.DesiredTerminated {
		if err := s.Store.SetServiceDesired(ctx, req.Name, controller.DesiredTerminated); err != nil {
			return nil, wrapStoreErr(err)
		}
	}
	action := "delete_service"
	status := uint16(http.StatusAccepted)
	name := req.Name
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Cluster: &name, Status: &status,
	})
	return DeleteService202Response{}, nil
}

// enforceServicesPerProject is the one-service-per-project rule (ruling
// D8): counting the project's live rows (desired running or suspended)
// under other names, a deploy that would exceed s.ServicesPerProject is
// 409 and audited as a deny (reason service_limit), the same shape as
// denyCreate's quota refusals for clusters. A cap of zero or less means
// the default of one (app.New sets it, but a bare Server must not be
// wide open).
func (s *Server) enforceServicesPerProject(ctx context.Context, identity *auth.Identity, name, project string) error {
	limit := s.ServicesPerProject
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.Store.ListServices(ctx)
	if err != nil {
		return wrapStoreErr(err)
	}
	var live []string
	for i := range rows {
		row := &rows[i]
		if row.Spec.Project != project || row.Name == name || row.Desired == controller.DesiredTerminated {
			continue
		}
		live = append(live, row.Name)
	}
	if len(live) < limit {
		return nil
	}
	reason := "service_limit"
	action := "deploy_service"
	status := uint16(http.StatusConflict)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionDeny, Reason: &reason, Action: &action, Cluster: &name, Status: &status,
	})
	return conflict(fmt.Sprintf("project %s already has service %s; redeploy it under that name or delete it first", project, live[0]))
}
