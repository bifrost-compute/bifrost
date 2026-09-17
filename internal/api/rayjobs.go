// Ephemeral RayJob API (requirement 5): POST /api/v1/jobs submits a job
// whose cluster is created for it and removed after it finishes; GET and
// DELETE by id read and tear down. Handlers manipulate desired state in the
// Store; controller.JobReconciler converges the RayJob and keeps the
// gateway routing table in step. Authorization is the #5 rule the A1 stubs
// pinned (authorizeJobInProject / authorizeJobByID, below) — jobs are
// "code": Developer/Admin write, Operator read, project-scoped.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
	"github.com/bifrost-compute/bifrost/internal/provision"
)

// Head shape defaults the contract promises when a job spec leaves them
// empty (RayJobSpec.head_cpu / head_memory descriptions).
const (
	defaultJobHeadCpu    = "1"
	defaultJobHeadMemory = "2Gi"
)

// newJobID is the server-generated id for a submission without one:
// `job-<8 hex>` (contract: SubmitJob.id).
func newJobID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("api: crypto/rand unavailable: " + err.Error())
	}
	return "job-" + hex.EncodeToString(b[:])
}

// rayJobSpecFromWire converts the wire RayJobSpec into core.RayJobSpec.
// Shape defaults, profile expansion and storage resolution happen
// afterwards in SubmitJob (finishJobSpec), so a profile can fill what the
// client left empty and storage names are checked against the catalog
// (#12). Owner is left unset — SubmitJob stamps it from the identity,
// never from the body.
func rayJobSpecFromWire(w *RayJobSpec) (core.RayJobSpec, error) {
	if w.Entrypoint == "" {
		return core.RayJobSpec{}, badRequest("entrypoint is required")
	}
	var groups []core.WorkerGroup
	if w.WorkerGroups != nil {
		var err error
		if groups, err = workerGroupsFromWire(*w.WorkerGroups); err != nil {
			return core.RayJobSpec{}, err
		}
	}
	spec := core.RayJobSpec{
		Project:      w.Project,
		Entrypoint:   w.Entrypoint,
		Image:        w.Image,
		WorkerGroups: groups,
	}
	if w.Storage != nil {
		spec.Storage = append([]string(nil), (*w.Storage)...)
	}
	if w.Profile != nil && *w.Profile != "" {
		name := *w.Profile
		spec.Profile = &name
	}
	// environment (#52) names the catalog entry the job runs with;
	// finishJobSpec resolves it against the catalog (#55) after profile
	// expansion.
	if w.Environment != nil && *w.Environment != "" {
		name := *w.Environment
		spec.Environment = &name
	}
	if w.HeadCpu != nil {
		spec.HeadCpu = *w.HeadCpu
	}
	if w.HeadMemory != nil {
		spec.HeadMemory = *w.HeadMemory
	}
	if w.RayVersion != nil {
		spec.RayVersion = *w.RayVersion
	}
	if w.RuntimeEnvYaml != nil {
		spec.RuntimeEnvYaml = *w.RuntimeEnvYaml
	}
	if w.TtlSecondsAfterFinished != nil {
		if *w.TtlSecondsAfterFinished < 0 {
			return core.RayJobSpec{}, badRequest("ttl_seconds_after_finished must be non-negative")
		}
		ttl := uint32(*w.TtlSecondsAfterFinished)
		spec.TtlSecondsAfterFinished = &ttl
	}
	return spec, nil
}

// finishJobSpec completes a submitted spec the way create_cluster
// completes a cluster's: the profile (requirement 7, plan ruling D4)
// fills the shape fields the client left empty, then the contract's
// defaults fill what is still empty (head "1"/"2Gi", ray_version from the
// image tag), then the shape is validated and the project's admission
// rule applied. Works on the ClusterSpec view because that is what the
// profile catalog and the admission rule are written against; the
// resolved shape is copied back into the job spec. Every refusal is the
// 400 the caller sees; reason names the audit row.
func (s *Server) finishJobSpec(ctx context.Context, id core.ClusterId, spec *core.RayJobSpec) (reason string, err error) {
	view := provision.ClusterSpecForJob(id, spec)
	if view.Profile != nil {
		if perr := s.resolveProfile(ctx, &view); perr != nil {
			return "profile_rejected", perr
		}
	}
	// Environment resolution (#55): a spec names an environment OR writes
	// its own runtime_env_yaml, never both — profile expansion's
	// whole-or-nothing rule, so a workload never runs a half-merged
	// environment. Resolution compiles the catalog entry into the governed
	// runtime_env the job's CR carries and pins it on the spec, so a later
	// catalog edit is never retroactive.
	if spec.Environment != nil && strings.TrimSpace(spec.RuntimeEnvYaml) != "" {
		return "environment_rejected", badRequest(fmt.Sprintf("environment %q and runtime_env_yaml are alternatives; name an environment or write a runtime_env, not both", *spec.Environment))
	}
	var envResolved *core.ResolvedEnvironment
	if spec.Environment != nil {
		r, rerr := s.resolveEnvironment(ctx, view.Project, *spec.Environment, &view.Image)
		if rerr != nil {
			// environmentAuditReason: the scan gate's refusals (#58) audit
			// under their own reasons; everything else is
			// environment_rejected.
			return environmentAuditReason(rerr), rerr
		}
		envResolved = r
		spec.RuntimeEnvYaml = r.RuntimeEnvYaml
	}
	if view.Image == "" {
		return "invalid_spec", badRequest("image is required")
	}
	if view.HeadCpu == "" {
		view.HeadCpu = defaultJobHeadCpu
	}
	if view.HeadMemory == "" {
		view.HeadMemory = defaultJobHeadMemory
	}
	admission, aerr := s.admissionFor(ctx, view.Project)
	if aerr != nil {
		return "", wrapStoreErr(aerr)
	}
	// A catalog image (#10) states its Ray version; the tag heuristic is
	// the fallback for images the catalog does not know.
	if view.RayVersion == "" {
		if entry := admission.CatalogEntry(view.Image); entry != nil {
			view.RayVersion = entry.RayVersion
		}
	}
	if view.RayVersion == "" {
		v, ok := provision.RayVersionFromImage(view.Image)
		if !ok {
			return "invalid_spec", badRequest("ray_version is required when it cannot be derived from the image tag: " + view.Image)
		}
		view.RayVersion = v
	}
	if verr := validateClusterShape(&view); verr != nil {
		return "invalid_spec", verr
	}
	if aerr := admission.Check(&view); aerr != nil {
		return aerr.reason, badRequest(aerr.message)
	}
	// runtime_env governance (#53): the spec's runtime_env_yaml rides
	// verbatim into the RayJob CR, so it is parsed and checked against the
	// project's effective rule set (runtimeEnvPolicyFor — the admission
	// rule's runtime-env knobs, governed defaults otherwise) here, before
	// the spec is ever persisted. An environment's compiled runtime_env
	// (#55) takes the same path: resolution already validated it, and the
	// check is idempotent. The --allow-ungoverned-runtime-env serve flag
	// restores the pre-#53 verbatim passthrough for upgraders.
	//
	// Once validated, a document without a setup timeout gets the policy
	// default injected (#56): the bound rides the stored spec into the CR,
	// so an install that wedges fails at the timeout instead of hanging
	// forever. A document that sets its own timeout is kept verbatim.
	if !s.RuntimeEnvUngoverned {
		runtimeEnvPolicy, perr := s.runtimeEnvPolicyFor(ctx, view.Project)
		if perr != nil {
			return "", wrapStoreErr(perr)
		}
		if verr := runtimeEnvPolicy.Validate(spec.RuntimeEnvYaml); verr != nil {
			return "runtime_env_rejected", badRequest(verr.Error())
		}
		bounded, berr := runtimeEnvPolicy.EnforceSetupTimeout(spec.RuntimeEnvYaml)
		if berr != nil {
			return "runtime_env_rejected", badRequest(berr.Error())
		}
		spec.RuntimeEnvYaml = bounded
		if envResolved != nil {
			// The pinned resolution is the compiled document the CR carries;
			// keep the two identical (resolution already injected the same
			// bound, so this is normally a no-op assignment).
			envResolved.RuntimeEnvYaml = bounded
		}
	}
	// Storage (requirement 12): names are resolved against the catalog after
	// admission, exactly as CreateCluster does, and the resolution rides the
	// job spec so a later catalog edit is never retroactive.
	resolved, serr := s.resolveStorage(ctx, view.Project, view.Storage)
	if serr != nil {
		return "storage_rejected", serr
	}
	spec.StorageResolved = resolved
	// Workload identity (#20): the ServiceAccount the project's jobs run
	// under — the job's cluster pods and its submitter alike — pinned at
	// admission like storage.
	sa, werr := s.resolveWorkloadIdentity(ctx, view.Project, core.WorkloadJob)
	if werr != nil {
		return "", werr
	}
	spec.ServiceAccountResolved = sa
	// Tenant namespace (#21): the job, its cluster and its submitter land
	// in the project's namespace, pinned at admission.
	ns, nerr := s.resolveNamespace(ctx, view.Project)
	if nerr != nil {
		return "", nerr
	}
	spec.NamespaceResolved = ns
	spec.EnvironmentResolved = envResolved
	spec.Image, spec.RayVersion = view.Image, view.RayVersion
	spec.HeadCpu, spec.HeadMemory = view.HeadCpu, view.HeadMemory
	spec.WorkerGroups = view.WorkerGroups
	if spec.TtlSecondsAfterFinished == nil && view.TtlSeconds != nil && *view.TtlSeconds <= uint64(^uint32(0)) {
		// A profile's ttl_seconds default is the closest thing it has to
		// a job's ttl_seconds_after_finished; a request's own value wins.
		ttl := uint32(*view.TtlSeconds)
		spec.TtlSecondsAfterFinished = &ttl
	}
	return "", nil
}

// gatewayURLFor is the externally reachable gateway address of a
// registered cluster/job: GatewayExternalBase + hostname while the
// registry holds an entry for id; nil otherwise (not registered, or no
// external base configured).
func (s *Server) gatewayURLFor(id core.ClusterId) *string {
	if s.Registry == nil || s.GatewayExternalBase == "" {
		return nil
	}
	e, ok := s.Registry.ByID(id)
	if !ok {
		return nil
	}
	url := s.GatewayExternalBase + e.Hostname
	return &url
}

// queueNameForProject resolves the Kueue LocalQueue a project's workloads
// are admitted through (nil = none), for the `queue` view field.
func (s *Server) queueNameForProject(ctx context.Context, project string) *string {
	q, err := controller.QueueAssignmentForProject(ctx, s.Store, project)
	if err != nil {
		slog.Warn("api: queue assignment lookup failed", "project", project, "error", err)
		return nil
	}
	if q == nil {
		return nil
	}
	name := q.QueueName
	return &name
}

func int64Ptr(v *uint64) *int64 {
	if v == nil {
		return nil
	}
	i := int64(*v)
	return &i
}

// rayJobView converts a StoredRayJob into the wire RayJobView.
func (s *Server) rayJobView(ctx context.Context, j *controller.StoredRayJob) RayJobView {
	return RayJobView{
		Id:               j.ID.String(),
		Project:          j.Spec.Project,
		Owner:            j.Owner,
		Status:           j.Status,
		DeploymentStatus: j.DeploymentStatus,
		Cluster:          j.ClusterName,
		Message:          j.Message,
		Queue:            s.queueNameForProject(ctx, j.Spec.Project),
		GatewayUrl:       s.gatewayURLFor(j.ID),
		SubmittedAt:      int64(j.SubmittedAt),
		StartedAt:        int64Ptr(j.StartedAt),
		FinishedAt:       int64Ptr(j.FinishedAt),
	}
}

func (s *Server) auditJob(ctx context.Context, identity *auth.Identity, action, id string, decision core.AuditDecision, reason *string, status int) {
	st := uint16(status)
	a := action
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: decision, Reason: reason, Action: &a, Cluster: &id, Status: &st,
	})
}

// SubmitJob records a job's desired spec (the job reconciler converges
// it). Write on job in the spec's project (authorizeJobInProject), then the
// same completion and admission a cluster of the job's shape gets —
// profile, defaults, spec validity, the project's allowlist (finishJobSpec),
// GPU tenant-isolation (#58), quota and budget — over the derived
// ClusterSpec view, so a job cannot claim what a cluster could not. Answers
// 201 with the job as recorded.
func (s *Server) SubmitJob(ctx context.Context, req SubmitJobRequestObject) (SubmitJobResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if req.Body == nil {
		return nil, badRequest("missing request body")
	}
	body := req.Body
	if err := s.authorizeJobInProject(ctx, identity, auth.Write, body.Spec.Project); err != nil {
		return nil, err
	}
	idStr := newJobID()
	if body.Id != nil && *body.Id != "" {
		idStr = *body.Id
	}
	if !core.IsK8sName(idStr) {
		return nil, badRequest("id must be a valid Kubernetes name (RFC 1123 label): " + idStr)
	}
	id := core.ClusterId(idStr)
	spec, err := rayJobSpecFromWire(&body.Spec)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		owner := identity.Owner()
		spec.Owner = &owner
	}
	deny := func(reason string, status int) {
		r := reason
		s.auditJob(ctx, identity, "submit_job", idStr, core.AuditDecisionDeny, &r, status)
	}

	if reason, ferr := s.finishJobSpec(ctx, id, &spec); ferr != nil {
		if reason != "" {
			deny(reason, http.StatusBadRequest)
		}
		return nil, ferr
	}
	view := provision.ClusterSpecForJob(id, &spec)
	// GPU tenant-isolation admission (#58), the same rule CreateCluster
	// applies after shape/profile resolution — over the derived ClusterSpec
	// view, so a job cannot claim a fractional-GPU shape a same-shape
	// cluster would be refused in a multi-tenant pool.
	if verr := s.checkGpuTenantIsolation(ctx, spec.Project, &view); verr != nil {
		var viol policy.GpuSharingViolation
		if errors.As(verr, &viol) {
			deny("gpu_tenant_isolation", http.StatusBadRequest)
			return nil, badRequest(viol.Error())
		}
		return nil, verr
	}
	_, requested, derr := policy.ClusterDemand(&view)
	if derr != nil {
		deny("invalid_spec", http.StatusBadRequest)
		return nil, badRequest("invalid spec: " + derr.Error())
	}

	existing, err := s.Store.GetRayJob(ctx, id)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if existing != nil {
		deny("already_exists", http.StatusConflict)
		return nil, conflict("job already exists: " + idStr)
	}

	if err := s.admitProjectDemand(ctx, identity, "submit_job", id, spec.Project, requested); err != nil {
		return nil, err
	}

	if err := s.Store.UpsertRayJob(ctx, id, spec, spec.Owner); err != nil {
		return nil, wrapStoreErr(err)
	}
	s.auditJob(ctx, identity, "submit_job", idStr, core.AuditDecisionAllow, nil, http.StatusCreated)
	if q, qerr := controller.QueueAssignmentForProject(ctx, s.Store, spec.Project); qerr != nil {
		slog.Warn("api: queue assignment lookup failed", "job", idStr, "error", qerr)
	} else if q != nil {
		s.auditJob(ctx, identity, "queue_assign", idStr, core.AuditDecisionAllow, nil, http.StatusCreated)
	}

	stored, err := s.Store.GetRayJob(ctx, id)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if stored == nil {
		return nil, HTTPError{Status: http.StatusInternalServerError, Code: "internal_error", Message: "job vanished after submit"}
	}
	return SubmitJob201JSONResponse(s.rayJobView(ctx, stored)), nil
}

// admitProjectDemand is quota (#44) and time-windowed budget (#77)
// admission for a job, mirroring CreateCluster's: quota counts the
// project's other desired-running clusters AND unfinished jobs against the
// configured limit under the per-project admit lock; budget caps
// cumulative consumption over the trailing window.
func (s *Server) admitProjectDemand(ctx context.Context, identity *auth.Identity, action string, id core.ClusterId, project string, requested policy.ResourceMap) error {
	storedPolicy, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return wrapStoreErr(err)
	}
	cfg := PolicyConfig{}
	if storedPolicy != nil {
		cfg = configFromStored(storedPolicy)
	}
	idStr := id.String()

	if limit, ok := cfg.Quotas[project]; ok {
		unlock := s.withProjectAdmitLock(project)
		defer unlock()
		clusters, err := s.Store.List(ctx)
		if err != nil {
			return wrapStoreErr(err)
		}
		inUse := policy.ResourceMap{}
		for i := range clusters {
			c := &clusters[i]
			if c.Spec.Project != project || c.ID == id || c.Desired != controller.DesiredRunning {
				continue
			}
			_, m, derr := policy.ClusterDemand(&c.Spec)
			if derr != nil {
				slog.Error("api: unparseable stored spec blocks quota accounting", "cluster", c.ID, "error", derr)
				return HTTPError{Status: http.StatusInternalServerError, Code: "internal_error",
					Message: "quota accounting failed: an existing cluster has an invalid spec"}
			}
			inUse = inUse.Add(m)
		}
		jobs, err := s.Store.ListRayJobs(ctx)
		if err != nil {
			return wrapStoreErr(err)
		}
		for i := range jobs {
			j := &jobs[i]
			if j.Spec.Project != project || j.ID == id || j.Desired != controller.DesiredRunning || j.FinishedAt != nil {
				continue
			}
			jv := provision.ClusterSpecForJob(j.ID, &j.Spec)
			_, m, derr := policy.ClusterDemand(&jv)
			if derr != nil {
				slog.Error("api: unparseable stored job spec blocks quota accounting", "job", j.ID, "error", derr)
				return HTTPError{Status: http.StatusInternalServerError, Code: "internal_error",
					Message: "quota accounting failed: an existing job has an invalid spec"}
			}
			inUse = inUse.Add(m)
		}
		if aerr := policy.AdmitQuota(project, limit, inUse, requested); aerr != nil {
			r := "quota_exceeded"
			s.auditJob(ctx, identity, action, idStr, core.AuditDecisionDeny, &r, http.StatusConflict)
			return conflict(aerr.Error())
		}
	}

	if budget, ok := cfg.Budgets[project]; ok {
		to := controller.NowUnix()
		from := satSub(to, budget.WindowSecs)
		consumed, cerr := s.windowedConsumption(ctx, project, from, to)
		if cerr != nil {
			return wrapStoreErr(cerr)
		}
		b := budget
		if berr := policy.AdmitBudget(project, &b, consumed); berr != nil {
			r := "budget_exceeded"
			s.auditJob(ctx, identity, action, idStr, core.AuditDecisionDeny, &r, http.StatusConflict)
			return conflict(berr.Error())
		}
	}
	return nil
}

// loadJobForCaller is the shared read step of GetJob/DeleteJob: the row,
// or 404 — also for a project-narrowed caller whose projects do not
// include the job's (an out-of-scope id must not reveal that it exists) —
// then the scoped check for action on the job's project.
func (s *Server) loadJobForCaller(ctx context.Context, identity *auth.Identity, id core.ClusterId, action auth.PermissionType) (*controller.StoredRayJob, error) {
	j, err := s.Store.GetRayJob(ctx, id)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if j == nil {
		return nil, notFound("no such job")
	}
	_, narrowed := readScope(ctx, s.Store, identity)
	if len(narrowed) > 0 && !containsString(narrowed, j.Spec.Project) {
		return nil, notFound("no such job")
	}
	if err := AuthorizeScoped(ctx, s.Store, identity, action, auth.TargetJob, j.Spec.Project); err != nil {
		return nil, err
	}
	return j, nil
}

// GetJob reads one job: Read on job (authorizeJobByID), out-of-scope ids
// read as 404.
func (s *Server) GetJob(ctx context.Context, req GetJobRequestObject) (GetJobResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if _, err := s.authorizeJobByID(ctx, identity, auth.Read); err != nil {
		return nil, err
	}
	j, err := s.loadJobForCaller(ctx, identity, core.ClusterId(req.Id), auth.Read)
	if err != nil {
		return nil, err
	}
	return GetJob200JSONResponse(s.rayJobView(ctx, j)), nil
}

// DeleteJob stops a job and tears its cluster down (desired=terminated,
// 202) or, with ?purge=true, hard-deletes an already-terminated tombstone
// (200; 409 while the job or its cluster still exists). Write on job,
// same visibility rule as GetJob.
func (s *Server) DeleteJob(ctx context.Context, req DeleteJobRequestObject) (DeleteJobResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if _, err := s.authorizeJobByID(ctx, identity, auth.Write); err != nil {
		return nil, err
	}
	id := core.ClusterId(req.Id)
	j, err := s.loadJobForCaller(ctx, identity, id, auth.Write)
	if err != nil {
		return nil, err
	}
	idStr := id.String()

	if req.Params.Purge != nil && *req.Params.Purge {
		if j.Desired != controller.DesiredTerminated || !controller.RayJobObservedGone(j) {
			return nil, conflict("cannot purge a live job: it must be terminated and observed gone first")
		}
		removed, err := s.Store.RemoveRayJob(ctx, id)
		if err != nil {
			return nil, wrapStoreErr(err)
		}
		if !removed {
			return nil, notFound("no such job")
		}
		s.auditJob(ctx, identity, "purge_job", idStr, core.AuditDecisionAllow, nil, http.StatusOK)
		return DeleteJob200Response{}, nil
	}

	if err := s.Store.SetRayJobDesired(ctx, id, controller.DesiredTerminated); err != nil {
		if storeErrContains(err, "no such job") {
			return nil, notFound("no such job")
		}
		return nil, wrapStoreErr(err)
	}
	s.auditJob(ctx, identity, "delete_job", idStr, core.AuditDecisionAllow, nil, http.StatusAccepted)
	return DeleteJob202Response{}, nil
}

// authorizeJobInProject is the write-side authorization for a job in
// project (#5 rule: jobs are "code" — Developer/Admin write, Operator
// read, project-scoped). It composes the two rules cluster routes already
// apply separately: a caller holding project-scoped assignments is
// narrowed to those projects (readScope's pinned edge case — the scoped
// binding defines where they operate, even though a Developer's global
// role grants Write on jobs everywhere), and within scope the ordinary
// AuthorizeScoped check applies.
func (s *Server) authorizeJobInProject(ctx context.Context, identity *auth.Identity, action auth.PermissionType, project string) error {
	_, narrowed := readScope(ctx, s.Store, identity)
	if len(narrowed) > 0 && !containsString(narrowed, project) {
		emitAuthzDenial(ctx, s.Store, identity, action, auth.TargetJob)
		return ErrForbidden
	}
	return AuthorizeScoped(ctx, s.Store, identity, action, auth.TargetJob, project)
}

// authorizeJobByID is the authorization step for a job addressed by id
// before its row is loaded (get_job/delete_job). It grants when the
// caller's global roles permit action on jobs OR any effective assignment
// does (on some project — which one is settled against the row's project
// once it exists, exactly as scopeForRead does for clusters); otherwise
// it is the audited 403. The returned flag reports whether the caller is
// project-narrowed (readScope): a narrowed caller must never learn that an
// out-of-scope id exists, so ids outside their projects read as 404.
func (s *Server) authorizeJobByID(ctx context.Context, identity *auth.Identity, action auth.PermissionType) (narrowed bool, err error) {
	if identity == nil {
		return false, nil
	}
	assignments, projects := readScope(ctx, s.Store, identity)
	if identity.Permits(action, auth.TargetJob) {
		return len(projects) > 0, nil
	}
	for _, a := range assignments {
		if a.Role.Grants(action, auth.TargetJob) {
			return len(projects) > 0, nil
		}
	}
	emitAuthzDenial(ctx, s.Store, identity, action, auth.TargetJob)
	return false, ErrForbidden
}
