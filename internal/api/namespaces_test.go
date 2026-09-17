package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
)

func putNamespaces(t *testing.T, s *Server, m map[string]string) (PolicyView, error) {
	t.Helper()
	resp, err := s.UpdatePolicy(ctxWithIdentity(admin()), UpdatePolicyRequestObject{Body: &UpdatePolicy{Namespaces: &m}})
	if err != nil {
		return PolicyView{}, err
	}
	return PolicyView(mustResponse[UpdatePolicy200JSONResponse](t, resp)), nil
}

func TestNamespacesSectionIsRefusedOnASingleNamespaceControlPlane(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	_, err := putNamespaces(t, s, map[string]string{"team-a": "team-a"})
	mustHTTPError(t, err, 400)
	if !strings.Contains(httpMessage(err), "tenant namespaces are disabled") {
		t.Errorf("message = %q", httpMessage(err))
	}
	// Other sections still work, and the view carries `{}`.
	view, err := putStorage(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if view.Namespaces == nil || len(*view.Namespaces) != 0 {
		t.Errorf("view.namespaces = %v, want {}", view.Namespaces)
	}
}

func TestNamespacesSectionValidatesAndReplaces(t *testing.T) {
	s := &Server{Store: newMemStore(t), TenantNamespaces: true}
	view, err := putNamespaces(t, s, map[string]string{"team-a": "ray-team-a", "team-b": "ray-team-b"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if view.Namespaces == nil || (*view.Namespaces)["team-a"] != "ray-team-a" {
		t.Fatalf("view.namespaces = %v", view.Namespaces)
	}
	for name, c := range map[string]struct {
		m    map[string]string
		want string
	}{
		"empty project": {map[string]string{"": "x"}, "project must not be empty"},
		"star":          {map[string]string{"*": "x"}, `"*" is not a project here`},
		"bad name":      {map[string]string{"team-a": "Team.A"}, "not a valid Kubernetes namespace name"},
		"too long":      {map[string]string{"team-a": strings.Repeat("a", 64)}, "not a valid Kubernetes namespace name"},
	} {
		_, err := putNamespaces(t, s, c.m)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustHTTPError(t, err, 400)
		if !strings.Contains(httpMessage(err), c.want) {
			t.Errorf("%s: message %q, want %q", name, httpMessage(err), c.want)
		}
	}
	p, _ := s.Store.GetPolicy(context.Background())
	if len(p.Namespaces) != 2 {
		t.Errorf("a refused PUT must leave the section as it was: %v", p.Namespaces)
	}
	if view, err := putNamespaces(t, s, map[string]string{}); err != nil || view.Namespaces == nil || len(*view.Namespaces) != 0 {
		t.Errorf("{} must clear: %v %v", view.Namespaces, err)
	}
}

func TestAdmissionPinsTheTenantNamespaceAndNeverMovesAWorkload(t *testing.T) {
	store := controller.NewMemoryStore()
	s := &Server{Store: store, TenantNamespaces: true}
	if _, err := putNamespaces(t, s, map[string]string{"team-a": "ray-team-a"}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	op := ctxWithIdentity(testIdentity("op", auth.RoleOperator))
	body := func(id, project string) *CreateCluster {
		return &CreateCluster{Id: id, Spec: ClusterSpec{Name: id, Project: project, RayVersion: "2.9.0", Image: "rayproject/ray:2.9.0",
			HeadCpu: "1", HeadMemory: "2Gi", WorkerGroups: []WorkerGroup{}}}
	}
	resp, err := s.CreateCluster(op, CreateClusterRequestObject{Body: body("c1", "team-a")})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if raw, _ := json.Marshal(resp); strings.Contains(string(raw), "namespace") {
		t.Errorf("create response echoes the namespace: %s", raw)
	}
	cl, _ := store.Get(ctx, "c1")
	if cl == nil || cl.Spec.NamespaceResolved != "ray-team-a" {
		t.Fatalf("cluster namespace = %v", cl)
	}
	if _, err := s.CreateCluster(op, CreateClusterRequestObject{Body: body("c2", "team-b")}); err != nil {
		t.Fatal(err)
	}
	if cl, _ := store.Get(ctx, "c2"); cl == nil || cl.Spec.NamespaceResolved != "" {
		t.Errorf("an unmapped project must pin nothing, got %v", cl)
	}
	view := mustSubmit(t, s, admin(), "j1", "team-a")
	if j, _ := store.GetRayJob(ctx, core.ClusterId(view.Id)); j == nil || j.Spec.NamespaceResolved != "ray-team-a" {
		t.Errorf("job namespace = %v", j)
	}
	spec := minimalServiceSpec()
	spec.Project = "team-a"
	if err := deployAs(t, s, admin(), "svc-a", spec); err != nil {
		t.Fatal(err)
	}
	if svc, _ := store.GetService(ctx, "svc-a"); svc == nil || svc.Spec.NamespaceResolved != "ray-team-a" {
		t.Errorf("service namespace = %v", svc)
	}
	// Remapping never moves an admitted workload.
	if _, err := putNamespaces(t, s, map[string]string{"team-a": "elsewhere"}); err != nil {
		t.Fatal(err)
	}
	cl, _ = store.Get(ctx, "c1")
	if cl.Spec.NamespaceResolved != "ray-team-a" {
		t.Errorf("a mapping edit moved a running cluster to %q", cl.Spec.NamespaceResolved)
	}
	if _, err := s.CreateCluster(op, CreateClusterRequestObject{Body: body("c3", "team-a")}); err != nil {
		t.Fatal(err)
	}
	if cl, _ := store.Get(ctx, "c3"); cl.Spec.NamespaceResolved != "elsewhere" {
		t.Errorf("a new cluster must land in the new namespace, got %q", cl.Spec.NamespaceResolved)
	}
}

// A Kueue LocalQueue is namespaced and must share its workloads'
// namespace: the map and the allocations are checked against each other
// in both directions.
func TestNamespacesAndAllocationsMustAgree(t *testing.T) {
	store := controller.NewMemoryStore()
	s := &Server{Store: store, TenantNamespaces: true}
	ctx := context.Background()
	if _, err := s.CreatePool(ctxWithIdentity(admin()), CreatePoolRequestObject{Body: &CreatePool{Spec: minimalPoolSpec("compute")}}); err != nil {
		t.Fatalf("create pool: %v", err)
	}
	if err := store.UpsertAllocation(ctx, core.AllocationSpec{Pool: "compute", Project: "team-a", Namespace: "bifrost"}); err != nil {
		t.Fatal(err)
	}
	_, err := putNamespaces(t, s, map[string]string{"team-a": "ray-team-a"})
	mustHTTPError(t, err, 400)
	if !strings.Contains(httpMessage(err), `allocation in pool "compute" lives in namespace "bifrost"`) {
		t.Errorf("message = %q", httpMessage(err))
	}
	if _, err := putNamespaces(t, s, map[string]string{"team-a": "bifrost"}); err != nil {
		t.Fatalf("a map agreeing with the allocation must be accepted: %v", err)
	}
	if _, err := putNamespaces(t, s, map[string]string{"team-b": "ray-team-b"}); err != nil {
		t.Fatalf("mapping an unallocated project must be accepted: %v", err)
	}
	// The converse: an allocation for a mapped project must use its namespace.
	bad := &PutAllocation{Namespace: "bifrost"}
	_, err = s.PutAllocation(ctxWithIdentity(admin()), PutAllocationRequestObject{Name: "compute", Project: "team-b", Body: bad})
	mustHTTPError(t, err, 400)
	if !strings.Contains(httpMessage(err), `mapped to namespace "ray-team-b"`) {
		t.Errorf("message = %q", httpMessage(err))
	}
	good := &PutAllocation{Namespace: "ray-team-b"}
	if _, err := s.PutAllocation(ctxWithIdentity(admin()), PutAllocationRequestObject{Name: "compute", Project: "team-b", Body: good}); err != nil {
		t.Errorf("an allocation in the mapped namespace must be accepted: %v", err)
	}
}
