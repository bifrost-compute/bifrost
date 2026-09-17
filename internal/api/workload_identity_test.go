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

func putWorkloadIdentity(t *testing.T, s *Server, rules map[string]WorkloadIdentityRule) (PolicyView, error) {
	t.Helper()
	resp, err := s.UpdatePolicy(ctxWithIdentity(admin()), UpdatePolicyRequestObject{Body: &UpdatePolicy{WorkloadIdentity: &rules}})
	if err != nil {
		return PolicyView{}, err
	}
	return PolicyView(mustResponse[UpdatePolicy200JSONResponse](t, resp)), nil
}

func TestUpdatePolicyWorkloadIdentitySectionReplaceAndValidation(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	view, err := putWorkloadIdentity(t, s, map[string]WorkloadIdentityRule{
		"*":      {ServiceAccount: strPtr("bifrost-workload")},
		"team-a": {JobServiceAccount: strPtr("team-a-runner"), ServingServiceAccount: strPtr("team-a-serving")},
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if view.WorkloadIdentity == nil || len(*view.WorkloadIdentity) != 2 {
		t.Fatalf("view.workload_identity = %+v, want both rules", view.WorkloadIdentity)
	}
	got := (*view.WorkloadIdentity)["team-a"]
	if got.ServiceAccount != nil || got.JobServiceAccount == nil || *got.JobServiceAccount != "team-a-runner" || got.InteractiveServiceAccount != nil {
		t.Errorf("team-a rule on the wire = %+v", got)
	}

	// An absent key leaves the section untouched; another section's edit
	// does not clear it.
	if _, err := putStorage(t, s, []StorageEntry{envEntry("s3-a", "s3-a-creds", "team-a")}); err != nil {
		t.Fatal(err)
	}
	p, err := s.Store.GetPolicy(context.Background())
	if err != nil || p == nil || len(p.WorkloadIdentity) != 2 || p.WorkloadIdentity["team-a"].JobServiceAccount != "team-a-runner" {
		t.Fatalf("a storage edit must leave workload_identity alone: %+v (%v)", p, err)
	}
	// `{}` clears it.
	view, err = putWorkloadIdentity(t, s, map[string]WorkloadIdentityRule{})
	if err != nil {
		t.Fatal(err)
	}
	if view.WorkloadIdentity == nil || len(*view.WorkloadIdentity) != 0 {
		t.Errorf("{} must clear the section and the view must still carry `{}`, got %+v", view.WorkloadIdentity)
	}

	for name, c := range map[string]struct {
		rules map[string]WorkloadIdentityRule
		want  string
	}{
		"empty project":  {map[string]WorkloadIdentityRule{"": {ServiceAccount: strPtr("x")}}, "project must not be empty"},
		"empty rule":     {map[string]WorkloadIdentityRule{"team-a": {}}, "names no service account"},
		"bad name":       {map[string]WorkloadIdentityRule{"team-a": {ServiceAccount: strPtr("Team_A")}}, `service_account "Team_A" is not a valid Kubernetes name`},
		"bad job name":   {map[string]WorkloadIdentityRule{"team-a": {JobServiceAccount: strPtr("-runner")}}, `job_service_account "-runner"`},
		"blank override": {map[string]WorkloadIdentityRule{"team-a": {ServiceAccount: strPtr("")}}, "names no service account"},
	} {
		_, err := putWorkloadIdentity(t, s, c.rules)
		if err == nil {
			t.Errorf("%s: accepted, want 400", name)
			continue
		}
		mustHTTPError(t, err, 400)
		if !strings.Contains(httpMessage(err), c.want) {
			t.Errorf("%s: message %q, want it to contain %q", name, httpMessage(err), c.want)
		}
	}
	// A refused PUT changes nothing.
	p, _ = s.Store.GetPolicy(context.Background())
	if len(p.WorkloadIdentity) != 0 {
		t.Errorf("a refused PUT must leave the section as it was: %+v", p.WorkloadIdentity)
	}
}

func TestResolveWorkloadIdentityPrecedence(t *testing.T) {
	rules := map[string]core.WorkloadIdentityRule{
		"*":      {ServiceAccount: "bifrost-workload", JobServiceAccount: "bifrost-runner"},
		"team-a": {ServiceAccount: "team-a", ServingServiceAccount: "team-a-serving"},
		"team-c": {JobServiceAccount: "team-c-runner"},
	}
	for name, c := range map[string]struct {
		project string
		kind    core.WorkloadKind
		want    string
	}{
		"project default wins over * default":          {"team-a", core.WorkloadInteractive, "team-a"},
		"project default wins over * kind-specific":    {"team-a", core.WorkloadJob, "team-a"},
		"project kind-specific":                        {"team-a", core.WorkloadServing, "team-a-serving"},
		"unlisted project falls back to *":             {"team-b", core.WorkloadInteractive, "bifrost-workload"},
		"unlisted project falls back to * kind":        {"team-b", core.WorkloadJob, "bifrost-runner"},
		"project rule silent for kind falls back to *": {"team-c", core.WorkloadServing, "bifrost-workload"},
		"project rule speaks for its kind":             {"team-c", core.WorkloadJob, "team-c-runner"},
	} {
		got := resolveWorkloadIdentityFrom(rules, c.project, c.kind)
		if got == nil || *got != c.want {
			t.Errorf("%s: got %v, want %q", name, got, c.want)
		}
	}
	if got := resolveWorkloadIdentityFrom(map[string]core.WorkloadIdentityRule{"team-c": {JobServiceAccount: "r"}}, "team-c", core.WorkloadInteractive); got != nil {
		t.Errorf("no rule for the kind and no * = nil (namespace default), got %q", *got)
	}
	if got := resolveWorkloadIdentityFrom(nil, "team-a", core.WorkloadJob); got != nil {
		t.Errorf("no rules = nil, got %q", *got)
	}
}

// Admission pins the identity on every workload kind, never echoes it,
// and a later rule edit is never retroactive.
func TestAdmissionPinsWorkloadIdentityPerKindAndNeverRetroactively(t *testing.T) {
	store := controller.NewMemoryStore()
	s := &Server{Store: store}
	if _, err := putWorkloadIdentity(t, s, map[string]WorkloadIdentityRule{
		"team-a": {ServiceAccount: strPtr("team-a"), JobServiceAccount: strPtr("team-a-runner"), ServingServiceAccount: strPtr("team-a-serving")},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	op := ctxWithIdentity(testIdentity("op", auth.RoleOperator))

	// Interactive cluster.
	body := CreateCluster{Id: "c1", Spec: ClusterSpec{Name: "c1", Project: "team-a", RayVersion: "2.9.0", Image: "rayproject/ray:2.9.0",
		HeadCpu: "1", HeadMemory: "2Gi", WorkerGroups: []WorkerGroup{}}}
	resp, err := s.CreateCluster(op, CreateClusterRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cl, err := store.Get(ctx, "c1")
	if err != nil || cl == nil || cl.Spec.ServiceAccountResolved == nil || *cl.Spec.ServiceAccountResolved != "team-a" {
		t.Fatalf("cluster resolution = %v (%v)", cl, err)
	}
	if raw, _ := json.Marshal(resp); strings.Contains(string(raw), "service_account") {
		t.Errorf("create response echoes the resolution: %s", raw)
	}
	// A project with no rule keeps the namespace default.
	other := CreateCluster{Id: "c2", Spec: ClusterSpec{Name: "c2", Project: "team-b", RayVersion: "2.9.0", Image: "rayproject/ray:2.9.0",
		HeadCpu: "1", HeadMemory: "2Gi", WorkerGroups: []WorkerGroup{}}}
	if _, err := s.CreateCluster(op, CreateClusterRequestObject{Body: &other}); err != nil {
		t.Fatalf("create c2: %v", err)
	}
	if cl, _ := store.Get(ctx, "c2"); cl == nil || cl.Spec.ServiceAccountResolved != nil {
		t.Errorf("an unbound project must resolve to nil, got %v", cl)
	}

	// Ephemeral job: the job identity.
	view := mustSubmit(t, s, admin(), "j1", "team-a")
	j, err := store.GetRayJob(ctx, core.ClusterId(view.Id))
	if err != nil || j == nil || j.Spec.ServiceAccountResolved == nil || *j.Spec.ServiceAccountResolved != "team-a-runner" {
		t.Fatalf("job resolution = %v (%v)", j, err)
	}

	// Serving: the serving identity.
	spec := minimalServiceSpec()
	spec.Project = "team-a"
	if err := deployAs(t, s, admin(), "svc-a", spec); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	svc, err := store.GetService(ctx, "svc-a")
	if err != nil || svc == nil || svc.Spec.ServiceAccountResolved == nil || *svc.Spec.ServiceAccountResolved != "team-a-serving" {
		t.Fatalf("service resolution = %v (%v)", svc, err)
	}

	// Never retroactive: clearing the rules leaves every admitted
	// workload with the identity it was admitted with.
	if _, err := putWorkloadIdentity(t, s, map[string]WorkloadIdentityRule{}); err != nil {
		t.Fatal(err)
	}
	cl, _ = store.Get(ctx, "c1")
	j, _ = store.GetRayJob(ctx, core.ClusterId(view.Id))
	svc, _ = store.GetService(ctx, "svc-a")
	if cl.Spec.ServiceAccountResolved == nil || j.Spec.ServiceAccountResolved == nil || svc.Spec.ServiceAccountResolved == nil {
		t.Fatal("a rule edit must never reach an admitted workload")
	}
}
