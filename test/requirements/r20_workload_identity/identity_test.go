// Requirement 20 — workload identity: the pods of a project's clusters,
// jobs and services run under a per-project Kubernetes ServiceAccount the
// administrator names, so a cloud IAM binding (EKS Pod Identity / IRSA,
// GKE Workload Identity) attaches to the project's workloads without a
// static credential anywhere — not in the storage catalog, not on the pod,
// not through Bifrost.
//
// The shape (the admission map's, with the storage catalog's discipline):
// an administrator PUTs a `workload_identity` section on the policy row
// keyed by project (or "*"), naming a default ServiceAccount and optional
// per-kind overrides (interactive / job / serving). Admission resolves the
// caller's project and the workload's kind once, pins the name on the spec,
// and the provisioner stamps it on every pod template — head, workers and
// the RayJob submitter. A later rule edit never reaches an admitted
// workload. Bifrost never creates, reads or binds the account: the live
// client only checks it exists (metadata) so a typo is a readable condition.
//
// Lane coverage: L2 (inproc) proves the section's validation and
// section-replace semantics, the per-kind resolution pinned at admission
// (through the inproc target's ResolvedServiceAccount seam — the contract
// never echoes a spec), the namespace default for an unbound project, and
// non-retroactivity. L3 (a cluster target) creates a real ServiceAccount and
// asserts the head and worker pods, and a RayJob's cluster and submitter
// templates, run under it. A rule naming an account the platform never
// created fails the apply with an error naming it (the reconciler's log
// and backoff, exactly like a missing storage Secret) rather than pods
// stuck in ContainerCreating; that path is unit-tested in
// internal/provision/live because the view carries no apply-error text
// today (a follow-on in the design spec).
package r20_workload_identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// setWorkloadIdentity PUTs the workload_identity section as admin and
// restores the previous rules when the test ends (the policy is platform
// state). Returns (status, body) so refusals can be asserted.
func setWorkloadIdentity(t *testing.T, tgt req.Target, rules map[string]client.WorkloadIdentityRule) (int, []byte) {
	t.Helper()
	ctx := context.Background()
	admin := tgt.As("admin").API()
	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	r, err := admin.UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{WorkloadIdentity: &rules})
	if err != nil {
		t.Fatalf("update_policy workload_identity: %v", err)
	}
	if r.StatusCode() == http.StatusOK {
		t.Cleanup(func() {
			restore := map[string]client.WorkloadIdentityRule{}
			if before.JSON200.WorkloadIdentity != nil {
				restore = *before.JSON200.WorkloadIdentity
			}
			_, _ = admin.UpdatePolicyWithResponse(context.Background(), client.UpdatePolicyJSONRequestBody{WorkloadIdentity: &restore})
		})
	}
	return r.StatusCode(), r.Body
}

func rule(def, interactive, job, serving string) client.WorkloadIdentityRule {
	r := client.WorkloadIdentityRule{}
	if def != "" {
		r.ServiceAccount = &def
	}
	if interactive != "" {
		r.InteractiveServiceAccount = &interactive
	}
	if job != "" {
		r.JobServiceAccount = &job
	}
	if serving != "" {
		r.ServingServiceAccount = &serving
	}
	return r
}

// resolvedSA reads the identity a workload was admitted with through the
// inproc seam; a cluster target answers from the pods instead (see the L3
// tests), so callers skip when the seam is absent.
func resolvedSA(t *testing.T, tgt req.Target, kind, id string) (string, bool) {
	t.Helper()
	r, ok := tgt.(interface {
		ResolvedServiceAccount(kind, id string) (string, bool)
	})
	if !ok {
		t.Skipf("%s target has no ResolvedServiceAccount seam; the cluster lane proves the identity from the pods", tgt.Name())
	}
	return r.ResolvedServiceAccount(kind, id)
}

func TestWorkloadIdentitySectionValidatesAndReplaces(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "the workload_identity policy section is validated as a unit (400 for an empty project, an empty rule or a non-Kubernetes name), round-trips on the policy view and is section-replaced by PUT")
	ctx := context.Background()
	sa := req.Name("wi")
	st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{
		"*":      rule(sa, "", "", ""),
		"team-a": rule("", "", sa+"-runner", ""),
	})
	if st != http.StatusOK {
		t.Fatalf("PUT workload_identity = %d %s, want 200", st, body)
	}
	view, err := tgt.As("admin").API().GetPolicyWithResponse(ctx)
	if err != nil || view.JSON200 == nil || view.JSON200.WorkloadIdentity == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, view.StatusCode(), view.Body)
	}
	got := *view.JSON200.WorkloadIdentity
	if got["*"].ServiceAccount == nil || *got["*"].ServiceAccount != sa || got["team-a"].JobServiceAccount == nil || *got["team-a"].JobServiceAccount != sa+"-runner" {
		t.Fatalf("policy view workload_identity = %+v", got)
	}
	// A developer may read the policy but never write this section.
	dev, err := tgt.As("dev-a").API().UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{WorkloadIdentity: &map[string]client.WorkloadIdentityRule{"team-a": rule("cluster-admin", "", "", "")}})
	if err != nil || !fixture.Denied(dev.StatusCode()) {
		t.Fatalf("dev-a PUT workload_identity = %v %v, want denied", err, dev.StatusCode())
	}
	for name, bad := range map[string]map[string]client.WorkloadIdentityRule{
		"empty project": {"": rule(sa, "", "", "")},
		"empty rule":    {"team-a": {}},
		"bad name":      {"team-a": rule("Not_A_K8s_Name", "", "", "")},
	} {
		st, body := setWorkloadIdentity(t, tgt, bad)
		if st != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d %s, want 400", name, st, body)
		}
	}
	// The refusals changed nothing.
	after, _ := tgt.As("admin").API().GetPolicyWithResponse(ctx)
	if after.JSON200 == nil || after.JSON200.WorkloadIdentity == nil || len(*after.JSON200.WorkloadIdentity) != 2 {
		t.Fatalf("a refused PUT must leave the section as it was: %s", after.Body)
	}
}

func TestIdentityIsPinnedPerKindAtAdmission(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "admission pins the project's ServiceAccount on a cluster, a job and a service by workload kind; the project rule overrides the \"*\" rule; an unbound project keeps the namespace default; the identity never appears in a response")
	sa := req.Name("wi")
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{
		"*":      rule(sa+"-default", "", "", ""),
		"team-a": rule(sa+"-a", "", sa+"-a-runner", sa+"-a-serving"),
	}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	bodies := map[string][]byte{}

	// Interactive cluster in team-a: the project default.
	id := req.Name("wic")
	st, created := fixture.Create(t, tgt, "dev-a", id, "team-a", nil)
	if st != http.StatusCreated {
		t.Fatalf("create = %d %s", st, created)
	}
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	bodies["create_cluster"] = created
	if got, ok := resolvedSA(t, tgt, "cluster", id); !ok || got != sa+"-a" {
		t.Errorf("cluster identity = %q (%v), want %s", got, ok, sa+"-a")
	}
	// Job in team-a: the job override.
	job := fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(req.Name("wij"), "team-a", "python -c 1", nil))
	jobID, _ := job["id"].(string)
	if got, ok := resolvedSA(t, tgt, "job", jobID); !ok || got != sa+"-a-runner" {
		t.Errorf("job identity = %q (%v), want %s", got, ok, sa+"-a-runner")
	}
	// Service in team-a: the serving override.
	svc := req.Name("wis")
	if st, body := fixture.Deploy(t, tgt, "admin", fixture.ServiceBody(svc, "team-a")); st/100 != 2 {
		t.Fatalf("deploy = %d %s", st, body)
	}
	t.Cleanup(func() { fixture.DeleteService(t, tgt, "admin", svc) })
	if got, ok := resolvedSA(t, tgt, "service", svc); !ok || got != sa+"-a-serving" {
		t.Errorf("service identity = %q (%v), want %s", got, ok, sa+"-a-serving")
	}
	// Cluster in team-b: no project rule, so the "*" default.
	idB := req.Name("wib")
	if st, body := fixture.Create(t, tgt, "dev-b", idB, "team-b", nil); st != http.StatusCreated {
		t.Fatalf("create b = %d %s", st, body)
	}
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", idB) })
	if got, ok := resolvedSA(t, tgt, "cluster", idB); !ok || got != sa+"-default" {
		t.Errorf("unlisted project identity = %q (%v), want the * default %s", got, ok, sa+"-default")
	}

	// The identity is a pod-shaping detail, never on the wire.
	if st, view := fixture.Get(t, tgt, "dev-a", id); st == http.StatusOK {
		raw := fmt.Sprint(view)
		bodies["get_cluster"] = []byte(raw)
	}
	for what, body := range bodies {
		if strings.Contains(string(body), "service_account") || strings.Contains(string(body), sa+"-a") {
			t.Errorf("%s response carries the workload identity: %s", what, body)
		}
	}
}

func TestUnboundProjectKeepsTheNamespaceDefault(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "with no workload_identity rule at all, admission pins nothing and the pods keep the namespace default — the pre-#20 behaviour is the zero value")
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{}); st != http.StatusOK {
		t.Fatalf("clear = %d %s", st, body)
	}
	id := req.Name("win")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	if got, ok := resolvedSA(t, tgt, "cluster", id); ok {
		t.Errorf("no rule must pin no identity, got %q", got)
	}
}

func TestRuleEditIsNeverRetroactive(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "a workload keeps the ServiceAccount it was admitted with when the rule is changed or cleared afterwards")
	sa := req.Name("wi")
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{"team-a": rule(sa, "", "", "")}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	id := req.Name("wir")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	if got, ok := resolvedSA(t, tgt, "cluster", id); !ok || got != sa {
		t.Fatalf("identity = %q (%v), want %s", got, ok, sa)
	}
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{"team-a": rule(sa+"-v2", "", "", "")}); st != http.StatusOK {
		t.Fatalf("PUT v2 = %d %s", st, body)
	}
	if got, ok := resolvedSA(t, tgt, "cluster", id); !ok || got != sa {
		t.Errorf("after the edit the cluster's identity = %q (%v), want the admitted %s", got, ok, sa)
	}
	// A cluster admitted under the new rule gets the new identity.
	id2 := req.Name("wir2")
	fixture.MustCreate(t, tgt, "dev-a", id2, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id2) })
	if got, ok := resolvedSA(t, tgt, "cluster", id2); !ok || got != sa+"-v2" {
		t.Errorf("a new cluster's identity = %q (%v), want %s", got, ok, sa+"-v2")
	}
}

// --- L3: the identity reaches real pods ---

// createServiceAccount creates a run-labelled ServiceAccount in the
// workload namespace and deletes it when the test ends.
func createServiceAccount(t *testing.T, tgt req.Target, name string) {
	t.Helper()
	k, _ := tgt.K8s()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: tgt.Namespace(), Labels: map[string]string{req.RunLabel: req.RunID()},
	}}
	if err := k.Create(context.Background(), sa); err != nil {
		t.Fatalf("create serviceaccount %s: %v", name, err)
	}
	t.Cleanup(func() { _ = k.Delete(context.Background(), sa) })
}

// clusterPods returns the cluster's pods once the head exists.
func clusterPods(t *testing.T, tgt req.Target, id string) []corev1.Pod {
	t.Helper()
	k, _ := tgt.K8s()
	var pods corev1.PodList
	req.Eventually(t, tgt, func() (bool, string) {
		if err := k.List(context.Background(), &pods, ctrlclient.InNamespace(tgt.Namespace()),
			ctrlclient.MatchingLabels{"ray.io/cluster": id}); err != nil {
			return false, err.Error()
		}
		heads := 0
		for _, p := range pods.Items {
			if p.Labels["ray.io/node-type"] == "head" {
				heads++
			}
		}
		return heads == 1, fmt.Sprintf("%d pods, %d heads", len(pods.Items), heads)
	})
	return pods.Items
}

func TestPodsRunUnderTheProjectServiceAccount(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "a cluster's head and worker pods run under the project's ServiceAccount (spec.serviceAccountName), which the platform created and Bifrost only named")
	req.NeedK8s(t, tgt)
	sa := req.Name("wi-sa")
	createServiceAccount(t, tgt, sa)
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{"team-a": rule(sa, "", "", "")}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	id := req.Name("wip")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	fixture.WaitObserved(t, tgt, "dev-a", id, "running")
	for _, p := range clusterPods(t, tgt, id) {
		if p.Spec.ServiceAccountName != sa {
			t.Errorf("pod %s (%s) serviceAccountName = %q, want %s", p.Name, p.Labels["ray.io/node-type"], p.Spec.ServiceAccountName, sa)
		}
	}
}

func TestRayJobClusterAndSubmitterCarryTheJobIdentity(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 20, "a RayJob's cluster templates and its submitter template name the project's job ServiceAccount, so every pod of the run holds one identity")
	req.NeedK8s(t, tgt)
	sa := req.Name("wi-runner")
	createServiceAccount(t, tgt, sa)
	if st, body := setWorkloadIdentity(t, tgt, map[string]client.WorkloadIdentityRule{"team-a": rule("", "", sa, "")}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	ttl := int32(5)
	job := fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(req.Name("wijob"), "team-a", "python -c 1", &ttl))
	jobID, _ := job["id"].(string)
	k, _ := tgt.K8s()
	var rj rayv1.RayJob
	req.Eventually(t, tgt, func() (bool, string) {
		if err := k.Get(context.Background(), ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: jobID}, &rj); err != nil {
			return false, err.Error()
		}
		return true, "RayJob present"
	})
	if rj.Spec.RayClusterSpec == nil || rj.Spec.RayClusterSpec.HeadGroupSpec.Template.Spec.ServiceAccountName != sa {
		t.Errorf("RayJob head template serviceAccountName != %s: %+v", sa, rj.Spec.RayClusterSpec)
	}
	if rj.Spec.SubmitterPodTemplate == nil || rj.Spec.SubmitterPodTemplate.Spec.ServiceAccountName != sa {
		t.Errorf("RayJob submitter template serviceAccountName != %s: %+v", sa, rj.Spec.SubmitterPodTemplate)
	}
}
