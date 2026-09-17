// Requirement 21 — tenant namespaces: each project's clusters, jobs and
// services live in their own Kubernetes namespace, the hard tenant
// boundary of the ATEP Ray Namespace Platform design: the platform's
// ResourceQuota, Pod Identity associations and offboarding-by-deletion all
// key on it, and a pod in one project's namespace cannot name another
// project's ServiceAccount.
//
// The shape: an administrator maps project -> namespace in the policy's
// `namespaces` section (PUT /settings/policy, section-replace, validated as
// a unit; 400 on a single-namespace control plane). Admission pins the
// mapping on each spec and the provisioner writes its network posture into
// the namespace and applies the workload there. A later edit never moves an
// admitted workload. The platform creates the namespace; Bifrost only
// requires it to exist.
//
// Lane coverage: L2 (inproc) proves the section's validation and replace
// semantics, per-kind pinning and non-retroactivity through the inproc
// ResolvedNamespace seam, and the LocalQueue/namespace agreement rule. L3
// (a cluster target declaring the "tenant-namespaces" capability) creates a
// tenant namespace and asserts the RayCluster, its pods and its network
// posture land there and a RayJob follows.
package r21_tenant_namespaces

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// setNamespaces PUTs the namespaces section as admin and restores the
// previous map when the test ends. Returns (status, body).
func setNamespaces(t *testing.T, tgt req.Target, m map[string]string) (int, []byte) {
	t.Helper()
	ctx := context.Background()
	admin := tgt.As("admin").API()
	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	r, err := admin.UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{Namespaces: &m})
	if err != nil {
		t.Fatalf("update_policy namespaces: %v", err)
	}
	if r.StatusCode() == http.StatusOK {
		t.Cleanup(func() {
			restore := map[string]string{}
			if before.JSON200.Namespaces != nil {
				restore = *before.JSON200.Namespaces
			}
			_, _ = admin.UpdatePolicyWithResponse(context.Background(), client.UpdatePolicyJSONRequestBody{Namespaces: &restore})
		})
	}
	return r.StatusCode(), r.Body
}

func resolvedNS(t *testing.T, tgt req.Target, kind, id string) (string, bool) {
	t.Helper()
	r, ok := tgt.(interface {
		ResolvedNamespace(kind, id string) (string, bool)
	})
	if !ok {
		t.Skipf("%s target has no ResolvedNamespace seam; the cluster lane proves placement from the objects", tgt.Name())
	}
	return r.ResolvedNamespace(kind, id)
}

func TestNamespacesSectionValidatesAndReplaces(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 21, "the namespaces policy section is validated as a unit (400 for an empty project, \"*\", or a non-namespace name), round-trips on the policy view and is section-replaced by PUT; developers cannot write it")
	req.NeedsCapability(t, tgt, "tenant-namespaces")
	ctx := context.Background()
	ns := req.Name("ns")
	st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns})
	if st != http.StatusOK {
		t.Fatalf("PUT namespaces = %d %s, want 200", st, body)
	}
	view, err := tgt.As("admin").API().GetPolicyWithResponse(ctx)
	if err != nil || view.JSON200 == nil || view.JSON200.Namespaces == nil || (*view.JSON200.Namespaces)["team-a"] != ns {
		t.Fatalf("get_policy namespaces: err=%v body=%s", err, view.Body)
	}
	dev, err := tgt.As("dev-a").API().UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{Namespaces: &map[string]string{"team-a": "kube-system"}})
	if err != nil || !fixture.Denied(dev.StatusCode()) {
		t.Fatalf("dev-a PUT namespaces = %v %v, want denied", err, dev.StatusCode())
	}
	for name, bad := range map[string]map[string]string{
		"empty project": {"": ns},
		"star":          {"*": ns},
		"bad name":      {"team-a": "Not.A.Namespace"},
	} {
		if st, body := setNamespaces(t, tgt, bad); st != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d %s, want 400", name, st, body)
		}
	}
	after, _ := tgt.As("admin").API().GetPolicyWithResponse(ctx)
	if after.JSON200 == nil || after.JSON200.Namespaces == nil || (*after.JSON200.Namespaces)["team-a"] != ns {
		t.Fatalf("a refused PUT must leave the section as it was: %s", after.Body)
	}
}

func TestNamespaceIsPinnedPerKindAtAdmission(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 21, "admission pins the project's namespace on a cluster, a job and a service; an unmapped project keeps the default; the namespace never appears in a response")
	req.NeedsCapability(t, tgt, "tenant-namespaces")
	ns := req.Name("ns")
	if st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	id := req.Name("tnc")
	st, created := fixture.Create(t, tgt, "dev-a", id, "team-a", nil)
	if st != http.StatusCreated {
		t.Fatalf("create = %d %s", st, created)
	}
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	if got, ok := resolvedNS(t, tgt, "cluster", id); !ok || got != ns {
		t.Errorf("cluster namespace = %q (%v), want %s", got, ok, ns)
	}
	job := fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(req.Name("tnj"), "team-a", "python -c 1", nil))
	jobID, _ := job["id"].(string)
	if got, ok := resolvedNS(t, tgt, "job", jobID); !ok || got != ns {
		t.Errorf("job namespace = %q (%v), want %s", got, ok, ns)
	}
	svc := req.Name("tns")
	if st, body := fixture.Deploy(t, tgt, "admin", fixture.ServiceBody(svc, "team-a")); st/100 != 2 {
		t.Fatalf("deploy = %d %s", st, body)
	}
	t.Cleanup(func() { fixture.DeleteService(t, tgt, "admin", svc) })
	if got, ok := resolvedNS(t, tgt, "service", svc); !ok || got != ns {
		t.Errorf("service namespace = %q (%v), want %s", got, ok, ns)
	}
	idB := req.Name("tnb")
	if st, body := fixture.Create(t, tgt, "dev-b", idB, "team-b", nil); st != http.StatusCreated {
		t.Fatalf("create b = %d %s", st, body)
	}
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", idB) })
	if got, ok := resolvedNS(t, tgt, "cluster", idB); ok {
		t.Errorf("an unmapped project must pin nothing, got %q", got)
	}
	if strings.Contains(string(created), "namespace") {
		t.Errorf("create response carries the namespace: %s", created)
	}
	if st, view := fixture.Get(t, tgt, "dev-a", id); st == http.StatusOK && strings.Contains(fmt.Sprint(view), ns) {
		t.Errorf("get response carries the namespace: %v", view)
	}
}

func TestMappingEditNeverMovesAnAdmittedWorkload(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 21, "a workload stays in the namespace it was admitted into when the mapping changes; a new one lands in the new namespace")
	req.NeedsCapability(t, tgt, "tenant-namespaces")
	ns := req.Name("ns")
	if st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	id := req.Name("tnr")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	if got, ok := resolvedNS(t, tgt, "cluster", id); !ok || got != ns {
		t.Fatalf("namespace = %q (%v), want %s", got, ok, ns)
	}
	if st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns + "-v2"}); st != http.StatusOK {
		t.Fatalf("PUT v2 = %d %s", st, body)
	}
	if got, _ := resolvedNS(t, tgt, "cluster", id); got != ns {
		t.Errorf("the edit moved an admitted cluster to %q", got)
	}
	id2 := req.Name("tnr2")
	fixture.MustCreate(t, tgt, "dev-a", id2, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id2) })
	if got, _ := resolvedNS(t, tgt, "cluster", id2); got != ns+"-v2" {
		t.Errorf("a new cluster's namespace = %q, want %s", got, ns+"-v2")
	}
}

// --- L3: the objects really land in the tenant namespace ---

// createNamespace creates a run-labelled tenant namespace (the platform's
// job in production) and deletes it when the test ends.
func createNamespace(t *testing.T, tgt req.Target, name string) {
	t.Helper()
	k, _ := tgt.K8s()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{req.RunLabel: req.RunID()}}}
	if err := k.Create(context.Background(), ns); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() { _ = k.Delete(context.Background(), ns) })
}

func TestWorkloadsLandInTheTenantNamespaceWithItsPosture(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 21, "a mapped project's RayCluster, its pods, its per-cluster allow and the namespace default-deny/tenant-allow posture all live in the tenant namespace, none in the default one; the cluster runs and is torn down there")
	req.NeedsCapability(t, tgt, "tenant-namespaces")
	req.NeedK8s(t, tgt)
	ctx := context.Background()
	k, _ := tgt.K8s()
	ns := req.Name("tenant")
	createNamespace(t, tgt, ns)
	if st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	id := req.Name("tnl")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	t.Cleanup(func() { fixture.Delete(t, tgt, "admin", id) })
	fixture.WaitObserved(t, tgt, "dev-a", id, "running")

	var rc rayv1.RayCluster
	if err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: id}, &rc); err != nil {
		t.Fatalf("RayCluster %s not in tenant namespace %s: %v", id, ns, err)
	}
	if err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: id}, &rc); err == nil {
		t.Errorf("RayCluster %s must not also exist in the default namespace %s", id, tgt.Namespace())
	}
	var pods corev1.PodList
	if err := k.List(ctx, &pods, ctrlclient.InNamespace(ns), ctrlclient.MatchingLabels{"ray.io/cluster": id}); err != nil || len(pods.Items) == 0 {
		t.Fatalf("pods in %s = %d (%v), want the cluster's pods", ns, len(pods.Items), err)
	}
	var nps networkingv1.NetworkPolicyList
	if err := k.List(ctx, &nps, ctrlclient.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, np := range nps.Items {
		have[np.Name] = true
	}
	for _, want := range []string{"bifrost-default-deny", "bifrost-tenant-allow", "bifrost-cluster-" + id} {
		if !have[want] {
			t.Errorf("NetworkPolicy %s missing from tenant namespace %s; have %v", want, ns, have)
		}
	}
	// Teardown reaches into the tenant namespace too.
	fixture.Delete(t, tgt, "admin", id)
	req.Eventually(t, tgt, func() (bool, string) {
		err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: id}, &rc)
		return err != nil, fmt.Sprintf("raycluster present=%v", err == nil)
	})
}

func TestRayJobLandsInTheTenantNamespace(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 21, "a mapped project's RayJob is applied in the tenant namespace, so its ephemeral cluster and submitter run there")
	req.NeedsCapability(t, tgt, "tenant-namespaces")
	req.NeedK8s(t, tgt)
	ctx := context.Background()
	k, _ := tgt.K8s()
	ns := req.Name("tenantj")
	createNamespace(t, tgt, ns)
	if st, body := setNamespaces(t, tgt, map[string]string{"team-a": ns}); st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	ttl := int32(5)
	job := fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(req.Name("tnjob"), "team-a", "python -c 1", &ttl))
	jobID, _ := job["id"].(string)
	var rj rayv1.RayJob
	req.Eventually(t, tgt, func() (bool, string) {
		err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: jobID}, &rj)
		return err == nil, fmt.Sprintf("rayjob in %s: %v", ns, err)
	})
}
