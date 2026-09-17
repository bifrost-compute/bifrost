package live

import (
	"context"
	"errors"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"

	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/provision"
)

func managedCluster(ns, name string) *rayv1.RayCluster {
	return &rayv1.RayCluster{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: ns, Labels: map[string]string{provision.ManagedByLabel: provision.FieldManager},
	}}
}

func fakeClusterClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	sch, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(sch).WithObjects(objs...).Build()
}

// Tenant namespaces (#21): a spec's pinned namespace is honoured only in
// tenant mode; single-namespace mode ignores it because a namespaced Role
// could not reach it anyway (and the API refuses to set one there).
func TestNsForHonoursThePinOnlyInTenantMode(t *testing.T) {
	single := &Client{namespace: "bifrost"}
	if got := single.nsFor("team-a"); got != "bifrost" {
		t.Errorf("single-namespace nsFor = %q, want the default", got)
	}
	tenant := &Client{namespace: "bifrost", tenantNamespaces: true}
	if got := tenant.nsFor("team-a"); got != "team-a" {
		t.Errorf("tenant nsFor = %q, want the pin", got)
	}
	if got := tenant.nsFor(""); got != "bifrost" {
		t.Errorf("tenant nsFor(\"\") = %q, want the default", got)
	}
}

// locate answers from the default in single-namespace mode without a
// call; in tenant mode it finds a managed object wherever it lives,
// caches the answer, and reports NotFound for a name nowhere.
func TestLocateFindsManagedObjectsAcrossNamespaces(t *testing.T) {
	ctx := context.Background()
	k := fakeClusterClient(t, managedCluster("team-a", "c1"), managedCluster("bifrost", "c2"),
		// An unmanaged RayCluster of the same name in another namespace is
		// never Bifrost's: the managed-by label is the ownership test.
		&rayv1.RayCluster{ObjectMeta: metav1.ObjectMeta{Name: "c3", Namespace: "someone-elses"}})
	c := &Client{c: k, namespace: "bifrost", tenantNamespaces: true}
	for id, want := range map[string]string{"c1": "team-a", "c2": "bifrost"} {
		ns, err := c.locate(ctx, id, &rayv1.RayClusterList{})
		if err != nil || ns != want {
			t.Errorf("locate(%s) = %q, %v; want %q", id, ns, err, want)
		}
		if v, ok := c.located.Load(id); !ok || v != want {
			t.Errorf("locate(%s) must cache %q, got %v", id, want, v)
		}
	}
	if _, err := c.locate(ctx, "c3", &rayv1.RayClusterList{}); !apierrors.IsNotFound(err) {
		t.Errorf("an unmanaged object must not be located: %v", err)
	}
	if ns, err := c.locateOrDefault(ctx, "c3", &rayv1.RayClusterList{}); err != nil || ns != "bifrost" {
		t.Errorf("locateOrDefault of nothing = %q, %v; want the default", ns, err)
	}
	single := &Client{c: k, namespace: "bifrost"}
	if ns, err := single.locate(ctx, "c1", &rayv1.RayClusterList{}); err != nil || ns != "bifrost" {
		t.Errorf("single-namespace locate = %q, %v; want the default without looking", ns, err)
	}
}

// Observe reads a cluster in its tenant namespace and reports the head
// Service URL in that namespace — the address the gateway proxies to.
func TestObserveAndListSpanTenantNamespaces(t *testing.T) {
	ctx := context.Background()
	k := fakeClusterClient(t, managedCluster("team-a", "c1"), managedCluster("bifrost", "c2"))
	c := &Client{c: k, namespace: "bifrost", tenantNamespaces: true}
	obs, err := c.Observe(ctx, "c1")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.ApiBaseUrl == nil || *obs.ApiBaseUrl != "http://c1-head-svc.team-a.svc:8265" {
		t.Errorf("api base url = %v, want the team-a head service", obs.ApiBaseUrl)
	}
	if url, _ := c.DashboardApiBase("c1"); url != "http://c1-head-svc.team-a.svc:8265" {
		t.Errorf("DashboardApiBase after Observe = %q", url)
	}
	all, err := c.List(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("List = %d clusters, %v; want both namespaces", len(all), err)
	}
	if _, err := c.Observe(ctx, "nope"); err == nil {
		t.Error("Observe of nothing must fail")
	} else {
		var perr provision.ProvisionError
		if !errors.As(err, &perr) || perr.Kind != provision.ProvisionErrNotFound {
			t.Errorf("err = %v, want ProvisionErrNotFound", err)
		}
	}
	// A stale cache entry (the object moved or was recreated elsewhere)
	// is dropped and the lookup repeated.
	c.remember("c2", "wrong-ns")
	if obs, err := c.Observe(ctx, "c2"); err != nil || *obs.ApiBaseUrl != "http://c2-head-svc.bifrost.svc:8265" {
		t.Errorf("Observe with a stale cache = %v, %v", obs.ApiBaseUrl, err)
	}
	// Single-namespace mode lists the default namespace only.
	single := &Client{c: k, namespace: "bifrost"}
	only, err := single.List(ctx)
	if err != nil || len(only) != 1 || only[0].ID != "c2" {
		t.Errorf("single-namespace List = %+v, %v; want c2 only", only, err)
	}
}

// Terminate and ReapNetworkPolicies clean a tenant namespace, including
// the per-cluster policies of a CR that already vanished — after a
// restart nothing else knows where they were.
func TestTerminateAndReapCleanTheTenantNamespace(t *testing.T) {
	ctx := context.Background()
	allow := provision.ClusterAllowNetworkPolicy("c1", nil)
	allow.Namespace = "team-a"
	k := fakeClusterClient(t, managedCluster("team-a", "c1"), allow)
	c := &Client{c: k, namespace: "bifrost", tenantNamespaces: true}
	if err := c.Terminate(ctx, "c1"); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	var rc rayv1.RayCluster
	if err := k.Get(ctx, client.ObjectKey{Namespace: "team-a", Name: "c1"}, &rc); !apierrors.IsNotFound(err) {
		t.Errorf("RayCluster must be gone from team-a: %v", err)
	}
	var np networkingv1.NetworkPolicy
	if err := k.Get(ctx, client.ObjectKey{Namespace: "team-a", Name: provision.ClusterAllowPolicyName("c1")}, &np); !apierrors.IsNotFound(err) {
		t.Errorf("per-cluster allow must be gone from team-a: %v", err)
	}

	// Orphaned policy, no CR, cold cache: the reap finds it anyway.
	orphan := provision.ClusterAllowNetworkPolicy("gone", nil)
	orphan.Namespace = "team-b"
	k2 := fakeClusterClient(t, orphan)
	c2 := &Client{c: k2, namespace: "bifrost", tenantNamespaces: true}
	if err := c2.ReapNetworkPolicies(ctx, core.ClusterId("gone")); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if err := k2.Get(ctx, client.ObjectKey{Namespace: "team-b", Name: provision.ClusterAllowPolicyName("gone")}, &np); !apierrors.IsNotFound(err) {
		t.Errorf("orphaned allow must be reaped from team-b: %v", err)
	}
}
