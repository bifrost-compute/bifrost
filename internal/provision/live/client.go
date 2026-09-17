// Package live is Bifrost's live Kubernetes client (Wave 1 Task 6): the
// only place in the codebase that opens a real connection to an API
// server. It wires internal/provision's pure translators
// (RayClusterFor/RayServiceFor/CohortFor/... and the interfaces they
// implement — Provisioner/PoolProvisioner/ServiceProvisioner) onto
// controller-runtime, mirroring the predecessor provision crate's `kuberay_client`/
// `kueue_client` (feature `kuberay`).
//
// Client mechanics (ADR-0001 #5, task-6-brief.md): controller-runtime as a
// LIBRARY only — client.New() uncached (no Manager, no informer cache;
// every read below is a live round trip to the API server), a scheme
// registering ray v1 + kueue v1beta2 + the core Kubernetes API groups;
// mutations are server-side apply (client.Patch with client.Apply +
// client.FieldOwner(provision.FieldManager) [+ client.ForceOwnership,
// except pool objects — see ApplyPool]); reads are Get/List for
// observation, plus a raw clientset for the pod-logs subresource, which
// controller-runtime's typed client has no verb for.
//
// This file is in scripts/coverage-gate.sh's COVERAGE_EXCLUDE and MUST
// stay thin: every method here is I/O plus a direct call into
// internal/provision's pure functions (translators, NodeBreakdown,
// EventsFromK8s, TailLines, ZeroStatus, ...) or straightforward
// list/filter/delete loops with no meaningful branching of their own.
// Anything with logic worth unit-testing belongs in internal/provision,
// not here — see internal/provision/observe.go's package doc for why the
// live-read mappers in particular live there.
package live

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	kueuev1beta2 "sigs.k8s.io/kueue/apis/kueue/v1beta2"

	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/provision"
)

// Client is the live KubeRay + Kueue backend, scoped to one namespace.
// Implements [provision.Provisioner] and [provision.PoolProvisioner]
// directly; [provision.ServiceProvisioner] is implemented by
// [ServiceClient] (see NewServiceClient) because Go methods — unlike Rust
// trait impls — cannot be overloaded on return type alone, and
// Provisioner.List / ServiceProvisioner.List share a name but return
// different element types.
type Client struct {
	c           client.Client
	clientset   kubernetes.Interface
	namespace   string
	autoscaling bool
	// tenantNamespaces (#21, `serve --tenant-namespaces`) lets a spec pin
	// the namespace its objects live in (core.ClusterSpec.NamespaceResolved,
	// the project's tenant namespace from the policy's `namespaces` map).
	// Off, every object lives in namespace and every read is scoped to it —
	// today's behaviour, and the one a namespaced Role permits. On, reads
	// span every namespace (a ClusterRole) and by-id operations locate the
	// object first (see getManaged / locate).
	tenantNamespaces bool
	// located caches id -> namespace for objects this client applied or
	// listed, so a by-id read in tenant mode is one Get, not a cluster-wide
	// list. A miss (restart, object moved) falls back to the list; a stale
	// entry is dropped on NotFound.
	located sync.Map
	// scheduling is stamped onto every tenant pod template this client
	// applies (provision.Scheduling): deployment-wide placement such as
	// the tolerations a tainted user node group demands.
	scheduling provision.Scheduling
	// packageProxy, when configured (`serve --package-proxy`), is the one
	// egress exception the default-deny posture grants a workload whose
	// runtime env installs packages (provision.PackageProxy, issue #56).
	// nil = no allowance is ever written.
	packageProxy *provision.PackageProxy

	// apiServer caches where the API server answers (see
	// provision.APIServerEndpoint): read from the `kubernetes` Endpoints
	// once per apiServerTTL, so a cluster create does not add a round trip
	// and a control-plane endpoint change is picked up within minutes.
	apiServerMu   sync.Mutex
	apiServer     *provision.APIServerEndpoint
	apiServerRead time.Time
}

// apiServerTTL bounds how stale the cached API server endpoint may be.
const apiServerTTL = 5 * time.Minute

var (
	_ provision.Provisioner     = (*Client)(nil)
	_ provision.PoolProvisioner = (*Client)(nil)
)

// NewScheme builds the runtime.Scheme this package's client needs: the
// core Kubernetes API groups (corev1, networkingv1, eventsv1, ...) plus
// ray.io/v1 and kueue.x-k8s.io/v1beta2 (ADR-0003's pinned typed APIs).
func NewScheme() (*runtime.Scheme, error) {
	sch := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(sch); err != nil {
		return nil, fmt.Errorf("live: registering core k8s API groups: %w", err)
	}
	if err := rayv1.AddToScheme(sch); err != nil {
		return nil, fmt.Errorf("live: registering ray.io/v1: %w", err)
	}
	if err := kueuev1beta2.AddToScheme(sch); err != nil {
		return nil, fmt.Errorf("live: registering kueue.x-k8s.io/v1beta2: %w", err)
	}
	return sch, nil
}

// NewClient connects to the API server described by cfg (ambient
// kubeconfig / in-cluster service account is the caller's concern to
// resolve into cfg, e.g. via ctrl.GetConfig()) and returns a live
// [Client] scoped to namespace. autoscaling selects the field-ownership
// regime new clusters apply under (ADR-0007-equivalent; see
// [provision.RayClusterFor]). Uncached per ADR-0001 #5: no Manager, no
// informer cache — client.New() talks to the API server directly on every
// call.
// Option configures a [Client] beyond NewClient's positional parameters.
type Option func(*Client)

// WithScheduling sets the placement every tenant pod carries (see
// provision.Scheduling): `serve --ray-node-selector` / `--ray-tolerations`.
func WithScheduling(s provision.Scheduling) Option {
	return func(c *Client) { c.scheduling = s }
}

// WithTenantNamespaces enables per-project tenant namespaces (#21): a
// workload spec's NamespaceResolved is honoured, reads span every
// namespace, and the control plane's own namespace is labelled so the
// tenant-allow policy in each project namespace admits it. Requires the
// chart's cluster-wide RBAC.
func WithTenantNamespaces() Option {
	return func(c *Client) { c.tenantNamespaces = true }
}

// WithPackageProxy sets the platform package proxy (`serve
// --package-proxy`, issue #56): workloads whose runtime env installs
// packages get a per-workload egress NetworkPolicy to it under the
// default-deny posture. nil (the flag's default) writes no allowance.
func WithPackageProxy(proxy *provision.PackageProxy) Option {
	return func(c *Client) { c.packageProxy = proxy }
}

func NewClient(cfg *rest.Config, namespace string, autoscaling bool, opts ...Option) (*Client, error) {
	sch, err := NewScheme()
	if err != nil {
		return nil, err
	}
	c, err := client.New(cfg, client.Options{Scheme: sch})
	if err != nil {
		return nil, fmt.Errorf("live: building controller-runtime client: %w", err)
	}
	// controller-runtime's typed client has no verb for the pod logs
	// subresource; a plain clientset is the only way to reach
	// GET /api/v1/namespaces/{ns}/pods/{name}/log.
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("live: building clientset for pod logs: %w", err)
	}
	cl := &Client{c: c, clientset: clientset, namespace: namespace, autoscaling: autoscaling}
	for _, o := range opts {
		o(cl)
	}
	return cl, nil
}

// ServiceClient is [Client]'s [provision.ServiceProvisioner] façade over
// the same connection — a distinct Go type solely because
// Provisioner.List and ServiceProvisioner.List can't both be named `List`
// on the same receiver with different return types the way Rust's two
// trait impls can share one struct.
type ServiceClient struct {
	*Client
}

var _ provision.ServiceProvisioner = (*ServiceClient)(nil)

// NewServiceClient returns c's ServiceProvisioner façade.
func NewServiceClient(c *Client) *ServiceClient { return &ServiceClient{c} }

func apiBaseURL(namespace, id string) string {
	// KubeRay's head service is always named "<id>-head-svc"; the
	// dashboard / Ray Job Submission API listens on 8265.
	return fmt.Sprintf("http://%s-head-svc.%s.svc:8265", id, namespace)
}

// nsFor is the namespace a workload's objects live in: the namespace its
// spec pinned at admission when tenant namespaces are on, else the
// client's default. A pinned namespace is ignored in single-namespace
// mode on purpose — a namespaced Role cannot reach anywhere else, so the
// policy PUT that would set one is refused there (api.Server.TenantNamespaces).
func (c *Client) nsFor(pinned string) string {
	if c.tenantNamespaces && pinned != "" {
		return pinned
	}
	return c.namespace
}

// listScope is the namespace bound of a managed-object list: the default
// namespace, or every namespace in tenant mode.
func (c *Client) listScope() client.ListOption {
	if c.tenantNamespaces {
		return client.InNamespace("")
	}
	return client.InNamespace(c.namespace)
}

func (c *Client) remember(id, namespace string) { c.located.Store(id, namespace) }
func (c *Client) forget(id string)              { c.located.Delete(id) }

// knownNamespace is the namespace id was last seen in, else the default —
// for callers without a context (MetricsEndpoint, DashboardApiBase) and
// for deletes of objects that may already be gone.
func (c *Client) knownNamespace(id string) string {
	if ns, ok := c.cached(id); ok {
		return ns
	}
	return c.namespace
}

// cached is the located-cache read; the map only ever holds strings.
func (c *Client) cached(id string) (string, bool) {
	v, ok := c.located.Load(id)
	if !ok {
		return "", false
	}
	ns, isString := v.(string)
	return ns, isString
}

// errNotLocated is locate's "no managed object of that name anywhere".
var errNotLocated = apierrors.NewNotFound(schema.GroupResource{Group: "ray.io", Resource: "managed"}, "")

// locate returns the namespace holding the managed object named id, of
// the kind list is for. Single-namespace mode answers the default without
// a call. Tenant mode answers from the cache, else lists the kind across
// every namespace by the managed-by label and matches the name — the
// restart-recovery path (observation over memory: the store never holds a
// namespace the cluster does not). Not found anywhere is errNotLocated.
func (c *Client) locate(ctx context.Context, id string, list client.ObjectList) (string, error) {
	if !c.tenantNamespaces {
		return c.namespace, nil
	}
	if ns, ok := c.cached(id); ok {
		return ns, nil
	}
	if err := c.c.List(ctx, list, client.InNamespace(""), client.MatchingLabels{provision.ManagedByLabel: provision.FieldManager}); err != nil {
		return "", err
	}
	items, err := meta.ExtractList(list)
	if err != nil {
		return "", err
	}
	for _, item := range items {
		if o, ok := item.(client.Object); ok && o.GetName() == id {
			c.remember(id, o.GetNamespace())
			return o.GetNamespace(), nil
		}
	}
	return "", errNotLocated
}

// locateOrDefault is locate for callers whose operation is a harmless
// no-op in the wrong namespace (deletes, event and log reads of a gone
// cluster): not found anywhere answers the default namespace.
func (c *Client) locateOrDefault(ctx context.Context, id string, list client.ObjectList) (string, error) {
	ns, err := c.locate(ctx, id, list)
	if err == nil {
		return ns, nil
	}
	if apierrors.IsNotFound(err) {
		return c.namespace, nil
	}
	return "", err
}

// getManaged reads the managed object named id into obj, locating its
// namespace first in tenant mode. A cached namespace that no longer holds
// the object is dropped and the lookup repeated once. NotFound anywhere is
// a NotFound error, so callers keep their apierrors.IsNotFound checks.
func (c *Client) getManaged(ctx context.Context, id string, obj client.Object, list client.ObjectList) error {
	if !c.tenantNamespaces {
		return c.c.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: id}, obj)
	}
	if ns, ok := c.cached(id); ok {
		err := c.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: id}, obj)
		if err == nil || !apierrors.IsNotFound(err) {
			return err
		}
		c.forget(id)
	}
	ns, err := c.locate(ctx, id, list)
	if err != nil {
		return err
	}
	return c.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: id}, obj)
}

func serviceURL(namespace, name string) string {
	return fmt.Sprintf("http://%s-serve-svc.%s.svc:8000", name, namespace)
}

// wrapErr turns a non-nil client-go/controller-runtime error into a
// [provision.ProvisionError] with [provision.ProvisionErrBackend] — it
// does NOT itself special-case NotFound. Every call site that needs the
// NotFound distinction checks apierrors.IsNotFound(err) and constructs
// [provision.ProvisionErrNotFound] directly BEFORE ever calling wrapErr
// (e.g. Observe, ClusterNodes, setSuspend), so wrapErr never even sees
// those errors; it only wraps the generic "something else went wrong"
// case.
func wrapErr(err error) error {
	if err == nil {
		return nil
	}
	return provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: err.Error()}
}

// applySSA performs a server-side-apply Patch of obj (ADR-0001 #5 /
// task-6-brief.md's literal instruction:
// `client.Patch(ctx, obj, client.Apply, ...)`), centralizing every SSA
// call site in this package behind one deprecation suppression AND the
// [provision.ZeroStatus] guard. This is the ONLY function in the package
// that calls client.Patch with client.Apply — every apply site in this
// file goes through it — so ZeroStatus firing here, unconditionally,
// before every Patch, is structural: no apply site can forget it (unlike
// a per-call-site convention, which is exactly what let the
// ResourceFlavor apply skip it in this file's first draft). ZeroStatus
// itself is a documented no-op for types with no `.Status` field (e.g.
// ResourceFlavor, NetworkPolicy) or types it doesn't recognize, so calling
// it on every obj here is always safe.
//
// controller-runtime v0.24 offers a newer typed `c.Apply(ctx,
// applyConfiguration, ...)` API, but it requires a generated
// applyconfigurations package — code-generator's applyconfiguration-gen
// output — which does not exist (and is not vendored) for the third-party
// ray.io/v1 or kueue.x-k8s.io/v1beta2 types this client applies. The
// classic Patch-with-client.Apply path is the only viable SSA mechanism
// available for these types, so the deprecation is suppressed here rather
// than at each of this file's apply sites.
func applySSA(ctx context.Context, c client.Client, obj client.Object, opts ...client.PatchOption) error {
	provision.ZeroStatus(obj)
	return c.Patch(ctx, obj, client.Apply, opts...) //nolint:staticcheck // SA1019: see doc comment
}

// ---------------------------------------------------------------------------
// Network posture (namespace-level default-deny + allows, per-cluster allow)
// ---------------------------------------------------------------------------

// adminManagedDeny is the check-then-apply probe: does namespace carry a
// default-deny NetworkPolicy Bifrost does not manage? If so, an admin runs
// their own network posture and Bifrost must leave ALL network policy in
// the namespace untouched. Ported from kuberay_client.rs:160-174.
func (c *Client) adminManagedDeny(ctx context.Context, namespace string) (bool, error) {
	var list networkingv1.NetworkPolicyList
	if err := c.c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return false, wrapErr(err)
	}
	for i := range list.Items {
		p := &list.Items[i]
		ours := p.Labels[provision.ManagedByLabel] == provision.FieldManager
		if !ours && provision.IsDefaultDeny(p) {
			return true, nil
		}
	}
	return false, nil
}

// applyNetworkPolicy server-side-applies one NetworkPolicy manifest into
// namespace. Ported from kuberay_client.rs:176-204.
func (c *Client) applyNetworkPolicy(ctx context.Context, namespace string, policy *networkingv1.NetworkPolicy) error {
	policy.Namespace = namespace
	return wrapErr(applySSA(ctx, c.c, policy, client.FieldOwner(provision.FieldManager), client.ForceOwnership))
}

// ensureClusterAllow ensures the per-cluster intra-tenant allow policy for
// id (kuberay_client.rs:211-234): cluster pods may talk to each other, and
// to nothing else. Skipped under an admin-managed default-deny, same as
// the namespace posture — Bifrost never widens an admin posture.
func (c *Client) ensureClusterAllow(ctx context.Context, namespace, id string, owner *string) error {
	deny, err := c.adminManagedDeny(ctx, namespace)
	if err != nil {
		return err
	}
	if deny {
		return nil
	}
	return c.applyNetworkPolicy(ctx, namespace, provision.ClusterAllowNetworkPolicy(id, owner))
}

// ensureStorageSourcesExist fails fast when an object the spec's storage
// entries (requirement 12) name is missing from the workload namespace, so
// the cluster surfaces a condition the user can read instead of pods stuck
// in CreateContainerConfigError (a missing Secret) or Pending (a missing
// claim). The check is METADATA ONLY: the Get asks for a
// PartialObjectMetadata, so a Secret's data never reaches Bifrost's
// process (RBAC grants `secrets: get`, and this is the only use of it).
func (c *Client) ensureStorageSourcesExist(ctx context.Context, namespace string, storage []core.ResolvedStorage) error {
	return ensureStorageSourcesExist(ctx, c.c, namespace, storage)
}

func ensureStorageSourcesExist(ctx context.Context, c client.Client, namespace string, storage []core.ResolvedStorage) error {
	for _, st := range storage {
		meta := &metav1.PartialObjectMetadata{}
		var name string
		switch st.Source.OrDefault() {
		case core.StorageSourcePersistentVolumeClaim:
			meta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("PersistentVolumeClaim"))
			name = st.ClaimName
		default:
			meta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
			name = st.SecretName
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, meta); err != nil {
			if apierrors.IsNotFound(err) {
				return provision.ProvisionError{Kind: provision.ProvisionErrBackend,
					Message: fmt.Sprintf("%s %q not found in namespace %s (storage entry %q)", meta.GetObjectKind().GroupVersionKind().Kind, name, namespace, st.Name)}
			}
			return wrapErr(err)
		}
	}
	return nil
}

// ensureServiceAccountExists fails fast when the ServiceAccount a spec's
// workload identity (#20) names is missing from the workload namespace, so
// the workload surfaces a readable condition instead of pods that the
// kubelet refuses to create (a pod naming a missing ServiceAccount stays
// in ContainerCreating with "serviceaccount not found"). Metadata only,
// like the storage check: Bifrost never reads the account's tokens or
// binds anything to it — the platform owns the account and its cloud IAM
// binding. nil names nothing (the namespace default) and passes.
func (c *Client) ensureServiceAccountExists(ctx context.Context, namespace string, serviceAccount *string) error {
	return ensureServiceAccountExists(ctx, c.c, namespace, serviceAccount)
}

func ensureServiceAccountExists(ctx context.Context, c client.Client, namespace string, serviceAccount *string) error {
	if serviceAccount == nil || *serviceAccount == "" {
		return nil
	}
	meta := &metav1.PartialObjectMetadata{}
	meta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("ServiceAccount"))
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: *serviceAccount}, meta); err != nil {
		if apierrors.IsNotFound(err) {
			return provision.ProvisionError{Kind: provision.ProvisionErrBackend,
				Message: fmt.Sprintf("ServiceAccount %q not found in namespace %s (workload identity)", *serviceAccount, namespace)}
		}
		return wrapErr(err)
	}
	return nil
}

// deleteClusterAllow deletes the per-cluster allow policy for id, plus the
// per-workload egress policies a cluster may have carried (autoscaler,
// package proxy). Idempotent: already-gone is success. Ported from
// kuberay_client.rs:239-256.
func (c *Client) deleteClusterAllow(ctx context.Context, namespace, id string) error {
	for _, name := range []string{provision.ClusterAllowPolicyName(id), provision.AutoscalerPolicyName(id), provision.PackageProxyPolicyName(id)} {
		np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := c.c.Delete(ctx, np); err != nil && !apierrors.IsNotFound(err) {
			return wrapErr(err)
		}
	}
	return nil
}

// ensureAutoscalerEgress applies the policy that lets this cluster's head —
// where KubeRay runs the autoscaler sidecar — reach the API server. Skipped
// under an admin-managed default-deny, like every policy Bifrost writes.
//
// The endpoint is not optional: a control plane started with
// --ray-autoscaling that cannot read the `kubernetes` EndpointSlice (RBAC) would
// otherwise provision clusters whose autoscaler dies quietly, which is the
// failure this exists to end. So the cluster gets a readable error instead.
func (c *Client) ensureAutoscalerEgress(ctx context.Context, namespace, id string) error {
	deny, err := c.adminManagedDeny(ctx, namespace)
	if err != nil {
		return err
	}
	if deny {
		return nil
	}
	api, err := c.apiServerEndpoint(ctx)
	if err != nil {
		return err
	}
	return c.applyNetworkPolicy(ctx, namespace, provision.AutoscalerEgressNetworkPolicy(id, api))
}

// ensurePackageProxyEgress applies the per-workload egress policy that lets
// this workload's pods reach the platform package proxy (issue #56) — but
// only when a proxy is configured AND the workload's runtime env actually
// installs packages (provision.RuntimeEnvInstallsPackages): a workload
// without a pip install gets no allowance at all. Skipped under an
// admin-managed default-deny, like every policy Bifrost writes.
//
// runtimeEnvYaml is the workload's admitted runtime env: a job's
// spec.RuntimeEnvYaml (environment-compiled or hand-written), or a
// cluster's pinned environment resolution (Ray has no cluster-level
// runtime_env, but the resolution is the cluster-wide default jobs run
// with, and Ray's agent installs its packages on the cluster's nodes).
func (c *Client) ensurePackageProxyEgress(ctx context.Context, namespace, id, runtimeEnvYaml string) error {
	if c.packageProxy == nil || !provision.RuntimeEnvInstallsPackages(runtimeEnvYaml) {
		return nil
	}
	deny, err := c.adminManagedDeny(ctx, namespace)
	if err != nil {
		return err
	}
	if deny {
		return nil
	}
	return c.applyNetworkPolicy(ctx, namespace, provision.PackageProxyEgressNetworkPolicy(id, c.packageProxy))
}

// apiServerEndpoint reads (and caches) the `kubernetes` EndpointSlice in
// `default`: the addresses and port the API server answers on, which is what
// an egress NetworkPolicy has to name (the Service VIP is DNAT'd away before
// policy is evaluated). Needs `get` on endpointslices/kubernetes in default.
func (c *Client) apiServerEndpoint(ctx context.Context) (provision.APIServerEndpoint, error) {
	c.apiServerMu.Lock()
	defer c.apiServerMu.Unlock()
	if c.apiServer != nil && time.Since(c.apiServerRead) < apiServerTTL {
		return *c.apiServer, nil
	}
	slice, err := c.clientset.DiscoveryV1().EndpointSlices("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		return provision.APIServerEndpoint{}, provision.ProvisionError{Kind: provision.ProvisionErrBackend,
			Message: fmt.Sprintf("autoscaling needs the API server endpoint (get endpointslices/kubernetes in default, discovery.k8s.io): %v", err)}
	}
	out := provision.APIServerEndpoint{}
	for _, ep := range slice.Endpoints {
		out.Addresses = append(out.Addresses, ep.Addresses...)
	}
	for _, p := range slice.Ports {
		if p.Port == nil {
			continue
		}
		if (p.Name != nil && *p.Name == "https") || out.Port == 0 {
			out.Port = *p.Port
		}
	}
	if len(out.Addresses) == 0 || out.Port == 0 {
		return provision.APIServerEndpoint{}, provision.ProvisionError{Kind: provision.ProvisionErrBackend,
			Message: "autoscaling needs the API server endpoint: endpointslices/kubernetes in default has no addresses"}
	}
	c.apiServer, c.apiServerRead = &out, time.Now()
	return out, nil
}

// EnsureNamespacePosture ensures the namespace-level security posture:
// default-deny + tenant-allow NetworkPolicies (skipped under an
// admin-managed default-deny) and Pod Security Standards labels (skipped
// if the namespace already enforces `restricted`, never downgraded).
// Idempotent server-side apply throughout. Ported from
// kuberay_client.rs:282-341.
func (c *Client) EnsureNamespacePosture(ctx context.Context) error {
	return c.ensurePostureIn(ctx, c.namespace)
}

// ensurePostureIn is EnsureNamespacePosture for one namespace: the default
// workload namespace, or a project's tenant namespace (#21). A tenant
// namespace must already exist — the platform creates it, like the
// ServiceAccounts a workload identity names — and gets the same posture;
// the control plane's own namespace is additionally labelled so the
// tenant-allow policy written there admits Bifrost's pods across the
// namespace boundary (provision.ControlPlaneNamespaceLabel).
func (c *Client) ensurePostureIn(ctx context.Context, namespace string) error {
	if namespace != c.namespace {
		if err := c.ensureControlPlaneNamespaceLabel(ctx); err != nil {
			return err
		}
	}
	deny, err := c.adminManagedDeny(ctx, namespace)
	if err != nil {
		return err
	}
	if !deny {
		for _, policy := range []*networkingv1.NetworkPolicy{provision.DefaultDenyNetworkPolicy(), provision.TenantAllowNetworkPolicy()} {
			if err := c.applyNetworkPolicy(ctx, namespace, policy); err != nil {
				return err
			}
		}
	}

	var ns corev1.Namespace
	if err := c.c.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: fmt.Sprintf("namespace %s not found", namespace)}
		}
		return wrapErr(err)
	}
	if ns.Labels["pod-security.kubernetes.io/enforce"] == "restricted" {
		// Already stricter than Bifrost's baseline — never downgrade.
		return nil
	}
	patch := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: provision.NamespacePSSLabels()},
	}
	// No ForceOwnership: if another manager owns the enforce label with a
	// conflicting (looser) value, the conflict error surfaces the
	// disagreement instead of silently stealing the field (matches the
	// Rust reference's `PatchParams::apply` without `.force()` here).
	return wrapErr(applySSA(ctx, c.c, patch, client.FieldOwner(provision.FieldManager)))
}

// ensureControlPlaneNamespaceLabel stamps provision.ControlPlaneNamespaceLabel
// on the control plane's own namespace (the client's default namespace,
// where the chart deploys Bifrost). The tenant-allow policy in a project
// namespace admits control-plane pods only from a namespace carrying this
// label, so without it a cross-namespace cluster's head would be
// unreachable from the gateway. Idempotent SSA on one label; done once
// per process (sync.Once semantics via the cache key "").
func (c *Client) ensureControlPlaneNamespaceLabel(ctx context.Context) error {
	if _, done := c.located.Load(controlPlaneLabelledKey); done {
		return nil
	}
	patch := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{Name: c.namespace, Labels: map[string]string{provision.ControlPlaneNamespaceLabel: "true"}},
	}
	if err := applySSA(ctx, c.c, patch, client.FieldOwner(provision.FieldManager)); err != nil {
		return wrapErr(err)
	}
	c.located.Store(controlPlaneLabelledKey, c.namespace)
	return nil
}

// controlPlaneLabelledKey is the located-cache sentinel recording that the
// control-plane namespace label has been ensured this process. No workload
// id can collide with it: ids are RFC 1123 names, never empty.
const controlPlaneLabelledKey = ""

// ---------------------------------------------------------------------------
// Provisioner: cluster lifecycle
// ---------------------------------------------------------------------------

func observedGeneration(obj client.Object) *uint64 {
	v, ok := obj.GetAnnotations()[provision.GenerationAnnotation]
	if !ok {
		return nil
	}
	g, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return nil
	}
	return &g
}

// Apply creates or updates the RayCluster for id (server-side apply,
// force-owned by [provision.FieldManager]). idempotencyKey identifies this
// logical apply for the caller's own audit trail (internal/controller,
// Task 9); the live client itself does not need it to be idempotent — SSA
// with an unchanged desired state already is. Ported from
// kuberay_client.rs:356-412.
func (c *Client) Apply(ctx context.Context, id core.ClusterId, spec *core.ClusterSpec, generation uint64, idempotencyKey string, queue *provision.QueueAssignment) (provision.ApplyResponse, error) {
	_ = idempotencyKey // audit-trail correlation lives with the caller (Task 9); not used by the client itself.
	// The per-cluster intra-tenant allow goes in first, so the cluster's
	// pods are never up under the default-deny without their own allow
	// (head<->worker traffic would stall the rollout).
	ns := c.nsFor(spec.NamespaceResolved)
	// A tenant namespace (#21) gets the namespace posture here: the
	// reconciler's EnsureNamespacePosture call covers the default
	// namespace only, and the cross-namespace allow depends on it.
	if ns != c.namespace {
		if err := c.ensurePostureIn(ctx, ns); err != nil {
			return provision.ApplyResponse{}, err
		}
	}
	if err := c.ensureClusterAllow(ctx, ns, string(id), spec.Owner); err != nil {
		return provision.ApplyResponse{}, err
	}
	if err := c.ensureStorageSourcesExist(ctx, ns, spec.StorageResolved); err != nil {
		return provision.ApplyResponse{}, err
	}
	if err := c.ensureServiceAccountExists(ctx, ns, spec.ServiceAccountResolved); err != nil {
		return provision.ApplyResponse{}, err
	}
	// The same rule RayClusterFor applies (provision.EffectiveAutoscaling):
	// whenever the sidecar will run, it must be able to reach the API
	// server, or it dies on a connect timeout and the cluster never scales.
	if provision.EffectiveAutoscaling(c.autoscaling, queue) {
		if err := c.ensureAutoscalerEgress(ctx, ns, string(id)); err != nil {
			return provision.ApplyResponse{}, err
		}
	}
	// Package installs under default-deny egress (issue #56): a cluster
	// whose pinned environment resolution installs packages gets the
	// package-proxy allowance; every other cluster gets none.
	clusterRuntimeEnv := ""
	if spec.EnvironmentResolved != nil {
		clusterRuntimeEnv = spec.EnvironmentResolved.RuntimeEnvYaml
	}
	if err := c.ensurePackageProxyEgress(ctx, ns, string(id), clusterRuntimeEnv); err != nil {
		return provision.ApplyResponse{}, err
	}
	manifest, err := provision.RayClusterForScheduled(id, spec, c.autoscaling, generation, queue, c.scheduling)
	if err != nil {
		return provision.ApplyResponse{}, provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: err.Error()}
	}
	manifest.Namespace = ns
	if err := applySSA(ctx, c.c, manifest, client.FieldOwner(provision.FieldManager), client.ForceOwnership); err != nil {
		return provision.ApplyResponse{}, wrapErr(err)
	}
	c.remember(string(id), ns)
	url := apiBaseURL(ns, string(id))
	return provision.ApplyResponse{Generation: generation, ApiBaseUrl: &url}, nil
}

// Terminate deletes the RayCluster for id and its per-cluster allow
// policy. Idempotent: already-gone is success. Ported from
// kuberay_client.rs:421-430.
func (c *Client) Terminate(ctx context.Context, id core.ClusterId) error {
	ns, err := c.locateOrDefault(ctx, string(id), &rayv1.RayClusterList{})
	if err != nil {
		return wrapErr(err)
	}
	rc := &rayv1.RayCluster{ObjectMeta: metav1.ObjectMeta{Name: string(id), Namespace: ns}}
	if err := c.c.Delete(ctx, rc); err != nil && !apierrors.IsNotFound(err) {
		return wrapErr(err)
	}
	c.forget(string(id))
	return c.deleteClusterAllow(ctx, ns, string(id))
}

// ReapNetworkPolicies deletes id's per-cluster allow policy — a backstop
// for a RayCluster CR that has already vanished (Terminate would then
// never fire). Ported from kuberay_client.rs:432-437.
func (c *Client) ReapNetworkPolicies(ctx context.Context, id core.ClusterId) error {
	if err := c.deleteClusterAllow(ctx, c.knownNamespace(string(id)), string(id)); err != nil {
		return err
	}
	if !c.tenantNamespaces {
		return nil
	}
	// The CR is gone, so nothing locates its namespace; after a restart the
	// cache is empty too. Find the per-cluster policies wherever they are.
	var list networkingv1.NetworkPolicyList
	if err := c.c.List(ctx, &list, client.InNamespace(""), client.MatchingLabels{provision.ManagedByLabel: provision.FieldManager}); err != nil {
		return wrapErr(err)
	}
	names := map[string]bool{provision.ClusterAllowPolicyName(string(id)): true, provision.AutoscalerPolicyName(string(id)): true, provision.PackageProxyPolicyName(string(id)): true}
	for i := range list.Items {
		if names[list.Items[i].Name] {
			if err := c.c.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return wrapErr(err)
			}
		}
	}
	return nil
}

// setSuspend flips only spec.suspend via a JSON merge patch — see
// [provision.SuspendPatch]'s doc comment for why this is not a partial SSA
// apply. Ported from kuberay_client.rs:138-148.
func (c *Client) setSuspend(ctx context.Context, id core.ClusterId, suspend bool) error {
	ns, err := c.locate(ctx, string(id), &rayv1.RayClusterList{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return provision.ProvisionError{Kind: provision.ProvisionErrNotFound, ClusterID: id}
		}
		return wrapErr(err)
	}
	rc := &rayv1.RayCluster{ObjectMeta: metav1.ObjectMeta{Name: string(id), Namespace: ns}}
	patch := client.RawPatch(types.MergePatchType, provision.SuspendPatch(suspend))
	if err := c.c.Patch(ctx, rc, patch); err != nil {
		if apierrors.IsNotFound(err) {
			return provision.ProvisionError{Kind: provision.ProvisionErrNotFound, ClusterID: id}
		}
		return wrapErr(err)
	}
	return nil
}

func (c *Client) Suspend(ctx context.Context, id core.ClusterId) error {
	return c.setSuspend(ctx, id, true)
}

func (c *Client) Resume(ctx context.Context, id core.ClusterId) error {
	return c.setSuspend(ctx, id, false)
}

// Observe reads a RayCluster's status, mapping it to a
// [provision.ObservedCluster]. Ported from kuberay_client.rs:447-469.
func (c *Client) Observe(ctx context.Context, id core.ClusterId) (provision.ObservedCluster, error) {
	var rc rayv1.RayCluster
	if err := c.getManaged(ctx, string(id), &rc, &rayv1.RayClusterList{}); err != nil {
		if apierrors.IsNotFound(err) {
			return provision.ObservedCluster{}, provision.ProvisionError{Kind: provision.ProvisionErrNotFound, ClusterID: id}
		}
		return provision.ObservedCluster{}, wrapErr(err)
	}
	var fpPtr *string
	if fp, ok := provision.FingerprintFromRayCluster(&rc.Spec); ok {
		fpPtr = &fp
	}
	url := apiBaseURL(rc.Namespace, string(id))
	return provision.ObservedCluster{
		ID:                 id,
		State:              provision.StatusToState(rc.Status),
		ObservedGeneration: observedGeneration(&rc),
		SpecFingerprint:    fpPtr,
		ApiBaseUrl:         &url,
	}, nil
}

// List returns every RayCluster this field manager owns in the namespace.
// Ported from kuberay_client.rs:471-492.
func (c *Client) List(ctx context.Context) ([]provision.ObservedCluster, error) {
	var list rayv1.RayClusterList
	if err := c.c.List(ctx, &list, c.listScope(), client.MatchingLabels{provision.ManagedByLabel: provision.FieldManager}); err != nil {
		return nil, wrapErr(err)
	}
	out := make([]provision.ObservedCluster, 0, len(list.Items))
	for i := range list.Items {
		rc := &list.Items[i]
		c.remember(rc.Name, rc.Namespace)
		var fpPtr *string
		if fp, ok := provision.FingerprintFromRayCluster(&rc.Spec); ok {
			fpPtr = &fp
		}
		url := apiBaseURL(rc.Namespace, rc.Name)
		out = append(out, provision.ObservedCluster{
			ID:                 core.ClusterId(rc.Name),
			State:              provision.StatusToState(rc.Status),
			ObservedGeneration: observedGeneration(rc),
			SpecFingerprint:    fpPtr,
			ApiBaseUrl:         &url,
		})
	}
	return out, nil
}

// MetricsEndpoint returns the Ray head's Prometheus metrics endpoint.
// Ported from kuberay_client.rs:494-499.
func (c *Client) MetricsEndpoint(id core.ClusterId) (string, bool) {
	return apiBaseURL(c.knownNamespace(string(id)), string(id)) + "/metrics", true
}

// DashboardApiBase returns the cluster's native Ray dashboard / Job
// Submission API base URL. Ported from kuberay_client.rs:501-506.
func (c *Client) DashboardApiBase(id core.ClusterId) (string, bool) {
	return apiBaseURL(c.knownNamespace(string(id)), string(id)), true
}

// ClusterNodes reads the RayCluster + the pods KubeRay owns for it
// (label [provision.RayClusterLabel]=id) and hands them to
// [provision.NodeBreakdown]. Kubernetes is the source, never the Ray
// dashboard, so this answers even when the dashboard is unreachable.
// Ported from kuberay_client.rs:508-536.
func (c *Client) ClusterNodes(ctx context.Context, id core.ClusterId) (*core.ClusterNodes, error) {
	var rc rayv1.RayCluster
	if err := c.getManaged(ctx, string(id), &rc, &rayv1.RayClusterList{}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, provision.ProvisionError{Kind: provision.ProvisionErrNotFound, ClusterID: id}
		}
		return nil, wrapErr(err)
	}
	var pods corev1.PodList
	if err := c.c.List(ctx, &pods, client.InNamespace(rc.Namespace), client.MatchingLabels{provision.RayClusterLabel: string(id)}); err != nil {
		return nil, wrapErr(err)
	}
	nodes := provision.NodeBreakdown(string(id), &rc, pods.Items)
	return &nodes, nil
}

// ClusterEvents lists core/v1 Events in the namespace and normalizes them
// via [provision.EventsFromK8s]. No fieldSelector (it can't express the
// `<id>-` name-prefix match); filtering happens in the pure helper. Ported
// from kuberay_client.rs:538-556.
func (c *Client) ClusterEvents(ctx context.Context, id core.ClusterId) (*core.ClusterEvents, error) {
	ns, err := c.locateOrDefault(ctx, string(id), &rayv1.RayClusterList{})
	if err != nil {
		return nil, wrapErr(err)
	}
	var list corev1.EventList
	if err := c.c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil, wrapErr(err)
	}
	events := provision.EventsFromK8s(string(id), list.Items)
	return &events, nil
}

// ClusterLogs tails logs for one of id's pods (head by default). pod, when
// set, must name one of the cluster's own pods — a pod outside the set
// returns (nil, nil) (404), never an arbitrary namespace pod. Ported from
// kuberay_client.rs:558-635.
func (c *Client) ClusterLogs(ctx context.Context, id core.ClusterId, pod *string, tail uint32) (*core.ClusterLogs, error) {
	ns, err := c.locateOrDefault(ctx, string(id), &rayv1.RayClusterList{})
	if err != nil {
		return nil, wrapErr(err)
	}
	var pods corev1.PodList
	if err := c.c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{provision.RayClusterLabel: string(id)}); err != nil {
		return nil, wrapErr(err)
	}
	ordered := provision.RankPods(pods.Items)
	if len(ordered) == 0 {
		// Cluster exists but has no pods yet (just applied / suspended):
		// an empty view, not 404, so the tab renders cleanly.
		return &core.ClusterLogs{ClusterId: string(id), Tail: tail}, nil
	}

	var target string
	if pod != nil {
		found := false
		for _, n := range ordered {
			if n == *pod {
				found = true
				break
			}
		}
		if !found {
			return nil, nil //nolint:nilnil // a pod outside the cluster's set is a 404, not an error — matches Observe/Get elsewhere in this package returning (nil, nil) for "not found, not a failure"
		}
		target = *pod
	} else {
		target = ordered[0]
	}

	tailInt64 := int64(tail)
	raw, err := c.clientset.CoreV1().Pods(ns).GetLogs(target, &corev1.PodLogOptions{TailLines: &tailInt64, Timestamps: true}).DoRaw(ctx)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, wrapErr(err)
		}
		// The pod vanished between list and fetch: empty tail, not an error.
		raw = nil
	}
	lines, truncated := provision.TailLines(string(raw), tail)
	return &core.ClusterLogs{ClusterId: string(id), Pods: ordered, Pod: target, Tail: tail, Lines: lines, Truncated: truncated}, nil
}

// ---------------------------------------------------------------------------
// ServiceProvisioner: Ray Serve services (RayService)
// ---------------------------------------------------------------------------

// Deploy server-side-applies the RayService for name. Ported from
// kuberay_client.rs:640-664.
func (s *ServiceClient) Deploy(ctx context.Context, name string, spec *core.ServiceSpec, generation uint64, queue *provision.QueueAssignment) error {
	// Same posture rule as clusters and jobs: KubeRay's serve-status polls
	// reach the head only through the tenant-allow policy, so a namespace
	// whose first workload is a RayService must get it here.
	ns := s.nsFor(spec.NamespaceResolved)
	if err := s.ensurePostureIn(ctx, ns); err != nil {
		return err
	}
	// Service pods carry the same cluster-id label (RayServiceFor's pod
	// templates stamp it), so they get the same per-cluster allow —
	// including across a RayService zero-downtime upgrade, where old and
	// new generated RayClusters coexist but share it. Services carry no
	// per-owner Ray-client pin: they are addressed through the Serve
	// gateway, not a user's ray.init.
	if err := s.ensureClusterAllow(ctx, ns, name, nil); err != nil {
		return err
	}
	if err := s.ensureStorageSourcesExist(ctx, ns, spec.StorageResolved); err != nil {
		return err
	}
	if err := s.ensureServiceAccountExists(ctx, ns, spec.ServiceAccountResolved); err != nil {
		return err
	}
	// queue is the project's serving LocalQueue (requirement 4), resolved
	// by the service reconciler from the serving pool's allocation.
	manifest, err := provision.RayServiceForScheduled(name, spec, generation, queue, s.scheduling)
	if err != nil {
		return provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: err.Error()}
	}
	manifest.Namespace = ns
	if err := applySSA(ctx, s.c, manifest, client.FieldOwner(provision.FieldManager), client.ForceOwnership); err != nil {
		return wrapErr(err)
	}
	s.remember(name, ns)
	return nil
}

// Get reads a RayService's status. Ported from kuberay_client.rs:666-684.
func (s *ServiceClient) Get(ctx context.Context, name string) (*provision.ObservedService, error) {
	var rs rayv1.RayService
	if err := s.getManaged(ctx, name, &rs, &rayv1.RayServiceList{}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil //nolint:nilnil // not-found is (nil, nil), matching kuberay_client.rs's Option-returning `get`
		}
		return nil, wrapErr(err)
	}
	return s.observedService(&rs), nil
}

// observedService reads the observation off a RayService: state from its
// conditions/status, the in-cluster Serve URL, the owning project from
// [provision.ProjectLabel] and the applied generation from
// [provision.GenerationAnnotation] (nil when either is absent).
func (s *ServiceClient) observedService(rs *rayv1.RayService) *provision.ObservedService {
	url := serviceURL(rs.Namespace, rs.Name)
	return &provision.ObservedService{
		Name:       rs.Name,
		State:      provision.ServiceStatusToState(rs.Status),
		Url:        &url,
		Project:    rs.Labels[provision.ProjectLabel],
		Generation: observedGeneration(rs),
	}
}

// Delete deletes the RayService and its per-cluster allow policy.
// Idempotent. Ported from kuberay_client.rs:686-696.
func (s *ServiceClient) Delete(ctx context.Context, name string) error {
	ns, err := s.locateOrDefault(ctx, name, &rayv1.RayServiceList{})
	if err != nil {
		return wrapErr(err)
	}
	rs := &rayv1.RayService{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	if err := s.c.Delete(ctx, rs); err != nil && !apierrors.IsNotFound(err) {
		return wrapErr(err)
	}
	s.forget(name)
	return s.deleteClusterAllow(ctx, ns, name)
}

// List returns every RayService this field manager owns in the namespace.
// Ported from kuberay_client.rs:698-723.
func (s *ServiceClient) List(ctx context.Context) ([]provision.ObservedService, error) {
	var list rayv1.RayServiceList
	if err := s.c.List(ctx, &list, s.listScope(), client.MatchingLabels{provision.ManagedByLabel: provision.FieldManager}); err != nil {
		return nil, wrapErr(err)
	}
	out := make([]provision.ObservedService, 0, len(list.Items))
	for i := range list.Items {
		s.remember(list.Items[i].Name, list.Items[i].Namespace)
		out = append(out, *s.observedService(&list.Items[i]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// PoolProvisioner: Kueue objects (Cohort / ResourceFlavors / ClusterQueue /
// LocalQueues)
// ---------------------------------------------------------------------------

// ApplyPool server-side-applies a pool's shared Cohort and flavors, its
// ClusterQueue, and every allocation's LocalQueue. Order: the shared
// Cohort + flavors first, then the ClusterQueue that references them, then
// the namespaced LocalQueues (which need their namespaces to exist)
// pointing at it — Kueue is eventually consistent, so this is for tidiness,
// not correctness. Unlike the cluster/service applies, this does NOT pass
// client.ForceOwnership: the Cohort may be shared with pools/objects
// Bifrost does not own, and a forced apply would steal those fields rather
// than surface the conflict. Ported from kueue_client.rs:192-249.
func (c *Client) ApplyPool(ctx context.Context, spec *core.PoolSpec, allocs []core.AllocationSpec) error {
	cohort := provision.CohortFor(spec)
	if err := applySSA(ctx, c.c, cohort, client.FieldOwner(provision.FieldManager)); err != nil {
		return wrapErr(err)
	}
	for i := range spec.Flavors {
		flavor := provision.ResourceFlavorFor(spec.Name, &spec.Flavors[i])
		if err := applySSA(ctx, c.c, flavor, client.FieldOwner(provision.FieldManager)); err != nil {
			return wrapErr(err)
		}
	}
	cq, err := provision.ClusterQueueFor(spec)
	if err != nil {
		return provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: err.Error()}
	}
	if err := applySSA(ctx, c.c, cq, client.FieldOwner(provision.FieldManager)); err != nil {
		return wrapErr(err)
	}
	for i := range allocs {
		lq := provision.LocalQueueFor(&allocs[i], spec.Purpose)
		if err := applySSA(ctx, c.c, lq, client.FieldOwner(provision.FieldManager)); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

// deleteAll deletes every object in objs, treating already-gone as
// success.
func deleteAll(ctx context.Context, c client.Client, objs []client.Object) error {
	for _, o := range objs {
		if err := c.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
			return wrapErr(err)
		}
	}
	return nil
}

// DeletePool deletes every Kueue object carrying [provision.PoolLabel]=name
// — every object Bifrost creates for a pool carries it (stamped by the
// pure translators), so teardown finds them by selector even though the
// pool spec is already gone from the store. LocalQueues are namespaced
// (listed across all namespaces); the rest are cluster-scoped. Idempotent.
// Ported from kueue_client.rs:251-281.
func (c *Client) DeletePool(ctx context.Context, name string) error {
	sel := client.MatchingLabels{provision.PoolLabel: name}

	var lqs kueuev1beta2.LocalQueueList
	if err := c.c.List(ctx, &lqs, sel); err != nil {
		return wrapErr(err)
	}
	lqObjs := make([]client.Object, len(lqs.Items))
	for i := range lqs.Items {
		lqObjs[i] = &lqs.Items[i]
	}
	if err := deleteAll(ctx, c.c, lqObjs); err != nil {
		return err
	}

	var cohorts kueuev1beta2.CohortList
	if err := c.c.List(ctx, &cohorts, sel); err != nil {
		return wrapErr(err)
	}
	cohortObjs := make([]client.Object, len(cohorts.Items))
	for i := range cohorts.Items {
		cohortObjs[i] = &cohorts.Items[i]
	}
	if err := deleteAll(ctx, c.c, cohortObjs); err != nil {
		return err
	}

	var flavors kueuev1beta2.ResourceFlavorList
	if err := c.c.List(ctx, &flavors, sel); err != nil {
		return wrapErr(err)
	}
	flavorObjs := make([]client.Object, len(flavors.Items))
	for i := range flavors.Items {
		flavorObjs[i] = &flavors.Items[i]
	}
	if err := deleteAll(ctx, c.c, flavorObjs); err != nil {
		return err
	}

	var cqs kueuev1beta2.ClusterQueueList
	if err := c.c.List(ctx, &cqs, sel); err != nil {
		return wrapErr(err)
	}
	cqObjs := make([]client.Object, len(cqs.Items))
	for i := range cqs.Items {
		cqObjs[i] = &cqs.Items[i]
	}
	return deleteAll(ctx, c.c, cqObjs)
}

// ObservePool reads a pool's quota ledger off its ClusterQueue status —
// the status IS the ledger — plus each of its LocalQueues' own
// status.flavorsUsage for per-project attribution (the ClusterQueue-level
// FlavorsUsage is pool-scoped, not per-project). Returns (nil, nil) when
// the ClusterQueue does not exist. Ported from kueue_client.rs:283-317.
func (c *Client) ObservePool(ctx context.Context, name string) (*provision.PoolObservation, error) {
	var cq kueuev1beta2.ClusterQueue
	if err := c.c.Get(ctx, client.ObjectKey{Name: name}, &cq); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil //nolint:nilnil // not-found is (nil, nil), matching kueue_client.rs's Option-returning `observe_pool`
		}
		return nil, wrapErr(err)
	}

	var lqs kueuev1beta2.LocalQueueList
	if err := c.c.List(ctx, &lqs, client.MatchingLabels{provision.PoolLabel: name}); err != nil {
		return nil, wrapErr(err)
	}
	queuesUsage := map[string]map[string]string{}
	for i := range lqs.Items {
		lq := &lqs.Items[i]
		if byResource := provision.SumLocalQueueUsage(lq.Status.FlavorsUsage); len(byResource) > 0 {
			queuesUsage[lq.Name] = byResource
		}
	}

	return &provision.PoolObservation{
		AdmittedWorkloads:  provision.NonNegativeUint32(cq.Status.AdmittedWorkloads),
		ReservingWorkloads: provision.NonNegativeUint32(cq.Status.ReservingWorkloads),
		PendingWorkloads:   provision.NonNegativeUint32(cq.Status.PendingWorkloads),
		FlavorsUsage:       provision.FlavorUsageMap(cq.Status.FlavorsUsage),
		QueuesUsage:        queuesUsage,
	}, nil
}

// KueuePresent reports whether the API server serves the Kueue CRDs
// (probed via the ClusterQueue GVK's REST mapping). Ported from
// kueue_client.rs:319-335; unlike the Rust reference this is not
// result-cached per client — the REST mapper controller-runtime's
// uncached client.New() builds already caches API-group discovery
// internally, so a repeated call is cheap once the mapping is resolved.
func (c *Client) KueuePresent(ctx context.Context) bool {
	_, err := c.c.RESTMapper().RESTMapping(schema.GroupKind{Group: "kueue.x-k8s.io", Kind: "ClusterQueue"}, "v1beta2")
	return err == nil
}
