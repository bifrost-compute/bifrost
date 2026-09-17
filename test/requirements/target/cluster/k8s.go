package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/bifrost-compute/bifrost/test/requirements/req"
)

// clusterIDLabel is the label the control plane stamps on every object it
// owns (spec §1.4); postflight sweeps by it.
const clusterIDLabel = "bifrost.dev/cluster-id"

type k8sHandle struct {
	raw       ctrlclient.Client
	guarded   ctrlclient.Client
	clientset kubernetes.Interface
	ns        string
}

// newK8s resolves the kubeconfig the way the control plane does
// (controller-runtime's GetConfig), checks the current context against the
// target's allowlist, and builds the raw + guarded clients. Returns
// (nil, nil) when no kubeconfig resolves at all: the lane then runs API-only
// and every k8s-needing test skips with a recorded reason.
func newK8s(ns string, contexts []string) (*k8sHandle, error) {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return nil, nil //nolint:nilnil // documented: no kubeconfig = no K8s()
	}
	if err := checkContext(contexts); err != nil {
		return nil, err
	}
	sch := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(sch); err != nil {
		return nil, err
	}
	if err := rayv1.AddToScheme(sch); err != nil {
		return nil, err
	}
	raw, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: sch})
	if err != nil {
		return nil, fmt.Errorf("controller-runtime client: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("clientset: %w", err)
	}
	return &k8sHandle{
		raw:       raw,
		guarded:   &guarded{Client: raw, run: req.RunID()},
		clientset: cs,
		ns:        ns,
	}, nil
}

// checkContext refuses a kubeconfig whose current context is not on the
// target's allowlist (spec §6): REQ_TARGET=kind against a production
// kubeconfig must not run.
func checkContext(allow []string) error {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rawCfg, err := rules.Load()
	if err != nil {
		// In-cluster or otherwise context-less configs have nothing to check.
		if _, icErr := rest.InClusterConfig(); icErr == nil {
			return nil
		}
		return fmt.Errorf("loading kubeconfig: %w", err)
	}
	cur := rawCfg.CurrentContext
	if cur == "" {
		if _, icErr := rest.InClusterConfig(); icErr == nil {
			return nil
		}
		return errors.New("kubeconfig has no current context")
	}
	for _, pat := range allow {
		if regexp.MustCompile(pat).MatchString(cur) {
			return nil
		}
	}
	return fmt.Errorf("kubeconfig context %q is not on this target's allowlist %v (targets.yaml)", cur, allow)
}

// guarded wraps a controller-runtime client so that a test can mutate only
// objects that belong to its run: a bifrost.dev/cluster-id carrying the run
// prefix, or the req.RunLabel the runner stamps on probe objects. Reads are
// unrestricted. This is the "Never" clause of spec §6 made mechanical.
type guarded struct {
	ctrlclient.Client
	run string
}

func (g *guarded) owned(obj ctrlclient.Object) error {
	l := obj.GetLabels()
	if strings.HasPrefix(l[clusterIDLabel], g.run+"-") || l[req.RunLabel] == g.run {
		return nil
	}
	return fmt.Errorf("refusing to mutate %s/%s: it does not belong to run %s (labels %v)",
		obj.GetNamespace(), obj.GetName(), g.run, l)
}

func (g *guarded) Create(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
	if err := g.owned(obj); err != nil {
		return err
	}
	return g.Client.Create(ctx, obj, opts...)
}

func (g *guarded) Delete(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.DeleteOption) error {
	if err := g.owned(obj); err != nil {
		return err
	}
	return g.Client.Delete(ctx, obj, opts...)
}

func (g *guarded) Update(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.UpdateOption) error {
	if err := g.owned(obj); err != nil {
		return err
	}
	return g.Client.Update(ctx, obj, opts...)
}

func (g *guarded) Patch(ctx context.Context, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.PatchOption) error {
	if err := g.owned(obj); err != nil {
		return err
	}
	return g.Client.Patch(ctx, obj, patch, opts...)
}

func (g *guarded) DeleteAllOf(context.Context, ctrlclient.Object, ...ctrlclient.DeleteAllOfOption) error {
	return errors.New("DeleteAllOf is never allowed from a requirement test")
}

// postflight reaps the run's probe objects and waits until no RayCluster,
// pod, NetworkPolicy or Secret still carries the run's labels. Leftovers
// are the error — the run leaked, and a human looks before the next run.
func (h *k8sHandle) postflight(ctx context.Context, prefix, probeNS string) error {
	runSel := ctrlclient.MatchingLabels{req.RunLabel: req.RunID()}
	for _, ns := range uniq(h.ns, probeNS) {
		var pods corev1.PodList
		if err := h.raw.List(ctx, &pods, ctrlclient.InNamespace(ns), runSel); err == nil {
			for i := range pods.Items {
				_ = h.raw.Delete(ctx, &pods.Items[i], ctrlclient.GracePeriodSeconds(0))
			}
		}
		var nps networkingv1.NetworkPolicyList
		if err := h.raw.List(ctx, &nps, ctrlclient.InNamespace(ns), runSel); err == nil {
			for i := range nps.Items {
				_ = h.raw.Delete(ctx, &nps.Items[i])
			}
		}
		// Requirement 12 tests create run-labelled Secrets for the storage
		// catalog to reference; reap them like probe objects. Listing
		// Secrets is a metadata-only concern here — nothing reads .data.
		var secrets corev1.SecretList
		if err := h.raw.List(ctx, &secrets, ctrlclient.InNamespace(ns), runSel); err == nil {
			for i := range secrets.Items {
				_ = h.raw.Delete(ctx, &secrets.Items[i])
			}
		}
		// Requirement 20 tests create run-labelled ServiceAccounts for the
		// workload-identity rules to name; reap them the same way.
		var sas corev1.ServiceAccountList
		if err := h.raw.List(ctx, &sas, ctrlclient.InNamespace(ns), runSel); err == nil {
			for i := range sas.Items {
				_ = h.raw.Delete(ctx, &sas.Items[i])
			}
		}
	}

	// The sweep gets its own deadline so a slow teardown reports what is
	// still there instead of inheriting a parent context that has already
	// expired ("left objects behind: [] (context deadline exceeded)" was the
	// symptom: the list was empty only because the last poll never ran).
	sweepCtx, cancel := context.WithTimeout(context.Background(), postflightBudget())
	defer cancel()
	var left []string
	err := wait.PollUntilContextTimeout(sweepCtx, 3*time.Second, postflightBudget(), true, func(ctx context.Context) (bool, error) {
		// Build this poll into cur and publish it only when the poll completes,
		// so a deadline mid-poll still reports the previous snapshot instead of [].
		var cur []string
		var rcs rayv1.RayClusterList
		if err := h.raw.List(ctx, &rcs, ctrlclient.InNamespace(h.ns)); err != nil {
			return false, err
		}
		for _, rc := range rcs.Items {
			if strings.HasPrefix(rc.Labels[clusterIDLabel], prefix) || strings.HasPrefix(rc.Name, prefix) {
				cur = append(cur, "raycluster/"+rc.Name)
			}
		}
		// RayJobs (#5) and RayServices (#1/#2) are owned kinds too: a test
		// that leaks one would otherwise leak silently, since their child
		// RayClusters are named by KubeRay, not by the run prefix.
		var rjs rayv1.RayJobList
		if err := h.raw.List(ctx, &rjs, ctrlclient.InNamespace(h.ns)); err != nil {
			return false, err
		}
		for _, rj := range rjs.Items {
			if strings.HasPrefix(rj.Labels[clusterIDLabel], prefix) || strings.HasPrefix(rj.Name, prefix) {
				cur = append(cur, "rayjob/"+rj.Name)
			}
		}
		var rss rayv1.RayServiceList
		if err := h.raw.List(ctx, &rss, ctrlclient.InNamespace(h.ns)); err != nil {
			return false, err
		}
		for _, rs := range rss.Items {
			if strings.HasPrefix(rs.Labels[clusterIDLabel], prefix) || strings.HasPrefix(rs.Name, prefix) {
				cur = append(cur, "rayservice/"+rs.Name)
			}
		}
		var pods corev1.PodList
		if err := h.raw.List(ctx, &pods, ctrlclient.InNamespace(h.ns)); err != nil {
			return false, err
		}
		for _, p := range pods.Items {
			if strings.HasPrefix(p.Labels[clusterIDLabel], prefix) || strings.HasPrefix(p.Labels["ray.io/cluster"], prefix) {
				cur = append(cur, "pod/"+p.Name)
			}
		}
		var nps networkingv1.NetworkPolicyList
		if err := h.raw.List(ctx, &nps, ctrlclient.InNamespace(h.ns)); err != nil {
			return false, err
		}
		for _, np := range nps.Items {
			if strings.HasPrefix(np.Labels[clusterIDLabel], prefix) || strings.HasPrefix(strings.TrimPrefix(np.Name, "bifrost-cluster-"), prefix) {
				cur = append(cur, "networkpolicy/"+np.Name)
			}
		}
		for _, ns := range uniq(h.ns, probeNS) {
			var probes corev1.PodList
			if err := h.raw.List(ctx, &probes, ctrlclient.InNamespace(ns), runSel); err != nil {
				return false, err
			}
			for _, p := range probes.Items {
				cur = append(cur, "probe-pod/"+ns+"/"+p.Name)
			}
			var secrets corev1.SecretList
			if err := h.raw.List(ctx, &secrets, ctrlclient.InNamespace(ns), runSel); err != nil {
				return false, err
			}
			for _, s := range secrets.Items {
				cur = append(cur, "secret/"+ns+"/"+s.Name)
			}
		}
		left = cur
		return len(left) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("run %s left objects behind: %v (%v)", req.RunID(), left, err)
	}
	return nil
}

// postflightBudget is how long the sweep waits for Kubernetes to show the
// run's objects gone: REQ_POSTFLIGHT_TIMEOUT (Go duration), default 4m — a
// RayService teardown on a small runner can take most of that.
func postflightBudget() time.Duration {
	if v := os.Getenv("REQ_POSTFLIGHT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 4 * time.Minute
}

func uniq(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

// restart deletes the control-plane pods matched by selector and waits
// until a pod that did not exist before is Ready.
func (h *k8sHandle) restart(ctx context.Context, selector string) error {
	sel, err := labels.Parse(selector)
	if err != nil {
		return fmt.Errorf("control-plane selector %q: %w", selector, err)
	}
	var before corev1.PodList
	if err := h.raw.List(ctx, &before, ctrlclient.InNamespace(h.ns), ctrlclient.MatchingLabelsSelector{Selector: sel}); err != nil {
		return err
	}
	if len(before.Items) == 0 {
		return fmt.Errorf("no control-plane pods match %q in %s", selector, h.ns)
	}
	old := map[string]bool{}
	for i := range before.Items {
		old[before.Items[i].Name] = true
		if err := h.raw.Delete(ctx, &before.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %s: %w", before.Items[i].Name, err)
		}
	}
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		var now corev1.PodList
		if err := h.raw.List(ctx, &now, ctrlclient.InNamespace(h.ns), ctrlclient.MatchingLabelsSelector{Selector: sel}); err != nil {
			return false, nil //nolint:nilerr // transient API errors during restart are expected
		}
		for _, p := range now.Items {
			if old[p.Name] {
				continue
			}
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// destroyStore scales the control-plane deployment to zero, deletes its
// data PVC and re-creates it empty, then scales back and waits for a fresh
// Ready pod. This is the store-loss drill's only workable shape on this
// deployment: the image ships no shell (UBI9-micro) and the root fs is
// read-only, so the SQLite file cannot be removed from inside the pod —
// the volume has to go away. The PVC name and replica count are read from
// the live deployment, not assumed.
func (h *k8sHandle) destroyStore(ctx context.Context, selector string) error {
	sel, err := labels.Parse(selector)
	if err != nil {
		return fmt.Errorf("control-plane selector %q: %w", selector, err)
	}
	listOpts := []ctrlclient.ListOption{ctrlclient.InNamespace(h.ns), ctrlclient.MatchingLabelsSelector{Selector: sel}}

	var deploys appsv1.DeploymentList
	if err := h.raw.List(ctx, &deploys, listOpts...); err != nil {
		return err
	}
	if len(deploys.Items) != 1 {
		return fmt.Errorf("%d control-plane deployments match %q in %s, want exactly 1", len(deploys.Items), selector, h.ns)
	}
	dep := &deploys.Items[0]
	replicas := int32(1)
	if dep.Spec.Replicas != nil {
		replicas = *dep.Spec.Replicas
	}
	pvcName := ""
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			pvcName = v.PersistentVolumeClaim.ClaimName
			break
		}
	}
	if pvcName == "" {
		return fmt.Errorf("control-plane deployment %s mounts no PVC; its store is not durable on this target", dep.Name)
	}

	zero := int32(0)
	dep.Spec.Replicas = &zero
	if err := h.raw.Update(ctx, dep); err != nil {
		return fmt.Errorf("scale %s to 0: %w", dep.Name, err)
	}
	// From here the deployment must come back no matter how the wipe goes.
	restore := func() error {
		var cur appsv1.Deployment
		if err := h.raw.Get(ctx, ctrlclient.ObjectKey{Namespace: h.ns, Name: dep.Name}, &cur); err != nil {
			return err
		}
		cur.Spec.Replicas = &replicas
		return h.raw.Update(ctx, &cur)
	}
	failed := true
	defer func() {
		if failed {
			_ = restore()
		}
	}()

	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		var pods corev1.PodList
		if err := h.raw.List(ctx, &pods, listOpts...); err != nil {
			return false, nil //nolint:nilerr // transient API errors during teardown are expected
		}
		return len(pods.Items) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("control-plane pods still present after scale-to-0: %w", err)
	}

	var pvc corev1.PersistentVolumeClaim
	if err := h.raw.Get(ctx, ctrlclient.ObjectKey{Namespace: h.ns, Name: pvcName}, &pvc); err != nil {
		return fmt.Errorf("get PVC %s: %w", pvcName, err)
	}
	spec := *pvc.Spec.DeepCopy()
	spec.VolumeName = "" // unbind: the replacement must dynamically provision
	if err := h.raw.Delete(ctx, &pvc); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete PVC %s: %w", pvcName, err)
	}
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		err := h.raw.Get(ctx, ctrlclient.ObjectKey{Namespace: h.ns, Name: pvcName}, &corev1.PersistentVolumeClaim{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil //nolint:nilerr // deletion (pvc-protection finalizer) still pending
	})
	if err != nil {
		return fmt.Errorf("PVC %s still present after delete: %w", pvcName, err)
	}
	fresh := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName, Namespace: h.ns, Labels: pvc.Labels},
		Spec:       spec,
	}
	if err := h.raw.Create(ctx, fresh); err != nil {
		return fmt.Errorf("re-create PVC %s: %w", pvcName, err)
	}

	if err := restore(); err != nil {
		return fmt.Errorf("scale %s back to %d: %w", dep.Name, replicas, err)
	}
	failed = false
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		var pods corev1.PodList
		if err := h.raw.List(ctx, &pods, listOpts...); err != nil {
			return false, nil //nolint:nilerr // transient API errors during scale-up are expected
		}
		for _, p := range pods.Items {
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// runPod creates the probe pod, waits (to Running when Detach, else to a
// terminal phase), collects logs, and — for run-to-completion pods —
// deletes it. Detached pods are reaped by postflight.
func (h *k8sHandle) runPod(ctx context.Context, spec req.PodSpec) (req.PodResult, error) {
	name := req.Name("probe-" + fmt.Sprintf("%x", time.Now().UnixNano()%0xfffff))
	lbl := map[string]string{req.RunLabel: req.RunID(), "app.kubernetes.io/name": "bifrost-req-probe"}
	for k, v := range spec.Labels {
		lbl[k] = v
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: spec.Namespace, Labels: lbl},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "probe",
				Image:   spec.Image,
				Command: spec.Command,
			}},
		},
	}
	if err := h.raw.Create(ctx, pod); err != nil {
		return req.PodResult{}, fmt.Errorf("create probe pod: %w", err)
	}
	res := req.PodResult{Name: name}
	var phase corev1.PodPhase
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, spec.Timeout, true, func(ctx context.Context) (bool, error) {
		var cur corev1.Pod
		if err := h.raw.Get(ctx, ctrlclient.ObjectKey{Namespace: spec.Namespace, Name: name}, &cur); err != nil {
			return false, nil //nolint:nilerr // keep polling through transient errors
		}
		phase = cur.Status.Phase
		res.IP = cur.Status.PodIP
		if spec.Detach {
			return phase == corev1.PodRunning && res.IP != "", nil
		}
		return phase == corev1.PodSucceeded || phase == corev1.PodFailed, nil
	})
	if !spec.Detach || err != nil {
		res.Logs = h.logs(ctx, spec.Namespace, name)
	}
	if err != nil {
		return res, fmt.Errorf("probe pod %s: phase=%s: %w\n%s", name, phase, err, res.Logs)
	}
	res.Succeeded = spec.Detach || phase == corev1.PodSucceeded
	if !spec.Detach {
		_ = h.raw.Delete(ctx, pod, ctrlclient.GracePeriodSeconds(0))
	}
	return res, nil
}

func (h *k8sHandle) logs(ctx context.Context, ns, name string) string {
	rc, err := h.clientset.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return "(logs unavailable: " + err.Error() + ")"
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
	return string(b)
}
