package provision

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// KubeRay backend: translate a Bifrost [core.ClusterSpec] into a typed
// RayCluster custom resource, and map RayCluster status back to a
// [core.ClusterState]. Ported from the predecessor's provision crate, src/kuberay.rs.
//
// This file is pure (no Kubernetes client) so the ADR-0007-equivalent
// field-ownership rule is exhaustively testable: when Ray's in-tree
// autoscaler is enabled, Bifrost owns MinReplicas/MaxReplicas only and must
// NEVER write Replicas or ScaleStrategy — the autoscaler sidecar owns
// those, and writing them causes the stuck-instance conflicts documented
// upstream. The live client wiring (server-side apply, observe, delete) is
// added on top of these functions in internal/provision/live (Task 6).

// QueueAssignment is the Kueue queue a RayCluster is admitted through
// (ADR-0010-equivalent): the allocation's LocalQueue name, plus whether the
// pool allows elastic resizing. Derived at apply time from the
// project->allocation lookup (not user input), so it is a parameter of
// [RayClusterFor], never part of ClusterSpec's serialized form
// (kuberay.rs:20-33).
type QueueAssignment struct {
	// QueueName is the LocalQueue name (= the allocation's project name).
	QueueName string
	// Elastic pools stamp [ElasticJobAnnotation] and force the in-tree
	// autoscaler on — elastic mode (KEP-77 Workload Slices) requires it.
	Elastic bool
}

const (
	APIVersion  = "ray.io/v1"
	Kind        = "RayCluster"
	ServiceKind = "RayService"

	// FieldManager is the server-side-apply field manager identifying
	// Bifrost's owned fields, so drift is attributable and `replicas` can
	// be left unmanaged (ADR-0007-equivalent). Actual client.FieldOwner
	// wiring is Task 6; this is the manifest-visible label value.
	FieldManager = "bifrost"

	ManagedByLabel = "app.kubernetes.io/managed-by"
	ClusterIDLabel = "bifrost.dev/cluster-id"
	// OwnerLabel is stamped on the RayCluster and its head/worker pods
	// recording the cluster's authenticated owner (tier-2 owned session
	// clusters). Value is core.ClusterSpec.Owner rewritten by
	// ownerLabelValue (F9 — IdP usernames are not always valid RFC 1123
	// label values); the raw owner rides in OwnerRawAnnotation.
	// Frozen-contract label key (see bifrost-api openapi.json
	// ClusterSpec.owner description).
	OwnerLabel = "bifrost.dev/owner"
	// ProjectLabel is stamped on a RayService so the live client can read
	// the owning project back (requirement 2: project-scoped services)
	// without a store lookup — the resource itself says whose it is.
	ProjectLabel = "bifrost.dev/project"
	// NotebookNamespace is the namespace the interactive notebooks
	// (JupyterHub singleuser pods) run in — the only namespace the
	// per-owner Ray-client ingress rule admits from.
	NotebookNamespace = "jupyter"
	// GenerationAnnotation carries the Bifrost spec generation this
	// resource reflects (ADR-0006-equivalent). Stamped on the RayCluster
	// metadata (so Observe can read back the generation the cluster
	// actually carries) *and* on the pod templates (so a generation bump
	// changes the pod-template hash and KubeRay rolls the pods).
	GenerationAnnotation = "bifrost.dev/generation"

	// QueueLabel nominates the Kueue LocalQueue a workload is admitted
	// through.
	QueueLabel = "kueue.x-k8s.io/queue-name"
	// ElasticJobAnnotation marks a RayCluster/RayJob as elastic (Workload
	// Slices, KEP-77).
	ElasticJobAnnotation = "kueue.x-k8s.io/elastic-job"
)

// EffectiveAutoscaling is the one rule for whether a cluster runs the
// in-tree autoscaler, given the operator's --ray-autoscaling flag and the
// cluster's Kueue queue assignment (nil when its project is in no pool).
//
// A cluster in no pool follows the operator flag. A Kueue-managed cluster
// does not: Kueue admits a workload by counting its pods, so its
// RayCluster webhook rejects `enableInTreeAutoscaling: true` unless the
// workload is elastic (the kueue.x-k8s.io/elastic-job annotation, which in
// turn needs the ElasticJobsViaWorkloadSlices gate). So an elastic pool is
// always autoscaled — elastic mode requires the sidecar — and a
// non-elastic pool is never autoscaled, whatever the flag says: the pool
// owner asked for fixed-size admission and Bifrost writes replicas.
// (docs/defects/2026-09-09-autoscaling-denied-in-kueue-pools.md: with the
// flag on, every clustered pool cluster on grace was denied at admission.)
// ADR-0007 holds either way: with autoscaling on we never write replicas.
func EffectiveAutoscaling(flag bool, queue *QueueAssignment) bool {
	if queue == nil {
		return flag
	}
	return queue.Elastic
}

// RayClusterFor builds the RayCluster manifest for spec at generation.
// autoscaling selects the field-ownership regime (ADR-0007-equivalent).
// queue nominates the Kueue LocalQueue (ADR-0010-equivalent): nil (the
// default) produces a manifest equivalent to the queue-free form; non-nil
// stamps the [QueueLabel] label, and an elastic assignment also stamps the
// [ElasticJobAnnotation] annotation and forces the in-tree autoscaler on
// regardless of autoscaling (KEP-77 requires it). Ported from
// kuberay.rs:69-140.
//
// Resource quantities (cpu/memory/gpu strings on spec) are parsed into
// typed [resource.Quantity] fields — the one place this port's typed-API
// requirement diverges from the Rust reference's untyped
// serde_json::Value, which passed the strings through unchecked and let
// the API server reject malformed ones. A parse failure here is returned
// as an error instead.
func RayClusterFor(id core.ClusterId, spec *core.ClusterSpec, autoscaling bool, generation uint64, queue *QueueAssignment) (*rayv1.RayCluster, error) {
	return RayClusterForScheduled(id, spec, autoscaling, generation, queue, Scheduling{})
}

// RayClusterForScheduled is [RayClusterFor] with the control plane's
// [Scheduling] (node selector, tolerations) stamped onto every pod
// template, head and worker groups alike. The live client calls this; the
// zero Scheduling renders byte-identically to RayClusterFor.
func RayClusterForScheduled(id core.ClusterId, spec *core.ClusterSpec, autoscaling bool, generation uint64, queue *QueueAssignment, sched Scheduling) (*rayv1.RayCluster, error) {
	autoscaling = EffectiveAutoscaling(autoscaling, queue)

	workerSpecs := make([]rayv1.WorkerGroupSpec, 0, len(spec.WorkerGroups))
	for i := range spec.WorkerGroups {
		g := spec.WorkerGroups[i]
		ws, err := workerGroupSpec(string(id), &g, spec.Image, autoscaling, &generation, spec.Owner, spec.StorageResolved, derefString(spec.ServiceAccountResolved), sched)
		if err != nil {
			return nil, fmt.Errorf("provision: worker group %q: %w", g.Name, err)
		}
		workerSpecs = append(workerSpecs, ws)
	}

	labels := map[string]string{
		ManagedByLabel: FieldManager,
		ClusterIDLabel: string(id),
	}
	// Stamp the owner (tier-2 owned session clusters) for attribution and
	// so the per-owner ingress policy has a label to key on. Only when
	// set — ownerless clusters (admin/service paths) carry no owner
	// label. The label value goes through ownerLabelValue (F9): IdP
	// usernames are not RFC 1123 labels, and the NetworkPolicy selector
	// rewrites with the same helper so the two keep matching. The raw
	// owner is kept in OwnerRawAnnotation for observability.
	if spec.Owner != nil {
		labels[OwnerLabel] = ownerLabelValue(*spec.Owner)
	}
	annotations := map[string]string{
		GenerationAnnotation: strconv.FormatUint(generation, 10),
	}
	if spec.Owner != nil {
		annotations[OwnerRawAnnotation] = *spec.Owner
	}
	if queue != nil {
		labels[QueueLabel] = queue.QueueName
		if queue.Elastic {
			annotations[ElasticJobAnnotation] = "true"
		}
	}

	head, err := headGroupSpec(string(id), spec, &generation, sched)
	if err != nil {
		return nil, fmt.Errorf("provision: head group: %w", err)
	}

	return &rayv1.RayCluster{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        string(id),
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: rayv1.RayClusterSpec{
			RayVersion:              spec.RayVersion,
			EnableInTreeAutoscaling: ptr.To(autoscaling),
			AutoscalerOptions:       autoscalerOptions(autoscaling),
			// Bifrost owns `suspend` (SSA field manager) so a force
			// re-apply clears an out-of-band `suspend: true` and resumes
			// the cluster. Without this, our field manager never owns
			// the field and a Suspended cluster could never be repaired
			// by re-applying. Kueue also drives `suspend` for admission
			// (gang scheduling), but Bifrost's desired false never
			// fights it — an admitted cluster converges to running
			// pods.
			Suspend:          ptr.To(false),
			HeadGroupSpec:    head,
			WorkerGroupSpecs: workerSpecs,
		},
	}, nil
}

// owned_spec_fingerprint's worker-group projection.
type fingerprintWorker struct {
	Name   string  `json:"name"`
	Cpu    string  `json:"cpu"`
	Memory string  `json:"memory"`
	Gpu    *string `json:"gpu"`
	Min    uint32  `json:"min"`
	Max    uint32  `json:"max"`
}

// fingerprintStorage is the storage projection's drift-relevant shape
// (requirement 12): which source reaches the pods, how, and where. A
// stripped envFrom or mount is drift, exactly like a changed image. The
// catalog name is not on the manifest for env entries, so it is not part
// of the projection. Exactly one of Secret/Claim is set: the source kind
// is recoverable from which field is non-empty.
type fingerprintStorage struct {
	Secret    string  `json:"secret,omitempty"`
	Claim     string  `json:"claim,omitempty"`
	Mode      string  `json:"mode"`
	MountPath *string `json:"mount_path"`
}

// owned_spec_fingerprint / fingerprint_from_cr's shared projection shape.
type fingerprintSpec struct {
	RayVersion string              `json:"ray_version"`
	Image      string              `json:"image"`
	HeadCpu    string              `json:"head_cpu"`
	HeadMemory string              `json:"head_memory"`
	Workers    []fingerprintWorker `json:"workers"`
	// Storage is omitted when empty so specs without storage fingerprint
	// exactly as they did before requirement 12.
	Storage []fingerprintStorage `json:"storage,omitempty"`
	// ServiceAccount is the workload identity (#20), read back off the
	// head template's serviceAccountName; omitted when empty for the same
	// reason as Storage. A stripped or swapped ServiceAccount is drift —
	// it would change which cloud IAM role the pods hold.
	ServiceAccount string `json:"service_account,omitempty"`
}

// derefString is the "" for nil of an optional string.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sortStorageProjection orders a projection deterministically (secret,
// claim, mode, mount path): the desired side comes from the spec's list
// order, the live side from envFrom-then-volumes traversal, and the two
// must agree byte for byte.
func sortStorageProjection(in []fingerprintStorage) []fingerprintStorage {
	sort.Slice(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Secret != b.Secret {
			return a.Secret < b.Secret
		}
		if a.Claim != b.Claim {
			return a.Claim < b.Claim
		}
		if a.Mode != b.Mode {
			return a.Mode < b.Mode
		}
		return ptr.Deref(a.MountPath, "") < ptr.Deref(b.MountPath, "")
	})
	return in
}

// storageProjection is the fingerprint's view of a spec's resolved storage.
func storageProjection(storage []core.ResolvedStorage) []fingerprintStorage {
	out := make([]fingerprintStorage, 0, len(storage))
	for _, st := range storage {
		f := fingerprintStorage{Mode: st.Mode.String()}
		switch st.Source.OrDefault() {
		case core.StorageSourcePersistentVolumeClaim:
			f.Claim = st.ClaimName
		default:
			f.Secret = st.SecretName
		}
		if st.Mode == core.StorageModeFile {
			if st.MountPath == nil {
				continue // not projected by podTemplate either
			}
			mp := *st.MountPath
			f.MountPath = &mp
		}
		out = append(out, f)
	}
	return sortStorageProjection(out)
}

// storageFromTemplate reads the storage projection back off a live pod
// template: every envFrom.secretRef on the first container, and every
// Secret or PersistentVolumeClaim volume that container mounts (with its
// mount path).
func storageFromTemplate(tmpl *corev1.PodTemplateSpec) []fingerprintStorage {
	c, ok := firstContainer(tmpl)
	if !ok {
		return nil
	}
	out := make([]fingerprintStorage, 0, len(c.EnvFrom)+len(tmpl.Spec.Volumes))
	for _, e := range c.EnvFrom {
		if e.SecretRef != nil {
			out = append(out, fingerprintStorage{Secret: e.SecretRef.Name, Mode: core.StorageModeEnv.String()})
		}
	}
	mounts := make(map[string]string, len(c.VolumeMounts))
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m.MountPath
	}
	for _, v := range tmpl.Spec.Volumes {
		mp, mounted := mounts[v.Name]
		if !mounted {
			continue
		}
		switch {
		case v.Secret != nil:
			out = append(out, fingerprintStorage{Secret: v.Secret.SecretName, Mode: core.StorageModeFile.String(), MountPath: ptr.To(mp)})
		case v.PersistentVolumeClaim != nil:
			out = append(out, fingerprintStorage{Claim: v.PersistentVolumeClaim.ClaimName, Mode: core.StorageModeFile.String(), MountPath: ptr.To(mp)})
		}
	}
	return sortStorageProjection(out)
}

// OwnedSpecFingerprint is the fingerprint of the Bifrost-owned,
// drift-relevant fields (ADR-0004-equivalent drift detection). Deliberately
// EXCLUDES Replicas: that is the autoscaler's when in-tree autoscaling is
// on (ADR-0007), and even off it converges on its own, so a replica count
// is never treated as drift. Name/Project/TTL are control-plane metadata,
// not on the CR. Both [RayClusterFor] (implicitly) and
// [FingerprintFromRayCluster] project the same shape, so an out-of-band
// edit of an owned field changes the result. Ported from
// kuberay.rs:149-168.
//
// Quantity fields (Cpu/Memory/Gpu) are canonicalized through
// [canonicalQuantity] before hashing. This is NOT in the Rust reference
// (which hashes the raw strings, since Rust's Value passes them through
// unparsed everywhere) — it is required here because
// [FingerprintFromRayCluster] reads the *live* manifest back through
// resource.Quantity.String(), which normalizes the wire form ("0.5" ->
// "500m", "1024Mi" -> "1Gi", "2000m" -> "2"). Without canonicalizing this
// side the same way, any spec whose author wrote a non-canonical quantity
// string would never match its own freshly-applied manifest, and the
// reconcile loop would treat it as permanently drifted, forever
// re-applying (fixed in fix round 1, see task-5-report.md).
func OwnedSpecFingerprint(spec *core.ClusterSpec) string {
	workers := make([]fingerprintWorker, len(spec.WorkerGroups))
	for i, g := range spec.WorkerGroups {
		workers[i] = fingerprintWorker{
			Name: g.Name, Cpu: canonicalQuantity(g.Cpu), Memory: canonicalQuantity(g.Memory), Gpu: canonicalQuantityPtr(g.Gpu),
			Min: g.MinReplicas, Max: g.MaxReplicas,
		}
	}
	b, err := json.Marshal(fingerprintSpec{
		RayVersion:     spec.RayVersion,
		Image:          spec.Image,
		HeadCpu:        canonicalQuantity(spec.HeadCpu),
		HeadMemory:     canonicalQuantity(spec.HeadMemory),
		Workers:        workers,
		Storage:        storageProjection(spec.StorageResolved),
		ServiceAccount: derefString(spec.ServiceAccountResolved),
	})
	if err != nil {
		// fingerprintSpec is built entirely from strings/uint32s: only a
		// pathological allocation failure could make this fail.
		panic(fmt.Sprintf("provision: marshaling fingerprint: %v", err))
	}
	return string(b)
}

// canonicalQuantity parses s as a Kubernetes resource.Quantity and returns
// its canonical string form (matching what resource.Quantity.String()
// produces when read back off a live manifest, see [containerResources]).
// Falls back to s unchanged when it doesn't parse as a quantity —
// deliberately no error return: this is a hashing input, not a validated
// construction path (that validation already happened, or will fail
// loudly, in [podTemplate]/[RayClusterFor]), so a fingerprint over the raw
// string is still well-defined and simply won't match a canonicalized
// live read-back for that one malformed field.
func canonicalQuantity(s string) string {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return s
	}
	return q.String()
}

// canonicalQuantityPtr is [canonicalQuantity] lifted over the optional GPU
// quantity string.
func canonicalQuantityPtr(s *string) *string {
	if s == nil {
		return nil
	}
	c := canonicalQuantity(*s)
	return &c
}

// FingerprintFromRayCluster recomputes the owned-field fingerprint from a
// *live* RayCluster spec (the inverse projection of [RayClusterFor]), so
// Observe can detect out-of-band edits. Returns ok=false if the manifest is
// missing the fields Bifrost owns (nothing to compare). Container resources
// are read from the first container of each group's pod template, matching
// [podTemplate]. Ported from kuberay.rs:175-208.
func FingerprintFromRayCluster(spec *rayv1.RayClusterSpec) (fingerprint string, ok bool) {
	if spec == nil {
		// Nothing to compare against — same "not comparable" outcome as a
		// spec missing the owned fields (review follow-up, task-6-brief.md
		// ledger item 3: guard against a nil live-read spec rather than
		// panicking on spec.HeadGroupSpec).
		return "", false
	}
	headCPU, headMemory, headOK := containerResources(&spec.HeadGroupSpec.Template)
	if !headOK {
		return "", false
	}
	workers := make([]fingerprintWorker, 0, len(spec.WorkerGroupSpecs))
	for _, g := range spec.WorkerGroupSpecs {
		cpu, memory, gOK := containerResources(&g.Template)
		if !gOK {
			continue
		}
		var min, max uint32
		if g.MinReplicas != nil && *g.MinReplicas > 0 {
			min = uint32(*g.MinReplicas)
		}
		if g.MaxReplicas != nil && *g.MaxReplicas > 0 {
			max = uint32(*g.MaxReplicas)
		}
		workers = append(workers, fingerprintWorker{
			Name: g.GroupName, Cpu: cpu, Memory: memory, Gpu: containerGPU(&g.Template),
			Min: min, Max: max,
		})
	}
	image, _ := containerImage(&spec.HeadGroupSpec.Template)
	b, err := json.Marshal(fingerprintSpec{
		RayVersion:     spec.RayVersion,
		Image:          image,
		HeadCpu:        headCPU,
		HeadMemory:     headMemory,
		Workers:        workers,
		Storage:        storageFromTemplate(&spec.HeadGroupSpec.Template),
		ServiceAccount: spec.HeadGroupSpec.Template.Spec.ServiceAccountName,
	})
	if err != nil {
		panic(fmt.Sprintf("provision: marshaling fingerprint: %v", err))
	}
	return string(b), true
}

// firstContainer returns the first container of a pod template's spec
// (`template.spec.containers[0]`), and whether one exists.
func firstContainer(tmpl *corev1.PodTemplateSpec) (*corev1.Container, bool) {
	if tmpl == nil || len(tmpl.Spec.Containers) == 0 {
		return nil, false
	}
	return &tmpl.Spec.Containers[0], true
}

func containerResources(tmpl *corev1.PodTemplateSpec) (cpu, memory string, ok bool) {
	c, found := firstContainer(tmpl)
	if !found {
		return "", "", false
	}
	cpuQ, cpuOK := c.Resources.Requests[corev1.ResourceCPU]
	memQ, memOK := c.Resources.Requests[corev1.ResourceMemory]
	if !cpuOK || !memOK {
		return "", "", false
	}
	return cpuQ.String(), memQ.String(), true
}

func containerGPU(tmpl *corev1.PodTemplateSpec) *string {
	c, found := firstContainer(tmpl)
	if !found {
		return nil
	}
	q, ok := c.Resources.Requests[corev1.ResourceName("nvidia.com/gpu")]
	if !ok {
		return nil
	}
	s := q.String()
	return &s
}

func containerImage(tmpl *corev1.PodTemplateSpec) (string, bool) {
	c, found := firstContainer(tmpl)
	if !found {
		return "", false
	}
	return c.Image, true
}

func headGroupSpec(id string, spec *core.ClusterSpec, generation *uint64, sched Scheduling) (rayv1.HeadGroupSpec, error) {
	tmpl, err := podTemplate(id, HeadContainerName, spec.Image, spec.HeadCpu, spec.HeadMemory, nil, generation, spec.Owner, spec.StorageResolved, derefString(spec.ServiceAccountResolved), sched)
	if err != nil {
		return rayv1.HeadGroupSpec{}, err
	}
	return rayv1.HeadGroupSpec{
		RayStartParams: map[string]string{"dashboard-host": "0.0.0.0"},
		Template:       tmpl,
	}, nil
}

func workerGroupSpec(id string, g *core.WorkerGroup, image string, autoscaling bool, generation *uint64, owner *string, storage []core.ResolvedStorage, serviceAccount string, sched Scheduling) (rayv1.WorkerGroupSpec, error) {
	// Workers run the cluster image (Kubernetes requires an image on
	// every container; KubeRay does NOT copy the head image onto worker
	// groups, so an empty image would be rejected).
	tmpl, err := podTemplate(id, WorkerContainerName, image, g.Cpu, g.Memory, g.Gpu, generation, owner, storage, serviceAccount, sched)
	if err != nil {
		return rayv1.WorkerGroupSpec{}, err
	}
	ws := rayv1.WorkerGroupSpec{
		GroupName:      g.Name,
		MinReplicas:    ptr.To(int32(g.MinReplicas)),
		MaxReplicas:    ptr.To(int32(g.MaxReplicas)),
		RayStartParams: map[string]string{},
		Template:       tmpl,
	}
	// ADR-0007: only set Replicas when we own it (autoscaling off). With
	// the in-tree autoscaler on, the sidecar owns replicas + scaleStrategy;
	// writing them here would fight it.
	if !autoscaling {
		ws.Replicas = ptr.To(int32(g.Replicas))
	}
	return ws, nil
}

// HeadContainerName / WorkerContainerName are the container names KubeRay
// also uses; podTemplate keys the probe shape on them.
const (
	HeadContainerName   = "ray-head"
	WorkerContainerName = "ray-worker"
)

// rayHealthScript is the probe body: exit 0 when every endpoint answers
// "success". Timeouts mirror KubeRay's defaults (2 s raylet, 10 s GCS).
const rayHealthScript = `import sys, urllib.request
def ok(url, t):
    try:
        return b"success" in urllib.request.urlopen(url, timeout=t).read()
    except Exception:
        return False
checks = [ok("http://localhost:52365/api/local_raylet_healthz", 2)]
if len(sys.argv) > 1 and sys.argv[1] == "head":
    checks.append(ok("http://localhost:8265/api/gcs_healthz", 10))
sys.exit(0 if all(checks) else 1)
`

// rayProbe is the liveness/readiness probe for a Ray node: raylet health on
// every node, GCS health on the head as well. Timing matches KubeRay's
// defaults (initial 30 s, period 5 s, timeout 5 s, 120 failures) so the
// convergence behaviour operators already know is unchanged; only the
// command differs — python, which every Ray image has, instead of wget.
func rayProbe(head bool) *corev1.Probe {
	args := []string{"python", "-c", rayHealthScript}
	if head {
		args = append(args, "head")
	}
	return &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: args}},
		InitialDelaySeconds: 30,
		PeriodSeconds:       5,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    120,
	}
}

// storage is the spec's resolved private-storage catalog entries
// (requirement 12): env entries become `envFrom.secretRef`, file entries a
// volume at their mount path backed by the entry's source (a read-only
// Secret volume, or a read-write PersistentVolumeClaim). Only
// Secret NAMES are written; the kubelet resolves them inside the pod, so
// the credentials never pass through Bifrost.
//
// serviceAccount is the workload identity (#20): the ServiceAccount the
// pod runs under, "" for the namespace default. Only the NAME is written;
// the platform owns the account and whatever cloud IAM role is bound to
// it, so credentials reach the pod from the node's identity agent and
// never through Bifrost.
func podTemplate(clusterID, containerName, image, cpu, memory string, gpu *string, generation *uint64, owner *string, storage []core.ResolvedStorage, serviceAccount string, sched Scheduling) (corev1.PodTemplateSpec, error) {
	cpuQ, err := resource.ParseQuantity(cpu)
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("provision: invalid cpu quantity %q: %w", cpu, err)
	}
	memQ, err := resource.ParseQuantity(memory)
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("provision: invalid memory quantity %q: %w", memory, err)
	}
	limits := corev1.ResourceList{corev1.ResourceCPU: cpuQ, corev1.ResourceMemory: memQ}
	requests := corev1.ResourceList{corev1.ResourceCPU: cpuQ, corev1.ResourceMemory: memQ}
	if gpu != nil {
		gpuQ, err := resource.ParseQuantity(*gpu)
		if err != nil {
			return corev1.PodTemplateSpec{}, fmt.Errorf("provision: invalid gpu quantity %q: %w", *gpu, err)
		}
		limits[corev1.ResourceName("nvidia.com/gpu")] = gpuQ
		requests[corev1.ResourceName("nvidia.com/gpu")] = gpuQ
	}
	container := corev1.Container{
		Name:      containerName,
		Resources: corev1.ResourceRequirements{Limits: limits, Requests: requests},
	}
	// Explicit probes, so KubeRay does not inject its defaults. KubeRay's
	// default probes shell out to `wget`, and a Ray image without it (any
	// slim environment image; the checkmaite Ray image on grace) runs Ray
	// perfectly and is killed by the liveness probe every ~10 minutes
	// (docs/defects/2026-09-02-health-probes-assume-wget.md). Every Ray image
	// has the Python that runs Ray, so the probes ask Ray's own health
	// endpoints through it: the raylet on every node, plus GCS on the head.
	container.LivenessProbe = rayProbe(containerName == HeadContainerName)
	container.ReadinessProbe = rayProbe(containerName == HeadContainerName)
	volumes := projectStorage(&container, storage)
	// Both head and workers carry the cluster image; only omitted if a
	// caller passes empty (KubeRay then applies its default).
	if image != "" {
		container.Image = image
	}
	// Every tenant pod carries the cluster-id label: it is what the
	// scoped NetworkPolicies select on — the default-deny/tenant-allow
	// pair matches pods with the label at all, and the per-cluster allow
	// matches this exact value, keeping tenant clusters isolated from
	// each other. KubeRay merges its own ray.io/* labels alongside it.
	podLabels := map[string]string{ClusterIDLabel: clusterID}
	// Stamp the owner onto every pod (tier-2 attribution). The per-owner
	// ingress policy keys on the notebook pod's owner label, not this
	// one — this label makes the cluster's pods self-describe who owns
	// them. ownerLabelValue (F9) keeps it a valid RFC 1123 label value.
	if owner != nil {
		podLabels[OwnerLabel] = ownerLabelValue(*owner)
	}
	tmpl := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{container}, Volumes: volumes, ServiceAccountName: serviceAccount},
	}
	// Deployment-wide placement (where this control plane may put tenant
	// pods on this cluster). A zero Scheduling leaves the spec untouched.
	sched.apply(&tmpl.Spec)
	// Stamp the generation into the pod template so a spec bump changes
	// the template hash and KubeRay rolls the pods. Services pass nil —
	// KubeRay's RayService controller owns their rollout, not Bifrost.
	if generation != nil {
		tmpl.Annotations = map[string]string{GenerationAnnotation: strconv.FormatUint(*generation, 10)}
	}
	return tmpl, nil
}

// StorageVolumeName is the pod volume a file-mode storage entry mounts
// through: "storage-<catalog name>" (the API keeps catalog names RFC 1123
// labels short enough for this to be a valid volume name).
func StorageVolumeName(entry string) string { return "storage-" + entry }

// projectStorage adds the storage entries to container (envFrom for env
// mode, a volume mount for file mode) and returns the volumes the pod
// needs for the mounts: a Secret volume (read-only) or a
// PersistentVolumeClaim (read-write — data volumes, not
// credentials), per the entry's source. Env entries carry only Secret
// names — the kubelet resolves them inside the pod, so the credentials
// never pass through Bifrost.
func projectStorage(container *corev1.Container, storage []core.ResolvedStorage) []corev1.Volume {
	var volumes []corev1.Volume
	for _, st := range storage {
		switch st.Mode {
		case core.StorageModeEnv:
			container.EnvFrom = append(container.EnvFrom, corev1.EnvFromSource{
				SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: st.SecretName}},
			})
		case core.StorageModeFile:
			if st.MountPath == nil {
				continue // validated away at the catalog edit; never mount at ""
			}
			name := StorageVolumeName(st.Name)
			mount := corev1.VolumeMount{Name: name, MountPath: *st.MountPath}
			var src corev1.VolumeSource
			switch st.Source.OrDefault() {
			case core.StorageSourcePersistentVolumeClaim:
				// Claims are data volumes, not credentials: they mount
				// read-write (the Kubernetes default), matching the
				// pre-catalog deployments that ran against the same claims.
				// The catalog's projects scoping is the access boundary.
				src = corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: st.ClaimName,
				}}
			default:
				src = corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: st.SecretName}}
				mount.ReadOnly = true
			}
			volumes = append(volumes, corev1.Volume{Name: name, VolumeSource: src})
			container.VolumeMounts = append(container.VolumeMounts, mount)
		}
	}
	return volumes
}

// SuspendPatch is the partial manifest a suspend/resume call actuates: a
// JSON merge patch flipping only spec.suspend. Deliberately NOT a
// server-side apply: a partial SSA apply with Bifrost's field manager is
// fully-specified intent and would drop every other Bifrost-owned field
// from the applied set. Bifrost already owns spec.suspend via the full
// apply ([RayClusterFor] always writes it), so a merge patch flips the
// value while single-writer ownership (ADR-0007-equivalent) stays with the
// FieldManager. Ported from kuberay.rs:637-639.
func SuspendPatch(suspend bool) []byte {
	type patch struct {
		Spec struct {
			Suspend bool `json:"suspend"`
		} `json:"spec"`
	}
	var p patch
	p.Spec.Suspend = suspend
	b, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("provision: marshaling suspend patch: %v", err))
	}
	return b
}

// RayServiceFor builds the RayService manifest for a Serve service. The
// ServeConfigV2 is passed through verbatim; the upgrade strategy selects
// canary (NewCluster — zero-downtime with safe rollback) vs in-place
// (None). Ported from kuberay.rs:644-683.
//
// generation is the Bifrost spec generation being applied, stamped as
// [GenerationAnnotation] so the service reconciler can tell a RayService
// that already carries the current spec from one that is behind (the
// same contract RayClusterFor has). queue, when non-nil, stamps
// [QueueLabel] so Kueue can admit the RayCluster KubeRay derives from
// this RayService (KubeRay copies RayService labels onto it); the
// serving-pool package fills it, nil keeps the manifest label-free.
//
// spec.StorageResolved (requirement 12) is projected onto both pod
// templates as Secret references, exactly as RayClusterFor does.
func RayServiceFor(name string, spec *core.ServiceSpec, generation uint64, queue *QueueAssignment) (*rayv1.RayService, error) {
	return RayServiceForScheduled(name, spec, generation, queue, Scheduling{})
}

// RayServiceForScheduled is [RayServiceFor] with the control plane's
// [Scheduling] stamped onto the Serve head and worker pod templates.
func RayServiceForScheduled(name string, spec *core.ServiceSpec, generation uint64, queue *QueueAssignment, sched Scheduling) (*rayv1.RayService, error) {
	var upgradeType rayv1.RayServiceUpgradeType
	switch spec.Upgrade {
	case core.UpgradeStrategyCanary:
		upgradeType = rayv1.RayServiceNewCluster
	case core.UpgradeStrategyInPlace:
		upgradeType = rayv1.RayServiceUpgradeNone
	default:
		return nil, fmt.Errorf("provision: unknown upgrade strategy %q", spec.Upgrade)
	}

	worker := core.WorkerGroup{
		Name: "worker", Cpu: spec.WorkerCpu, Memory: spec.WorkerMemory, Gpu: nil,
		MinReplicas: spec.WorkerReplicas, MaxReplicas: spec.WorkerReplicas, Replicas: spec.WorkerReplicas,
	}
	// Serve worker replicas are fixed here (autoscaling=false); Serve
	// autoscaling is Ray Serve's own concern (deployment num_replicas).
	workerSpec, err := workerGroupSpec(name, &worker, spec.Image, false, nil, nil, spec.StorageResolved, derefString(spec.ServiceAccountResolved), sched)
	if err != nil {
		return nil, fmt.Errorf("provision: service worker group: %w", err)
	}
	headTmpl, err := podTemplate(name, HeadContainerName, spec.Image, spec.HeadCpu, spec.HeadMemory, nil, nil, nil, spec.StorageResolved, derefString(spec.ServiceAccountResolved), sched)
	if err != nil {
		return nil, fmt.Errorf("provision: service head group: %w", err)
	}

	labels := map[string]string{
		ManagedByLabel: FieldManager,
		ClusterIDLabel: name,
	}
	if spec.Project != "" {
		labels[ProjectLabel] = spec.Project
	}
	if queue != nil {
		labels[QueueLabel] = queue.QueueName
	}
	annotations := map[string]string{
		GenerationAnnotation: strconv.FormatUint(generation, 10),
	}

	return &rayv1.RayService{
		TypeMeta: metav1.TypeMeta{APIVersion: APIVersion, Kind: ServiceKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: rayv1.RayServiceSpec{
			ServeConfigV2:   spec.ServeConfigV2,
			UpgradeStrategy: &rayv1.RayServiceUpgradeStrategy{Type: &upgradeType},
			RayClusterSpec: rayv1.RayClusterSpec{
				RayVersion: spec.RayVersion,
				HeadGroupSpec: rayv1.HeadGroupSpec{
					RayStartParams: map[string]string{"dashboard-host": "0.0.0.0"},
					Template:       headTmpl,
				},
				WorkerGroupSpecs: []rayv1.WorkerGroupSpec{workerSpec},
			},
		},
	}, nil
}

// ServiceStatusToState maps a RayService status to a [core.ClusterState].
//
// Conditions first (KubeRay >= 1.3, the pinned v1.7.0 populates them):
// Ready=True means requests can be served (the serve Service has at least
// one healthy endpoint) → running; UpgradeInProgress/RollbackInProgress
// = True means a new version is rolling out or being rolled back →
// updating; Suspending/Suspended → the matching states. With no
// recognised condition the deprecated ServiceStatus is the fallback —
// "Running" is the only value v1.7 still writes there (it is defined as
// equivalent to Ready=True), and the older "Restarting"/"UpgradingCluster"
// values are kept for a downgraded operator. Anything else is still
// coming up → provisioning. Ported from kuberay.rs:687-695 and extended
// for the conditions API.
func ServiceStatusToState(status rayv1.RayServiceStatuses) core.ClusterState {
	if meta.IsStatusConditionTrue(status.Conditions, string(rayv1.RayServiceReady)) {
		return core.ClusterStateRunning
	}
	if meta.IsStatusConditionTrue(status.Conditions, string(rayv1.UpgradeInProgress)) ||
		meta.IsStatusConditionTrue(status.Conditions, string(rayv1.RollbackInProgress)) {
		return core.ClusterStateUpdating
	}
	if meta.IsStatusConditionTrue(status.Conditions, string(rayv1.RayServiceSuspended)) {
		return core.ClusterStateSuspended
	}
	if meta.IsStatusConditionTrue(status.Conditions, string(rayv1.RayServiceSuspending)) {
		return core.ClusterStateSuspending
	}
	switch string(status.ServiceStatus) { //nolint:staticcheck // SA1019: deliberate fallback for operators that only write the deprecated field, see doc comment
	case "Running":
		return core.ClusterStateRunning
	// A new version is being rolled out / health-checked.
	case "Restarting", "UpgradingCluster":
		return core.ClusterStateUpdating
	default:
		return core.ClusterStateProvisioning
	}
}

// StatusToState maps a RayCluster status to a [core.ClusterState]
// (observation-first — derived from observed reality, never a stored
// phase). KubeRay reports `.status.state` as "ready"/"unhealthy"/
// "suspended". Ported from kuberay.rs:701-709.
//
// State is deprecated upstream in favor of Conditions (see
// [ServiceStatusToState]'s doc comment for the same fidelity-over-rewrite
// rationale).
func StatusToState(status rayv1.RayClusterStatus) core.ClusterState {
	switch string(status.State) { //nolint:staticcheck // SA1019: ported fidelity, see doc comment
	case "ready":
		return core.ClusterStateRunning
	case "suspended":
		return core.ClusterStateSuspended
	case "unhealthy":
		return core.ClusterStateDegraded
	default:
		// No state yet -> still coming up.
		return core.ClusterStateProvisioning
	}
}

// ---------------------------------------------------------------------------
// Namespace security posture: default-deny + explicit allows (tenant
// network isolation) and Pod Security Standards labels. These are
// per-namespace objects — one set covers every RayCluster Bifrost applies
// into the namespace — translated here (pure) and applied by the live
// client's EnsureNamespacePosture (Task 6). Ported from kuberay.rs:344-628.
// ---------------------------------------------------------------------------

const (
	NetworkPolicyAPIVersion = "networking.k8s.io/v1"
	NetworkPolicyKind       = "NetworkPolicy"
	// DefaultDenyPolicyName is the default-deny policy Bifrost ensures.
	// Distinct name so an admin's own default-deny is detectable
	// (check-then-apply never overwrites it).
	DefaultDenyPolicyName = "bifrost-default-deny"
	// TenantAllowPolicyName is the explicit-allow policy paired with the
	// default-deny.
	TenantAllowPolicyName = "bifrost-tenant-allow"
	// ClusterAllowPolicyPrefix is the name prefix of the per-cluster
	// intra-tenant allow policy ([ClusterAllowNetworkPolicy]); the suffix
	// is the cluster id.
	ClusterAllowPolicyPrefix = "bifrost-cluster-"
	// ControlPlaneNamespaceLabel marks the namespace(s) the Bifrost
	// control plane (API / reconciler / job gateway) runs in.
	ControlPlaneNamespaceLabel = "bifrost.dev/control-plane"
	// ControlPlanePodLabel marks the Bifrost control-plane pods
	// themselves: the tenant allow policy admits ingress from pods
	// carrying this label, never from a whole namespace.
	ControlPlanePodLabel = "bifrost.dev/control-plane"

	pssEnforceLabel = "pod-security.kubernetes.io/enforce"
	pssWarnLabel    = "pod-security.kubernetes.io/warn"
	pssAuditLabel   = "pod-security.kubernetes.io/audit"
)

// tenantPodSelector is the pod selector every Bifrost tenant policy scopes
// to: only pods Bifrost itself provisioned, recognized by [ClusterIDLabel].
// NEVER an empty (namespace-wide) selector: the kuberay namespace can be —
// and often is — Bifrost's own namespace, and a namespace-wide default-deny
// locks the control plane, the UI, and the gateway's upstreams out of it.
func tenantPodSelector() metav1.LabelSelector {
	return metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: ClusterIDLabel, Operator: metav1.LabelSelectorOpExists},
		},
	}
}

// ClusterAllowPolicyName is the name of the per-cluster allow policy for
// cluster id.
func ClusterAllowPolicyName(id string) string {
	return ClusterAllowPolicyPrefix + id
}

func tcpPort(port int) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(int32(port))
	return networkingv1.NetworkPolicyPort{Protocol: ptr.To(corev1.ProtocolTCP), Port: &p}
}

func udpPort(port int) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(int32(port))
	return networkingv1.NetworkPolicyPort{Protocol: ptr.To(corev1.ProtocolUDP), Port: &p}
}

// DefaultDenyNetworkPolicy is the default-deny NetworkPolicy (the
// single highest-impact isolation fix): select every Bifrost-provisioned
// tenant pod ([tenantPodSelector], never every pod in the namespace), deny
// all ingress and egress. NetworkPolicies are additive (union of allows),
// so pairing this with [TenantAllowNetworkPolicy] + the per-cluster
// [ClusterAllowNetworkPolicy] yields exactly the allow rules and nothing
// else — and non-tenant pods in the namespace are untouched. Ported from
// kuberay.rs:405-418.
func DefaultDenyNetworkPolicy() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: NetworkPolicyAPIVersion, Kind: NetworkPolicyKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:   DefaultDenyPolicyName,
			Labels: map[string]string{ManagedByLabel: FieldManager},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: tenantPodSelector(),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

// TenantAllowNetworkPolicy is the allows every Bifrost tenant pod needs
// under the default-deny, scoped to [tenantPodSelector]. Intra-cluster
// traffic is NOT here — it is per-cluster ([ClusterAllowNetworkPolicy]) so
// tenant clusters stay isolated from each other. This policy carries only
// the cross-cutting allows: control-plane ingress to the head's
// dashboard/client ports, KubeRay-operator ingress, and kube-dns egress.
// Ported from kuberay.rs:444-516.
func TenantAllowNetworkPolicy() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: NetworkPolicyAPIVersion, Kind: NetworkPolicyKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:   TenantAllowPolicyName,
			Labels: map[string]string{ManagedByLabel: FieldManager},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: tenantPodSelector(),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					// The Bifrost control plane -> Ray head
					// dashboard/client. Pod-labeled peers only:
					// same-namespace control-plane pods, and
					// control-plane pods in a labeled namespace. Never a
					// bare namespaceSelector: that would admit colocated
					// tenant pods.
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{ControlPlanePodLabel: "true"}}},
						{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{ControlPlaneNamespaceLabel: "true"}},
							PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{ControlPlanePodLabel: "true"}},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{tcpPort(8265), tcpPort(10001)},
				},
				{
					// The KubeRay operator (wherever it runs) -> dashboard,
					// dashboard agent, serve.
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{},
							PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "kuberay-operator"}},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{tcpPort(8265), tcpPort(52365), tcpPort(8000)},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// kube-dns only: default-deny otherwise breaks DNS.
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
							PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{udpPort(53), tcpPort(53)},
				},
			},
		},
	}
}

// ClusterAllowNetworkPolicy is the per-cluster intra-tenant allow
// (preserving tenant-vs-tenant isolation): pods of cluster id (matched by
// the exact [ClusterIDLabel] value) may talk to each other on every port —
// Ray head<->workers use GCS 6379, dashboard 8265, client 10001 plus the
// raylet's dynamic ports, too many to enumerate — and to nothing else.
// Applied with the cluster's RayCluster/RayService and deleted with it.
//
// Tier-2 per-owner Ray-client pin: when owner is non-nil, a second ingress
// rule admits the owner's notebook — pods in [NotebookNamespace] carrying
// bifrost.dev/owner=<owner> (the label the hub stamps on that user's
// singleuser pod) — to the Ray client (:10001) and dashboard (:8265) ports,
// and to nothing else. When owner is nil (ownerless clusters) only the
// intra-cluster allow is emitted. Ported from kuberay.rs:536-582.
//
// The selector value is rewritten with ownerLabelValue (F9) — the same
// helper that stamps the RayCluster/pod labels — so an IdP username that
// is not a valid label value neither wedges the apply nor desynchronizes
// selector from label. (The hub stamping notebook pods must apply the same
// mapping for rewritten owners.)
func ClusterAllowNetworkPolicy(id string, owner *string) *networkingv1.NetworkPolicy {
	sameCluster := &metav1.LabelSelector{MatchLabels: map[string]string{ClusterIDLabel: id}}
	ingress := []networkingv1.NetworkPolicyIngressRule{
		{From: []networkingv1.NetworkPolicyPeer{{PodSelector: sameCluster}}},
	}
	if owner != nil {
		// The owner's notebook pod -> Ray client + dashboard only.
		// Scoped to the notebook namespace AND the owner pod-label
		// together (a peer block ANDs its selectors), so only that
		// user's notebook in that namespace matches.
		ingress = append(ingress, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": NotebookNamespace}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{OwnerLabel: ownerLabelValue(*owner)}},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{tcpPort(10001), tcpPort(8265)},
		})
	}
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: NetworkPolicyAPIVersion, Kind: NetworkPolicyKind},
		ObjectMeta: metav1.ObjectMeta{
			Name: ClusterAllowPolicyName(id),
			Labels: map[string]string{
				ManagedByLabel: FieldManager,
				ClusterIDLabel: id,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *sameCluster,
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     ingress,
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{To: []networkingv1.NetworkPolicyPeer{{PodSelector: sameCluster}}},
			},
		},
	}
}

// autoscalerOptions sizes the autoscaler sidecar KubeRay adds to the head
// when in-tree autoscaling is on. KubeRay's default reserves 500m CPU and
// 512Mi for it — half a core held by a poller that reads a CR and patches a
// replica count. On a small node that reservation is what stops the second
// cluster from scheduling (the kind lane's autoscaling shard, 4 vCPU, two
// heads). Requests are set to what the sidecar uses; limits stay at KubeRay's
// defaults so it can burst when a scale decision is busy. nil when
// autoscaling is off: no sidecar, nothing to size.
func autoscalerOptions(autoscaling bool) *rayv1.AutoscalerOptions {
	if !autoscaling {
		return nil
	}
	return &rayv1.AutoscalerOptions{
		Resources: &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
		},
	}
}

// APIServerEndpoint is where the Kubernetes API server actually answers:
// the addresses and port of the `kubernetes` EndpointSlice in `default`, not the
// Service VIP. Egress NetworkPolicy is evaluated after the kube-proxy DNAT,
// so a rule written against the ClusterIP (10.x.x.1:443) matches nothing;
// the rule has to name the endpoint IPs and the real port (6443, 16443…).
type APIServerEndpoint struct {
	Addresses []string
	Port      int32
}

// AutoscalerPolicyName is the name of a cluster's autoscaler egress policy.
func AutoscalerPolicyName(id string) string {
	return ClusterAllowPolicyName(id) + "-autoscaler"
}

// AutoscalerEgressNetworkPolicy lets an autoscaled cluster's head reach the
// Kubernetes API server, and nothing else it could not already reach.
//
// With EnableInTreeAutoscaling KubeRay adds an `autoscaler` container to the
// head pod, and that container reads and patches its own RayCluster through
// the API server. Bifrost's tenant posture — default-deny plus a tenant-allow
// whose only egress is kube-dns — closed that path: the sidecar died on a
// connect timeout to the Service VIP, restarted until the head restarted
// with it, and no cluster run with --ray-autoscaling ever gained a worker.
// Found on grace by the grace-e2e sim lane, 2026-09-08 (defect
// docs/defects/2026-09-08-autoscaler-blocked-by-tenant-egress.md).
//
// Scoped as narrowly as the fault: the head pod of this cluster only
// (workers run no autoscaler), the endpoint addresses only, the API port
// only. Policies are additive, so nothing in the tenant posture changes.
// Applied with the cluster and deleted with it, like the cluster allow.
func AutoscalerEgressNetworkPolicy(id string, api APIServerEndpoint) *networkingv1.NetworkPolicy {
	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(api.Addresses))
	for _, ip := range api.Addresses {
		cidr := ip + "/32"
		if strings.Contains(ip, ":") {
			cidr = ip + "/128"
		}
		peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
	}
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: NetworkPolicyAPIVersion, Kind: NetworkPolicyKind},
		ObjectMeta: metav1.ObjectMeta{
			Name: AutoscalerPolicyName(id),
			Labels: map[string]string{
				ManagedByLabel: FieldManager,
				ClusterIDLabel: id,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
				ClusterIDLabel:     id,
				"ray.io/node-type": "head",
			}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    peers,
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(int(api.Port))},
			}},
		},
	}
}

// NamespacePSSLabels are the Pod Security Standards namespace labels.
// Enforce is baseline, not restricted: KubeRay-generated Ray pods do not
// carry the full restricted securityContext (runAsNonRoot, seccomp,
// drop-all capabilities), so enforcing restricted would reject every Ray
// pod Bifrost provisions. Warn/audit at restricted still surface the gap
// without breaking workloads. Ported from kuberay.rs:596-602.
func NamespacePSSLabels() map[string]string {
	return map[string]string{
		pssEnforceLabel: "baseline",
		pssWarnLabel:    "restricted",
		pssAuditLabel:   "restricted",
	}
}

// IsDefaultDeny is a structural check for check-then-apply: does this
// NetworkPolicy deny all ingress+egress for every pod in the namespace?
// Used to detect an admin-managed default-deny Bifrost must not touch.
// Ported from kuberay.rs:609-628.
func IsDefaultDeny(policy *networkingv1.NetworkPolicy) bool {
	if policy == nil {
		return false
	}
	spec := &policy.Spec
	selectsAll := len(spec.PodSelector.MatchLabels) == 0 && len(spec.PodSelector.MatchExpressions) == 0
	var hasIngress, hasEgress bool
	for _, t := range spec.PolicyTypes {
		switch t {
		case networkingv1.PolicyTypeIngress:
			hasIngress = true
		case networkingv1.PolicyTypeEgress:
			hasEgress = true
		}
	}
	return selectsAll && hasIngress && hasEgress && len(spec.Ingress) == 0 && len(spec.Egress) == 0
}

// sortedKeys returns the sorted keys of m — used wherever a Go map (whose
// iteration order is undefined) must project as a deterministic, sorted
// sequence the way Rust's BTreeMap iterates in the reference.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
