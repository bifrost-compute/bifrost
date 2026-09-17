package provision

import (
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	kueuev1beta2 "sigs.k8s.io/kueue/apis/kueue/v1beta2"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// Live-observation mappers (api-v1.md §5.3/§5.8/§5.6): pure functions from
// already-fetched Kubernetes objects to Bifrost's domain observation
// types. Deliberately outside internal/provision/live (which is in
// COVERAGE_EXCLUDE and kept I/O-only, per the wave plan): these functions
// carry the entire filtering/normalization/parsing logic, so they live
// where they are unit-testable and covered. The live client
// (internal/provision/live) does only the I/O (get RayCluster, list
// pods/events, fetch pod logs) and hands the raw typed results here.
//
// Ported from the predecessor's provision crate, src/kuberay.rs:869-1063 (node_breakdown,
// events_from_k8s, tail_lines and their quantity/label helpers). See each
// function's doc comment for the typed-API divergences from the Rust
// reference oracle, which read untyped serde_json::Value against a
// kube-rs dynamic client — deliberately deferred to this task by Task 5
// (task-5-report.md's "Scope decision" section, impedance item 6's
// sibling note).

// ---------------------------------------------------------------------------
// Node breakdown (api-v1.md §5.3, GET /api/v1/clusters/{id}/nodes)
// ---------------------------------------------------------------------------

const (
	// RayClusterLabel is the KubeRay pod label carrying the owning
	// RayCluster's name — the selector the live client lists pods by
	// (`ray.io/cluster=<name>`). Ported from kuberay.rs:724.
	RayClusterLabel = "ray.io/cluster"
	// RayGroupLabel is the KubeRay pod label carrying the worker-group
	// name; head pods carry the head group's name and are distinguished by
	// [RayNodeTypeLabel]. Ported from kuberay.rs:727.
	RayGroupLabel = "ray.io/group"
	// RayNodeTypeLabel is the KubeRay pod label carrying the node type:
	// "head" or "worker". Ported from kuberay.rs:729.
	RayNodeTypeLabel = "ray.io/node-type"
)

// NodeBreakdown builds the head + per-worker-group node breakdown
// (api-v1.md §5.3) from a RayCluster object and the pods KubeRay owns for
// it. pods must already be scoped to the cluster (the live client lists by
// [RayClusterLabel]=id before calling this) — NodeBreakdown does no
// cluster-membership filtering of its own, matching the Rust reference.
// Worker groups follow the RayCluster spec's order; a group seen only on
// pods (e.g. mid-rename) is appended so nothing a pod belongs to is
// silently dropped. desired comes from the spec (Replicas, else
// MinReplicas) since per-group desired counts are not in the status; ready
// is counted from the pods (Running + Ready). rc may be nil (treated as a
// RayCluster with no worker groups), matching a defensive nil-spec guard.
//
// Pure — no Kubernetes client — so it is exhaustively unit-tested against
// constructed Pod/RayCluster fixtures. Ported from
// kuberay.rs:876-954 (node_breakdown). The Rust reference also hand-rolled
// parse_cpu/parse_memory/parse_gpu (kuberay.rs:739-788) to turn quantity
// *strings* into numbers, because it read pods as untyped
// serde_json::Value; that parsing has no equivalent here because typed
// corev1.Pod container requests are already resource.Quantity values —
// [sumRequests] just reads them.
func NodeBreakdown(clusterID string, rc *rayv1.RayCluster, pods []corev1.Pod) core.ClusterNodes {
	var head *core.NodeView
	for i := range pods {
		if pods[i].Labels[RayNodeTypeLabel] == "head" {
			nv := podToNodeView(&pods[i], true)
			head = &nv
			break
		}
	}

	isWorker := func(p *corev1.Pod) bool { return p.Labels[RayNodeTypeLabel] != "head" }

	var workerGroups []core.WorkerGroupNodes
	seen := map[string]bool{}

	var specGroups []rayv1.WorkerGroupSpec
	if rc != nil {
		specGroups = rc.Spec.WorkerGroupSpecs
	}
	for _, g := range specGroups {
		name := g.GroupName
		desired, ok := nonNegativeU32(g.Replicas)
		if !ok {
			desired, _ = nonNegativeU32(g.MinReplicas)
		}
		nodes := nodesForGroup(pods, isWorker, name)
		seen[name] = true
		workerGroups = append(workerGroups, core.WorkerGroupNodes{
			Name: name, Desired: desired, Ready: countReady(nodes), Nodes: nodes,
		})
	}

	// Groups present on pods but absent from the spec (mid-rename / scaled
	// by something else): append them so their nodes are still reported.
	// Desired is unknown here, so it falls back to the observed pod count.
	for i := range pods {
		p := &pods[i]
		if !isWorker(p) {
			continue
		}
		name, ok := p.Labels[RayGroupLabel]
		if !ok || seen[name] {
			continue
		}
		nodes := nodesForGroup(pods, isWorker, name)
		seen[name] = true
		workerGroups = append(workerGroups, core.WorkerGroupNodes{
			Name: name, Desired: uint32(len(nodes)), Ready: countReady(nodes), Nodes: nodes,
		})
	}

	return core.ClusterNodes{ClusterId: clusterID, Head: head, WorkerGroups: workerGroups}
}

// NonNegativeUint32 clamps a possibly-negative int32 status/spec counter
// to a uint32 (negative -> 0). Exported: both NodeBreakdown's
// Replicas/MinReplicas fallback (via the unexported pointer-lifted
// [nonNegativeU32] below) and internal/provision/live's ObservePool
// (Kueue ClusterQueueStatus's Admitted/Reserving/PendingWorkloads int32
// counters) need this same clamp — a single shared definition, not two
// same-named-but-different functions in two packages (fix round 1, M3/dedupe).
func NonNegativeUint32(v int32) uint32 {
	if v < 0 {
		return 0
	}
	return uint32(v)
}

// nonNegativeU32 is [NonNegativeUint32] lifted over an optional pointer,
// distinguishing "nil" from "present" for NodeBreakdown's
// Replicas-then-MinReplicas fallback chain (mirroring the Rust
// reference's `.and_then(|v| v.as_u64())`, which yields None for a
// missing OR negative value, falling through to the next `.or_else`) — a
// value-only clamp can't express "try the next field instead," so this
// stays a distinct, unexported helper rather than folding into
// NonNegativeUint32 itself.
func nonNegativeU32(v *int32) (n uint32, ok bool) {
	if v == nil || *v < 0 {
		return 0, false
	}
	return NonNegativeUint32(*v), true
}

func nodesForGroup(pods []corev1.Pod, isWorker func(*corev1.Pod) bool, group string) []core.NodeView {
	var nodes []core.NodeView
	for i := range pods {
		p := &pods[i]
		if !isWorker(p) || p.Labels[RayGroupLabel] != group {
			continue
		}
		nodes = append(nodes, podToNodeView(p, false))
	}
	return nodes
}

func countReady(nodes []core.NodeView) uint32 {
	var n uint32
	for _, node := range nodes {
		if node.Phase == "Running" && node.Ready {
			n++
		}
	}
	return n
}

// podToNodeView maps one pod to a [core.NodeView]. Ported from
// kuberay.rs:822-867 (pod_to_node_view).
func podToNodeView(pod *corev1.Pod, isHead bool) core.NodeView {
	ready := false
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			ready = true
			break
		}
	}
	phase := string(pod.Status.Phase)
	if phase == "" {
		phase = "Unknown"
	}
	nv := core.NodeView{
		PodName: pod.Name,
		IsHead:  isHead,
		Phase:   phase,
		Ready:   ready,
	}
	if !isHead {
		if g, ok := pod.Labels[RayGroupLabel]; ok {
			nv.Group = &g
		}
	}
	if pod.Status.PodIP != "" {
		ip := pod.Status.PodIP
		nv.NodeIp = &ip
	}
	if pod.Spec.NodeName != "" {
		host := pod.Spec.NodeName
		nv.Host = &host
	}
	if v, ok := sumRequests(pod, corev1.ResourceCPU, func(q resource.Quantity) float64 { return q.AsApproximateFloat64() }, func(a, b float64) float64 { return a + b }); ok {
		nv.Cpu = &v
	}
	if v, ok := sumRequests(pod, corev1.ResourceMemory, func(q resource.Quantity) int64 { return q.Value() }, func(a, b int64) int64 { return a + b }); ok {
		u := uint64(v)
		nv.MemoryBytes = &u
	}
	if v, ok := sumRequests(pod, corev1.ResourceName("nvidia.com/gpu"), func(q resource.Quantity) float64 { return q.AsApproximateFloat64() }, func(a, b float64) float64 { return a + b }); ok {
		nv.Gpu = &v
	}
	return nv
}

// sumRequests sums one named resource request across every container in a
// pod, returning ok=false when no container declares it (distinct from a
// declared-but-zero quantity). Ported from kuberay.rs:793-819
// (sum_requests); extract replaces the Rust reference's quantity-string
// parse function, since a typed corev1.Pod's requests are already
// resource.Quantity values.
func sumRequests[T any](pod *corev1.Pod, name corev1.ResourceName, extract func(resource.Quantity) T, add func(T, T) T) (T, bool) {
	var acc T
	found := false
	for _, c := range pod.Spec.Containers {
		q, ok := c.Resources.Requests[name]
		if !ok {
			continue
		}
		v := extract(q)
		if found {
			acc = add(acc, v)
		} else {
			acc = v
			found = true
		}
	}
	return acc, found
}

// ---------------------------------------------------------------------------
// Events (api-v1.md §5.8, GET /api/v1/clusters/{id}/events)
// ---------------------------------------------------------------------------

// MaxEvents caps the events [EventsFromK8s] returns: a busy namespace can
// hold thousands; the newest window is what the tab shows. Ported from
// kuberay.rs:962.
const MaxEvents = 200

// objectBelongsToCluster reports whether a Kubernetes object name belongs
// to the cluster id: true for the RayCluster itself (exact match) and for
// everything KubeRay names under it (head/worker pods, the head service,
// …), which all carry the `<id>-` prefix. Ported from kuberay.rs:969-971.
func objectBelongsToCluster(id, objectName string) bool {
	return objectName == id || strings.HasPrefix(objectName, id+"-")
}

// EventsFromK8s normalizes a list of Kubernetes Events into the cluster's
// events (api-v1.md §5.8): keeps only events about clusterID's objects,
// sorts newest-first by last-seen (nil last-seen sinks to the bottom), and
// caps at [MaxEvents]. Pure, so the filtering/normalization is
// unit-tested without a cluster; the live client (internal/provision/live)
// does the I/O (list Events) and hands the result here. Ported from
// kuberay.rs:989-1043 (events_from_k8s).
//
// The Rust reference oracle read Events through kube-rs's dynamic API and
// so defensively normalized both the legacy core/v1 Event schema
// (involvedObject/firstTimestamp/count) and the events.k8s.io/v1 schema
// (regarding/eventTime/deprecatedCount/series) — it could not know at
// compile time which GVK a given dynamic watch would surface. This port's
// live client only ever lists typed corev1.Event objects — kuberay_client.rs's
// own event_resource() already pins {group: "", version: "v1"} (the
// legacy/core schema, never events.k8s.io), so the dual-schema branches
// were defensive, not load-bearing — and the API server normalizes an
// events.k8s.io/v1-sourced Event onto the legacy corev1.Event shape
// (InvolvedObject, Message, Count, FirstTimestamp/LastTimestamp, EventTime,
// Series) before it ever reaches client code. This port therefore reads
// only the legacy corev1.Event fields; Series is still consulted (it is a
// real field on corev1.Event, carrying collapsed-event compat data
// regardless of source schema).
func EventsFromK8s(clusterID string, raw []corev1.Event) core.ClusterEvents {
	events := make([]core.ClusterEvent, 0, len(raw))
	for i := range raw {
		ev := &raw[i]
		name := ev.InvolvedObject.Name
		if name == "" || !objectBelongsToCluster(clusterID, name) {
			continue
		}
		kind := ev.InvolvedObject.Kind
		if kind == "" {
			kind = "Object"
		}
		object := kind + "/" + name

		// RULING (fix round 1): a typed corev1.Event.Count of 0 is
		// indistinguishable from "count absent" (Go's int32 has no None),
		// unlike Rust's serde_json::Value; rather than guess "absent, so
		// default to 1" (the Rust reference's unwrap_or(1), which a real
		// API-server-populated Event's count never actually exercises),
		// this port yields the literal 0 — matching what the Rust
		// reference itself would output for wire JSON with an explicit
		// "count":0, i.e. port fidelity for the reachable case rather
		// than an unverifiable guess for the unreachable one.
		count := uint32(ev.Count)
		if count == 0 && ev.Series != nil && ev.Series.Count > 0 {
			count = uint32(ev.Series.Count)
		}

		firstSeen := metaTimePtr(ev.FirstTimestamp)
		if firstSeen == nil {
			firstSeen = microTimePtr(ev.EventTime)
		}
		lastSeen := metaTimePtr(ev.LastTimestamp)
		if lastSeen == nil && ev.Series != nil {
			lastSeen = microTimePtr(ev.Series.LastObservedTime)
		}
		if lastSeen == nil {
			lastSeen = microTimePtr(ev.EventTime)
		}
		if lastSeen == nil {
			lastSeen = firstSeen
		}

		eventType := ev.Type
		if eventType == "" {
			eventType = "Normal"
		}
		var reason, message *string
		if ev.Reason != "" {
			r := ev.Reason
			reason = &r
		}
		if ev.Message != "" {
			m := ev.Message
			message = &m
		}

		events = append(events, core.ClusterEvent{
			EventType: eventType,
			Reason:    reason,
			Message:   message,
			Count:     count,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			Object:    &object,
		})
	}

	// Newest first by last-seen (RFC3339 sorts lexicographically). Events
	// with no timestamp sink to the bottom.
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i].LastSeen, events[j].LastSeen
		switch {
		case a != nil && b != nil:
			return *a > *b
		case a == nil:
			return false
		default:
			return true
		}
	})
	if len(events) > MaxEvents {
		events = events[:MaxEvents]
	}

	return core.ClusterEvents{ClusterId: clusterID, Events: events}
}

// metaTimePtr formats t as RFC3339, or nil when t is unset. RFC3339Nano
// (not the whole-second RFC3339) so two events within the same second
// still sort correctly by [EventsFromK8s]'s lexicographic last-seen
// comparison — metav1.Time only carries second precision, so this is a
// no-op for it (RFC3339Nano's fractional digits are trimmed to nothing
// when the value is exactly zero), but [microTimePtr] below shares this
// format string and metav1.MicroTime carries real microsecond precision.
func metaTimePtr(t metav1.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

// microTimePtr formats t as RFC3339Nano, or nil when t is unset — see
// [metaTimePtr]'s doc comment for why sub-second precision matters here.
func microTimePtr(t metav1.MicroTime) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

// ---------------------------------------------------------------------------
// Logs (api-v1.md §5.6, GET /api/v1/clusters/{id}/logs, non-streaming tail)
// ---------------------------------------------------------------------------

// TailLines splits a raw pod-log blob into the last tail lines (oldest
// first) and a flag for whether the tail was filled (older lines may exist
// beyond it). The Kubernetes API already tail-caps server-side; this
// defends against a source that ignores the cap and computes the
// truncated hint. Pure and tested. Ported from kuberay.rs:1049-1063.
func TailLines(raw string, tail uint32) ([]string, bool) {
	var lines []string
	if raw != "" {
		lines = strings.Split(raw, "\n")
		// Rust's str::lines() splits on '\n' but never yields the empty
		// element a trailing '\n' produces ("the final line ending is
		// optional" — kuberay.rs relies on this to avoid counting a
		// phantom empty last line for a blob that, like every real pod
		// log, ends in a newline). Reproduce that first: drop the split's
		// final element, but ONLY when raw actually ends in '\n' — an
		// internal blank line (e.g. "a\nb\n\nc") must NOT be dropped by
		// this step, only the artifact of the trailing terminator.
		if strings.HasSuffix(raw, "\n") {
			lines = lines[:len(lines)-1]
		}
		// str::lines() also strips a trailing '\r' from every line (its
		// LinesAnyMap), so \r\n-terminated logs (not just \n-terminated
		// ones) tail cleanly. This MUST run before the trailing-blank-line
		// drop below: a CRLF blank line before the final terminator (e.g.
		// "a\r\nb\r\n\r\n") splits+drops down to a last element of "\r", not
		// "" — trimming the \r first turns it into "" so the blank-line
		// check below actually recognizes and drops it. (Fix round 2, T12:
		// these two steps were previously in the opposite order, so a
		// trailing CRLF blank line was never dropped.)
		for i, l := range lines {
			lines[i] = strings.TrimSuffix(l, "\r")
		}
		// A genuinely blank final line (raw ends "...\n\n", or a CRLF
		// equivalent) still leaves one more empty element after the drop
		// above. kuberay.rs's tail_lines defends against a log source that
		// emits one anyway (e.g. a doubled trailing newline) by dropping it
		// too — same unconditional "is the last element empty" check the
		// original Go implementation already had, just applied as a second
		// pass after the Rust-semantics drop, not instead of it.
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
	}
	total := uint32(len(lines))
	if tail > 0 && total > tail {
		lines = lines[total-tail:]
	}
	truncated := tail > 0 && total >= tail
	return lines, truncated
}

// RankPods orders pod names head-first, then name-sorted, for a stable
// pod-log selector order (api-v1.md §5.6: "head first so the default
// target is the head"). Moved here from internal/provision/live (fix
// round 1, M3) — pure, so it belongs where it's covered/testable, per
// this file's package doc. Ported from kuberay_client.rs:573-589.
func RankPods(pods []corev1.Pod) []string {
	type ranked struct {
		isHead bool
		name   string
	}
	rs := make([]ranked, 0, len(pods))
	for i := range pods {
		rs = append(rs, ranked{isHead: pods[i].Labels[RayNodeTypeLabel] == "head", name: pods[i].Name})
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].isHead != rs[j].isHead {
			return rs[i].isHead
		}
		return rs[i].name < rs[j].name
	})
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.name
	}
	return out
}

// LogContainer is the container a log tail of pod should read: the Ray
// container by its KubeRay name (head, worker or the RayJob submitter),
// else the pod's first container, else "" (a pod with no containers, which
// the API server will reject on its own). KubeRay's autoscaler sidecar
// rides the head pod, and a log request on a multi-container pod must
// name one.
func LogContainer(pod *corev1.Pod) string {
	for _, want := range []string{HeadContainerName, WorkerContainerName, SubmitterContainerName} {
		for _, c := range pod.Spec.Containers {
			if c.Name == want {
				return c.Name
			}
		}
	}
	if len(pod.Spec.Containers) > 0 {
		return pod.Spec.Containers[0].Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Kueue pool-observation mappers (ADR-0010-equivalent; the body of
// PoolProvisioner.ObservePool). Moved here from internal/provision/live
// (fix round 1, M3) — pure, so they belong where they're covered/testable.
// ---------------------------------------------------------------------------

// FlavorUsageMap converts a ClusterQueue's status.flavorsUsage into
// flavor -> resource -> total quantity string. Ported from
// kueue_client.rs:130-154 (flavors_usage_map).
func FlavorUsageMap(items []kueuev1beta2.FlavorUsage) map[string]map[string]string {
	out := make(map[string]map[string]string, len(items))
	for _, f := range items {
		resources := make(map[string]string, len(f.Resources))
		for _, r := range f.Resources {
			resources[string(r.Name)] = r.Total.String()
		}
		out[string(f.Name)] = resources
	}
	return out
}

// SumLocalQueueUsage flattens a LocalQueue's flavor-scoped usage into
// resource -> total quantity string, summing across flavors. Unlike the
// Rust reference's kueue_client.rs:167-188 (which re-parses each quantity
// string through a float parser to sum it, skipping unparseable ones with
// a warning), this sums typed resource.Quantity values directly via
// [resource.Quantity.Add] — no reparse, no precision loss, and nothing to
// skip, since every value already arrived as a valid Quantity off the
// typed API. Noted as a typed-API improvement, not a behavior change: the
// wire result is the same canonical-quantity total.
func SumLocalQueueUsage(items []kueuev1beta2.LocalQueueFlavorUsage) map[string]string {
	sums := map[string]resource.Quantity{}
	for _, f := range items {
		for _, r := range f.Resources {
			q := sums[string(r.Name)]
			q.Add(r.Total)
			sums[string(r.Name)] = q
		}
	}
	out := make(map[string]string, len(sums))
	for k, v := range sums {
		out[k] = v.String()
	}
	return out
}
