package provision

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	kueuev1beta2 "sigs.k8s.io/kueue/apis/kueue/v1beta2"
)

// mustParseTime/mustParseMicroTime build metav1.Time/metav1.MicroTime test
// fixtures from an RFC3339 string, failing the test on a malformed literal.
func mustParseTime(t *testing.T, s string) metav1.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return metav1.NewTime(tm)
}

func mustParseMicroTime(t *testing.T, s string) metav1.MicroTime {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return metav1.NewMicroTime(tm)
}

// -----------------------------------------------------------------
// Node breakdown (api-v1.md §5.3) — ported from kuberay.rs's
// node_breakdown_* tests (kuberay.rs:1128-1200).
// -----------------------------------------------------------------

// testPod mirrors kuberay.rs's `fn pod(...)` test fixture builder: a
// single-container pod carrying the KubeRay labels NodeBreakdown reads,
// requesting cpu=2/memory=4Gi/nvidia.com/gpu=1.
func testPod(name, nodeType, group, phase string, ready bool) corev1.Pod {
	condStatus := corev1.ConditionFalse
	if ready {
		condStatus = corev1.ConditionTrue
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				RayClusterLabel:  "demo",
				RayNodeTypeLabel: nodeType,
				RayGroupLabel:    group,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{{
				Name: "ray",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:                    resource.MustParse("2"),
						corev1.ResourceMemory:                 resource.MustParse("4Gi"),
						corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1"),
					},
				},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPhase(phase),
			PodIP: "10.1.2.3",
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: condStatus,
			}},
		},
	}
}

func rayClusterWithGroups(groups []struct {
	name     string
	replicas int32
	min      int32
}) *rayv1.RayCluster {
	specs := make([]rayv1.WorkerGroupSpec, len(groups))
	for i, g := range groups {
		specs[i] = rayv1.WorkerGroupSpec{
			GroupName:   g.name,
			Replicas:    ptr.To(g.replicas),
			MinReplicas: ptr.To(g.min),
		}
	}
	return &rayv1.RayCluster{Spec: rayv1.RayClusterSpec{WorkerGroupSpecs: specs}}
}

func TestNodeBreakdownMapsHeadAndGroups(t *testing.T) {
	// Head, two ready CPU workers, one pending GPU worker.
	pods := []corev1.Pod{
		testPod("demo-head", "head", "headgroup", "Running", true),
		testPod("demo-cpu-1", "worker", "cpu", "Running", true),
		testPod("demo-cpu-2", "worker", "cpu", "Running", true),
		testPod("demo-gpu-1", "worker", "gpu", "Pending", false),
	}
	rc := rayClusterWithGroups([]struct {
		name     string
		replicas int32
		min      int32
	}{{"cpu", 2, 0}, {"gpu", 1, 1}})

	nodes := NodeBreakdown("demo", rc, pods)

	if nodes.ClusterId != "demo" {
		t.Fatalf("cluster_id = %q, want demo", nodes.ClusterId)
	}
	if nodes.Head == nil {
		t.Fatal("head present expected")
	}
	head := nodes.Head
	if !head.IsHead {
		t.Fatal("head.IsHead = false, want true")
	}
	if head.Group != nil {
		t.Fatalf("head.Group = %v, want nil", *head.Group)
	}
	if head.PodName != "demo-head" {
		t.Fatalf("head.PodName = %q, want demo-head", head.PodName)
	}
	// 2 cores, 4Gi, 1 gpu summed from the single container.
	if head.Cpu == nil || *head.Cpu != 2.0 {
		t.Fatalf("head.Cpu = %v, want 2.0", head.Cpu)
	}
	if head.MemoryBytes == nil || *head.MemoryBytes != 4*1024*1024*1024 {
		t.Fatalf("head.MemoryBytes = %v, want %d", head.MemoryBytes, uint64(4*1024*1024*1024))
	}
	if head.Gpu == nil || *head.Gpu != 1.0 {
		t.Fatalf("head.Gpu = %v, want 1.0", head.Gpu)
	}

	if len(nodes.WorkerGroups) != 2 {
		t.Fatalf("len(WorkerGroups) = %d, want 2", len(nodes.WorkerGroups))
	}
	cpu := nodes.WorkerGroups[0]
	if cpu.Name != "cpu" || cpu.Desired != 2 || cpu.Ready != 2 || len(cpu.Nodes) != 2 {
		t.Fatalf("cpu group = %+v, want name=cpu desired=2 ready=2 nodes=2", cpu)
	}
	for _, n := range cpu.Nodes {
		if n.IsHead {
			t.Fatal("cpu group node must not be head")
		}
	}

	gpu := nodes.WorkerGroups[1]
	if gpu.Name != "gpu" || gpu.Desired != 1 {
		t.Fatalf("gpu group = %+v, want name=gpu desired=1", gpu)
	}
	// Pending + not-Ready -> not counted ready.
	if gpu.Ready != 0 {
		t.Fatalf("gpu.Ready = %d, want 0", gpu.Ready)
	}
	if gpu.Nodes[0].Phase != "Pending" {
		t.Fatalf("gpu.Nodes[0].Phase = %q, want Pending", gpu.Nodes[0].Phase)
	}
	if gpu.Nodes[0].Ready {
		t.Fatal("gpu.Nodes[0].Ready = true, want false")
	}
}

func TestNodeBreakdownUsesMinReplicasWhenAutoscaling(t *testing.T) {
	// Autoscaled group: Replicas nil, desired falls back to MinReplicas.
	rc := &rayv1.RayCluster{
		Spec: rayv1.RayClusterSpec{
			WorkerGroupSpecs: []rayv1.WorkerGroupSpec{
				{GroupName: "cpu", MinReplicas: ptr.To(int32(3))},
			},
		},
	}
	nodes := NodeBreakdown("demo", rc, nil)
	if nodes.WorkerGroups[0].Desired != 3 {
		t.Fatalf("Desired = %d, want 3", nodes.WorkerGroups[0].Desired)
	}
	if nodes.WorkerGroups[0].Ready != 0 {
		t.Fatalf("Ready = %d, want 0", nodes.WorkerGroups[0].Ready)
	}
}

func TestNodeBreakdownReportsPodOnlyGroups(t *testing.T) {
	// A pod whose group is not in the spec must still be reported.
	pods := []corev1.Pod{testPod("demo-x-1", "worker", "ghost", "Running", true)}
	rc := rayClusterWithGroups(nil)
	nodes := NodeBreakdown("demo", rc, pods)
	if nodes.Head != nil {
		t.Fatalf("Head = %v, want nil", nodes.Head)
	}
	if len(nodes.WorkerGroups) != 1 {
		t.Fatalf("len(WorkerGroups) = %d, want 1", len(nodes.WorkerGroups))
	}
	if nodes.WorkerGroups[0].Name != "ghost" || nodes.WorkerGroups[0].Desired != 1 || nodes.WorkerGroups[0].Ready != 1 {
		t.Fatalf("group = %+v, want name=ghost desired=1 ready=1", nodes.WorkerGroups[0])
	}
}

func TestNodeBreakdownEmptyWhenNoPods(t *testing.T) {
	rc := rayClusterWithGroups([]struct {
		name     string
		replicas int32
		min      int32
	}{{"cpu", 2, 0}})
	nodes := NodeBreakdown("demo", rc, nil)
	if nodes.Head != nil {
		t.Fatalf("Head = %v, want nil", nodes.Head)
	}
	if len(nodes.WorkerGroups) != 1 || nodes.WorkerGroups[0].Desired != 2 || nodes.WorkerGroups[0].Ready != 0 {
		t.Fatalf("group = %+v, want name=cpu desired=2 ready=0", nodes.WorkerGroups[0])
	}
	if len(nodes.WorkerGroups[0].Nodes) != 0 {
		t.Fatalf("Nodes = %v, want empty", nodes.WorkerGroups[0].Nodes)
	}
}

// A nil RayCluster (defensive guard, mirrors the nil-spec guard added to
// FingerprintFromRayCluster) must not panic — it degrades to "no worker
// groups", same as an empty spec.
func TestNodeBreakdownNilRayCluster(t *testing.T) {
	pods := []corev1.Pod{testPod("demo-head", "head", "headgroup", "Running", true)}
	nodes := NodeBreakdown("demo", nil, pods)
	if nodes.Head == nil {
		t.Fatal("Head present expected")
	}
	if len(nodes.WorkerGroups) != 0 {
		t.Fatalf("WorkerGroups = %v, want empty", nodes.WorkerGroups)
	}
}

// -----------------------------------------------------------------
// Events (api-v1.md §5.8) — ported from kuberay.rs's events_* tests
// (kuberay.rs:1872-1969).
// -----------------------------------------------------------------

func TestEventsFilterByClusterAndSortNewestFirst(t *testing.T) {
	mustTime := func(s string) metav1.Time { return mustParseTime(t, s) }
	raw := []corev1.Event{
		{
			Type: "Warning", Reason: "FailedScheduling", Message: "0/3 nodes available",
			Count:          4,
			FirstTimestamp: mustTime("2026-08-22T10:00:00Z"),
			LastTimestamp:  mustTime("2026-08-22T10:05:00Z"),
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "team-b-scoring-head-abc"},
		},
		{
			Type: "Normal", Reason: "Pulled", Message: "Container image pulled",
			Count:          1,
			FirstTimestamp: mustTime("2026-08-22T10:10:00Z"),
			LastTimestamp:  mustTime("2026-08-22T10:10:00Z"),
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "team-b-scoring-worker-xyz"},
		},
		// Belongs to a DIFFERENT cluster — must be excluded.
		{
			Type: "Normal", Reason: "Created",
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "other-cluster-head-1"},
		},
		// The RayCluster object itself (exact-name match).
		{
			Type: "Normal", Reason: "Created",
			LastTimestamp:  mustTime("2026-08-22T09:00:00Z"),
			InvolvedObject: corev1.ObjectReference{Kind: "RayCluster", Name: "team-b-scoring"},
		},
	}
	out := EventsFromK8s("team-b-scoring", raw)
	if out.ClusterId != "team-b-scoring" {
		t.Fatalf("cluster_id = %q", out.ClusterId)
	}
	if len(out.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3 (the other-cluster event is excluded)", len(out.Events))
	}
	if got := deref(out.Events[0].Reason); got != "Pulled" {
		t.Fatalf("Events[0].Reason = %q, want Pulled", got)
	}
	if got := deref(out.Events[1].Reason); got != "FailedScheduling" {
		t.Fatalf("Events[1].Reason = %q, want FailedScheduling", got)
	}
	if out.Events[1].EventType != "Warning" {
		t.Fatalf("Events[1].EventType = %q, want Warning", out.Events[1].EventType)
	}
	if out.Events[1].Count != 4 {
		t.Fatalf("Events[1].Count = %d, want 4", out.Events[1].Count)
	}
	if got := deref(out.Events[1].Object); got != "Pod/team-b-scoring-head-abc" {
		t.Fatalf("Events[1].Object = %q", got)
	}
	if got := deref(out.Events[2].Object); got != "RayCluster/team-b-scoring" {
		t.Fatalf("Events[2].Object = %q", got)
	}
}

// TestEventsDefaultCountAndType diverges from kuberay.rs's
// events_default_count_and_type (kuberay.rs:1944-1954), which asserts
// Count == 1 for an event whose wire JSON has NO "count" key at all —
// serde_json::Value can represent "key absent" distinctly from "key
// present with value 0", so Rust's `.unwrap_or(1)` only fires on true
// absence. A typed corev1.Event.Count (int32, no pointer) cannot make
// that distinction: "absent" and "explicitly 0" both decode to the Go
// zero value. EventsFromK8s's RULING (fix round 1) is to yield the
// literal 0 rather than guess "must have been absent" — see its inline
// comment — so this port's equivalent event decodes to Count == 0, not 1.
// EventType's "Normal" default is unaffected and still ported verbatim.
func TestEventsDefaultCountAndType(t *testing.T) {
	raw := []corev1.Event{{
		Reason:         "Scheduled",
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "c-head-0"},
	}}
	out := EventsFromK8s("c", raw)
	if len(out.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(out.Events))
	}
	if out.Events[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (port-fidelity divergence from the Rust reference, see doc comment)", out.Events[0].Count)
	}
	if out.Events[0].EventType != "Normal" {
		t.Fatalf("EventType = %q, want Normal", out.Events[0].EventType)
	}
}

func TestEventsCappedAtMax(t *testing.T) {
	raw := make([]corev1.Event, 0, MaxEvents+50)
	for i := 0; i < MaxEvents+50; i++ {
		ts := mustParseTime(t, "2026-08-22T10:00:00Z")
		ts = metav1.NewTime(ts.Add(time.Duration(i%60) * time.Minute))
		raw = append(raw, corev1.Event{
			Type: "Normal", Reason: "Ping",
			LastTimestamp:  ts,
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "c-head-0"},
		})
	}
	out := EventsFromK8s("c", raw)
	if len(out.Events) != MaxEvents {
		t.Fatalf("len(Events) = %d, want %d", len(out.Events), MaxEvents)
	}
}

// TestEventsSubSecondOrdering proves the RFC3339Nano fix (fix round 1):
// two events within the same second, distinguished only by microsecond
// EventTime, must still sort newest-first. Whole-second RFC3339 would
// have rendered both timestamps identically ("...T10:00:00Z" for both)
// and left their relative order to sort.SliceStable's input order instead
// of the real one.
func TestEventsSubSecondOrdering(t *testing.T) {
	earlier := mustParseMicroTime(t, "2026-08-22T10:00:00Z")
	earlier.Time = earlier.Add(100 * time.Millisecond)
	later := mustParseMicroTime(t, "2026-08-22T10:00:00Z")
	later.Time = later.Add(900 * time.Millisecond)
	raw := []corev1.Event{
		{Type: "Normal", Reason: "First", EventTime: earlier, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "c-head-0"}},
		{Type: "Normal", Reason: "Second", EventTime: later, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "c-head-0"}},
	}
	out := EventsFromK8s("c", raw)
	if len(out.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(out.Events))
	}
	if got := deref(out.Events[0].Reason); got != "Second" {
		t.Fatalf("Events[0].Reason = %q, want Second (the later sub-second timestamp sorts first)", got)
	}
	if got := deref(out.Events[1].Reason); got != "First" {
		t.Fatalf("Events[1].Reason = %q, want First", got)
	}
}

// TestEventsSeriesFallbackCountAndLastObserved covers the Series-based
// fallback branch (a collapsed/repeated event where Count itself is 0):
// count comes from Series.Count and last-seen from
// Series.LastObservedTime. corev1.Event.Series is a real field (carrying
// events.k8s.io/v1-sourced series data the API server normalizes onto the
// legacy schema) — see EventsFromK8s's doc comment for why this port reads
// only the legacy corev1.Event shape rather than a separate
// events.k8s.io/v1 code path.
func TestEventsSeriesFallbackCountAndLastObserved(t *testing.T) {
	firstSeen := mustParseMicroTime(t, "2026-08-22T11:00:00Z")
	lastObserved := mustParseMicroTime(t, "2026-08-22T11:30:00Z")
	raw := []corev1.Event{{
		Type: "Warning", Reason: "BackOff", Message: "Back-off restarting failed container",
		EventTime:      firstSeen,
		Series:         &corev1.EventSeries{Count: 7, LastObservedTime: lastObserved},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "team-b-scoring-worker-1"},
	}}
	out := EventsFromK8s("team-b-scoring", raw)
	if len(out.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(out.Events))
	}
	e := out.Events[0]
	if got := deref(e.Message); got != "Back-off restarting failed container" {
		t.Fatalf("Message = %q", got)
	}
	if e.Count != 7 {
		t.Fatalf("Count = %d, want 7", e.Count)
	}
	if got := deref(e.LastSeen); got != "2026-08-22T11:30:00Z" {
		t.Fatalf("LastSeen = %q, want 2026-08-22T11:30:00Z", got)
	}
	if got := deref(e.Object); got != "Pod/team-b-scoring-worker-1" {
		t.Fatalf("Object = %q", got)
	}
}

// -----------------------------------------------------------------
// Logs (api-v1.md §5.6) — ported from kuberay.rs's
// tail_lines_caps_and_flags_truncation (kuberay.rs:1972-1990).
// -----------------------------------------------------------------

func TestTailLinesCapsAndFlagsTruncation(t *testing.T) {
	raw := "a\nb\nc\nd\ne\n"
	lines, truncated := TailLines(raw, 3)
	assertStrSlice(t, lines, []string{"c", "d", "e"})
	if !truncated {
		t.Fatal("truncated = false, want true")
	}

	all, trunc := TailLines(raw, 10)
	assertStrSlice(t, all, []string{"a", "b", "c", "d", "e"})
	if trunc {
		t.Fatal("truncated = true, want false (fewer lines than the tail)")
	}

	// Exactly the tail: full, so flagged truncated (there may be more).
	exact, exactTrunc := TailLines("x\ny\n", 2)
	assertStrSlice(t, exact, []string{"x", "y"})
	if !exactTrunc {
		t.Fatal("truncated = false, want true (exactly filled the tail)")
	}

	empty, emptyTrunc := TailLines("", 100)
	if len(empty) != 0 {
		t.Fatalf("lines = %v, want empty", empty)
	}
	if emptyTrunc {
		t.Fatal("truncated = true, want false")
	}
}

// TestTailLinesMatchesRustLinesSemantics covers cases the Rust
// kuberay.rs::tail_lines test never exercised (fix round 1, M2): the
// interaction between a genuinely blank final line and the trailing-
// newline artifact, and \r\n line endings.
func TestTailLinesMatchesRustLinesSemantics(t *testing.T) {
	// One blank line before the final newline: the trailing-newline
	// artifact is dropped (Rust's str::lines() semantics), and the
	// resulting trailing blank is ALSO dropped (this port's extra
	// defense against a source that emits one anyway) — so "a", "b", and
	// the blank line all collapse to just "a","b".
	lines, truncated := TailLines("a\nb\n\n", 5)
	assertStrSlice(t, lines, []string{"a", "b"})
	if truncated {
		t.Fatal("truncated = true, want false (2 lines < tail 5)")
	}

	// Two blank lines before the final newline: only ONE of the two gets
	// collapsed away (one by the trailing-newline drop, one by the extra
	// defensive pop) — the other blank line survives as a real "" line.
	lines2, truncated2 := TailLines("a\nb\n\n\n", 5)
	assertStrSlice(t, lines2, []string{"a", "b", ""})
	if truncated2 {
		t.Fatal("truncated = true, want false (3 lines < tail 5)")
	}

	// \r\n line endings: each line's trailing \r is stripped.
	crlf, _ := TailLines("a\r\nb\r\n", 5)
	assertStrSlice(t, crlf, []string{"a", "b"})

	// CRLF + a blank line before the final terminator (fix round 2, T12):
	// the trailing-newline-artifact drop leaves a last element of "\r", not
	// "" — the \r must be trimmed BEFORE the trailing-blank-line check runs,
	// or the blank CRLF line survives as a stray "" instead of collapsing
	// away like the \n-only case above.
	crlfBlank, _ := TailLines("a\r\nb\r\n\r\n", 5)
	assertStrSlice(t, crlfBlank, []string{"a", "b"})

	// Same blank-line collapse as the first case, but tail=2 exactly
	// fills from the already-collapsed 2-line result.
	exact, exactTruncated := TailLines("a\nb\n\n", 2)
	assertStrSlice(t, exact, []string{"a", "b"})
	if !exactTruncated {
		t.Fatal("truncated = false, want true (exactly filled the tail)")
	}
}

func assertStrSlice(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// -----------------------------------------------------------------
// RankPods (api-v1.md §5.6 pod-log selector order) — moved here from
// internal/provision/live (fix round 1, M3). Pins the Rust cmp semantics
// (`b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1))`: head-labeled pods sort
// before worker pods; ties within a group break on name ascending).
// -----------------------------------------------------------------

func TestRankPodsHeadFirstThenNameSorted(t *testing.T) {
	pods := []corev1.Pod{
		testPod("demo-cpu-2", "worker", "cpu", "Running", true),
		testPod("demo-cpu-1", "worker", "cpu", "Running", true),
		testPod("demo-head", "head", "headgroup", "Running", true),
	}
	assertStrSlice(t, RankPods(pods), []string{"demo-head", "demo-cpu-1", "demo-cpu-2"})
}

func TestRankPodsNoHead(t *testing.T) {
	pods := []corev1.Pod{
		testPod("demo-b", "worker", "cpu", "Running", true),
		testPod("demo-a", "worker", "cpu", "Running", true),
	}
	assertStrSlice(t, RankPods(pods), []string{"demo-a", "demo-b"})
}

func TestRankPodsMultipleHeads(t *testing.T) {
	// Not a real KubeRay topology (KubeRay creates exactly one head pod
	// per cluster), but RankPods is a pure function over whatever pods
	// it's handed, and must still degrade sanely: every head-labeled pod
	// sorts before every worker, name-sorted among themselves.
	pods := []corev1.Pod{
		testPod("demo-worker-1", "worker", "cpu", "Running", true),
		testPod("demo-head-b", "head", "headgroup", "Running", true),
		testPod("demo-head-a", "head", "headgroup", "Running", true),
	}
	assertStrSlice(t, RankPods(pods), []string{"demo-head-a", "demo-head-b", "demo-worker-1"})
}

func TestRankPodsEmpty(t *testing.T) {
	got := RankPods(nil)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// -----------------------------------------------------------------
// FlavorUsageMap / SumLocalQueueUsage (Kueue pool observation) — moved
// here from internal/provision/live (fix round 1, M3).
// -----------------------------------------------------------------

func TestFlavorUsageMap(t *testing.T) {
	items := []kueuev1beta2.FlavorUsage{
		{
			Name: "default",
			Resources: []kueuev1beta2.ResourceUsage{
				{Name: corev1.ResourceCPU, Total: resource.MustParse("4")},
				{Name: corev1.ResourceMemory, Total: resource.MustParse("8Gi")},
			},
		},
		{
			Name: "gpu",
			Resources: []kueuev1beta2.ResourceUsage{
				{Name: corev1.ResourceName("nvidia.com/gpu"), Total: resource.MustParse("2")},
			},
		},
	}
	got := FlavorUsageMap(items)
	want := map[string]map[string]string{
		"default": {"cpu": "4", "memory": "8Gi"},
		"gpu":     {"nvidia.com/gpu": "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFlavorUsageMapEmpty(t *testing.T) {
	got := FlavorUsageMap(nil)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// TestSumLocalQueueUsage proves the typed-API improvement documented on
// SumLocalQueueUsage: summing across flavors via resource.Quantity.Add is
// exact, unlike the Rust reference's float-reparse-and-sum
// (kueue_client.rs's sum_usage_by_resource), which would compute
// 0.1 + 0.2 == 0.30000000000000004 under IEEE-754 float64 — 100m + 200m
// here canonicalizes cleanly to exactly "300m".
func TestSumLocalQueueUsage(t *testing.T) {
	items := []kueuev1beta2.LocalQueueFlavorUsage{
		{
			Name: "default",
			Resources: []kueuev1beta2.LocalQueueResourceUsage{
				{Name: corev1.ResourceCPU, Total: resource.MustParse("100m")},
			},
		},
		{
			Name: "gpu-flavor",
			Resources: []kueuev1beta2.LocalQueueResourceUsage{
				{Name: corev1.ResourceCPU, Total: resource.MustParse("200m")},
				{Name: corev1.ResourceName("nvidia.com/gpu"), Total: resource.MustParse("1")},
			},
		},
	}
	got := SumLocalQueueUsage(items)
	want := map[string]string{"cpu": "300m", "nvidia.com/gpu": "1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSumLocalQueueUsageEmpty(t *testing.T) {
	got := SumLocalQueueUsage(nil)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// The log tail names the Ray container, never the autoscaler sidecar that
// shares an autoscaled head pod, and falls back to the first container
// for a pod Bifrost did not shape.
func TestLogContainerPrefersTheRayContainer(t *testing.T) {
	head := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "autoscaler"}, {Name: HeadContainerName}}}}
	if got := LogContainer(head); got != HeadContainerName {
		t.Errorf("head pod log container = %q, want %s", got, HeadContainerName)
	}
	worker := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: WorkerContainerName}}}}
	if got := LogContainer(worker); got != WorkerContainerName {
		t.Errorf("worker = %q", got)
	}
	other := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}, {Name: "sidecar"}}}}
	if got := LogContainer(other); got != "main" {
		t.Errorf("unshaped pod = %q, want its first container", got)
	}
	if got := LogContainer(&corev1.Pod{}); got != "" {
		t.Errorf("no containers = %q, want \"\"", got)
	}
}
