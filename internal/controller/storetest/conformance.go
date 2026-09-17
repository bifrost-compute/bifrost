// Package storetest is a TEST-SUPPORT package, not itself a suite of
// tests: it exports RunConformance, the store.rs-ported conformance
// suite every controller.Store backend must pass. It lives outside
// *_test.go files (the standard Go idiom for shared test helpers other
// packages import — e.g. net/http/httptest) because a _test.go file's
// exports are only visible within its own package, and SQLite/Postgres
// backends (Tasks 3-4) need to call RunConformance from their own
// *_test.go files in internal/controller.
//
// Oracle: the predecessor's controller crate, tests/store.rs
// (retired reference project; cited here only for the file:line
// citations that make porting traceable — never in user-facing
// strings). That file structures its scenarios as a handful of long
// `async fn foo_conformance(store: &dyn Store)` helpers, each invoked
// once per backend by a thin `#[tokio::test]`; this file mirrors that
// shape with one run*Conformance(t, store) per Rust helper, and each
// comment-delimited assertion block inside becomes one named t.Run
// subtest — see the task report's parity table for the full Rust name
// -> Go subtest mapping.
//
// Six scenarios in store.rs are deliberately NOT ported here, in four
// groups (see the task report's table for the authoritative list):
//   - Legacy-chain migration backfill
//     (sqlite_audit_chain_backfills_pre_migration_rows,
//     postgres_audit_chain_backfills_pre_migration_rows): ADR-0004's
//     ruling is that no legacy Bifrost audit chains exist, so there is
//     no migration path to test.
//   - Concurrent-distinct-upserts generation collapse
//     (concurrent_distinct_upserts_do_not_collapse_generation,
//     postgres_concurrent_distinct_upserts_do_not_collapse_generation):
//     exercise a specific backend's transaction-serialization strategy
//     (SQLite's BEGIN IMMEDIATE / Postgres's advisory lock), not
//     Store-interface-level behavior — the Rust reference's own comment
//     notes its in-memory store "can't race" here (max_connections=1).
//   - Concurrent audit-chain appends
//     (postgres_concurrent_audit_appends_keep_one_chain): same class,
//     Postgres's advisory-lock serialization of concurrent record_audit
//     calls specifically.
//   - SQLite persistence across reopen (sqlite_persists_across_reopen):
//     durability-across-process-restart is meaningless for an in-memory
//     store.
//
// All six belong in Tasks 3-4's own backend-specific test files.
package storetest

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
)

// RunConformance runs the full store-conformance suite against a fresh
// Store returned by newStore for each top-level section — mirroring the
// Rust reference's pattern of a fresh InMemoryStore/SqliteStore per
// `#[tokio::test]`. Call it from a backend's own test:
//
//	func TestConformance(t *testing.T) {
//		storetest.RunConformance(t, func() controller.Store { return NewMemoryStore() })
//	}
func RunConformance(t *testing.T, newStore func() controller.Store) {
	t.Run("Clusters", func(t *testing.T) { runClusterConformance(t, newStore()) })
	t.Run("Services", func(t *testing.T) { runServiceConformance(t, newStore()) })
	t.Run("RayJobs", func(t *testing.T) { runRayJobConformance(t, newStore()) })
	t.Run("Pools", func(t *testing.T) { runPoolConformance(t, newStore()) })
	t.Run("Usage", func(t *testing.T) { runUsageConformance(t, newStore()) })
	t.Run("Audit", func(t *testing.T) { runAuditConformance(t, newStore()) })
	t.Run("LocalAuth", func(t *testing.T) { runLocalAuthConformance(t, newStore()) })
	t.Run("RoleAssignments", func(t *testing.T) { runAssignmentConformance(t, newStore()) })
	t.Run("Policy", func(t *testing.T) {
		t.Run("SetGetOverwriteSeedNeverClobbers", func(t *testing.T) { runPolicyConformance(t, newStore()) })
		t.Run("SeedOnEmptyStore", func(t *testing.T) { runPolicySeedConformance(t, newStore()) })
	})

	// --- Additions (NOT ported from store.rs) ---
	//
	// Ruled in on top of the Rust oracle (task-2 coordinator ruling,
	// same precedent as the Wave-0 M3 addendum): generalized,
	// backend-agnostic versions of the fix-round-1/2 aliasing
	// regression tests, a nil-vs-empty-slice contract, and a
	// Go-specific validation gap that has no Rust equivalent (Rust's
	// DesiredState is a compile-time-checked enum with no invalid
	// representation; Go's is a string type, so only Go needs to
	// reject a bad value at the Store boundary). Every SQL-backed
	// store passes these because a column round-trip is naturally a
	// deep copy; only a hand-rolled in-memory backend can get this
	// wrong, which is exactly what fix rounds 1-2 found.
	t.Run("Additions", func(t *testing.T) {
		t.Run("MutationIsolation", func(t *testing.T) { runMutationIsolationConformance(t, newStore()) })
		t.Run("ListMethodsReturnNonNilEmpty", func(t *testing.T) { runNonNilEmptyConformance(t, newStore()) })
		t.Run("SetDesiredRejectsInvalidState", func(t *testing.T) { runSetDesiredValidationConformance(t, newStore()) })
	})
}

// PoisonedSpecJSON is a spec_json no Store method could have written: a
// resolved storage entry naming the retired host_path source, which
// core.StorageSource.UnmarshalJSON rejects — the exact row shape that
// bricked grace's control plane (every List failed on the one undecodable
// row). RunUndecodableRowConformance's per-backend poison hook inserts it
// with raw SQL, below the Store interface.
const PoisonedSpecJSON = `{"name":"poisoned","project":"p1","ray_version":"2.57.0","image":"rayproject/ray:2.57.0","head_cpu":"1","head_memory":"2Gi","worker_groups":[],"storage_resolved":[{"name":"d","source":"host_path","host_path":"/srv/d","mode":"file","mount_path":"/srv/d"}]}`

// RunUndecodableRowConformance is the shared assertion set for a cluster
// row whose spec_json the current binary can no longer decode (another
// addition, not ported from store.rs): List must skip it and still return
// the healthy rows, Get must keep failing on it, and the id-keyed
// operations (TombstoneByID, SetDesired, RemoveCluster) must work so an
// operator can dispose of the row through the API. Seeding needs a raw
// INSERT below the Store interface, so the backend's own test supplies
// poison; the in-memory store cannot express an undecodable row and never
// calls this. The poisoned row is expected desired='terminated' with
// observed_state NULL (a purgeable tombstone).
func RunUndecodableRowConformance(t *testing.T, store controller.Store, poison func(t *testing.T, id core.ClusterId)) {
	t.Helper()
	ctx := context.Background()
	good := core.ClusterId("healthy")
	if _, err := store.UpsertDesired(ctx, good, clusterSpecFixture("healthy", 1)); err != nil {
		t.Fatalf("seed healthy cluster: %v", err)
	}
	bad := core.ClusterId("poisoned")
	poison(t, bad)

	t.Run("ListSkipsIt", func(t *testing.T) {
		list, err := store.List(ctx)
		if err != nil {
			t.Fatalf("List with a poisoned row present: %v", err)
		}
		if len(list) != 1 || list[0].ID != good {
			t.Fatalf("List = %+v, want only the healthy row", list)
		}
	})
	t.Run("GetStillFails", func(t *testing.T) {
		if _, err := store.Get(ctx, bad); err == nil {
			t.Fatal("Get on the poisoned row must fail")
		}
	})
	t.Run("TombstoneByIDReadsThrough", func(t *testing.T) {
		desired, gone, found, err := store.TombstoneByID(ctx, bad)
		if err != nil || !found || desired != controller.DesiredTerminated || !gone {
			t.Fatalf("TombstoneByID(poisoned) = %v, %v, %v, %v; want terminated/gone/found", desired, gone, found, err)
		}
		if _, _, found, err := store.TombstoneByID(ctx, "missing"); err != nil || found {
			t.Fatalf("TombstoneByID(missing) = found=%v err=%v, want not-found", found, err)
		}
	})
	t.Run("SetDesiredWorks", func(t *testing.T) {
		if err := store.SetDesired(ctx, bad, controller.DesiredTerminated); err != nil {
			t.Fatalf("SetDesired on the poisoned row: %v", err)
		}
	})
	t.Run("RemoveClusterWorks", func(t *testing.T) {
		removed, err := store.RemoveCluster(ctx, bad)
		if err != nil || !removed {
			t.Fatalf("RemoveCluster(poisoned) = %v, %v; want removed", removed, err)
		}
		if got, err := store.Get(ctx, bad); err != nil || got != nil {
			t.Fatalf("Get after removal = %v, %v; want gone", got, err)
		}
		list, err := store.List(ctx)
		if err != nil || len(list) != 1 || list[0].ID != good {
			t.Fatalf("List after removal = %+v, %v; want only the healthy row", list, err)
		}
	})
}

// --- Fixtures (store.rs:13-35, 223-251) ---

func clusterSpecFixture(name string, replicas uint32) core.ClusterSpec {
	gpu := (*string)(nil)
	return core.ClusterSpec{
		Engine:     core.DefaultEngine,
		Name:       name,
		Project:    "demo",
		RayVersion: "2.57.0",
		Image:      "rayproject/ray:2.57.0",
		HeadCpu:    "1",
		HeadMemory: "2Gi",
		WorkerGroups: []core.WorkerGroup{{
			Name:        "cpu",
			Cpu:         "1",
			Memory:      "2Gi",
			Gpu:         gpu,
			MinReplicas: 0,
			MaxReplicas: 4,
			Replicas:    replicas,
		}},
	}
}

func poolSpecFixture(name string, weight float64) core.PoolSpec {
	return core.PoolSpec{
		Name: name,
		Flavors: []core.FlavorSpec{{
			Name: "a100",
			Resources: map[string]string{
				"cpu":            "64",
				"nvidia.com/gpu": "8",
			},
			NodeLabels: map[string]string{},
			Taints:     []core.TaintSpec{},
		}},
		Cohort:            "research",
		FairSharingWeight: weight,
		Elastic:           true,
		// Explicit default, like clusterSpecFixture's Engine: a SQL round
		// trip writes the default, so DeepEqual needs it set here too.
		Purpose: core.DefaultPoolPurpose,
	}
}

func allocationFixture(pool, project string) core.AllocationSpec {
	return core.AllocationSpec{
		Pool:           pool,
		Project:        project,
		Namespace:      project,
		Nominal:        map[string]string{"cpu": "16"},
		BorrowingLimit: map[string]string{},
		LendingLimit:   map[string]string{},
	}
}

func strPtr(s string) *string                                      { return &s }
func u16Ptr(v uint16) *uint16                                      { return &v }
func u32Ptr(v uint32) *uint32                                      { return &v }
func u64Ptr(v uint64) *uint64                                      { return &v }
func clusterStatePtr(s core.ClusterState) *core.ClusterState       { return &s }
func driftConditionPtr(d core.DriftCondition) *core.DriftCondition { return &d }

// --- Clusters (store.rs:37-210, `conformance`) ---

func runClusterConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()
	id := core.ClusterId("demo")

	t.Run("UpsertOntoTerminatedRecordIsAFreshCreate", func(t *testing.T) {
		// Not in store.rs — found on grace 2026-09-02: re-creating a deleted
		// id answered 201 and left desired=terminated, a zombie that never
		// provisions. Store.UpsertDesired's contract: a terminated record is
		// re-created, not edited.
		rid := core.ClusterId("revive")
		if _, err := store.UpsertDesired(ctx, rid, clusterSpecFixture("revive", 1)); err != nil {
			t.Fatal(err)
		}
		if err := store.SetDesired(ctx, rid, controller.DesiredTerminated); err != nil {
			t.Fatal(err)
		}
		before, _ := store.Get(ctx, rid)
		if before == nil || before.Desired != controller.DesiredTerminated || before.TerminatedAt == nil {
			t.Fatalf("precondition: %+v", before)
		}
		gen, err := store.UpsertDesired(ctx, rid, clusterSpecFixture("revive", 1))
		if err != nil {
			t.Fatal(err)
		}
		if gen != before.Generation+1 {
			t.Fatalf("revive generation = %d, want %d (a new apply)", gen, before.Generation+1)
		}
		got, _ := store.Get(ctx, rid)
		if got == nil || got.Desired != controller.DesiredRunning || got.TerminatedAt != nil ||
			got.ObservedState != nil || got.ObservedGeneration != 0 || got.FailureCount != 0 || got.Condition != nil {
			t.Fatalf("revived record is not fresh: %+v", got)
		}
		if removed, err := store.RemoveCluster(ctx, rid); err != nil || !removed {
			t.Fatalf("remove revive record: removed=%v err=%v", removed, err)
		}
	})

	t.Run("UpsertDesiredGenerationTracking", func(t *testing.T) {
		// store.rs:40-51.
		if gen, err := store.UpsertDesired(ctx, id, clusterSpecFixture("demo", 1)); err != nil || gen != 1 {
			t.Fatalf("first upsert: gen=%d err=%v, want 1, nil", gen, err)
		}
		if gen, err := store.UpsertDesired(ctx, id, clusterSpecFixture("demo", 1)); err != nil || gen != 1 {
			t.Fatalf("unchanged upsert: gen=%d err=%v, want 1, nil", gen, err)
		}
		if gen, err := store.UpsertDesired(ctx, id, clusterSpecFixture("demo", 3)); err != nil || gen != 2 {
			t.Fatalf("changed upsert: gen=%d err=%v, want 2, nil", gen, err)
		}

		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Generation != 2 {
			t.Fatalf("Generation = %d, want 2", got.Generation)
		}
		if got.Desired != controller.DesiredRunning {
			t.Fatalf("Desired = %v, want DesiredRunning", got.Desired)
		}
		if got.Spec.WorkerGroups[0].Replicas != 3 {
			t.Fatalf("Replicas = %d, want 3", got.Spec.WorkerGroups[0].Replicas)
		}
		if got.ObservedState != nil {
			t.Fatalf("ObservedState = %v, want nil", got.ObservedState)
		}
	})

	t.Run("ObservationRoundTrip", func(t *testing.T) {
		// store.rs:53-60.
		if err := store.RecordObservation(ctx, id, clusterStatePtr(core.ClusterStateRunning), 2); err != nil {
			t.Fatalf("record observation: %v", err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.ObservedState == nil || *got.ObservedState != core.ClusterStateRunning {
			t.Fatalf("ObservedState = %v, want Running", got.ObservedState)
		}
		if got.ObservedGeneration != 2 {
			t.Fatalf("ObservedGeneration = %d, want 2", got.ObservedGeneration)
		}
	})

	t.Run("SetDesiredTransitionsAndTombstoneClock", func(t *testing.T) {
		// store.rs:62-88.
		if err := store.SetDesired(ctx, id, controller.DesiredTerminated); err != nil {
			t.Fatalf("set terminated: %v", err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Desired != controller.DesiredTerminated {
			t.Fatalf("Desired = %v, want DesiredTerminated", got.Desired)
		}
		if got.TerminatedAt == nil {
			t.Fatal("TerminatedAt = nil, want set (tombstone-retention clock)")
		}

		// #51: Suspended round-trips too.
		if err := store.SetDesired(ctx, id, controller.DesiredSuspended); err != nil {
			t.Fatalf("set suspended: %v", err)
		}
		got, err = store.Get(ctx, id)
		if err != nil || got == nil || got.Desired != controller.DesiredSuspended {
			t.Fatalf("Desired after suspend = %v, want DesiredSuspended (err=%v)", got, err)
		}

		if err := store.SetDesired(ctx, id, controller.DesiredRunning); err != nil {
			t.Fatalf("set running: %v", err)
		}
		got, err = store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Desired != controller.DesiredRunning {
			t.Fatalf("Desired = %v, want DesiredRunning", got.Desired)
		}
		// Moving away from Terminated clears the retention clock.
		if got.TerminatedAt != nil {
			t.Fatalf("TerminatedAt = %v, want nil after resume", got.TerminatedAt)
		}
	})

	t.Run("List", func(t *testing.T) {
		// store.rs:90-91.
		list, err := store.List(ctx)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 1 {
			t.Fatalf("len(list) = %d, want 1", len(list))
		}
	})

	t.Run("IntentOutboxFencingReplayMismatchReap", func(t *testing.T) {
		// store.rs:93-122.
		out, err := store.BeginIntent(ctx, "demo/2", "fp-a")
		if err != nil || out != (controller.IntentOutcome{Kind: controller.IntentOutcomeProceed, Replay: false}) {
			t.Fatalf("fresh begin_intent: out=%+v err=%v", out, err)
		}
		out, err = store.BeginIntent(ctx, "demo/2", "fp-a")
		if err != nil || out != (controller.IntentOutcome{Kind: controller.IntentOutcomeProceed, Replay: true}) {
			t.Fatalf("replay begin_intent: out=%+v err=%v", out, err)
		}
		out, err = store.BeginIntent(ctx, "demo/2", "fp-b")
		if err != nil || out.Kind != controller.IntentOutcomeParamMismatch {
			t.Fatalf("mismatch begin_intent: out=%+v err=%v", out, err)
		}
		if err := store.CompleteIntent(ctx, "demo/2", `{"generation":2}`); err != nil {
			t.Fatalf("complete intent: %v", err)
		}
		rec, err := store.GetIntent(ctx, "demo/2")
		if err != nil || rec == nil {
			t.Fatalf("get intent: %v %v", rec, err)
		}
		if rec.Status != controller.IntentStatusApplied {
			t.Fatalf("Status = %v, want Applied", rec.Status)
		}
		if rec.ResponseJSON == nil || *rec.ResponseJSON != `{"generation":2}` {
			t.Fatalf("ResponseJSON = %v, want {\"generation\":2}", rec.ResponseJSON)
		}
		if rec.ParamsFingerprint != "fp-a" {
			t.Fatalf("ParamsFingerprint = %q, want \"fp-a\"", rec.ParamsFingerprint)
		}

		// Reap only removes Applied rows older than the cutoff.
		if n, err := store.ReapIntents(ctx, 0); err != nil || n != 0 {
			t.Fatalf("reap(0): n=%d err=%v, want 0, nil", n, err)
		}
		if n, err := store.ReapIntents(ctx, 32_503_680_000); err != nil || n != 1 {
			t.Fatalf("reap(far future): n=%d err=%v, want 1, nil", n, err)
		}
		if rec, err := store.GetIntent(ctx, "demo/2"); err != nil || rec != nil {
			t.Fatalf("get intent after reap: %v %v, want nil, nil", rec, err)
		}
	})

	t.Run("ObservedGenerationMonotonicFence", func(t *testing.T) {
		// store.rs:124-138 (#41).
		if err := store.RecordObservation(ctx, id, clusterStatePtr(core.ClusterStateRunning), 5); err != nil {
			t.Fatalf("record observation gen 5: %v", err)
		}
		if err := store.RecordObservation(ctx, id, clusterStatePtr(core.ClusterStateRunning), 2); err != nil {
			t.Fatalf("record observation gen 2: %v", err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.ObservedGeneration != 5 {
			t.Fatalf("ObservedGeneration = %d, want 5 (stale observation must not roll it back)", got.ObservedGeneration)
		}
	})

	t.Run("ConditionRoundTrip", func(t *testing.T) {
		// store.rs:140-150 (#41/#47).
		if err := store.SetCondition(ctx, id, driftConditionPtr(core.DriftConditionSpecDrift)); err != nil {
			t.Fatalf("set condition: %v", err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got == nil || got.Condition == nil || *got.Condition != core.DriftConditionSpecDrift {
			t.Fatalf("Condition = %v, want SpecDrift (err=%v)", got, err)
		}
		if err := store.SetCondition(ctx, id, nil); err != nil {
			t.Fatalf("clear condition: %v", err)
		}
		got, err = store.Get(ctx, id)
		if err != nil || got == nil || got.Condition != nil {
			t.Fatalf("Condition after clear = %v, want nil (err=%v)", got, err)
		}
	})

	t.Run("QuarantineRoundTrip", func(t *testing.T) {
		// store.rs:152-157 (#41).
		if q, err := store.IsQuarantined(ctx); err != nil || q {
			t.Fatalf("initial quarantine: q=%v err=%v, want false, nil", q, err)
		}
		if err := store.SetQuarantine(ctx, true); err != nil {
			t.Fatalf("set quarantine true: %v", err)
		}
		if q, err := store.IsQuarantined(ctx); err != nil || !q {
			t.Fatalf("quarantine after set true: q=%v err=%v, want true, nil", q, err)
		}
		if err := store.SetQuarantine(ctx, false); err != nil {
			t.Fatalf("set quarantine false: %v", err)
		}
		if q, err := store.IsQuarantined(ctx); err != nil || q {
			t.Fatalf("quarantine after set false: q=%v err=%v, want false, nil", q, err)
		}
	})

	t.Run("BackoffStateRoundTrip", func(t *testing.T) {
		// store.rs:159-166 (#43).
		if err := store.RecordAttempt(ctx, id, 3, 12_345); err != nil {
			t.Fatalf("record attempt: %v", err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.FailureCount != 3 || got.NextAttemptAt != 12_345 {
			t.Fatalf("FailureCount=%d NextAttemptAt=%d, want 3, 12345", got.FailureCount, got.NextAttemptAt)
		}
		// A fresh upsert (unchanged spec) preserves the backoff state.
		if _, err := store.UpsertDesired(ctx, id, clusterSpecFixture("demo", 3)); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		got, err = store.Get(ctx, id)
		if err != nil || got == nil || got.FailureCount != 3 {
			t.Fatalf("FailureCount after re-upsert = %v, want 3 (err=%v)", got, err)
		}
	})

	t.Run("JobHistoryRoundTrip", func(t *testing.T) {
		// store.rs:168-196 (#20/Phase 3).
		if err := store.RecordJob(ctx, core.JobRecord{
			Id:          "raysubmit_1",
			Cluster:     "gone-cluster",
			Submitter:   "user@x",
			Status:      "RUNNING",
			SubmittedAt: 1000,
		}); err != nil {
			t.Fatalf("record job: %v", err)
		}
		// Re-record with the same id updates status/duration (terminal).
		if err := store.RecordJob(ctx, core.JobRecord{
			Id:           "raysubmit_1",
			Cluster:      "gone-cluster",
			Submitter:    "user@x",
			Status:       "SUCCEEDED",
			DurationSecs: u64Ptr(42),
			SubmittedAt:  1000,
		}); err != nil {
			t.Fatalf("re-record job: %v", err)
		}
		jobs, err := store.ListJobs(ctx)
		if err != nil {
			t.Fatalf("list jobs: %v", err)
		}
		if len(jobs) != 1 {
			t.Fatalf("len(jobs) = %d, want 1", len(jobs))
		}
		if jobs[0].Status != "SUCCEEDED" {
			t.Fatalf("Status = %q, want \"SUCCEEDED\"", jobs[0].Status)
		}
		if jobs[0].DurationSecs == nil || *jobs[0].DurationSecs != 42 {
			t.Fatalf("DurationSecs = %v, want 42", jobs[0].DurationSecs)
		}
		if jobs[0].Cluster != "gone-cluster" {
			t.Fatalf("Cluster = %q, want \"gone-cluster\"", jobs[0].Cluster)
		}
	})

	t.Run("SetDesiredMissingClusterErrors", func(t *testing.T) {
		// store.rs:198-202.
		if err := store.SetDesired(ctx, core.ClusterId("ghost"), controller.DesiredRunning); err == nil {
			t.Fatal("expected an error for a missing cluster")
		}
	})

	t.Run("RemoveClusterHardDeleteIdempotent", func(t *testing.T) {
		// store.rs:204-209.
		removed, err := store.RemoveCluster(ctx, id)
		if err != nil || !removed {
			t.Fatalf("remove_cluster: removed=%v err=%v, want true, nil", removed, err)
		}
		got, err := store.Get(ctx, id)
		if err != nil || got != nil {
			t.Fatalf("get after remove: %v %v, want nil, nil", got, err)
		}
		// Idempotent: removing an absent row is (false, nil), not an error.
		removed, err = store.RemoveCluster(ctx, id)
		if err != nil || removed {
			t.Fatalf("remove_cluster again: removed=%v err=%v, want false, nil", removed, err)
		}
	})
}

// --- Pools (store.rs:254-413, `pool_conformance`) ---

func runPoolConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	t.Run("UpsertPoolGetRoundTrip", func(t *testing.T) {
		// store.rs:255-267.
		gen, err := store.UpsertPool(ctx, "gpu", poolSpecFixture("gpu", 1.0))
		if err != nil || gen != 1 {
			t.Fatalf("upsert pool: gen=%d err=%v, want 1, nil", gen, err)
		}
		got, err := store.GetPool(ctx, "gpu")
		if err != nil || got == nil {
			t.Fatalf("get pool: %v %v", got, err)
		}
		if got.Name != "gpu" || got.Generation != 1 {
			t.Fatalf("Name=%q Generation=%d, want \"gpu\", 1", got.Name, got.Generation)
		}
		if !reflect.DeepEqual(got.Spec, poolSpecFixture("gpu", 1.0)) {
			t.Fatalf("Spec = %+v, want %+v", got.Spec, poolSpecFixture("gpu", 1.0))
		}
		if got.CreatedAt == 0 {
			t.Fatal("CreatedAt = 0, want > 0")
		}
	})

	t.Run("UpsertPoolGenerationTracking", func(t *testing.T) {
		// store.rs:269-290.
		before, err := store.GetPool(ctx, "gpu")
		if err != nil || before == nil {
			t.Fatalf("get pool: %v %v", before, err)
		}
		if gen, err := store.UpsertPool(ctx, "gpu", poolSpecFixture("gpu", 1.0)); err != nil || gen != 1 {
			t.Fatalf("identical re-upsert: gen=%d err=%v, want 1, nil", gen, err)
		}
		if gen, err := store.UpsertPool(ctx, "gpu", poolSpecFixture("gpu", 2.0)); err != nil || gen != 2 {
			t.Fatalf("changed re-upsert: gen=%d err=%v, want 2, nil", gen, err)
		}
		after, err := store.GetPool(ctx, "gpu")
		if err != nil || after == nil || after.Generation != 2 {
			t.Fatalf("get pool after change: %v %v, want generation 2", after, err)
		}
		if after.CreatedAt != before.CreatedAt {
			t.Fatalf("CreatedAt = %d, want unchanged %d", after.CreatedAt, before.CreatedAt)
		}
	})

	t.Run("PoolObservationRoundTripSurvivesSpecUpdate", func(t *testing.T) {
		// store.rs:292-339.
		got, err := store.GetPool(ctx, "gpu")
		if err != nil || got == nil || got.ObservedJSON != nil {
			t.Fatalf("ObservedJSON before observe = %v, want nil (err=%v)", got, err)
		}
		if err := store.RecordPoolObservation(ctx, "gpu", `{"admitted_workloads":1}`); err != nil {
			t.Fatalf("record pool observation: %v", err)
		}
		got, err = store.GetPool(ctx, "gpu")
		if err != nil || got == nil || got.ObservedJSON == nil || *got.ObservedJSON != `{"admitted_workloads":1}` {
			t.Fatalf("ObservedJSON = %v, want {\"admitted_workloads\":1} (err=%v)", got, err)
		}
		if got.ObservedAt == nil {
			t.Fatal("ObservedAt = nil, want set (recording an observation stamps it)")
		}
		if _, err := store.UpsertPool(ctx, "gpu", poolSpecFixture("gpu", 3.0)); err != nil {
			t.Fatalf("upsert pool: %v", err)
		}
		got, err = store.GetPool(ctx, "gpu")
		if err != nil || got == nil || got.ObservedJSON == nil {
			t.Fatalf("ObservedJSON after spec update = %v, want still set (err=%v)", got, err)
		}
	})

	t.Run("ListPoolsSeesAll", func(t *testing.T) {
		// store.rs:341-354. The order is asserted, not sorted away: gpu
		// was upserted first (runPoolConformance's fixture), cpu second,
		// and ListPools must come back name-ordered regardless.
		if _, err := store.UpsertPool(ctx, "cpu", poolSpecFixture("cpu", 1.0)); err != nil {
			t.Fatalf("upsert cpu pool: %v", err)
		}
		pools, err := store.ListPools(ctx)
		if err != nil {
			t.Fatalf("list pools: %v", err)
		}
		names := make([]string, len(pools))
		for i, p := range pools {
			names[i] = p.Name
		}
		if !reflect.DeepEqual(names, []string{"cpu", "gpu"}) {
			t.Fatalf("names = %v, want [cpu gpu] (name-ordered)", names)
		}
	})

	t.Run("ListPoolsIsNameOrdered", func(t *testing.T) {
		// First-match consumers (GPU tenancy admission checks, queue
		// assignment) need ListPools to be deterministic: every backend
		// must return pools name-ordered, however they were inserted.
		for _, name := range []string{"pool-zeta", "pool-alpha", "pool-mid"} {
			if _, err := store.UpsertPool(ctx, name, poolSpecFixture(name, 1.0)); err != nil {
				t.Fatalf("upsert %s: %v", name, err)
			}
		}
		pools, err := store.ListPools(ctx)
		if err != nil {
			t.Fatalf("list pools: %v", err)
		}
		names := make([]string, len(pools))
		for i, p := range pools {
			names[i] = p.Name
		}
		if !slices.IsSorted(names) {
			t.Fatalf("ListPools order = %v, want name-sorted", names)
		}
	})

	t.Run("GetMissingPoolNoneDeleteMissingErrors", func(t *testing.T) {
		// store.rs:356-359.
		if got, err := store.GetPool(ctx, "ghost"); err != nil || got != nil {
			t.Fatalf("get missing pool: %v %v, want nil, nil", got, err)
		}
		err := store.DeletePool(ctx, "ghost")
		if err == nil {
			t.Fatal("expected an error deleting a missing pool")
		}
		if !strings.Contains(err.Error(), "no such pool ghost") {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), "no such pool ghost")
		}
	})

	t.Run("AllocationUpsertListDeleteScopedPerPool", func(t *testing.T) {
		// store.rs:361-408.
		if err := store.UpsertAllocation(ctx, allocationFixture("gpu", "proj-a")); err != nil {
			t.Fatalf("upsert alloc gpu/proj-a: %v", err)
		}
		if err := store.UpsertAllocation(ctx, allocationFixture("gpu", "proj-b")); err != nil {
			t.Fatalf("upsert alloc gpu/proj-b: %v", err)
		}
		if err := store.UpsertAllocation(ctx, allocationFixture("cpu", "proj-c")); err != nil {
			t.Fatalf("upsert alloc cpu/proj-c: %v", err)
		}
		// Re-upsert of the same key updates in place (no duplicate).
		updated := allocationFixture("gpu", "proj-a")
		updated.Nominal["memory"] = "64Gi"
		if err := store.UpsertAllocation(ctx, updated); err != nil {
			t.Fatalf("re-upsert alloc gpu/proj-a: %v", err)
		}

		gpuAllocs, err := store.ListAllocations(ctx, "gpu")
		if err != nil {
			t.Fatalf("list allocations gpu: %v", err)
		}
		gpuProjects := make([]string, len(gpuAllocs))
		for i, a := range gpuAllocs {
			gpuProjects[i] = a.Project
		}
		sort.Strings(gpuProjects)
		if !reflect.DeepEqual(gpuProjects, []string{"proj-a", "proj-b"}) {
			t.Fatalf("gpu projects = %v, want [proj-a proj-b]", gpuProjects)
		}
		// Scoped per pool.
		if cpuAllocs, err := store.ListAllocations(ctx, "cpu"); err != nil || len(cpuAllocs) != 1 {
			t.Fatalf("list allocations cpu: len=%d err=%v, want 1, nil", len(cpuAllocs), err)
		}
		if ghostAllocs, err := store.ListAllocations(ctx, "ghost"); err != nil || len(ghostAllocs) != 0 {
			t.Fatalf("list allocations ghost: len=%d err=%v, want 0, nil", len(ghostAllocs), err)
		}

		if err := store.DeleteAllocation(ctx, "gpu", "proj-a"); err != nil {
			t.Fatalf("delete alloc gpu/proj-a: %v", err)
		}
		remaining, err := store.ListAllocations(ctx, "gpu")
		if err != nil {
			t.Fatalf("list allocations gpu after delete: %v", err)
		}
		if len(remaining) != 1 || remaining[0].Project != "proj-b" {
			t.Fatalf("remaining = %+v, want one row proj-b", remaining)
		}
		err = store.DeleteAllocation(ctx, "gpu", "proj-a")
		if err == nil {
			t.Fatal("expected an error deleting an already-deleted allocation")
		}
		if !strings.Contains(err.Error(), "no such allocation gpu/proj-a") {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), "no such allocation gpu/proj-a")
		}
	})

	t.Run("DeletePoolHardDelete", func(t *testing.T) {
		// store.rs:410-412.
		if err := store.DeletePool(ctx, "cpu"); err != nil {
			t.Fatalf("delete pool cpu: %v", err)
		}
		if got, err := store.GetPool(ctx, "cpu"); err != nil || got != nil {
			t.Fatalf("get pool cpu after delete: %v %v, want nil, nil", got, err)
		}
	})
}

// --- Usage (store.rs:421-504, `usage_conformance`) ---

func usageSampleFixture(ts uint64, project, pool, resource string, qty float64) controller.UsageSample {
	source := controller.UsageSourceKueueLedger
	if pool == "" {
		source = controller.UsageSourceObservedSpec
	}
	return controller.UsageSample{Ts: ts, Project: project, Pool: pool, Resource: resource, Quantity: qty, Source: source}
}

func ownedUsageSample(ts uint64, project, owner string, qty float64) controller.UsageSample {
	s := usageSampleFixture(ts, project, "gpu", "cpu", qty)
	s.Owner = owner
	return s
}

func runUsageConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	// store.rs:436-454: append out of order, everything comes back
	// ts-ordered.
	samples := []controller.UsageSample{
		usageSampleFixture(300, "proj-a", "gpu", "cpu", 8.0),
		usageSampleFixture(100, "proj-a", "gpu", "cpu", 4.0),
		usageSampleFixture(200, "proj-a", "gpu", "cpu", 6.0),
		usageSampleFixture(150, "proj-b", "gpu", "cpu", 2.0),
		usageSampleFixture(150, "proj-a", "gpu", "memory", 16.0),
		usageSampleFixture(150, "proj-a", "cpu-pool", "cpu", 1.0),
		usageSampleFixture(150, "proj-c", "", "cpu", 3.0), // no allocation -> pool ""
	}
	if err := store.RecordUsageSamples(ctx, samples); err != nil {
		t.Fatalf("record usage samples: %v", err)
	}

	t.Run("RecordAndListOrderedByTs", func(t *testing.T) {
		all, err := store.UsageSamples(ctx, nil, nil, nil, 0, ^uint64(0))
		if err != nil {
			t.Fatalf("usage samples: %v", err)
		}
		if len(all) != 7 {
			t.Fatalf("len(all) = %d, want 7", len(all))
		}
		ts := make([]uint64, len(all))
		for i, s := range all {
			ts[i] = s.Ts
		}
		want := []uint64{100, 150, 150, 150, 150, 200, 300}
		if !reflect.DeepEqual(ts, want) {
			t.Fatalf("ts = %v, want %v", ts, want)
		}
	})

	t.Run("RangeQueryInclusive", func(t *testing.T) {
		window, err := store.UsageSamples(ctx, nil, nil, nil, 150, 200)
		if err != nil || len(window) != 5 {
			t.Fatalf("range query: len=%d err=%v, want 5, nil", len(window), err)
		}
	})

	t.Run("ProjectFilter", func(t *testing.T) {
		a, err := store.UsageSamples(ctx, strPtr("proj-a"), nil, nil, 0, ^uint64(0))
		if err != nil || len(a) != 5 {
			t.Fatalf("project filter: len=%d err=%v, want 5, nil", len(a), err)
		}
		for _, s := range a {
			if s.Project != "proj-a" {
				t.Fatalf("sample project = %q, want proj-a", s.Project)
			}
		}
	})

	t.Run("PoolFilter", func(t *testing.T) {
		gpu, err := store.UsageSamples(ctx, nil, strPtr("gpu"), nil, 0, ^uint64(0))
		if err != nil || len(gpu) != 5 {
			t.Fatalf("pool filter: len=%d err=%v, want 5, nil", len(gpu), err)
		}
		for _, s := range gpu {
			if s.Pool != "gpu" {
				t.Fatalf("sample pool = %q, want gpu", s.Pool)
			}
		}
	})

	t.Run("CombinedFiltersAndSourceRoundTrip", func(t *testing.T) {
		one, err := store.UsageSamples(ctx, strPtr("proj-a"), strPtr("gpu"), nil, 100, 100)
		if err != nil || len(one) != 1 {
			t.Fatalf("combined filter: len=%d err=%v, want 1, nil", len(one), err)
		}
		if one[0].Quantity != 4.0 {
			t.Fatalf("Quantity = %v, want 4.0", one[0].Quantity)
		}
		if one[0].Source != controller.UsageSourceKueueLedger {
			t.Fatalf("Source = %v, want KueueLedger", one[0].Source)
		}
		c, err := store.UsageSamples(ctx, strPtr("proj-c"), nil, nil, 0, ^uint64(0))
		if err != nil || len(c) != 1 {
			t.Fatalf("proj-c filter: len=%d err=%v, want 1, nil", len(c), err)
		}
		if c[0].Source != controller.UsageSourceObservedSpec {
			t.Fatalf("proj-c Source = %v, want ObservedSpec", c[0].Source)
		}
	})

	t.Run("EmptyRangeNoMatch", func(t *testing.T) {
		if v, err := store.UsageSamples(ctx, nil, nil, nil, 1000, 2000); err != nil || len(v) != 0 {
			t.Fatalf("empty range: len=%d err=%v, want 0, nil", len(v), err)
		}
		if v, err := store.UsageSamples(ctx, strPtr("ghost"), nil, nil, 0, ^uint64(0)); err != nil || len(v) != 0 {
			t.Fatalf("ghost project: len=%d err=%v, want 0, nil", len(v), err)
		}
	})

	t.Run("OwnerRoundTripAndFilter", func(t *testing.T) {
		// Requirement 14 per-user attribution (not in store.rs): owner
		// persists, filters, and "" is the unattributed bucket every
		// pre-owner sample lands in.
		owned := []controller.UsageSample{
			ownedUsageSample(5000, "proj-a", "alice", 1.0),
			ownedUsageSample(5001, "proj-a", "bob", 2.0),
			ownedUsageSample(5002, "proj-a", "alice", 3.0),
			ownedUsageSample(5003, "proj-b", "alice", 4.0),
		}
		if err := store.RecordUsageSamples(ctx, owned); err != nil {
			t.Fatalf("record owned samples: %v", err)
		}
		alice, err := store.UsageSamples(ctx, nil, nil, strPtr("alice"), 5000, 6000)
		if err != nil || len(alice) != 3 {
			t.Fatalf("owner filter: len=%d err=%v, want 3, nil", len(alice), err)
		}
		for _, s := range alice {
			if s.Owner != "alice" {
				t.Fatalf("sample owner = %q, want alice", s.Owner)
			}
		}
		both, err := store.UsageSamples(ctx, strPtr("proj-a"), nil, strPtr("alice"), 5000, 6000)
		if err != nil || len(both) != 2 || both[0].Quantity != 1.0 || both[1].Quantity != 3.0 {
			t.Fatalf("project+owner filter: %+v err=%v", both, err)
		}
		all, err := store.UsageSamples(ctx, nil, nil, nil, 5000, 6000)
		if err != nil || len(all) != 4 {
			t.Fatalf("nil owner must not filter: len=%d err=%v", len(all), err)
		}
		unattributed, err := store.UsageSamples(ctx, nil, nil, strPtr(""), 0, ^uint64(0))
		if err != nil || len(unattributed) != len(samples) {
			t.Fatalf("empty-owner filter: len=%d err=%v, want the %d ownerless samples", len(unattributed), err, len(samples))
		}
		for _, s := range unattributed {
			if s.Owner != "" {
				t.Fatalf("unattributed sample has owner %q", s.Owner)
			}
		}
	})
}

// --- Audit (store.rs:518-702, `audit_conformance`) ---

func runAuditConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	// store.rs:530-566: append, seq is 1-based and monotonic.
	s1, err := store.RecordAudit(ctx, &core.AuditEvent{
		Ts:           100,
		Subject:      strPtr("alice"),
		Decision:     core.AuditDecisionDeny,
		Reason:       strPtr("insufficient_permission"),
		Action:       strPtr("create_cluster"),
		Cluster:      strPtr("demo"),
		Method:       strPtr("POST"),
		Path:         strPtr("/api/v1/clusters"),
		Status:       u16Ptr(403),
		LatencyMs:    u64Ptr(4),
		Required:     &core.AuditRequired{Action: "write", Target: "cluster"},
		GrantedRoles: []string{"viewer"},
	})
	if err != nil {
		t.Fatalf("record audit s1: %v", err)
	}
	s2, err := store.RecordAudit(ctx, &core.AuditEvent{
		Ts: 200, Subject: strPtr("bob"), Decision: core.AuditDecisionAllow, Status: u16Ptr(200),
	})
	if err != nil {
		t.Fatalf("record audit s2: %v", err)
	}
	// Authn failure: no subject/status.
	s3, err := store.RecordAudit(ctx, &core.AuditEvent{
		Ts: 300, Decision: core.AuditDecisionDeny, Reason: strPtr("missing_token"), Path: strPtr("/api/v1/clusters"),
	})
	if err != nil {
		t.Fatalf("record audit s3: %v", err)
	}
	if s1 != 1 || s2 != 2 || s3 != 3 {
		t.Fatalf("seqs = %d,%d,%d, want 1,2,3", s1, s2, s3)
	}

	t.Run("ListAuditFullReadNewestFirst", func(t *testing.T) {
		// store.rs:568-587.
		rows, next, err := store.ListAudit(ctx, core.AuditFilter{})
		if err != nil {
			t.Fatalf("list audit: %v", err)
		}
		seqs := make([]uint64, len(rows))
		for i, r := range rows {
			seqs[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs, []uint64{3, 2, 1}) {
			t.Fatalf("seqs = %v, want [3 2 1]", seqs)
		}
		if next != nil {
			t.Fatalf("next = %v, want nil", next)
		}
		full := rows[2].Event
		if full.Subject == nil || *full.Subject != "alice" {
			t.Fatalf("full.Subject = %v, want alice", full.Subject)
		}
		if full.Decision != core.AuditDecisionDeny {
			t.Fatalf("full.Decision = %v, want Deny", full.Decision)
		}
		wantRequired := &core.AuditRequired{Action: "write", Target: "cluster"}
		if full.Required == nil || *full.Required != *wantRequired {
			t.Fatalf("full.Required = %v, want %v", full.Required, wantRequired)
		}
		if !reflect.DeepEqual(full.GrantedRoles, []string{"viewer"}) {
			t.Fatalf("full.GrantedRoles = %v, want [viewer]", full.GrantedRoles)
		}
		if full.LatencyMs == nil || *full.LatencyMs != 4 {
			t.Fatalf("full.LatencyMs = %v, want 4", full.LatencyMs)
		}
		// Null-absent fields stay null-absent.
		if rows[0].Event.Subject != nil {
			t.Fatalf("rows[0].Subject = %v, want nil", rows[0].Event.Subject)
		}
		if rows[0].Event.Status != nil {
			t.Fatalf("rows[0].Status = %v, want nil", rows[0].Event.Status)
		}
		if len(rows[0].Event.GrantedRoles) != 0 {
			t.Fatalf("rows[0].GrantedRoles = %v, want empty", rows[0].Event.GrantedRoles)
		}
	})

	t.Run("ListAuditFromToInclusive", func(t *testing.T) {
		// store.rs:589-599.
		rows, _, err := store.ListAudit(ctx, core.AuditFilter{From: u64Ptr(200), To: u64Ptr(200)})
		if err != nil || len(rows) != 1 || rows[0].Event.Ts != 200 {
			t.Fatalf("from/to filter: rows=%+v err=%v, want one row ts=200", rows, err)
		}
	})

	t.Run("ListAuditSubjectFilter", func(t *testing.T) {
		// store.rs:601-609.
		rows, _, err := store.ListAudit(ctx, core.AuditFilter{Subject: strPtr("alice")})
		if err != nil || len(rows) != 1 || rows[0].Seq != 1 {
			t.Fatalf("subject filter: rows=%+v err=%v, want one row seq=1", rows, err)
		}
	})

	t.Run("ListAuditMinStatusExcludesNull", func(t *testing.T) {
		// store.rs:611-620.
		rows, _, err := store.ListAudit(ctx, core.AuditFilter{MinStatus: u16Ptr(400)})
		if err != nil || len(rows) != 1 || rows[0].Seq != 1 {
			t.Fatalf("min_status filter: rows=%+v err=%v, want one row seq=1", rows, err)
		}
	})

	t.Run("ListAuditDecisionFilter", func(t *testing.T) {
		// store.rs:622-629.
		decision := core.AuditDecisionDeny
		rows, _, err := store.ListAudit(ctx, core.AuditFilter{Decision: &decision})
		if err != nil {
			t.Fatalf("decision filter: %v", err)
		}
		seqs := make([]uint64, len(rows))
		for i, r := range rows {
			seqs[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs, []uint64{3, 1}) {
			t.Fatalf("seqs = %v, want [3 1]", seqs)
		}
	})

	t.Run("ListAuditCombinedFieldFilters", func(t *testing.T) {
		// store.rs:631-642.
		rows, _, err := store.ListAudit(ctx, core.AuditFilter{
			Cluster: strPtr("demo"), Method: strPtr("POST"), PathPrefix: strPtr("/api/v1"), Reason: strPtr("insufficient_permission"),
		})
		if err != nil || len(rows) != 1 || rows[0].Seq != 1 {
			t.Fatalf("combined filter: rows=%+v err=%v, want one row seq=1", rows, err)
		}
	})

	t.Run("ListAuditPagination", func(t *testing.T) {
		// store.rs:644-663.
		page1, next, err := store.ListAudit(ctx, core.AuditFilter{Limit: u32Ptr(2)})
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		seqs1 := make([]uint64, len(page1))
		for i, r := range page1 {
			seqs1[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs1, []uint64{3, 2}) {
			t.Fatalf("page1 seqs = %v, want [3 2]", seqs1)
		}
		if next == nil || *next != 2 {
			t.Fatalf("page1 next = %v, want 2", next)
		}
		page2, next2, err := store.ListAudit(ctx, core.AuditFilter{Limit: u32Ptr(2), Cursor: next})
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		seqs2 := make([]uint64, len(page2))
		for i, r := range page2 {
			seqs2[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs2, []uint64{1}) {
			t.Fatalf("page2 seqs = %v, want [1]", seqs2)
		}
		if next2 != nil {
			t.Fatalf("page2 next = %v, want nil", next2)
		}
	})

	t.Run("ListAuditCursorBeyondOldestIsEmpty", func(t *testing.T) {
		// store.rs:665-674.
		page, next, err := store.ListAudit(ctx, core.AuditFilter{Cursor: u64Ptr(1)})
		if err != nil || len(page) != 0 || next != nil {
			t.Fatalf("cursor beyond oldest: page=%+v next=%v err=%v, want empty, nil, nil", page, next, err)
		}
	})

	t.Run("AuditChainFullVerifies", func(t *testing.T) {
		// store.rs:676-687 (#59).
		window, err := store.AuditChain(ctx, nil, 100)
		if err != nil {
			t.Fatalf("audit chain: %v", err)
		}
		if window.Head != controller.AuditGenesisHash {
			t.Fatalf("Head = %q, want genesis", window.Head)
		}
		seqs := make([]uint64, len(window.Rows))
		for i, r := range window.Rows {
			seqs[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs, []uint64{1, 2, 3}) {
			t.Fatalf("seqs = %v, want [1 2 3]", seqs)
		}
		for _, r := range window.Rows {
			if len(r.ChainHash) != 64 {
				t.Fatalf("ChainHash len = %d, want 64", len(r.ChainHash))
			}
		}
		v := controller.VerifyAuditChain(window.Head, window.Rows)
		if !v.OK() || v.EventsChecked != 3 {
			t.Fatalf("verify: OK=%v EventsChecked=%d, want true, 3", v.OK(), v.EventsChecked)
		}
	})

	t.Run("AuditChainMidTrailWindowAndLimit", func(t *testing.T) {
		// store.rs:689-701.
		window, err := store.AuditChain(ctx, u64Ptr(2), 100)
		if err != nil {
			t.Fatalf("audit chain from 2: %v", err)
		}
		full, err := store.AuditChain(ctx, nil, 100)
		if err != nil {
			t.Fatalf("audit chain full: %v", err)
		}
		if window.Head != full.Rows[0].ChainHash {
			t.Fatalf("window.Head = %q, want row1's hash %q", window.Head, full.Rows[0].ChainHash)
		}
		seqs := make([]uint64, len(window.Rows))
		for i, r := range window.Rows {
			seqs[i] = r.Seq
		}
		if !reflect.DeepEqual(seqs, []uint64{2, 3}) {
			t.Fatalf("seqs = %v, want [2 3]", seqs)
		}
		if v := controller.VerifyAuditChain(window.Head, window.Rows); !v.OK() {
			t.Fatalf("window verify: %+v", v)
		}
		one, err := store.AuditChain(ctx, u64Ptr(2), 1)
		if err != nil {
			t.Fatalf("audit chain limit 1: %v", err)
		}
		if len(one.Rows) != 1 || one.Rows[0].Seq != 2 {
			t.Fatalf("limited window = %+v, want one row seq=2", one.Rows)
		}
		if v := controller.VerifyAuditChain(one.Head, one.Rows); !v.OK() {
			t.Fatalf("limited window verify: %+v", v)
		}
	})
}

// --- Local auth (store.rs:791-959, `local_auth_conformance`) ---

func runLocalAuthConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	t.Run("CreateGetRoundTrip", func(t *testing.T) {
		// store.rs:794-816.
		if err := store.CreateLocalUser(ctx, "alice", strPtr("alice@x.io"), "$2b$hash-a", core.LocalRoleDeveloper); err != nil {
			t.Fatalf("create alice: %v", err)
		}
		if err := store.CreateLocalUser(ctx, "bob", nil, "$2b$hash-b", core.LocalRoleViewer); err != nil {
			t.Fatalf("create bob: %v", err)
		}
		alice, err := store.GetLocalUser(ctx, "alice")
		if err != nil || alice == nil {
			t.Fatalf("get alice: %v %v", alice, err)
		}
		if alice.Email == nil || *alice.Email != "alice@x.io" {
			t.Fatalf("Email = %v, want alice@x.io", alice.Email)
		}
		if alice.Role != core.LocalRoleDeveloper {
			t.Fatalf("Role = %v, want Developer", alice.Role)
		}
		if alice.PasswordHash != "$2b$hash-a" {
			t.Fatalf("PasswordHash = %q, want $2b$hash-a", alice.PasswordHash)
		}
		if alice.Disabled {
			t.Fatal("Disabled = true, want false")
		}
		if alice.CreatedAt == 0 {
			t.Fatal("CreatedAt = 0, want > 0")
		}
		if alice.FailedLogins != 0 || alice.LockedUntil != nil {
			t.Fatalf("FailedLogins=%d LockedUntil=%v, want 0, nil", alice.FailedLogins, alice.LockedUntil)
		}
	})

	t.Run("DuplicateUsernameErrorsUnknownIsNone", func(t *testing.T) {
		// store.rs:817-822.
		if err := store.CreateLocalUser(ctx, "alice", nil, "x", core.LocalRoleViewer); err == nil {
			t.Fatal("expected an error creating a duplicate username")
		}
		if got, err := store.GetLocalUser(ctx, "ghost"); err != nil || got != nil {
			t.Fatalf("get ghost: %v %v, want nil, nil", got, err)
		}
	})

	t.Run("ListUsersOrderedByUsername", func(t *testing.T) {
		// store.rs:824-832.
		users, err := store.ListLocalUsers(ctx)
		if err != nil {
			t.Fatalf("list local users: %v", err)
		}
		names := make([]string, len(users))
		for i, u := range users {
			names[i] = u.Username
		}
		if !reflect.DeepEqual(names, []string{"alice", "bob"}) {
			t.Fatalf("names = %v, want [alice bob]", names)
		}
	})

	t.Run("UpdatesRoundTripAndErrorOnMissingUser", func(t *testing.T) {
		// store.rs:834-854.
		if err := store.SetLocalUserPassword(ctx, "alice", "$2b$hash-a2"); err != nil {
			t.Fatalf("set password: %v", err)
		}
		if err := store.SetLocalUserRole(ctx, "alice", core.LocalRoleAdmin); err != nil {
			t.Fatalf("set role: %v", err)
		}
		if err := store.SetLocalUserDisabled(ctx, "bob", true); err != nil {
			t.Fatalf("set disabled: %v", err)
		}
		alice, err := store.GetLocalUser(ctx, "alice")
		if err != nil || alice == nil || alice.PasswordHash != "$2b$hash-a2" || alice.Role != core.LocalRoleAdmin {
			t.Fatalf("alice after updates = %+v, err=%v", alice, err)
		}
		bob, err := store.GetLocalUser(ctx, "bob")
		if err != nil || bob == nil || !bob.Disabled {
			t.Fatalf("bob.Disabled = %v, want true (err=%v)", bob, err)
		}
		if err := store.SetLocalUserPassword(ctx, "ghost", "x"); err == nil {
			t.Fatal("expected an error setting password on a missing user")
		}
		if err := store.SetLocalUserRole(ctx, "ghost", core.LocalRoleViewer); err == nil {
			t.Fatal("expected an error setting role on a missing user")
		}
		if err := store.SetLocalUserDisabled(ctx, "ghost", false); err == nil {
			t.Fatal("expected an error setting disabled on a missing user")
		}
	})

	t.Run("LockoutStateMachine", func(t *testing.T) {
		// store.rs:856-879.
		for i := 0; i < 4; i++ {
			if err := store.RecordLoginFailure(ctx, "alice"); err != nil {
				t.Fatalf("record login failure %d: %v", i, err)
			}
		}
		alice, err := store.GetLocalUser(ctx, "alice")
		if err != nil || alice == nil || alice.FailedLogins != 4 || alice.LockedUntil != nil {
			t.Fatalf("alice after 4 failures = %+v, err=%v", alice, err)
		}
		if err := store.RecordLoginFailure(ctx, "alice"); err != nil {
			t.Fatalf("record login failure 5: %v", err)
		}
		alice, err = store.GetLocalUser(ctx, "alice")
		if err != nil || alice == nil {
			t.Fatalf("get alice: %v %v", alice, err)
		}
		if alice.FailedLogins != 0 {
			t.Fatalf("FailedLogins = %d, want 0 (counter resets when the lock trips)", alice.FailedLogins)
		}
		if alice.LockedUntil == nil {
			t.Fatal("LockedUntil = nil, want set (5th failure locks)")
		}
		now := controller.NowUnix()
		lockedUntil := *alice.LockedUntil
		if lockedUntil < now+controller.LockoutSecs-5 || lockedUntil > now+controller.LockoutSecs+5 {
			t.Fatalf("LockedUntil ~= now + %d, got %d at %d", controller.LockoutSecs, lockedUntil, now)
		}
		if err := store.RecordLoginSuccess(ctx, "alice"); err != nil {
			t.Fatalf("record login success: %v", err)
		}
		alice, err = store.GetLocalUser(ctx, "alice")
		if err != nil || alice == nil || alice.FailedLogins != 0 || alice.LockedUntil != nil {
			t.Fatalf("alice after success = %+v, err=%v", alice, err)
		}
		if err := store.RecordLoginFailure(ctx, "ghost"); err == nil {
			t.Fatal("expected an error recording a login failure for a missing user")
		}
	})

	apiTokenFixture := func(prefix, username string) core.ApiTokenRecord {
		return core.ApiTokenRecord{
			Prefix:    prefix,
			TokenHash: "$2b$hash-" + prefix,
			Username:  username,
			Label:     "ci",
			CreatedAt: 100,
			ExpiresAt: 200,
		}
	}

	t.Run("TokenCreateLookupPrefixCollision", func(t *testing.T) {
		// store.rs:881-924.
		if err := store.CreateApiToken(ctx, apiTokenFixture("aaaa1111", "alice")); err != nil {
			t.Fatalf("create token aaaa1111: %v", err)
		}
		if err := store.CreateApiToken(ctx, apiTokenFixture("bbbb2222", "alice")); err != nil {
			t.Fatalf("create token bbbb2222: %v", err)
		}
		if err := store.CreateApiToken(ctx, apiTokenFixture("cccc3333", "bob")); err != nil {
			t.Fatalf("create token cccc3333: %v", err)
		}
		if err := store.CreateApiToken(ctx, apiTokenFixture("aaaa1111", "alice")); err == nil {
			t.Fatal("expected an error on prefix collision")
		}

		got, err := store.GetApiTokenByPrefix(ctx, "aaaa1111")
		if err != nil || got == nil {
			t.Fatalf("get token: %v %v", got, err)
		}
		if got.TokenHash != "$2b$hash-aaaa1111" || got.Username != "alice" || got.ExpiresAt != 200 || got.Revoked || got.LastUsedAt != nil {
			t.Fatalf("token = %+v", got)
		}
		if got, err := store.GetApiTokenByPrefix(ctx, "zzzz9999"); err != nil || got != nil {
			t.Fatalf("get missing token: %v %v, want nil, nil", got, err)
		}
	})

	t.Run("TokenListOwnerScoped", func(t *testing.T) {
		// store.rs:926-930.
		aliceTokens, err := store.ListApiTokens(ctx, "alice")
		if err != nil || len(aliceTokens) != 2 {
			t.Fatalf("list alice tokens: len=%d err=%v, want 2, nil", len(aliceTokens), err)
		}
		for _, tok := range aliceTokens {
			if tok.Username != "alice" {
				t.Fatalf("token.Username = %q, want alice", tok.Username)
			}
		}
		if v, err := store.ListApiTokens(ctx, "ghost"); err != nil || len(v) != 0 {
			t.Fatalf("list ghost tokens: len=%d err=%v, want 0, nil", len(v), err)
		}
	})

	t.Run("TokenTouchStampsLastUsedAt", func(t *testing.T) {
		// store.rs:932-942.
		if err := store.TouchApiToken(ctx, "aaaa1111", 150); err != nil {
			t.Fatalf("touch token: %v", err)
		}
		got, err := store.GetApiTokenByPrefix(ctx, "aaaa1111")
		if err != nil || got == nil || got.LastUsedAt == nil || *got.LastUsedAt != 150 {
			t.Fatalf("LastUsedAt = %v, want 150 (err=%v)", got, err)
		}
	})

	t.Run("TokenRevokeOwnerScopedIdempotent", func(t *testing.T) {
		// store.rs:944-958.
		if err := store.RevokeApiToken(ctx, "bbbb2222", "bob"); err == nil {
			t.Fatal("expected an error: bob cannot revoke alice's token")
		}
		if err := store.RevokeApiToken(ctx, "zzzz9999", "bob"); err == nil {
			t.Fatal("expected an error revoking a nonexistent prefix")
		}
		if err := store.RevokeApiToken(ctx, "bbbb2222", "alice"); err != nil {
			t.Fatalf("revoke own token: %v", err)
		}
		got, err := store.GetApiTokenByPrefix(ctx, "bbbb2222")
		if err != nil || got == nil || !got.Revoked {
			t.Fatalf("token after revoke = %v, want Revoked=true (err=%v)", got, err)
		}
		// Idempotent re-revoke of one's own token.
		if err := store.RevokeApiToken(ctx, "bbbb2222", "alice"); err != nil {
			t.Fatalf("re-revoke own token: %v", err)
		}
	})
}

// --- Role assignments (store.rs:981-1049, `assignment_conformance`) ---

func runAssignmentConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	t.Run("EmptyByDefault", func(t *testing.T) {
		// store.rs:982-988.
		if v, err := store.ListRoleAssignments(ctx, nil); err != nil || len(v) != 0 {
			t.Fatalf("list all: len=%d err=%v, want 0, nil", len(v), err)
		}
		if v, err := store.ListRoleAssignments(ctx, strPtr("alice")); err != nil || len(v) != 0 {
			t.Fatalf("list alice: len=%d err=%v, want 0, nil", len(v), err)
		}
	})

	t.Run("UpsertAndPerPrincipalListOrdered", func(t *testing.T) {
		// store.rs:990-1011.
		if err := store.UpsertRoleAssignment(ctx, "alice", "operator", "project:ml-team"); err != nil {
			t.Fatalf("upsert alice/operator: %v", err)
		}
		if err := store.UpsertRoleAssignment(ctx, "alice", "viewer", "*"); err != nil {
			t.Fatalf("upsert alice/viewer: %v", err)
		}
		if err := store.UpsertRoleAssignment(ctx, "bob", "developer", "project:data"); err != nil {
			t.Fatalf("upsert bob/developer: %v", err)
		}

		alice, err := store.ListRoleAssignments(ctx, strPtr("alice"))
		if err != nil || len(alice) != 2 {
			t.Fatalf("list alice: len=%d err=%v, want 2, nil", len(alice), err)
		}
		if alice[0].Scope != "*" || alice[0].Role != "viewer" {
			t.Fatalf("alice[0] = %+v, want scope=* role=viewer", alice[0])
		}
		if alice[1].Scope != "project:ml-team" {
			t.Fatalf("alice[1].Scope = %q, want project:ml-team", alice[1].Scope)
		}
		for _, a := range alice {
			if a.Principal != "alice" {
				t.Fatalf("a.Principal = %q, want alice", a.Principal)
			}
			if a.CreatedAt == 0 {
				t.Fatal("a.CreatedAt = 0, want > 0")
			}
		}
	})

	t.Run("ReUpsertPreservesCreatedAt", func(t *testing.T) {
		// store.rs:1013-1022.
		before, err := store.ListRoleAssignments(ctx, strPtr("alice"))
		if err != nil || len(before) != 2 {
			t.Fatalf("list alice before: len=%d err=%v, want 2, nil", len(before), err)
		}
		first := before[1].CreatedAt
		if err := store.UpsertRoleAssignment(ctx, "alice", "operator", "project:ml-team"); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		after, err := store.ListRoleAssignments(ctx, strPtr("alice"))
		if err != nil || len(after) != 2 {
			t.Fatalf("list alice after: len=%d err=%v, want 2, nil", len(after), err)
		}
		if after[1].CreatedAt != first {
			t.Fatalf("CreatedAt = %d, want unchanged %d", after[1].CreatedAt, first)
		}
	})

	t.Run("UnfilteredListAllPrincipalsOrdered", func(t *testing.T) {
		// store.rs:1024-1028.
		all, err := store.ListRoleAssignments(ctx, nil)
		if err != nil || len(all) != 3 {
			t.Fatalf("list all: len=%d err=%v, want 3, nil", len(all), err)
		}
		if all[0].Principal != "alice" || all[2].Principal != "bob" {
			t.Fatalf("all[0].Principal=%q all[2].Principal=%q, want alice, bob", all[0].Principal, all[2].Principal)
		}
	})

	t.Run("DeleteRoundTripAndMissingErrors", func(t *testing.T) {
		// store.rs:1030-1048.
		if err := store.DeleteRoleAssignment(ctx, "alice", "viewer", "*"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		alice, err := store.ListRoleAssignments(ctx, strPtr("alice"))
		if err != nil || len(alice) != 1 {
			t.Fatalf("list alice after delete: len=%d err=%v, want 1, nil", len(alice), err)
		}
		err = store.DeleteRoleAssignment(ctx, "alice", "viewer", "*")
		if err == nil {
			t.Fatal("expected an error deleting an already-deleted assignment")
		}
		if !strings.Contains(err.Error(), "no such assignment alice/viewer/*") {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), "no such assignment alice/viewer/*")
		}
	})
}

// --- Policy (store.rs:1062-1121, `policy_conformance` + `policy_seed_conformance`) ---

func policyFixture(cpuPrice float64, seed bool) *controller.StoredPolicy {
	return &controller.StoredPolicy{
		Prices: map[string]float64{"cpu": cpuPrice},
		Quotas: map[string]map[string]float64{"ml-team": {"cpu": 500.0}},
		// #77: budgets ride the same JSON policy row.
		Budgets: map[string]controller.StoredBudget{
			"ml-team": {WindowSecs: 604_800, Limits: map[string]float64{"nvidia.com/gpu": 100.0}},
		},
		FromFileSeed: seed,
		// #7/#12 (plan ruling D7): the profile, admission and storage
		// catalogs ride the same row. Non-nil so a SQL round trip
		// (nil -> `[]`/`{}` -> empty non-nil) stays DeepEqual.
		Profiles: []core.Profile{{
			Name: "small", Description: strPtr("one cpu worker"), Image: "rayproject/ray:2.57.0", RayVersion: "2.57.0",
			HeadCpu: "1", HeadMemory: "2Gi",
			WorkerGroups: []core.WorkerGroup{{Name: "cpu", Cpu: "1", Memory: "2Gi", MinReplicas: 0, MaxReplicas: 2, Replicas: 1}},
			MaxWorkers:   u32Ptr(2), TtlSeconds: u64Ptr(3600), Projects: []string{"ml-team"}, Storage: []string{},
		}},
		Admission: map[string]core.AdmissionRule{
			"*":       {AllowedImages: []string{"rayproject/ray:2.57.0"}, MaxWorkers: 8},
			"ml-team": {AllowedImages: []string{}, MaxWorkers: 4},
		},
		Storage: []core.StorageEntry{
			{Name: "s3-creds", SecretName: "ml-team-s3", Mode: core.StorageModeEnv, Projects: []string{"ml-team"}},
			{Name: "data", SecretName: "shared-data", Mode: core.StorageModeFile, MountPath: strPtr("/mnt/data"), Projects: []string{}},
			{Name: "analytics", Source: core.StorageSourcePersistentVolumeClaim, ClaimName: "analytics-pvc", Mode: core.StorageModeFile, MountPath: strPtr("/app/data"), Projects: []string{"ml-team"}},
			{Name: "scratch", Source: core.StorageSourcePersistentVolumeClaim, ClaimName: "scratch-pvc", Mode: core.StorageModeFile, MountPath: strPtr("/srv/scratch"), Projects: []string{}},
		},
		// #52: the environment catalog rides the same row. Non-nil so the
		// SQL round trip (nil -> `[]` -> empty non-nil) stays DeepEqual.
		Environments: []core.Environment{{
			Name: "ml-base", Description: strPtr("governed ml base"), BaseImage: "rayproject/ray:2.57.0",
			Packages: []string{"numpy==1.26.4"}, EnvVars: map[string]string{"OMP_NUM_THREADS": "4"},
			Projects: []string{"ml-team"}, Status: core.EnvironmentStatusPublished,
			PublishedBy: strPtr("root"), PublishedAt: &policyFixturePublishedAt,
			Scan: &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0"), ScannedAt: &policyFixturePublishedAt},
		}},
		// #10: the image catalog rides the row too.
		Images: []core.ImageEntry{
			{Name: "ray-2.57", Description: strPtr("upstream"), Ref: "rayproject/ray:2.57.0", Digest: "", RayVersion: "2.57.0", PythonVersion: "3.11", Projects: []string{}},
			{Name: "team-ray", Ref: "registry.example/ml/ray:2.57.0-team", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Engine: core.EngineRay, RayVersion: "2.57.0", PythonVersion: "", Projects: []string{"ml-team"}},
		},
	}
}

// policyFixturePublishedAt is the fixture environment's publication time,
// UTC so the JSON round trip (RFC 3339, no monotonic clock) stays
// DeepEqual.
var policyFixturePublishedAt = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

func runPolicyConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	t.Run("UnsetReadsAsNone", func(t *testing.T) {
		// store.rs:1085-1086.
		if got, err := store.GetPolicy(ctx); err != nil || got != nil {
			t.Fatalf("get policy: %v %v, want nil, nil", got, err)
		}
	})

	t.Run("SetGetRoundTrip", func(t *testing.T) {
		// store.rs:1088-1090.
		if err := store.SetPolicy(ctx, policyFixture(0.048, true)); err != nil {
			t.Fatalf("set policy: %v", err)
		}
		got, err := store.GetPolicy(ctx)
		if err != nil || got == nil || !reflect.DeepEqual(got, policyFixture(0.048, true)) {
			t.Fatalf("get policy = %+v, want %+v (err=%v)", got, policyFixture(0.048, true), err)
		}
	})

	t.Run("OverwriteReplacesRow", func(t *testing.T) {
		// store.rs:1092-1094.
		if err := store.SetPolicy(ctx, policyFixture(0.05, false)); err != nil {
			t.Fatalf("set policy: %v", err)
		}
		got, err := store.GetPolicy(ctx)
		if err != nil || got == nil || !reflect.DeepEqual(got, policyFixture(0.05, false)) {
			t.Fatalf("get policy = %+v, want %+v (err=%v)", got, policyFixture(0.05, false), err)
		}
	})

	t.Run("SeedNeverClobbersExisting", func(t *testing.T) {
		// store.rs:1096-1099.
		inserted, err := store.SeedPolicy(ctx, policyFixture(9.9, true))
		if err != nil || inserted {
			t.Fatalf("seed over existing: inserted=%v err=%v, want false, nil", inserted, err)
		}
		got, err := store.GetPolicy(ctx)
		if err != nil || got == nil || !reflect.DeepEqual(got, policyFixture(0.05, false)) {
			t.Fatalf("get policy after no-op seed = %+v, want %+v (err=%v)", got, policyFixture(0.05, false), err)
		}
	})
}

func runPolicySeedConformance(t *testing.T, store controller.Store) {
	// store.rs:1104-1121: seed_policy on an EMPTY store inserts and
	// reports the insertion; a second seed is a no-op.
	ctx := context.Background()
	seed := &controller.StoredPolicy{
		Quotas:       map[string]map[string]float64{"demo": {"cpu": 5.0}},
		Budgets:      map[string]controller.StoredBudget{},
		FromFileSeed: true,
		// Empty non-nil for the same reason as Budgets: the SQL stores read
		// `[]`/`{}` back as empty non-nil.
		Profiles:     []core.Profile{},
		Admission:    map[string]core.AdmissionRule{},
		Storage:      []core.StorageEntry{},
		Environments: []core.Environment{},
		Images:       []core.ImageEntry{},
	}

	inserted, err := store.SeedPolicy(ctx, seed)
	if err != nil || !inserted {
		t.Fatalf("seed on empty store: inserted=%v err=%v, want true, nil", inserted, err)
	}
	got, err := store.GetPolicy(ctx)
	if err != nil || got == nil || !reflect.DeepEqual(got, seed) {
		t.Fatalf("get policy = %+v, want %+v (err=%v)", got, seed, err)
	}

	inserted, err = store.SeedPolicy(ctx, seed)
	if err != nil || inserted {
		t.Fatalf("second seed: inserted=%v err=%v, want false, nil", inserted, err)
	}
	got, err = store.GetPolicy(ctx)
	if err != nil || got == nil || !reflect.DeepEqual(got, seed) {
		t.Fatalf("get policy after second seed = %+v, want %+v (err=%v)", got, seed, err)
	}
}

// --- Additions: not ported from store.rs (see the package doc comment
// and RunConformance's "Additions" section) ---

func runMutationIsolationConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	t.Run("MutateAfterUpsertDoesNotAffectStore", func(t *testing.T) {
		id := core.ClusterId("mut-upsert")
		spec := clusterSpecFixture("mut-upsert", 1)
		gpu := "1"
		ttl := uint64(100)
		spec.WorkerGroups[0].Gpu = &gpu
		spec.TtlSeconds = &ttl
		if _, err := store.UpsertDesired(ctx, id, spec); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		// Mutate the caller's own spec (and its pointee memory) after the
		// call returns.
		spec.WorkerGroups[0].Name = "mutated-by-caller"
		gpu = "mutated-gpu"
		ttl = 999

		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Spec.WorkerGroups[0].Name != "cpu" {
			t.Fatalf("WorkerGroups[0].Name = %q, want unaffected \"cpu\"", got.Spec.WorkerGroups[0].Name)
		}
		if got.Spec.WorkerGroups[0].Gpu == nil || *got.Spec.WorkerGroups[0].Gpu != "1" {
			t.Fatalf("Gpu = %v, want unaffected \"1\"", got.Spec.WorkerGroups[0].Gpu)
		}
		if got.Spec.TtlSeconds == nil || *got.Spec.TtlSeconds != 100 {
			t.Fatalf("TtlSeconds = %v, want unaffected 100", got.Spec.TtlSeconds)
		}
	})

	t.Run("MutateAfterGetDoesNotAffectStore", func(t *testing.T) {
		id := core.ClusterId("mut-get")
		spec := clusterSpecFixture("mut-get", 1)
		gpu := "1"
		spec.WorkerGroups[0].Gpu = &gpu
		if _, err := store.UpsertDesired(ctx, id, spec); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		got, err := store.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Spec.WorkerGroups[0].Gpu == nil {
			t.Fatal("expected Gpu to be set")
		}
		got.Spec.WorkerGroups[0].Name = "mutated"
		*got.Spec.WorkerGroups[0].Gpu = "mutated-gpu"

		got2, err := store.Get(ctx, id)
		if err != nil || got2 == nil {
			t.Fatalf("get2: %v %v", got2, err)
		}
		if got2.Spec.WorkerGroups[0].Name != "cpu" {
			t.Fatalf("WorkerGroups[0].Name = %q, want unaffected \"cpu\"", got2.Spec.WorkerGroups[0].Name)
		}
		if got2.Spec.WorkerGroups[0].Gpu == nil || *got2.Spec.WorkerGroups[0].Gpu != "1" {
			t.Fatalf("Gpu = %v, want unaffected \"1\"", got2.Spec.WorkerGroups[0].Gpu)
		}
	})

	t.Run("MutateEventAfterRecordAuditChainStaysClean", func(t *testing.T) {
		subject := "alice"
		event := &core.AuditEvent{
			Ts: 100, Decision: core.AuditDecisionAllow, Subject: &subject, GrantedRoles: []string{"viewer"},
		}
		if _, err := store.RecordAudit(ctx, event); err != nil {
			t.Fatalf("record audit: %v", err)
		}

		// Mutate the caller's event (and its backing memory) after the
		// call returns.
		subject = "mallory"
		event.GrantedRoles[0] = "admin"
		event.Ts = 999

		window, err := store.AuditChain(ctx, nil, 100)
		if err != nil {
			t.Fatalf("audit chain: %v", err)
		}
		// The sharpest consequence of the aliasing bug this contract
		// guards against: a spurious tamper report caused purely by the
		// caller mutating its own event after the call, never a real
		// tamper of the stored chain.
		v := controller.VerifyAuditChain(window.Head, window.Rows)
		if !v.OK() {
			t.Fatalf("expected chain to verify after caller-side mutation, first broken seq = %v", v.FirstBrokenSeq)
		}
	})
}

func runNonNilEmptyConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()

	if v, err := store.List(ctx); err != nil || v == nil {
		t.Fatalf("List: %v %v", v, err)
	}
	if v, err := store.ListJobs(ctx); err != nil || v == nil {
		t.Fatalf("ListJobs: %v %v", v, err)
	}
	if v, err := store.ListServices(ctx); err != nil || v == nil {
		t.Fatalf("ListServices: %v %v", v, err)
	}
	if v, err := store.ListRayJobs(ctx); err != nil || v == nil {
		t.Fatalf("ListRayJobs: %v %v", v, err)
	}
	if v, err := store.ListPools(ctx); err != nil || v == nil {
		t.Fatalf("ListPools: %v %v", v, err)
	}
	if v, err := store.ListAllocations(ctx, "pool"); err != nil || v == nil {
		t.Fatalf("ListAllocations: %v %v", v, err)
	}
	if v, err := store.UsageSamples(ctx, nil, nil, nil, 0, ^uint64(0)); err != nil || v == nil {
		t.Fatalf("UsageSamples: %v %v", v, err)
	}
	if rows, next, err := store.ListAudit(ctx, core.AuditFilter{}); err != nil || rows == nil || next != nil {
		t.Fatalf("ListAudit: rows=%v next=%v err=%v", rows, next, err)
	}
	if window, err := store.AuditChain(ctx, nil, 10); err != nil || window.Rows == nil {
		t.Fatalf("AuditChain.Rows: %v %v", window.Rows, err)
	}
	if v, err := store.ListLocalUsers(ctx); err != nil || v == nil {
		t.Fatalf("ListLocalUsers: %v %v", v, err)
	}
	if v, err := store.ListApiTokens(ctx, "someone"); err != nil || v == nil {
		t.Fatalf("ListApiTokens: %v %v", v, err)
	}
	if v, err := store.ListRoleAssignments(ctx, nil); err != nil || v == nil {
		t.Fatalf("ListRoleAssignments: %v %v", v, err)
	}
}

func runSetDesiredValidationConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()
	id := core.ClusterId("c1")
	if _, err := store.UpsertDesired(ctx, id, clusterSpecFixture("c1", 1)); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := store.SetDesired(ctx, id, controller.DesiredState("bogus")); err == nil {
		t.Fatal("expected an error for an invalid DesiredState value")
	}

	got, err := store.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Desired != controller.DesiredRunning {
		t.Fatalf("Desired = %v, want unaffected DesiredRunning", got.Desired)
	}
}

// --- Services (requirements 1/2; not in store.rs — services had no row
// there) ---

func serviceSpecFixture(name string, replicas uint32) core.ServiceSpec {
	return core.ServiceSpec{
		Name: name, Project: "demo", RayVersion: "2.57.0", Image: "rayproject/ray:2.57.0",
		ServeConfigV2: "applications: []", HeadCpu: "1", HeadMemory: "2Gi",
		WorkerReplicas: replicas, WorkerCpu: "1", WorkerMemory: "2Gi",
		Upgrade: core.DefaultUpgradeStrategy,
	}
}

func runServiceConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()
	name := "svc"

	t.Run("UpsertGenerationTrackingAndOwnerStampedOnCreate", func(t *testing.T) {
		if gen, err := store.UpsertService(ctx, name, serviceSpecFixture(name, 1), strPtr("alice")); err != nil || gen != 1 {
			t.Fatalf("first upsert: gen=%d err=%v, want 1, nil", gen, err)
		}
		if gen, err := store.UpsertService(ctx, name, serviceSpecFixture(name, 1), strPtr("bob")); err != nil || gen != 1 {
			t.Fatalf("unchanged upsert: gen=%d err=%v, want 1, nil", gen, err)
		}
		if gen, err := store.UpsertService(ctx, name, serviceSpecFixture(name, 3), strPtr("bob")); err != nil || gen != 2 {
			t.Fatalf("changed upsert: gen=%d err=%v, want 2, nil", gen, err)
		}
		got, err := store.GetService(ctx, name)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.Name != name || got.Generation != 2 || got.Desired != controller.DesiredRunning || got.Spec.WorkerReplicas != 3 {
			t.Fatalf("stored service = %+v", got)
		}
		if got.Owner == nil || *got.Owner != "alice" {
			t.Fatalf("Owner = %v, want alice (stamped on create, kept on update)", got.Owner)
		}
		if got.ObservedState != nil || got.ObservedURL != nil || got.TerminatedAt != nil || got.CreatedAt == 0 {
			t.Fatalf("fresh service observation/timestamps wrong: %+v", got)
		}
	})

	t.Run("StorageChangeBumpsGeneration", func(t *testing.T) {
		spec := serviceSpecFixture(name, 3)
		spec.Storage = []string{"s3-creds"}
		if gen, err := store.UpsertService(ctx, name, spec, nil); err != nil || gen != 3 {
			t.Fatalf("storage upsert: gen=%d err=%v, want 3, nil", gen, err)
		}
		got, _ := store.GetService(ctx, name)
		if got == nil || len(got.Spec.Storage) != 1 || got.Spec.Storage[0] != "s3-creds" {
			t.Fatalf("storage did not persist: %+v", got)
		}
	})

	t.Run("ObservationRoundTrip", func(t *testing.T) {
		if err := store.RecordServiceObservation(ctx, name, clusterStatePtr(core.ClusterStateRunning), strPtr("http://svc-serve-svc:8000")); err != nil {
			t.Fatalf("record observation: %v", err)
		}
		got, _ := store.GetService(ctx, name)
		if got == nil || got.ObservedState == nil || *got.ObservedState != core.ClusterStateRunning ||
			got.ObservedURL == nil || *got.ObservedURL != "http://svc-serve-svc:8000" {
			t.Fatalf("observation = %+v", got)
		}
		if err := store.RecordServiceObservation(ctx, name, nil, nil); err != nil {
			t.Fatalf("clear observation: %v", err)
		}
		got, _ = store.GetService(ctx, name)
		if got == nil || got.ObservedState != nil || got.ObservedURL != nil {
			t.Fatalf("observation not cleared: %+v", got)
		}
		if err := store.RecordServiceObservation(ctx, "ghost", clusterStatePtr(core.ClusterStateRunning), nil); err != nil {
			t.Fatalf("observation of unknown service must be a no-op, got %v", err)
		}
	})

	t.Run("ListOrderedByName", func(t *testing.T) {
		if _, err := store.UpsertService(ctx, "alpha", serviceSpecFixture("alpha", 1), nil); err != nil {
			t.Fatal(err)
		}
		all, err := store.ListServices(ctx)
		if err != nil || len(all) != 2 || all[0].Name != "alpha" || all[1].Name != name {
			t.Fatalf("list = %+v err=%v", all, err)
		}
	})

	t.Run("SetDesiredStampsTerminatedAtAndRejectsUnknown", func(t *testing.T) {
		if err := store.SetServiceDesired(ctx, name, controller.DesiredTerminated); err != nil {
			t.Fatalf("set desired: %v", err)
		}
		got, _ := store.GetService(ctx, name)
		if got == nil || got.Desired != controller.DesiredTerminated || got.TerminatedAt == nil {
			t.Fatalf("terminated service = %+v", got)
		}
		if err := store.SetServiceDesired(ctx, name, controller.DesiredRunning); err != nil {
			t.Fatalf("set desired running: %v", err)
		}
		if got, _ = store.GetService(ctx, name); got == nil || got.TerminatedAt != nil {
			t.Fatalf("TerminatedAt must clear when leaving terminated: %+v", got)
		}
		err := store.SetServiceDesired(ctx, "ghost", controller.DesiredTerminated)
		if err == nil || !strings.Contains(err.Error(), "no such service ghost") {
			t.Fatalf("unknown service: %v", err)
		}
		if err := store.SetServiceDesired(ctx, name, controller.DesiredState("bogus")); err == nil {
			t.Fatal("invalid desired state must be rejected")
		}
	})

	t.Run("UpsertOntoTerminatedRecordIsAFreshCreate", func(t *testing.T) {
		if err := store.SetServiceDesired(ctx, name, controller.DesiredTerminated); err != nil {
			t.Fatal(err)
		}
		_ = store.RecordServiceObservation(ctx, name, clusterStatePtr(core.ClusterStateTerminating), nil)
		before, _ := store.GetService(ctx, name)
		gen, err := store.UpsertService(ctx, name, serviceSpecFixture(name, 3), strPtr("carol"))
		if err != nil || gen != before.Generation+1 {
			t.Fatalf("revive: gen=%d err=%v, want %d", gen, err, before.Generation+1)
		}
		got, _ := store.GetService(ctx, name)
		if got == nil || got.Desired != controller.DesiredRunning || got.TerminatedAt != nil ||
			got.ObservedState != nil || got.Owner == nil || *got.Owner != "carol" {
			t.Fatalf("revived service is not fresh: %+v", got)
		}
	})

	t.Run("RemoveReportsWhetherARowExisted", func(t *testing.T) {
		if removed, err := store.RemoveService(ctx, name); err != nil || !removed {
			t.Fatalf("remove: removed=%v err=%v", removed, err)
		}
		if removed, err := store.RemoveService(ctx, name); err != nil || removed {
			t.Fatalf("second remove: removed=%v err=%v, want false", removed, err)
		}
		if got, err := store.GetService(ctx, name); err != nil || got != nil {
			t.Fatalf("get after remove: %v %v, want nil, nil", got, err)
		}
	})
}

// --- Ephemeral Ray jobs (requirement 5; not in store.rs) ---

func rayJobSpecFixture(project string) core.RayJobSpec {
	ttl := uint32(30)
	return core.RayJobSpec{
		Project: project, Entrypoint: "python -c 1", Image: "rayproject/ray:2.57.0", RayVersion: "2.57.0",
		HeadCpu: "1", HeadMemory: "2Gi",
		WorkerGroups:            []core.WorkerGroup{{Name: "cpu", Cpu: "1", Memory: "2Gi", MaxReplicas: 1, Replicas: 1}},
		Storage:                 []string{"s3-creds"},
		TtlSecondsAfterFinished: &ttl,
	}
}

func runRayJobConformance(t *testing.T, store controller.Store) {
	ctx := context.Background()
	id := core.ClusterId("job-1")

	t.Run("UpsertCreatesRunningRowWithSubmittedAt", func(t *testing.T) {
		if err := store.UpsertRayJob(ctx, id, rayJobSpecFixture("team-a"), strPtr("alice")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		got, err := store.GetRayJob(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.ID != id || got.Desired != controller.DesiredRunning || got.SubmittedAt == 0 ||
			got.Status != "" || got.DeploymentStatus != "" || got.ClusterName != nil || got.StartedAt != nil {
			t.Fatalf("fresh job = %+v", got)
		}
		if got.Owner == nil || *got.Owner != "alice" || got.Spec.Project != "team-a" ||
			got.Spec.TtlSecondsAfterFinishedOrDefault() != 30 || len(got.Spec.Storage) != 1 {
			t.Fatalf("spec/owner did not round-trip: %+v", got)
		}
	})

	t.Run("ReUpsertReplacesSpecAndOwnerOnly", func(t *testing.T) {
		before, _ := store.GetRayJob(ctx, id)
		if err := store.UpsertRayJob(ctx, id, rayJobSpecFixture("team-b"), strPtr("bob")); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		got, _ := store.GetRayJob(ctx, id)
		if got == nil || got.Spec.Project != "team-b" || got.Owner == nil || *got.Owner != "bob" {
			t.Fatalf("re-upsert did not replace spec/owner: %+v", got)
		}
		if got.SubmittedAt != before.SubmittedAt || got.Desired != before.Desired {
			t.Fatalf("re-upsert must keep submitted_at/desired: before=%+v after=%+v", before, got)
		}
	})

	t.Run("ObservationOverwritesEveryField", func(t *testing.T) {
		obs := controller.RayJobObservation{
			Status: "RUNNING", DeploymentStatus: "Running",
			ClusterName: strPtr("job-1-raycluster-abcde"), DashboardURL: strPtr("http://job-1-head-svc:8265"),
			Message: strPtr("submitted"), StartedAt: u64Ptr(1000),
		}
		if err := store.RecordRayJobObservation(ctx, id, obs); err != nil {
			t.Fatalf("record observation: %v", err)
		}
		got, _ := store.GetRayJob(ctx, id)
		if got == nil || got.Status != "RUNNING" || got.DeploymentStatus != "Running" ||
			got.ClusterName == nil || *got.ClusterName != "job-1-raycluster-abcde" ||
			got.DashboardURL == nil || *got.DashboardURL != "http://job-1-head-svc:8265" ||
			got.Message == nil || *got.Message != "submitted" ||
			got.StartedAt == nil || *got.StartedAt != 1000 || got.FinishedAt != nil {
			t.Fatalf("observation = %+v", got)
		}
		done := controller.RayJobObservation{Status: "SUCCEEDED", DeploymentStatus: "Complete", StartedAt: u64Ptr(1000), FinishedAt: u64Ptr(1200)}
		if err := store.RecordRayJobObservation(ctx, id, done); err != nil {
			t.Fatal(err)
		}
		got, _ = store.GetRayJob(ctx, id)
		if got == nil || got.Status != "SUCCEEDED" || got.ClusterName != nil || got.Message != nil ||
			got.FinishedAt == nil || *got.FinishedAt != 1200 {
			t.Fatalf("terminal observation must overwrite (nil clears): %+v", got)
		}
		if err := store.RecordRayJobObservation(ctx, "ghost", done); err != nil {
			t.Fatalf("observation of unknown job must be a no-op, got %v", err)
		}
	})

	t.Run("AttemptBackoffRoundTrip", func(t *testing.T) {
		if err := store.RecordRayJobAttempt(ctx, id, 3, 4242); err != nil {
			t.Fatalf("record attempt: %v", err)
		}
		got, _ := store.GetRayJob(ctx, id)
		if got == nil || got.FailureCount != 3 || got.NextAttemptAt != 4242 {
			t.Fatalf("backoff = %+v", got)
		}
		if err := store.RecordRayJobAttempt(ctx, id, 0, 0); err != nil {
			t.Fatal(err)
		}
		if got, _ = store.GetRayJob(ctx, id); got == nil || got.FailureCount != 0 || got.NextAttemptAt != 0 {
			t.Fatalf("backoff not cleared: %+v", got)
		}
		if err := store.RecordRayJobAttempt(ctx, "ghost", 1, 1); err != nil {
			t.Fatalf("attempt on unknown job must be a no-op, got %v", err)
		}
	})

	t.Run("ListMostRecentFirstTiesById", func(t *testing.T) {
		// Every upsert in one test run lands in the same second, so the
		// id tiebreak is what makes the order observable here.
		for _, other := range []core.ClusterId{"job-0", "job-2"} {
			if err := store.UpsertRayJob(ctx, other, rayJobSpecFixture("team-a"), nil); err != nil {
				t.Fatal(err)
			}
		}
		all, err := store.ListRayJobs(ctx)
		if err != nil || len(all) != 3 {
			t.Fatalf("list: len=%d err=%v", len(all), err)
		}
		for i := 1; i < len(all); i++ {
			a, b := all[i-1], all[i]
			if a.SubmittedAt < b.SubmittedAt || (a.SubmittedAt == b.SubmittedAt && a.ID > b.ID) {
				t.Fatalf("list order violated at %d: %s(%d) before %s(%d)", i, a.ID, a.SubmittedAt, b.ID, b.SubmittedAt)
			}
		}
		// The upserts above may straddle a second boundary, so job-2 is
		// not necessarily last; find it by id rather than by position.
		for _, j := range all {
			if j.ID == "job-2" && j.Owner != nil {
				t.Fatalf("nil owner must round-trip as nil: %+v", j)
			}
		}
	})

	t.Run("SetDesiredAndRejectUnknown", func(t *testing.T) {
		if err := store.SetRayJobDesired(ctx, id, controller.DesiredTerminated); err != nil {
			t.Fatalf("set desired: %v", err)
		}
		if got, _ := store.GetRayJob(ctx, id); got == nil || got.Desired != controller.DesiredTerminated {
			t.Fatalf("desired = %+v", got)
		}
		err := store.SetRayJobDesired(ctx, "ghost", controller.DesiredTerminated)
		if err == nil || !strings.Contains(err.Error(), "no such job ghost") {
			t.Fatalf("unknown job: %v", err)
		}
		if err := store.SetRayJobDesired(ctx, id, controller.DesiredState("bogus")); err == nil {
			t.Fatal("invalid desired state must be rejected")
		}
	})

	t.Run("RemoveReportsWhetherARowExisted", func(t *testing.T) {
		if removed, err := store.RemoveRayJob(ctx, id); err != nil || !removed {
			t.Fatalf("remove: removed=%v err=%v", removed, err)
		}
		if removed, err := store.RemoveRayJob(ctx, id); err != nil || removed {
			t.Fatalf("second remove: removed=%v err=%v, want false", removed, err)
		}
		if got, err := store.GetRayJob(ctx, id); err != nil || got != nil {
			t.Fatalf("get after remove: %v %v, want nil, nil", got, err)
		}
	})
}
