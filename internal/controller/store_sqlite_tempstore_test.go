package controller_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/controller"
)

// The usage-samples read sorts the whole window; past a few tens of
// thousands of rows SQLite spills the sort to its temp store. The chart
// runs the container with a read-only root filesystem and no writable
// /tmp, so a file-backed temp store failed every such read with
// SQLITE_IOERR_SHORT_READ (6410) on grace. The DSN keeps the temp store
// in memory.
//
// Honest scope: this cannot reproduce the container's failure on a
// developer machine. SQLite's unix VFS falls back from SQLITE_TMPDIR and
// TMPDIR to /var/tmp, /usr/tmp, /tmp and the working directory, and at
// least one of those is always writable outside a locked-down container,
// so the pre-fix DSN passes here too. What this test pins is that a
// large, spilling sort completes with the in-memory temp store under the
// most hostile temp configuration a process can set for itself; the
// deployment-shaped proof is the live cluster (the WARN lines stop).
// TestSqliteTempStoreIsInMemoryOnEveryConnection is the guard on the
// setting itself.
func TestSqliteLargeUsageSortCompletesWithUnwritableTempEnv(t *testing.T) {
	ctx := context.Background()
	unwritable := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatal(err)
	}
	if f, err := os.CreateTemp(unwritable, "probe"); err == nil {
		_ = f.Close()
		t.Skip("temp dir is writable regardless of mode (running as root?); the deployment condition cannot be reproduced here")
	}
	// SQLite's unix VFS picks its temp directory from these, in order.
	t.Setenv("SQLITE_TMPDIR", unwritable)
	t.Setenv("TMPDIR", unwritable)

	store := newTestSqliteStore(t, filepath.Join(t.TempDir(), "usage.db"))
	// Enough rows to outgrow the default page cache: grace failed at ~31k.
	const n = 80_000
	batch := make([]controller.UsageSample, 0, 5_000)
	for i := 0; i < n; i++ {
		batch = append(batch, controller.UsageSample{
			Ts: uint64(1_700_000_000 + i), Project: "team-a", Pool: "compute", Resource: "cpu",
			Quantity: float64(i % 7), Source: controller.UsageSourceObservedSpec, Owner: "alice",
		})
		if len(batch) == cap(batch) {
			if err := store.RecordUsageSamples(ctx, batch); err != nil {
				t.Fatalf("record: %v", err)
			}
			batch = batch[:0]
		}
	}
	got, err := store.UsageSamples(ctx, nil, nil, nil, 0, ^uint64(0)>>1)
	if err != nil {
		t.Fatalf("usage read with an unwritable temp dir: %v", err)
	}
	if len(got) != n {
		t.Fatalf("rows = %d, want %d", len(got), n)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Ts < got[i-1].Ts {
			t.Fatalf("rows not ordered by ts at %d", i)
		}
	}
}

// The DSN is where the guarantee lives (database/sql opens many
// connections; a PRAGMA executed on one would not reach the others), and
// a pooled connection reports the setting back as MEMORY (2).
func TestSqliteTempStoreIsInMemoryOnEveryConnection(t *testing.T) {
	if !strings.Contains(controller.SqliteDSNForTest("/x/y.db"), "_pragma=temp_store(2)") {
		t.Fatalf("DSN = %s, want temp_store(2)", controller.SqliteDSNForTest("/x/y.db"))
	}
	store := newTestSqliteStore(t, filepath.Join(t.TempDir(), "ts.db"))
	for i := 0; i < 3; i++ {
		v, err := store.TempStoreForTest(context.Background())
		if err != nil || v != 2 {
			t.Fatalf("PRAGMA temp_store on connection %d = %d, %v; want 2 (MEMORY)", i, v, err)
		}
	}
}
