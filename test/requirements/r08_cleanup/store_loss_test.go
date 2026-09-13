// Requirement 8 — the store-loss drill. The restart tests in this package
// kill the control-plane pod but keep its SQLite store on the PVC; this
// drill takes the store itself away (scale-to-zero, delete and re-create
// the data PVC — see k8sHandle.destroyStore for why the volume, not an
// in-pod rm) while a cluster is running, then watches what the design
// actually does with an EMPTY store:
//
//   - DetectStaleRestore (internal/controller/reconcile.go) only fires when
//     a store row exists whose generation lags the backing cluster's. An
//     empty store has no rows, so no quarantine: the control plane comes up
//     healthy and actuates new work normally. That is what the code
//     promises for this failure shape, and this test pins it.
//   - The pre-wipe cluster's record is gone with the store, and nothing
//     re-adopts the backing RayCluster: every reconcile pass iterates
//     store.List, so a cluster the store forgot is never observed, never
//     reaped, never alarmed on. It becomes an unmanaged orphan. That
//     recovery gap is pinned with req.NotYetBuilt — when adoption (or an
//     empty-store quarantine) is built, the body starts passing and the
//     marker comes out in the same PR.
package r08_cleanup

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

func TestStoreLossWhileClusterExists(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 8, "store-loss drill: the control plane's database is destroyed while a cluster runs; the record is lost, the backing cluster is orphaned, and the control plane itself is not wedged")
	req.NeedK8s(t, tgt)
	req.NeedsCapability(t, tgt, "store-loss")
	d, ok := tgt.(req.StoreDestroyer)
	if !ok {
		t.Fatalf("target %s declares capability store-loss but is not a req.StoreDestroyer", tgt.Name())
	}
	ctx := context.Background()
	k, _ := tgt.K8s()
	key := func(id string) ctrlclient.ObjectKey {
		return ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: id}
	}

	id := req.Name("sl")
	fixture.MustCreate(t, tgt, "dev-a", id, "team-a")
	fixture.WaitObserved(t, tgt, "dev-a", id, "running")
	var before rayv1.RayCluster
	if err := k.Get(ctx, key(id), &before); err != nil {
		t.Fatal(err)
	}
	// However the drill ends, the backing RayCluster is this run's to
	// remove: after the wipe the store has no record of it, so the target's
	// own cleanup — which deletes through the API — cannot reach it. The
	// per-cluster NetworkPolicies need the same treatment: they are reaped
	// by the control plane's tombstone sweep, which the wiped store will
	// never run for this cluster, and postflight's leak check flags them.
	t.Cleanup(func() {
		var cur rayv1.RayCluster
		if err := k.Get(ctx, key(id), &cur); err == nil {
			_ = k.Delete(ctx, &cur)
		}
		// Label string kept in sync with provision.ClusterIDLabel by hand —
		// requirement packages must not import internal/.
		byCluster := ctrlclient.MatchingLabels{"bifrost.dev/cluster-id": id}
		var nps networkingv1.NetworkPolicyList
		if err := k.List(ctx, &nps, ctrlclient.InNamespace(tgt.Namespace()), byCluster); err == nil {
			for i := range nps.Items {
				_ = k.Delete(ctx, &nps.Items[i])
			}
			_ = wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
				var left networkingv1.NetworkPolicyList
				if err := k.List(ctx, &left, ctrlclient.InNamespace(tgt.Namespace()), byCluster); err != nil {
					return false, err
				}
				return len(left.Items) == 0, nil
			})
		}
	})

	if err := d.DestroyStore(ctx); err != nil {
		t.Fatalf("destroy store: %v", err)
	}

	// The record is gone with the store. DestroyStore waited for /healthz
	// and re-seeded the suite's principals, so this GET also proves the API
	// serves and authenticates again on the empty store.
	if st, _ := fixture.Get(t, tgt, "admin", id); st != http.StatusNotFound {
		t.Fatalf("get pre-wipe cluster after store loss = %d, want 404 (its record was in the store, nowhere else)", st)
	}

	// The backing RayCluster is untouched: same object, still present. No
	// reaper noticed it — nothing in the reconciler walks backing clusters
	// the store has forgotten.
	var after rayv1.RayCluster
	if err := k.Get(ctx, key(id), &after); err != nil {
		t.Fatalf("the backing RayCluster disappeared with the store — the store is not supposed to be its lifeline: %v", err)
	}
	if after.UID != before.UID {
		t.Fatalf("backing RayCluster was replaced (uid %s -> %s): an empty store must not stomp what it forgot", before.UID, after.UID)
	}

	// Audit chain after the drill: the pre-wipe history died with the
	// store (there is no backup in this deployment). The chain the control
	// plane starts fresh must at least be internally consistent — verify
	// must not report a break.
	ver, err := tgt.As("admin").API().VerifyAuditTrailWithResponse(ctx, nil)
	if err != nil || ver.StatusCode() != http.StatusOK {
		t.Fatalf("audit verify after store loss: err=%v status=%v", err, ver.StatusCode())
	}
	var res struct {
		Ok            bool  `json:"ok"`
		EventsChecked int64 `json:"events_checked"`
	}
	_ = json.Unmarshal(ver.Body, &res)
	if !res.Ok {
		t.Errorf("audit chain broken after store loss: %s", ver.Body)
	}
	t.Logf("audit chain after store loss: ok=%v events_checked=%d (pre-wipe history is unrecoverable — it lived only in the store)", res.Ok, res.EventsChecked)

	// The design's promise for an EMPTY store: DetectStaleRestore has no
	// row to compare, so no quarantine — the control plane keeps actuating.
	// A quarantined control plane observes only; a cluster created now
	// would sit unprovisioned for the whole lane budget. Converging to
	// running is the proof it is not wedged.
	probe := req.Name("sl-probe")
	fixture.MustCreate(t, tgt, "dev-a", probe, "team-a")
	fixture.WaitObserved(t, tgt, "dev-a", probe, "running")

	// The gap: the orphaned pre-wipe cluster is never brought back under
	// management. ReconcileAll iterates store.List, and the boot-time
	// quarantine needs a stale row to fire — an empty store hits neither
	// path, so the orphan runs unmanaged until a human notices. One
	// reconcile window (the kind deployment ticks every 10s) is all
	// adoption would need if it existed at boot, like DetectStaleRestore.
	req.NotYetBuilt(t, 8, "empty-store recovery is not implemented: nothing re-adopts a backing cluster the store forgot (reconcile iterates store rows only; the stale-restore quarantine needs a row to compare), so a store loss strands every managed cluster as an unmanaged orphan with no alarm", func(b *req.B) {
		err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 90*time.Second, true, func(ctx context.Context) (bool, error) {
			st, v := fixture.Get(b, tgt, "admin", id)
			if st != http.StatusOK {
				return false, nil
			}
			_, o := fixture.State(v)
			return o == "running", nil
		})
		if err != nil {
			b.Fatalf("pre-wipe cluster %s was not re-adopted within 90s of the store loss; it stays an unmanaged orphan", id)
		}
	})
}
