package live

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/bifrost-compute/bifrost/internal/provision"
)

// The workload identity's existence check (#20) is metadata only and
// fails fast with a readable condition naming the account, so a rule that
// names a ServiceAccount the platform never created surfaces on the
// cluster instead of as pods the kubelet refuses to start.
func TestEnsureServiceAccountExistsIsMetadataOnlyAndFailsFast(t *testing.T) {
	fake := &fakeGetClient{present: map[string]bool{"team-a-runner": true}}
	err := ensureServiceAccountExists(context.Background(), fake, "tenants", ptr.To("team-b-runner"))
	if err == nil {
		t.Fatal("a missing ServiceAccount must fail the apply")
	}
	var perr provision.ProvisionError
	if !errors.As(err, &perr) || perr.Kind != provision.ProvisionErrBackend || !strings.Contains(perr.Message, `ServiceAccount "team-b-runner" not found in namespace tenants`) {
		t.Fatalf("err = %v, want a backend ProvisionError naming team-b-runner", err)
	}
	if len(fake.asked) != 1 {
		t.Fatalf("Get calls = %d, want 1", len(fake.asked))
	}
	meta, ok := fake.asked[0].(*metav1.PartialObjectMetadata)
	if !ok {
		t.Fatalf("Get asked for %T; only PartialObjectMetadata may be requested", fake.asked[0])
	}
	if gvk := meta.GroupVersionKind(); gvk.Kind != "ServiceAccount" || gvk.Version != "v1" {
		t.Fatalf("Get asked for %s, want core/v1 ServiceAccount metadata", gvk)
	}
	if err := ensureServiceAccountExists(context.Background(), fake, "tenants", ptr.To("team-a-runner")); err != nil {
		t.Fatalf("present: %v", err)
	}
	// nil and "" name nothing: the namespace default, no lookup at all.
	asked := len(fake.asked)
	if err := ensureServiceAccountExists(context.Background(), fake, "tenants", nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := ensureServiceAccountExists(context.Background(), fake, "tenants", ptr.To("")); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(fake.asked) != asked {
		t.Fatal("the namespace default must not be looked up")
	}
}
