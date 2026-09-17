package provision

import (
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// --- Requirement 20: workload identity reaches every pod template ---

func TestServiceAccountIsStampedOnEveryPodTemplate(t *testing.T) {
	spec := testSpec(t, wg("cpu", 0, 4, 2))
	spec.ServiceAccountResolved = ptr.To("team-a-interactive")
	rc, err := RayClusterFor("demo", spec, false, 1, nil)
	if err != nil {
		t.Fatalf("RayClusterFor: %v", err)
	}
	if got := rc.Spec.HeadGroupSpec.Template.Spec.ServiceAccountName; got != "team-a-interactive" {
		t.Errorf("head serviceAccountName = %q", got)
	}
	if got := rc.Spec.WorkerGroupSpecs[0].Template.Spec.ServiceAccountName; got != "team-a-interactive" {
		t.Errorf("worker serviceAccountName = %q", got)
	}

	svc := testServiceSpec(core.UpgradeStrategyCanary)
	svc.ServiceAccountResolved = ptr.To("team-a-serving")
	rs, err := RayServiceFor("svc", svc, 1, nil)
	if err != nil {
		t.Fatalf("RayServiceFor: %v", err)
	}
	if got := rs.Spec.RayClusterSpec.HeadGroupSpec.Template.Spec.ServiceAccountName; got != "team-a-serving" {
		t.Errorf("service head serviceAccountName = %q", got)
	}
	if got := rs.Spec.RayClusterSpec.WorkerGroupSpecs[0].Template.Spec.ServiceAccountName; got != "team-a-serving" {
		t.Errorf("service worker serviceAccountName = %q", got)
	}
}

// A job's cluster pods AND its submitter run under the job identity: the
// submitter runs `ray job submit` as a peer of the cluster, and a
// submitter under a different identity would be the one pod in the
// tenant's workload holding some other role.
func TestRayJobStampsTheJobIdentityOnClusterAndSubmitter(t *testing.T) {
	spec := testJobSpec(wg("cpu", 1, 2, 1))
	spec.ServiceAccountResolved = ptr.To("team-a-runner")
	rj, err := RayJobFor("job-1", spec, 3, nil)
	if err != nil {
		t.Fatalf("RayJobFor: %v", err)
	}
	if got := rj.Spec.RayClusterSpec.HeadGroupSpec.Template.Spec.ServiceAccountName; got != "team-a-runner" {
		t.Errorf("job head serviceAccountName = %q", got)
	}
	if got := rj.Spec.RayClusterSpec.WorkerGroupSpecs[0].Template.Spec.ServiceAccountName; got != "team-a-runner" {
		t.Errorf("job worker serviceAccountName = %q", got)
	}
	if got := rj.Spec.SubmitterPodTemplate.Spec.ServiceAccountName; got != "team-a-runner" {
		t.Errorf("submitter serviceAccountName = %q", got)
	}
}

// No rule = the namespace default, exactly as before #20: no
// serviceAccountName on any template, no key on the manifest.
func TestNoWorkloadIdentityLeavesTheTemplatesUntouched(t *testing.T) {
	rc, err := RayClusterFor("demo", testSpec(t, wg("cpu", 0, 4, 2)), false, 1, nil)
	if err != nil {
		t.Fatalf("RayClusterFor: %v", err)
	}
	if rc.Spec.HeadGroupSpec.Template.Spec.ServiceAccountName != "" {
		t.Fatal("a spec without a workload identity must leave serviceAccountName empty")
	}
	if strings.Contains(string(mustJSON(t, marshal(t, rc))), "serviceAccountName") {
		t.Fatal("no serviceAccountName key may appear on the manifest")
	}
	rj, err := RayJobFor("job-1", testJobSpec(wg("cpu", 1, 2, 1)), 3, nil)
	if err != nil {
		t.Fatalf("RayJobFor: %v", err)
	}
	if rj.Spec.SubmitterPodTemplate.Spec.ServiceAccountName != "" {
		t.Fatal("a job without a workload identity must leave the submitter's serviceAccountName empty")
	}
}

// The owned fingerprint covers the identity: it round-trips through the
// manifest, and a stripped or swapped ServiceAccount is drift — an
// out-of-band edit that changes which cloud IAM role the pods hold must be
// repaired, not tolerated.
func TestOwnedFingerprintCoversServiceAccount(t *testing.T) {
	spec := testSpec(t, wg("cpu", 0, 4, 2))
	plain := OwnedSpecFingerprint(spec)
	if strings.Contains(plain, "service_account") {
		t.Fatalf("a spec without a workload identity must fingerprint as before: %s", plain)
	}
	spec.ServiceAccountResolved = ptr.To("team-a-interactive")
	want := OwnedSpecFingerprint(spec)
	if want == plain {
		t.Fatal("adding a workload identity must change the fingerprint")
	}
	rc, err := RayClusterFor("demo", spec, false, 1, nil)
	if err != nil {
		t.Fatalf("RayClusterFor: %v", err)
	}
	got, ok := FingerprintFromRayCluster(&rc.Spec)
	if !ok || got != want {
		t.Fatalf("fingerprint mismatch (ok=%v):\nwant %s\ngot  %s", ok, want, got)
	}
	swapped := rc.DeepCopy()
	swapped.Spec.HeadGroupSpec.Template.Spec.ServiceAccountName = "cluster-admin-sa"
	if fp, _ := FingerprintFromRayCluster(&swapped.Spec); fp == want {
		t.Fatal("a swapped ServiceAccount must change the fingerprint")
	}
	stripped := rc.DeepCopy()
	stripped.Spec.HeadGroupSpec.Template.Spec.ServiceAccountName = ""
	if fp, _ := FingerprintFromRayCluster(&stripped.Spec); fp == want {
		t.Fatal("a stripped ServiceAccount must change the fingerprint")
	}
}

func TestWorkloadIdentityRuleFor(t *testing.T) {
	r := core.WorkloadIdentityRule{ServiceAccount: "default-sa", JobServiceAccount: "runner"}
	if got := r.For(core.WorkloadInteractive); got != "default-sa" {
		t.Errorf("interactive = %q, want the default", got)
	}
	if got := r.For(core.WorkloadJob); got != "runner" {
		t.Errorf("job = %q, want the kind-specific account", got)
	}
	if got := r.For(core.WorkloadServing); got != "default-sa" {
		t.Errorf("serving = %q, want the default", got)
	}
	if got := (core.WorkloadIdentityRule{JobServiceAccount: "runner"}).For(core.WorkloadServing); got != "" {
		t.Errorf("a rule with no default and no serving account must answer \"\" for serving, got %q", got)
	}
	if !(core.WorkloadIdentityRule{}).IsZero() || r.IsZero() {
		t.Error("IsZero")
	}
}
