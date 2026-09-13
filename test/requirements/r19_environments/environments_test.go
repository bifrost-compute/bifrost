// Requirement 19 — governed, named environments end to end (the governed-
// environments epic's MVP done line, issue #56): a job names a published
// environment from the administrator's catalog and its pinned pip packages
// install at job start, with a bounded setup timeout, failure surfacing,
// and — on lanes behind the default-deny tenant egress — an explicit
// allowance to the platform package proxy only.
//
// Lane coverage: L2 (inproc) proves admission, the compiled runtime_env
// pinned on the stored spec, the injected setup-timeout bound, the
// install-failure surfacing path (via the fake's uninstallable-package
// marker, inproc.FakeUninstallablePackage) and the refusal audit rows. The
// one thing a fake cannot prove — a real pip install reaching a real index
// through the proxy allowance — is TestEnvironmentPackagesImportAtJobStart,
// gated on the "package-proxy" capability; no target declares it yet, so
// its first real execution is the next kind run with a --package-proxy
// deployment.
package r19_environments

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	networkingv1 "k8s.io/api/networking/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
	"github.com/bifrost-compute/bifrost/test/requirements/target/inproc"
)

// quickTTL keeps a finished job's cluster around only briefly (r05's
// convention, duplicated per the repo rule that requirement packages share
// only fixture/).
func quickTTL() *int32 { v := int32(5); return &v }

// setEnvironments replaces the environment catalog as admin and restores
// it when the test ends (the policy is platform state). r05's inline
// pattern, factored out because every test here replaces the catalog.
func setEnvironments(t *testing.T, tgt req.Target, envs []client.EnvironmentSpec) {
	t.Helper()
	ctx := context.Background()
	admin := tgt.As("admin").API()
	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	put, err := admin.UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{Environments: &envs})
	if err != nil || put.StatusCode()/100 != 2 {
		t.Fatalf("update_policy environments: err=%v status=%v body=%s", err, put.StatusCode(), put.Body)
	}
	t.Cleanup(func() {
		restore := []client.EnvironmentSpec{}
		if before.JSON200.Environments != nil {
			restore = *before.JSON200.Environments
		}
		_, _ = admin.UpdatePolicyWithResponse(context.Background(), client.UpdatePolicyJSONRequestBody{Environments: &restore})
	})
}

// jobRuntimeEnv reads the runtime_env document the job was admitted with.
// The contract never echoes a job's spec, so each lane reads it through its
// own seam: the stored spec on inproc (its target exposes the store), the
// live RayJob CR's runtimeEnvYAML on a cluster target.
func jobRuntimeEnv(t *testing.T, tgt req.Target, id string) string {
	t.Helper()
	if r, ok := tgt.(interface{ JobRuntimeEnv(string) (string, bool) }); ok {
		env, found := r.JobRuntimeEnv(id)
		if !found {
			t.Fatalf("no stored job %s", id)
		}
		return env
	}
	if k, ok := tgt.K8s(); ok {
		var rj rayv1.RayJob
		req.Eventually(t, tgt, func() (bool, string) {
			err := k.Get(context.Background(), ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: id}, &rj)
			return err == nil, fmt.Sprintf("get RayJob %s: %v", id, err)
		})
		return rj.Spec.RuntimeEnvYAML
	}
	t.Fatalf("target %s exposes neither the stored spec nor Kubernetes", tgt.Name())
	return ""
}

// TestJobNamingPublishedEnvironmentIsAdmitted is the MVP's happy path up to
// admission: the catalog entry compiles into the governed runtime_env the
// job's spec carries — pinned packages, env vars, and the bounded setup
// timeout injected (#56) — and the job is admitted. Completion is asserted
// only where an install can actually succeed: inproc's fake, or a cluster
// lane with the package proxy configured.
func TestJobNamingPublishedEnvironmentIsAdmitted(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 19, "a job naming a published environment is admitted with the environment's compiled runtime_env pinned on its spec: the pinned package, and the policy's setup-timeout bound injected because the environment sets none")
	envName := req.Name("mlbase")
	published := client.Published
	image := fixture.RayImage()
	setEnvironments(t, tgt, []client.EnvironmentSpec{{
		Name:      envName,
		BaseImage: &image,
		Packages:  &[]string{"numpy==1.26.4"},
		EnvVars:   &map[string]string{"REQ_ENV_PROBE": "r19"},
		Status:    &published,
	}})

	id := req.Name("envok")
	body := fixture.SubmitJobBody(id, "team-a", `python -c "import numpy; print('REQ-ENV-OK')"`, quickTTL())
	body.Spec.Image = "" // the environment's base image fills it
	body.Spec.Environment = &envName
	view := fixture.MustSubmitJob(t, tgt, "dev-a", body)
	if view["status"] == nil {
		t.Fatalf("view carries no status: %v", view)
	}

	env := jobRuntimeEnv(t, tgt, id)
	for _, want := range []string{"numpy==1.26.4", "REQ_ENV_PROBE: r19", "setup_timeout_seconds: 600"} {
		if !fixture.Contains(env, want) {
			t.Errorf("admitted runtime_env lacks %q:\n%s", want, env)
		}
	}

	// On inproc the fake "install" always succeeds; on a cluster lane the
	// install needs the package proxy, which TestEnvironmentPackagesImportAtJobStart
	// owns. A kind lane without it must not wait out its budget on a job
	// whose pip install the default-deny egress refuses.
	if _, ok := tgt.K8s(); !ok || tgt.Has("package-proxy") {
		fixture.WaitJob(t, tgt, "dev-a", id, "SUCCEEDED")
	}
}

// TestEnvironmentPackagesImportAtJobStart is the L3 half of the MVP: the
// pinned package really installs at job start — through the package-proxy
// egress allowance, under the default-deny posture — and the entrypoint
// imports it. Gated on the "package-proxy" capability: the control plane
// must run with --package-proxy and the proxy must serve. No target
// declares the capability yet; first real execution is the next kind run
// with a proxy deployed.
func TestEnvironmentPackagesImportAtJobStart(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 19, "the environment's pinned pure-python package installs at job start behind default-deny egress with only the package proxy allowed, and the entrypoint imports it")
	req.NeedK8s(t, tgt)
	req.NeedsCapability(t, tgt, "package-proxy")
	ctx := context.Background()

	envName := req.Name("mlreal")
	published := client.Published
	image := fixture.RayImage()
	setEnvironments(t, tgt, []client.EnvironmentSpec{{
		Name:      envName,
		BaseImage: &image,
		Packages:  &[]string{"numpy==1.26.4"},
		Status:    &published,
	}})

	id := req.Name("envreal")
	body := fixture.SubmitJobBody(id, "team-a", `python -c "import numpy; print('REQ-ENV-IMPORT-OK', numpy.__version__)"`, quickTTL())
	body.Spec.Image = ""
	body.Spec.Environment = &envName
	fixture.MustSubmitJob(t, tgt, "dev-a", body)

	// The proxy egress allowance is per-workload and narrow: the job's pods
	// only, the proxy's addresses and port only. (Policy name inlined: the
	// provision package's name helper is internal/, off-limits here.)
	k, _ := tgt.K8s()
	req.Eventually(t, tgt, func() (bool, string) {
		var np networkingv1.NetworkPolicy
		err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: "bifrost-cluster-" + id + "-pkgproxy"}, &np)
		return err == nil, fmt.Sprintf("get package-proxy policy: %v", err)
	})

	fixture.WaitJob(t, tgt, "dev-a", id, "SUCCEEDED")
}

// TestEnvironmentInstallFailureSurfacesUsefulMessage is the failure half of
// the user story: the install fails (a package no index serves), the job
// ends FAILED, and its message says why — the runtime-env setup error, not
// a bare "exited 1". The failing environment pins a 120s setup timeout
// through its escape hatch, which both keeps a real lane inside its budget
// and proves a caller-pinned timeout is preserved over the injected
// default. On inproc the fake's uninstallable-package marker
// (inproc.FakeUninstallablePackage) drives the same path; on a cluster the
// install fails for real.
func TestEnvironmentInstallFailureSurfacesUsefulMessage(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 19, "when the environment's package install fails, the job ends FAILED and its message carries the runtime-env setup error naming the package")
	envName := req.Name("broken")
	published := client.Published
	image := fixture.RayImage()
	timeout := "config:\n  setup_timeout_seconds: 120"
	setEnvironments(t, tgt, []client.EnvironmentSpec{{
		Name:           envName,
		BaseImage:      &image,
		Packages:       &[]string{inproc.FakeUninstallablePackage + "==0.0.0"},
		RuntimeEnvYaml: &timeout,
		Status:         &published,
	}})

	id := req.Name("envfail")
	body := fixture.SubmitJobBody(id, "team-a", `python -c "print('never runs')"`, quickTTL())
	body.Spec.Image = ""
	body.Spec.Environment = &envName
	fixture.MustSubmitJob(t, tgt, "dev-a", body)

	env := jobRuntimeEnv(t, tgt, id)
	for _, want := range []string{inproc.FakeUninstallablePackage + "==0.0.0", "setup_timeout_seconds: 120"} {
		if !fixture.Contains(env, want) {
			t.Errorf("admitted runtime_env lacks %q:\n%s", want, env)
		}
	}

	view := fixture.WaitJob(t, tgt, "dev-a", id, "FAILED")
	msg, _ := view["message"].(string)
	if _, inprocLane := tgt.K8s(); !inprocLane {
		// The fake reports exactly what it was told; the assertion pins the
		// message a user reads to the setup failure and the package.
		if !fixture.Contains(msg, "runtime_env setup failed") || !fixture.Contains(msg, inproc.FakeUninstallablePackage) {
			t.Fatalf("job message = %q, want the runtime-env setup failure naming the package", msg)
		}
	} else {
		// Real Ray writes its own text; the contract is that the failure is
		// attributable to the environment setup, not a silent FAILED.
		if msg == "" || !strings.Contains(strings.ToLower(msg), "runtime") {
			t.Fatalf("job message = %q, want the runtime-env setup error", msg)
		}
	}
}

// TestUnpublishedOrForeignEnvironmentIsRefused covers the denials: a draft
// is not selectable yet, a deprecated environment takes no new references,
// and an environment scoped to another project is not visible — each a 400
// that persists nothing and leaves an environment_rejected audit deny
// naming the caller.
func TestUnpublishedOrForeignEnvironmentIsRefused(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 19, "draft, deprecated and foreign-project environments refuse new references with a 400, persist nothing, and leave environment_rejected audit rows")
	ctx := context.Background()
	image := fixture.RayImage()
	draft, deprecated, published := client.Draft, client.Deprecated, client.Published
	setEnvironments(t, tgt, []client.EnvironmentSpec{
		{Name: req.Name("wip"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &draft},
		{Name: req.Name("old"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &deprecated},
		{Name: req.Name("foreign"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &published, Projects: &[]string{"team-b"}},
	})
	devA := fixture.Subject(t, tgt, "dev-a")

	for i, name := range []string{req.Name("wip"), req.Name("old"), req.Name("foreign")} {
		id := req.Name(fmt.Sprintf("deny%d", i))
		body := fixture.SubmitJobBody(id, "team-a", `python -c 1`, quickTTL())
		body.Spec.Environment = &name
		st, respBody := fixture.SubmitJob(t, tgt, "dev-a", body)
		if st != http.StatusBadRequest {
			t.Fatalf("submit naming environment %s = %d %s, want 400", name, st, respBody)
		}
		if g, err := tgt.As("admin").API().GetJobWithResponse(ctx, id); err != nil || g.StatusCode() != http.StatusNotFound {
			t.Fatalf("a refused submit must persist nothing; get_job %s = %v", id, statusCodeOf(g, err))
		}
	}

	audit, err := tgt.As("admin").API().ListAuditEventsWithResponse(ctx, nil)
	if err != nil || audit.StatusCode() != http.StatusOK {
		t.Fatalf("list_audit_events: err=%v status=%v", err, audit.StatusCode())
	}
	var rows []struct {
		Subject  *string `json:"subject"`
		Decision string  `json:"decision"`
		Reason   *string `json:"reason"`
	}
	if err := json.Unmarshal(audit.Body, &struct {
		Items *[]struct {
			Subject  *string `json:"subject"`
			Decision string  `json:"decision"`
			Reason   *string `json:"reason"`
		} `json:"items"`
	}{Items: &rows}); err != nil {
		t.Fatalf("list_audit_events: unmarshal: %v", err)
	}
	denies := 0
	for _, r := range rows {
		if r.Decision == "deny" && r.Subject != nil && *r.Subject == devA &&
			r.Reason != nil && *r.Reason == "environment_rejected" {
			denies++
		}
	}
	if denies < 3 {
		t.Fatalf("audit trail has %d environment_rejected denies for %s, want one per refused reference", denies, devA)
	}
}

// TestScanGateRefusesUncleanVerdicts covers the CVE/scan gate (#58): with
// the project's admission rule requiring scanned environments, a reference
// to a published environment whose recorded verdict is absent or failed is
// a 400 that persists nothing and audits under the gate's own reasons; a
// clean verdict is admitted. The verdict is a recorded field — the control
// plane does not scan; an administrator sets it after the offline workflow
// (scripts/scan-environment.py).
func TestScanGateRefusesUncleanVerdicts(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 19, "with require_scanned_environments on, a reference to an environment whose scan verdict is absent or failed is refused (400, environment_unscanned/environment_scan_failed audit denies); a clean verdict is admitted")
	ctx := context.Background()
	admin := tgt.As("admin").API()
	image := fixture.RayImage()
	published := client.Published
	failed := client.EnvironmentScanStatus("failed")
	clean := client.EnvironmentScanStatus("clean")
	scanner := "trivy 0.57.0"
	setEnvironments(t, tgt, []client.EnvironmentSpec{
		{Name: req.Name("unscanned"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &published},
		{Name: req.Name("vuln"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &published,
			Scan: &client.EnvironmentScan{Status: failed, Scanner: &scanner}},
		{Name: req.Name("vetted"), BaseImage: &image, Packages: &[]string{"numpy==1.26.4"}, Status: &published,
			Scan: &client.EnvironmentScan{Status: clean, Scanner: &scanner}},
	})

	// Turn the gate on for every project ("*" rule), restoring the admission
	// section when the test ends (the policy is platform state).
	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	on := true
	adm := map[string]client.AdmissionRule{"*": {RequireScannedEnvironments: &on}}
	put, err := admin.UpdatePolicyWithResponse(ctx, client.UpdatePolicyJSONRequestBody{Admission: &adm})
	if err != nil || put.StatusCode()/100 != 2 {
		t.Fatalf("update_policy admission: err=%v status=%v body=%s", err, put.StatusCode(), put.Body)
	}
	t.Cleanup(func() {
		restore := map[string]client.AdmissionRule{}
		if before.JSON200.Admission != nil {
			restore = *before.JSON200.Admission
		}
		_, _ = admin.UpdatePolicyWithResponse(context.Background(), client.UpdatePolicyJSONRequestBody{Admission: &restore})
	})

	devA := fixture.Subject(t, tgt, "dev-a")
	for i, name := range []string{req.Name("unscanned"), req.Name("vuln")} {
		id := req.Name(fmt.Sprintf("scandeny%d", i))
		body := fixture.SubmitJobBody(id, "team-a", `python -c 1`, quickTTL())
		body.Spec.Environment = &name
		st, respBody := fixture.SubmitJob(t, tgt, "dev-a", body)
		if st != http.StatusBadRequest {
			t.Fatalf("submit naming %s = %d %s, want 400", name, st, respBody)
		}
		if g, gerr := admin.GetJobWithResponse(ctx, id); gerr != nil || g.StatusCode() != http.StatusNotFound {
			t.Fatalf("a refused submit must persist nothing; get_job %s = %v", id, statusCodeOf(g, gerr))
		}
	}

	// A clean verdict is admitted.
	okID := req.Name("scanok")
	okBody := fixture.SubmitJobBody(okID, "team-a", `python -c "print('REQ-SCAN-OK')"`, quickTTL())
	okBody.Spec.Image = ""
	okBody.Spec.Environment = ptrString(req.Name("vetted"))
	fixture.MustSubmitJob(t, tgt, "dev-a", okBody)

	// The refusals audit under the gate's own reasons, distinct from the
	// catalog's environment_rejected.
	audit, err := admin.ListAuditEventsWithResponse(ctx, nil)
	if err != nil || audit.StatusCode() != http.StatusOK {
		t.Fatalf("list_audit_events: err=%v status=%v", err, audit.StatusCode())
	}
	var rows []struct {
		Subject  *string `json:"subject"`
		Decision string  `json:"decision"`
		Reason   *string `json:"reason"`
	}
	if err := json.Unmarshal(audit.Body, &struct {
		Items *[]struct {
			Subject  *string `json:"subject"`
			Decision string  `json:"decision"`
			Reason   *string `json:"reason"`
		} `json:"items"`
	}{Items: &rows}); err != nil {
		t.Fatalf("list_audit_events: unmarshal: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Decision == "deny" && r.Subject != nil && *r.Subject == devA && r.Reason != nil {
			seen[*r.Reason] = true
		}
	}
	for _, reason := range []string{"environment_unscanned", "environment_scan_failed"} {
		if !seen[reason] {
			t.Errorf("audit trail lacks a %s deny for %s", reason, devA)
		}
	}
}

func ptrString(s string) *string { return &s }

func statusCodeOf(r *client.GetJobHTTPResponse, err error) any {
	if err != nil {
		return err
	}
	if r == nil {
		return nil
	}
	return r.StatusCode()
}
