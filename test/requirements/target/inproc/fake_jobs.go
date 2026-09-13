package inproc

import (
	"context"
	"strings"
	"sync"

	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/provision"
)

// fakeJobProvisioner is the KubeRay RayJob controller, faked (requirement
// 5). A job walks KubeRay's deployment statuses one step per observe —
// Initializing, then Running (with a dashboard URL, so the reconciler
// registers it with the gateway) for runningObserves passes, then
// Complete/SUCCEEDED — or Failed/FAILED when the entrypoint exits 1, or
// with a runtime-env setup failure message when its runtime env names
// [FakeUninstallablePackage] (requirement 19). DeleteJob removes it, as
// deleting the RayJob does.
type fakeJobProvisioner struct {
	mu   sync.Mutex
	jobs map[core.ClusterId]*fakeJob
}

type fakeJob struct {
	spec     core.RayJobSpec
	observes int
}

// runningObserves is how many observations a fake job stays Running: at
// the 25 ms reconcile interval (two observes per actuating pass, one
// otherwise) that is roughly a second — long enough for a test to catch
// the job RUNNING and reach its gateway host, short enough that a
// completion test converges well inside the L2 budget.
const runningObserves = 40

func newFakeJobProvisioner() *fakeJobProvisioner {
	return &fakeJobProvisioner{jobs: map[core.ClusterId]*fakeJob{}}
}

var _ provision.JobProvisioner = (*fakeJobProvisioner)(nil)

func fakeClusterName(id core.ClusterId) string { return string(id) + "-raycluster-fake" }

func (p *fakeJobProvisioner) ApplyJob(_ context.Context, id core.ClusterId, spec *core.RayJobSpec, _ uint64, _ *provision.QueueAssignment) error {
	if !core.IsK8sName(string(id)) {
		return provision.ProvisionError{Kind: provision.ProvisionErrBackend, Message: "resource name may not be empty or invalid: " + string(id)}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.jobs[id]; !ok {
		p.jobs[id] = &fakeJob{spec: *spec}
	}
	return nil
}

// fails reports whether the entrypoint is one of the "exit 1" shapes the
// r05 tests use for a failing job.
func (j *fakeJob) fails() bool {
	return strings.Contains(j.spec.Entrypoint, "exit 1") || strings.Contains(j.spec.Entrypoint, "exit(1)")
}

// FakeUninstallablePackage is the install-failure marker (requirement 19,
// issue #56): the one package the fake index can never serve. A job whose
// runtime env names it dies the way a real cluster's pip failure does —
// the runtime-env setup fails before the entrypoint runs, Ray reports the
// job FAILED with the setup error as its message, and KubeRay marks the
// deployment Failed. The r19 tests name this package in an environment's
// package list; on a real cluster the same submission fails for real (the
// package exists on no index).
const FakeUninstallablePackage = "bifrost-uninstallable"

// installFails reports whether the job's runtime env names the marker
// package.
func (j *fakeJob) installFails() bool {
	return strings.Contains(j.spec.RuntimeEnvYaml, FakeUninstallablePackage)
}

func (p *fakeJobProvisioner) observed(id core.ClusterId, j *fakeJob) provision.ObservedJob {
	cluster := fakeClusterName(id)
	obs := provision.ObservedJob{ID: id, ClusterName: &cluster}
	switch {
	case j.observes <= 1:
		obs.DeploymentStatus = "Initializing"
	case j.observes <= 1+runningObserves:
		url := "http://" + cluster + "-head-svc:8265"
		start := uint64(1_700_000_000)
		obs.DeploymentStatus = provision.JobRunningDeploymentStatus
		obs.JobStatus = "RUNNING"
		obs.DashboardURL = &url
		obs.StartTime = &start
	default:
		start, end := uint64(1_700_000_000), uint64(1_700_000_030)
		obs.StartTime, obs.EndTime = &start, &end
		switch {
		case j.installFails():
			// The fake index never serves the marker package: the
			// runtime-env setup fails before the entrypoint runs, and the
			// message Ray would write names the setup failure and the
			// package (requirement 19: the job's message must say WHY).
			obs.DeploymentStatus = provision.JobFailedDeploymentStatus
			obs.JobStatus = "FAILED"
			msg := "runtime_env setup failed: Failed to install pip packages: ERROR: No matching distribution found for " + FakeUninstallablePackage
			obs.Message = &msg
		case j.fails():
			obs.DeploymentStatus = provision.JobFailedDeploymentStatus
			obs.JobStatus = "FAILED"
			msg := "Job failed: entrypoint exited with status 1"
			obs.Message = &msg
		default:
			obs.DeploymentStatus = provision.JobCompleteDeploymentStatus
			obs.JobStatus = "SUCCEEDED"
		}
	}
	return obs
}

func (p *fakeJobProvisioner) ObserveJob(_ context.Context, id core.ClusterId) (provision.ObservedJob, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	j, ok := p.jobs[id]
	if !ok {
		return provision.ObservedJob{}, provision.ProvisionError{Kind: provision.ProvisionErrNotFound, ClusterID: id}
	}
	j.observes++
	return p.observed(id, j), nil
}

func (p *fakeJobProvisioner) DeleteJob(_ context.Context, id core.ClusterId) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.jobs, id)
	return nil
}

func (p *fakeJobProvisioner) ListJobs(context.Context) ([]provision.ObservedJob, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]provision.ObservedJob, 0, len(p.jobs))
	for id, j := range p.jobs {
		out = append(out, p.observed(id, j))
	}
	return out, nil
}
