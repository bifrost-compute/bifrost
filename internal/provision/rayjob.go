package provision

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// KubeRay RayJob backend (requirement 5): translate a [core.RayJobSpec]
// into a typed RayJob custom resource whose cluster KubeRay creates for the
// job and deletes after it finishes, and map a RayJob's status back to the
// provider-agnostic [ObservedJob]. Pure (no Kubernetes client), like
// kuberay.go: the live wiring is internal/provision/live/rayjob.go.

const (
	// JobKind is the RayJob CRD kind.
	JobKind = "RayJob"
	// SubmitterContainerName is the name KubeRay gives the K8sJobMode
	// submitter container; kept identical so KubeRay recognizes the
	// template Bifrost supplies.
	SubmitterContainerName = "ray-job-submitter"
	// JobRunningDeploymentStatus is KubeRay's deployment status while the
	// job's cluster is up and the job is being driven — the window during
	// which the gateway routes to it. The other three are the terminal
	// deployment statuses; mirrored as plain strings so internal/controller
	// (k8s-free by depguard) can name them without the KubeRay types.
	JobRunningDeploymentStatus          = "Running"
	JobCompleteDeploymentStatus         = "Complete"
	JobFailedDeploymentStatus           = "Failed"
	JobValidationFailedDeploymentStatus = "ValidationFailed"
)

// JobDeploymentIsTerminal reports whether a KubeRay deployment status means
// the job will never progress again (its cluster is gone or going).
func JobDeploymentIsTerminal(deploymentStatus string) bool {
	switch deploymentStatus {
	case JobCompleteDeploymentStatus, JobFailedDeploymentStatus, JobValidationFailedDeploymentStatus:
		return true
	default:
		return false
	}
}

// ClusterSpecForJob is the ClusterSpec view of a job: the shape of the
// cluster KubeRay creates for it. Shared by the translator (below), quota
// admission (policy.ClusterDemand over the derived spec) and the
// administrator's allowlist check, so a job is admitted by exactly the
// rules a cluster of the same shape would be.
func ClusterSpecForJob(id core.ClusterId, spec *core.RayJobSpec) core.ClusterSpec {
	return core.ClusterSpec{
		Name:            string(id),
		Project:         spec.Project,
		Engine:          core.EngineRay,
		RayVersion:      spec.RayVersion,
		Image:           spec.Image,
		HeadCpu:         spec.HeadCpu,
		HeadMemory:      spec.HeadMemory,
		WorkerGroups:    spec.WorkerGroups,
		Owner:           spec.Owner,
		Profile:         spec.Profile,
		Storage:         spec.Storage,
		StorageResolved: spec.StorageResolved,
		// The job's cluster pods run under the job identity (#20), as does
		// the submitter (submitterTemplate).
		ServiceAccountResolved: spec.ServiceAccountResolved,
	}
}

// RayJobFor builds the RayJob manifest for spec under id. The embedded
// RayClusterSpec is [RayClusterFor]'s (same pod templates, probes and
// labels, so the job's pods carry [ClusterIDLabel]=id and fall under the
// same per-cluster NetworkPolicy allow as a managed cluster's). KubeRay
// owns the cluster's lifetime: ShutdownAfterJobFinishes deletes it once
// the job ends, TTLSecondsAfterFinished after a grace period. Submission
// is K8sJobMode — a Kubernetes Job runs `ray job submit` against the head
// — with a submitter template that carries the same tenant labels, so the
// submitter is a peer of the cluster under the default-deny posture (a
// label-less submitter could never reach the head's :8265).
func RayJobFor(id core.ClusterId, spec *core.RayJobSpec, generation uint64, queue *QueueAssignment) (*rayv1.RayJob, error) {
	return RayJobForScheduled(id, spec, generation, queue, Scheduling{})
}

// RayJobForScheduled is [RayJobFor] with the control plane's [Scheduling]
// stamped onto the job's cluster pods AND its submitter pod: the submitter
// is a peer of the cluster under the same taints, so it must be placeable
// wherever the cluster is.
func RayJobForScheduled(id core.ClusterId, spec *core.RayJobSpec, generation uint64, queue *QueueAssignment, sched Scheduling) (*rayv1.RayJob, error) {
	if spec.Entrypoint == "" {
		return nil, fmt.Errorf("provision: job %s: entrypoint is required", id)
	}
	cs := ClusterSpecForJob(id, spec)
	rc, err := RayClusterForScheduled(id, &cs, false, generation, queue, sched)
	if err != nil {
		return nil, err
	}
	ttl := spec.TtlSecondsAfterFinishedOrDefault()
	if ttl > uint32(1<<31-1) {
		return nil, fmt.Errorf("provision: job %s: ttl_seconds_after_finished %d out of range", id, ttl)
	}
	return &rayv1.RayJob{
		TypeMeta: metav1.TypeMeta{APIVersion: APIVersion, Kind: JobKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:        string(id),
			Labels:      rc.Labels,
			Annotations: rc.Annotations,
		},
		Spec: rayv1.RayJobSpec{
			Entrypoint:               spec.Entrypoint,
			RuntimeEnvYAML:           spec.RuntimeEnvYaml,
			RayClusterSpec:           &rc.Spec,
			SubmitterPodTemplate:     submitterTemplate(string(id), spec, sched),
			ShutdownAfterJobFinishes: true,
			TTLSecondsAfterFinished:  int32(ttl),
			SubmissionMode:           rayv1.K8sJobMode,
		},
	}, nil
}

// submitterTemplate is KubeRay's default submitter (its image, its
// resource envelope, RestartPolicy Never) plus the tenant labels every
// Bifrost pod carries and the job's workload identity (#20): the
// submitter runs `ray job submit` as a peer of the cluster, so it holds
// the same ServiceAccount the cluster's pods do. KubeRay fills the command.
func submitterTemplate(id string, spec *core.RayJobSpec, sched Scheduling) *corev1.PodTemplateSpec {
	labels := map[string]string{ClusterIDLabel: id}
	if spec.Owner != nil {
		labels[OwnerLabel] = ownerLabelValue(*spec.Owner)
	}
	tmpl := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyNever,
			ServiceAccountName: derefString(spec.ServiceAccountResolved),
			Containers: []corev1.Container{{
				Name:  SubmitterContainerName,
				Image: spec.Image,
				Resources: corev1.ResourceRequirements{
					Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("1Gi")},
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("200Mi")},
				},
			}},
		},
	}
	sched.apply(&tmpl.Spec)
	return tmpl
}

// JobStatusToState maps a RayJob status to a [core.RayJobState]. Ray's own
// job status wins when it has one; before Ray reports anything, KubeRay's
// deployment status decides between "still coming up" (pending) and a
// failure KubeRay declared without Ray ever running the job (failed — e.g.
// ValidationFailed, or the cluster never became ready).
func JobStatusToState(status rayv1.RayJobStatus) core.RayJobState {
	if st, ok := core.ParseRayJobStatus(string(status.JobStatus)); ok {
		return st
	}
	switch status.JobDeploymentStatus {
	case rayv1.JobDeploymentStatusFailed, rayv1.JobDeploymentStatusValidationFailed:
		return core.RayJobStateFailed
	case rayv1.JobDeploymentStatusComplete:
		return core.RayJobStateSucceeded
	default:
		return core.RayJobStatePending
	}
}

// JobDashboardBaseURL normalizes KubeRay's status.dashboardURL — written as
// `<head-svc>.<ns>.svc.<cluster-domain>:8265`, scheme-less (KubeRay's
// FetchHeadServiceURL) — into the http:// base URL the gateway proxies to.
// A value that already carries a scheme passes through.
func JobDashboardBaseURL(dashboardURL string) string {
	if dashboardURL == "" {
		return ""
	}
	if strings.Contains(dashboardURL, "://") {
		return dashboardURL
	}
	return "http://" + dashboardURL
}

// ObservedJobFromRayJob projects a live RayJob onto [ObservedJob]: the
// backend vocabularies verbatim, timestamps as unix seconds, and the
// dashboard URL normalized through [JobDashboardBaseURL].
func ObservedJobFromRayJob(rj *rayv1.RayJob) ObservedJob {
	obs := ObservedJob{
		ID:               core.ClusterId(rj.Name),
		JobStatus:        string(rj.Status.JobStatus),
		DeploymentStatus: string(rj.Status.JobDeploymentStatus),
	}
	if rj.Status.RayClusterName != "" {
		name := rj.Status.RayClusterName
		obs.ClusterName = &name
	}
	if url := JobDashboardBaseURL(rj.Status.DashboardURL); url != "" {
		obs.DashboardURL = &url
	}
	if rj.Status.Message != "" {
		msg := rj.Status.Message
		obs.Message = &msg
	}
	obs.StartTime = unixSeconds(rj.Status.StartTime)
	obs.EndTime = unixSeconds(rj.Status.EndTime)
	return obs
}

func unixSeconds(t *metav1.Time) *uint64 {
	if t == nil || t.IsZero() {
		return nil
	}
	s := t.Unix()
	if s < 0 {
		return nil
	}
	v := uint64(s)
	return &v
}

// RayVersionFromImage derives the Ray version from an image tag
// (`rayproject/ray:2.56.0-py311` -> "2.56.0"): the API edge's default when
// a job spec leaves ray_version empty. ok is false when the image has no
// tag, or the tag does not start with a digit (`latest`, a digest).
func RayVersionFromImage(image string) (string, bool) {
	tag := ""
	if i := strings.LastIndex(image, ":"); i >= 0 && !strings.Contains(image[i:], "/") {
		tag = image[i+1:]
	}
	if tag == "" {
		return "", false
	}
	if j := strings.IndexByte(tag, '-'); j >= 0 {
		tag = tag[:j]
	}
	if _, err := strconv.Atoi(tag[:1]); err != nil {
		return "", false
	}
	return tag, true
}
