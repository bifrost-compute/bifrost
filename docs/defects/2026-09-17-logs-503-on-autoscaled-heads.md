# Logs tab answers 503 for every autoscaled cluster

**Found:** 2026-09-17, on grace, while validating rows 20 and 21 end to
end: `GET /api/v1/clusters/{id}/logs` returned `503 log source unavailable`
for every cluster created that day, in the default namespace and in a
tenant namespace alike, while the nine-day-old `checkmaite-jobs` cluster's
logs worked. The control plane logged, per call:

```
api: logs backend error cluster=ctl-proof error="backend error: the server
rejected our request for an unknown reason (get pods ctl-proof-head)"
```

**The bug:** grace runs `--ray-autoscaling`, so every new head pod carries
two containers, `ray-head` and KubeRay's `autoscaler` sidecar. The live
client's `ClusterLogs` requested `pods/log` without naming a container. On
a multi-container pod the API server answers 400 ("a container name must be
specified for pod …, choose one of: [ray-head autoscaler]"), which
client-go reports as "rejected our request for an unknown reason" and the
handler maps to 503. Single-container pods (autoscaling off, or the
pre-autoscaling `checkmaite-jobs`) never hit it, which is why kind's
non-autoscaling lane and the earlier grace deployment were green. The
nightly in-cluster runner's r15 failure on grace has the same signature.

**Fix:** `provision.LogContainer(pod)` picks the Ray container by its
KubeRay name (`ray-head`, `ray-worker`, or the RayJob submitter), falling
back to the pod's first container, and `ClusterLogs` passes it as
`PodLogOptions.Container`. Covered by `TestLogContainerPrefersTheRayContainer`;
the live path is the L3 logs assertions, which now run against autoscaled
heads on grace.
