# Workload identity for Ray workloads — Design Spec (row 20)

**Status:** built 2026-09-17 on bifrost main (this commit). Follow-ons in §5
are not built.
**Origin:** a comparison of Bifrost against the ATEP *Ray Namespace
Platform* design and its work register (Keycloak groups → tenant
namespaces, CheckMAITE submitting RayJobs by bounded Kubernetes
impersonation, EKS Pod Identity → per-ServiceAccount IAM roles → S3 prefixes
and KMS, no static credentials). The comparison concluded that Bifrost
should stay the Ray control plane — its catalog, gateway and per-cluster
policies close most of the register's compute items — and should adopt the
namespace design's two infrastructure strengths it lacked: **workload
identity via ServiceAccounts** (this spec) and **one namespace per project**
(§5.1). This spec is the first of the two.
**Repos touched:** `bifrost` only. `bifrost-api` receives the contract by
the usual sync. `bifrost-pack` needs one RBAC line (§4.3). `bifrost-ui` is
optional (§5.4).
**Requirements served:** #20 (new row), and the credential half of #12 (S3
from the cluster without a static key) and #18 (no long-lived secrets on
tenant pods).

The ask, in one sentence: *an administrator names, per project, the
Kubernetes ServiceAccount a project's clusters, jobs and Serve deployments
run under; the platform binds a cloud IAM role to that account; Bifrost only
stamps the name on every pod it renders — so a tenant's pods reach their S3
prefix through the node's identity agent and no credential ever exists to
leak, rotate or mount.*

---

## 1. Load-bearing facts

- **Bifrost set no `serviceAccountName` on any pod template before this
  change** (`internal/provision/kuberay.go:podTemplate`). Every tenant pod
  ran as the workload namespace's `default` ServiceAccount, so every
  project's pods held the same Kubernetes identity and there was nothing
  for a cloud IAM binding to attach to per project.
- **Cloud workload identity binds to a ServiceAccount in a namespace.** EKS
  Pod Identity associations and IRSA annotations, GKE Workload Identity and
  Azure workload identity all key on `(namespace, serviceAccount)`. The pod
  needs only to *name* the account; the node agent or the projected token
  webhook does the rest. No image change, no SDK configuration, no Secret.
- **Submission identity and workload identity are already separate in
  Bifrost.** The audit row records who asked (the OIDC subject); pods never
  see the caller's token. This change gives the workload half a real,
  per-project identity; it does not touch the submission half.
- **KubeRay is compatible.** With in-tree autoscaling on, KubeRay creates
  the autoscaler Role and binds it to `utils.GetHeadGroupServiceAccountName`
  — the head template's `serviceAccountName` when set, else the RayCluster
  name. A custom account therefore needs no extra grant for the autoscaler.
  KubeRay does not write `serviceAccountName` back into the CR template,
  so the live read-back the fingerprint uses is Bifrost's own value.
- **The storage catalog (#12) stays.** Secrets and PVCs remain the right
  delivery for credentials the cloud cannot mint (a third-party API key, an
  NFS claim). Workload identity removes the *cloud* credential from that
  catalog; it does not replace the catalog.

## 2. Design

### 2.1 Policy section

`PolicyView.workload_identity` / `UpdatePolicy.workload_identity`: a map
keyed by project (or `"*"`), value `WorkloadIdentityRule`:

| field | meaning |
|---|---|
| `service_account` | default for every workload kind |
| `interactive_service_account` | overrides the default for self-serve RayClusters (#6) |
| `job_service_account` | overrides for ephemeral RayJobs (#5): cluster pods **and** the submitter |
| `serving_service_account` | overrides for RayServices (#1, #2, #4) |

Section-replace like `admission` and `storage`: a present key replaces the
whole map, `{}` clears it, an absent key leaves it untouched. Validated as
a unit: project key non-empty, every name an RFC 1123 subdomain, a rule
that names nothing is a 400 (it would be a silent no-op an administrator
could mistake for a binding). Admin-only, like every policy write.

### 2.2 Resolution and pinning

`resolveWorkloadIdentity(project, kind)` consults `"*"` then the project's
rule; the project's answer for that kind overrides. The result is pinned
on the spec as `ServiceAccountResolved` (`ClusterSpec`, `RayJobSpec`,
`ServiceSpec`) at admission, after storage resolution. It is persisted,
never echoed (views carry no spec), and **never retroactive**: an admitted
workload keeps its identity when the rule changes. `nil` = no rule = the
namespace default, byte-identical to the pre-#20 manifests.

Resolution cannot refuse: an unbound project is a valid answer. A wrong
name is caught at apply (§2.4), not at admission, because the control plane
does not hold a Kubernetes client at admission time on every deployment.

### 2.3 Projection

`podTemplate` writes `spec.serviceAccountName` on head and worker templates
of RayClusters and RayServices; `submitterTemplate` writes it on the RayJob
submitter, so every pod of a run holds one identity. Only the name is
written. The owned fingerprint gains `service_account` (omitted when
empty), read back from the live head template, so a stripped or swapped
account — which would change the IAM role the pods hold — is drift and is
repaired.

### 2.4 Existence check

`ensureServiceAccountExists` runs before every apply (cluster, service,
job) and fetches `PartialObjectMetadata` for the named account. Missing →
`ProvisionErrBackend` naming the account and namespace — the apply fails,
the reconciler logs it and backs off, exactly like a missing storage
Secret. The cluster view does not yet carry apply-error text (§5.5). RBAC: `serviceaccounts: get` on the
control plane's Role. Bifrost never creates, patches, reads tokens of, or
binds anything to the account.

### 2.5 What Bifrost deliberately does not do

- Create ServiceAccounts or IAM bindings. Those are platform objects with
  platform lifecycles (Terraform, the tenant onboarding item in the ATEP
  register). Bifrost naming them keeps one owner per object.
- Read or mint cloud credentials. There is no AWS/GCP SDK in the binary.
- Set `automountServiceAccountToken`. EKS Pod Identity and IRSA inject
  their own projected token volume through a webhook; leaving the default
  alone avoids fighting it. Tightening this is an operator's admission
  policy, not Bifrost's.

## 3. Threat model delta

| before | after |
|---|---|
| Cloud access from a cluster needs a static key in a Secret, catalogued per project, mounted on pods, rotated by hand, extractable by any code the notebook runs | Pods hold a short-lived token for one IAM role; nothing to extract that outlives the pod, nothing to rotate |
| Every project's pods share the namespace `default` account | Each project's pods hold their own account; a policy on it (S3 bucket policy condition, KMS grant, GKE IAM binding) is per project |
| A job's submitter ran as `default` while the cluster ran the same | Submitter and cluster hold the same project identity |
| An out-of-band edit to `serviceAccountName` was invisible | It is drift and is repaired |

Residual: with one shared workload namespace, the Pod Identity association
is per (namespace, account) — fine — but a tenant who could create pods in
that namespace naming another project's account would inherit its role.
Tenants have no Kubernetes API access in Bifrost's model, so this needs
the namespace-per-project follow-on (§5.1) only for defence in depth.

## 4. Verification

- `internal/provision`: projection on every template, no-rule manifests
  unchanged, fingerprint covers the account (round-trip, swap, strip).
- `internal/provision/live`: existence check is metadata-only, fails fast,
  skips nil.
- `internal/api`: section validation and replace semantics, resolution
  precedence, per-kind pinning on create/submit/deploy, non-retroactivity,
  no echo.
- `test/requirements/r20_workload_identity`: L2 through the inproc target's
  `ResolvedServiceAccount` seam; L3 creates a real ServiceAccount and
  asserts head, worker and RayJob submitter templates and pods name it.

### 4.3 Deployment note (bifrost-pack, grace)

The control plane's Role needs `serviceaccounts: get` (added to the kind
manifests here; the Helm chart in `bifrost-pack` needs the same line). The
in-cluster requirement runner needs `serviceaccounts: get/list/create/delete`
(added to `deploy/in-cluster/rbac.yaml`). On grace (microk8s, no cloud IAM)
the feature is validated to the ServiceAccount boundary: pods run under the
named account and hold its projected token; there is no IAM role to bind.
On EKS the remaining steps are the platform's: create the account per
tenant namespace, create the Pod Identity association to a role whose
policy grants the tenant's S3 prefix and KMS key, and PUT the rule.

### 4.4 The S3 requirement, stated plainly

Workload identity delivers S3 access without a static credential only when
the object store can **verify the pod's identity token and map it to a
policy**. That is what EKS Pod Identity (or IRSA) does against AWS S3: the
pod presents its projected ServiceAccount token, STS exchanges it for role
credentials, the role's policy names the tenant's prefix, KMS grants follow
the role. Three things have to be true, and only the third is Bifrost's:

1. The store (or an STS in front of it) trusts the cluster's OIDC issuer
   and implements `AssumeRoleWithWebIdentity` — AWS does; MinIO does
   (OpenID provider = the Kubernetes API server); **aks3 does not yet**:
   as of `bf9c57c` it authenticates SigV4 against a single root credential
   with no STS, no per-user keys and no bucket policies (Phase 0).
2. A per-tenant policy exists: prefix-scoped bucket policy or IAM role,
   plus the KMS grant, created by the platform per tenant.
3. The pods carry the tenant's ServiceAccount — this change.

On grace the store is aks3 and `team-a` reaches it through the
`team-a-aks3` Secret (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_ENDPOINT_URL` / `AWS_REGION`), the static-credential pattern this
design retires. Until aks3 grows an STS endpoint with web-identity
federation and prefix policies, grace validates (3) — pods run under the
named account and hold its projected token — and keeps (1)–(2) on the
storage catalog. The ATEP EKS path needs no aks3 work: (1) and (2) are
AWS and Terraform.

## 5. Follow-ons (not built)

### 5.1 One namespace per project — built 2026-09-17 (row 21)

`serve --tenant-namespaces` enables the policy row's `namespaces` section
(project → namespace; 400 when the flag is off). Admission pins
`NamespaceResolved` on every spec, never retroactively. The live client:

- places the RayCluster, RayJob (cluster and submitter) and RayService in
  the pinned namespace and writes the default-deny / tenant-allow posture
  and PSS labels there, after labelling its own namespace
  `bifrost.dev/control-plane=true` so the tenant-allow admits the gateway
  across the boundary;
- locates by-id objects (observe, suspend, terminate, nodes, logs, events)
  through an id → namespace cache warmed by apply and list, falling back to
  a cluster-wide list on the managed-by label — the restart-recovery path;
- lists across all namespaces, and reaps a vanished cluster's per-cluster
  policies wherever they were left;
- keeps single-namespace mode byte-identical: no flag, no pin honoured, no
  cross-namespace call, so a namespaced Role keeps working.

Kueue constraint: a LocalQueue is namespaced, so a project's allocation
must live in its mapped namespace. The map PUT refuses a contradicting
allocation and the allocation PUT refuses a contradicting namespace.

RBAC: the Ray rules become a ClusterRole (bifrost-pack `tenancy.enabled`),
and `namespaces: get, patch` loses its `resourceNames` narrowing. The
tenant namespaces themselves are the platform's to create, label for
ResourceQuota and Pod Identity, and delete at offboarding; Bifrost requires
them to exist and reports a missing one as a backend error on the apply.

Not done here: the notebook-side allow still keys on the single `jupyter`
namespace (`provision.NotebookNamespace`); a per-tenant JupyterHub
namespace needs the owner allow to take the notebook namespace from the
policy too.

### 5.2 Result prefix for jobs

An optional `result_prefix` on `RayJobSpec` (an S3/GCS URI the pod writes
under its identity) recorded on the job row, so a finished job's outputs
are addressable from the API without Bifrost holding a cloud client.

### 5.3 Storage catalog source `workload_identity`

A no-op catalog source that documents "this project's data comes through
its ServiceAccount" so the console can show where a cluster's data access
comes from without implying a Secret exists.

### 5.4 Console

A Workload identity card on Settings mirroring the admission editor.

### 5.5 Apply errors on the view

`ClusterView.condition` carries only `spec_drift` / `degraded`. A failed
apply (missing Secret, claim or ServiceAccount) is a log line and a backoff
counter. Surfacing the last apply error's message on the view would make
both #12 and #20 misconfigurations self-diagnosing from the console.
