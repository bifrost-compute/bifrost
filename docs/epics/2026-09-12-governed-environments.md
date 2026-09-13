# Epic: Governed environments for Ray workloads

*Drafted 2026-09-12 from a scoping pass over Ray's environment model, vendor
patterns (Anyscale, Databricks, SageMaker), and Bifrost's existing governance
surface. File with `scripts/file-environments-epic.sh` when GitHub is
reachable.*

## Epic statement

A user composes the environment their job or cluster needs — base image +
packages + env vars — from an administrator-governed subset, through the API
(and later the console), with versioning, audit, and security gates; no
arbitrary Dockerfiles, no unvetted image pushes.

## Why

Research summary:

- Ray's `runtime_env` (pip/conda/working_dir/env_vars) is powerful but **fully
  ungoverned in Bifrost today**: `RayJobSpec.runtime_env_yaml` passes verbatim
  into the RayJob CR (`internal/api/rayjobs.go:81`,
  `internal/provision/rayjob.go:114`). A user can set
  `pip_install_options: ["--index-url", "https://evil"]`, `py_executable`,
  `image_uri`, or remote `working_dir` URIs fetched with node credentials.
- Vendor pattern consensus (Anyscale base images + restricted containerfiles,
  Databricks versioned runtimes, SageMaker image catalogs): **a governed
  catalog of named, versioned environments; users pick and lightly
  parameterize; nobody ships raw Dockerfiles.** This matches Bifrost's
  existing profile/storage governance posture exactly.
- What exists to build on: the profile catalog pattern
  (`internal/api/profiles.go` — validated as a unit on the policy row,
  project-scoped, expanded at create, never retroactive), the
  `AllowedImagePrefixes` admission mechanism (`internal/api/admission.go`),
  and the storage catalog's resolve-by-name pattern (`internal/api/storage.go`).
- Missing: environment as a first-class named/versioned/shareable object;
  any validation of `runtime_env_yaml`; an environment story for interactive
  clusters; package governance; a build pipeline.

## Security model (both MVP and post-MVP)

- MVP (runtime_env-backed): residual risk is pip supply chain — reduced to
  "packages from the platform proxy only, names allowlisted, versions pinned"
  (default-deny tenant egress already exists; the proxy becomes the only
  install egress).
- Post-MVP (server-side image builds): residual risk is builder privilege —
  contained by rootless builders in an isolated namespace/SA, generated-only
  Containerfiles (FROM allowlisted base + pip lines, no user RUN),
  digest-pinned tags, cosign signatures verified at admission, scan gate
  before an environment can leave draft.

## Issues

Dependency graph:

```
1 (contract) ──► 3 (catalog) ──► 4 (resolution) ──► 5 (MVP e2e) ──► 9 (ADR) ──► 10 (builds)
        │              │                │
        │              ├──► 6 (publish/audit)
        │              └──► 7 (scan gate)
        └──► 8 (UI interface spec)
2 (runtime_env governance) — independent, land first as risk reduction
```

### Issue 1 — Contract: EnvironmentSpec schema and `environment` references (bifrost-api)

As the API contract owner, I want a versioned schema for a named environment
and a way for job/cluster specs to reference one, so all three repos build
against one frozen shape.

Scope: bifrost-api repo only. New `EnvironmentSpec`: `name`, `description`,
`base_image` (allowlisted prefix), `packages` (pinned `name==version` list,
pip syntax subset), `env_vars` (map), `runtime_env_yaml` (optional escape
hatch), `projects` (empty = all), `status` (draft|published|deprecated),
`published_by`, `published_at`, `scan` (nullable verdict ref). Specs gain
optional `environment: string` on `RayJobSpec` and `ClusterSpec`; policy
document gains an `environments` section; `GET /environments` mirroring
`GET /profiles`.

Acceptance: pinned-version requirement enforced at contract level (pattern);
fully backward compatible (all fields optional); generated Go types drop into
`zz_generated_api.go` cleanly.

Blocks: 2, 3, 7, 8.

### Issue 2 — Govern `runtime_env_yaml` as it exists today

As an admin, I want the existing free-form `runtime_env_yaml` validated
against policy so today's passthrough stops being an open supply-chain and
egress hole before the environment feature lands.

Scope: `internal/api/rayjobs.go`, new `internal/api/runtimeenv.go`,
`internal/core` policy types, `internal/api/admission.go`. Parse at submit;
field allowlist (default `pip`, `env_vars`, `config`; deny `py_executable`,
`image_uri`, `conda` unless enabled); deny `pip_install_options` with
`--index-url`/`--extra-index-url`/`--find-links` unless admin-declared;
`working_dir`/`py_modules` remote URIs default-deny; cap
`setup_timeout_seconds`; package denylist. Refusals 400 with audit reason
`runtime_env_rejected`. Documented permissive toggle preserves current
behavior for upgraders (default governed).

Independent; land first as risk reduction.

### Issue 3 — Environment catalog on the policy row

As an admin, I want a catalog of named environments editable via
`PUT /settings/policy`, validated as a unit, project-scoped, exactly like
profiles and storage.

Scope: new `internal/core/environment.go`, `internal/api/settings.go`, new
`internal/api/environments.go` (list/read). Copy the storage.go pattern: unit
validation at edit (unique RFC 1123 names, base image in admission allowlist,
pinned packages, denylist, valid status transitions), project scoping,
`[]`-never-`null`. Read side mirrors `ListProfiles` including project-scoped
narrowing.

Depends on: 1. Blocks: 4, 6.

### Issue 4 — Environment resolution at admission, jobs and clusters

As a user, I name `environment: "ml-base"` on my job or cluster and get its
packages/env applied, with the resolution pinned to my spec so a later
catalog edit never retroactively changes my workload.

Scope: `internal/api/rayjobs.go` (`finishJobSpec`),
`internal/api/clusters.go`, `internal/provision/rayjob.go`. Name → compiled
`runtime_env` YAML; merge with request-supplied `runtime_env_yaml` (conflict
= 400, mirroring profile expansion's whole-or-nothing rule); store as
`EnvironmentResolved` on the spec. Interactive clusters: applied via the
job-submission path and documented as cluster-wide default (Ray has no
cluster-level runtime_env on the CR — design note). Unknown/foreign name =
400 like `resolveStorage`.

Depends on: 2, 3. Blocks: 5.

*Landed (#55, 2026-09-13).* Resolution lives in
`internal/api/environments.go` (`resolveEnvironment`/`compileEnvironment`),
called from `finishJobSpec` and `CreateCluster`. Rules as implemented: only
`published` environments are referenceable (draft and deprecated both 400 a
new reference; stored resolutions are unaffected); a request supplying both
`environment` and `runtime_env_yaml` is a 400 — whole-or-nothing, no merge;
the environment's `base_image` fills the spec's image like a profile's
(differing image = 400) and passes the admission allowlist through the
ordinary `admission.Check`; env-var merge order is structured `env_vars`
plus the escape hatch's (overlaps refused at the catalog edit), and both
land in Ray's runtime_env, which wins over storage's pod-level `envFrom`
inside the job. The resolution is pinned on the spec as
`EnvironmentResolved` (name, base image, compiled YAML, resolved-at) —
stored only, never on the wire, so the frozen contract is untouched.
Clusters persist it as the cluster-wide default for later job submissions
(Ray has no cluster-level runtime_env on the CR; interactive Ray Client
sessions carry none of Bifrost's at all). The AdmissionRule runtime-env
knobs (#75) are wired: `runtimeEnvPolicyFor` folds the `*` rule and the
project's rule into the validator's policy, so they are API-editable now.

### Issue 5 — MVP: runtime_env-backed environments end to end

As a user, I submit a job naming a published environment and its pip packages
install at job start, with caching, a bounded setup timeout, and clear
failure surfacing.

Scope: `internal/provision/rayjob.go`, `internal/controller` (status
surfacing), docs. Force `config.setup_timeout_seconds` default; explicit
tenant-egress rule to the platform package proxy (default-deny egress bites
here — see defects 2026-09-03, 2026-09-08); surface runtime-env setup failure
in job `message`; document caching and cold-start honestly. New requirement
probe `test/requirements/r1x_environments`: pinned pure-python package
imports successfully; install failure produces a useful failed-job message;
works behind default-deny egress with only the proxy allowed.

Depends on: 4. **This is the MVP's done line.**

*Landed (#56, 2026-09-13).* The bounded timeout is
`RuntimeEnvPolicy.EnforceSetupTimeout` (`internal/api/runtimeenv.go`),
applied in `finishJobSpec` (hand-written and environment-compiled
documents alike) and in `resolveEnvironment` (the cluster path's pinned
default): a runtime env without `config.setup_timeout_seconds` is stored
with the policy default injected — 600s, lowered to a tighter policy cap —
and a caller-pinned timeout within the cap is kept verbatim. Failure
surfacing needed no new plumbing: KubeRay copies Ray's job failure message
(including the runtime-env setup error) into `RayJob.Status.Message`, which
already flows `ObservedJobFromRayJob` → `RecordRayJobObservation` → the job
view's `message`; the L2 fake gained the `bifrost-uninstallable` package
marker (`inproc.FakeUninstallablePackage`) so that path is testable without
a cluster. Tenant egress: `serve --package-proxy <ip-or-cidr>:<port>`
(operator-only, no user control) makes the live client apply a per-workload
egress NetworkPolicy (`provision.PackageProxyEgressNetworkPolicy`) to the
proxy's address and port — only for jobs/clusters whose admitted runtime
env actually installs packages (`provision.RuntimeEnvInstallsPackages`);
with no proxy configured nothing is written and installs work only against
registries the tenant policies already reach. The requirement probe is
`test/requirements/r19_environments` (requirement row 19): L2 green,
including the install-failure message and the refusal audit rows; the real
pip-install-and-import assertion is gated on a `package-proxy` capability
no target declares yet — first execution is the next kind run with a proxy
deployed.

### Issue 6 — Publication workflow, versioning, audit

As an admin, I want environments drafted, published, and deprecated with an
audit trail and explicit RBAC on who may publish vs use.

Scope: `internal/api/environments.go`, `internal/auth`, audit actions
(`publish_environment`, `deprecate_environment`). MVP keeps the catalog
admin-only via `PUT /settings/policy` (recommended — matches profiles);
user-submitted drafts with admin approval are deferred. Status transitions
enforced; deprecated refuses new references but stored resolutions keep
working.

Depends on: 3.

*Landed (#57, 2026-09-13).* The catalog stays admin-only via
`PUT /settings/policy` (user-submitted drafts remain deferred); the
lifecycle discipline lives in `applyEnvironmentTransitions`
(`internal/api/environments.go`), which the policy PUT runs on the
`environments` section against the stored catalog — section-replace means
transitions are computed by diffing old and new sections by name.
Transition table as implemented:

| from \ to | draft | published | deprecated | removed |
|---|---|---|---|---|
| (new) | ok | publish (stamped) | ok (retired outright) | — |
| draft | edit; stale publish metadata cleared | publish (stamped) | 400 — remove the draft instead | ok |
| published | 400 — no un-publishing; deprecate | edit; absent metadata falls back to the stored entry's | deprecate | ok |
| deprecated | re-draft; publish metadata clears | 400 — go through draft again | edit | ok |

A publish sets `published_by` from the caller's identity and `published_at`
to now when absent; whatever the path, a stored published entry must carry
both — one that still lacks them after the fill (a seeded entry echoed back
without metadata, or a dev-mode edit with no caller identity) is a 400
naming the entry, fixable by supplying the metadata explicitly. Removal is
allowed at any status, mirroring the profile and storage sections:
resolutions pinned on admitted specs are never retroactive, so removal
harms nothing already running.

Audit: the PUT emits the usual `update_policy` row plus one
`publish_environment` / `deprecate_environment` allow row per environment
whose lifecycle the edit moved (a deprecated-outright new entry is not a
deprecation — nothing was published). The rows name actor, action and time;
the durable per-environment attribution is the catalog entry's
`published_by`/`published_at` — `core.AuditEvent`'s field set is fixed by
the store schema (sqlite/postgres columns and the hash chain's canonical
form), so no free-form detail field was added. `use_environment` stays
implied: the submit path's `create_cluster`/`submit_job` audit rows (and
`environment_rejected` denies) name the workload, and the pinned
`EnvironmentResolved` on the stored spec names the environment durably —
a separate per-use row would add a field the audit schema cannot carry
cheaply.

RBAC matrix: **publish/deprecate/edit** = admin only (policy-write
permission, Admin on the cluster — pinned by
`TestUpdatePolicyEnvironmentsAdminOnly` and the r03 `update_policy` row);
**use** = anyone whose project the environment is open to
(`environmentAvailableTo` at admission); **read the catalog** = any
authenticated role, project-narrowed (`ListEnvironments`).

### Issue 7 — CVE/scan gate for environments

As a security admin, I want an environment's packages and base image to carry
a scan verdict that admission can require to be clean.

Scope: contract `scan` field (Issue 1), admission rule
`require_scanned_environments`, docs. MVP: verdict is a recorded field an
admin sets after running an offline scanner (trivy/grype on the base image;
pip-audit on the package list) — no scanner integration in the control plane;
ship a `scripts/` helper for the offline workflow. Later: CronJob that scans
and PATCHes the verdict.

Depends on: 3, 4. Can land after MVP (rule defaults off).

*Landed (#58, 2026-09-13).* The gate is a per-project AdmissionRule knob,
`require_scanned_environments` (`internal/api/openapi.json`,
`core.AdmissionRule`), not a global policy flag — the epic's "under
admission" read as the admission map, so the platform-wide `"*"` rule and a
project's own rule inherit exactly like the other admission knobs (a
project rule can only turn the gate on, never un-set a `"*"` gate — the
boolean carries no set/unset distinction once stored). The verdict stays a
recorded field an admin sets after an offline scan; the control plane does
not scan.

Enforcement is in `resolveEnvironment` (`internal/api/environments.go`), so
jobs and clusters share it. With the gate on, a published environment whose
`scan` is absent or pending is refused 400 with audit reason
`environment_unscanned`; a `failed` verdict with `environment_scan_failed`
— both carried on the new `environmentRefusal` type so the gate's refusals
are distinguishable in the audit trail from the catalog's other
`environment_rejected` denies. Verdict-echoes-in-audit: the refusal rows
suffice, same ruling as #57 — `core.AuditEvent`'s field set is fixed, so
the verdict content (scanner, scanned_at) lives on the catalog entry and
the pinned spec, not on the deny row, which names actor, workload, reason
and time.

Verdict hygiene: a verdict attests the exact packages and base image it
scanned, so `applyEnvironmentTransitions` drops a stored `scan` whenever an
edit changes either (absent = unscanned — a changed environment meets the
gate's refusal, never a stale "clean"); edits touching anything else keep
the verdict.

Offline workflow: `scripts/scan-environment.py <policy.json> <name>`
runs trivy (HIGH/CRITICAL) on the base image and pip-audit on the pinned
packages, and emits the JSON fragment to paste into the entry's `scan`
field (or `--write` edits the document in place); there is no PATCH path —
applying the verdict is the ordinary admin-only `PUT /settings/policy`
section-replace (GET the policy, edit, PUT it back). The deferred CronJob
that scans and PATCHes stays deferred.

### Issue 8 — Console affordances (bifrost-ui; interface spec only)

As a console user, I want an environment picker and a guided builder (base
image dropdown, package editor with allowlist validation, env var table,
version history) — never a Dockerfile editor.

Scope: bifrost-ui repo; thin interface description: `GET /environments`
drives pickers on job-submit and cluster-create forms; builder form
constructs `EnvironmentSpec` drafts; validation errors surface the API's
precise 400s; read-only "resolved environment" view on detail pages.
Non-goal: raw YAML editor in the guided path.

Depends on: 1, 3. Parallel with 4–7.

### Issue 9 — Design: server-side image builds (ADR + spike, post-MVP gate)

As the platform team, we want a written decision on whether/how to build
images server-side so heavy dependencies (compiled wheels, CUDA stacks,
system packages) get a reproducible, scannable path.

Scope: docs/adr + spike. Compare kaniko vs buildah vs rootless BuildKit vs
external CI + prefix allowlist (status quo+). Generated Containerfiles only
(FROM allowlisted base + pip lines), never user-authored Dockerfiles.
Deliverable: ADR with go/no-go, cost estimate, security model (builder
namespace/SA, egress to package proxy only, digest-pinned tags, cosign).

Depends on: MVP usage data (5). Blocks: 10.

### Issue 10 — Image-build pipeline implementation (post-MVP, if Issue 9 says go)

As a user, I can request an environment whose heavy deps are baked into an
image built by the platform, scanned, signed, and automatically added to my
project's allowed prefixes.

Scope: new builder component (separate namespace/SA), build status on the
environment, registry integration. Out of MVP by construction.

Depends on: 9.

## MVP recommendation

**MVP = Issues 2, 1, 3, 4, 5 (+ 6 in reduced admin-only form).** Govern the
existing passthrough, then catalog-backed named environments compiling to
governed `runtime_env` YAML on RayJobs. No image builds in MVP: zero new
infrastructure, copies two proven in-repo patterns (storage catalog
resolution, profile expansion), and the catalog shape carries forward
unchanged when image builds arrive.

Triggers that should force the image-build conversation: compiled/native deps
(CUDA, GDAL), cold-start complaints cache tuning can't fix, or a compliance
requirement for pre-scanned immutable artifacts.

## Open decisions

- User-submitted draft environments vs admin-only catalog — recommend
  admin-only for MVP (Issue 6), matching profiles.
- ~~New requirement number for traceability~~ — resolved (#56): row 19,
  `r19_environments`.
