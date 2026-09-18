# Custom images for Ray — Design Spec (catalog · inspect · build)

**Status:** revised 2026-09-17 after review. Scope split: Bifrost owns
**environment overlays** (a base image plus a Ray `runtime_env` fragment,
no image build — shipped, see §0), the **image catalog**, **admission** and
**inspect** (shipped, see §0); the **image builder** (§5) moves to Artifact
Keeper, where the base-image mirror, the package proxies, the scanner and
the push target already live, with Bifrost consuming the built image through
the webhook in §4.2. Originally: draft produced 2026-09-17 from bifrost main `09bb854`,
bifrost-ui main, artifact-keeper main, and a live read of the grace deployment.
**Repos touched:** `bifrost` (Go control plane), `bifrost-api` (contract),
`bifrost-ui` (console), `artifact-keeper` (OCI metadata enrichment, optional
but recommended), `artifact-keeper-web` (shared inspect component, optional),
`bifrost-pack` (BuildKit RBAC, registry credential, AK webhook).
**Requirements served:** #7 (admins control which images run — today a prefix
allowlist with no UI), #10 (environments on the cluster — currently "blocked on
nebi + Artifact Keeper"), and the image half of #18 (the images Ray runs are
scanned and traceable).

The ask, in one sentence: *an administrator or developer should be able to see
which images are approved for Ray, look inside one without pulling it, compose a
new one from a form rather than a Dockerfile, build it inside the cluster, and
pick it when starting a cluster or job — with Artifact Keeper as the registry
of record and the scanner.*

---

## 0. Where this stands (2026-09-17, bifrost main)

- **Environment overlays are already on main as row 19** (governed
  environments, #52–#58, `docs/epics/2026-09-12-governed-environments.md`):
  a published catalog entry with `base_image`, pinned `packages`,
  `env_vars`, an escape-hatch `runtime_env_yaml`, lifecycle
  (draft/published/deprecated), publish audit and a recorded scan verdict
  with an admission gate. That supersedes the "overlay" package this spec
  proposed; nothing more to build there.
- **Builds are deferred by ADR-0007** behind a go/no-go, with rootless
  BuildKit and generated Containerfiles as the choice if triggered. This
  spec's §5 stands as the design for that trigger, with one amendment from
  review: the builder belongs in Artifact Keeper (mirror, proxies, scanner
  and push target already live there); Bifrost consumes the built digest as
  a catalog entry.
- **Shipped here:** the **image catalog** (`core.ImageEntry`, policy `images`
  section, `GET /api/v1/images`, `AdmissionRule.catalog_only`, deny reasons
  `image_not_in_catalog` / `image_engine_mismatch`, `ray_version` filled from
  the catalog) and **inspect** (`GET /api/v1/images/{name}/inspect`,
  `internal/registry`: a stdlib OCI distribution client resolving tag or
  digest, index → platform manifest, config blob → env/entrypoint/cmd/user/
  workdir/ports/labels and `history` joined to layers; Bearer-challenge auth
  anonymous or with basic credentials; loopback registries over plain HTTP;
  5 minute cache). `ImageInspect` is the shared JSON shape of §4.1 minus the
  `security` and `bifrost` blocks.
- **Shipped 2026-09-18: image sources.** `core.ImageSource` (policy
  `image_sources`), `GET /api/v1/images/sources` and
  `GET /api/v1/images/sources/{name}/tags` list a registry repository's
  tags (or a registry's whole `/v2/_catalog`) live through
  `internal/registry` (`ListRepositories`, `ListTags`, paginated, same
  Bearer-challenge session as inspect). `serve --image-registries` loads a
  per-host file (`registry.LoadHostsFile`: API address the pod reaches,
  basic credentials or a `password_file`), consulted by inspect and the
  listings, so `localhost:32000` references resolve through the
  in-cluster Service and Artifact Keeper is read with a repository-scoped
  token. The console picks a tag from a source into the catalog form
  (bifrost-ui, same day).
- **Not shipped in bifrost:** pull secrets on pods (D7), digest resolution
  at save (D3), Artifact Keeper scan summary and webhook (§4.2/§4.3),
  registry-host SSRF screening for inspect (the catalog is admin-only; the
  gateway registry's screening in `internal/core/registry.go` is the model
  to reuse). The console half (IMG-C) shipped in bifrost-ui the same day:
  Images page, inspect dialog, approved-image picker, catalog and
  environments editors, submit-job form.
- **The builder moved to Artifact Keeper (2026-09-17, branches
  `feat/image-builder` in artifact-keeper and artifact-keeper-web).** The
  spike on grace settled both unknowns: rootless BuildKit v0.33 runs on the
  microk8s node with only seccomp/AppArmor unconfined on its own container
  (no privileged flag, despite Ubuntu's unprivileged-userns restriction),
  and it pushes into an Artifact Keeper Docker repository (`ray`, created
  for this) with a SLSA v1 provenance attestation whose `mode=max` payload
  embeds the Dockerfile at
  `predicate.runDetails.metadata.buildkit_metadata.source.infos[].data`.
  What the branches add: `GET /repositories/{key}/image-inspect` (the §4.1
  document read from the registry's own storage, plus the real Dockerfile
  from provenance), `/repositories/{key}/image-builds` (structured spec →
  deterministic Containerfile → `buildctl` against `AK_BUILDKIT_ADDR` →
  push as the requesting user via a short-lived API token, with
  `attest:provenance=mode=max`), and in the console a Build tab with a New
  image wizard whose Containerfile preview is the server's dry run, plus an
  Image tab on every manifest. The builder is a client of buildkitd, not a
  sidecar: buildkitd is its own Deployment (`~/deploy/buildkitd.yaml` on
  grace, namespace `image-builder`) and the backend only ships `buildctl`.
  Bifrost's remaining piece is the webhook that turns a pushed build into a
  catalog entry (§4.2 item 5).

- **Proven end to end on grace (2026-09-18).** An image built by the
  Artifact Keeper builder (`rayproject/ray:2.56.0` + a pip package) was
  browsed into Bifrost through an image source, added to the catalog, pulled
  by the node from `artifacts.100-89-230-107.sslip.io` and run as a Ray job
  through Bifrost. What that took, and what it means for the design: the
  node's containerd trusts the cluster CA through a `certs.d/<host>/hosts.toml`
  (a pack or node-bootstrap item, not code); the Artifact Keeper repository is
  publicly readable because pods carry no pull secret (D7 remains the proper
  fix); Bifrost reaches the registry API over the in-cluster HTTP address via
  the `--image-registries` file, so the control plane needs no CA either.
  Nodes without AVX2 need `polars-lts-cpu`-style wheels — a reason the wizard
  should surface the target node architecture in the future.

## 1. Load-bearing facts (verified in code and on grace)

### 1.1 Bifrost today

1. **An image is a bare string.** `ClusterSpec.Image`, `RayJobSpec.Image`,
   `Profile.Image`, `ServiceSpec.Image` are all `string`
   (`internal/core/{cluster,rayjob,profile,service}.go`). Nothing resolves a
   tag to a digest; nothing records platform, Ray version, or provenance.
2. **Admission is a prefix match.** `internal/api/admission.go` `Check` admits
   a spec if `strings.HasPrefix(spec.Image, p)` for any `p` in the project's
   `allowed_images` (or the `"*"` rule). The rule lives in the policy row
   (`controller.StoredPolicy.Admission`, edited through
   `PUT /api/v1/settings/policy`, section-replace, plan ruling D7). A prefix of
   `rayproject/ray` admits every tag ever published under that name.
3. **Ray version is guessed from the tag.** `RayJobSpec.RayVersion` is filled
   "from the image tag" at the edge. A custom image tagged a non-numeric suffix (the second checkmaite tag on grace)
   (the checkmaite image on grace) already defeats that heuristic.
4. **No registry credentials reach pods.** `internal/provision/kuberay.go`
   `podTemplate` sets no `imagePullSecrets`; grace works only because every
   image is public (Docker Hub) or on the node-local microk8s registry
   (`localhost:32000`). A private Artifact Keeper repo cannot be pulled today.
5. **Any Ray image runs.** Defect 2 (wget probes) is fixed; probes use
   `python`, which every Ray image has. This is the provisioner-side blocker
   row 10 said was cleared, and it is.
6. **The console has no image or profile UI.** `bifrost-ui/src/routes/settings.tsx`
   edits prices and quotas only; there is no profile catalog editor, no
   admission editor. `cluster-new.tsx` has a free-text `Image` input with a
   per-engine default (`defaultImageFor`). No `profile` picker exists in the
   UI at all (grep is empty).
7. **The catalog pattern already exists twice.** `Profile` and `StorageEntry`
   are both named catalog entries with a `projects` scope, stored on the policy
   row, validated as a unit at edit, and resolved at admission into a persisted
   `Resolved*` shape so a later catalog edit is never retroactive. An image
   catalog should be the third instance of the same pattern.
8. **Contract first.** Every new operation or schema lands in
   `bifrost-api/openapi.yaml`, regenerates `zz_generated_api.go` and the
   TS/Python SDKs, needs `permissions.yaml` rows and a body builder in the
   r03 RBAC matrix, and a requirement test package. That is process, not risk,
   but it sets the minimum size of package IMG-A.

### 1.2 Artifact Keeper today (source + grace)

| Capability | Where | Relevance |
|---|---|---|
| Full OCI distribution API: push, pull, chunked upload, `/v2/_catalog`, token auth at `/v2/token`, optional anonymous pull | `backend/src/api/handlers/oci_v2.rs` | Registry of record for built images; BuildKit pushes here |
| Docker Hub pull-through (`AK_DEFAULT_DOCKER_MIRROR_REPO`, remote repos) | `oci_v2.rs` ~2828 | `rayproject/ray` base images can be mirrored, cached, and scanned in-house |
| Server-side tag rollup: `GET /api/v1/repositories/:key/artifacts?group_by=docker_tag` with true multi-arch size and scan status | AK #1336; consumed by `docker-tag-list.tsx` | Bifrost's catalog page can list tags without walking manifests |
| Scans (Trivy + Grype), findings API, per-artifact scan list, quarantine/policy engine, `block_unscanned` | `handlers/security.rs` | "Authorized to run" can include "scan gate passed" |
| SBOM generate/list/components/by-artifact, Dependency-Track projects | `handlers/sbom.rs`; `artifact-keeper-dtrack` pod on grace | The "what is in this image" package list, without running it |
| Webhooks (`artifact_uploaded`, `artifact_deleted`, …) with HMAC secret, deliveries, redeliver | `handlers/webhooks.rs` | Push → Bifrost re-resolves digest / auto-registers a built image |
| Service accounts with tokens; SSO via Keycloak | `handlers/service_accounts.rs`, `sso.rs` | Machine credential for Bifrost and for the builder |
| PyPI and Conda remote/proxy repos | format handlers | Builds can fetch packages through AK: no direct egress needed |

**The gap that matters:** `backend/src/formats/oci.rs` `parse_metadata` records
only `schemaVersion`, `mediaType`, `config{digest,size}` and `layerCount`. It
never opens the image **config blob**, so Artifact Keeper does not know an
image's `Env`, `Entrypoint`, `Cmd`, `User`, `WorkingDir`, `Labels`, or its
`history[]` (the per-layer `created_by` instructions). Its web UI reflects
this: `package-metadata-viewer.tsx` shows `[architecture, os, config, layers,
mediaType]` for docker and there is no config or history view. The "docker
inspect" experience the user wants does not exist on either side yet, which is
exactly why it is the right thing to build once and share (§4).

### 1.3 grace inventory (2026-09-17)

| Item | Value |
|---|---|
| Kubernetes | microk8s v1.35.6, containerd 2.1.6, Ubuntu 26.04, kernel 7.0 |
| Node | 40 CPU, ~108 GiB RAM, **no GPU**, amd64 only |
| Artifact Keeper | `https://artifacts.100-89-230-107.sslip.io`, backend + web + trivy + scanner-adapter + dependency-track + opensearch + postgres, all running |
| AK repositories | **one**: `hf-internal` (huggingface, local). **No Docker/OCI repo exists yet.** |
| Ray images in use | `rayproject/ray:2.56.0` (Docker Hub), `localhost:32000/checkmaite-api:2.56.0-r1` and a second checkmaite tag (microk8s built-in registry) |
| Bifrost | `bifrost.100-89-230-107.sslip.io` (UI), `bifrost-api.…` (API), sqlite store, `--namespace=bifrost`, no `--allowed-images` set |
| Pull secrets in `bifrost` ns | none |
| nebi | not present (no binary, no CRD) |

Consequence: the first grace step is administrative, not code: create an AK
Docker repo (`ray`), a Docker Hub mirror repo, and a service account; then
re-tag the checkmaite Ray image into AK so Bifrost has something real to
catalog and scan.

---

## 2. Decisions (proposed; each needs a ruling, see §7)

- **D1 — The image catalog is the third policy-row catalog.** `StoredPolicy`
  gains `Images []core.ImageEntry`, edited through the existing
  `PUT /api/v1/settings/policy` section-replace (`images:` present replaces
  the section) and listed project-filtered by a new
  `GET /api/v1/images`. No new CRUD surface for the catalog itself: it follows
  profiles and storage exactly.
- **D2 — Specs keep `image: string`; the catalog pins it.** A user picks a
  catalog entry; the client sends `image: "<registry>/<repo>@sha256:…"` (the
  entry's resolved `ref@digest`). No spec schema change, no client breakage.
  Admission gains one per-project switch, `catalog_only: bool`: when set, the
  spec's image must equal a catalog entry's pinned reference (digest match),
  otherwise the prefix allowlist applies as today. Profiles may name an
  `image_name` from the catalog; expansion (D4 of the build-out plan) fills
  `image` and `ray_version` from the entry.
- **D3 — Every entry carries an explicit `ray_version`, `python_version`,
  `engine`, `platforms`.** Nothing is inferred from a tag any more. The
  catalog resolves tag → digest at save time and again on an AK
  `artifact_uploaded` webhook for that repo/tag ("track tag" mode) or never
  ("pinned" mode); the mode is per entry.
- **D4 — Inspect is one JSON shape, parsed once.** A normalized `ImageInspect`
  document (§4.1) is the contract. Artifact Keeper's OCI handler becomes the
  canonical producer (it already has the config blob on disk at push time; a
  small Rust change in `parse_metadata`). Bifrost exposes
  `GET /api/v1/images/{name}/inspect`, which reads AK's enriched metadata when
  the entry's registry is AK and otherwise fetches manifest + config itself
  with go-containerregistry using the entry's pull credential, caching by
  digest. Either way the console renders the same document.
- **D5 — Builds are structured, not free-form.** An `EnvSpec` (§5.1) is the
  stored object; the Dockerfile is rendered from it by a deterministic
  template and stamped into the image as the OCI label
  `dev.bifrost-compute/env-spec` (JSON) plus `org.opencontainers.image.*`
  labels. Inspect shows the exact spec for Bifrost-built images and the
  reconstructed history for foreign ones. A raw-Dockerfile escape hatch is an
  admin-enabled flag, default off.
- **D6 — Builder is rootless BuildKit as a Kubernetes Job, driven by a
  reconciler.** `ImageBuild` is a new stored resource kind with the same
  level-triggered observe-and-repair loop clusters and jobs have; the Job
  translator lives in `internal/provision` (the only package that talks
  Kubernetes). Base images and pip/conda packages resolve through AK proxy
  repos, so build pods need no egress beyond the cluster.
- **D7 — Registry credentials are catalog data delivered as pull secrets.**
  An entry may name `pull_secret` (a `kubernetes.io/dockerconfigjson` Secret
  in the workload namespace, same delivery model as #12 storage secrets). The
  provisioner adds it to head, worker and submitter pod specs. A deployment
  default `--registry-pull-secret` covers the common single-registry case.
- **D8 — nebi authors specs; Bifrost builds and catalogs.** `EnvSpec` is
  deliberately shaped as the object an environment manager produces. When nebi
  exists it becomes a spec source (`source: nebi`, with the nebi environment
  id); nothing in this design waits on it. Row 10 can move from "blocked" to
  "built; nebi as spec source pending".

---

## 3. Architecture

```
bifrost-ui ─┬─ Images page ── catalog table (scan badge, digest, ray/py, projects)
            ├─ Image drawer ── <OciInspect> (config · history · layers · SBOM · CVEs)
            ├─ Env editor ──── EnvSpec form → Dockerfile preview → Build
            └─ cluster-new / job-new ── image picker (catalog entries the project may use)
                    │  generated client (bifrost-api)
                    ▼
bifrost  internal/api      GET /images · GET /images/{name}/inspect
                           POST /images/builds · GET /images/builds/{id} · GET …/logs (WS, via gateway)
                           PUT /settings/policy {images: […], admission: {catalog_only}}
         internal/policy   admission: catalog match → prefix fallback; scan-gate check (§4.3)
         internal/controller  StoredPolicy.Images · ImageBuild rows · BuildReconciler
         internal/provision   imagePullSecrets on pod templates · BuildKit Job translator · observe
         internal/registry (new, pure client)  go-containerregistry: manifest/config/history fetch, digest resolve
                    │                                        │
                    ▼                                        ▼
Artifact Keeper  /v2 (push/pull, token) · /api/v1 (tag rollup, scans, SBOM, webhooks) · docker-hub mirror · pypi/conda proxies
```

Boundary rules preserved: `core` stays stdlib-only (`ImageEntry`, `EnvSpec`,
`ImageBuild` are plain structs); only `provision` imports client-go; the new
`internal/registry` package speaks HTTP to registries and is the only place
go-containerregistry appears (depguard rule added).

---

## 4. Inspect, and what is shared with Artifact Keeper

### 4.1 `ImageInspect` (the shared JSON contract)

```jsonc
{
  "reference": "artifacts.example/ray/checkmaite:2.56.0-r2",
  "digest": "sha256:…",              // manifest (or index) digest
  "platforms": [{"os":"linux","architecture":"amd64"}],
  "size_bytes": 4123456789,
  "config": {                         // from the image config blob
    "env": {"PATH":"…","RAY_USAGE_STATS_ENABLED":"0"},
    "entrypoint": [], "cmd": ["/bin/bash"],
    "user": "ray", "working_dir": "/home/ray",
    "exposed_ports": ["8265/tcp"],
    "labels": {"org.opencontainers.image.source":"…", "dev.bifrost-compute/env-spec":"{…}"}
  },
  "history": [                        // one row per config.history entry, layer digest joined where !empty_layer
    {"created_by":"RUN pip install --no-cache-dir ray[default]==2.56.0", "layer_digest":"sha256:…", "size_bytes":812345678, "empty_layer":false, "created":"…"}
  ],
  "layers": [{"digest":"sha256:…","size_bytes":…,"media_type":"…"}],
  "bifrost": {                        // present only when the label decodes
    "env_spec": { … EnvSpec … }, "build_id": "…", "rendered_dockerfile": "…"
  },
  "security": {                       // present only when the registry is Artifact Keeper
    "scan_status": "passed|failed|pending|not_scanned",
    "critical": 0, "high": 3, "medium": 12,
    "scan_url": "https://artifacts…/repositories/ray/…#security",
    "sbom_id": "…", "sbom_url": "…", "components": 412
  },
  "source": "artifact-keeper|registry"  // which producer filled the document
}
```

Two facts drive the shape. First, a Dockerfile cannot be recovered from an
image, but `history[].created_by` for any BuildKit- or docker-built image is
the instruction list, so the "graphical Dockerfile" view is an honest
rendering of `history` with sizes attached, and an exact rendering of
`bifrost.env_spec` when present. Second, everything above the `security`
block is derivable from two registry GETs (manifest, config), so a non-AK
registry degrades gracefully instead of failing.

### 4.2 What is shared, concretely

1. **The `ImageInspect` schema.** Defined once, in `bifrost-api` under
   `components/schemas/ImageInspect`, and mirrored as the JSON Artifact Keeper
   stores in `artifact.metadata` for OCI manifests. Both UIs render the same
   document; a Bifrost-built image looks identical in the AK console and the
   Bifrost console.
2. **The parser, in Artifact Keeper.** Extend `OciHandler::parse_metadata`
   (Rust, ~150 lines): after a manifest is stored, load the config blob by
   digest, decode `config`, `history`, `rootfs.diff_ids`, join layers, and
   write the `ImageInspect` fields into metadata. This is a pure win for AK
   (its own docker tag dialog gets env/entrypoint/history for free), costs
   Bifrost nothing at read time, and needs no registry credentials in
   Bifrost for AK-hosted images. Bifrost's go-containerregistry path remains
   for foreign registries and as the fallback when AK is older.
3. **The React inspect component.** `bifrost-ui` (Vite + shadcn) and
   `artifact-keeper-web` (Next.js + shadcn) share the same component
   vocabulary. A small package, `@bifrost-compute/oci-inspect`, exporting
   `<OciInspect doc={ImageInspect} />` with tabs *Overview · Dockerfile view ·
   Layers · Environment · Security*, headless enough to take the host's
   `Badge`/`Tabs`/`Table` via props. Recommended but optional (§7 R5); if not
   shared, the same component is written once in bifrost-ui and ported later.
4. **Scanning is not duplicated.** Bifrost never runs Trivy. It reads AK's
   per-tag rollup (`group_by=docker_tag` gives `scan_status`), deep-links to
   the AK security tab, and (§4.3) can make admission depend on it.
5. **Webhooks close the loop.** An AK webhook (`artifact_uploaded` on the
   Ray repo, HMAC-verified with `AK_WEBHOOK_SECRET_KEY`) hits
   `POST /api/v1/images/webhooks/artifact-keeper`; Bifrost re-resolves
   tracked tags and marks pinned entries "newer tag available". Builds push
   and then wait for this event rather than polling.
6. **Package proxies make builds air-gapped.** Builder pods fetch base images
   from the AK Docker Hub mirror and wheels/conda packages from AK PyPI/Conda
   remote repos, so the tenant NetworkPolicy's "DNS and intra-cluster only"
   egress stance holds for builds as well.

### 4.3 Scan gate as admission (the "authorized to run with Ray" question)

"Authorized" becomes a conjunction, all evaluated at create time and written
to the audit row on deny:

1. the image resolves to a catalog entry the project may use (`catalog_only`), or matches the prefix allowlist (legacy);
2. the entry's `min_scan_status` (per project rule; default `not_required`) is met using AK's rollup, e.g. `passed` or `no_critical`;
3. the entry's `engine` and `ray_version` are compatible with the spec (Ray head and workers must share a Ray version; the catalog now knows it).

Deny reasons: `image_not_in_catalog`, `image_scan_gate`, `image_engine_mismatch`.

---

## 5. Builds

### 5.1 `EnvSpec` (stored; the thing the GUI edits)

```jsonc
{
  "name": "team-a-genomics",
  "base": {"ray_version":"2.56.0", "python":"3.11", "variant":"cpu|cu124|cu128", "image": null},  // image overrides the rayproject/ray computed ref
  "apt": ["libgomp1"],
  "conda": {"channels":["conda-forge"], "packages":["samtools=1.20"]},
  "pip": {"packages":["scanpy==1.10.2","polars"], "index": "https://artifacts…/api/pypi/pypi-proxy/simple"},
  "env": {"OMP_NUM_THREADS":"1"},
  "files": [{"path":"/home/ray/config.yaml","configmap":"team-a-ray-config","key":"config.yaml"}],
  "run": [],                        // extra RUN lines; only when admission.allow_raw_run
  "labels": {"team":"a"},
  "source": {"kind":"console|nebi|api", "ref": null}
}
```

The renderer is a single Go template producing a Dockerfile of the form
`FROM <mirror>/rayproject/ray:<ray>-py<py>[-<variant>]` → `USER root` → apt →
`USER ray` → conda → pip → `ENV` → `COPY` → labels. Deterministic output means
the "Dockerfile preview" in the GUI is byte-identical to what gets built, and
the rendered text is also stored on the `ImageBuild` row.

### 5.2 `ImageBuild` resource and reconciler

- `POST /api/v1/images/builds {env_spec, target: {repo, tag}, project}` →
  `202 {id}`; Developer or Admin, project-scoped like `submit_job`.
- Store row: id, project, owner, env_spec, rendered_dockerfile, target,
  phase (`pending|building|pushing|scanning|succeeded|failed`), digest,
  started/finished, failure reason. Same crash-safety rule as clusters: phase
  is re-observed from the Job on every pass, never trusted.
- Provisioner translator: a `batch/v1 Job` in the control-plane namespace
  running `moby/buildkit:rootless` with `BUILDKITD_FLAGS=--oci-worker-no-process-sandbox`,
  `securityContext: {runAsUser: 1000, seccompProfile: Unconfined, appArmorProfile: Unconfined}`,
  no privileged flag; the Dockerfile and any `files` are mounted from a
  ConfigMap; the push credential is a projected Secret holding the AK
  service-account token as a `config.json`. Labels `bifrost-compute.dev/build=<id>`
  and the owner label so the tenant NetworkPolicy and the run-prefix postflight
  sweep already cover it.
- Logs: the Job's pod log stream is proxied through the existing gateway
  WebSocket path (`gateway_ws.go`), keyed `build-<id>.<--gateway-domain>`,
  same credential strip-and-swap as job log tails.
- On success the reconciler resolves the digest (webhook or direct GET),
  creates or updates the catalog entry with `source: built`, `build_id`, and
  waits for AK's scan rollup before flipping phase to `succeeded` (so the
  scan gate is meaningful the moment the image appears in the picker).

### 5.3 Console

- **Images** (new route): table from `GET /api/v1/images` joined with AK's
  tag rollup: name, reference (short digest, copy), Ray/Python, platforms,
  scan badge, projects, source (built / external / nebi), "newer tag" hint.
  Row click opens the inspect drawer (`<OciInspect>`).
- **New environment**: the `EnvSpec` form with a live Dockerfile preview on
  the right, a "Build" button, and a build-progress panel streaming logs.
- **Profiles and admission editors** (currently missing entirely): needed so
  admins can set `catalog_only` and `min_scan_status` per project and point
  profiles at catalog entries without hand-editing JSON.
- **Cluster / job creation**: replace the free-text image input with a
  picker filtered by project and engine; "advanced: raw image" remains when
  the project is not `catalog_only`.

---

## 6. Work packages and estimates

Branches `feat/img-<pkg>`, one worktree and PR per package, same conventions
as the 2026-09-02 build-out plan. A and E have no code dependency on each
other and can start together; B and C depend on A; D depends on A and B.

| Pkg | Scope | Repos | Estimate |
|---|---|---|---|
| **IMG-A** catalog + admission + pull secrets | `ImageEntry`, `StoredPolicy.Images`, `PUT /settings/policy images:`, `GET /images`, `catalog_only`/`min_scan_status` rules, digest resolution (`internal/registry`), `imagePullSecrets` on pod templates, `--registry-pull-secret`, permissions.yaml + r03 bodies, `r07` tests for catalog admission, `r10` tests for pull-secret delivery on kind | bifrost, bifrost-api, bifrost-pack | 1.5–2 weeks |
| **IMG-B** inspect + AK integration | `ImageInspect` schema, `GET /images/{name}/inspect`, AK client (tag rollup, scans, SBOM), webhook receiver, AK `parse_metadata` enrichment PR | bifrost, bifrost-api, artifact-keeper | 1–1.5 weeks (AK PR ~2 days of it) |
| **IMG-C** console | Images route, `<OciInspect>`, image picker in cluster-new/job-new, profile + admission editors in Settings | bifrost-ui (+ optional shared package) | 1.5–2 weeks |
| **IMG-D** builds | `EnvSpec`, renderer + golden tests, `ImageBuild` store + reconciler, BuildKit Job translator + observe, log WS route, `POST /images/builds`, env editor + build panel UI, `r10` build test on kind (pushes to an in-cluster registry) | bifrost, bifrost-api, bifrost-ui, bifrost-pack | 3–4 weeks |
| **IMG-E** grace rollout | AK repos (`ray` local, `docker-hub` mirror, `pypi-proxy`, `conda-proxy`), service account + token, webhook to Bifrost, anonymous pull on `ray`, retag `checkmaite-api` into AK, seed catalog, verify BuildKit rootless on the microk8s node | grace, bifrost-pack values | 2–3 days |

Total: roughly 7–9 weeks of implementer time; the user-visible "pick an
approved image, see inside it" slice (A + B + C) lands in about 4 weeks, with
builds following.

---

## 7. Rulings needed before A starts

- **R1** `catalog_only` default for new deployments: off (legacy prefix rule stays the default) or on for `"*"`? Recommend **off**, on for grace once the catalog is seeded.
- **R2** Raw Dockerfile / free `RUN` lines: admin-enabled per project, default off? Recommend **yes, default off**.
- **R3** Who may build: Developer (project-scoped, like `submit_job`) or Admin only? Recommend **Developer**, with builds counted against the project's quota as a CPU-hours line item.
- **R4** Canonical inspect parser in Artifact Keeper (Rust PR) with Bifrost fallback, or Bifrost-only? Recommend **both**, AK first.
- **R5** Ship `<OciInspect>` as a shared package now, or write it in bifrost-ui and extract later? Recommend **bifrost-ui first, extract when AK web adopts it**; the JSON contract is the part that must be shared on day one.
- **R6** Supported base matrix for the renderer: Ray `2.56.x` only at first, Python `3.11`/`3.12`, variants `cpu` and `cu124`? grace cannot exercise CUDA variants (no GPU), so they would be built but untested there.
- **R7** Does row 10 get re-titled to "Custom environments and images on the cluster" with nebi as one spec source, or does this become row 19? Recommend **re-title row 10**; it is the same user need.

---

## 8. Risks and how the design contains them

- **Rootless BuildKit on microk8s.** Needs unprivileged user namespaces and either fuse-overlayfs or native rootless overlay. Ubuntu 26.04 / kernel 7.0 has both; verify in IMG-E before IMG-D is estimated further. Fallback: kaniko (no daemon, no userns) with a smaller feature set.
- **Build egress.** The tenant NetworkPolicy admits DNS and intra-cluster only. Routing base images and packages through AK proxies keeps that stance; a direct-egress mode is not offered.
- **Digest drift.** Tracked tags change under users; the entry's `mode` (pinned vs track) and the "newer tag available" hint make the choice visible instead of silent.
- **Ray version skew.** Head, workers and submitter always share one image, so the only skew is between the image's Ray and the client's Ray in Jupyter; the catalog now exposes `ray_version` so the extension can warn.
- **Storage growth in AK.** Built images land on hostpath storage on grace; AK's GC and the `oci-blob-report` cover it, and `ttl_seconds` on a catalog entry can mark experiments for cleanup.
- **Contract surface.** Roughly six new operations and four schemas; each needs RBAC matrix rows and requirement tests, which is why IMG-A is sized at two weeks despite small handler code.

---

## 9. Out of scope

Multi-arch builds (grace is amd64 only), image signing/attestation (AK signs
Debian/RPM/Alpine/Conda today, not OCI; revisit when it does), per-user
private images (entries are project-scoped like everything else), and a
Dockerfile *parser* (we render, we never parse; foreign images are shown via
`history`).
