# ADR-0007: Server-side image builds are deferred behind a go/no-go; generated Containerfiles only if we go

Status: accepted · 2026-09-13 · Implements the design gate called for by the governed-environments epic (docs/epics/2026-09-12-governed-environments.md, Issue 9; issue #60)

## Context

The environments MVP (issues #52–#58) composes a workload's environment at
admission: a named catalog entry compiles to governed `runtime_env` YAML —
allowlisted base image, pinned pip packages, env vars — installed on the
nodes at job start. That covers the pure-Python long tail. It does not cover:

- **Compiled/native dependencies** (CUDA stacks, GDAL, system packages) —
  pip wheels assume system libraries the base image may not have, and
  `runtime_env` cannot install them.
- **Cold-start latency** that per-node caching cannot fix — first install on
  a fresh node re-pays the full download+install; for large stacks this is
  minutes per node (the cache is per-node, 10 GiB default, LRU-evicted).
- **Compliance postures** that require pre-scanned, immutable artifacts
  rather than packages fetched at run time.

The epic scoped the answer as a server-side build pipeline: the platform
builds an image per environment, scans it, signs it, and adds its digest to
the project's allowed prefixes. This ADR records the build-technology
decision and the conditions under which we build it at all.

### Options considered

1. **External CI builds + prefix allowlist (status quo+).** Users/CI build
   images outside Bifrost; `AllowedImagePrefixes` already governs what runs.
   Zero new platform infrastructure. The cost is UX and governance: no
   catalog integration, no uniform scan/sign story, and every org wires its
   own pipeline.
2. **kaniko in-cluster.** Daemonless container builds as pods. Runs builds as
   root inside the container and needs registry push credentials — a build
   pod is code execution with registry write. Confinement is possible but the
   privilege story is weak.
3. **buildah.** Similar capability, similarly needs privileges (or fiddly
   user-namespace setup) for real Dockerfiles.
4. **Rootless BuildKit.** Builds as an unprivileged user in rootless mode,
   daemon-per-build, no host docker socket. The best isolation posture of the
   in-cluster options; the operational cost is a builder StatefulSet/namespace
   and rootless-mode sharp edges (storage driver, network).

In every in-cluster option the blast radius is dominated by one fact: **a
build executes the thing being built.** The security model therefore matters
more than the tool: generated Containerfiles only (`FROM` an allowlisted base
+ `RUN pip install` lines the platform writes — never user-authored
Dockerfiles), a dedicated builder namespace with its own ServiceAccount,
egress restricted to the platform package proxy, digest-pinned immutable
tags, cosign-signed outputs, and the scan gate (#58) before the environment
can leave draft.

## Decision

- **Do not build the pipeline yet.** The MVP's residual risks (pip supply
  chain, cold start) are currently mitigated by pinned versions, the package
  denylist, the package-proxy egress rule, and the scan gate. Building the
  pipeline now would be infrastructure without usage evidence.
- **Triggers that re-open this ADR** (any one suffices): real demand for
  compiled/native dependencies; measured cold-start pain that cache tuning
  cannot fix; a compliance requirement for pre-scanned immutable artifacts.
- **If triggered, the choice is rootless BuildKit** in an isolated namespace,
  building **generated Containerfiles only**, with digest-pinned references
  stored on the environment and cosign signatures verified at admission.
  kaniko and buildah are rejected on builder privilege; external-CI-only is
  rejected as the long-term UX (it remains the supported path today).
- The catalog shape already carries this forward unchanged: an environment
  with a built image is an entry whose `base_image` is the built digest —
  resolution (#55), the scan gate (#58), and the audit trail (#57) all keep
  working without model changes.

## Consequences

- Issue #61 (pipeline implementation) stays open and blocked on this ADR's
  triggers; the spike, when scheduled, should validate rootless BuildKit on
  the kind lane and produce the builder-namespace threat model before any
  implementation PR.
- Operators who need custom images today use the external-CI path; r10
  already proves externally-built images run, and the admission allowlist +
  per-environment scan verdict give governance over them.
- The UX gap (users who don't know how to build images) is absorbed by the
  catalog + console picker (#59) rather than by platform builds.
