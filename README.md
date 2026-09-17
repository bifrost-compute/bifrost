# Bifrost

**An open-source, Anyscale-grade control plane for Ray clusters on
Kubernetes, designed to grow to Dask.** Self-serve compute for data scientists, governed serving for
platform teams, and audit-ready operations for the people who answer for it —
without handing your stack to a managed platform.

In Norse myth, Bifrost is the guarded bridge between realms: the only way
across, and someone watches every crossing. That is the design in one
sentence — users get a bridge to real compute in seconds; operators get a
gate where identity, quota, and policy are enforced on every request.

## What it does

- **Self-serve clusters** — a JupyterLab user requests a private Ray cluster
  from a catalog of approved profiles and gets a client address back; no
  shared heads, workers, or object stores; idle clusters are reaped
  automatically.
- **Ephemeral jobs** — submit a job and Bifrost creates a cluster for it,
  runs it, records the outcome, and removes the cluster.
- **A guarded gateway** — callers never talk to Ray directly. The gateway
  terminates the caller's identity, enforces RBAC, and swaps in per-cluster
  credentials southbound, including for the Ray Jobs API and WebSocket log
  tails.
- **Governed model serving** — groups share models through group-owned
  RayService deployments, isolated in their own resource pools so notebook
  workloads can't starve production serving.
- **Admin-controlled profiles and storage** — administrators decide which
  images, CPU / memory / GPU shapes, worker counts, and storage sources users
  may request; users pick from approved options instead of submitting raw
  manifests.
- **Per-project workload identity** — administrators name the Kubernetes
  ServiceAccount each project's clusters, jobs and services run under, so a
  cloud IAM role (EKS Pod Identity, IRSA, GKE Workload Identity) binds to the
  project's pods and no static credential is needed anywhere.
- **Fair-share capacity** — Kueue-backed resource pools with quotas, weights,
  and borrowing between groups.
- **Cost and usage visibility** — who requested what, for how long, and what
  it cost, with tamper-evident audit trails.
- **Crash-safe by design** — ownership is recorded in a persistent store and
  observed state is reconstructed from the cluster on every reconcile pass,
  so the control plane recovers cleanly from its own restarts.

Bifrost composes with the open Ray stack rather than competing with it:
[KubeRay](https://github.com/ray-project/kuberay) is the Kubernetes
substrate, [Kueue](https://kueue.sigs.k8s.io) handles admission, and any
OIDC identity provider (Keycloak, Okta, Dex, …) supplies SSO.

## Architecture

One Go binary, one enforced dependency direction:

```
cmd/bifrost            the binary: serve · login · token · exchange
internal/api           REST surface (spec-first, generated from the frozen
                       contract) + auth middleware + the federating gateway
internal/auth          OIDC discovery, JWKS, RBAC, local users & PATs
internal/controller    persistent store + level-triggered reconcile engine
internal/provision     the ONLY package that talks Kubernetes: typed
                       KubeRay/Kueue translators behind a Provisioner interface
internal/policy        pure functions: quotas, budgets, cost, GPU sharing,
                       engine minimums (Ray's 2Gi per-container memory floor)
internal/core          the domain model — imports nothing but stdlib
```

Invariants the code is built around:

- **Deny by default.** Every route requires authorization; the server fails
  closed if bound to a non-loopback address without auth configured.
- **Credentials stop at the control plane.** User tokens never travel to
  clusters; clusters never see who called.
- **Observation over memory.** The reconciler never trusts a stored phase —
  it re-observes the cluster every pass and repairs drift.
- **Contract-first API.** The OpenAPI 3.1 contract is frozen in
  [`bifrost-api`](https://github.com/bifrost-compute/bifrost-api); the
  server's handlers are generated from it, so the spec and the code cannot
  drift apart. TypeScript and Python SDKs are generated from the same file.

## Status

Fifteen of the eighteen requirement rows in [`docs/SPEC.md`](docs/SPEC.md)
are built. That covers self-serve clusters, ephemeral jobs, the guarded
gateway, group model serving in its own resource pool, admin-controlled
profiles and storage, Kueue-backed pools with quotas, usage metering, the
audit chain, cluster health without Kubernetes access, and the JupyterLab
extension. Each row has a requirement test package under
[`test/requirements/`](test/requirements/) that runs in process, against a
kind cluster in CI, and against a live cluster, so "built" means proven on
real Kubernetes rather than asserted.

The full stack has been deployed end to end on a Kubernetes test
environment with Keycloak SSO, JupyterLab integration, per-owner network
isolation, and Grafana observability.

**Ray is the engine today.** The compute contract is engine-agnostic by
design, but the Dask engine (row 16) and the Slurm scheduler (row 17) are
not built. Row 18, the NIST security baseline, is partial: the audit chain
and a hardened UBI9 image exist, the FIPS variant does not.

Container images publish to `ghcr.io/bifrost-compute/bifrost` on every push
to `main`. The Helm chart lives in
[`bifrost-pack`](https://github.com/bifrost-compute/bifrost-pack).

## Development

```bash
make build    # CGO_ENABLED=0 — ships as a single static binary
make test     # race-enabled full suite
make cover    # coverage report
make lint     # golangci-lint (errcheck, exhaustive, depguard boundaries)
```

Go ≥ 1.25. No cgo in shipped binaries; pure-Go SQLite for dev, Postgres for
production. Start with [`docs/SPEC.md`](docs/SPEC.md) for the program
specification and [`docs/adr/`](docs/adr/) for the decisions and their
evidence.

## Related repositories

| Repo | What it holds |
|---|---|
| [`bifrost-api`](https://github.com/bifrost-compute/bifrost-api) | The frozen OpenAPI 3.1 contract and the generated TypeScript and Python SDKs |
| [`bifrost-ui`](https://github.com/bifrost-compute/bifrost-ui) | The management console (React), built entirely on the generated client |
| [`bifrost-jupyter`](https://github.com/bifrost-compute/bifrost-jupyter) | JupyterLab extension to start, stop, and connect to clusters |
| [`bifrost-pack`](https://github.com/bifrost-compute/bifrost-pack) | Helm chart and Nebari pack for deploying the whole stack |

## License

Apache-2.0.
