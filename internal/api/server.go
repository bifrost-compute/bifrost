package api

import (
	"context"
	_ "embed"
	"net/http"
	"sync"
	"time"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/provision"
	"github.com/bifrost-compute/bifrost/internal/registry"
)

// SpecPath is where the vendored OpenAPI contract is served. The Rust predecessor's
// lib.rs mounts its live-generated spec at exactly this path
// (`SwaggerUi::new("/docs").url("/api/v1/openapi.json", ...)`), and the
// frozen bifrost-api contract doesn't document a path for itself (a
// spec's own serving location is necessarily out-of-band), so this
// carries the legacy path forward rather than inventing a new one — the
// auth middleware's public allowlist matches it exactly.
const SpecPath = "/api/v1/openapi.json"

//go:embed openapi.json
var specJSON []byte

// version is the control-plane semver reported by GET /api/v1/version.
// It tracks the vendored contract's info.version for now; Wave 1 T15
// (the bifrost CLI/binary) may override it at link time the way the Rust predecessor
// used env!("CARGO_PKG_VERSION").
var version = "0.0.1"

// Server implements StrictServerInterface. Every operation is live as of
// Wave 1 T12: T11 ported clusters/registry/settings/access, T12 ported the
// rest (pools/services/cluster_obs/usage/audit/local_auth) — the interface
// compiled complete from day one (ADR-0002, Wave 1 T10) and has now burned
// down to zero ErrNotImplemented stubs.
//
// Every field is exported and independently optional in the sense that a
// caller wires up only what its deployment needs: Provisioner,
// ServiceProvisioner, and Local are each nil-checked by every operation
// that reads them, answering a graceful error (404/502/...) rather than
// touching a nil dependency. Store is the one exception — every real
// deployment configures it, so handlers call straight through to it
// (matching T11's clusters.go/settings.go convention); a Server built
// without one (e.g. a bare NewServer()) only stays safe for operations
// that never reach the Store at all (Healthz, Version, Providers). No
// operation anywhere in this file returns ErrNotImplemented (501)
// anymore — the T11/T12 handler tests exercise the real behavior; a
// caller wiring up a real deployment sets the fields its operations need.
type Server struct {
	// Store is the desired-state store backing clusters/pools/jobs/audit/
	// settings/access. Every operation this wave ports requires it.
	Store controller.Store
	// Registry is the gateway's static routing table (ListRegistry only;
	// mirrors the Rust predecessor's RegistryApiState.registry).
	Registry *core.ClusterRegistry
	// Validator is the configured OIDC validator, when one exists — carries
	// the RoleMappings ListRoles reports. nil in local-auth/dev deployments
	// (mirrors the Rust predecessor's AccessApiState.validator).
	Validator *auth.Validator
	// PolicySeed is the boot-time `--policy` default (the Rust predecessor's
	// ClusterApiState.policy / SettingsApiState.policy_seed): consulted
	// only until the store holds a policy row — see effectivePolicy in
	// settings.go.
	// PolicySeed.Admission carries the `--allowed-images`/`--max-workers`
	// flags as the "*" rule (Admission.SeedRules); PolicySeed.Profiles the
	// `--profiles` catalog. Both are API state once the row exists.
	PolicySeed PolicyConfig

	// Local is the local (IdP-free) authenticator (ADR-0011), when local
	// auth is enabled — login.go/local_auth.go's login/tokens/logout/user-
	// management operations need it. nil when the deployment uses OIDC
	// only (or neither): every local_auth.go operation then answers 404
	// "local auth is not enabled" — see requireLocal — mirroring the Rust
	// reference's router-level absence (the Rust predecessor mounts local_auth's
	// router only when `--local-auth` is set; Go's single generated
	// strict-server has no such conditional mount, so the handler enforces
	// it instead).
	Local *auth.LocalAuthenticator
	// Provisioner backs the cluster observability reads (cluster_obs.go:
	// nodes/events/logs) and the jobs/metrics southbound proxy's dashboard
	// base-URL resolution. nil means "no cluster backend" — those routes
	// answer 404/503 exactly as an unconfigured predecessor deployment does.
	Provisioner provision.Provisioner
	// ServiceProvisioner backs services.go (the Ray Serve CRUD proxy). nil
	// means no service backend is configured.
	ServiceProvisioner provision.ServiceProvisioner
	// JobProvisioner backs the ephemeral RayJob operations (requirement
	// 5). nil means no job backend is configured.
	JobProvisioner provision.JobProvisioner
	// Images reads image manifests and configs for inspect_image (#10).
	// nil = an anonymous client (public and loopback registries).
	Images *registry.Client
	// GatewayDomain is the DNS suffix dynamically registered clusters are
	// exposed under (`<name>.<GatewayDomain>`, plan ruling D1); "" = no
	// dynamic gateway.
	GatewayDomain string
	// GatewayExternalBase is the scheme/prefix clients reach the gateway
	// through (e.g. "https://"), used to build `gateway_url`; "" = none.
	GatewayExternalBase string
	// ServicesPerProject caps concurrently deployed services per project
	// (plan ruling D8); app.New defaults it to 1.
	ServicesPerProject int
	// ObsHTTPClient is the southbound HTTP client cluster_obs.go's jobs and
	// metrics proxies use to reach a cluster's Ray dashboard/Job API. nil
	// falls back to obsHTTPClient()'s default (timeouts + no
	// redirects, mirroring cluster_obs.rs's client). Exists as a field so
	// tests can point it at an httptest server without a real network.
	ObsHTTPClient *http.Client

	// RuntimeEnvUngoverned disables the runtime_env_yaml admission
	// validation (#53), restoring the pre-#53 verbatim passthrough into
	// the RayJob CR. Set only via the --allow-ungoverned-runtime-env
	// DANGER flag; the governed default refuses arbitrary pip indexes,
	// interpreters, per-worker images, and remote working_dir URIs.
	RuntimeEnvUngoverned bool

	// admitMu guards admitLocks (issue #44's per-project admission lock —
	// see clusters.go's withProjectAdmitLock doc comment for what this
	// does and does NOT cover).
	admitMu    sync.Mutex
	admitLocks map[string]*sync.Mutex

	// obsMu guards lazy-initializing obsInflight (cluster_obs.go's
	// jobs/metrics southbound proxy concurrency cap, mirroring
	// cluster_obs.rs's MAX_INFLIGHT semaphore).
	obsMu       sync.Mutex
	obsInflight chan struct{}
}

// obsConnectTimeout/obsReadTimeout mirror cluster_obs.rs's CONNECT_TIMEOUT/
// READ_TIMEOUT: a wedged head must not hang the request.
const (
	obsConnectTimeout = 5 * time.Second
	obsReadTimeout    = 30 * time.Second
)

// NewServer constructs the (currently stateless) skeleton server.
func NewServer() *Server { return &Server{} }

var _ StrictServerInterface = (*Server)(nil)

// Healthz is the liveness/readiness probe. Always 200 "ok", ported
// verbatim from the Rust predecessor's lib.rs healthz().
func (s *Server) Healthz(_ context.Context, _ HealthzRequestObject) (HealthzResponseObject, error) {
	return Healthz200TextResponse("ok"), nil
}

// Version reports control-plane identity + semver. name is always
// "bifrost" — the contract's VersionInfo.name doc says so, and it is the
// rebranded product identity (Global Constraints: "user-visible strings
// say Bifrost").
func (s *Server) Version(_ context.Context, _ VersionRequestObject) (VersionResponseObject, error) {
	return Version200JSONResponse{Name: "bifrost", Version: version}, nil
}

// specHandler serves the vendored contract verbatim at SpecPath.
func specHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(specJSON)
	}
}

// HandlerOptions configures NewHandler's auth wiring. Both Validator and
// Local may be nil (dev mode, matching the Rust predecessor's `validator = None`
// build_router() path) or either/both may be set — mirroring
// the Rust predecessor's `resolve_identity` dispatch (OIDC for JWT-shaped bearers,
// local for opaque `bfr_*` PATs).
type HandlerOptions struct {
	Validator *auth.Validator
	Local     *auth.LocalAuthenticator
	// Registry backs the federating gateway (T13, gateway.go): a Host
	// matching a registered cluster is proxied there instead of reaching
	// the control-plane routes at all, and (middleware.go's
	// host-is-cluster gate) is never treated as public. nil disables the
	// gateway entirely — every request is a control-plane request,
	// exactly as before T13.
	Registry *core.ClusterRegistry
	// Store persists the gateway's per-request audit trail and the
	// host-is-cluster authorization denials RequireAuth emits; nil keeps
	// both trace-only (mirrors the Rust predecessor's gateway-only mode, where no
	// store is configured at all).
	Store controller.Store
	// GatewayLimits overrides the federating gateway's hardening knobs
	// (body cap, inflight cap, timeouts). nil uses DefaultGatewayLimits().
	GatewayLimits *GatewayLimits
	// AllowUnauthenticated permits binding a non-loopback address with
	// no authentication configured (the Rust predecessor's --dev-allow-unauthenticated,
	// ServeOptions.allow_unauthenticated). It does NOT disable
	// deny-by-default when a validator or local authenticator IS
	// configured — it only lifts the fail-closed non-loopback guard
	// when neither is.
	AllowUnauthenticated bool
	// StrictMiddlewares run inside the typed strict-server layer, ahead
	// of any generated handler. Empty by default.
	StrictMiddlewares []StrictMiddlewareFunc
}

// maxControlPlaneBodyBytes bounds request bodies on the control-plane API
// routes (F3a). The gateway path caps its own buffered bodies at 64 MiB
// (GatewayLimits.MaxBodyBytes — job submissions can carry runtime-env
// uploads), but the generated API routes decode JSON bodies with no cap at
// all, so an oversized POST to a public route like /api/v1/auth/login is
// otherwise a straight memory-amplification vector. 4 MiB is far above any
// legitimate control-plane payload (cluster/job specs, policy documents).
const maxControlPlaneBodyBytes int64 = 4 << 20 // 4 MiB

// capControlPlaneBody installs http.MaxBytesReader around every request
// that reaches the control-plane routes. NewHandler installs it INSIDE the
// gateway dispatch (HostGateway), so proxied cluster-host traffic keeps the
// gateway's own 64 MiB buffered-body cap and is never touched by this one.
// An oversized body fails the JSON decode with "http: request body too
// large", which the strict server's RequestErrorHandlerFunc renders as the
// canonical 400 bad_request — a clean 4xx, no memory blowup.
func capControlPlaneBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxControlPlaneBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// maxControlPlaneInflight bounds concurrent in-flight control-plane
// requests (F2 remainder — the slow-body Slowloris gap). The gateway has
// its own inflight cap (GatewayLimits.MaxInflight, 64), but the
// control-plane routes had none: newHTTPServer (cmd/bifrost/serve.go)
// sets ReadHeaderTimeout/IdleTimeout only, so a client that sends headers
// fast and then drips a large body pins a goroutine and an fd
// indefinitely — and a whole-request Read/WriteTimeout is NOT an option,
// because it would kill the gateway's long-lived websocket bridges. 256
// is 4× the gateway's cap: control-plane requests are small JSON calls
// with no streaming surface, so 256 concurrent is far above any
// legitimate load, while capping the goroutine+fd hoard a slow-body
// flood can accumulate at a value the process absorbs trivially.
//
// Residual exposure, documented rather than silently accepted: within a
// held permit a body may still drip forever (no body-read deadline —
// impractical without a whole-request deadline, which the WS bridges
// rule out). The semaphore converts that unbounded hoard into a bounded
// one plus clean 503s; an L4/L7 proxy in front remains the right place
// for a true body-drip deadline.
const maxControlPlaneInflight int64 = 256

// errControlPlaneBusy backs the 503 emitted when the control-plane
// inflight semaphore is exhausted (same status/code shape as the
// gateway's errGatewayBusy, distinct message).
var errControlPlaneBusy = HTTPError{Status: http.StatusServiceUnavailable, Code: "service_unavailable", Message: "control plane busy: too many inflight requests"}

// capControlPlaneInflight wraps the control-plane routes with a
// permits-sized semaphore: excess requests are refused immediately (503)
// rather than queueing, since a queue behind the cap is itself a DoS
// surface. NewHandler installs it INSIDE the gateway dispatch — cluster-
// host traffic is governed by the gateway's own semaphore and never pays
// for this one. Excess requests are refused BEFORE their bodies are
// read, which is exactly the slow-body case this exists for.
func capControlPlaneInflight(permits int64, next http.Handler) http.Handler {
	sem := make(chan struct{}, permits)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			WriteError(w, r, errControlPlaneBusy)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHandler builds the full Bifrost API http.Handler: the generated
// routes plus SpecPath, with the federating gateway (T13, gateway.go)
// spliced in directly ahead of route matching, wrapped by the
// deny-by-default auth middleware and — when neither a validator nor
// local auth is configured and AllowUnauthenticated is false — the
// outermost fail-closed non-loopback guard. Layer order (outermost
// first) mirrors the predecessor's lib.rs build_app_full_svc_inner's: the
// loopback guard, when installed, wraps everything; then auth
// (RequireAuth, which also runs the host-is-cluster gate — see
// middleware.go); then the gateway (HostGateway); then the routes.
func NewHandler(server StrictServerInterface, opts HandlerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+SpecPath, specHandler())

	strict := NewStrictHandlerWithOptions(server, opts.StrictMiddlewares, StrictHTTPServerOptions{
		// A decode/binding error describes the CLIENT's own malformed
		// request (e.g. bad JSON) — unlike WriteError's generic fallback,
		// echoing it back is client-actionable, not a server-detail leak.
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			WriteError(w, r, HTTPError{Status: http.StatusBadRequest, Code: "bad_request", Message: err.Error()})
		},
		ResponseErrorHandlerFunc: WriteError,
	})
	h := HandlerWithOptions(strict, StdHTTPServerOptions{BaseRouter: mux})

	// Contract validation sits directly on the routes: inside auth (so a
	// missing token is 401, not 400) and inside the gateway (a cluster
	// host is never a contract path).
	h = ValidateRequests(h)

	// Control-plane body cap (F3a), login rate limit (F5), and inflight
	// semaphore (F2 remainder): all wrap the control-plane routes only,
	// installed here so the gateway's HostGateway layer (immediately
	// outside) proxies cluster-host traffic with its own limits and never
	// sees any of these guards.
	h = capControlPlaneInflight(maxControlPlaneInflight, h)
	h = capControlPlaneBody(h)
	h = newLoginRateLimiter(defaultLoginRatePerMinute, defaultLoginBurst).middleware(h)

	// The federating gateway sits directly in front of route matching:
	// a Host matching a registered cluster is proxied here and never
	// reaches the mux at all, so a cluster hostname can never be
	// shadowed by a control-plane path (T13's core invariant).
	gatewayLimits := DefaultGatewayLimits()
	if opts.GatewayLimits != nil {
		gatewayLimits = *opts.GatewayLimits
	}
	gw := NewGatewayStateWithLimits(opts.Registry, opts.Store, gatewayLimits)
	h = gw.HostGateway(h)

	h = RequireAuth(AuthState{Validator: opts.Validator, Local: opts.Local, Registry: opts.Registry, Store: opts.Store})(h)

	// Fail-closed (predecessor issue #45): when no authentication is
	// configured at all and it hasn't been explicitly overridden,
	// install the outermost per-request loopback guard so a caller who
	// hands this Handler straight to http.Serve on a non-loopback
	// listener still gets refused, regardless of what the (not-yet-built,
	// T15) CLI's own bind-time check does.
	if opts.Validator == nil && opts.Local == nil && !opts.AllowUnauthenticated {
		h = RefuseNonLoopback(h)
	}

	return h
}
