package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/bifrost-compute/bifrost/internal/api"
	"github.com/bifrost-compute/bifrost/internal/app"
	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/provision"
	"github.com/bifrost-compute/bifrost/internal/provision/live"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// serveOptions holds every --serve flag. Flag names/semantics are ported
// 1:1 from the predecessor CLI's Serve subcommand where the predecessor CLI had an
// equivalent (bind/registry/dev-allow-unauthenticated/
// allow-insecure-transport/reconcile-interval-secs); --store/--db replace
// the Rust predecessor's implicit --db prefix-sniffing with an explicit backend choice
// (see store.go); --namespace replaces --kuberay-namespace (shorter,
// nothing else in this CLI's surface says "kuberay"); --ray-autoscaling is
// new (T15) — it exposes live.NewClient's autoscaling parameter (ADR-0007)
// that the predecessor CLI hardcoded to false at its one call site.
//
// Deliberately NOT ported this wave (see the task report): --demo (mock
// provisioner, no Wave 1 equivalent exists), --policy (governance
// prices/quotas file — Phase 4/Wave 3), --metering-interval-secs (the
// metering loop is an explicit Global-Constraints Wave 3 scope-out),
// --audit-log (a second JSONL sink alongside slog; the audit trail's
// durable form is already the Store via RecordAudit, T11/T12).
type serveOptions struct {
	MeteringInterval        time.Duration
	AllowedImages           string
	MaxWorkers              int
	Profiles                string
	Bind                    string
	Registry                string
	AuthConfig              string
	DevAllowUnauthenticated bool
	AllowInsecureTransport  bool
	AllowPrivateEndpoints   bool
	StoreKind               string
	DB                      string
	Namespace               string
	ReconcileInterval       time.Duration
	Autoscaling             bool
	RayNodeSelector         string
	RayTolerations          string
	LocalAuth               bool
	GatewayDomain           string
	GatewayExternalBase     string
	ServicesPerProject      int
	RuntimeEnvUngoverned    bool
	PackageProxy            string
}

func newServeCmd() *cobra.Command {
	var opts serveOptions
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control-plane API server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Bind, "bind", "127.0.0.1:8484", "Address to bind")
	f.StringVar(&opts.Registry, "registry", "", "JSON cluster registry for the job gateway (see registry.go for the format)")
	f.StringVar(&opts.AuthConfig, "auth-config", "", "JSON OIDC auth config (issuer, audience, role mappings). "+
		"When set, every request needs a valid Bearer JWT and non-loopback binds are permitted")
	f.BoolVar(&opts.DevAllowUnauthenticated, "dev-allow-unauthenticated", false,
		"DANGER: serve without authentication on a non-loopback address. Refused by default")
	f.BoolVar(&opts.AllowInsecureTransport, "allow-insecure-transport", false,
		"DANGER: permit auth tokens over cleartext http:// southbound (local dev only)")
	f.BoolVar(&opts.AllowPrivateEndpoints, "allow-private-endpoints", false,
		"DANGER: permit registry api_base_urls at loopback/unspecified/RFC1918/ULA literal IPs (local dev only)")
	f.StringVar(&opts.StoreKind, "store", "memory", "Desired-state store backend: memory, sqlite, or postgres")
	f.StringVar(&opts.DB, "db", "", "Store DSN: a SQLite file path (--store sqlite) or a postgres:// URL (--store postgres)")
	f.StringVar(&opts.Namespace, "namespace", "",
		"Enable the cluster lifecycle controller: reconcile RayClusters in this Kubernetes namespace via KubeRay")
	f.DurationVar(&opts.ReconcileInterval, "reconcile-interval", controller.DefaultReconcileInterval, "Reconcile resync interval")
	f.BoolVar(&opts.Autoscaling, "ray-autoscaling", false,
		"New clusters default to KubeRay in-tree-autoscaler ownership of worker replicas (ADR-0007); "+
			"per-cluster Kueue-elastic pools always get it regardless of this flag")
	f.StringVar(&opts.RayNodeSelector, "ray-node-selector", "",
		"Node selector every tenant Ray pod (heads, workers, Serve, job submitters) carries, as comma-separated key=value pairs. "+
			"Deployment-wide placement, not per cluster")
	f.StringVar(&opts.RayTolerations, "ray-tolerations", "",
		"Tolerations every tenant Ray pod carries, as a JSON array of Kubernetes tolerations "+
			"(e.g. '[{\"key\":\"hub.jupyter.org/dedicated\",\"operator\":\"Equal\",\"value\":\"user\",\"effect\":\"NoSchedule\"}]'). "+
			"Lets tenant pods land on tainted node groups the control plane is configured for")
	f.DurationVar(&opts.MeteringInterval, "metering-interval", controller.DefaultMeteringInterval,
		"How often a usage sample is recorded per running cluster (requirement 14)")
	f.StringVar(&opts.AllowedImages, "allowed-images", "",
		"Comma-separated image prefixes a cluster may request (requirement 7: administrator-controlled images). Empty = any image")
	f.IntVar(&opts.MaxWorkers, "max-workers", 0,
		"Cap on the sum of max_replicas across a cluster's worker groups (requirement 7). 0 = no cap")
	f.StringVar(&opts.Profiles, "profiles", "",
		"JSON file seeding the profile catalog (requirement 7): a list of ProfileSpec objects. "+
			"Consulted until an administrator sets the catalog via PUT /api/v1/settings/policy")
	f.StringVar(&opts.GatewayDomain, "gateway-domain", "",
		"DNS suffix dynamically registered clusters are exposed under as <name>.<domain> (requirement 5). Empty = static registry only")
	f.StringVar(&opts.GatewayExternalBase, "gateway-external-base", "",
		"Scheme (and optional prefix) clients reach the gateway through, e.g. https://, used to build gateway_url. Empty = not reported")
	f.IntVar(&opts.ServicesPerProject, "services-per-project", 1,
		"Cap on concurrently deployed services per project (requirement 2); deploys beyond it answer 409")
	f.BoolVar(&opts.RuntimeEnvUngoverned, "allow-ungoverned-runtime-env", false,
		"DANGER: pass runtime_env_yaml verbatim into the RayJob CR without the #53 governance validation "+
			"(arbitrary pip indexes, interpreters, per-worker images and remote URIs become reachable from cluster nodes). "+
			"Pre-#53 behavior; an escape hatch for upgraders only")
	f.BoolVar(&opts.LocalAuth, "local-auth", false,
		"Enable local (IdP-free) username/password auth (ADR-0011); counts as configured authentication "+
			"for the fail-closed non-loopback rule")
	f.StringVar(&opts.PackageProxy, "package-proxy", "",
		"Platform package proxy as <ip-or-cidr>:<port> (e.g. 10.96.10.5:3128): workloads whose runtime env "+
			"installs packages get a per-workload egress NetworkPolicy to it under the default-deny tenant posture (#56). "+
			"Empty = no allowance; pip installs then work only against registries the tenant policies already reach")
	return cmd
}

// builtServer is buildServer's result: everything runServe needs to open
// a listener and start the reconcile loops, kept as a struct so the smoke
// test (serve_test.go) can call buildServer directly without binding a
// real socket.
type builtServer struct {
	app        *app.App
	closeStore func() error
	validator  *auth.Validator
	local      *auth.LocalAuthenticator
	// live is the KubeRay/Kueue client (T6), set only when --namespace
	// configures the lifecycle controller. It satisfies
	// provision.Provisioner, provision.PoolProvisioner, and (via
	// live.NewServiceClient) provision.ServiceProvisioner all at once —
	// the one live connection backs the reconciler, the pool reconciler,
	// and the Serve-service routes.
	live *live.Client
}

// buildServer resolves store -> registry -> auth -> (optional) live k8s
// client, then hands them to app.New to build the api.Server and handler,
// without opening any listener — the fail-closed bind guard
// (CheckBindAllowed) and the actual http.Server both live in runServe,
// which is the only caller that needs a real socket.
func buildServer(ctx context.Context, opts serveOptions) (*builtServer, error) {
	kind, err := parseStoreKind(opts.StoreKind)
	if err != nil {
		return nil, err
	}
	store, closeStore, err := openStore(ctx, kind, opts.DB)
	if err != nil {
		return nil, err
	}
	// From here on, every early-return must close what openStore opened.
	fail := func(err error) (*builtServer, error) {
		_ = closeStore()
		return nil, err
	}

	registry := &core.ClusterRegistry{}
	if opts.Registry != "" {
		reg, err := loadRegistry(opts.Registry, core.ValidateOptions{
			AllowInsecureTransport: opts.AllowInsecureTransport,
			AllowPrivateEndpoints:  opts.AllowPrivateEndpoints,
		})
		if err != nil {
			return fail(err)
		}
		registry = reg
	}
	static := registry.Snapshot()
	for _, c := range static {
		slog.Info("cluster registered", "id", c.Id, "hostname", c.Hostname)
	}
	slog.Info("registry loaded", "clusters", len(static))

	var validator *auth.Validator
	if opts.AuthConfig != "" {
		cfg, err := loadAuthConfig(opts.AuthConfig)
		if err != nil {
			return fail(err)
		}
		slog.Info("OIDC discovery", "issuer", cfg.Issuer, "audience", cfg.Audience)
		v, err := auth.Discover(ctx, cfg, auth.IdpClient(), opts.AllowInsecureTransport)
		if err != nil {
			return fail(err)
		}
		validator = v
	}

	var localAuth *auth.LocalAuthenticator
	if opts.LocalAuth {
		var dbPath string
		if kind == storeSqlite {
			dbPath = opts.DB
		}
		if err := bootstrapLocalAdmin(ctx, store, dbPath); err != nil {
			return fail(err)
		}
		localAuth = auth.NewLocalAuthenticator(store, 86_400, 90)
		slog.Info("local auth enabled (ADR-0011): /api/v1/auth/login")
	}

	var profiles []core.Profile
	if opts.Profiles != "" {
		data, err := os.ReadFile(opts.Profiles)
		if err != nil {
			return fail(fmt.Errorf("reading --profiles: %w", err))
		}
		if profiles, err = api.LoadProfiles(data); err != nil {
			return fail(fmt.Errorf("--profiles %s: %w", opts.Profiles, err))
		}
		slog.Info("profile catalog seeded", "profiles", len(profiles))
	}

	cfg := app.Config{
		Profiles:             profiles,
		Store:                store,
		Registry:             registry,
		Validator:            validator,
		Local:                localAuth,
		AllowUnauthenticated: opts.DevAllowUnauthenticated,
		ReconcileInterval:    opts.ReconcileInterval,
		MeteringInterval:     opts.MeteringInterval,
		GatewayDomain:        opts.GatewayDomain,
		GatewayExternalBase:  opts.GatewayExternalBase,
		ServicesPerProject:   opts.ServicesPerProject,
		RuntimeEnvUngoverned: opts.RuntimeEnvUngoverned,
		Admission: api.Admission{
			AllowedImagePrefixes: api.ParseImagePrefixes(opts.AllowedImages),
			MaxWorkers:           opts.MaxWorkers,
		},
	}
	var liveClient *live.Client
	if opts.Namespace != "" {
		restCfg, err := ctrlconfig.GetConfig()
		if err != nil {
			return fail(fmt.Errorf("resolving kubeconfig: %w", err))
		}
		sched, err := parseScheduling(opts)
		if err != nil {
			return fail(err)
		}
		proxy, err := provision.ParsePackageProxy(opts.PackageProxy)
		if err != nil {
			return fail(fmt.Errorf("--package-proxy: %w", err))
		}
		c, err := live.NewClient(restCfg, opts.Namespace, opts.Autoscaling, live.WithScheduling(sched), live.WithPackageProxy(proxy))
		if err != nil {
			return fail(err)
		}
		liveClient = c
		if !sched.IsZero() {
			slog.Info("tenant pod scheduling", "scheduling", sched.String())
		}
		if proxy != nil {
			slog.Info("package proxy egress enabled for installing workloads", "proxy", proxy.String())
		}
		cfg.Provisioner = c
		cfg.ServiceProvisioner = live.NewServiceClient(c)
		cfg.JobProvisioner = live.NewJobClient(c)
		slog.Info("cluster lifecycle controller + services + jobs enabled", "namespace", opts.Namespace)
	}

	a, err := app.New(cfg)
	if err != nil {
		return fail(err)
	}
	return &builtServer{
		app:        a,
		closeStore: closeStore,
		validator:  validator,
		local:      localAuth,
		live:       liveClient,
	}, nil
}

// bindIPFor extracts the bind address's host IP for CheckBindAllowed.
// Unparseable/absent hosts (an empty host from ":8484", or a
// SplitHostPort failure) resolve to nil, which CheckBindAllowed treats as
// NOT provably loopback — fail closed, not "assume safe".
func bindIPFor(bind string) net.IP {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// HTTP server timeouts. ReadHeaderTimeout and IdleTimeout bound
// Slowloris-style connection hoarding (F2). ReadTimeout and WriteTimeout
// are deliberately NOT set: they are whole-request deadlines that would
// kill the gateway's long-lived WebSocket bridges
// (internal/api/gateway_ws.go), which stay open for the life of a job.
const (
	httpReadHeaderTimeout = 10 * time.Second
	httpIdleTimeout       = 120 * time.Second
)

// newHTTPServer builds the one http.Server runServe listens on, factored
// out so serve_test.go can pin the timeout configuration without opening
// a socket.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
}

// warnIfCleartextLocalAuth is the F8 TLS-posture warning: the binary serves
// plain HTTP only (no TLS config exists), so with local auth on a
// non-loopback bind, login passwords and PATs cross the network in
// cleartext unless an ingress terminates TLS. This is a warning, not a
// refusal — ingress termination is a legitimate deployment, and
// CheckBindAllowed already owns the fail-closed decision.
func warnIfCleartextLocalAuth(bindIP net.IP, localAuthEnabled bool) {
	if !localAuthEnabled || (bindIP != nil && bindIP.IsLoopback()) {
		return
	}
	slog.Warn("local auth is enabled on a non-loopback bind and bifrost serves plain HTTP only: " +
		"login passwords and tokens will cross the network in cleartext — " +
		"terminate TLS at an ingress in front of bifrost")
}

// runServe is serve's production entry point: build the handler, enforce
// the bind-time fail-closed guard (CheckBindAllowed — internal/api's
// guard, called correctly so its error aborts startup before any socket
// opens), start the reconcile + pool-reconcile loops when a live
// provisioner is configured (RunReconciler runs the ADR-0007-equivalent
// stale-restore boot check itself — see reconcile.go's doc comment; no
// separate wiring is needed here), then serve until SIGINT/SIGTERM.
func runServe(ctx context.Context, opts serveOptions) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	built, err := buildServer(ctx, opts)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := built.closeStore(); cerr != nil {
			slog.Warn("store close failed", "error", cerr)
		}
	}()

	authConfigured := built.validator != nil || built.local != nil
	if err := api.CheckBindAllowed(bindIPFor(opts.Bind), authConfigured, opts.DevAllowUnauthenticated); err != nil {
		return err
	}
	warnIfCleartextLocalAuth(bindIPFor(opts.Bind), built.local != nil)

	go built.app.RunLoops(ctx)

	srv := newHTTPServer(opts.Bind, built.app.Handler)
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("bifrost serve listening", "bind", opts.Bind)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-serveErr:
		return err
	}
}

// parseScheduling turns --ray-node-selector / --ray-tolerations into the
// provision.Scheduling every tenant pod carries. Both flags are validated
// here so a typo fails `serve` at startup instead of surfacing as a
// rejected RayCluster on the first create.
func parseScheduling(opts serveOptions) (provision.Scheduling, error) {
	ns, err := provision.ParseNodeSelector(opts.RayNodeSelector)
	if err != nil {
		return provision.Scheduling{}, fmt.Errorf("--ray-node-selector: %w", err)
	}
	tol, err := provision.ParseTolerations(opts.RayTolerations)
	if err != nil {
		return provision.Scheduling{}, fmt.Errorf("--ray-tolerations: %w", err)
	}
	return provision.Scheduling{NodeSelector: ns, Tolerations: tol}, nil
}
