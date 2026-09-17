// Package inproc is the L2 target: the real control plane — app.New, real
// API server, real auth, real reconciler, real (memory) store — with only
// the Kubernetes edge faked. It is the ONE package under test/requirements
// allowed to import internal/ (guards_test.go enforces this).
package inproc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bifrost-compute/bifrost/internal/api"
	"github.com/bifrost-compute/bifrost/internal/app"
	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
)

type principal struct {
	role    core.LocalRole
	project string // "" = no project assignment
}

// Seeded principals, identical on every target (spec §1.1).
var principals = map[string]principal{
	"admin":    {role: core.LocalRoleAdmin},
	"operator": {role: core.LocalRoleOperator},
	"dev-a":    {role: core.LocalRoleDeveloper, project: "team-a"},
	"dev-b":    {role: core.LocalRoleDeveloper, project: "team-b"},
}

func password(name string) string { return "pw-" + name + "-0123456789" }

type target struct {
	srv       *httptest.Server
	store     controller.Store
	principal string
	tokens    *sync.Map // principal -> bearer token
	cancel    context.CancelFunc
	t         testing.TB
	// gatewayDomain is the control plane's --gateway-domain equivalent;
	// "" means the target has no dynamic gateway (Has("gateway") false).
	gatewayDomain string
}

// DefaultGatewayDomain is the gateway domain the default inproc target
// runs with. Nothing resolves it (.invalid is reserved for exactly that),
// which is the point: L2 asserts authorization and registration, never
// real routing.
const DefaultGatewayDomain = "inproc.invalid"

// DefaultGatewayExternalBase is the --gateway-external-base equivalent:
// the scheme views prefix a registered hostname with in gateway_url. Tests
// parse the host back out of it and send it as a Host header — no
// resolution of the .invalid name is ever attempted.
const DefaultGatewayExternalBase = "http://"

// seedBcryptCost is the bcrypt work factor inproc hashes seed passwords and
// issued tokens at: bcrypt.MinCost, not auth's production bcryptCost (12).
// Spec §3 caps the whole L2 requirement-test lane at under 3 minutes
// (merge-blocking); at cost 12 under -race a single bcrypt op runs ~2.2s,
// and a fresh inproc.New pays for several (4 seed hashes + a token
// hash/verify per login + a verify per authenticated request) — that
// alone blew the budget once the P1 suite reached ~52 tests each starting
// a fresh target. Production (cmd/bifrost/serve.go, via
// auth.NewLocalAuthenticator) is untouched: it still always hashes at 12.
const seedBcryptCost = bcrypt.MinCost

// Option tunes the in-process control plane a test builds. Requirement
// tests normally take the default (target.Get); tests about administrator
// configuration build their own with inproc.New(t, inproc.WithAdmission(...)).
type Option func(*app.Config)

// WithAdmission sets the administrator's image allowlist and worker cap
// (requirement 7) on the control plane under test. Plain values, not the
// internal type: requirement tests may not import internal/.
func WithAdmission(allowedImagePrefixes []string, maxWorkers int) Option {
	return func(c *app.Config) {
		c.Admission = api.Admission{AllowedImagePrefixes: allowedImagePrefixes, MaxWorkers: maxWorkers}
	}
}

// WithGatewayDomain sets the dynamic gateway domain (requirement 5) the
// control plane under test registers clusters under; "" disables the
// dynamic gateway so a test can assert the disabled path.
func WithGatewayDomain(domain string) Option {
	return func(c *app.Config) { c.GatewayDomain = domain }
}

// New builds the in-process target and starts its reconcile loop. Callers
// (target.Get) register Cleanup and srv.Close via t.Cleanup.
func New(t testing.TB, opts ...Option) req.Target {
	t.Helper()
	store := controller.NewMemoryStore()
	ctx := context.Background()
	for name, p := range principals {
		hash, err := auth.HashPasswordWithCost(password(name), seedBcryptCost)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateLocalUser(ctx, name, nil, hash, p.role); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	local, err := auth.NewLocalAuthenticatorWithCost(store, 86_400, 90, seedBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := app.Config{
		Store:               store,
		Local:               local,
		Provisioner:         newFakeProvisioner(),
		ServiceProvisioner:  newFakeServiceProvisioner(),
		JobProvisioner:      newFakeJobProvisioner(),
		ReconcileInterval:   25 * time.Millisecond,
		MeteringInterval:    100 * time.Millisecond,
		GatewayDomain:       DefaultGatewayDomain,
		GatewayExternalBase: DefaultGatewayExternalBase,
	}
	for _, o := range opts {
		o(&cfg)
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loopCtx, cancel := context.WithCancel(ctx)
	go a.RunLoops(loopCtx)
	srv := httptest.NewServer(a.Handler)

	tg := &target{srv: srv, store: store, principal: "admin", tokens: &sync.Map{}, cancel: cancel, t: t, gatewayDomain: cfg.GatewayDomain}
	// Project-scoped assignments are made through the API as admin, so the
	// seeding itself exercises the real access path. dev-a/dev-b hold an
	// `operator` grant on their project (their local role stays
	// `developer`): rbac.go makes developers read-only on clusters, so the
	// self-serve lifecycle a data-science-pack user needs is the
	// project-operator shape. The cluster target seeds identically.
	for name, p := range principals {
		if p.project == "" {
			continue
		}
		body := client.UpsertAssignmentJSONRequestBody{}
		_ = json.Unmarshal([]byte(fmt.Sprintf(`{"role":"operator","scope":"project:%s"}`, p.project)), &body)
		resp, err := tg.API().UpsertAssignmentWithResponse(ctx, name, body)
		if err != nil || resp.StatusCode()/100 != 2 {
			t.Fatalf("assign %s: err=%v status=%v body=%s", name, err, statusOf(resp), bodyOf(resp))
		}
	}
	t.Cleanup(func() {
		_ = tg.Cleanup(context.Background())
		cancel()
		srv.Close()
	})
	return tg
}

func statusOf(r *client.UpsertAssignmentHTTPResponse) any {
	if r == nil {
		return nil
	}
	return r.StatusCode()
}
func bodyOf(r *client.UpsertAssignmentHTTPResponse) string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

func (tg *target) Name() string      { return "inproc" }
func (tg *target) Namespace() string { return "inproc" }
func (tg *target) Clock() req.FakeClock {
	return nil // deferred to P1 (plan Global Constraints)
}
func (tg *target) K8s() (ctrlclient.Client, bool) { return nil, false }
func (tg *target) Has(capability string) bool {
	// "gateway": a --gateway-domain is configured, so registration and
	// authorization can be asserted (routing cannot — nothing resolves
	// the .invalid domain). Every other L3 capability is absent.
	return capability == "gateway" && tg.gatewayDomain != ""
}

// DestroyStore is never meaningful on inproc: its store is in-process
// memory, so there is no volume to lose. It exists so a test that
// type-asserts req.StoreDestroyer without gating on the store-loss
// capability gets a clear not-supported error instead of a panic.
func (tg *target) DestroyStore(context.Context) error {
	return fmt.Errorf("inproc target: no durable store to destroy")
}

func (tg *target) BaseURL() string { return tg.srv.URL }
func (tg *target) Authorize(r *http.Request) {
	if tok := tg.token(context.Background()); tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
}

func (tg *target) As(p string) req.Target {
	if _, ok := principals[p]; !ok && p != "anon" {
		panic("inproc: unknown principal " + p)
	}
	cp := *tg
	cp.principal = p
	return &cp
}

// token returns the current principal's cached bearer token, logging in
// (and caching the result) on first use. On a login failure it fails the
// test via tg.t.Fatalf rather than panicking — a flaky login must fail the
// one test that hit it, not crash the whole L2 binary out from under every
// other test running in the package. Fatalf unwinds via runtime.Goexit,
// which only stops the calling goroutine: token (and its callers, API and
// Authorize) must therefore run on the goroutine tg.t was constructed
// against, same as any other *testing.T method.
func (tg *target) token(ctx context.Context) string {
	tg.t.Helper()
	if tg.principal == "anon" {
		return ""
	}
	if v, ok := tg.tokens.Load(tg.principal); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	c, _ := client.NewClientWithResponses(tg.srv.URL)
	body := client.LoginJSONRequestBody{}
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"username":%q,"password":%q}`, tg.principal, password(tg.principal))), &body)
	resp, err := c.LoginWithResponse(ctx, body)
	if err != nil || resp.StatusCode() != http.StatusOK {
		tg.t.Fatalf("inproc: login %s failed: %v %s", tg.principal, err, bodyStr(resp))
		return ""
	}
	var m struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(resp.Body, &m)
	tg.tokens.Store(tg.principal, m.Token)
	return m.Token
}

func bodyStr(r *client.LoginHTTPResponse) string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// API returns a client authenticated as the current principal, performing
// a real login on first use. Must be called from the test goroutine tg.t
// was constructed against: on failure it fails via tg.t.Fatalf, which (via
// runtime.Goexit) only unwinds the calling goroutine — same constraint
// *testing.T carries everywhere else.
func (tg *target) API() *client.ClientWithResponses {
	tg.t.Helper()
	tok := tg.token(context.Background())
	c, err := client.NewClientWithResponses(tg.srv.URL, client.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		return nil
	}))
	if err != nil {
		tg.t.Fatalf("inproc: build API client: %v", err)
		return nil
	}
	return c
}

// JobRuntimeEnv returns the runtime_env_yaml the named job was admitted
// with — the stored spec's (possibly environment-compiled, timeout-bounded)
// document, which the fake provisioner carries verbatim into the fake
// RayJob. found=false when no such job exists. Requirement tests read the
// admitted document through this seam because the contract deliberately
// never echoes a job's spec (guards rule 1 keeps internal/ out of the test
// packages); a cluster target answers the same question by reading the
// RayJob CR's runtimeEnvYAML.
func (tg *target) JobRuntimeEnv(id string) (string, bool) {
	j, err := tg.store.GetRayJob(context.Background(), core.ClusterId(id))
	if err != nil || j == nil {
		return "", false
	}
	return j.Spec.RuntimeEnvYaml, true
}

// ResolvedServiceAccount returns the workload identity (#20) the named
// cluster, job or service was admitted with — the ServiceAccount the fake
// provisioner would stamp on every pod template — and whether it resolved
// to one at all (false = the namespace default). kind is "cluster", "job"
// or "service". Requirement tests read the pinned identity through this
// seam because the contract never echoes a spec (guards rule 1 keeps
// internal/ out of the test packages); a cluster target answers the same
// question from the pods' serviceAccountName.
func (tg *target) ResolvedServiceAccount(kind, id string) (string, bool) {
	ctx := context.Background()
	var sa *string
	switch kind {
	case "cluster":
		c, err := tg.store.Get(ctx, core.ClusterId(id))
		if err != nil || c == nil {
			return "", false
		}
		sa = c.Spec.ServiceAccountResolved
	case "job":
		j, err := tg.store.GetRayJob(ctx, core.ClusterId(id))
		if err != nil || j == nil {
			return "", false
		}
		sa = j.Spec.ServiceAccountResolved
	case "service":
		svc, err := tg.store.GetService(ctx, id)
		if err != nil || svc == nil {
			return "", false
		}
		sa = svc.Spec.ServiceAccountResolved
	}
	if sa == nil || *sa == "" {
		return "", false
	}
	return *sa, true
}

// Cleanup deletes every cluster and service whose name carries the run
// prefix, as admin.
func (tg *target) Cleanup(ctx context.Context) error {
	api := tg.As("admin").API()
	prefix := req.RunID() + "-"
	list, err := api.ListClustersWithResponse(ctx)
	if err != nil {
		return err
	}
	var items []struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal(list.Body, &items)
	for _, it := range items {
		if strings.HasPrefix(it.Id, prefix) {
			if _, err := api.DeleteClusterWithResponse(ctx, it.Id, nil); err != nil {
				return err
			}
		}
	}
	services, err := api.ListServicesWithResponse(ctx)
	if err != nil {
		return err
	}
	var svcs []struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(services.Body, &svcs)
	for _, it := range svcs {
		if strings.HasPrefix(it.Name, prefix) {
			if _, err := api.DeleteServiceWithResponse(ctx, it.Name); err != nil {
				return err
			}
		}
	}
	return nil
}
