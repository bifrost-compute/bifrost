package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/core"
)

// Adversarial probes for the API skeleton's security surface. These are
// deliberately end-to-end where it matters — several run a REAL listening
// server via httptest.NewServer rather than synthesizing a request, because
// the properties under test (middleware ordering, the mux's path cleaning,
// redirect re-entry) only hold once a full request actually traverses the
// stack. A unit-level httptest.NewRequest would pass while the deployed
// server leaked.
//
// Helpers newFakeUserStore/okHandler come from middleware_test.go.

// probeAuthedHandler returns the full handler with local auth configured,
// so deny-by-default is ACTIVE. The store holds no users and no tokens:
// every credential presented to it is invalid, which is what these probes
// want — the question is what happens to requests that fail auth, not
// whether a good token works.
func probeAuthedHandler() http.Handler {
	return NewHandler(NewServer(), HandlerOptions{
		Local: auth.NewLocalAuthenticator(newFakeUserStore(), 3600, 90),
	})
}

// noRedirectClient returns a client that surfaces a 3xx as its own answer
// instead of following it — a redirect is a distinct outcome from whatever
// it points at, and conflating them hides bypasses.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// ---------------------------------------------------------------------------
// Deny-by-default
// ---------------------------------------------------------------------------

// The headline property: no unimplemented operation may be reachable
// without a token. A 501 here instead of a 401 would mean the auth
// middleware sits INSIDE the router rather than around it — the request
// reached a handler before anyone checked for a credential. Every route
// below is a real, generated, currently-stubbed operation.
func TestUnauthenticatedRequestsNeverReachHandlers(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/clusters"},
		{"POST", "/api/v1/clusters"},
		{"GET", "/api/v1/pools"},
		{"GET", "/api/v1/audit/events"},
		{"GET", "/api/v1/access/roles"},
		{"GET", "/api/v1/auth/identity"},
		{"GET", "/api/v1/auth/tokens"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/services"},
		{"GET", "/api/v1/registry"},
		{"GET", "/api/v1/policy"},
		{"GET", "/api/v1/usage"},
		{"GET", "/api/v1/metrics"},
		{"GET", "/api/v1/jobs"},
	} {
		req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s -> %d, want 401 (a 501 means the request reached a handler before auth ran); body=%s",
				tc.method, tc.path, resp.StatusCode, bytes.TrimSpace(body))
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("%s %s: WWW-Authenticate = %q, want \"Bearer\"", tc.method, tc.path, got)
		}
	}
}

// The public allowlist is the entire pre-auth attack surface, so it must be
// exactly the five entries that remain after the dead /docs exemptions were
// dropped (F10 — nothing serves /docs; auth_layer.rs's is_public exempted
// them for a Swagger UI this server never mounts) and nothing that merely
// resembles them. The near-miss table is the point: prefix/suffix/case/slash
// variants are how an allowlist grows a hole during a refactor.
func TestPublicAllowlistIsExactlyTheFive(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	status := func(p string) int {
		resp, err := noRedirectClient().Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// The five exemptions must not 401. What they DO answer varies (404
	// where nothing is mounted, 405 for a POST-only operation, 501 for a
	// stub) — the assertion is only that auth let them through.
	for _, p := range []string{
		"/healthz",
		"/api/v1/version",
		SpecPath,
		"/api/v1/auth/login",
		"/api/v1/auth/providers",
	} {
		if code := status(p); code == http.StatusUnauthorized {
			t.Errorf("allowlisted path %s got 401", p)
		}
	}

	// Everything else must be refused — including the retired /docs entries
	// themselves (a 200 or 501 here means the path reached the router
	// without a credential).
	for _, p := range []string{
		"/healthz/", "/HEALTHZ", "/healthzz",
		"/api/v1/version/", "/api/v1/versionx", "/api/v1/Version",
		"/api/v1/auth/loginx", "/api/v1/auth/login/", "/api/v1/auth/",
		"/api/v1/auth/tokens", "/api/v1/auth/identity", "/api/v1/auth/logout",
		"/docs", "/docs/", "/docs/index.html", "/docsx", "/docs.json",
		"/api/v1/openapi.json/", "/api/v1/openapi.jsonx",
		"//healthz", "/./healthz", "/api/v1//version",
	} {
		if code := status(p); code == http.StatusOK || code == http.StatusNotImplemented {
			t.Errorf("BYPASS: %s answered %d without a token", p, code)
		}
	}
}

// The retired /docs/* prefix exemption was the one place a traversal could
// smuggle a protected path past isPublic. With the entries removed the
// allowlist refuses /docs/* outright — the traversal dies at the first
// gate, before the mux ever cleans the path — but the probe stays: if
// anyone re-adds a prefix exemption, only the mux's clean-and-redirect (and
// re-entry through auth) stands between this and a bypass, and this test is
// the signal for that regression.
func TestTraversalThroughDocsPrefixStillEndsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	for _, p := range []string{
		"/docs/../api/v1/clusters",
		"/docs/../../api/v1/clusters",
		"/docs/../api/v1/users",
		"/docs/./../api/v1/pools",
		"/docs/%2e%2e/api/v1/clusters",
	} {
		resp, err := srv.Client().Get(srv.URL + p) // follow the whole chain
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotImplemented {
			t.Errorf("BYPASS: %s reached a protected handler (terminal %d); body=%s",
				p, resp.StatusCode, bytes.TrimSpace(body))
		}
	}
}

// ---------------------------------------------------------------------------
// Fail-closed guards
// ---------------------------------------------------------------------------

// The bind guard's whole job is to stop an unauthenticated control plane
// from being reachable off-host. The wildcard binds (0.0.0.0 and [::]) are
// the cases that matter most and the easiest to get wrong, since neither is
// "loopback" but both are what a careless default binds to. A nil IP must
// also refuse: unparseable is not provably loopback.
func TestCheckBindAllowedMatrix(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ip            net.IP
		authed, allow bool
		wantErr       bool
	}{
		{"loopback v4, no auth", net.ParseIP("127.0.0.1"), false, false, false},
		{"loopback v4 non-.1, no auth", net.ParseIP("127.7.7.7"), false, false, false},
		{"loopback v6, no auth", net.ParseIP("::1"), false, false, false},
		{"v4-mapped loopback, no auth", net.ParseIP("::ffff:127.0.0.1"), false, false, false},
		{"wildcard 0.0.0.0, no auth", net.ParseIP("0.0.0.0"), false, false, true},
		{"wildcard [::], no auth", net.ParseIP("::"), false, false, true},
		{"LAN, no auth", net.ParseIP("10.0.0.5"), false, false, true},
		{"public, no auth", net.ParseIP("203.0.113.9"), false, false, true},
		{"nil ip, no auth", nil, false, false, true},
		{"wildcard, auth configured", net.ParseIP("0.0.0.0"), true, false, false},
		{"wildcard, explicit override", net.ParseIP("0.0.0.0"), false, true, false},
		{"nil ip, auth configured", nil, true, false, false},
	} {
		err := CheckBindAllowed(tc.ip, tc.authed, tc.allow)
		if gotErr := err != nil; gotErr != tc.wantErr {
			t.Errorf("%s: err=%v, want err=%v (%v)", tc.name, gotErr, tc.wantErr, err)
		}
		if err != nil && !errors.Is(err, ErrAuthNotConfigured) {
			t.Errorf("%s: error must wrap ErrAuthNotConfigured for callers to match on: %v", tc.name, err)
		}
	}
}

// The router-level guard decides from the TCP peer, which the caller cannot
// forge (it is not X-Forwarded-For). Anything it cannot parse into a
// loopback IP must be refused — a hostname is not proof, and neither is an
// empty RemoteAddr.
func TestRefuseNonLoopbackPeerParsing(t *testing.T) {
	h := RefuseNonLoopback(okHandler())
	for _, tc := range []struct {
		addr      string
		wantAllow bool
	}{
		{"127.0.0.1:5000", true},
		{"127.0.0.1", true},
		{"[::1]:5000", true},
		{"::1", true},
		{"[::ffff:127.0.0.1]:80", true},
		{"10.0.0.5:5000", false},
		{"203.0.113.9:443", false},
		{"", false},
		{"garbage", false},
		{"not-an-ip:80", false},
		{"localhost:8080", false}, // a name is not provably loopback
	} {
		req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
		req.RemoteAddr = tc.addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		allowed := rec.Code == http.StatusOK
		if allowed != tc.wantAllow {
			t.Errorf("peer %q: allowed=%v, want %v (status %d)", tc.addr, allowed, tc.wantAllow, rec.Code)
		}
		if !allowed && rec.Code != http.StatusForbidden {
			t.Errorf("peer %q: status %d, want 403", tc.addr, rec.Code)
		}
	}
}

// The guard must be installed on exactly the Rust condition
// (validator == nil && local == nil && !allowUnauthenticated). Installing
// it too eagerly breaks a configured deployment; too rarely leaves an
// unauthenticated one exposed. Probing /healthz specifically checks that
// the guard sits OUTSIDE the public allowlist — an allowlisted path must
// still be refused from a non-loopback peer when nothing can authenticate.
func TestFailClosedGuardInstallationCondition(t *testing.T) {
	local := auth.NewLocalAuthenticator(newFakeUserStore(), 3600, 90)
	for _, tc := range []struct {
		name      string
		opts      HandlerOptions
		wantGuard bool
	}{
		{"nothing configured", HandlerOptions{}, true},
		{"explicit override", HandlerOptions{AllowUnauthenticated: true}, false},
		{"local auth configured", HandlerOptions{Local: local}, false},
	} {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		NewHandler(NewServer(), tc.opts).ServeHTTP(rec, req)

		if guarded := rec.Code == http.StatusForbidden; guarded != tc.wantGuard {
			t.Errorf("%s: guard installed=%v, want %v (status %d)", tc.name, guarded, tc.wantGuard, rec.Code)
		}
	}
}

// Dev mode (nothing configured) passes everything through, but it must not
// fabricate an identity while doing so — a downstream authorization check
// that finds one would be reading a credential nobody presented.
func TestDevModeAttachesNoIdentity(t *testing.T) {
	// /api/v1/version (T10 scope): always live and dependency-free (no
	// Store needed), unlike every other route as of T12 — which finished
	// porting every remaining 501 stub, including /api/v1/pools (T11's
	// comment above this test named that route specifically as "a still-
	// unimplemented stub"; it no longer is, and calling it on a bare
	// no-dependencies NewServer() now panics on a nil Store instead of
	// 501ing). This probe only cares about the auth-layer property (dev
	// mode passes through with no identity attached), not any particular
	// handler's body, so it targets the one route guaranteed to need
	// nothing but the identity context to answer.
	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	NewHandler(NewServer(), HandlerOptions{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("dev mode from loopback should reach the handler, got %d", rec.Code)
	}
	if id, ok := IdentityFromContext(context.Background()); ok || id != nil {
		t.Errorf("dev mode attached an identity: %v", id)
	}
}

// ---------------------------------------------------------------------------
// Response surface
// ---------------------------------------------------------------------------

// Every rejection uses the one canonical envelope. T11/T12 inherit this
// shape across 45 handlers, so a divergence here is a divergence 45 times
// over. The scheme cases pin the Rust reference's case-sensitive
// strip_prefix("Bearer ") — "Basic"/"bearer" are missing_token, not
// invalid_token, because no bearer credential was presented at all.
func TestErrorEnvelopeIsCanonicalOnEveryRejection(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	for _, tc := range []struct {
		name, authHeader string
		wantCode         string
	}{
		{"no header", "", "missing_token"},
		{"wrong scheme", "Basic abc", "missing_token"},
		{"lowercase scheme", "bearer abc", "missing_token"},
		{"opaque garbage", "Bearer nope", "invalid_token"},
		{"jwt-shaped garbage", "Bearer a.b.c", "invalid_token"},
	} {
		req, err := http.NewRequest("GET", srv.URL+"/api/v1/clusters", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.authHeader != "" {
			req.Header.Set("Authorization", tc.authHeader)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", tc.name, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type %q, want application/json", tc.name, ct)
		}
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Errorf("%s: body is not JSON: %v (%s)", tc.name, err, body)
			continue
		}
		if envelope["error"] != tc.wantCode {
			t.Errorf("%s: error=%v, want %q", tc.name, envelope["error"], tc.wantCode)
		}
		for k := range envelope {
			if k != "error" && k != "message" {
				t.Errorf("%s: unexpected envelope field %q", tc.name, k)
			}
		}
	}
}

// WriteError is wired as both the strict server's RequestErrorHandlerFunc
// and ResponseErrorHandlerFunc, so it renders every error the API produces.
// An error that isn't an *HTTPError is by definition one nobody vetted for
// disclosure — a wrapped driver error, a filesystem path, a failed query —
// and its text must not be echoed to the caller. The detail belongs in a
// log; the client gets a fixed string.
func TestWriteErrorDoesNotEchoInternalErrorText(t *testing.T) {
	rec := httptest.NewRecorder()
	// No characters json.Encode would escape: an escaped quote in the body
	// would not match the raw needle and the assertion would silently pass
	// on a body that plainly contains the secret.
	secret := "pq: password authentication failed for user bifrost host=10.0.0.5"
	WriteError(rec, httptest.NewRequest("GET", "/x", nil), errors.New(secret))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(secret)) {
		t.Errorf("internal error text echoed to the client: %s", bytes.TrimSpace(rec.Body.Bytes()))
	}
	// A vetted *HTTPError still renders its own message — the guard above
	// must not flatten deliberate, safe messages into nothing.
	rec = httptest.NewRecorder()
	WriteError(rec, httptest.NewRequest("GET", "/x", nil), ErrNotImplemented)
	if !bytes.Contains(rec.Body.Bytes(), []byte("not_implemented")) {
		t.Errorf("a vetted HTTPError lost its code: %s", bytes.TrimSpace(rec.Body.Bytes()))
	}
}

// The embedded spec must be the vendored bytes exactly. Serving a
// re-encoded or partial document would silently desynchronize every
// generated client from the contract the server was built against.
func TestServedSpecIsByteIdenticalToVendoredFile(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + SpecPath)
	if err != nil {
		t.Fatal(err)
	}
	served, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	onDisk, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(served, onDisk) {
		t.Errorf("served spec differs from the vendored file (%d vs %d bytes)", len(served), len(onDisk))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// VersionInfo's contract requires exactly name and version. name is a fixed
// product identity, not a build-time value, so it is asserted literally;
// version must merely be present and non-empty, since T15 may inject it at
// link time. Extra fields would be a contract violation for every generated
// client that validates responses.
func TestVersionResponseMatchesContractSchema(t *testing.T) {
	srv := httptest.NewServer(probeAuthedHandler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, body)
	}
	if got["name"] != "bifrost" {
		t.Errorf(`name = %v, want "bifrost"`, got["name"])
	}
	if v, ok := got["version"].(string); !ok || v == "" {
		t.Errorf("version = %v, want a non-empty string", got["version"])
	}
	for k := range got {
		if k != "name" && k != "version" {
			t.Errorf("unexpected field %q in VersionInfo (contract requires exactly name+version)", k)
		}
	}
}

// The 501 burn-down count is only meaningful if it is anchored to the
// contract rather than to the server's own method set — counting methods
// against themselves would still pass if an operation were dropped from the
// interface entirely. This reads the frozen spec and asserts the operation
// total that 45-plus-healthz-plus-version has to add up to.
func TestContractOperationCountAnchorsTheBurndown(t *testing.T) {
	spec, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		t.Fatal(err)
	}

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true, "trace": true,
	}
	operations := 0
	for _, item := range doc.Paths {
		for method := range item {
			if httpMethods[method] {
				operations++
			}
		}
	}

	const wantOperations = 52 // 50 authenticated operations + healthz + version (0.2.0 adds submit_job, get_job, delete_job, list_profiles; #52 adds list_environments)
	if operations != wantOperations {
		t.Errorf("contract declares %d operations across %d paths, want %d — "+
			"if the vendored contract legitimately changed, the 501 burn-down count moves with it",
			operations, len(doc.Paths), wantOperations)
	}
}

// ---------------------------------------------------------------------------
// Bearer dispatch
// ---------------------------------------------------------------------------

// countingStore is a LocalUserStore that records whether the opaque-PAT
// path was consulted at all. It holds no tokens, so it can only ever say
// "no" — the interesting signal is whether it was asked.
type countingStore struct {
	lookups int
}

func (s *countingStore) GetLocalUser(context.Context, string) (*core.LocalUserRecord, error) {
	return nil, nil
}
func (s *countingStore) RecordLoginFailure(context.Context, string) error { return nil }
func (s *countingStore) RecordLoginSuccess(context.Context, string) error { return nil }
func (s *countingStore) CreateApiToken(context.Context, core.ApiTokenRecord) error {
	return nil
}
func (s *countingStore) GetApiTokenByPrefix(_ context.Context, _ string) (*core.ApiTokenRecord, error) {
	s.lookups++
	return nil, nil
}
func (s *countingStore) TouchApiToken(context.Context, string, uint64) error { return nil }

// resolveIdentity's dispatch must match the Rust reference's control flow
// exactly: when a validator is configured AND the token is JWT-shaped, the
// OIDC path OWNS the outcome — a validation failure returns nil rather than
// falling through to the opaque-PAT path. Falling through would mean a token
// rejected by the IdP gets a second, unrelated chance at authenticating, and
// would put attacker-supplied JWT payloads through the local token lookup on
// every failed request.
func TestJWTShapedTokenDoesNotFallThroughToLocal(t *testing.T) {
	idp := newFakeIdp(t)
	store := &countingStore{}
	state := AuthState{
		Validator: idp.discover(t),
		Local:     auth.NewLocalAuthenticator(store, 3600, 90),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt") // JWT-shaped, invalid
	RequireAuth(state)(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if store.lookups != 0 {
		t.Errorf("the local PAT path was consulted %d time(s) for a JWT-shaped token; "+
			"a failed OIDC validation must not fall through", store.lookups)
	}
}

// The converse arm of the same dispatch: a token that is NOT JWT-shaped
// skips the validator entirely and goes to the opaque-PAT path, even when a
// validator is configured. Without this, local PATs would stop working the
// moment OIDC was switched on.
func TestNonJWTShapedTokenReachesLocalEvenWithValidator(t *testing.T) {
	idp := newFakeIdp(t)
	store := &countingStore{}
	state := AuthState{
		Validator: idp.discover(t),
		Local:     auth.NewLocalAuthenticator(store, 3600, 90),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	req.Header.Set("Authorization", "Bearer bfr_abcd1234_0123456789abcdef0123456789abcdef")
	RequireAuth(state)(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (the store holds no tokens)", rec.Code)
	}
	if store.lookups != 1 {
		t.Errorf("local lookups = %d, want 1: an opaque token must reach the PAT path "+
			"even when a validator is configured", store.lookups)
	}
}
