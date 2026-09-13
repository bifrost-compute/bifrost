package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
)

func smallEnvironment(projects ...string) core.Environment {
	return core.Environment{
		Name:      "ml-base",
		BaseImage: "rayproject/ray:2.9.0",
		Packages:  []string{"numpy==1.26.4", "pandas[excel]==2.2.2"},
		EnvVars:   map[string]string{"OMP_NUM_THREADS": "4"},
		Status:    core.EnvironmentStatusPublished,
		Projects:  projects,
	}
}

func TestListEnvironmentsRequiresReadOnCluster(t *testing.T) {
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{smallEnvironment()}}}
	for _, tc := range []struct {
		id   *auth.Identity
		want int
	}{
		{testIdentity("admin", auth.RoleAdmin), http.StatusOK},
		{testIdentity("op", auth.RoleOperator), http.StatusOK},
		{testIdentity("dev", auth.RoleDeveloper), http.StatusOK},
		{testIdentity("viewer", auth.RoleViewer), http.StatusOK},
		// The self-service shape: no global role, one project grant — the
		// identity the environment picker asks as (same gate as profiles).
		{projectMember("pam", auth.RoleOperator, "team-a"), http.StatusOK},
		{testIdentity("nobody"), http.StatusForbidden},
		{testIdentity("auditor", auth.RoleAuditor), http.StatusOK},
	} {
		resp, err := s.ListEnvironments(ctxWithIdentity(tc.id), ListEnvironmentsRequestObject{})
		if tc.want == http.StatusOK {
			if err != nil {
				t.Errorf("list_environments as %v: %v", tc.id.Roles, err)
				continue
			}
			if got := mustResponse[ListEnvironments200JSONResponse](t, resp); len(got) != 1 || got[0].Name != "ml-base" {
				t.Errorf("list_environments as %v = %+v, want [ml-base]", tc.id.Roles, got)
			}
			continue
		}
		mustHTTPError(t, err, tc.want)
	}
}

func TestListEnvironmentsIsNarrowedToTheCallersProjects(t *testing.T) {
	store := newMemStore(t)
	ctx := context.Background()
	if err := store.UpsertRoleAssignment(ctx, "dev", "operator", "project:team-a"); err != nil {
		t.Fatal(err)
	}
	open := smallEnvironment()
	open.Name = "open"
	s := &Server{Store: store, PolicySeed: PolicyConfig{Environments: []core.Environment{
		smallEnvironment("team-a"), func() core.Environment { e := smallEnvironment("team-b"); e.Name = "b-only"; return e }(), open,
	}}}
	resp, err := s.ListEnvironments(ctxWithIdentity(testIdentity("dev", auth.RoleDeveloper)), ListEnvironmentsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range mustResponse[ListEnvironments200JSONResponse](t, resp) {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "ml-base,open" {
		t.Errorf("scoped dev sees %v, want [ml-base open] (team-a's and the unrestricted one)", names)
	}
	resp, err = s.ListEnvironments(ctxWithIdentity(testIdentity("root", auth.RoleAdmin)), ListEnvironmentsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustResponse[ListEnvironments200JSONResponse](t, resp); len(got) != 3 {
		t.Errorf("admin sees %d environments, want all 3", len(got))
	}
}

// The catalog is `[]`, never `null`, when no policy exists at all.
func TestListEnvironmentsEmptyCatalogIsEmptyList(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	resp, err := s.ListEnvironments(ctxWithIdentity(admin()), ListEnvironmentsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	got := mustResponse[ListEnvironments200JSONResponse](t, resp)
	if got == nil || len(got) != 0 {
		t.Errorf("empty catalog = %#v, want a non-nil empty list", got)
	}
}

func TestUpdatePolicyEnvironmentsSection(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	ctx := ctxWithIdentity(admin())
	published := Published
	when := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	pkgs := []string{"numpy==1.26.4"}
	projects := []string{"team-a"}
	vars := map[string]string{"OMP_NUM_THREADS": "4"}
	good := EnvironmentSpec{
		Name:        "ml-base",
		BaseImage:   strPtr("rayproject/ray:2.9.0"),
		Packages:    &pkgs,
		EnvVars:     &vars,
		Projects:    &projects,
		Status:      &published,
		PublishedBy: strPtr("root"),
		PublishedAt: &when,
		Scan:        &EnvironmentScan{Status: Clean, Scanner: strPtr("trivy 0.57.0"), ScannedAt: &when},
	}
	envs := []EnvironmentSpec{good}
	resp, err := s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &envs}})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	pv := mustResponse[UpdatePolicy200JSONResponse](t, resp)
	if pv.Environments == nil || len(*pv.Environments) != 1 {
		t.Fatalf("view after put = %+v, want one environment", pv)
	}
	got := (*pv.Environments)[0]
	if got.Name != "ml-base" || got.Status == nil || *got.Status != Published ||
		got.Scan == nil || got.Scan.Status != Clean || got.PublishedAt == nil || !got.PublishedAt.Equal(when) {
		t.Errorf("view environment = %+v, want the put one round-tripped", got)
	}

	// The list endpoint serves what the policy PUT stored.
	lresp, err := s.ListEnvironments(ctx, ListEnvironmentsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if list := mustResponse[ListEnvironments200JSONResponse](t, lresp); len(list) != 1 || list[0].Name != "ml-base" {
		t.Errorf("list after put = %+v, want [ml-base]", list)
	}

	// An unrelated edit leaves the section untouched.
	quotas := map[string]map[string]float64{"team-a": {"cpu": 9}}
	resp, err = s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Quotas: &quotas}})
	if err != nil {
		t.Fatal(err)
	}
	if pv = mustResponse[UpdatePolicy200JSONResponse](t, resp); len(*pv.Environments) != 1 {
		t.Errorf("quota edit disturbed environments: %+v", pv)
	}

	// Invalid catalogs are refused as a unit with a 400 naming the fault.
	unpinned := []string{"numpy"}
	badName := "Not_A_Name"
	draft := Draft
	bogus := EnvironmentSpecStatus("bogus")
	bogusScan := EnvironmentScanStatus("bogus")
	for name, bad := range map[string][]EnvironmentSpec{
		"duplicate":     {good, good},
		"empty name":    {{Name: ""}},
		"bad name":      {{Name: badName}},
		"unpinned pkg":  {func() EnvironmentSpec { e := good; e.Name = "u"; e.Packages = &unpinned; return e }()},
		"empty project": {func() EnvironmentSpec { e := good; e.Name = "e"; pr := []string{""}; e.Projects = &pr; return e }()},
		"empty var": {func() EnvironmentSpec {
			e := good
			e.Name = "v"
			v := map[string]string{"": "x"}
			e.EnvVars = &v
			return e
		}()},
		"bad status": {func() EnvironmentSpec { e := good; e.Name = "s"; e.Status = &bogus; return e }()},
		"bad scan": {func() EnvironmentSpec {
			e := good
			e.Name = "c"
			e.Scan = &EnvironmentScan{Status: bogusScan}
			return e
		}()},
		"ungoverned yaml": {func() EnvironmentSpec {
			e := good
			e.Name = "y"
			e.Status = &draft
			e.RuntimeEnvYaml = strPtr("conda: {}")
			return e
		}()},
		// The escape hatch and the structured fields fixing the same thing
		// is refused at the edit, not merged arbitrarily at resolution.
		"pip overlap": {func() EnvironmentSpec {
			e := good
			e.Name = "p"
			e.RuntimeEnvYaml = strPtr("pip: [requests==2.31.0]")
			return e
		}()},
		"env overlap": {func() EnvironmentSpec {
			e := good
			e.Name = "o"
			e.RuntimeEnvYaml = strPtr("env_vars:\n  OMP_NUM_THREADS: \"8\"")
			return e
		}()},
	} {
		bad := bad
		_, err := s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &bad}})
		if err == nil {
			t.Errorf("%s: accepted, want 400", name)
			continue
		}
		mustHTTPError(t, err, 400)
	}

	// Clearing: [] empties the section.
	none := []EnvironmentSpec{}
	resp, err = s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &none}})
	if err != nil {
		t.Fatal(err)
	}
	if pv = mustResponse[UpdatePolicy200JSONResponse](t, resp); len(*pv.Environments) != 0 {
		t.Errorf("clear left %+v", pv)
	}
}

// --- Publication workflow, versioning, audit (#57) ---

// putEnvironments replaces the environments section via UpdatePolicy and
// returns the handler's error (nil on success).
func putEnvironments(t *testing.T, s *Server, ctx context.Context, envs []core.Environment) error {
	t.Helper()
	wire := environmentsToWire(envs)
	_, err := s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &wire}})
	return err
}

// catalogByName reads the stored catalog back through GetPolicy.
func catalogByName(t *testing.T, s *Server, ctx context.Context) map[string]EnvironmentSpec {
	t.Helper()
	resp, err := s.GetPolicy(ctx, GetPolicyRequestObject{})
	if err != nil {
		t.Fatalf("get_policy: %v", err)
	}
	pv := mustResponse[GetPolicy200JSONResponse](t, resp)
	out := make(map[string]EnvironmentSpec)
	if pv.Environments != nil {
		for _, e := range *pv.Environments {
			out[e.Name] = e
		}
	}
	return out
}

func countAuditAction(t *testing.T, store controller.Store, action string) int {
	t.Helper()
	rows, _, err := store.ListAudit(context.Background(), core.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Event.Action != nil && *r.Event.Action == action {
			n++
		}
	}
	return n
}

// lifecycleEnv is a bare valid catalog entry at the given status; published
// and deprecated entries carry the publish metadata those statuses store.
func lifecycleEnv(name string, status core.EnvironmentStatus) core.Environment {
	e := core.Environment{Name: name, BaseImage: "rayproject/ray:2.9.0", Status: status}
	if status != core.EnvironmentStatusDraft {
		when := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		e.PublishedBy = strPtr("root")
		e.PublishedAt = &when
	}
	return e
}

// The transition table (#57): an environments-section PUT may publish a
// draft (or create a published entry outright — an implicit publish, stamped
// with the caller), edit within a status, deprecate a published entry,
// re-draft a deprecated one, and remove any entry; it may NOT un-publish to
// draft, deprecate a draft, or republish a deprecated entry directly.
func TestEnvironmentStatusTransitions(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store, PolicySeed: PolicyConfig{Environments: []core.Environment{
		lifecycleEnv("d", core.EnvironmentStatusDraft),
		lifecycleEnv("p", core.EnvironmentStatusPublished),
		lifecycleEnv("x", core.EnvironmentStatusDeprecated),
		lifecycleEnv("gone", core.EnvironmentStatusPublished),
	}}}
	ctx := ctxWithIdentity(admin())

	// Legal: draft->published (stamped by the caller), published->published
	// with the metadata left absent (the stored entry's rides forward),
	// deprecated->draft (stale metadata cleared), new entries at every
	// status, and a published entry removed outright.
	editP := core.Environment{Name: "p", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished}
	redraft := core.Environment{Name: "x", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusDraft,
		PublishedBy: strPtr("root"), PublishedAt: lifecycleEnv("x", core.EnvironmentStatusDeprecated).PublishedAt}
	if err := putEnvironments(t, s, ctx, []core.Environment{
		{Name: "d", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished},
		editP,
		redraft,
		lifecycleEnv("new-draft", core.EnvironmentStatusDraft),
		{Name: "new-pub", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished},
		lifecycleEnv("new-dep", core.EnvironmentStatusDeprecated),
	}); err != nil {
		t.Fatalf("legal edit: %v", err)
	}

	got := catalogByName(t, s, ctx)
	if st := got["d"].Status; st == nil || *st != Published {
		t.Errorf("d status = %+v, want published", got["d"])
	}
	if got["d"].PublishedBy == nil || *got["d"].PublishedBy != "root" || got["d"].PublishedAt == nil {
		t.Errorf("d publish metadata = by %v at %v, want stamped by the caller", got["d"].PublishedBy, got["d"].PublishedAt)
	}
	if got["p"].PublishedBy == nil || *got["p"].PublishedBy != "root" || got["p"].PublishedAt == nil {
		t.Errorf("p metadata left absent = by %v at %v, want the stored entry's carried forward", got["p"].PublishedBy, got["p"].PublishedAt)
	}
	if st := got["x"].Status; st == nil || *st != Draft || got["x"].PublishedBy != nil || got["x"].PublishedAt != nil {
		t.Errorf("x re-drafted = %+v, want draft with the publish metadata cleared", got["x"])
	}
	if st := got["new-draft"].Status; st == nil || *st != Draft {
		t.Errorf("new-draft = %+v, want draft", got["new-draft"])
	}
	if st := got["new-pub"].Status; st == nil || *st != Published || got["new-pub"].PublishedBy == nil || got["new-pub"].PublishedAt == nil {
		t.Errorf("new-pub = %+v, want published and stamped", got["new-pub"])
	}
	if st := got["new-dep"].Status; st == nil || *st != Deprecated {
		t.Errorf("new-dep = %+v, want deprecated (a catalog may record an entry as retired outright)", got["new-dep"])
	}
	if _, ok := got["gone"]; ok {
		t.Errorf("gone was not removed: %+v", got["gone"])
	}
	// Two publishes happened (d, new-pub): one audit row each.
	if n := countAuditAction(t, store, "publish_environment"); n != 2 {
		t.Errorf("publish_environment rows = %d, want 2 (d and new-pub)", n)
	}
	if n := countAuditAction(t, store, "deprecate_environment"); n != 0 {
		t.Errorf("deprecate_environment rows = %d, want 0 so far", n)
	}

	// Illegal transitions: a 400 naming the entry, and the catalog does not
	// move.
	before := catalogByName(t, s, ctx)
	for name, envs := range map[string][]core.Environment{
		"published to draft":      {lifecycleEnv("d", core.EnvironmentStatusDraft)},
		"draft to deprecated":     {lifecycleEnv("new-draft", core.EnvironmentStatusDeprecated)},
		"deprecated to published": {lifecycleEnv("new-dep", core.EnvironmentStatusPublished)},
	} {
		err := putEnvironments(t, s, ctx, envs)
		if err == nil {
			t.Errorf("%s: accepted, want 400", name)
			continue
		}
		mustHTTPError(t, err, 400)
	}
	if after := catalogByName(t, s, ctx); len(after) != len(before) {
		t.Errorf("an illegal transition moved the catalog: %d entries, want %d", len(after), len(before))
	}

	// Legal: published -> deprecated emits deprecate_environment; the PUT
	// also drops every other name — removal is allowed at any status,
	// mirroring the profile and storage sections.
	if err := putEnvironments(t, s, ctx, []core.Environment{lifecycleEnv("d", core.EnvironmentStatusDeprecated)}); err != nil {
		t.Fatalf("deprecate: %v", err)
	}
	got = catalogByName(t, s, ctx)
	if st := got["d"].Status; st == nil || *st != Deprecated || got["d"].PublishedBy == nil {
		t.Errorf("d deprecated = %+v, want deprecated with the publish metadata kept as attribution", got["d"])
	}
	if len(got) != 1 {
		t.Errorf("catalog after the deprecating edit = %d entries, want just d (removal is allowed at any status)", len(got))
	}
	if n := countAuditAction(t, store, "deprecate_environment"); n != 1 {
		t.Errorf("deprecate_environment rows = %d, want 1", n)
	}
}

// A published entry must carry published_by and published_at (#57): a
// seeded published entry that never got stamped, echoed back without the
// metadata, is a 400 naming the entry; supplying the metadata is the fix.
// In dev mode (no caller identity to stamp from) a new published entry
// without an explicit published_by is refused the same way.
func TestPublishedEnvironmentWithoutMetadataIsRefused(t *testing.T) {
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{
		{Name: "bare", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished},
	}}}
	ctx := ctxWithIdentity(admin())
	bare := core.Environment{Name: "bare", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished}
	mustHTTPError(t, putEnvironments(t, s, ctx, []core.Environment{bare}), 400)
	// Supplying the metadata on the edit is the remediation.
	if err := putEnvironments(t, s, ctx, []core.Environment{lifecycleEnv("bare", core.EnvironmentStatusPublished)}); err != nil {
		t.Fatalf("stamped edit of the seeded entry: %v", err)
	}

	// Dev mode: no identity, so nothing stamps a publish the entry doesn't
	// stamp itself.
	dev := &Server{Store: newMemStore(t)}
	err := putEnvironments(t, dev, context.Background(), []core.Environment{
		{Name: "e", BaseImage: "rayproject/ray:2.9.0", Status: core.EnvironmentStatusPublished},
	})
	mustHTTPError(t, err, 400)
	if err := putEnvironments(t, dev, context.Background(), []core.Environment{
		lifecycleEnv("e", core.EnvironmentStatusPublished),
	}); err != nil {
		t.Fatalf("dev-mode publish with explicit metadata: %v", err)
	}
}

// Publishing is admin-only by construction: the catalog rides the policy
// row, and policy writes need Admin on the cluster — operator, developer,
// auditor and developer-with-project-scope alike are 403 with a deny audit
// row (#57's RBAC matrix, mirroring the r03 policy-write matrix).
func TestUpdatePolicyEnvironmentsAdminOnly(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	wire := environmentsToWire([]core.Environment{lifecycleEnv("e", core.EnvironmentStatusDraft)})
	for _, id := range []*auth.Identity{
		testIdentity("op", auth.RoleOperator),
		testIdentity("dev", auth.RoleDeveloper),
		testIdentity("aud", auth.RoleAuditor),
		projectMember("pam", auth.RoleOperator, "team-a"),
	} {
		_, err := s.UpdatePolicy(ctxWithIdentity(id), UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &wire}})
		mustHTTPError(t, err, 403)
	}
	rows, _, err := store.ListAudit(context.Background(), core.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	denies := 0
	for _, r := range rows {
		e := r.Event
		if e.Decision == core.AuditDecisionDeny && e.Reason != nil && *e.Reason == "insufficient_permission" &&
			e.Required != nil && e.Required.Action == "admin" && e.Required.Target == "cluster" {
			denies++
		}
	}
	if denies != 4 {
		t.Errorf("deny audit rows = %d, want one per refused publish attempt", denies)
	}
	// Nothing was written.
	if p, err := store.GetPolicy(context.Background()); err != nil || p != nil {
		t.Errorf("policy row after refused writes = %+v, %v; want none", p, err)
	}
}

// The runtime-env governance knobs (#52 stretch) ride the admission
// section: they round-trip through PUT/GET, and an empty list entry or a
// negative cap is refused at the edit.
func TestUpdatePolicyAdmissionRuntimeEnvKnobs(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	ctx := ctxWithIdentity(admin())
	hosts := []string{"pypi.example.com"}
	deny := []string{"pypi-malware"}
	schemes := []string{"s3"}
	buckets := []string{"artifacts.example.com"}
	adm := map[string]AdmissionRule{"team-a": {
		AllowConda:             boolPtr(true),
		AllowUnpinnedPackages:  boolPtr(true),
		PackageDenylist:        &deny,
		AllowedIndexHosts:      &hosts,
		AllowedRemoteSchemes:   &schemes,
		AllowedRemoteHosts:     &buckets,
		MaxSetupTimeoutSeconds: i64(120),
		MaxDocumentBytes:       i64(4096),
	}}
	resp, err := s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Admission: &adm}})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rule := (*mustResponse[UpdatePolicy200JSONResponse](t, resp).Admission)["team-a"]
	if rule.AllowConda == nil || !*rule.AllowConda || rule.PackageDenylist == nil || (*rule.PackageDenylist)[0] != "pypi-malware" ||
		rule.MaxSetupTimeoutSeconds == nil || *rule.MaxSetupTimeoutSeconds != 120 || rule.MaxDocumentBytes == nil || *rule.MaxDocumentBytes != 4096 {
		t.Errorf("admission rule after put = %+v, want the knobs round-tripped", rule)
	}

	blank := []string{""}
	bad := map[string]AdmissionRule{"team-a": {AllowedIndexHosts: &blank}}
	mustHTTPError(t, mustErr(s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Admission: &bad}})), 400)
	neg := int64(-1)
	bad = map[string]AdmissionRule{"team-a": {MaxSetupTimeoutSeconds: &neg}}
	mustHTTPError(t, mustErr(s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Admission: &bad}})), 400)
}

func boolPtr(b bool) *bool { return &b }
func i64(v int64) *int64   { return &v }

// --- CVE/scan gate (#58) ---

// scannedEnvironment is a published catalog entry carrying the given scan
// verdict (nil = never scanned), so the gate tests read as a table over the
// verdict.
func scannedEnvironment(name string, scan *core.EnvironmentScan) core.Environment {
	when := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	return core.Environment{
		Name:        name,
		BaseImage:   "rayproject/ray:2.9.0",
		Packages:    []string{"numpy==1.26.4"},
		Status:      core.EnvironmentStatusPublished,
		PublishedBy: strPtr("root"),
		PublishedAt: &when,
		Scan:        scan,
	}
}

// The require_scanned_environments admission knob (#58): with the rule off
// an unscanned published environment resolves fine (the default, so the
// feature is opt-in); with the rule on, an absent, pending or failed
// verdict refuses the reference with a 400 whose audit reason distinguishes
// never-vetted (environment_unscanned) from recorded-failure
// (environment_scan_failed), and only a clean verdict is admitted.
func TestScanGateRefusesUncleanEnvironments(t *testing.T) {
	clean := &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0")}
	pending := &core.EnvironmentScan{Status: core.EnvironmentScanPending}
	failed := &core.EnvironmentScan{Status: core.EnvironmentScanFailed, Scanner: strPtr("trivy 0.57.0")}

	// Rule off (no admission section at all): every published environment
	// is referenceable, scanned or not.
	off := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{
		scannedEnvironment("bare", nil),
	}}}
	op := ctxWithIdentity(testIdentity("op", auth.RoleOperator))
	if _, err := off.resolveEnvironment(context.Background(), "team-a", "bare", new(string)); err != nil {
		t.Errorf("rule off, unscanned environment: %v, want admitted", err)
	}

	// Rule on for "*": absent and pending are environment_unscanned,
	// failed is environment_scan_failed, clean is admitted.
	store := newMemStore(t)
	gated := &Server{Store: store, PolicySeed: PolicyConfig{
		Environments: []core.Environment{
			scannedEnvironment("bare", nil),
			scannedEnvironment("pending", pending),
			scannedEnvironment("failed", failed),
			scannedEnvironment("clean", clean),
		},
		Admission: map[string]core.AdmissionRule{"*": {RequireScannedEnvironments: true}},
	}}
	for name, want := range map[string]string{
		"bare":    "environment_unscanned",
		"pending": "environment_unscanned",
		"failed":  "environment_scan_failed",
	} {
		_, err := gated.resolveEnvironment(op, "team-a", name, new(string))
		if err == nil {
			t.Errorf("%s: admitted, want a 400", name)
			continue
		}
		mustHTTPError(t, err, 400)
		if got := environmentAuditReason(err); got != want {
			t.Errorf("%s: audit reason = %q, want %q", name, got, want)
		}
	}
	if _, err := gated.resolveEnvironment(op, "team-a", "clean", new(string)); err != nil {
		t.Errorf("clean verdict refused: %v, want admitted", err)
	}

	// The refusal audits under its own reason through the create path.
	body := CreateCluster{Id: "c1", Spec: ClusterSpec{
		Name: "c1", Project: "team-a", Image: "rayproject/ray:2.9.0", HeadCpu: "1", HeadMemory: "2Gi",
		WorkerGroups: []WorkerGroup{}, Environment: strPtr("failed"),
	}}
	mustHTTPError(t, mustErr(gated.CreateCluster(op, CreateClusterRequestObject{Body: &body})), http.StatusBadRequest)
	if c, _ := store.Get(context.Background(), "c1"); c != nil {
		t.Error("a scan-gate-refused create must persist nothing")
	}
	rows, _, aerr := store.ListAudit(context.Background(), core.AuditFilter{})
	if aerr != nil {
		t.Fatal(aerr)
	}
	denied := false
	for _, row := range rows {
		if row.Event.Decision == core.AuditDecisionDeny && row.Event.Reason != nil && *row.Event.Reason == "environment_scan_failed" {
			denied = true
		}
	}
	if !denied {
		t.Error("expected a create_cluster audit deny with reason environment_scan_failed")
	}

	// A "*" gate is a platform rule: a project's own rule cannot un-set it
	// (a boolean toggle carries no set/unset distinction — admissionFor's
	// inheritance, same as the runtime-env permit toggles).
	starPlusProject := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{
		Environments: []core.Environment{scannedEnvironment("bare", nil)},
		Admission: map[string]core.AdmissionRule{
			"*":      {RequireScannedEnvironments: true},
			"team-a": {RequireScannedEnvironments: false},
		},
	}}
	if _, err := starPlusProject.resolveEnvironment(op, "team-a", "bare", new(string)); err == nil {
		t.Error("project rule un-set the '*' gate: admitted, want refused")
	}

	// Per-project scope: a rule naming team-b gates team-b's references
	// only; team-a's identical reference resolves.
	perProject := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{
		Environments: []core.Environment{scannedEnvironment("bare", nil)},
		Admission:    map[string]core.AdmissionRule{"team-b": {RequireScannedEnvironments: true}},
	}}
	if _, err := perProject.resolveEnvironment(op, "team-a", "bare", new(string)); err != nil {
		t.Errorf("ungated project's reference: %v, want admitted", err)
	}
	if _, err := perProject.resolveEnvironment(op, "team-b", "bare", new(string)); err == nil {
		t.Error("gated project's reference admitted, want refused")
	}
}

// The scan gate knob rides the admission section like the runtime-env knobs:
// it round-trips through PUT/GET.
func TestUpdatePolicyAdmissionScanGateKnob(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	ctx := ctxWithIdentity(admin())
	adm := map[string]AdmissionRule{"team-a": {RequireScannedEnvironments: boolPtr(true)}}
	resp, err := s.UpdatePolicy(ctx, UpdatePolicyRequestObject{Body: &UpdatePolicy{Admission: &adm}})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rule := (*mustResponse[UpdatePolicy200JSONResponse](t, resp).Admission)["team-a"]
	if rule.RequireScannedEnvironments == nil || !*rule.RequireScannedEnvironments {
		t.Errorf("admission rule after put = %+v, want require_scanned_environments round-tripped", rule)
	}
}

// Verdict hygiene (#58): a scan verdict attests the exact packages and base
// image it scanned, so an edit changing either drops the stored verdict;
// an edit touching anything else (description, env vars, status moves that
// keep the content) keeps it.
func TestScanVerdictDropsWhenScannedContentChanges(t *testing.T) {
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{
		scannedEnvironment("ml-base", &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0")}),
	}}}
	ctx := ctxWithIdentity(admin())

	// A description-only edit keeps the verdict.
	keep := scannedEnvironment("ml-base", &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0")})
	keep.Description = strPtr("documented")
	if err := putEnvironments(t, s, ctx, []core.Environment{keep}); err != nil {
		t.Fatalf("description edit: %v", err)
	}
	if got := catalogByName(t, s, ctx)["ml-base"]; got.Scan == nil || got.Scan.Status != Clean {
		t.Errorf("verdict after a description-only edit = %+v, want kept", got.Scan)
	}

	// A packages edit drops it.
	bump := scannedEnvironment("ml-base", &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0")})
	bump.Packages = []string{"numpy==1.26.4", "pandas==2.2.2"}
	if err := putEnvironments(t, s, ctx, []core.Environment{bump}); err != nil {
		t.Fatalf("packages edit: %v", err)
	}
	if got := catalogByName(t, s, ctx)["ml-base"]; got.Scan != nil {
		t.Errorf("verdict after a packages edit = %+v, want dropped (unscanned)", got.Scan)
	}

	// A base-image edit drops it too, even when the incoming entry echoes a
	// fresh-looking verdict.
	rebase := scannedEnvironment("ml-base", &core.EnvironmentScan{Status: core.EnvironmentScanClean, Scanner: strPtr("trivy 0.57.0")})
	rebase.Packages = bump.Packages
	rebase.BaseImage = "rayproject/ray:2.10.0"
	if err := putEnvironments(t, s, ctx, []core.Environment{rebase}); err != nil {
		t.Fatalf("base image edit: %v", err)
	}
	if got := catalogByName(t, s, ctx)["ml-base"]; got.Scan != nil {
		t.Errorf("verdict after a base-image edit = %+v, want dropped (unscanned)", got.Scan)
	}
}


// The environment reference resolves at admission (#55): a cluster naming
// a published environment persists the pinned resolution (name, base image,
// compiled runtime_env, resolved-at) on its spec; an unknown name is a 400
// with an environment_rejected deny row, exactly like resolveStorage.
func TestCreateClusterResolvesEnvironment(t *testing.T) {
	store := newMemStore(t)
	env := smallEnvironment()
	s := &Server{Store: store, PolicySeed: PolicyConfig{Environments: []core.Environment{env}}}
	ctx := ctxWithIdentity(testIdentity("op", auth.RoleOperator))

	body := CreateCluster{Id: "c1", Spec: ClusterSpec{
		Name: "c1", Project: "team-a", Image: env.BaseImage, HeadCpu: "1", HeadMemory: "2Gi",
		WorkerGroups: []WorkerGroup{}, Environment: strPtr(env.Name),
	}}
	if _, err := s.CreateCluster(ctx, CreateClusterRequestObject{Body: &body}); err != nil {
		t.Fatalf("create with environment: %v", err)
	}
	stored, err := store.Get(context.Background(), "c1")
	if err != nil || stored == nil {
		t.Fatalf("cluster not persisted: %v", err)
	}
	r := stored.Spec.EnvironmentResolved
	if r == nil || r.Name != env.Name || r.BaseImage != env.BaseImage || r.ResolvedAt == nil {
		t.Fatalf("environment_resolved = %+v, want the pinned resolution", r)
	}
	doc := decodeYaml(t, r.RuntimeEnvYaml)
	if pip, _ := doc["pip"].([]interface{}); len(pip) != len(env.Packages) {
		t.Errorf("compiled pip = %v, want the environment's packages", doc["pip"])
	}
	// #56: the pinned resolution carries the bounded setup timeout.
	if secs, set := setupTimeoutOf(t, r.RuntimeEnvYaml); !set || secs != DefaultSetupTimeoutSeconds {
		t.Errorf("pinned resolution setup timeout = %d (set %v), want the injected %d", secs, set, DefaultSetupTimeoutSeconds)
	}

	// An unknown name refuses the create with a deny row naming the reason.
	unknown := body
	unknown.Id = "c2"
	unknown.Spec.Name = "c2"
	unknown.Spec.Environment = strPtr("nosuch")
	mustHTTPError(t, mustErr(s.CreateCluster(ctx, CreateClusterRequestObject{Body: &unknown})), http.StatusBadRequest)
	rows, _, aerr := store.ListAudit(context.Background(), core.AuditFilter{})
	if aerr != nil {
		t.Fatal(aerr)
	}
	denied := false
	for _, row := range rows {
		if row.Event.Decision == core.AuditDecisionDeny && row.Event.Reason != nil && *row.Event.Reason == "environment_rejected" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("expected a create_cluster audit deny with reason environment_rejected")
	}
	if c, _ := store.Get(context.Background(), "c2"); c != nil {
		t.Fatal("a refused create must persist nothing")
	}
}
