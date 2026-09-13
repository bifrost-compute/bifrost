package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost-compute/bifrost/internal/auth"
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
		"empty var":     {func() EnvironmentSpec { e := good; e.Name = "v"; v := map[string]string{"": "x"}; e.EnvVars = &v; return e }()},
		"bad status":    {func() EnvironmentSpec { e := good; e.Name = "s"; e.Status = &bogus; return e }()},
		"bad scan":      {func() EnvironmentSpec { e := good; e.Name = "c"; e.Scan = &EnvironmentScan{Status: bogusScan}; return e }()},
		"ungoverned yaml": {func() EnvironmentSpec {
			e := good
			e.Name = "y"
			e.Status = &draft
			e.RuntimeEnvYaml = strPtr("conda: {}")
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
		AllowConda:               boolPtr(true),
		AllowUnpinnedPackages:    boolPtr(true),
		PackageDenylist:          &deny,
		AllowedIndexHosts:        &hosts,
		AllowedRemoteSchemes:     &schemes,
		AllowedRemoteHosts:       &buckets,
		MaxSetupTimeoutSeconds:   i64(120),
		MaxDocumentBytes:         i64(4096),
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
func i64(v int64) *int64     { return &v }

// The environment reference is inert in #52: a spec that names one is
// accepted and stored verbatim; nothing resolves it yet (#55).
func TestEnvironmentReferenceIsAcceptedAndStored(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store}
	ctx := ctxWithIdentity(testIdentity("op", auth.RoleOperator))

	env := "ml-base"
	body := CreateCluster{Id: "c1", Spec: ClusterSpec{
		Name: "c1", Project: "team-a", Image: "rayproject/ray:2.9.0", HeadCpu: "1", HeadMemory: "2Gi",
		WorkerGroups: []WorkerGroup{}, Environment: &env,
	}}
	if _, err := s.CreateCluster(ctx, CreateClusterRequestObject{Body: &body}); err != nil {
		t.Fatalf("create with environment: %v", err)
	}
	stored, err := store.Get(context.Background(), "c1")
	if err != nil || stored == nil {
		t.Fatalf("cluster not persisted: %v", err)
	}
	if stored.Spec.Environment == nil || *stored.Spec.Environment != "ml-base" {
		t.Errorf("stored spec environment = %v, want ml-base kept", stored.Spec.Environment)
	}
}
