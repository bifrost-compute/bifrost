package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/core"
)

// decodeYaml parses a compiled runtime_env document for assertions.
func decodeYaml(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.NewDecoder(strings.NewReader(raw)).Decode(&doc); err != nil {
		t.Fatalf("compiled runtime_env does not parse: %v\n%s", err, raw)
	}
	return doc
}

// submitJobWithEnvironment submits a job naming envName, with the given
// image and optional hand-written runtime_env_yaml, and returns the HTTP
// status (201 on success).
func submitJobWithEnvironment(t *testing.T, s *Server, id *auth.Identity, jobID, project, envName, image, runtimeEnv string) int {
	t.Helper()
	body := jobBodyFor(project)
	body.Id = strPtr(jobID)
	body.Spec.Image = image
	body.Spec.Environment = strPtr(envName)
	if runtimeEnv != "" {
		body.Spec.RuntimeEnvYaml = strPtr(runtimeEnv)
	}
	_, err := s.SubmitJob(ctxWithIdentity(id), SubmitJobRequestObject{Body: &body})
	return okOr(t, err)
}

// Environment resolution (#55): unknown names, environments closed to the
// caller's project, and non-published statuses are all 400 — only a
// published environment available to the project is referenceable.
func TestSubmitJobEnvironmentRefusals(t *testing.T) {
	published := smallEnvironment("team-a")
	draft := smallEnvironment()
	draft.Name, draft.Status = "wip", core.EnvironmentStatusDraft
	deprecated := smallEnvironment()
	deprecated.Name, deprecated.Status = "old", core.EnvironmentStatusDeprecated
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{published, draft, deprecated}}}
	admin := testIdentity("admin", auth.RoleAdmin)

	for name, tc := range map[string]struct {
		env, project string
	}{
		"unknown name":    {"nosuch", "team-a"},
		"foreign project": {"ml-base", "team-b"},
		"draft":           {"wip", "team-a"},
		"deprecated":      {"old", "team-a"},
	} {
		if got := submitJobWithEnvironment(t, s, admin, "job-"+tc.env, tc.project, tc.env, "rayproject/ray:2.9.0", ""); got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, got)
		}
		if j, _ := s.Store.GetRayJob(context.Background(), core.ClusterId("job-"+tc.env)); j != nil {
			t.Errorf("%s: a refused submit must persist nothing", name)
		}
	}
}

// The happy path: the job's image comes from the environment's base image
// when the request leaves it empty, the compiled runtime_env (packages ->
// pip, env_vars merged — the escape hatch's variables alongside the
// structured ones) rides the spec into the RayJob CR, and the resolution is
// pinned on the spec with its resolved-at stamp.
func TestSubmitJobResolvesEnvironment(t *testing.T) {
	store := newMemStore(t)
	env := smallEnvironment()
	env.RuntimeEnvYaml = "env_vars:\n  TOKEN_PATH: /var/run/token\nconfig:\n  setup_timeout_seconds: 300\nworking_dir: ./src"
	s := &Server{Store: store, PolicySeed: PolicyConfig{Environments: []core.Environment{env}}}
	admin := testIdentity("admin", auth.RoleAdmin)

	if got := submitJobWithEnvironment(t, s, admin, "job-env", "team-a", env.Name, "", ""); got != http.StatusOK {
		t.Fatalf("submit = %d, want accepted", got)
	}
	j, err := store.GetRayJob(context.Background(), "job-env")
	if err != nil || j == nil {
		t.Fatalf("job not persisted: %v", err)
	}
	if j.Spec.Image != env.BaseImage || j.Spec.RayVersion != "2.9.0" {
		t.Errorf("image/ray_version = %q/%q, want the environment's base image and its derived version", j.Spec.Image, j.Spec.RayVersion)
	}
	r := j.Spec.EnvironmentResolved
	if r == nil || r.Name != env.Name || r.BaseImage != env.BaseImage || r.ResolvedAt == nil {
		t.Fatalf("environment_resolved = %+v, want the pinned resolution", r)
	}
	if j.Spec.RuntimeEnvYaml != r.RuntimeEnvYaml {
		t.Errorf("spec runtime_env %q != the pinned compiled document %q", j.Spec.RuntimeEnvYaml, r.RuntimeEnvYaml)
	}
	doc := decodeYaml(t, r.RuntimeEnvYaml)
	pip, _ := doc["pip"].([]interface{})
	if len(pip) != len(env.Packages) || pip[0] != "numpy==1.26.4" || pip[1] != "pandas[excel]==2.2.2" {
		t.Errorf("compiled pip = %v, want the environment's packages", pip)
	}
	vars, _ := doc["env_vars"].(map[string]interface{})
	if len(vars) != 2 || vars["OMP_NUM_THREADS"] != "4" || vars["TOKEN_PATH"] != "/var/run/token" {
		t.Errorf("compiled env_vars = %v, want structured and escape-hatch variables merged", vars)
	}
	cfg, _ := doc["config"].(map[string]interface{})
	if cfg["setup_timeout_seconds"] != 300 || doc["working_dir"] != "./src" {
		t.Errorf("escape-hatch fields did not merge through: %v", doc)
	}
}

// Whole-or-nothing (profile expansion's rule): a request that supplies both
// environment and runtime_env_yaml is a 400; an image that differs from the
// environment's base image is a 400, while the same image is accepted.
func TestSubmitJobEnvironmentConflicts(t *testing.T) {
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{Environments: []core.Environment{smallEnvironment()}}}
	admin := testIdentity("admin", auth.RoleAdmin)

	if got := submitJobWithEnvironment(t, s, admin, "job-both", "team-a", "ml-base", "rayproject/ray:2.9.0", "pip: [requests==2.31.0]"); got != http.StatusBadRequest {
		t.Errorf("environment + runtime_env_yaml = %d, want 400", got)
	}
	if got := submitJobWithEnvironment(t, s, admin, "job-img", "team-a", "ml-base", "rayproject/ray:2.56.0", ""); got != http.StatusBadRequest {
		t.Errorf("image differing from the environment's base image = %d, want 400", got)
	}
	if got := submitJobWithEnvironment(t, s, admin, "job-same", "team-a", "ml-base", "rayproject/ray:2.9.0", ""); got != http.StatusOK {
		t.Errorf("image equal to the environment's base image = %d, want accepted", got)
	}
}

// The environment's base image is an image like any other: the project's
// admission allowlist applies to it (like a profile's image).
func TestSubmitJobEnvironmentBaseImageMustPassAdmission(t *testing.T) {
	env := smallEnvironment()
	env.BaseImage = "evil/img:2.9.0"
	s := &Server{Store: newMemStore(t), PolicySeed: PolicyConfig{
		Environments: []core.Environment{env},
		Admission:    Admission{AllowedImagePrefixes: []string{"rayproject/"}}.SeedRules(),
	}}
	admin := testIdentity("admin", auth.RoleAdmin)
	if got := submitJobWithEnvironment(t, s, admin, "job-evil", "team-a", env.Name, "", ""); got != http.StatusBadRequest {
		t.Fatalf("base image outside the admission allowlist = %d, want 400", got)
	}
}

// The resolution is pinned at admission: a later catalog edit — changed
// packages, even deprecation — never reaches into an already-admitted
// workload.
func TestEnvironmentResolutionIsNotRetroactive(t *testing.T) {
	store := newMemStore(t)
	s := &Server{Store: store, PolicySeed: PolicyConfig{Environments: []core.Environment{smallEnvironment()}}}
	admin := testIdentity("admin", auth.RoleAdmin)
	ctx := context.Background()

	if got := submitJobWithEnvironment(t, s, admin, "job-pin", "team-a", "ml-base", "rayproject/ray:2.9.0", ""); got != http.StatusOK {
		t.Fatalf("submit = %d, want accepted", got)
	}
	before, err := store.GetRayJob(ctx, "job-pin")
	if err != nil || before == nil {
		t.Fatal("job not persisted")
	}
	pinned := before.Spec.EnvironmentResolved

	// Rewrite the catalog entry: different packages, deprecated status.
	edited := smallEnvironment()
	edited.Packages = []string{"scipy==1.14.1"}
	edited.Status = core.EnvironmentStatusDeprecated
	envs := []EnvironmentSpec{environmentToWire(&edited)}
	if _, err := s.UpdatePolicy(ctxWithIdentity(admin), UpdatePolicyRequestObject{Body: &UpdatePolicy{Environments: &envs}}); err != nil {
		t.Fatalf("catalog edit: %v", err)
	}

	after, err := store.GetRayJob(ctx, "job-pin")
	if err != nil || after == nil {
		t.Fatal("job vanished")
	}
	r := after.Spec.EnvironmentResolved
	if r == nil || r.RuntimeEnvYaml != pinned.RuntimeEnvYaml || r.BaseImage != pinned.BaseImage ||
		r.ResolvedAt == nil || !r.ResolvedAt.Equal(*pinned.ResolvedAt) {
		t.Errorf("resolution moved under the admitted job: before %+v after %+v", pinned, r)
	}
	if after.Spec.RuntimeEnvYaml != pinned.RuntimeEnvYaml {
		t.Errorf("spec runtime_env moved: %q, want %q", after.Spec.RuntimeEnvYaml, pinned.RuntimeEnvYaml)
	}
	doc := decodeYaml(t, r.RuntimeEnvYaml)
	if pip, _ := doc["pip"].([]interface{}); len(pip) != 2 || pip[0] != "numpy==1.26.4" {
		t.Errorf("compiled pip after the catalog edit = %v, want the originally admitted packages", pip)
	}

	// And the deprecated entry now refuses new references.
	if got := submitJobWithEnvironment(t, s, admin, "job-late", "team-a", "ml-base", "rayproject/ray:2.9.0", ""); got != http.StatusBadRequest {
		t.Errorf("new reference to a deprecated environment = %d, want 400", got)
	}
}
