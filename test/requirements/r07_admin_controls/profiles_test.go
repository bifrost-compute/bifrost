package r07_admin_controls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// Profiles are the "profiles" half of requirement 7: an administrator
// defines named cluster shapes through the policy API, scoped to
// projects, and a user picks one by name — leaving the shape fields empty
// — instead of spelling out image, Ray version and quantities. The policy
// is platform state, so every test snapshots the profiles/admission
// sections and restores them on exit (never `[]`/`{}` blindly: a cluster
// target's deployment-wide "*" admission rule must survive).

// setPolicySections PUTs the given policy sections as admin and restores
// the sections it touched when the test ends.
func setPolicySections(t *testing.T, tgt req.Target, sections string) {
	t.Helper()
	ctx := context.Background()
	admin := tgt.As("admin").API()
	before, err := admin.GetPolicyWithResponse(ctx)
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v status=%v body=%s", err, before.StatusCode(), before.Body)
	}
	var body client.UpdatePolicyJSONRequestBody
	if err := json.Unmarshal([]byte(sections), &body); err != nil {
		t.Fatal(err)
	}
	r, err := admin.UpdatePolicyWithResponse(ctx, body)
	if err != nil || r.StatusCode()/100 != 2 {
		t.Fatalf("update_policy %s: err=%v status=%v body=%s", sections, err, r.StatusCode(), r.Body)
	}
	t.Cleanup(func() {
		restore := client.UpdatePolicyJSONRequestBody{}
		if body.Profiles != nil {
			profiles := []client.ProfileSpec{}
			if before.JSON200.Profiles != nil {
				profiles = *before.JSON200.Profiles
			}
			restore.Profiles = &profiles
		}
		if body.Admission != nil {
			admission := map[string]client.AdmissionRule{}
			if before.JSON200.Admission != nil {
				admission = *before.JSON200.Admission
			}
			restore.Admission = &admission
		}
		if body.Images != nil {
			images := []client.ImageEntry{}
			if before.JSON200.Images != nil {
				images = *before.JSON200.Images
			}
			restore.Images = &images
		}
		_, _ = admin.UpdatePolicyWithResponse(context.Background(), restore)
	})
}

// smallProfileJSON is a one-worker profile named `name`, open to
// `projects`, with `maxWorkers` as its worker cap (0 = none).
func smallProfileJSON(name string, projects []string, maxWorkers int) string {
	projs, _ := json.Marshal(projects)
	capJSON := "null"
	if maxWorkers > 0 {
		capJSON = fmt.Sprint(maxWorkers)
	}
	return fmt.Sprintf(`{"name":%q,"description":"one worker","projects":%s,"image":%q,"ray_version":"2.56.0",
		"head_cpu":"1","head_memory":"2Gi","max_workers":%s,
		"worker_groups":[{"name":"w","cpu":"1","memory":"2Gi","gpu":null,"min_replicas":%[6]d,"max_replicas":%[6]d,"replicas":%[6]d}]}`,
		name, projs, fixture.RayImage(), capJSON, 0, fixture.WorkerReplicas())
}

// profileBody is a create whose shape fields are all empty: the profile
// fills them.
func profileBody(id, project, profile string) client.CreateClusterJSONRequestBody {
	raw := fmt.Sprintf(`{"id":%q,"spec":{"name":%q,"project":%q,"profile":%q,"ray_version":"","image":"",
		"head_cpu":"","head_memory":"","worker_groups":[]}}`, id, id, project, profile)
	var body client.CreateClusterJSONRequestBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		panic("profileBody: " + err.Error())
	}
	return body
}

func TestProfileSelectedByName(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "a user creates a cluster by naming an administrator's profile with empty shape fields; a project the profile excludes gets 400")
	ctx := context.Background()
	profile := req.Name("small")
	setPolicySections(t, tgt, fmt.Sprintf(`{"profiles":[%s]}`, smallProfileJSON(profile, []string{"team-a"}, 0)))

	id := req.Name("prof")
	resp, err := tgt.As("dev-a").API().CreateClusterWithResponse(ctx, profileBody(id, "team-a", profile))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusCreated {
		t.Fatalf("create with profile = %d %s, want 201", resp.StatusCode(), resp.Body)
	}
	got, err := tgt.As("dev-a").API().GetClusterWithResponse(ctx, id)
	if err != nil || got.JSON200 == nil {
		t.Fatalf("get: err=%v status=%v body=%s", err, got.StatusCode(), got.Body)
	}
	if got.JSON200.RayVersion != "2.56.0" {
		t.Errorf("ray_version = %q, want the profile's 2.56.0", got.JSON200.RayVersion)
	}

	other := req.Name("profb")
	resp, err = tgt.As("dev-b").API().CreateClusterWithResponse(ctx, profileBody(other, "team-b", profile))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("create with a profile not open to team-b = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if st, _ := fixture.Get(t, tgt, "admin", other); st != http.StatusNotFound {
		t.Fatalf("a refused create must persist nothing; get = %d", st)
	}
}

func TestListProfilesShowsOnlyTheCallersProjects(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "list_profiles shows a project member the profiles open to their projects, and an administrator the whole catalog")
	ctx := context.Background()
	forA, forB, forAll := req.Name("pa"), req.Name("pb"), req.Name("pall")
	setPolicySections(t, tgt, fmt.Sprintf(`{"profiles":[%s,%s,%s]}`,
		smallProfileJSON(forA, []string{"team-a"}, 0), smallProfileJSON(forB, []string{"team-b"}, 0), smallProfileJSON(forAll, nil, 0)))

	names := func(principal string) map[string]bool {
		r, err := tgt.As(principal).API().ListProfilesWithResponse(ctx)
		if err != nil || r.JSON200 == nil {
			t.Fatalf("list_profiles as %s: err=%v status=%v body=%s", principal, err, r.StatusCode(), r.Body)
		}
		out := map[string]bool{}
		for _, p := range *r.JSON200 {
			out[p.Name] = true
		}
		return out
	}
	a := names("dev-a")
	if !a[forA] || !a[forAll] || a[forB] {
		t.Errorf("dev-a sees %v, want %s and %s but not %s", a, forA, forAll, forB)
	}
	admin := names("admin")
	if !admin[forA] || !admin[forB] || !admin[forAll] {
		t.Errorf("admin sees %v, want all three", admin)
	}
}

func TestProfileMaxWorkersIsEnforced(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "a profile's max_workers caps the worker replicas a cluster using it may ask for")
	ctx := context.Background()
	profile := req.Name("capped")
	// A head-only profile with a cap of 1: the request brings its own
	// worker group, and the profile's cap governs it.
	raw := fmt.Sprintf(`{"name":%q,"projects":["team-a"],"image":%q,"ray_version":"2.56.0","head_cpu":"1","head_memory":"2Gi","max_workers":1,"worker_groups":[]}`,
		profile, fixture.RayImage())
	setPolicySections(t, tgt, fmt.Sprintf(`{"profiles":[%s]}`, raw))

	body := profileBody(req.Name("over"), "team-a", profile)
	var groups []client.WorkerGroup
	_ = json.Unmarshal([]byte(`[{"name":"w","cpu":"1","memory":"2Gi","min_replicas":0,"max_replicas":2,"replicas":0}]`), &groups)
	body.Spec.WorkerGroups = groups
	resp, err := tgt.As("dev-a").API().CreateClusterWithResponse(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("create over the profile's worker cap = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	body.Spec.WorkerGroups[0].MaxReplicas = 1
	body.Id = req.Name("atcap")
	body.Spec.Name = body.Id
	resp, err = tgt.As("dev-a").API().CreateClusterWithResponse(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusCreated {
		t.Fatalf("create at the profile's worker cap = %d %s, want 201", resp.StatusCode(), resp.Body)
	}
}

func TestConflictingFieldWithProfileIsRefused(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "a create that names a profile and also sets a shape field the profile fixes is refused with 400")
	ctx := context.Background()
	profile := req.Name("fixed")
	setPolicySections(t, tgt, fmt.Sprintf(`{"profiles":[%s]}`, smallProfileJSON(profile, []string{"team-a"}, 0)))

	body := profileBody(req.Name("conf"), "team-a", profile)
	body.Spec.HeadCpu = "2"
	resp, err := tgt.As("dev-a").API().CreateClusterWithResponse(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("create with a conflicting head_cpu = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if !fixture.Contains(string(resp.Body), "head_cpu") {
		t.Errorf("refusal should name the conflicting field: %s", resp.Body)
	}
}
