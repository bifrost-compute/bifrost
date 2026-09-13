// Story: the administrator onboards team-a (requirements 7, 12, 13).
//
// One admin session sets up everything a new team needs: a compute pool
// with a team-a allocation (developers may not touch pools), a profile
// scoped to team-a that fills a cluster's shape by name, a per-project
// image allowlist that binds team-b and not team-a, and a private-storage
// catalog entry team-a can reference by name while its Secret's value never
// crosses the API. Every refusal — 400 or 403 — leaves a deny row, and the
// audit chain verifies at the end.
package story_admin_onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// setPolicySections PUTs the given policy sections as admin and restores
// the sections it touched when the test ends (the policy is platform
// state). Same shape as r07's helper; duplicated per the repo convention
// that requirement packages share only fixture/.
func setPolicySections(t *testing.T, tgt req.Target, sections string) []byte {
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
		if body.Storage != nil {
			storage := []client.StorageEntry{}
			if before.JSON200.Storage != nil {
				storage = *before.JSON200.Storage
			}
			restore.Storage = &storage
		}
		if body.Environments != nil {
			environments := []client.EnvironmentSpec{}
			if before.JSON200.Environments != nil {
				environments = *before.JSON200.Environments
			}
			restore.Environments = &environments
		}
		_, _ = admin.UpdatePolicyWithResponse(context.Background(), restore)
	})
	return r.Body
}

// smallProfileJSON is a one-worker profile named `name`, open to
// `projects`.
func smallProfileJSON(name string, projects []string) string {
	projs, _ := json.Marshal(projects)
	return fmt.Sprintf(`{"name":%q,"description":"one worker","projects":%s,"image":%q,"ray_version":"2.56.0",
		"head_cpu":"1","head_memory":"2Gi","max_workers":null,
		"worker_groups":[{"name":"w","cpu":"1","memory":"2Gi","gpu":null,"min_replicas":%[4]d,"max_replicas":%[4]d,"replicas":%[4]d}]}`,
		name, projs, fixture.RayImage(), fixture.WorkerReplicas())
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

// createCluster posts body as principal, registers teardown on 201, and
// returns (status, body).
func createCluster(t *testing.T, tgt req.Target, principal string, body client.CreateClusterJSONRequestBody) (int, []byte) {
	t.Helper()
	resp, err := tgt.As(principal).API().CreateClusterWithResponse(context.Background(), body)
	if err != nil {
		t.Fatalf("create %s as %s: %v", body.Id, principal, err)
	}
	if resp.StatusCode() == http.StatusCreated {
		t.Cleanup(func() { fixture.Delete(t, tgt, "admin", body.Id) })
	}
	return resp.StatusCode(), resp.Body
}

type auditRow struct {
	Subject  *string `json:"subject"`
	Decision string  `json:"decision"`
	Reason   *string `json:"reason"`
}

func TestAdminOnboardsTeamA(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "the administrator onboards team-a with a profile and an image allowlist; out-of-scope and off-list creates are 400 and audited")
	req.Covers(t, 7, "a published environment from the governed catalog resolves at admission for its project; foreign and unknown references are 400 and audited")
	req.Covers(t, 12, "team-a's storage entry is referenced by name; another project's reference is 400 and no Secret value ever crosses the API")
	req.Covers(t, 13, "the administrator creates a compute pool and allocates team-a into it; a developer's pool mutation is 403")
	ctx := context.Background()
	admin := tgt.As("admin").API()
	devA := fixture.Subject(t, tgt, "dev-a")
	devB := fixture.Subject(t, tgt, "dev-b")

	// Pools: a compute pool with team-a allocated. Only admins mutate them.
	pool := req.Name("onbpool")
	var createPool client.CreatePoolJSONRequestBody
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"spec":{"name":%q,"cohort":"req-onb","fair_sharing_weight":1,"elastic":false,
		"flavors":[{"name":"default","resources":{"cpu":"16","memory":"64Gi"},"node_labels":{},"taints":[]}]}}`, pool)), &createPool)
	if r, err := admin.CreatePoolWithResponse(ctx, createPool); err != nil || r.StatusCode()/100 != 2 {
		t.Fatalf("create pool: err=%v status=%v body=%s", err, r.StatusCode(), r.Body)
	}
	t.Cleanup(func() { _, _ = admin.DeletePoolWithResponse(context.Background(), pool) })
	if r, err := tgt.As("dev-a").API().CreatePoolWithResponse(ctx, createPool); err != nil || r.StatusCode() != http.StatusForbidden {
		t.Fatalf("developer create pool: err=%v status=%v, want 403", err, r.StatusCode())
	}
	var alloc client.PutAllocationJSONRequestBody
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"namespace":%q,"nominal":{"cpu":"8","memory":"32Gi"},"borrowing_limit":{},"lending_limit":{}}`, tgt.Namespace())), &alloc)
	if r, err := admin.PutAllocationWithResponse(ctx, pool, "team-a", alloc); err != nil || r.StatusCode()/100 != 2 {
		t.Fatalf("put allocation: err=%v status=%v body=%s", err, r.StatusCode(), r.Body)
	}
	t.Cleanup(func() { _, _ = admin.DeleteAllocationWithResponse(context.Background(), pool, "team-a") })

	// Profiles: one small profile, open to team-a only.
	profile := req.Name("onbsmall")
	setPolicySections(t, tgt, fmt.Sprintf(`{"profiles":[%s]}`, smallProfileJSON(profile, []string{"team-a"})))

	idA := req.Name("onba")
	if st, body := createCluster(t, tgt, "dev-a", profileBody(idA, "team-a", profile)); st != http.StatusCreated {
		t.Fatalf("dev-a create with the team-a profile = %d %s, want 201", st, body)
	}
	got, err := tgt.As("dev-a").API().GetClusterWithResponse(ctx, idA)
	if err != nil || got.JSON200 == nil {
		t.Fatalf("get: err=%v status=%v body=%s", err, got.StatusCode(), got.Body)
	}
	if got.JSON200.RayVersion != "2.56.0" {
		t.Errorf("ray_version = %q, want the profile's 2.56.0", got.JSON200.RayVersion)
	}
	idB := req.Name("onbb")
	if st, body := createCluster(t, tgt, "dev-b", profileBody(idB, "team-b", profile)); st != http.StatusBadRequest {
		t.Fatalf("dev-b create with team-a's profile = %d %s, want 400", st, body)
	}
	if st, _ := fixture.Get(t, tgt, "admin", idB); st != http.StatusNotFound {
		t.Fatalf("a refused create must persist nothing; get = %d", st)
	}
	if st, body := createCluster(t, tgt, "dev-a", profileBody(req.Name("onbnp"), "team-a", req.Name("nosuchprofile"))); st != http.StatusBadRequest {
		t.Fatalf("create with an unknown profile = %d %s, want 400", st, body)
	}

	// Admission: team-b's allowlist refuses the canonical image; team-a is
	// unaffected.
	setPolicySections(t, tgt, `{"admission":{"team-b":{"allowed_images":["registry.example/"]}}}`)
	if st, body := createCluster(t, tgt, "dev-b", fixture.ClusterBody(req.Name("onbimg"), "team-b", nil)); st != http.StatusBadRequest {
		t.Fatalf("team-b create outside its allowlist = %d %s, want 400", st, body)
	}
	if st, body := createCluster(t, tgt, "dev-a", fixture.ClusterBody(req.Name("onbok"), "team-a", nil)); st != http.StatusCreated {
		t.Fatalf("team-a create with the canonical image = %d %s, want 201", st, body)
	}

	// Storage: an env-mode entry naming a Secret, scoped to team-a. The
	// Secret's value is never named anywhere — Bifrost carries the name,
	// the kubelet resolves it.
	entry := req.Name("onb-s3")
	secret := req.Name("onb-creds")
	entries, _ := json.Marshal([]client.StorageEntry{{Name: entry, SecretName: &secret, Mode: client.Env, Projects: &[]string{"team-a"}}})
	put := setPolicySections(t, tgt, fmt.Sprintf(`{"storage":%s}`, entries))

	bodies := map[string][]byte{"update_policy": put}
	storID := req.Name("onbst")
	storBody := fixture.ClusterBody(storID, "team-a", nil)
	storBody.Spec.Storage = &[]string{entry}
	st, created := createCluster(t, tgt, "dev-a", storBody)
	if st != http.StatusCreated {
		t.Fatalf("dev-a create referencing team-a's storage = %d %s, want 201", st, created)
	}
	bodies["create_cluster"] = created

	// dev-b referencing team-a's entry: 400 (an allowlisted image, so the
	// refusal is the storage scope, not admission).
	crossBody := fixture.ClusterBodyWithImage(req.Name("onbx"), "team-b", "registry.example/ray:2.56.0", nil)
	crossBody.Spec.Storage = &[]string{entry}
	if st, body := createCluster(t, tgt, "dev-b", crossBody); st != http.StatusBadRequest {
		t.Fatalf("dev-b referencing team-a's storage = %d %s, want 400", st, body)
	}
	// An unknown name is 400 too.
	unknownBody := fixture.ClusterBody(req.Name("onbu"), "team-a", nil)
	unknownBody.Spec.Storage = &[]string{req.Name("nosuchstorage")}
	if st, body := createCluster(t, tgt, "dev-a", unknownBody); st != http.StatusBadRequest {
		t.Fatalf("create with unknown storage = %d %s, want 400", st, body)
	}

	// Environments (#52/#55): a published entry scoped to team-a, its base
	// image the canonical one so the reference alone decides the outcome.
	// dev-a's create resolves it at admission; dev-b's reference of a
	// foreign entry and any unknown name are 400.
	envName := req.Name("onbenv")
	envImage := fixture.RayImage()
	envStatus := client.Published
	envs, _ := json.Marshal([]client.EnvironmentSpec{{
		Name:      envName,
		BaseImage: &envImage,
		Packages:  &[]string{"numpy==1.26.4"},
		EnvVars:   &map[string]string{"OMP_NUM_THREADS": "4"},
		Projects:  &[]string{"team-a"},
		Status:    &envStatus,
	}})
	setPolicySections(t, tgt, fmt.Sprintf(`{"environments":%s}`, envs))

	envBody := fixture.ClusterBody(req.Name("onbe"), "team-a", nil)
	envBody.Spec.Environment = &envName
	if st, body := createCluster(t, tgt, "dev-a", envBody); st != http.StatusCreated {
		t.Fatalf("dev-a create referencing team-a's environment = %d %s, want 201", st, body)
	}
	crossEnv := fixture.ClusterBodyWithImage(req.Name("onbef"), "team-b", "registry.example/ray:2.56.0", nil)
	crossEnv.Spec.Environment = &envName
	if st, body := createCluster(t, tgt, "dev-b", crossEnv); st != http.StatusBadRequest {
		t.Fatalf("dev-b referencing team-a's environment = %d %s, want 400", st, body)
	}
	unknownEnv := fixture.ClusterBody(req.Name("onbeu"), "team-a", nil)
	unknownEnv.Spec.Environment = &[]string{req.Name("nosuchenv")}[0]
	if st, body := createCluster(t, tgt, "dev-a", unknownEnv); st != http.StatusBadRequest {
		t.Fatalf("create with unknown environment = %d %s, want 400", st, body)
	}

	// Nothing resolved ever crosses the wire: the policy view carries only
	// names and delivery instructions, cluster views carry no resolution,
	// and the audit trail never saw a Secret's name or value.
	var policyView struct {
		Storage []map[string]any `json:"storage"`
	}
	if err := json.Unmarshal(put, &policyView); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"name": true, "source": true, "secret_name": true, "claim_name": true, "mode": true, "mount_path": true, "projects": true}
	found := false
	for _, e := range policyView.Storage {
		if e["name"] == entry {
			found = true
		}
		for k := range e {
			if !allowed[k] {
				t.Errorf("policy storage entry carries %q; only names and delivery instructions may be on the wire (%v)", k, e)
			}
		}
	}
	if !found {
		t.Fatalf("PUT response does not list %s: %s", entry, put)
	}
	if got, err := tgt.As("dev-a").API().GetClusterWithResponse(ctx, storID); err == nil {
		bodies["get_cluster"] = got.Body
	}
	if list, err := tgt.As("dev-a").API().ListClustersWithResponse(ctx); err == nil {
		bodies["list_clusters"] = list.Body
	}
	audit, err := tgt.As("admin").API().ListAuditEventsWithResponse(ctx, nil)
	if err != nil || audit.StatusCode() != http.StatusOK {
		t.Fatalf("list_audit_events: err=%v status=%v", err, audit.StatusCode())
	}
	bodies["list_audit_events"] = audit.Body
	for what, body := range bodies {
		if strings.Contains(string(body), "storage_resolved") {
			t.Errorf("%s response carries the storage resolution: %s", what, body)
		}
		// The policy view legitimately names the Secret; nothing else may.
		if what != "update_policy" && strings.Contains(string(body), secret) {
			t.Errorf("%s response names the Secret %s: the reference must stay inside the policy", what, secret)
		}
	}

	// Every refusal in the session left a deny row naming its caller.
	var rows []auditRow
	if err := json.Unmarshal(audit.Body, &struct {
		Items *[]auditRow `json:"items"`
	}{Items: &rows}); err != nil {
		t.Fatalf("list_audit_events: unmarshal: %v", err)
	}
	deny := func(subject, reason string) bool {
		for _, r := range rows {
			if r.Decision == "deny" && r.Subject != nil && *r.Subject == subject && r.Reason != nil && *r.Reason == reason {
				return true
			}
		}
		return false
	}
	for _, want := range [][2]string{
		{devA, "insufficient_permission"}, // create_pool as a developer
		{devB, "profile_rejected"},        // team-a's profile used by team-b
		{devA, "profile_rejected"},        // unknown profile
		{devB, "image_not_allowed"},       // team-b outside its allowlist
		{devB, "storage_rejected"},        // team-b referencing team-a's entry
		{devA, "storage_rejected"},        // unknown storage name
		{devB, "environment_rejected"},    // team-b referencing team-a's environment
		{devA, "environment_rejected"},    // unknown environment name
	} {
		if !deny(want[0], want[1]) {
			t.Errorf("no deny row for subject %s reason %s", want[0], want[1])
		}
	}

	ver, err := admin.VerifyAuditTrailWithResponse(ctx, nil)
	if err != nil || ver.StatusCode() != http.StatusOK {
		t.Fatalf("verify_audit_trail: err=%v status=%v", err, ver.StatusCode())
	}
	var res struct {
		Ok          bool   `json:"ok"`
		FirstBroken *int64 `json:"first_broken_seq"`
	}
	if err := json.Unmarshal(ver.Body, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Ok || res.FirstBroken != nil {
		t.Fatalf("audit chain broken: %s", ver.Body)
	}
}
