package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/registry"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// policyWith seeds the store's policy row with the given catalogs.
func policyWith(t *testing.T, store controller.Store, p controller.StoredPolicy) {
	t.Helper()
	if err := store.SetPolicy(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
}

func updatePolicyJSON(t *testing.T, s *Server, id *auth.Identity, sections string) error {
	t.Helper()
	var body UpdatePolicyJSONRequestBody
	if err := json.Unmarshal([]byte(sections), &body); err != nil {
		t.Fatal(err)
	}
	_, err := s.UpdatePolicy(ctxWithIdentity(id), UpdatePolicyRequestObject{Body: &body})
	return err
}

func submitJSON(t *testing.T, s *Server, id *auth.Identity, raw string) error {
	t.Helper()
	var body SubmitJobJSONRequestBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	_, err := s.SubmitJob(ctxWithIdentity(id), SubmitJobRequestObject{Body: &body})
	return err
}

func createJSON(t *testing.T, s *Server, id *auth.Identity, raw string) error {
	t.Helper()
	var body CreateClusterJSONRequestBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateCluster(ctxWithIdentity(id), CreateClusterRequestObject{Body: &body})
	return err
}

func rayEntry(projects ...string) core.ImageEntry {
	return core.ImageEntry{Name: "ray-2.9", Ref: "rayproject/ray:2.9.0", RayVersion: "2.9.0", PythonVersion: "3.11", Projects: projects}
}

func TestImagesSectionIsValidatedAtTheEdit(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	admin := testIdentity("admin", auth.RoleAdmin)
	for name, sections := range map[string]string{
		"no ray_version":  `{"images":[{"name":"i","ref":"rayproject/ray:2.9.0"}]}`,
		"bad digest":      `{"images":[{"name":"i","ref":"rayproject/ray:2.9.0","ray_version":"2.9.0","digest":"sha256:xyz"}]}`,
		"digest mismatch": `{"images":[{"name":"i","ref":"rayproject/ray@` + testDigest + `","ray_version":"2.9.0","digest":"sha256:` + strings.Repeat("ab", 32) + `"}]}`,
		"bad ref":         `{"images":[{"name":"i","ref":"not a ref","ray_version":"2.9.0"}]}`,
		"empty ref":       `{"images":[{"name":"i","ref":"","ray_version":"2.9.0"}]}`,
		"duplicate":       `{"images":[{"name":"i","ref":"a:1","ray_version":"1"},{"name":"i","ref":"b:1","ray_version":"1"}]}`,
		"empty project":   `{"images":[{"name":"i","ref":"a:1","ray_version":"1","projects":[""]}]}`,
	} {
		if err := updatePolicyJSON(t, s, admin, sections); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
	// A dask image needs no ray_version; a pinned ref carries its digest
	// into the entry.
	ok := `{"images":[
		{"name":"ray","ref":"rayproject/ray:2.9.0","ray_version":"2.9.0","python_version":"3.11","projects":["team-a"]},
		{"name":"pinned","ref":"ghcr.io/x/ray@` + testDigest + `","ray_version":"2.9.0"},
		{"name":"dask","ref":"ghcr.io/dask/dask:2024.1","engine":"dask"}],
		"admission":{"team-a":{"catalog_only":true}}}`
	if err := updatePolicyJSON(t, s, admin, ok); err != nil {
		t.Fatalf("valid catalog: %v", err)
	}
	resp, err := s.GetPolicy(ctxWithIdentity(admin), GetPolicyRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	view := mustResponse[GetPolicy200JSONResponse](t, resp)
	if view.Images == nil || len(*view.Images) != 3 || *(*view.Images)[1].Digest != testDigest || *(*view.Images)[2].Engine != Dask {
		t.Errorf("policy view images = %+v", view.Images)
	}
	if rule := (*view.Admission)["team-a"]; rule.CatalogOnly == nil || !*rule.CatalogOnly {
		t.Errorf("catalog_only not echoed: %+v", rule)
	}
}

func TestCatalogOnlyAdmissionAndRayVersionFromTheCatalog(t *testing.T) {
	store := newMemStore(t)
	policyWith(t, store, controller.StoredPolicy{
		Images:    []core.ImageEntry{rayEntry(), {Name: "dask", Ref: "ghcr.io/dask/dask:2024.1", Engine: core.EngineDask}},
		Admission: map[string]core.AdmissionRule{"team-a": {CatalogOnly: true}},
	})
	s := &Server{Store: store}
	admin := testIdentity("admin", auth.RoleAdmin)
	cluster := func(id, project, image, engine string) string {
		return `{"id":"` + id + `","spec":{"name":"` + id + `","project":"` + project + `","engine":"` + engine + `","image":"` + image + `","ray_version":"",
			"head_cpu":"1","head_memory":"2Gi","worker_groups":[]}}`
	}
	if err := createJSON(t, s, admin, cluster("ok", "team-a", "rayproject/ray:2.9.0", "ray")); err != nil {
		t.Fatalf("catalog image under catalog_only: %v", err)
	}
	if c, _ := store.Get(context.Background(), "ok"); c == nil || c.Spec.RayVersion != "2.9.0" {
		t.Errorf("ray_version not taken from the catalog: %+v", c)
	}
	err := createJSON(t, s, admin, cluster("no", "team-a", "rayproject/ray:2.10.0", "ray"))
	if statusOf(t, err) != http.StatusBadRequest || !strings.Contains(err.Error(), "image catalog") {
		t.Errorf("non-catalog image under catalog_only = %v, want 400 naming the catalog", err)
	}
	err = createJSON(t, s, admin, cluster("mismatch", "team-a", "ghcr.io/dask/dask:2024.1", "ray"))
	if statusOf(t, err) != http.StatusBadRequest || !strings.Contains(err.Error(), "dask image") {
		t.Errorf("dask catalog image on a ray spec = %v, want 400 engine mismatch", err)
	}
	// team-b has no catalog_only rule: any image, and the tag heuristic.
	if err := createJSON(t, s, admin, cluster("free", "team-b", "rayproject/ray:2.10.0", "ray")); err != nil {
		t.Errorf("team-b without catalog_only: %v", err)
	}
	// Jobs run the same admission.
	if err := submitJSON(t, s, admin, `{"id":"j-ok","spec":{"project":"team-a","entrypoint":"python -c 1","image":"rayproject/ray:2.9.0"}}`); err != nil {
		t.Errorf("job with catalog image: %v", err)
	}
	if err := submitJSON(t, s, admin, `{"id":"j-no","spec":{"project":"team-a","entrypoint":"python -c 1","image":"rayproject/ray:2.10.0"}}`); statusOf(t, err) != http.StatusBadRequest {
		t.Errorf("job with non-catalog image = %v, want 400", err)
	}
	for _, id := range []string{"no", "mismatch"} {
		if c, _ := store.Get(context.Background(), core.ClusterId(id)); c != nil {
			t.Errorf("%s persisted after a 400", id)
		}
	}
}

func TestListImagesIsNarrowedToTheCallersProjects(t *testing.T) {
	store := newMemStore(t)
	if err := store.UpsertRoleAssignment(context.Background(), "dev", "operator", "project:team-a"); err != nil {
		t.Fatal(err)
	}
	b := rayEntry("team-b")
	b.Name = "b-only"
	policyWith(t, store, controller.StoredPolicy{Images: []core.ImageEntry{rayEntry("team-a"), b}})
	s := &Server{Store: store}
	resp, err := s.ListImages(ctxWithIdentity(testIdentity("dev", auth.RoleDeveloper)), ListImagesRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustResponse[ListImages200JSONResponse](t, resp); len(got) != 1 || got[0].Name != "ray-2.9" || *got[0].RayVersion != "2.9.0" {
		t.Errorf("scoped dev sees %+v, want [ray-2.9]", got)
	}
	_, err = s.ListImages(ctxWithIdentity(testIdentity("nobody")), ListImagesRequestObject{})
	mustHTTPError(t, err, http.StatusForbidden)
}

// fakeSingleImageRegistry serves one single-platform image anonymously.
func fakeSingleImageRegistry(t *testing.T) (host string) {
	t.Helper()
	digestOf := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	cfg := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"User":"ray","WorkingDir":"/home/ray","Labels":{"team":"a"}},
		"history":[{"created_by":"FROM base","empty_layer":false},{"created_by":"USER ray","empty_layer":true}]}`)
	layer := []byte("layer")
	man := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"` + digestOf(cfg) + `","size":1},
		"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestOf(layer) + `","size":5}]}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/ray/team/manifests/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", digestOf(man))
		_, _ = w.Write(man)
	})
	mux.HandleFunc("/v2/ray/team/blobs/"+digestOf(cfg), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(cfg) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestInspectImageReadsTheRegistryAndHidesOtherProjectsEntries(t *testing.T) {
	host := fakeSingleImageRegistry(t)
	store := newMemStore(t)
	if err := store.UpsertRoleAssignment(context.Background(), "dev", "operator", "project:team-b"); err != nil {
		t.Fatal(err)
	}
	policyWith(t, store, controller.StoredPolicy{Images: []core.ImageEntry{
		{Name: "team", Ref: host + "/ray/team:1", RayVersion: "2.9.0", Projects: []string{"team-a"}},
		{Name: "gone", Ref: "127.0.0.1:1/ray/team:1", RayVersion: "2.9.0"},
	}})
	s := &Server{Store: store, Images: registry.New(nil)}
	admin := testIdentity("admin", auth.RoleAdmin)
	resp, err := s.InspectImage(ctxWithIdentity(admin), InspectImageRequestObject{Name: "team"})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	doc := mustResponse[InspectImage200JSONResponse](t, resp)
	if doc.Reference != host+"/ray/team:1" || doc.Config.User != "ray" || doc.Config.Labels["team"] != "a" || len(doc.History) != 2 || doc.History[0].LayerDigest == nil || doc.History[1].LayerDigest != nil || doc.SizeBytes != 5 || doc.Source != "registry" || len(doc.Platforms) != 1 || doc.Platforms[0].Os != "linux" {
		b, _ := json.Marshal(doc)
		t.Errorf("inspect = %s", b)
	}
	// A team-b member never learns team-a's entry exists.
	_, err = s.InspectImage(ctxWithIdentity(testIdentity("dev", auth.RoleDeveloper)), InspectImageRequestObject{Name: "team"})
	mustHTTPError(t, err, http.StatusNotFound)
	_, err = s.InspectImage(ctxWithIdentity(admin), InspectImageRequestObject{Name: "nope"})
	mustHTTPError(t, err, http.StatusNotFound)
	// The registry is unreachable: 502, not 500.
	_, err = s.InspectImage(ctxWithIdentity(admin), InspectImageRequestObject{Name: "gone"})
	mustHTTPError(t, err, http.StatusBadGateway)
	_, err = s.InspectImage(ctxWithIdentity(testIdentity("nobody")), InspectImageRequestObject{Name: "team"})
	mustHTTPError(t, err, http.StatusForbidden)
}
