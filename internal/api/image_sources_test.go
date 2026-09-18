package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/registry"
)

// fakeListingRegistry serves a catalog and per-repository tags, optionally
// behind a Bearer challenge answered only for svc/secret.
func fakeListingRegistry(t *testing.T, requireAuth bool) string {
	t.Helper()
	mux := http.NewServeMux()
	guard := func(w http.ResponseWriter, r *http.Request) bool {
		if !requireAuth || r.Header.Get("Authorization") == "Bearer tok" {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/v2/token",service="fake"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	mux.HandleFunc("/v2/token", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"tok"}`))
	})
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		if guard(w, r) {
			_, _ = w.Write([]byte(`{"repositories":["ray/team","jupyter-ray"]}`))
		}
	})
	mux.HandleFunc("/v2/ray/team/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if guard(w, r) {
			_, _ = w.Write([]byte(`{"name":"ray/team","tags":["2.56.0","2.55.0"]}`))
		}
	})
	mux.HandleFunc("/v2/jupyter-ray/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if guard(w, r) {
			_, _ = w.Write([]byte(`{"name":"jupyter-ray","tags":["latest"]}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func putImageSources(t *testing.T, s *Server, in []ImageSource) (PolicyView, error) {
	t.Helper()
	resp, err := s.UpdatePolicy(ctxWithIdentity(admin()), UpdatePolicyRequestObject{Body: &UpdatePolicy{ImageSources: &in}})
	if err != nil {
		return PolicyView{}, err
	}
	return PolicyView(mustResponse[UpdatePolicy200JSONResponse](t, resp)), nil
}

func TestImageSourcesSectionIsValidatedAtTheEdit(t *testing.T) {
	s := &Server{Store: newMemStore(t)}
	repo := "ray/team"
	view, err := putImageSources(t, s, []ImageSource{
		{Name: "ak-ray", Registry: "artifact-keeper-backend.artifact-keeper.svc.cluster.local:8080", Repository: &repo, Projects: &[]string{"team-a"}},
		{Name: "node", Registry: "localhost:32000"},
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if view.ImageSources == nil || len(*view.ImageSources) != 2 || (*view.ImageSources)[1].Repository == nil || *(*view.ImageSources)[1].Repository != "" {
		t.Fatalf("view.image_sources = %+v", view.ImageSources)
	}
	bad := "Ray/Team"
	for name, c := range map[string]struct {
		in   []ImageSource
		want string
	}{
		"bad name":       {[]ImageSource{{Name: "Not.A.Label", Registry: "ghcr.io"}}, "RFC 1123 label"},
		"duplicate":      {[]ImageSource{{Name: "a", Registry: "ghcr.io"}, {Name: "a", Registry: "ghcr.io"}}, "duplicate name"},
		"url registry":   {[]ImageSource{{Name: "a", Registry: "https://ghcr.io"}}, "host[:port]"},
		"path registry":  {[]ImageSource{{Name: "a", Registry: "ghcr.io/ray"}}, "host[:port]"},
		"bad repository": {[]ImageSource{{Name: "a", Registry: "ghcr.io", Repository: &bad}}, "lowercase OCI repository path"},
		"empty project":  {[]ImageSource{{Name: "a", Registry: "ghcr.io", Projects: &[]string{""}}}, "empty name"},
	} {
		_, err := putImageSources(t, s, c.in)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustHTTPError(t, err, 400)
		if !strings.Contains(httpMessage(err), c.want) {
			t.Errorf("%s: message %q, want %q", name, httpMessage(err), c.want)
		}
	}
	p, _ := s.Store.GetPolicy(context.Background())
	if len(p.ImageSources) != 2 {
		t.Errorf("a refused PUT must leave the section as it was: %v", p.ImageSources)
	}
	if view, err := putImageSources(t, s, []ImageSource{}); err != nil || view.ImageSources == nil || len(*view.ImageSources) != 0 {
		t.Errorf("[] must clear: %v %v", view.ImageSources, err)
	}
}

func TestImageSourceTagsListTheRegistryAndHideOtherProjectsSources(t *testing.T) {
	host := fakeListingRegistry(t, false)
	store := newMemStore(t)
	if err := store.UpsertRoleAssignment(context.Background(), "dev", "operator", "project:team-b"); err != nil {
		t.Fatal(err)
	}
	policyWith(t, store, controller.StoredPolicy{ImageSources: []core.ImageSource{
		{Name: "team", Registry: host, Repository: "ray/team", Projects: []string{"team-a"}},
		{Name: "all", Registry: host},
		{Name: "gone", Registry: "127.0.0.1:1", Repository: "x"},
	}})
	s := &Server{Store: store, Images: registry.New(nil)}
	adminCtx := ctxWithIdentity(testIdentity("admin", auth.RoleAdmin))

	resp, err := s.ListImageSourceTags(adminCtx, ListImageSourceTagsRequestObject{Name: "team"})
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	got := mustResponse[ListImageSourceTags200JSONResponse](t, resp)
	if got.Registry != host || len(got.Repositories) != 1 || got.Repositories[0].Repository != "ray/team" ||
		strings.Join(got.Repositories[0].Tags, ",") != "2.55.0,2.56.0" || got.Repositories[0].Refs[1] != host+"/ray/team:2.56.0" {
		t.Errorf("tags = %+v", got)
	}
	// No repository = the whole catalog, each repository with its tags.
	resp, err = s.ListImageSourceTags(adminCtx, ListImageSourceTagsRequestObject{Name: "all"})
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	all := mustResponse[ListImageSourceTags200JSONResponse](t, resp)
	if len(all.Repositories) != 2 || all.Repositories[0].Repository != "jupyter-ray" || all.Repositories[1].Repository != "ray/team" {
		t.Errorf("catalog listing = %+v", all.Repositories)
	}
	// A team-b member never learns team-a's source exists, but sees the open one.
	dev := ctxWithIdentity(testIdentity("dev", auth.RoleDeveloper))
	_, err = s.ListImageSourceTags(dev, ListImageSourceTagsRequestObject{Name: "team"})
	mustHTTPError(t, err, http.StatusNotFound)
	list, err := s.ListImageSources(dev, ListImageSourcesRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range mustResponse[ListImageSources200JSONResponse](t, list) {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "all,gone" {
		t.Errorf("dev sees %v, want all,gone only", names)
	}
	_, err = s.ListImageSourceTags(adminCtx, ListImageSourceTagsRequestObject{Name: "nope"})
	mustHTTPError(t, err, http.StatusNotFound)
	_, err = s.ListImageSourceTags(adminCtx, ListImageSourceTagsRequestObject{Name: "gone"})
	mustHTTPError(t, err, http.StatusBadGateway)
}

// The deployment's registries file is what lets a source name the host the
// nodes pull from while the control plane reads it elsewhere, as someone
// else: an authenticating registry behind an alias.
func TestImageSourceTagsUseTheConfiguredHostAddressAndCredentials(t *testing.T) {
	host := fakeListingRegistry(t, true)
	store := newMemStore(t)
	policyWith(t, store, controller.StoredPolicy{ImageSources: []core.ImageSource{{Name: "ak", Registry: "localhost:32000", Repository: "ray/team"}}})
	client := registry.New(nil)
	client.Hosts = func(h string) (registry.HostConfig, bool) {
		return registry.HostConfig{APIBase: "http://" + host, Username: "svc", Password: "secret"}, h == "localhost:32000"
	}
	s := &Server{Store: store, Images: client}
	resp, err := s.ListImageSourceTags(ctxWithIdentity(admin()), ListImageSourceTagsRequestObject{Name: "ak"})
	if err != nil {
		t.Fatalf("tags through alias: %v", err)
	}
	got := mustResponse[ListImageSourceTags200JSONResponse](t, resp)
	if got.Repositories[0].Refs[0] != "localhost:32000/ray/team:2.55.0" {
		t.Errorf("refs must name the nodes' host, got %v", got.Repositories[0].Refs)
	}
	// The same source without the alias is unreachable: 502.
	plain := &Server{Store: store, Images: registry.New(nil)}
	_, err = plain.ListImageSourceTags(ctxWithIdentity(admin()), ListImageSourceTagsRequestObject{Name: "ak"})
	mustHTTPError(t, err, http.StatusBadGateway)
}
