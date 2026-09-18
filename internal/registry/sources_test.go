package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Image sources (#10): the catalog and a repository's tags are read through
// the same session as manifests, following pagination, anonymously or
// through the token exchange with the host's configured credentials.
func TestListRepositoriesAndTagsFollowPagination(t *testing.T) {
	f := newFakeRegistry(false)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := New(nil)
	repos, err := c.ListRepositories(context.Background(), host)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if want := []string{"other", "ray/base", "ray/team"}; !reflect.DeepEqual(repos, want) {
		t.Errorf("repositories = %v, want %v (sorted)", repos, want)
	}
	tags, err := c.ListTags(context.Background(), host, "ray/team")
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if want := []string{"2.55.0", "2.56.0", "2.57.0-py312"}; !reflect.DeepEqual(tags, want) {
		t.Errorf("tags = %v, want both pages merged and sorted %v", tags, want)
	}
	if f.tagHits != 2 {
		t.Errorf("tag list requests = %d, want 2 (the Link header was followed once)", f.tagHits)
	}
	if _, err := c.ListTags(context.Background(), host, ""); err == nil {
		t.Error("an empty repository must be refused")
	}
}

// A host the deployment describes (`serve --image-registries`) is reached
// at its configured API address with its credentials, while references and
// sources keep naming the host the nodes pull from. Here the "node" host is
// a made-up address nothing answers on; only the alias makes it work.
func TestHostsAliasAndCredentialsReachTheRegistry(t *testing.T) {
	f := newFakeRegistry(true)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := New(nil)
	c.Hosts = func(host string) (HostConfig, bool) {
		if host == "localhost:32000" {
			return HostConfig{APIBase: srv.URL, Username: "svc", Password: "secret"}, true
		}
		return HostConfig{}, false
	}
	tags, err := c.ListTags(context.Background(), "localhost:32000", "ray/team")
	if err != nil {
		t.Fatalf("tags through the alias with credentials: %v", err)
	}
	if len(tags) != 3 || f.tokenHits == 0 {
		t.Errorf("tags = %v, token exchanges = %d; want 3 tags via one exchange", tags, f.tokenHits)
	}
	doc, err := c.Inspect(context.Background(), "localhost:32000/ray/team:2.56.0")
	if err != nil {
		t.Fatalf("inspect through the alias: %v", err)
	}
	if doc.Reference != "localhost:32000/ray/team:2.56.0" {
		t.Errorf("inspect reference = %q, want the reference as given (the nodes' name), not the API address", doc.Reference)
	}
	// Without the alias the made-up host is unreachable, and without
	// credentials the challenge cannot be answered.
	plain := New(nil)
	if _, err := plain.ListTags(context.Background(), "localhost:32000", "ray/team"); err == nil {
		t.Error("an unaliased, unanswered host must fail")
	}
	anon := New(nil)
	anon.Hosts = func(host string) (HostConfig, bool) { return HostConfig{APIBase: srv.URL}, host == "localhost:32000" }
	var re *Error
	if _, err := anon.ListTags(context.Background(), "localhost:32000", "ray/team"); !asError(err, &re) || re.Status != http.StatusUnauthorized {
		t.Errorf("alias without credentials against an authenticating registry = %v, want 401", err)
	}
}

func TestLoadHostsFile(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "token")
	if err := os.WriteFile(pw, []byte("ak-token-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "registries.json")
	if err := os.WriteFile(path, []byte(`{"registries":[
		{"host":"localhost:32000","api":"http://registry.container-registry.svc:5000/"},
		{"host":"artifact-keeper-backend.artifact-keeper.svc.cluster.local:8080","api":"http://artifact-keeper-backend.artifact-keeper.svc.cluster.local:8080","username":"bifrost","password_file":"`+pw+`"}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := LoadHostsFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	hc, ok := hosts("localhost:32000")
	if !ok || hc.APIBase != "http://registry.container-registry.svc:5000" || hc.Username != "" {
		t.Errorf("node registry = %+v, %v", hc, ok)
	}
	ak, ok := hosts("artifact-keeper-backend.artifact-keeper.svc.cluster.local:8080")
	if !ok || ak.Username != "bifrost" || ak.Password != "ak-token-value" {
		t.Errorf("artifact keeper = %+v, %v; want the password read from the file, trimmed", ak, ok)
	}
	if _, ok := hosts("ghcr.io"); ok {
		t.Error("an undescribed host must answer ok=false")
	}
	for name, body := range map[string]string{
		"no host":        `{"registries":[{"api":"http://x"}]}`,
		"bad api":        `{"registries":[{"host":"a:1","api":"x:5000"}]}`,
		"half creds":     `{"registries":[{"host":"a:1","username":"u"}]}`,
		"missing pwfile": `{"registries":[{"host":"a:1","username":"u","password_file":"` + filepath.Join(dir, "nope") + `"}]}`,
		"not json":       `nope`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadHostsFile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
