package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Reference
	}{
		{"rayproject/ray:2.56.0", Reference{Host: "docker.io", APIHost: "registry-1.docker.io", Repository: "rayproject/ray", Tag: "2.56.0"}},
		{"nginx", Reference{Host: "docker.io", APIHost: "registry-1.docker.io", Repository: "library/nginx", Tag: "latest"}},
		{"ghcr.io/bifrost-compute/bifrost:main", Reference{Host: "ghcr.io", APIHost: "ghcr.io", Repository: "bifrost-compute/bifrost", Tag: "main"}},
		{"localhost:32000/checkmaite-api:2.56.0-r1", Reference{Host: "localhost:32000", APIHost: "localhost:32000", Repository: "checkmaite-api", Tag: "2.56.0-r1", Insecure: true}},
		{"artifacts.example/ray/team@sha256:" + strings.Repeat("ab", 32), Reference{Host: "artifacts.example", APIHost: "artifacts.example", Repository: "ray/team", Digest: "sha256:" + strings.Repeat("ab", 32)}},
	} {
		got, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "repo@sha256:short", "has space:1"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeRegistry serves one multi-platform image behind a Bearer challenge:
// an index -> two platform manifests (+ an attestation) -> a config blob.
type fakeRegistry struct {
	requireAuth bool
	blobs       map[string][]byte
	manifests   map[string][]byte // by tag and by digest
	mediaTypes  map[string]string
	tokenHits   int
}

func newFakeRegistry(requireAuth bool) *fakeRegistry {
	f := &fakeRegistry{requireAuth: requireAuth, blobs: map[string][]byte{}, manifests: map[string][]byte{}, mediaTypes: map[string]string{}}
	cfg := map[string]any{
		"architecture": "amd64", "os": "linux",
		"config": map[string]any{
			"Env": []string{"PATH=/usr/bin", "RAY_USAGE_STATS_ENABLED=0"}, "Cmd": []string{"/bin/bash"}, "User": "ray", "WorkingDir": "/home/ray",
			"ExposedPorts": map[string]any{"8265/tcp": map[string]any{}}, "Labels": map[string]string{"org.opencontainers.image.source": "https://example/repo"},
		},
		"history": []map[string]any{
			{"created_by": "FROM ubuntu", "empty_layer": false},
			{"created_by": "ENV RAY_USAGE_STATS_ENABLED=0", "empty_layer": true},
			{"created_by": "RUN pip install ray==2.56.0", "empty_layer": false},
		},
	}
	cfgB, _ := json.Marshal(cfg)
	f.blobs[digestOf(cfgB)] = cfgB
	layer1, layer2 := []byte("layer-one"), []byte("layer-two-is-bigger")
	man := map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(cfgB), "size": len(cfgB)},
		"layers": []map[string]any{
			{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digestOf(layer1), "size": len(layer1)},
			{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digestOf(layer2), "size": len(layer2)},
		},
	}
	manB, _ := json.Marshal(man)
	f.manifests[digestOf(manB)] = manB
	f.mediaTypes[digestOf(manB)] = mediaOCIManifest
	armB := []byte(`{"schemaVersion":2,"mediaType":"` + mediaOCIManifest + `","config":{"digest":"sha256:none","size":1},"layers":[]}`)
	f.manifests[digestOf(armB)] = armB
	f.mediaTypes[digestOf(armB)] = mediaOCIManifest
	idx := map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIIndex,
		"manifests": []map[string]any{
			{"mediaType": mediaOCIManifest, "digest": digestOf(armB), "size": len(armB), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"mediaType": mediaOCIManifest, "digest": digestOf(manB), "size": len(manB), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			{"mediaType": mediaOCIManifest, "digest": "sha256:" + strings.Repeat("0", 64), "size": 1, "platform": map[string]string{"os": "unknown", "architecture": "unknown"},
				"annotations": map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
		},
	}
	idxB, _ := json.Marshal(idx)
	f.manifests["2.56.0"] = idxB
	f.mediaTypes["2.56.0"] = mediaOCIIndex
	f.manifests[digestOf(idxB)] = idxB
	f.mediaTypes[digestOf(idxB)] = mediaOCIIndex
	return f
}

func (f *fakeRegistry) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits++
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Query().Get("scope"), "repository:ray/team:pull") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"token":"tok123"}`))
	})
	mux.HandleFunc("/v2/ray/team/", func(w http.ResponseWriter, r *http.Request) {
		if f.requireAuth && r.Header.Get("Authorization") != "Bearer tok123" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/v2/token",service="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v2/ray/team/")
		kind, name, _ := strings.Cut(rest, "/")
		switch kind {
		case "manifests":
			b, ok := f.manifests[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"no such tag"}]}`))
				return
			}
			w.Header().Set("Content-Type", f.mediaTypes[name])
			w.Header().Set("Docker-Content-Digest", digestOf(b))
			_, _ = w.Write(b)
		case "blobs":
			b, ok := f.blobs[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(b)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return mux
}

func TestInspectResolvesIndexAndJoinsHistory(t *testing.T) {
	f := newFakeRegistry(true)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := New(func(h string) (string, string, bool) {
		if h != host {
			t.Errorf("credentials asked for %q, want %q", h, host)
		}
		return "svc", "secret", true
	})
	doc, err := c.Inspect(context.Background(), host+"/ray/team:2.56.0")
	if err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 1 {
		t.Errorf("token fetched %d times, want once per inspection", f.tokenHits)
	}
	if len(doc.Platforms) != 2 || doc.Platforms[1].Architecture != "amd64" {
		t.Errorf("platforms = %+v, want linux/arm64 + linux/amd64 (attestation skipped)", doc.Platforms)
	}
	if doc.SizeBytes != int64(len("layer-one")+len("layer-two-is-bigger")) || len(doc.Layers) != 2 {
		t.Errorf("size/layers = %d/%d", doc.SizeBytes, len(doc.Layers))
	}
	if doc.Config.User != "ray" || doc.Config.Env["RAY_USAGE_STATS_ENABLED"] != "0" || doc.Config.ExposedPorts[0] != "8265/tcp" || doc.Config.Labels["org.opencontainers.image.source"] == "" {
		t.Errorf("config = %+v", doc.Config)
	}
	if len(doc.History) != 3 || doc.History[0].LayerDigest != doc.Layers[0].Digest || !doc.History[1].EmptyLayer || doc.History[1].LayerDigest != "" || doc.History[2].LayerDigest != doc.Layers[1].Digest || doc.History[2].SizeBytes != int64(len("layer-two-is-bigger")) {
		t.Errorf("history = %+v", doc.History)
	}
	if !ValidDigest(doc.Digest) {
		t.Errorf("digest = %q", doc.Digest)
	}
	// Cached: a second inspection does not touch the registry.
	before := f.tokenHits
	if _, err := c.Inspect(context.Background(), host+"/ray/team:2.56.0"); err != nil || f.tokenHits != before {
		t.Errorf("second inspect: err=%v tokenHits=%d, want cached", err, f.tokenHits)
	}
	c.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := c.Inspect(context.Background(), host+"/ray/team:2.56.0"); err != nil || f.tokenHits != before+1 {
		t.Errorf("expired inspect: err=%v tokenHits=%d, want refetched", err, f.tokenHits)
	}
}

func TestInspectAnonymousAndErrors(t *testing.T) {
	f := newFakeRegistry(false)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := New(nil)
	if _, err := c.Inspect(context.Background(), host+"/ray/team:2.56.0"); err != nil {
		t.Fatalf("anonymous inspect: %v", err)
	}
	_, err := c.Inspect(context.Background(), host+"/ray/team:nope")
	var re *Error
	if !asError(err, &re) || re.Status != http.StatusNotFound || !strings.Contains(re.Msg, "MANIFEST_UNKNOWN") {
		t.Fatalf("missing tag: %v, want a 404 registry error naming MANIFEST_UNKNOWN", err)
	}
	// Auth required and no credentials: the anonymous token exchange fails.
	f2 := newFakeRegistry(true)
	srv2 := httptest.NewServer(f2.handler())
	defer srv2.Close()
	host2 := strings.TrimPrefix(srv2.URL, "http://")
	if _, err := c.Inspect(context.Background(), host2+"/ray/team:2.56.0"); !asError(err, &re) || re.Status != http.StatusUnauthorized {
		t.Fatalf("no credentials: %v, want a 401 registry error", err)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func TestParseChallenge(t *testing.T) {
	scheme, p := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:rayproject/ray:pull,push"`)
	if scheme != "Bearer" || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" || p["scope"] != "repository:rayproject/ray:pull,push" {
		t.Errorf("parseChallenge = %q %+v", scheme, p)
	}
}
