package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/bifrost-compute/bifrost/test/requirements/req"
)

// FakeRegistry serves one single-platform OCI image (`<host>/ray/team:1`)
// anonymously on a loopback address, for inspect_image tests against the
// in-process target — a control plane running in a cluster cannot reach
// it, so cluster targets skip or use REQ_INSPECT_IMAGE instead. Returns
// the image reference to put in the catalog.
func FakeRegistry(t req.T) (ref string) {
	t.Helper()
	digestOf := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	cfg := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin","RAY_USAGE_STATS_ENABLED=0"],"User":"ray","WorkingDir":"/home/ray","Labels":{"org.opencontainers.image.title":"fake ray"}},
		"history":[{"created_by":"FROM ubuntu","empty_layer":false},{"created_by":"RUN pip install ray","empty_layer":false},{"created_by":"USER ray","empty_layer":true}]}`)
	l1, l2 := []byte("one"), []byte("two-bigger")
	man := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + digestOf(cfg) + `","size":1},
		"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestOf(l1) + `","size":3},{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"` + digestOf(l2) + `","size":10}]}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/ray/team/manifests/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", digestOf(man))
		_, _ = w.Write(man)
	})
	mux.HandleFunc("/v2/ray/team/blobs/"+digestOf(cfg), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(cfg) })
	// Image sources (#10): the catalog and the repository's tags, so a
	// requirement test can browse this registry as a source.
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"repositories":["ray/team"]}`))
	})
	mux.HandleFunc("/v2/ray/team/tags/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"ray/team","tags":["1","2-py312"]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://") + "/ray/team:1"
}
