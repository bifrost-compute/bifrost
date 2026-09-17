// Package registry is a minimal OCI distribution client: enough of the
// registry HTTP API to describe an image without pulling it — resolve a
// reference, fetch its manifest (or index), and read the image config
// blob for the container config and the per-layer build history. It
// speaks to any registry that implements the distribution spec (Docker
// Hub, GHCR, Artifact Keeper, the microk8s built-in registry) and handles
// the Bearer token challenge dance anonymously or with basic credentials.
//
// stdlib only, on purpose: the alternative (go-containerregistry) would be
// the largest dependency in the binary for three GET requests.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Media types the client accepts for a manifest GET, in preference order.
const (
	mediaOCIIndex        = "application/vnd.oci.image.index.v1+json"
	mediaOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	maxManifestBytes     = 4 << 20
	maxConfigBytes       = 8 << 20
	defaultCacheTTL      = 5 * time.Minute
	attestationReference = "attestation-manifest"
)

// Reference is a parsed image reference.
type Reference struct {
	// Host is the registry as written (`docker.io`, `ghcr.io`,
	// `localhost:32000`); APIHost is where the /v2 API lives (Docker Hub's
	// differs).
	Host, APIHost string
	// Repository is the path within the registry (`library/nginx`,
	// `rayproject/ray`).
	Repository string
	// Tag or Digest names the manifest; exactly one is set.
	Tag, Digest string
	// Insecure means plain HTTP: loopback registries only.
	Insecure bool
}

// String is the normalized reference.
func (r Reference) String() string {
	s := r.Host + "/" + r.Repository
	if r.Digest != "" {
		return s + "@" + r.Digest
	}
	return s + ":" + r.Tag
}

// Parse splits an image reference the way Docker does: a first path
// component with a `.` or `:` or equal to `localhost` is a registry host,
// otherwise the host is docker.io and a single-component repository gets
// the `library/` prefix; `@sha256:…` is a digest, a trailing `:x` a tag,
// and the tag defaults to `latest`.
func Parse(ref string) (Reference, error) {
	if ref == "" || strings.ContainsAny(ref, " \t\n") {
		return Reference{}, errors.New("empty or malformed image reference")
	}
	var out Reference
	rest := ref
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		out.Digest = rest[i+1:]
		rest = rest[:i]
		if !ValidDigest(out.Digest) {
			return Reference{}, fmt.Errorf("malformed digest %q", out.Digest)
		}
	}
	slash := strings.IndexByte(rest, '/')
	first := rest
	if slash >= 0 {
		first = rest[:slash]
	}
	if slash >= 0 && (strings.ContainsAny(first, ".:") || first == "localhost") {
		out.Host = first
		rest = rest[slash+1:]
	} else {
		out.Host = "docker.io"
	}
	if lastSlash := strings.LastIndexByte(rest, '/'); true {
		if colon := strings.LastIndexByte(rest, ':'); colon > lastSlash {
			out.Tag = rest[colon+1:]
			rest = rest[:colon]
		}
	}
	if rest == "" {
		return Reference{}, fmt.Errorf("image reference %q has no repository", ref)
	}
	if out.Host == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	out.Repository = rest
	if out.Digest == "" && out.Tag == "" {
		out.Tag = "latest"
	}
	if out.Digest != "" {
		out.Tag = ""
	}
	out.APIHost = out.Host
	if out.Host == "docker.io" || out.Host == "index.docker.io" {
		out.APIHost = "registry-1.docker.io"
	}
	out.Insecure = isLoopback(out.Host)
	return out, nil
}

// ValidDigest reports whether s is `sha256:` + 64 hex characters.
func ValidDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(s[len(prefix):])
	return err == nil
}

func isLoopback(host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Inspect is what the registry says about an image: the resolved
// manifest, its platforms, the container config, and the build history
// joined to the layers it produced.
type Inspect struct {
	Reference string
	Digest    string
	Platforms []Platform
	SizeBytes int64
	Config    Config
	History   []HistoryEntry
	Layers    []Layer
}

// Platform is one os/architecture(/variant) an index offers.
type Platform struct {
	OS, Architecture, Variant string
}

// Config is the container config from the image config blob.
type Config struct {
	Env          map[string]string
	Entrypoint   []string
	Cmd          []string
	User         string
	WorkingDir   string
	ExposedPorts []string
	Labels       map[string]string
}

// HistoryEntry is one build step; LayerDigest/SizeBytes are set when the
// step produced a layer.
type HistoryEntry struct {
	CreatedBy   string
	Created     string
	Comment     string
	EmptyLayer  bool
	LayerDigest string
	SizeBytes   int64
}

// Layer is one filesystem layer of the inspected manifest.
type Layer struct {
	Digest    string
	MediaType string
	SizeBytes int64
}

// Error is a registry-side failure: the HTTP status the registry answered
// (0 when the request never completed) and what was being fetched.
type Error struct {
	Status int
	What   string
	Msg    string
}

func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("%s: registry answered %d: %s", e.What, e.Status, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.What, e.Msg)
}

// Client inspects images. The zero value is usable; New sets sensible
// timeouts and a cache.
type Client struct {
	// HTTP is the transport; nil = a 30 s-timeout default.
	HTTP *http.Client
	// Credentials returns basic credentials for a registry host, when the
	// deployment has any; nil or ok=false = anonymous.
	Credentials func(host string) (user, pass string, ok bool)
	// CacheTTL bounds how long an inspection by reference is reused; a
	// tag can move underneath it, so this is short. <= 0 disables caching.
	CacheTTL time.Duration
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	at  time.Time
	doc *Inspect
}

// New returns a Client with a 30 s HTTP timeout and a 5 minute cache.
func New(creds func(host string) (string, string, bool)) *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Credentials: creds, CacheTTL: defaultCacheTTL}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Inspect describes ref. A digest reference is inspected exactly; a tag
// is resolved to whatever the registry serves now. An index is resolved
// to its linux/amd64 manifest when present, else its first non-attestation
// manifest, and every platform the index offers is reported.
func (c *Client) Inspect(ctx context.Context, ref string) (*Inspect, error) {
	if doc := c.fromCache(ref); doc != nil {
		return doc, nil
	}
	r, err := Parse(ref)
	if err != nil {
		return nil, &Error{What: "parse " + ref, Msg: err.Error()}
	}
	s := &session{c: c, ref: r}
	doc, err := s.inspect(ctx)
	if err != nil {
		return nil, err
	}
	doc.Reference = ref
	c.toCache(ref, doc)
	return doc, nil
}

func (c *Client) fromCache(ref string) *Inspect {
	if c.CacheTTL <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[ref]
	if !ok || c.now().Sub(e.at) > c.CacheTTL {
		return nil
	}
	return e.doc
}

func (c *Client) toCache(ref string, doc *Inspect) {
	if c.CacheTTL <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	c.cache[ref] = cached{at: c.now(), doc: doc}
}

// session is one inspection: it carries the bearer token the registry
// issued for this repository across the manifest and blob reads.
type session struct {
	c     *Client
	ref   Reference
	token string
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platformJSON     `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platformJSON struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type manifestJSON struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
}

type configJSON struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Config       struct {
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		User         string              `json:"User"`
		WorkingDir   string              `json:"WorkingDir"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"config"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		Comment    string `json:"comment"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

func isIndex(mediaType string) bool {
	return mediaType == mediaOCIIndex || mediaType == mediaDockerList
}

func (s *session) inspect(ctx context.Context) (*Inspect, error) {
	name := s.ref.Tag
	if s.ref.Digest != "" {
		name = s.ref.Digest
	}
	body, digest, mediaType, err := s.getManifest(ctx, name)
	if err != nil {
		return nil, err
	}
	var m manifestJSON
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, &Error{What: "manifest " + s.ref.String(), Msg: "not JSON: " + err.Error()}
	}
	if m.MediaType == "" {
		m.MediaType = mediaType
	}
	doc := &Inspect{Digest: digest}
	if isIndex(m.MediaType) || len(m.Manifests) > 0 {
		chosen := chooseManifest(m.Manifests)
		if chosen == nil {
			return nil, &Error{What: "index " + s.ref.String(), Msg: "lists no image manifests"}
		}
		for _, d := range m.Manifests {
			if d.Platform == nil || d.Annotations["vnd.docker.reference.type"] == attestationReference {
				continue
			}
			doc.Platforms = append(doc.Platforms, Platform{OS: d.Platform.OS, Architecture: d.Platform.Architecture, Variant: d.Platform.Variant})
		}
		body, digest, _, err = s.getManifest(ctx, chosen.Digest)
		if err != nil {
			return nil, err
		}
		m = manifestJSON{}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, &Error{What: "manifest " + chosen.Digest, Msg: "not JSON: " + err.Error()}
		}
		doc.Digest = digest
	}
	if m.Config.Digest == "" {
		return nil, &Error{What: "manifest " + s.ref.String(), Msg: "has no config descriptor (schema 1 manifests are not supported)"}
	}
	for _, l := range m.Layers {
		doc.Layers = append(doc.Layers, Layer{Digest: l.Digest, MediaType: l.MediaType, SizeBytes: l.Size})
		doc.SizeBytes += l.Size
	}
	cfgBody, err := s.getBlob(ctx, m.Config.Digest)
	if err != nil {
		return nil, err
	}
	var cfg configJSON
	if err := json.Unmarshal(cfgBody, &cfg); err != nil {
		return nil, &Error{What: "config " + m.Config.Digest, Msg: "not JSON: " + err.Error()}
	}
	if len(doc.Platforms) == 0 && (cfg.OS != "" || cfg.Architecture != "") {
		doc.Platforms = []Platform{{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}}
	}
	doc.Config = Config{
		Env:        map[string]string{},
		Entrypoint: append([]string{}, cfg.Config.Entrypoint...),
		Cmd:        append([]string{}, cfg.Config.Cmd...),
		User:       cfg.Config.User,
		WorkingDir: cfg.Config.WorkingDir,
		Labels:     map[string]string{},
	}
	for _, kv := range cfg.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		doc.Config.Env[k] = v
	}
	for k, v := range cfg.Config.Labels {
		doc.Config.Labels[k] = v
	}
	for p := range cfg.Config.ExposedPorts {
		doc.Config.ExposedPorts = append(doc.Config.ExposedPorts, p)
	}
	sort.Strings(doc.Config.ExposedPorts)
	layer := 0
	for _, h := range cfg.History {
		e := HistoryEntry{CreatedBy: h.CreatedBy, Created: h.Created, Comment: h.Comment, EmptyLayer: h.EmptyLayer}
		if !h.EmptyLayer && layer < len(doc.Layers) {
			e.LayerDigest = doc.Layers[layer].Digest
			e.SizeBytes = doc.Layers[layer].SizeBytes
			layer++
		}
		doc.History = append(doc.History, e)
	}
	if doc.Layers == nil {
		doc.Layers = []Layer{}
	}
	if doc.History == nil {
		doc.History = []HistoryEntry{}
	}
	if doc.Platforms == nil {
		doc.Platforms = []Platform{}
	}
	if doc.Config.ExposedPorts == nil {
		doc.Config.ExposedPorts = []string{}
	}
	return doc, nil
}

// chooseManifest picks linux/amd64 when the index offers it, else the
// first entry that is an image (not an attestation).
func chooseManifest(ds []descriptor) *descriptor {
	var first *descriptor
	for i := range ds {
		d := &ds[i]
		if d.Annotations["vnd.docker.reference.type"] == attestationReference {
			continue
		}
		if d.Platform != nil && d.Platform.OS == "unknown" {
			continue
		}
		if first == nil {
			first = d
		}
		if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" {
			return d
		}
	}
	return first
}

func (s *session) baseURL() string {
	scheme := "https"
	if s.ref.Insecure {
		scheme = "http"
	}
	return scheme + "://" + s.ref.APIHost + "/v2/" + s.ref.Repository
}

func (s *session) getManifest(ctx context.Context, name string) (body []byte, digest, mediaType string, err error) {
	resp, err := s.get(ctx, s.baseURL()+"/manifests/"+name, []string{mediaOCIIndex, mediaOCIManifest, mediaDockerList, mediaDockerManifest})
	if err != nil {
		return nil, "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", s.errorFrom(resp, "manifest "+s.ref.Host+"/"+s.ref.Repository+" "+name)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, "", "", &Error{What: "manifest " + name, Msg: err.Error()}
	}
	if len(body) > maxManifestBytes {
		return nil, "", "", &Error{What: "manifest " + name, Msg: "larger than 4 MiB"}
	}
	digest = resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		sum := sha256.Sum256(body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	mediaType, _, _ = strings.Cut(resp.Header.Get("Content-Type"), ";")
	return body, digest, strings.TrimSpace(mediaType), nil
}

func (s *session) getBlob(ctx context.Context, digest string) ([]byte, error) {
	resp, err := s.get(ctx, s.baseURL()+"/blobs/"+digest, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, s.errorFrom(resp, "config blob "+digest)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigBytes+1))
	if err != nil {
		return nil, &Error{What: "config blob " + digest, Msg: err.Error()}
	}
	if len(body) > maxConfigBytes {
		return nil, &Error{What: "config blob " + digest, Msg: "larger than 8 MiB"}
	}
	return body, nil
}

func (s *session) errorFrom(resp *http.Response, what string) error {
	msg := http.StatusText(resp.StatusCode)
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var body struct {
		Errors []struct {
			Code, Message string
		} `json:"errors"`
	}
	if json.Unmarshal(b, &body) == nil && len(body.Errors) > 0 {
		msg = body.Errors[0].Code + ": " + body.Errors[0].Message
	}
	return &Error{Status: resp.StatusCode, What: what, Msg: msg}
}

// get performs an authenticated GET: anonymously or with basic
// credentials first, then — on a 401 Bearer challenge — after exchanging
// them at the challenge's realm for a token scoped to this repository.
func (s *session) get(ctx context.Context, rawURL string, accept []string) (*http.Response, error) {
	resp, err := s.do(ctx, rawURL, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || s.token != "" {
		return resp, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // draining before close
	_ = resp.Body.Close()
	scheme, params := parseChallenge(challenge)
	if !strings.EqualFold(scheme, "bearer") {
		return nil, &Error{Status: http.StatusUnauthorized, What: "GET " + rawURL, Msg: "registry requires credentials (" + scheme + ")"}
	}
	if err := s.fetchToken(ctx, params); err != nil {
		return nil, err
	}
	return s.do(ctx, rawURL, accept)
}

func (s *session) do(ctx context.Context, rawURL string, accept []string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &Error{What: "GET " + rawURL, Msg: err.Error()}
	}
	for _, a := range accept {
		req.Header.Add("Accept", a)
	}
	req.Header.Set("User-Agent", "bifrost-registry/1")
	switch {
	case s.token != "":
		req.Header.Set("Authorization", "Bearer "+s.token)
	case s.c.Credentials != nil:
		if u, p, ok := s.c.Credentials(s.ref.Host); ok {
			req.SetBasicAuth(u, p)
		}
	}
	resp, err := s.c.httpClient().Do(req)
	if err != nil {
		return nil, &Error{What: "GET " + rawURL, Msg: err.Error()}
	}
	return resp, nil
}

// fetchToken exchanges at the challenge realm for a bearer token: `GET
// realm?service=…&scope=repository:<repo>:pull`, with basic credentials
// when the deployment has them (anonymous otherwise — Docker Hub and GHCR
// issue pull tokens to anyone for public images).
func (s *session) fetchToken(ctx context.Context, params map[string]string) error {
	realm := params["realm"]
	if realm == "" {
		return &Error{What: "auth " + s.ref.Host, Msg: "bearer challenge without a realm"}
	}
	u, err := url.Parse(realm)
	if err != nil {
		return &Error{What: "auth " + s.ref.Host, Msg: "bad realm: " + err.Error()}
	}
	q := u.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + s.ref.Repository + ":pull"
	}
	q.Set("scope", scope)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return &Error{What: "auth " + s.ref.Host, Msg: err.Error()}
	}
	if s.c.Credentials != nil {
		if user, pass, ok := s.c.Credentials(s.ref.Host); ok {
			req.SetBasicAuth(user, pass)
		}
	}
	resp, err := s.c.httpClient().Do(req)
	if err != nil {
		return &Error{What: "auth " + s.ref.Host, Msg: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return s.errorFrom(resp, "auth "+s.ref.Host)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return &Error{What: "auth " + s.ref.Host, Msg: "token response not JSON: " + err.Error()}
	}
	s.token = tok.Token
	if s.token == "" {
		s.token = tok.AccessToken
	}
	if s.token == "" {
		return &Error{What: "auth " + s.ref.Host, Msg: "token response carried no token"}
	}
	return nil
}

// parseChallenge splits `Bearer realm="…",service="…",scope="…"` into its
// scheme and parameters.
func parseChallenge(h string) (scheme string, params map[string]string) {
	params = map[string]string{}
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	for _, part := range splitChallengeParams(rest) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return scheme, params
}

// splitChallengeParams splits on commas outside quotes.
func splitChallengeParams(s string) []string {
	var parts []string
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			b.WriteRune(r)
		case r == ',' && !quoted:
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, b.String())
	}
	return parts
}
