package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

// HostConfig is a deployment's view of one registry host (#10, image
// sources): where to talk to it and as whom. Image references keep naming
// the host the NODES pull from (`localhost:32000`, the Artifact Keeper
// Service); the control plane, which runs in a pod, may need a different
// address for the same registry and a credential the nodes get from the
// kubelet's own configuration.
type HostConfig struct {
	// APIBase is `<scheme>://<host[:port]>` the /v2 API answers on for
	// this host; "" = the host itself (https, or http for loopback).
	APIBase string `json:"api"`
	// Username and Password are the basic credentials presented to the
	// registry and to its token endpoint on a Bearer challenge: a
	// repository-scoped access token as the password is the Artifact
	// Keeper shape. Empty = anonymous.
	Username string `json:"username"`
	Password string `json:"password"`
}

// hostsFile is the on-disk shape `serve --image-registries` reads: one
// entry per registry host as references name it. `password_file` lets the
// secret live in its own mounted file.
type hostsFile struct {
	Registries []struct {
		Host         string `json:"host"`
		API          string `json:"api"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		PasswordFile string `json:"password_file"`
	} `json:"registries"`
}

// LoadHostsFile parses a registries file into a Hosts lookup. The
// password of an entry naming `password_file` is read from that file
// (trailing whitespace trimmed) so a Kubernetes Secret key can be mounted
// beside the JSON without templating the secret into it.
func LoadHostsFile(path string) (func(host string) (HostConfig, bool), error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("image registries: %w", err)
	}
	var f hostsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("image registries %s: %w", path, err)
	}
	hosts := make(map[string]HostConfig, len(f.Registries))
	for i, r := range f.Registries {
		if r.Host == "" {
			return nil, fmt.Errorf("image registries %s: registries[%d] has no host", path, i)
		}
		if r.API != "" && !strings.HasPrefix(r.API, "http://") && !strings.HasPrefix(r.API, "https://") {
			return nil, fmt.Errorf("image registries %s: registries[%d].api %q must start with http:// or https://", path, i, r.API)
		}
		hc := HostConfig{APIBase: strings.TrimRight(r.API, "/"), Username: r.Username, Password: r.Password}
		if r.PasswordFile != "" {
			b, err := os.ReadFile(r.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("image registries %s: registries[%d].password_file: %w", path, i, err)
			}
			hc.Password = strings.TrimSpace(string(b))
		}
		if (hc.Username == "") != (hc.Password == "") {
			return nil, fmt.Errorf("image registries %s: registries[%d] (%s) needs both username and password, or neither", path, i, r.Host)
		}
		hosts[r.Host] = hc
	}
	return func(host string) (HostConfig, bool) {
		hc, ok := hosts[host]
		return hc, ok
	}, nil
}

// basicAuthFor is the credential the client presents to host: the Hosts
// configuration first, then the Credentials hook.
func (c *Client) basicAuthFor(host string) (user, pass string, ok bool) {
	if c.Hosts != nil {
		if hc, found := c.Hosts(host); found && hc.Username != "" {
			return hc.Username, hc.Password, true
		}
	}
	if c.Credentials != nil {
		return c.Credentials(host)
	}
	return "", "", false
}

// hostSession is a session for registry-level reads (catalog, tags): the
// reference carries the host and, for tags, the repository, and nothing
// else.
func (c *Client) hostSession(host, repository string) *session {
	ref := Reference{Host: host, APIHost: host, Repository: repository, Insecure: isLoopback(host)}
	if host == "docker.io" || host == "index.docker.io" {
		ref.APIHost = "registry-1.docker.io"
	}
	return &session{c: c, ref: ref}
}

// ListRepositories lists the repositories a registry host serves
// (`GET /v2/_catalog`, following pagination). Docker Hub does not
// implement the catalog; private registries and Artifact Keeper do. The
// token scope is `registry:catalog:*`, which the registry's challenge
// normally states itself.
func (c *Client) ListRepositories(ctx context.Context, host string) ([]string, error) {
	s := c.hostSession(host, "")
	var out []string
	next := s.v2Root() + "/_catalog?n=200"
	for next != "" {
		var page struct {
			Repositories []string `json:"repositories"`
		}
		link, err := s.getJSON(ctx, next, &page, "catalog "+host)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Repositories...)
		next = s.nextPage(next, link)
	}
	sort.Strings(out)
	return out, nil
}

// ListTags lists the tags of one repository on a host (`GET
// /v2/<repository>/tags/list`, following pagination), sorted. The
// repository is as the registry names it: `ray/team`, `checkmaite-api`.
func (c *Client) ListTags(ctx context.Context, host, repository string) ([]string, error) {
	if repository == "" {
		return nil, &Error{What: "tags " + host, Msg: "no repository named"}
	}
	s := c.hostSession(host, repository)
	var out []string
	next := s.baseURL() + "/tags/list?n=500"
	for next != "" {
		var page struct {
			Tags []string `json:"tags"`
		}
		link, err := s.getJSON(ctx, next, &page, "tags "+host+"/"+repository)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Tags...)
		next = s.nextPage(next, link)
	}
	sort.Strings(out)
	return out, nil
}

// getJSON performs an authenticated GET and decodes a JSON body, returning
// the Link header for pagination.
func (s *session) getJSON(ctx context.Context, rawURL string, into any, what string) (link string, err error) {
	resp, err := s.get(ctx, rawURL, []string{"application/json"})
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", s.errorFrom(resp, what)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into); err != nil {
		return "", &Error{What: what, Msg: "response not JSON: " + err.Error()}
	}
	return resp.Header.Get("Link"), nil
}

// nextPage resolves an RFC 5988 `Link: <url>; rel="next"` header against
// the page it came with; "" when there is no next page.
func (s *session) nextPage(current, link string) string {
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start, end := strings.IndexByte(part, '<'), strings.IndexByte(part, '>')
		if start < 0 || end <= start {
			continue
		}
		u := part[start+1 : end]
		if strings.HasPrefix(u, "/") {
			root := s.v2Root()
			return strings.TrimSuffix(root, "/v2") + u
		}
		return u
	}
	return ""
}
