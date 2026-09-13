// runtime_env governance (issue #53): RayJobSpec.runtime_env_yaml is passed
// verbatim into the RayJob CR's runtimeEnvYAML, so an unvalidated document
// is a supply-chain and egress hole — pip_install_options can redirect the
// package index, py_executable/image_uri select arbitrary code, remote
// working_dir/py_modules URIs are fetched with node credentials. This file
// parses the submitted YAML at admission time and enforces the platform's
// rule set before the spec is ever persisted.
//
// Where the knobs live: the contract's AdmissionRule gained the
// RuntimeEnvPolicy field set with the environment contract (#52), so the
// rule set rides the policy row and is API-editable as data — but this
// validator still applies the governed defaults below; the per-project
// wiring from admission rule to validator is the environment catalog
// issue (#54). The serve flag --allow-ungoverned-runtime-env remains the
// upgrader escape hatch.
package api

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuntimeEnvPolicy is the governance rule set applied to a submitted
// runtime_env_yaml. The zero value is the governed default: the five-field
// allowlist, pinned packages only, no index redirection, local uploads
// only, setup_timeout capped at DefaultSetupTimeoutSeconds, documents
// capped at DefaultMaxDocumentBytes.
type RuntimeEnvPolicy struct {
	// AllowPyExecutable permits the py_executable field (an arbitrary
	// interpreter the platform cannot attest). Default deny.
	AllowPyExecutable bool
	// AllowImageURI permits the image_uri field (an arbitrary container
	// image per worker, bypassing the admission image allowlist). Default
	// deny.
	AllowImageURI bool
	// AllowConda permits the conda field (a full environment file whose
	// channels and dependencies the control plane cannot audit). Default
	// deny.
	AllowConda bool
	// AllowUnpinnedPackages permits pip entries that are not pinned to an
	// exact version (name==version). Default deny: an unpinned entry
	// installs whatever the index serves at job start.
	AllowUnpinnedPackages bool
	// DeniedPackages are PyPI-normalized package names (PEP 503:
	// lowercase, runs of -_. collapsed to -) that must never install,
	// pinned or not.
	DeniedPackages []string
	// AllowedIndexHosts are the hosts an administrator trusts as package
	// indexes. When empty, pip_install_options must not mention
	// --index-url/--extra-index-url/--find-links/--pre at all; when set,
	// those options are permitted only with a value whose host is listed
	// here.
	AllowedIndexHosts []string
	// AllowedRemoteSchemes and AllowedRemoteHosts together permit remote
	// working_dir/py_modules URIs: a URI is allowed only when its scheme
	// is in AllowedRemoteSchemes AND its host in AllowedRemoteHosts. Both
	// empty (the default) = local paths/uploads only.
	AllowedRemoteSchemes []string
	AllowedRemoteHosts   []string
	// MaxSetupTimeoutSeconds caps config.setup_timeout_seconds. <= 0 =
	// DefaultSetupTimeoutSeconds.
	MaxSetupTimeoutSeconds int64
	// MaxDocumentBytes caps the raw runtime_env_yaml size. <= 0 =
	// DefaultMaxDocumentBytes.
	MaxDocumentBytes int
}

// The governed defaults: Ray's own setup_timeout default is 600s and a
// runtime_env document is small, so the caps below never bite a legitimate
// submission.
const (
	// DefaultSetupTimeoutSeconds is the default cap for
	// config.setup_timeout_seconds (Ray's own default; unbounded without
	// governance).
	DefaultSetupTimeoutSeconds = 600
	// DefaultMaxDocumentBytes caps the submitted runtime_env_yaml document.
	DefaultMaxDocumentBytes = 64 * 1024
)

// runtimeEnvDeniedFields are the allowlist-exempt fields a policy can
// re-enable individually; every other field outside the default allowlist
// is refused with no escape (container and uv are image/package channels
// the epic's later issues govern explicitly, nsight/mpi/java_jars and
// unknown keys are not governed at all).
var runtimeEnvDeniedFields = map[string]string{
	"py_executable": "py_executable selects an arbitrary interpreter binary the platform cannot attest",
	"image_uri":     "image_uri selects an arbitrary per-worker container image, bypassing the admission image allowlist",
	"conda":         "conda environment files fetch from channels the control plane cannot audit",
}

// remoteURIScheme matches a leading URI scheme (scheme://...) — Ray fetches
// http(s)/s3/gs/abfs(s) working_dir and py_modules with node credentials,
// so anything with a scheme is treated as remote.
var remoteURIScheme = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*)://`)

// pinnedPackageRe is the one pip entry form the governed default accepts:
// name[optional,extras]==exact.version. It deliberately rejects version
// wildcards (==1.0.*), direct references (name @ https://...), and every
// range specifier — none of them pin a single artifact.
var pinnedPackageRe = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$`)

// Validate returns nil when raw is admissible under p, else the precise
// refusal the caller surfaces as a 400 (reason runtime_env_rejected). An
// empty/whitespace/null document is admissible everywhere: it carries no
// runtime env.
func (p RuntimeEnvPolicy) Validate(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	maxBytes := p.MaxDocumentBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDocumentBytes
	}
	if len(raw) > maxBytes {
		return fmt.Errorf("runtime_env_yaml is %d bytes; the governance limit is %d", len(raw), maxBytes)
	}
	var doc map[string]interface{}
	if err := yaml.NewDecoder(strings.NewReader(raw)).Decode(&doc); err != nil {
		return fmt.Errorf("runtime_env_yaml is not a valid YAML mapping: %v", err)
	}
	if len(doc) == 0 {
		return nil
	}
	for field, value := range doc {
		var err error
		switch field {
		case "pip":
			err = p.checkPip(value)
		case "env_vars":
			err = checkEnvVars(value)
		case "config":
			err = p.checkConfig(value)
		case "working_dir":
			err = p.checkLocalOrAllowedURI(value, "working_dir")
		case "py_modules":
			err = p.checkPyModules(value)
		default:
			if why, denied := runtimeEnvDeniedFields[field]; denied {
				if p.deniedFieldEnabled(field) {
					continue
				}
				err = fmt.Errorf("runtime_env_yaml field %q is denied by policy: %s", field, why)
			} else {
				err = fmt.Errorf("runtime_env_yaml field %q is not in the governance allowlist (pip, env_vars, config, working_dir, py_modules)", field)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p RuntimeEnvPolicy) deniedFieldEnabled(field string) bool {
	switch field {
	case "py_executable":
		return p.AllowPyExecutable
	case "image_uri":
		return p.AllowImageURI
	case "conda":
		return p.AllowConda
	}
	return false
}

// checkPip validates the pip field's two Ray forms: a bare list of
// requirement strings, or an object carrying packages plus pip's own
// knobs (pip_check, pip_version, pip_install_options). Any other shape —
// including keys Ray would accept but governance does not — is refused.
func (p RuntimeEnvPolicy) checkPip(value interface{}) error {
	switch pip := value.(type) {
	case []interface{}:
		return p.checkPipEntries(pip)
	case map[string]interface{}:
		for key, v := range pip {
			switch key {
			case "packages":
				entries, ok := v.([]interface{})
				if !ok {
					return fmt.Errorf("runtime_env_yaml pip.packages must be a list of requirement strings")
				}
				if err := p.checkPipEntries(entries); err != nil {
					return err
				}
			case "pip_install_options":
				opts, ok := v.([]interface{})
				if !ok {
					return fmt.Errorf("runtime_env_yaml pip.pip_install_options must be a list of option strings")
				}
				if err := p.checkPipInstallOptions(opts); err != nil {
					return err
				}
			case "pip_check", "pip_version":
				// pip's own consistency check and installer pin: no
				// supply-chain or egress reach.
			default:
				return fmt.Errorf("runtime_env_yaml pip key %q is not governed (allowed: packages, pip_check, pip_version, pip_install_options)", key)
			}
		}
		return nil
	default:
		return fmt.Errorf("runtime_env_yaml pip must be a list of pinned packages or an object with a packages list")
	}
}

// checkPipEntries applies the pin rule and the package denylist to a list
// of requirement strings.
func (p RuntimeEnvPolicy) checkPipEntries(entries []interface{}) error {
	for _, e := range entries {
		entry, ok := e.(string)
		if !ok {
			return fmt.Errorf("runtime_env_yaml pip entries must be strings")
		}
		name := pipPackageName(entry)
		if name == "" {
			return fmt.Errorf("runtime_env_yaml pip entry %q is not a package requirement", entry)
		}
		if p.packageDenied(name) {
			return fmt.Errorf("runtime_env_yaml pip package %q is on the platform denylist", name)
		}
		if !p.AllowUnpinnedPackages && !pinnedPackageRe.MatchString(entry) {
			return fmt.Errorf("runtime_env_yaml pip entry %q is not pinned to an exact version (name==version); an unpinned entry installs whatever an index serves at job start", entry)
		}
	}
	return nil
}

// pipPackageName extracts the (PEP 503-normalized) package name from a
// requirement string: everything before the first extras bracket, version
// specifier, marker, or direct-reference "@". "" when there is no name at
// all (a bare URL or option).
func pipPackageName(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.HasPrefix(entry, "-") || strings.Contains(entry, "://") {
		return ""
	}
	end := strings.IndexAny(entry, "[=<>!~;@ \t")
	name := entry
	if end >= 0 {
		name = entry[:end]
	}
	return normalizePackageName(name)
}

// normalizePackageName is PEP 503: lowercase, runs of -_. become a
// single -.
func normalizePackageName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	dash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		dash = false
		b.WriteRune(r)
	}
	return strings.TrimSuffix(b.String(), "-")
}

func (p RuntimeEnvPolicy) packageDenied(normalizedName string) bool {
	for _, d := range p.DeniedPackages {
		if normalizePackageName(d) == normalizedName {
			return true
		}
	}
	return false
}

// pipIndexOptions are the pip_install_options with supply-chain reach:
// they redirect where pip downloads from (or, for --pre, widen what an
// index may serve). Each takes a value except --pre.
var pipIndexOptions = map[string]bool{
	"--index-url":       true,
	"-i":                true,
	"--extra-index-url": true,
	"--find-links":      true,
	"-f":                true,
	"--pre":             false,
}

// checkPipInstallOptions refuses index-redirection options unless the
// policy declares allowed index hosts, and then only when the option's
// value resolves to one of those hosts. Both pip spellings are covered:
// "--index-url https://host" (separate token) and "--index-url=https://host".
func (p RuntimeEnvPolicy) checkPipInstallOptions(opts []interface{}) error {
	for i := 0; i < len(opts); i++ {
		token, ok := opts[i].(string)
		if !ok {
			return fmt.Errorf("runtime_env_yaml pip_install_options entries must be strings")
		}
		name, value, hasValue := token, "", false
		if eq := strings.IndexByte(token, '='); eq >= 0 {
			name, value, hasValue = token[:eq], token[eq+1:], true
		}
		takesValue, banned := pipIndexOptions[strings.ToLower(name)]
		if !banned {
			continue
		}
		if len(p.AllowedIndexHosts) == 0 {
			return fmt.Errorf("runtime_env_yaml pip_install_options %q redirects where packages come from; the platform policy declares no allowed index hosts", name)
		}
		if !takesValue {
			continue // --pre: permitted once an index allowlist exists
		}
		if !hasValue {
			if i+1 >= len(opts) {
				return fmt.Errorf("runtime_env_yaml pip_install_options %q needs a value", name)
			}
			i++
			value, ok = opts[i].(string)
			if !ok {
				return fmt.Errorf("runtime_env_yaml pip_install_options %q needs a string value", name)
			}
		}
		if !p.indexHostAllowed(value) {
			return fmt.Errorf("runtime_env_yaml pip_install_options %q value %q is not one of the administrator's allowed index hosts (%s)",
				name, value, strings.Join(p.AllowedIndexHosts, ", "))
		}
	}
	return nil
}

// indexHostAllowed reports whether value is a URL whose host the policy's
// index allowlist names (host-only, case-insensitive; a value that is not
// a URL with a host — e.g. a local path — is not an index and is refused).
func (p RuntimeEnvPolicy) indexHostAllowed(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return containsFold(p.AllowedIndexHosts, u.Hostname())
}

// checkLocalOrAllowedURI enforces local-upload-only for working_dir and
// each py_modules entry unless the policy allowlists the URI's scheme AND
// host.
func (p RuntimeEnvPolicy) checkLocalOrAllowedURI(value interface{}, field string) error {
	s, ok := value.(string)
	if !ok {
		return fmt.Errorf("runtime_env_yaml %s must be a path or URI string", field)
	}
	m := remoteURIScheme.FindStringSubmatch(s)
	if m == nil {
		return nil // local path / upload
	}
	scheme := strings.ToLower(m[1])
	host := ""
	if u, err := url.Parse(s); err == nil {
		host = u.Hostname()
	}
	if containsFold(p.AllowedRemoteSchemes, scheme) && host != "" && containsFold(p.AllowedRemoteHosts, host) {
		return nil
	}
	return fmt.Errorf("runtime_env_yaml %s %q is a remote URI: cluster nodes would fetch it with their own credentials; only local uploads are allowed by policy", field, s)
}

func (p RuntimeEnvPolicy) checkPyModules(value interface{}) error {
	entries, ok := value.([]interface{})
	if !ok {
		return fmt.Errorf("runtime_env_yaml py_modules must be a list of paths or URIs")
	}
	for _, e := range entries {
		if err := p.checkLocalOrAllowedURI(e, "py_modules"); err != nil {
			return err
		}
	}
	return nil
}

// checkEnvVars shape-checks env_vars: a string->string mapping. Values are
// the job's own environment, so governance audits shape, not content.
func checkEnvVars(value interface{}) error {
	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("runtime_env_yaml env_vars must be a mapping of variable names to values")
	}
	for k, v := range m {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("runtime_env_yaml env_vars[%q] must be a string", k)
		}
	}
	return nil
}

// checkConfig validates the config object: setup_timeout_seconds (positive
// int within the policy cap) and eager_install (bool) are the governed
// keys; anything else is refused.
func (p RuntimeEnvPolicy) checkConfig(value interface{}) error {
	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("runtime_env_yaml config must be a mapping")
	}
	capSecs := p.MaxSetupTimeoutSeconds
	if capSecs <= 0 {
		capSecs = DefaultSetupTimeoutSeconds
	}
	for key, v := range m {
		switch key {
		case "setup_timeout_seconds":
			secs, ok := yamlInt(v)
			if !ok || secs <= 0 {
				return fmt.Errorf("runtime_env_yaml config.setup_timeout_seconds must be a positive integer")
			}
			if secs > capSecs {
				return fmt.Errorf("runtime_env_yaml config.setup_timeout_seconds is %d; the policy cap is %d", secs, capSecs)
			}
		case "eager_install":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("runtime_env_yaml config.eager_install must be a boolean")
			}
		default:
			return fmt.Errorf("runtime_env_yaml config key %q is not governed (allowed: setup_timeout_seconds, eager_install)", key)
		}
	}
	return nil
}

// yamlInt accepts the integer forms a YAML decode produces, refusing
// fractional floats silently truncated to an int.
func yamlInt(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n <= uint64(^uint64(0)>>1) {
			return int64(n), true
		}
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}

func containsFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}
