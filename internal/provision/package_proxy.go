package provision

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"gopkg.in/yaml.v3"
)

// Tenant egress for package installs (issue #56). Bifrost's namespace
// posture is default-deny: [DefaultDenyNetworkPolicy] closes every tenant
// pod's egress and [TenantAllowNetworkPolicy] reopens only kube-dns. That
// is the posture the governed-environments epic wants — the pip supply
// chain reduces to "packages from the platform package proxy only" — but it
// also means a runtime_env's pip install has nowhere to download from.
// PackageProxy is the operator-configured exception (`serve
// --package-proxy`): the one address:port a workload whose runtime env
// actually installs packages may reach. No user control, mirroring
// --ray-node-selector's deployment-wide placement config.
//
// A standard NetworkPolicy egress peer is an IPBlock: the proxy must be
// named by address, not DNS name (FQDN policies are a CNI extension, not
// portable). When no proxy is configured, no allowance is written and pip
// installs work only against registries the tenant policies already reach
// (a catalogued in-cluster mirror fronted by its own hand-written policy,
// say — the storage defect 2026-09-03 documents that pattern).

// PackageProxy is where the platform's package proxy answers: an IP or
// CIDR and a TCP port.
type PackageProxy struct {
	// CIDR is the proxy address as a NetworkPolicy IPBlock CIDR — a single
	// address as /32 (or /128), or a wider block when the operator fronts
	// the proxy from several addresses.
	CIDR string
	// Port is the proxy's TCP port.
	Port int32
}

// ParsePackageProxy parses the `--package-proxy` flag: `<ip-or-cidr>:<port>`
// (e.g. `10.96.10.5:3128` or `10.0.0.0/24:3128`). "" yields nil — no proxy
// configured, no egress allowance written. A DNS name is refused: a
// NetworkPolicy egress peer cannot name one, so accepting it would
// silently write nothing.
func ParsePackageProxy(s string) (*PackageProxy, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("want <ip-or-cidr>:<port> (e.g. 10.96.10.5:3128): %w", err)
	}
	cidr := host
	if ip := net.ParseIP(host); ip != nil {
		bits := 32
		if strings.Contains(host, ":") {
			bits = 128
		}
		cidr = fmt.Sprintf("%s/%d", host, bits)
	} else if _, _, err := net.ParseCIDR(host); err != nil {
		return nil, fmt.Errorf("host %q is neither an IP address nor a CIDR; a NetworkPolicy egress peer cannot name a DNS name", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %q is not a TCP port number", portStr)
	}
	return &PackageProxy{CIDR: cidr, Port: int32(port)}, nil
}

func (p *PackageProxy) String() string { return p.CIDR + ":" + strconv.Itoa(int(p.Port)) }

// PackageProxyPolicyName is the name of the per-workload package-proxy
// egress policy; the suffix is the cluster/job id, like the cluster allow.
func PackageProxyPolicyName(id string) string {
	return ClusterAllowPolicyName(id) + "-pkgproxy"
}

// PackageProxyEgressNetworkPolicy lets the pods of one workload (cluster or
// ephemeral job) reach the platform package proxy, and nothing else they
// could not already reach. Scoped as narrowly as the need: the workload's
// own pods only (the [ClusterIDLabel] value), the proxy's addresses only,
// the proxy's port only. Policies are additive, so the tenant posture is
// unchanged otherwise. Applied with the workload and deleted with it, like
// [ClusterAllowNetworkPolicy] and [AutoscalerEgressNetworkPolicy].
//
// The caller applies it only for a workload whose runtime env actually
// installs packages ([RuntimeEnvInstallsPackages]) — a workload without a
// pip install gets no allowance at all.
func PackageProxyEgressNetworkPolicy(id string, proxy *PackageProxy) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: NetworkPolicyAPIVersion, Kind: NetworkPolicyKind},
		ObjectMeta: metav1.ObjectMeta{
			Name: PackageProxyPolicyName(id),
			Labels: map[string]string{
				ManagedByLabel: FieldManager,
				ClusterIDLabel: id,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{ClusterIDLabel: id}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: proxy.CIDR}}},
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(int(proxy.Port))},
			}},
		},
	}
}

// RuntimeEnvInstallsPackages reports whether a runtime_env document carries
// a non-empty pip package list — the cheap, provision-side read of "this
// workload will pip-install at start", which is when the package-proxy
// egress allowance applies. The admission edge (#53/#55) has already
// validated the document by the time this runs, so the two governed pip
// shapes (bare list, object with packages) are all that is recognized; a
// document in any other shape — including one that fails to parse, possible
// only under --allow-ungoverned-runtime-env — is treated as installing:
// the allowance errs open, never closed, so a workload that does install is
// never denied its proxy by a conservative read.
func RuntimeEnvInstallsPackages(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	var doc map[string]interface{}
	if err := yaml.NewDecoder(strings.NewReader(raw)).Decode(&doc); err != nil {
		return true
	}
	pip, ok := doc["pip"]
	if !ok {
		return false
	}
	switch v := pip.(type) {
	case []interface{}:
		return len(v) > 0
	case map[string]interface{}:
		pkgs, _ := v["packages"].([]interface{})
		return len(pkgs) > 0
	default:
		return true
	}
}
