package provision

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

// The --package-proxy flag parses as <ip-or-cidr>:<port>, with a bare IP
// widened to its host CIDR and a DNS name refused (a NetworkPolicy egress
// peer cannot name one).
func TestParsePackageProxy(t *testing.T) {
	if p, err := ParsePackageProxy(""); err != nil || p != nil {
		t.Fatalf("empty = %v %v, want nil proxy, no error", p, err)
	}
	cases := []struct {
		in       string
		wantCIDR string
		wantPort int32
	}{
		{"10.96.10.5:3128", "10.96.10.5/32", 3128},
		{"[fd00::5]:3128", "fd00::5/128", 3128},
		{"10.0.0.0/24:3128", "10.0.0.0/24", 3128},
	}
	for _, tc := range cases {
		p, err := ParsePackageProxy(tc.in)
		if err != nil {
			t.Fatalf("ParsePackageProxy(%q): %v", tc.in, err)
		}
		if p.CIDR != tc.wantCIDR || p.Port != tc.wantPort {
			t.Errorf("ParsePackageProxy(%q) = %v, want %s:%d", tc.in, p, tc.wantCIDR, tc.wantPort)
		}
	}
	for _, bad := range []string{"proxy.example:3128", "10.0.0.5", "10.0.0.5:0", "10.0.0.5:70000", "10.0.0.5:notaport", ":", "10.0.0.5:"} {
		if p, err := ParsePackageProxy(bad); err == nil {
			t.Errorf("ParsePackageProxy(%q) = %v, want an error", bad, p)
		}
	}
}

// The egress policy is scoped to the one workload's pods, the proxy's
// addresses, and the proxy's port — and nothing more.
func TestPackageProxyEgressNetworkPolicy(t *testing.T) {
	proxy := &PackageProxy{CIDR: "10.96.10.5/32", Port: 3128}
	np := PackageProxyEgressNetworkPolicy("job-1234", proxy)
	if np.Name != PackageProxyPolicyName("job-1234") {
		t.Errorf("name = %q", np.Name)
	}
	if np.Spec.PodSelector.MatchLabels[ClusterIDLabel] != "job-1234" {
		t.Errorf("pod selector = %v, want this workload's pods only", np.Spec.PodSelector)
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Errorf("policy types = %v, want egress only", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 1 {
		t.Fatalf("rules = %d ingress, %d egress; want exactly one egress rule", len(np.Spec.Ingress), len(np.Spec.Egress))
	}
	rule := np.Spec.Egress[0]
	if len(rule.To) != 1 || rule.To[0].IPBlock == nil || rule.To[0].IPBlock.CIDR != "10.96.10.5/32" {
		t.Errorf("egress peer = %+v, want the proxy's /32 only", rule.To)
	}
	if len(rule.Ports) != 1 || rule.Ports[0].Port == nil || rule.Ports[0].Port.IntValue() != 3128 {
		t.Errorf("egress ports = %+v, want tcp/3128 only", rule.Ports)
	}
}

// The provision-side read of "this workload pip-installs": a non-empty pip
// list in either governed shape installs; env-vars-only, empty and absent
// documents do not; an unreadable or unrecognized shape errs open.
func TestRuntimeEnvInstallsPackages(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty", "", false},
		{"whitespace", "  \n ", false},
		{"null document", "null", false},
		{"env vars only", "env_vars:\n  A: b", false},
		{"empty pip list", "pip: []", false},
		{"empty packages list", "pip:\n  packages: []", false},
		{"pip list", "pip:\n  - numpy==1.26.4", true},
		{"pip object", "pip:\n  packages: [numpy==1.26.4]\n  pip_check: true", true},
		{"unreadable errs open", "pip: [torch==2.1.0", true},
		{"unrecognized pip shape errs open", "pip: torch==2.1.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuntimeEnvInstallsPackages(tc.raw); got != tc.want {
				t.Errorf("RuntimeEnvInstallsPackages(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
	// The compiled form a governed environment resolves to (#55) installs.
	compiled := "config:\n  setup_timeout_seconds: 600\nenv_vars:\n  OMP_NUM_THREADS: \"4\"\npip:\n  - numpy==1.26.4\n"
	if !RuntimeEnvInstallsPackages(compiled) || !strings.Contains(compiled, "pip:") {
		t.Error("a compiled environment with packages must read as installing")
	}
}
