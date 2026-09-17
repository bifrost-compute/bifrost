package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// --- Tenant namespaces: wire <-> core, validation, resolution (#21) ---
//
// The `namespaces` section of the policy row maps a project to the
// Kubernetes namespace its clusters, jobs and services live in. It is the
// namespace boundary of the ATEP Ray Namespace Platform design brought
// into Bifrost's governance model: the platform creates one namespace per
// tenant (with its ResourceQuota, its Pod Identity associations and its
// offboarding-by-deletion story), the administrator maps the project to it
// here, and Bifrost writes its network posture into that namespace and
// places the project's workloads there. Same discipline as every other
// section: section-replace on PUT, validated as a unit, resolved once at
// admission and pinned on the spec (NamespaceResolved) so a later edit
// never moves a running workload.
//
// A namespaced Role cannot reach a second namespace, so the section is
// refused unless the control plane runs with `serve --tenant-namespaces`,
// which the chart pairs with cluster-wide RBAC.

// tenantNamespacesDisabled is the 400 a PUT of the section gets on a
// single-namespace control plane.
const tenantNamespacesDisabled = "tenant namespaces are disabled on this control plane: start it with `serve --tenant-namespaces` (and the chart's cluster-wide RBAC) to map projects to namespaces"

// isNamespaceName reports whether s is a valid Kubernetes namespace name:
// an RFC 1123 label (no dots, at most 63 characters).
func isNamespaceName(s string) bool {
	return core.IsK8sName(s) && !strings.Contains(s, ".") && len(s) <= 63
}

// namespacesFromWire validates an incoming project -> namespace map as a
// unit: non-empty project keys (no "*": the default namespace is the
// control plane's `--namespace`, not a policy value), and valid namespace
// names. It does not check the namespaces exist — the live client does,
// at apply, with a readable error — because the API may run without a
// Kubernetes client at all.
func namespacesFromWire(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for project, ns := range in {
		if project == "" {
			return nil, badRequest("invalid namespaces entry: project must not be empty")
		}
		if project == AdmissionEveryProject {
			return nil, badRequest(`invalid namespaces entry: "*" is not a project here; unmapped projects use the control plane's default namespace`)
		}
		if !isNamespaceName(ns) {
			return nil, badRequest(fmt.Sprintf("invalid namespaces entry for project %q: %q is not a valid Kubernetes namespace name (RFC 1123 label)", project, ns))
		}
		out[project] = ns
	}
	return out, nil
}

// namespacesToWire never returns nil: the contract's map is `{}`, not
// `null`, when nothing is configured.
func namespacesToWire(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// allocationsAgreeWithNamespaces refuses a project -> namespace map that
// contradicts an existing pool allocation: a Kueue LocalQueue is
// namespaced and must share its workloads' namespace, so a project whose
// allocation lives in namespace A cannot be mapped to namespace B without
// first moving the allocation. The check runs on the PUT (here) and on the
// allocation upsert (allocationNamespaceFor), so the two can never
// disagree.
func (s *Server) allocationsAgreeWithNamespaces(ctx context.Context, namespaces map[string]string) error {
	if len(namespaces) == 0 {
		return nil
	}
	pools, err := s.Store.ListPools(ctx)
	if err != nil {
		return wrapStoreErr(err)
	}
	for _, pool := range pools {
		allocs, err := s.Store.ListAllocations(ctx, pool.Name)
		if err != nil {
			return wrapStoreErr(err)
		}
		for _, a := range allocs {
			want, mapped := namespaces[a.Project]
			if mapped && a.Namespace != want {
				return badRequest(fmt.Sprintf("project %q is mapped to namespace %q but its allocation in pool %q lives in namespace %q; move the allocation first (a LocalQueue must share its workloads' namespace)", a.Project, want, pool.Name, a.Namespace))
			}
		}
	}
	return nil
}

// resolveNamespace returns the tenant namespace the effective policy maps
// project to, or "" for the control plane's default. Store failures
// surface as 5xx; an unmapped project is a valid answer, not an error.
func (s *Server) resolveNamespace(ctx context.Context, project string) (string, error) {
	if !s.TenantNamespaces {
		return "", nil
	}
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return "", wrapStoreErr(err)
	}
	if p == nil {
		return "", nil
	}
	return p.Namespaces[project], nil
}
