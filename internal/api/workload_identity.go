package api

import (
	"context"
	"fmt"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// --- Workload identity: wire <-> core, validation, resolution (#20) ---
//
// The workload_identity section of the policy row names, per project (or
// "*" for every project), the Kubernetes ServiceAccount a project's
// clusters, jobs and services run under. It follows the admission map's
// shape and the storage catalog's discipline: section-replace on PUT,
// validated as a unit, resolved once at admission and pinned on the spec
// (core.ClusterSpec.ServiceAccountResolved and friends) so a later edit is
// never retroactive.
//
// Bifrost never creates, reads or binds the ServiceAccount: the platform
// owns it (and the cloud IAM role bound to it); Bifrost only stamps its
// name on every pod template it renders, and the live client checks it
// exists before the apply so a typo surfaces as a readable condition
// rather than pods stuck in ContainerCreating.

func workloadIdentityRuleToWire(r core.WorkloadIdentityRule) WorkloadIdentityRule {
	out := WorkloadIdentityRule{}
	if r.ServiceAccount != "" {
		out.ServiceAccount = ptrTo(r.ServiceAccount)
	}
	if r.InteractiveServiceAccount != "" {
		out.InteractiveServiceAccount = ptrTo(r.InteractiveServiceAccount)
	}
	if r.JobServiceAccount != "" {
		out.JobServiceAccount = ptrTo(r.JobServiceAccount)
	}
	if r.ServingServiceAccount != "" {
		out.ServingServiceAccount = ptrTo(r.ServingServiceAccount)
	}
	return out
}

func ptrTo[T any](v T) *T { return &v }

// workloadIdentityToWire never returns nil: the contract's map is `{}`,
// not `null`, when nothing is configured.
func workloadIdentityToWire(in map[string]core.WorkloadIdentityRule) map[string]WorkloadIdentityRule {
	out := make(map[string]WorkloadIdentityRule, len(in))
	for k, v := range in {
		out[k] = workloadIdentityRuleToWire(v)
	}
	return out
}

// workloadIdentityFromWire converts an incoming workload_identity map and
// validates it as a unit: a non-empty project key ("*" for every
// project), and every named ServiceAccount a valid Kubernetes object name
// (RFC 1123 subdomain). A rule that names nothing is a 400 too — it
// would be a silent no-op an administrator could mistake for a binding.
func workloadIdentityFromWire(in map[string]WorkloadIdentityRule) (map[string]core.WorkloadIdentityRule, error) {
	out := make(map[string]core.WorkloadIdentityRule, len(in))
	for project, r := range in {
		if project == "" {
			return nil, badRequest("invalid workload identity rule: project must not be empty (use \"*\" for every project)")
		}
		what := fmt.Sprintf("invalid workload identity rule for project %q: ", project)
		rule := core.WorkloadIdentityRule{
			ServiceAccount:            deref(r.ServiceAccount),
			InteractiveServiceAccount: deref(r.InteractiveServiceAccount),
			JobServiceAccount:         deref(r.JobServiceAccount),
			ServingServiceAccount:     deref(r.ServingServiceAccount),
		}
		if rule.IsZero() {
			return nil, badRequest(what + "names no service account")
		}
		for field, name := range map[string]string{
			"service_account":             rule.ServiceAccount,
			"interactive_service_account": rule.InteractiveServiceAccount,
			"job_service_account":         rule.JobServiceAccount,
			"serving_service_account":     rule.ServingServiceAccount,
		} {
			if name != "" && !core.IsK8sName(name) {
				return nil, badRequest(fmt.Sprintf("%s%s %q is not a valid Kubernetes name (RFC 1123 subdomain)", what, field, name))
			}
		}
		out[project] = rule
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// resolveWorkloadIdentity returns the ServiceAccount the effective
// policy's workload_identity rules name for a workload of kind in
// project, or nil when no rule names one (the pods keep the namespace
// default). The "*" rule is consulted first and the project's own rule
// overrides it for the kind, so a deployment-wide default coexists with
// per-project identities. Store failures surface as 5xx through
// wrapStoreErr; a resolution itself never fails — an unbound project is a
// valid answer, not an error.
func (s *Server) resolveWorkloadIdentity(ctx context.Context, project string, kind core.WorkloadKind) (*string, error) {
	p, err := effectivePolicy(ctx, s.Store, &s.PolicySeed)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if p == nil {
		return nil, nil
	}
	return resolveWorkloadIdentityFrom(p.WorkloadIdentity, project, kind), nil
}

// resolveWorkloadIdentityFrom is the pure half of resolveWorkloadIdentity.
func resolveWorkloadIdentityFrom(rules map[string]core.WorkloadIdentityRule, project string, kind core.WorkloadKind) *string {
	var out string
	for _, key := range []string{AdmissionEveryProject, project} {
		rule, ok := rules[key]
		if !ok {
			continue
		}
		if sa := rule.For(kind); sa != "" {
			out = sa
		}
	}
	if out == "" {
		return nil
	}
	return &out
}
