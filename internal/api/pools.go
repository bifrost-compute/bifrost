// Capacity-pool API (ADR-0010, Slice 2). Pools are platform configuration
// (flavors + cohort + per-project allocations), not app lifecycle, so
// permissions are checked against auth.TargetPool per route: reads need
// Read (Viewer+), mutations need Write/Delete — which only Admin holds.
//
// Handlers only manipulate *desired* state in the Store (ADR-0004: the
// store is truth); the pool reconcile loop (Task 9) actuates the
// ResourceFlavor / ClusterQueue / LocalQueue objects through Kueue and
// records status observations back onto the pool rows. Ported from
// the Rust predecessor's pools.rs.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/bifrost-compute/bifrost/internal/auth"
	"github.com/bifrost-compute/bifrost/internal/controller"
	"github.com/bifrost-compute/bifrost/internal/core"
	"github.com/bifrost-compute/bifrost/internal/policy"
	"github.com/bifrost-compute/bifrost/internal/provision"
)

// gpuSharingFromWire converts the wire GpuSharing enum to core.GpuSharing,
// rejecting any value outside the known three (mirrors clusterSpecFromWire's
// Engine validation in clusters.go — the generated type is a bare string,
// so ingress validation happens here, not at json.Unmarshal time).
func gpuSharingFromWire(w *GpuSharing) (*core.GpuSharing, error) {
	if w == nil {
		return nil, nil
	}
	var v core.GpuSharing
	switch *w {
	case Mig:
		v = core.GpuSharingMig
	case TimeSlice:
		v = core.GpuSharingTimeSlice
	case WholeGpu:
		v = core.GpuSharingWholeGpu
	default:
		return nil, badRequest(fmt.Sprintf("invalid gpu_sharing %q", string(*w)))
	}
	return &v, nil
}

func taintsFromWire(in []TaintSpec) []core.TaintSpec {
	if len(in) == 0 {
		return nil
	}
	out := make([]core.TaintSpec, len(in))
	for i, t := range in {
		out[i] = core.TaintSpec{Key: t.Key, Value: t.Value, Effect: t.Effect}
	}
	return out
}

func flavorsFromWire(in []FlavorSpec) []core.FlavorSpec {
	if len(in) == 0 {
		return nil
	}
	out := make([]core.FlavorSpec, len(in))
	for i, f := range in {
		out[i] = core.FlavorSpec{
			Name:       f.Name,
			Resources:  f.Resources,
			NodeLabels: f.NodeLabels,
			Taints:     taintsFromWire(f.Taints),
		}
	}
	return out
}

// poolPurposeFromWire converts the wire PoolPurpose enum (#4) to
// core.PoolPurpose: absent = compute (every pre-#4 pool); anything but the
// two known values is a client error (the generated type is a bare
// string, so ingress validation happens here, as for gpu_sharing).
func poolPurposeFromWire(w *PoolPurpose) (core.PoolPurpose, error) {
	if w == nil {
		return core.DefaultPoolPurpose, nil
	}
	switch *w {
	case Compute:
		return core.PoolPurposeCompute, nil
	case Serving:
		return core.PoolPurposeServing, nil
	default:
		return "", badRequest(fmt.Sprintf("invalid purpose %q (want compute or serving)", string(*w)))
	}
}

// poolSpecFromWire converts the generated wire PoolSpec into core.PoolSpec.
func poolSpecFromWire(w *PoolSpec) (core.PoolSpec, error) {
	gpuSharing, err := gpuSharingFromWire(w.GpuSharing)
	if err != nil {
		return core.PoolSpec{}, err
	}
	purpose, err := poolPurposeFromWire(w.Purpose)
	if err != nil {
		return core.PoolSpec{}, err
	}
	return core.PoolSpec{
		Name:              w.Name,
		Flavors:           flavorsFromWire(w.Flavors),
		Cohort:            w.Cohort,
		FairSharingWeight: w.FairSharingWeight,
		Elastic:           w.Elastic,
		GpuSharing:        gpuSharing,
		Purpose:           purpose,
	}, nil
}

// formatQuantity renders a summed quantity back to a string: integral
// values without a decimal point ("128"), fractional values as-is ("0.5").
// Ported from pools.rs's format_quantity.
func formatQuantity(v float64) string {
	if v == float64(int64(v)) && v > -1e15 && v < 1e15 {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%v", v)
}

// sumFlavorResources sums every flavor's resource quantities, resource key
// -> summed amount, tracking any key that fails to parse on ANY flavor so
// the caller can omit it from a display sum (a partial sum would misreport
// capacity). Shared by poolView's total_nominal and poolUsageView's
// nominal half. Ported from pools.rs's PoolView::from_stored /
// pool_usage's nominal loop.
func sumFlavorResources(poolName string, flavors []core.FlavorSpec) (sums map[string]float64, unparseable map[string]bool) {
	sums = map[string]float64{}
	unparseable = map[string]bool{}
	for _, f := range flavors {
		for k, v := range f.Resources {
			q, err := policy.ParseQuantity(v)
			if err != nil {
				slog.Warn("api: unparseable flavor quantity omitted from total_nominal",
					"pool", poolName, "flavor", f.Name, "resource", k, "error", err)
				unparseable[k] = true
				continue
			}
			sums[k] += q
		}
	}
	return sums, unparseable
}

// poolView converts a StoredPool into the wire PoolView, including
// total_nominal (the per-resource sum of all flavors' nominal quotas).
func poolView(p *controller.StoredPool) PoolView {
	sums, unparseable := sumFlavorResources(p.Name, p.Spec.Flavors)
	totalNominal := make(map[string]string, len(sums))
	for k, v := range sums {
		if unparseable[k] {
			continue
		}
		totalNominal[k] = formatQuantity(v)
	}
	var gpuSharing *GpuSharing
	if p.Spec.GpuSharing != nil {
		v := GpuSharing(*p.Spec.GpuSharing)
		gpuSharing = &v
	}
	// purpose is always written (compute when the stored spec predates
	// #4) so a client can tell serving pools apart without knowing the
	// default.
	purpose := PoolPurpose(p.Spec.Purpose.OrDefault())
	flavors := make([]FlavorSpec, len(p.Spec.Flavors))
	for i, f := range p.Spec.Flavors {
		taints := make([]TaintSpec, len(f.Taints))
		for j, t := range f.Taints {
			taints[j] = TaintSpec{Key: t.Key, Value: t.Value, Effect: t.Effect}
		}
		flavors[i] = FlavorSpec{Name: f.Name, Resources: f.Resources, NodeLabels: f.NodeLabels, Taints: taints}
	}
	return PoolView{
		Name:              p.Name,
		Generation:        int64(p.Generation),
		CreatedAt:         int64(p.CreatedAt),
		Flavors:           flavors,
		Cohort:            p.Spec.Cohort,
		FairSharingWeight: p.Spec.FairSharingWeight,
		Elastic:           p.Spec.Elastic,
		GpuSharing:        gpuSharing,
		Purpose:           &purpose,
		TotalNominal:      totalNominal,
	}
}

// validatePoolQuantities requires every flavor resource value to parse as a
// Kubernetes quantity (core validates shape, never quantity syntax —
// parseability is checked here, at the edge). Ported from pools.rs's
// validate_quantities.
func validatePoolQuantities(spec *core.PoolSpec) error {
	for _, f := range spec.Flavors {
		for k, v := range f.Resources {
			if _, err := policy.ParseQuantity(v); err != nil {
				return badRequest(fmt.Sprintf("invalid spec: flavor %s resource %s: %s", f.Name, k, err.Error()))
			}
		}
	}
	return nil
}

// ListPools lists every capacity pool. Read on Target::Pool (Viewer+).
func (s *Server) ListPools(ctx context.Context, _ ListPoolsRequestObject) (ListPoolsResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Read, auth.TargetPool); err != nil {
		return nil, err
	}
	pools, err := s.Store.ListPools(ctx)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	views := make([]PoolView, len(pools))
	for i := range pools {
		views[i] = poolView(&pools[i])
	}
	return ListPools200JSONResponse(views), nil
}

// CreatePool creates a pool. Write on Target::Pool (Admin only in
// practice, since only Admin grants Write there — see rbac.go's Grants).
// Create-only in v0: upsert-with-bump is for a later PATCH.
func (s *Server) CreatePool(ctx context.Context, req CreatePoolRequestObject) (CreatePoolResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Write, auth.TargetPool); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing request body")
	}
	spec, err := poolSpecFromWire(&req.Body.Spec)
	if err != nil {
		return nil, err
	}
	if verr := spec.Validate(); verr != nil {
		return nil, badRequest("invalid spec: " + verr.Error())
	}
	if verr := validatePoolQuantities(&spec); verr != nil {
		return nil, verr
	}
	existing, err := s.Store.GetPool(ctx, spec.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if existing != nil {
		return nil, conflict(fmt.Sprintf("pool %s already exists", spec.Name))
	}
	if _, err := s.Store.UpsertPool(ctx, spec.Name, spec); err != nil {
		return nil, wrapStoreErr(err)
	}
	// The pool name isn't an AuditEvent field (api-v1.md §5.9); the action
	// string carries the pool scope, matching pools.rs's create_pool.
	action := "create_pool"
	status := uint16(http.StatusCreated)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Status: &status,
	})
	return CreatePool201Response{}, nil
}

// GetPool reads one pool. Read on Target::Pool.
func (s *Server) GetPool(ctx context.Context, req GetPoolRequestObject) (GetPoolResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Read, auth.TargetPool); err != nil {
		return nil, err
	}
	p, err := s.Store.GetPool(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if p == nil {
		return nil, notFound("no such pool")
	}
	return GetPool200JSONResponse(poolView(p)), nil
}

// DeletePool hard-deletes a pool. Delete on Target::Pool.
func (s *Server) DeletePool(ctx context.Context, req DeletePoolRequestObject) (DeletePoolResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Delete, auth.TargetPool); err != nil {
		return nil, err
	}
	err := s.Store.DeletePool(ctx, req.Name)
	switch {
	case err == nil:
		action := "delete_pool"
		status := uint16(http.StatusAccepted)
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionAllow, Action: &action, Status: &status,
		})
		return DeletePool202Response{}, nil
	case storeErrContains(err, "no such pool"):
		return nil, notFound("no such pool")
	default:
		return nil, wrapStoreErr(err)
	}
}

// ListAllocations lists one pool's project allocations. Read on
// Target::Pool.
func (s *Server) ListAllocations(ctx context.Context, req ListAllocationsRequestObject) (ListAllocationsResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Read, auth.TargetPool); err != nil {
		return nil, err
	}
	allocs, err := s.Store.ListAllocations(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	views := make([]AllocationSpec, len(allocs))
	for i, a := range allocs {
		views[i] = allocationSpecToWire(a)
	}
	return ListAllocations200JSONResponse(views), nil
}

// allocationSpecToWire converts core.AllocationSpec to the generated wire
// AllocationSpec. Field-by-field: Go only allows a blind struct
// conversion when both sides declare their fields in the same sequence,
// and the wire type's oapi-codegen-generated field order (alphabetized)
// doesn't match core's.
func allocationSpecToWire(a core.AllocationSpec) AllocationSpec {
	return AllocationSpec{
		Pool: a.Pool, Project: a.Project, Namespace: a.Namespace,
		Nominal: a.Nominal, BorrowingLimit: a.BorrowingLimit, LendingLimit: a.LendingLimit,
	}
}

// DeleteAllocation deletes one project's allocation within a pool. Delete
// on Target::Pool.
func (s *Server) DeleteAllocation(ctx context.Context, req DeleteAllocationRequestObject) (DeleteAllocationResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Delete, auth.TargetPool); err != nil {
		return nil, err
	}
	err := s.Store.DeleteAllocation(ctx, req.Name, req.Project)
	switch {
	case err == nil:
		action := "delete_allocation"
		status := uint16(http.StatusAccepted)
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionAllow, Action: &action, Status: &status,
		})
		return DeleteAllocation202Response{}, nil
	case storeErrContains(err, "no such allocation"):
		return nil, notFound("no such allocation")
	default:
		return nil, wrapStoreErr(err)
	}
}

// PutAllocation creates or replaces one project's allocation within a
// pool. Write on Target::Pool. Enforces GPU tenant isolation (#58): the
// upsert must not leave a pool resolving to time-slice shared by more than
// one project.
func (s *Server) PutAllocation(ctx context.Context, req PutAllocationRequestObject) (PutAllocationResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Write, auth.TargetPool); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing request body")
	}
	body := req.Body
	// Path params win; a contradicting body is a client error.
	if body.Pool != nil && *body.Pool != req.Name {
		return nil, badRequest("body pool/project must match the path (or be omitted)")
	}
	if body.Project != nil && *body.Project != req.Project {
		return nil, badRequest("body pool/project must match the path (or be omitted)")
	}
	pool, err := s.Store.GetPool(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if pool == nil {
		return nil, notFound("no such pool")
	}
	alloc := core.AllocationSpec{
		Pool: req.Name, Project: req.Project, Namespace: body.Namespace,
		Nominal: body.Nominal, BorrowingLimit: body.BorrowingLimit, LendingLimit: body.LendingLimit,
	}
	if verr := alloc.Validate(); verr != nil {
		return nil, badRequest("invalid allocation: " + verr.Error())
	}
	// Tenant namespaces (#21): a project's LocalQueue must live where its
	// workloads do, so an allocation for a mapped project is refused
	// unless it names that namespace (the PUT of the map checks the
	// converse).
	if mapped, err := s.resolveNamespace(ctx, alloc.Project); err != nil {
		return nil, err
	} else if mapped != "" && alloc.Namespace != mapped {
		return nil, badRequest(fmt.Sprintf("invalid allocation: project %q is mapped to namespace %q (policy namespaces), so its allocation must use that namespace, not %q", alloc.Project, mapped, alloc.Namespace))
	}

	// GPU tenant isolation (#58): tenants = distinct allocation projects
	// after the upsert (allocations are keyed (pool, project), so the set
	// union is exact — a re-PUT of an existing allocation doesn't
	// double-count).
	existing, err := s.Store.ListAllocations(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	tenants := map[string]struct{}{req.Project: {}}
	for _, a := range existing {
		tenants[a.Project] = struct{}{}
	}
	if verr := policy.CheckPoolGpuIsolation(&pool.Spec, s.PolicySeed.EffectiveGPUDefaultSharing(), len(tenants)); verr != nil {
		reason := "gpu_tenant_isolation"
		action := "put_allocation"
		status := uint16(http.StatusBadRequest)
		EmitAudit(ctx, s.Store, &core.AuditEvent{
			Ts: controller.NowUnix(), Subject: identitySubject(identity),
			Decision: core.AuditDecisionDeny, Reason: &reason, Action: &action, Status: &status,
		})
		return nil, badRequest(verr.Error())
	}

	if err := s.Store.UpsertAllocation(ctx, alloc); err != nil {
		return nil, wrapStoreErr(err)
	}
	action := "put_allocation"
	status := uint16(http.StatusOK)
	EmitAudit(ctx, s.Store, &core.AuditEvent{
		Ts: controller.NowUnix(), Subject: identitySubject(identity),
		Decision: core.AuditDecisionAllow, Action: &action, Status: &status,
	})
	return PutAllocation200Response{}, nil
}

// sumQuantities sums a quantity-string map into f64, skipping unparseable
// values with a warning (fail-soft display math, same convention as
// poolView). Ported from pools.rs's sum_quantities.
func sumQuantities(pool, origin string, resources map[string]string, into map[string]float64) {
	for k, v := range resources {
		q, err := policy.ParseQuantity(v)
		if err != nil {
			slog.Warn("api: unparseable usage quantity omitted", "pool", pool, "origin", origin, "resource", k, "error", err)
			continue
		}
		into[k] += q
	}
}

// PoolUsage reports one pool's live point-in-time utilization (Slice 4):
// built from the pool's latest stored ClusterQueue/LocalQueue observation
// plus the spec's nominal quotas. Read on Target::Pool.
func (s *Server) PoolUsage(ctx context.Context, req PoolUsageRequestObject) (PoolUsageResponseObject, error) {
	identity, _ := IdentityFromContext(ctx)
	if err := Authorize(ctx, s.Store, identity, auth.Read, auth.TargetPool); err != nil {
		return nil, err
	}
	p, err := s.Store.GetPool(ctx, req.Name)
	if err != nil {
		return nil, wrapStoreErr(err)
	}
	if p == nil {
		return nil, notFound("no such pool")
	}

	allocated := map[string]float64{}
	projects := map[string]map[string]float64{}
	if p.ObservedJSON != nil {
		var obs provision.PoolObservation
		if err := json.Unmarshal([]byte(*p.ObservedJSON), &obs); err != nil {
			slog.Warn("api: stored pool observation did not parse; treating as unobserved", "pool", req.Name, "error", err)
		} else {
			for flavor, resources := range obs.FlavorsUsage {
				sumQuantities(req.Name, flavor, resources, allocated)
			}
			for lq, resources := range obs.QueuesUsage {
				perProject := map[string]float64{}
				sumQuantities(req.Name, lq, resources, perProject)
				projects[lq] = perProject
			}
		}
	}

	nominal, unparseable := sumFlavorResources(req.Name, p.Spec.Flavors)

	keys := map[string]struct{}{}
	for k := range nominal {
		if !unparseable[k] {
			keys[k] = struct{}{}
		}
	}
	for k := range allocated {
		keys[k] = struct{}{}
	}
	sortedKeys := make([]string, 0, len(keys))
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	utilization := make(map[string]ResourceUtilization, len(sortedKeys))
	for _, k := range sortedKeys {
		a := allocated[k]
		n := nominal[k]
		pct := 0.0
		if n > 0 {
			pct = a / n * 100
		}
		utilization[k] = ResourceUtilization{Allocated: a, Nominal: n, Pct: pct}
	}

	var sampledAt *int64
	if p.ObservedAt != nil {
		v := int64(*p.ObservedAt)
		sampledAt = &v
	}
	return PoolUsage200JSONResponse(PoolUsageView{
		Pool: req.Name, SampledAt: sampledAt, Utilization: utilization, Projects: projects,
	}), nil
}
