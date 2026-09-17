package r07_admin_controls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/bifrost-compute/bifrost/pkg/client"
	"github.com/bifrost-compute/bifrost/test/requirements/fixture"
	"github.com/bifrost-compute/bifrost/test/requirements/req"
	"github.com/bifrost-compute/bifrost/test/requirements/target"
)

// The image catalog is the "images" half of requirement 7 made explicit
// (#10): instead of a prefix allowlist, an administrator lists the exact
// images a project may run — with their Ray version stated rather than
// guessed from the tag — and flips the project's admission rule to
// catalog_only. Users see only the entries open to their projects.

// currentAdmission is the policy's admission map as it stands, so a test
// can tighten one project's rule without dropping a cluster target's
// deployment-wide "*" rule.
func currentAdmission(t *testing.T, tgt req.Target) map[string]client.AdmissionRule {
	t.Helper()
	before, err := tgt.As("admin").API().GetPolicyWithResponse(context.Background())
	if err != nil || before.JSON200 == nil {
		t.Fatalf("get_policy: err=%v", err)
	}
	out := map[string]client.AdmissionRule{}
	if before.JSON200.Admission != nil {
		for k, v := range *before.JSON200.Admission {
			out[k] = v
		}
	}
	return out
}

func TestCatalogOnlyAdmitsCatalogImagesAndStatesTheirRayVersion(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 7, "with catalog_only set for a project, only an image-catalog entry open to it is admitted, and the entry's ray_version fills a spec that leaves it empty")
	req.Covers(t, 10, "an administrator vets images by exact reference in the image catalog; list_images shows a member only the entries open to their projects")
	ctx := context.Background()
	name := req.Name("img")
	admission := currentAdmission(t, tgt)
	rule := admission["team-a"]
	yes := true
	rule.CatalogOnly = &yes
	admission["team-a"] = rule
	admissionJSON, _ := json.Marshal(admission)
	setPolicySections(t, tgt, fmt.Sprintf(`{"images":[{"name":%q,"ref":%q,"ray_version":"2.56.0","python_version":"3.11","projects":["team-a"]}],"admission":%s}`,
		name, fixture.RayImage(), admissionJSON))

	// Catalog image, ray_version left empty: admitted, version from the catalog.
	id := req.Name("cat")
	body := fixture.ClusterBodyWithImage(id, "team-a", fixture.RayImage(), nil)
	body.Spec.RayVersion = ""
	resp, err := tgt.As("dev-a").API().CreateClusterWithResponse(ctx, body)
	if err != nil || resp.StatusCode() != http.StatusCreated {
		t.Fatalf("create with a catalog image: err=%v status=%v body=%s", err, resp.StatusCode(), resp.Body)
	}
	got, err := tgt.As("dev-a").API().GetClusterWithResponse(ctx, id)
	if err != nil || got.JSON200 == nil {
		t.Fatalf("get: err=%v", err)
	}
	if got.JSON200.RayVersion != "2.56.0" {
		t.Errorf("ray_version = %q, want the catalog's 2.56.0", got.JSON200.RayVersion)
	}

	// Same repository, a different tag: not the vetted image.
	other := req.Name("notcat")
	resp, err = tgt.As("dev-a").API().CreateClusterWithResponse(ctx, fixture.ClusterBodyWithImage(other, "team-a", fixture.RayImage()+"-notvetted", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("create with a non-catalog image under catalog_only = %d %s, want 400", resp.StatusCode(), resp.Body)
	}
	if st, _ := fixture.Get(t, tgt, "admin", other); st != http.StatusNotFound {
		t.Fatalf("a refused create must persist nothing; get = %d", st)
	}

	// list_images: team-a's entry is visible to dev-a and invisible to dev-b.
	sees := func(principal string) bool {
		r, err := tgt.As(principal).API().ListImagesWithResponse(ctx)
		if err != nil || r.JSON200 == nil {
			t.Fatalf("list_images as %s: err=%v status=%v body=%s", principal, err, r.StatusCode(), r.Body)
		}
		for _, e := range *r.JSON200 {
			if e.Name == name {
				return true
			}
		}
		return false
	}
	if !sees("dev-a") || sees("dev-b") || !sees("admin") {
		t.Errorf("visibility: dev-a=%v dev-b=%v admin=%v, want true false true", sees("dev-a"), sees("dev-b"), sees("admin"))
	}
}

func TestInspectImageDescribesACatalogEntryWithoutPulling(t *testing.T) {
	tgt := target.Get(t)
	req.Covers(t, 10, "inspect_image reads a catalog image's manifest, config and layer history from its registry without pulling it")
	ctx := context.Background()
	ref := os.Getenv("REQ_INSPECT_IMAGE")
	if tgt.Name() == "inproc" {
		ref = fixture.FakeRegistry(t)
	} else if ref == "" {
		reason := "target " + tgt.Name() + " declares no REQ_INSPECT_IMAGE the control plane can reach"
		t.Log(req.Line{Kind: "skip", Req: 0, Reason: reason}.Format())
		t.Skip(reason)
	}
	name := req.Name("insp")
	setPolicySections(t, tgt, fmt.Sprintf(`{"images":[{"name":%q,"ref":%q,"ray_version":"2.56.0","projects":["team-a"]}]}`, name, ref))

	r, err := tgt.As("dev-a").API().InspectImageWithResponse(ctx, name)
	if err != nil || r.JSON200 == nil {
		t.Fatalf("inspect_image: err=%v status=%v body=%s", err, r.StatusCode(), r.Body)
	}
	doc := r.JSON200
	if doc.Reference != ref || doc.Digest == "" || len(doc.Layers) == 0 || len(doc.History) == 0 || doc.SizeBytes <= 0 || doc.Source != "registry" {
		t.Errorf("inspect = %+v, want a digest, layers, history and size", doc)
	}
	nonEmpty := 0
	for _, h := range doc.History {
		if !h.EmptyLayer {
			nonEmpty++
			if h.LayerDigest == nil || h.SizeBytes == nil {
				t.Errorf("history step %q produced a layer but is not joined to it", h.CreatedBy)
			}
		}
	}
	if nonEmpty != len(doc.Layers) {
		t.Errorf("%d layer-producing steps for %d layers", nonEmpty, len(doc.Layers))
	}
	// Not open to team-b: 404, never 403 (they do not learn it exists).
	r2, err := tgt.As("dev-b").API().InspectImageWithResponse(ctx, name)
	if err != nil || r2.StatusCode() != http.StatusNotFound {
		t.Errorf("inspect as dev-b = %v %v, want 404", err, r2.StatusCode())
	}
}
