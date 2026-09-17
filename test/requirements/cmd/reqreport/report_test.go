package main

import (
	"os"
	"strings"
	"testing"
)

func TestBuildFromFixture(t *testing.T) {
	rep, err := Build([]string{"testdata/l2.json"}, "l2")
	if err != nil {
		t.Fatal(err)
	}
	r3 := rep.Rows[2]
	if r3.N != 3 || r3.Tests != 2 || r3.Passed != 1 || r3.Failed != 1 || r3.Status != "failing" {
		t.Errorf("row 3 = %+v", r3)
	}
	// Row 5 must count only TestC's notyetbuilt line. The fixture also
	// carries a REQ line for req=5 from
	// test/requirements/req/req_test.go's own self-test
	// (TestNotYetBuiltInverts/self-test, Package
	// ".../test/requirements/req") -- req's unit tests exercise
	// NotYetBuilt using "5" as an arbitrary example number, not a real
	// coverage claim -- and readEvents must drop it before it ever
	// reaches a Row (selfTestPackageSuffix). If this regresses, row 5
	// would show Tests=2, NotYetBuilt=2 instead of 1.
	r5 := rep.Rows[4]
	if r5.NotYetBuilt != 1 || r5.Tests != 1 || r5.Status != "not-yet-built" {
		t.Errorf("row 5 = %+v", r5)
	}
	for _, n := range r5.TestNames {
		if n == "TestNotYetBuiltInverts/self-test" {
			t.Errorf("row 5 test names = %v; req's self-test must not be counted", r5.TestNames)
		}
	}
	// Row 6: its only covering test (TestD) was skipped -- no pass, no
	// fail, no NotYetBuilt marker. A skipped test did not pass, so this
	// must NOT read "built" (fix round 1, spec §2.4): it reads "skipped".
	r6 := rep.Rows[5]
	if r6.Tests != 1 || r6.Skipped != 1 || len(r6.SkipReasons) != 1 || r6.Status != "skipped" {
		t.Errorf("row 6 = %+v", r6)
	}
	// Row 7 pins the parent/subtest counting model (Task 8 decision 3): a
	// REQ line logged by the PARENT test (before its t.Run loop) is
	// attributed to the parent's own Test name and outcome, never to the
	// subtests that carry pass/fail individually. go test -json marks the
	// parent itself "fail" when any subtest fails, so this fixture's
	// TestE/sub_fail failing is what makes row 7 fail, via TestE's own
	// fail action -- not via any subtest event.
	r7 := rep.Rows[6]
	if r7.Tests != 1 || r7.Failed != 1 || r7.Status != "failing" {
		t.Errorf("row 7 = %+v", r7)
	}
	if len(r7.TestNames) != 1 || r7.TestNames[0] != "TestE" {
		t.Errorf("row 7 test names = %v, want [TestE]", r7.TestNames)
	}
	// Row 8: one covering test passed (TestF), one covering test was
	// skipped (TestG). Something is outstanding (the skipped test never
	// ran), but it isn't a skip-only row either, so this must read
	// "partial", not "skipped" or "built".
	r8 := rep.Rows[7]
	if r8.Tests != 2 || r8.Passed != 1 || r8.Skipped != 1 || r8.Status != "partial" {
		t.Errorf("row 8 = %+v", r8)
	}
	if len(rep.Untested()) != 15 {
		t.Errorf("untested = %d, want 15", len(rep.Untested()))
	}
}

func TestRenderMatchesGolden(t *testing.T) {
	rep, err := Build([]string{"testdata/l2.json"}, "l2")
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Markdown()
	want, err := os.ReadFile("testdata/expected.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(string(want)) {
		t.Errorf("markdown differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestMarkerDriftIsAnError(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/drift.json"
	if err := os.WriteFile(p, []byte(`{"Action":"run","Test":"T"}
{"Action":"output","Test":"T","Output":"REQ: kind=notyetbuilt req=5 reason=\"x\" outcome=passed\n"}
{"Action":"fail","Test":"T"}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Build([]string{p}, "l2")
	if err != nil {
		t.Fatal(err)
	}
	if errs := rep.Problems(true); len(errs) == 0 || !strings.Contains(errs[0], "appears built") {
		t.Errorf("Problems = %v; want a marker-drift error", errs)
	}
}

// The same test name appearing in two different -in files must be a hard
// error (fix round 1): silently merging their REQ lines would double-count
// Tests, and whichever file's outcome event is read last would silently
// clobber the other's outcome, with no error and no sign of the lost
// coverage. The same name recurring within ONE file (run, then output,
// then an outcome event -- how go test reports a single test) is normal
// and is exercised throughout TestBuildFromFixture and TestRenderMatchesGolden.
func TestDuplicateTestAcrossFilesIsAnError(t *testing.T) {
	dir := t.TempDir()
	pA := dir + "/a.json"
	pB := dir + "/b.json"
	if err := os.WriteFile(pA, []byte(`{"Action":"run","Test":"TestX"}
{"Action":"output","Test":"TestX","Output":"REQ: kind=covers req=1 reason=\"first file\"\n"}
{"Action":"pass","Test":"TestX"}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pB, []byte(`{"Action":"run","Test":"TestX"}
{"Action":"output","Test":"TestX","Output":"REQ: kind=covers req=1 reason=\"second file\"\n"}
{"Action":"fail","Test":"TestX"}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Build([]string{pA, pB}, "l2")
	if err == nil {
		t.Fatal("Build did not error on a test name shared across two files")
	}
	if !strings.Contains(err.Error(), "TestX") || !strings.Contains(err.Error(), pA) || !strings.Contains(err.Error(), pB) {
		t.Errorf("error = %q; want it to name TestX, %s and %s", err.Error(), pA, pB)
	}
}

// TestSkippedInOneShardRunInAnotherIsOneTest: a capability-gated test skips
// in the shard that lacks the capability and runs in the one that has it.
// That is one test, counted once, with the outcome of the shard that ran it
// — not the double-count or the error the cross-file rule was written for.
func TestSkippedInOneShardRunInAnotherIsOneTest(t *testing.T) {
	dir := t.TempDir()
	pA := dir + "/rbac-selfserve.json"
	pB := dir + "/autoscaling.json"
	if err := os.WriteFile(pA, []byte(`{"Action":"run","Test":"TestAutoscale"}
{"Action":"output","Test":"TestAutoscale","Output":"REQ: kind=covers req=6 reason=\"scales\"\n"}
{"Action":"output","Test":"TestAutoscale","Output":"REQ: kind=skip req=0 reason=\"target kind lacks capability autoscaling\"\n"}
{"Action":"skip","Test":"TestAutoscale"}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pB, []byte(`{"Action":"run","Test":"TestAutoscale"}
{"Action":"output","Test":"TestAutoscale","Output":"REQ: kind=covers req=6 reason=\"scales\"\n"}
{"Action":"pass","Test":"TestAutoscale"}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Build([]string{pA, pB}, "l3")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	r6 := rep.Rows[5]
	if r6.Tests != 1 || r6.Passed != 1 || r6.Skipped != 0 {
		t.Fatalf("req 6 = tests %d passed %d skipped %d; want the one run counted once as a pass", r6.Tests, r6.Passed, r6.Skipped)
	}
	// Order of files must not matter.
	rep, err = Build([]string{pB, pA}, "l3")
	if err != nil {
		t.Fatalf("Build (reversed): %v", err)
	}
	if r6 := rep.Rows[5]; r6.Tests != 1 || r6.Passed != 1 {
		t.Fatalf("reversed: req 6 = tests %d passed %d", r6.Tests, r6.Passed)
	}
}
