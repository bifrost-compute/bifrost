package req

import (
	"fmt"
	"strings"
	"testing"
)

func TestRequirementsRowsAreNumberedInOrder(t *testing.T) {
	rs := Requirements()
	if len(rs) < 18 {
		t.Fatalf("got %d requirements; the Ray Software Pack table has 18 rows and additions only grow it", len(rs))
	}
	for i, r := range rs {
		if r.N != i+1 {
			t.Errorf("row %d has n=%d; rows must be numbered 1..%d in order", i, r.N, len(rs))
		}
		if r.Title == "" || r.Priority == "" {
			t.Errorf("row %d missing title or priority", r.N)
		}
	}
}

func TestCoversPanicsOutOfRange(t *testing.T) {
	for _, n := range []int{0, len(Requirements()) + 1, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Covers(%d) did not panic", n)
				}
			}()
			Covers(t, n, "x")
		}()
	}
}

func TestReqLineRoundTrip(t *testing.T) {
	cases := []Line{
		{Kind: "covers", Req: 6, Reason: "creates a cluster"},
		{Kind: "notyetbuilt", Req: 5, Reason: "ephemeral RayJob", Outcome: "failed"},
		{Kind: "skip", Req: 0, Reason: "needs k8s"},
	}
	for _, c := range cases {
		got, ok := ParseLine(c.Format())
		if !ok || got != c {
			t.Errorf("round trip %+v -> %+v ok=%v", c, got, ok)
		}
	}
	if _, ok := ParseLine("some unrelated log line"); ok {
		t.Error("ParseLine accepted a non-REQ line")
	}
}

// go's t.Log/t.Logf decorate each line with "file:line: " ahead of the
// message; ParseLine must read that real output, not just Line.Format's
// own bare output.
func TestParseLineToleratesGoTestDecoration(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Line
	}{
		{
			name: "spaces, as go test -v indents",
			line: `    req.go:103: REQ: kind=notyetbuilt req=5 reason="x" outcome=failed`,
			want: Line{Kind: "notyetbuilt", Req: 5, Reason: "x", Outcome: "failed"},
		},
		{
			name: "tab leading whitespace",
			line: "\treq_test.go:12: REQ: kind=covers req=6 reason=\"y\"",
			want: Line{Kind: "covers", Req: 6, Reason: "y"},
		},
	}
	for _, c := range cases {
		got, ok := ParseLine(c.line)
		if !ok {
			t.Errorf("%s: ParseLine(%q) ok=false, want true", c.name, c.line)
			continue
		}
		if got != c.want {
			t.Errorf("%s: ParseLine(%q) = %+v, want %+v", c.name, c.line, got, c.want)
		}
	}
}

// NotYetBuilt must invert: a failing body is the expected state and passes,
// logging a notyetbuilt REQ line with outcome=failed; a passing body means
// the requirement appears built, fails the caller with the "appears built"
// message, and logs outcome=passed.
func TestNotYetBuiltInverts(t *testing.T) {
	// Exercise the internal decision pipeline directly (via a recorder) so
	// we can inspect both the caller's pass/fail state AND the exact REQ
	// line / message content in one place.
	rec := &recorder{T: t}
	b := runNotYetBuiltBody(rec, func(b *B) { b.Error("the feature is missing") })
	reportNotYetBuilt(rec, 5, "not built yet", b)
	if len(rec.errorfs) != 0 {
		t.Errorf("a failing body should not fail its caller; got Errorf calls: %v", rec.errorfs)
	}
	if !containsSubstr(rec.logs, "outcome=failed") {
		t.Errorf("expected a notyetbuilt REQ line with outcome=failed; got %v", rec.logs)
	}

	rec = &recorder{T: t}
	b = runNotYetBuiltBody(rec, func(b *B) {})
	reportNotYetBuilt(rec, 5, "not built yet", b)
	if len(rec.errorfs) != 1 || !strings.Contains(rec.errorfs[0], "appears built") {
		t.Errorf(`expected one Errorf call containing "appears built"; got %v`, rec.errorfs)
	}
	if !containsSubstr(rec.logs, "outcome=passed") {
		t.Errorf("expected a notyetbuilt REQ line with outcome=passed; got %v", rec.logs)
	}

	// Also exercise the public entry point end to end. A failing body: real
	// subtest is fine, nothing fails so nothing cascades.
	passed := t.Run("failing-body-is-ok", func(t *testing.T) {
		NotYetBuilt(t, 5, "not built yet", func(b *B) {
			b.Error("the feature is missing")
		})
	})
	if !passed {
		t.Error("NotYetBuilt with a failing body should PASS the outer test")
	}

	// A passing body: testing.Fail unconditionally propagates up a real
	// subtest's parent chain the instant it is called, so observing that
	// failure through a genuine subtest would also fail this test (and the
	// whole package). Give NotYetBuilt an unparented *testing.T instead and
	// inspect it directly.
	caller := &testing.T{}
	NotYetBuilt(caller, 5, "not built yet", func(b *B) {})
	if !caller.Failed() {
		t.Error("NotYetBuilt with a passing body should fail its caller")
	}
}

// A panic inside a NotYetBuilt body must be treated the same as a failed
// assertion: the caller passes, and the panic text is visible in the
// caller's log output.
func TestNotYetBuiltBodyPanicTreatedAsFailed(t *testing.T) {
	rec := &recorder{T: t}
	b := runNotYetBuiltBody(rec, func(b *B) { panic("boom") })
	if !b.failed {
		t.Error("a panicking body should be recorded as failed")
	}
	if !containsSubstr(rec.logs, "boom") {
		t.Errorf("expected panic text in outer logs; got %v", rec.logs)
	}
	reportNotYetBuilt(rec, 5, "reason", b)
	if len(rec.errorfs) != 0 {
		t.Errorf("a panicking body should not fail its caller; got Errorf calls: %v", rec.errorfs)
	}

	passed := t.Run("panics", func(t *testing.T) {
		NotYetBuilt(t, 5, "reason", func(b *B) { panic("boom") })
	})
	if !passed {
		t.Error("a panicking body should PASS the outer test")
	}
}

// b.Fatal must fail the body (not the caller) and must not hang.
func TestNotYetBuiltBodyFatal(t *testing.T) {
	passed := t.Run("fatal", func(t *testing.T) {
		NotYetBuilt(t, 5, "reason", func(b *B) {
			b.Fatal("nope")
		})
	})
	if !passed {
		t.Error("a body calling Fatal should PASS the outer test")
	}
}

// b.Skip must pass the caller and log a skip REQ line, never an
// "appears built" one.
func TestNotYetBuiltBodySkip(t *testing.T) {
	rec := &recorder{T: t}
	b := runNotYetBuiltBody(rec, func(b *B) { b.Skip("needs k8s") })
	reportNotYetBuilt(rec, 5, "reason", b)
	if len(rec.errorfs) != 0 {
		t.Errorf("a skipped body should not fail its caller; got Errorf calls: %v", rec.errorfs)
	}
	if !containsSubstr(rec.logs, "kind=skip") {
		t.Errorf("expected a kind=skip REQ line; got %v", rec.logs)
	}
	if containsSubstr(rec.logs, "appears built") {
		t.Errorf("a skipped body must not be reported as appears built: %v", rec.logs)
	}

	passed := t.Run("skip", func(t *testing.T) {
		NotYetBuilt(t, 5, "reason", func(b *B) { b.Skip("needs k8s") })
	})
	if !passed {
		t.Error("a body calling Skip should PASS the outer test")
	}
}

// Cleanup registered on b must reach the real outer test's cleanup list.
func TestNotYetBuiltForwardsCleanup(t *testing.T) {
	var ran bool
	t.Run("sub", func(t *testing.T) {
		NotYetBuilt(t, 5, "not built yet", func(b *B) {
			b.Cleanup(func() { ran = true })
			b.Error("still missing") // keep the subtest itself from failing
		})
	})
	if !ran {
		t.Error("Cleanup registered inside a NotYetBuilt body did not run")
	}
}

// Covers called with the *B a body receives must still reach the outer
// test's log, so reqreport can see it.
func TestCoversInsideNotYetBuiltBody(t *testing.T) {
	rec := &recorder{T: t}
	runNotYetBuiltBody(rec, func(b *B) {
		Covers(b, 6, "creates a cluster")
		b.Error("still missing")
	})
	if !containsSubstr(rec.logs, "kind=covers req=6") {
		t.Errorf("expected a covers REQ line in outer logs; got %v", rec.logs)
	}
}

func containsSubstr(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// recorder is a T backed by a real *testing.T (for Name/Helper/Failed and
// so a genuine setup failure still surfaces normally) that captures
// Log/Logf/Error/Errorf/Cleanup calls for assertions instead of forwarding
// them to the real t.
type recorder struct {
	*testing.T
	logs     []string
	errorfs  []string
	cleanups []func()
}

func (r *recorder) Log(args ...any) { r.logs = append(r.logs, fmt.Sprint(args...)) }
func (r *recorder) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}
func (r *recorder) Error(args ...any) { r.errorfs = append(r.errorfs, fmt.Sprint(args...)) }
func (r *recorder) Errorf(format string, args ...any) {
	r.errorfs = append(r.errorfs, fmt.Sprintf(format, args...))
}
func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }
