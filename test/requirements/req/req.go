// Package req is the requirement-test framework's vocabulary: which
// requirement a test proves (Covers), which it is waiting on (NotYetBuilt),
// what a target must have for it to run (NeedsCapability), and the Target
// seam every test speaks through. It imports nothing from internal/.
package req

import (
	_ "embed"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed requirements.yaml
var requirementsYAML []byte

// Requirement is one row of the requirement table.
type Requirement struct {
	N        int    `yaml:"n"`
	Priority string `yaml:"priority"`
	Title    string `yaml:"title"`
}

var (
	reqsOnce sync.Once
	reqs     []Requirement
)

// Requirements returns the table's rows, in order.
func Requirements() []Requirement {
	reqsOnce.Do(func() {
		if err := yaml.Unmarshal(requirementsYAML, &reqs); err != nil {
			panic("req: requirements.yaml: " + err.Error())
		}
	})
	return reqs
}

func mustValid(n int) {
	if n < 1 || n > len(Requirements()) {
		panic(fmt.Sprintf("req: requirement %d is out of range 1..%d", n, len(Requirements())))
	}
}

// T is the subset of testing.TB the framework's helpers accept. *testing.T
// satisfies it; so does *B, the harness NotYetBuilt hands a body.
type T interface {
	Helper()
	Name() string
	Log(args ...any)
	Logf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Skip(args ...any)
	Skipf(format string, args ...any)
	Failed() bool
	Cleanup(func())
}

// Covers declares that the calling test proves requirement n. Call it first.
// A test may Covers two requirements when one scenario genuinely proves
// both; give each its own reason.
func Covers(t T, n int, reason string) {
	t.Helper()
	mustValid(n)
	t.Log(Line{Kind: "covers", Req: n, Reason: reason}.Format())
}

// fatalSentinel and skipSentinel are panic values B.Fatal/Fatalf and
// B.Skip/Skipf use to unwind a NotYetBuilt body without terminating the
// goroutine that's running it (unlike testing.T.FailNow's runtime.Goexit,
// which would also tear down the caller's own test goroutine, since a
// NotYetBuilt body now runs synchronously on it).
type fatalSentinel struct{}
type skipSentinel struct{}

// B is what a NotYetBuilt body receives; it never fails the caller. Error
// and Errorf record the body as failed and forward the text to the outer
// test's log (prefixed, so it reads as diagnostic detail, not a REQ line
// reqreport would try to parse). Fatal and Fatalf do the same, then unwind
// the body via panic(fatalSentinel{}). Skip and Skipf record the body as
// skipped, forward the reason to the outer log, and unwind via
// panic(skipSentinel{}). Cleanup forwards to the outer test's Cleanup, so a
// Target's registered cleanup still runs. Log and Logf forward directly, so
// a Covers call inside a body still reaches reqreport.
//
// B deliberately does not implement Run, Parallel, TempDir, Setenv,
// Deadline, or Context: a NotYetBuilt body must obtain its Target and any
// other fixtures from the outer *testing.T before calling NotYetBuilt, and
// use B only for assertions. That's enforced by the type, not convention.
type B struct {
	outer T

	mu      sync.Mutex
	failed  bool
	skipped bool
	skipWhy string
}

func (b *B) Helper()      {}
func (b *B) Name() string { return b.outer.Name() }
func (b *B) Log(args ...any) {
	b.outer.Log(args...)
}
func (b *B) Logf(format string, args ...any) {
	b.outer.Logf(format, args...)
}
func (b *B) Cleanup(f func()) { b.outer.Cleanup(f) }

// Failed reports whether the body has recorded a failure so far.
func (b *B) Failed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failed
}

func (b *B) Error(args ...any) {
	b.mu.Lock()
	b.failed = true
	b.mu.Unlock()
	b.outer.Logf("not-yet-built body: %s", fmt.Sprint(args...))
}

func (b *B) Errorf(format string, args ...any) {
	b.mu.Lock()
	b.failed = true
	b.mu.Unlock()
	b.outer.Logf("not-yet-built body: %s", fmt.Sprintf(format, args...))
}

func (b *B) Fatal(args ...any) {
	b.Error(args...)
	panic(fatalSentinel{})
}

func (b *B) Fatalf(format string, args ...any) {
	b.Errorf(format, args...)
	panic(fatalSentinel{})
}

func (b *B) Skip(args ...any) {
	b.mu.Lock()
	b.skipped = true
	b.skipWhy = fmt.Sprint(args...)
	b.mu.Unlock()
	panic(skipSentinel{})
}

func (b *B) Skipf(format string, args ...any) {
	b.mu.Lock()
	b.skipped = true
	b.skipWhy = fmt.Sprintf(format, args...)
	b.mu.Unlock()
	panic(skipSentinel{})
}

// NotYetBuilt runs body against a harness that never fails t: a failing
// body is the expected state for an unbuilt requirement, and t passes; a
// passing body means the requirement appears built, and t fails until a
// human removes the marker in the same PR that built it. A body that calls
// Skip is treated as neither built nor failed: t passes and a skip REQ
// line is logged instead of a notyetbuilt one.
//
// body receives a *B, not a *testing.T: get any fixtures (a Target, say)
// from t before calling NotYetBuilt, and use the *B only for assertions.
// Running body via t.Run with a real *testing.T would not work: go's
// testing.Fail unconditionally propagates up a subtest's parent chain the
// instant an assertion fails, which is the expected, common case for an
// unbuilt requirement, and would fail t (and every ancestor up to the
// top-level test) regardless of what NotYetBuilt did afterward.
func NotYetBuilt(t *testing.T, n int, reason string, body func(b *B)) {
	t.Helper()
	mustValid(n)
	b := runNotYetBuiltBody(t, body)
	reportNotYetBuilt(t, n, reason, b)
}

// runNotYetBuiltBody runs body against a fresh *B tied to t, recovering a
// panic (including B.Fatal/Fatalf's and B.Skip/Skipf's sentinels) so a
// NotYetBuilt body can never crash the caller's goroutine. An unrecognized
// panic is treated as a failed assertion, with its text and stack logged to
// t so it's visible for debugging.
func runNotYetBuiltBody(t T, body func(*B)) (b *B) {
	b = &B{outer: t}
	defer func() {
		switch r := recover().(type) {
		case nil, fatalSentinel, skipSentinel:
			// already recorded on b by B's own methods.
		default:
			b.mu.Lock()
			b.failed = true
			b.mu.Unlock()
			t.Logf("not-yet-built body panicked: %v\n%s", r, debug.Stack())
		}
	}()
	body(b)
	return b
}

// reportNotYetBuilt decides, from b's recorded outcome, what REQ line to
// log on t and whether to fail t. Split out from NotYetBuilt so it's
// testable directly against a recording T, without needing a real
// *testing.T or exercising the panic-recovery path.
func reportNotYetBuilt(t T, n int, reason string, b *B) {
	switch {
	case b.skipped:
		t.Log(Line{Kind: "skip", Req: n, Reason: "not-yet-built body skipped: " + b.skipWhy}.Format())
	case b.failed:
		t.Log(Line{Kind: "notyetbuilt", Req: n, Reason: reason, Outcome: "failed"}.Format())
	default:
		t.Log(Line{Kind: "notyetbuilt", Req: n, Reason: reason, Outcome: "passed"}.Format())
		t.Errorf("requirement %d appears built: the NotYetBuilt body passed. remove the NotYetBuilt marker in the same PR that made this pass (reason was: %s)", n, reason)
	}
}

// NeedsCapability skips unless the target declares cap. The skip is
// recorded as a REQ line so the report can say WHY a column is partial.
func NeedsCapability(t T, tgt Target, cap string) {
	t.Helper()
	if !tgt.Has(cap) {
		reason := "target " + tgt.Name() + " lacks capability " + cap
		t.Log(Line{Kind: "skip", Req: 0, Reason: reason}.Format())
		t.Skip(reason)
	}
}

// NeedK8s skips on targets without Kubernetes (inproc).
func NeedK8s(t T, tgt Target) {
	t.Helper()
	if _, ok := tgt.K8s(); !ok {
		reason := "target " + tgt.Name() + " has no Kubernetes"
		t.Log(Line{Kind: "skip", Req: 0, Reason: reason}.Format())
		t.Skip(reason)
	}
}

// EventuallyTimeout is the per-lane convergence budget (spec §8).
func EventuallyTimeout(tgt Target) time.Duration {
	if _, ok := tgt.K8s(); ok {
		// REQ_EVENTUALLY_TIMEOUT (Go duration) lets a slow lane — a 4-vCPU
		// CI runner pulling a 2.5 GB Ray image and starting a RayService —
		// buy time without loosening the default a real cluster is held to.
		if v := os.Getenv("REQ_EVENTUALLY_TIMEOUT"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
		return 5 * time.Minute
	}
	return 5 * time.Second
}

// Eventually polls cond until it reports true or the lane timeout elapses.
// cond returns a human-readable state for the failure message. This is the
// only sanctioned way to wait; time.Sleep is forbidden under test/requirements.
func Eventually(t T, tgt Target, cond func() (ok bool, state string)) {
	t.Helper()
	deadline := time.Now().Add(EventuallyTimeout(tgt))
	var last string
	for time.Now().Before(deadline) {
		ok, state := cond()
		if ok {
			return
		}
		last = state
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s; last state: %s", EventuallyTimeout(tgt), last)
}

var (
	runIDOnce sync.Once
	runID     string
)

// RunID is a short per-process id used as the cluster-name prefix so every
// object a run creates can be found and removed (spec §1.4).
func RunID() string {
	runIDOnce.Do(func() {
		if v := os.Getenv("REQ_RUN_ID"); v != "" {
			runID = v
			return
		}
		runID = fmt.Sprintf("t%x", time.Now().UnixNano()%0xffffff)
	})
	return runID
}

// Name returns a cluster id carrying the run prefix: "t<run>-<short>".
func Name(short string) string { return RunID() + "-" + short }
