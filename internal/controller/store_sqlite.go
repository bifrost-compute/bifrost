// SQLite-backed Store (ADR-0004: Postgres is truth in prod; SQLite serves
// single-node dev). Uses database/sql with modernc.org/sqlite — a pure-Go
// driver, so CGO_ENABLED=0 builds stay possible (predecessor ADR carried
// forward: sqlx/rusqlite required no such constraint, but Go's C-binding
// SQLite drivers (mattn/go-sqlite3) do, which this project avoids).
//
// Spec and enum-carrying columns are stored as JSON text so the schema
// stays portable to Postgres (Task 4 reuses the same shape); filter-facing
// columns (audit_events, usage_samples, local auth) are plain columns so
// SQL WHERE clauses do the filtering instead of an application-side scan.
//
// Ported from the predecessor's controller crate, src/store_sqlite.rs (retired Rust
// reference; cited here only for the file:line references that make
// porting traceable — never in user-facing strings).
package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/bifrost-compute/bifrost/internal/core"
)

// SqliteStore is a database/sql-backed Store using the pure-Go
// modernc.org/sqlite driver.
type SqliteStore struct {
	db *sql.DB

	// auditMu serializes RecordAudit's read-compute-insert sequence
	// (store_sqlite.rs:179-184, "audit_lock"): a new row's chain hash is
	// computed from the current newest row's, so two concurrent
	// RecordAudit calls must not interleave their SELECT and INSERT —
	// otherwise both could read the same "newest" hash and produce two
	// rows that both claim to chain from it, forking the chain instead of
	// extending it. Single-process SQLite; cross-process shared database
	// files were never a supported deployment (same rationale as the Rust
	// reference), so an in-process mutex is sufficient — no SQL-level
	// locking is needed for this path.
	auditMu sync.Mutex
}

var _ Store = (*SqliteStore)(nil)

// sqliteDSN builds a database/sql DSN for the modernc.org/sqlite driver at
// path, tuned to match store_sqlite.rs's concurrency posture:
//   - _txlock=immediate (store_sqlite.rs:405-412, "#42"): every
//     db.BeginTx opens with BEGIN IMMEDIATE instead of the default
//     DEFERRED, taking the write lock at transaction start. Two
//     concurrent read-modify-write transactions (UpsertDesired,
//     UpsertPool, BeginIntent) then serialize instead of both reading the
//     pre-bump generation/fingerprint under a lazily-upgraded DEFERRED
//     lock and colliding.
//   - _busy_timeout=5000 (store_sqlite.rs:227-229): a transaction that
//     loses the race waits up to 5s for the write lock instead of
//     surfacing SQLITE_BUSY to the caller.
//   - _journal_mode=WAL: concurrent readers don't block the single
//     writer (the Rust reference relies on sqlx's own pool semantics for
//     this; WAL is the direct SQLite equivalent).
func sqliteDSN(path string) string {
	return fmt.Sprintf("file:%s?_txlock=immediate&_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on&_pragma=temp_store(2)", path)
}

// NewSqliteStore opens (creating if absent) a SQLite-backed Store at path
// and applies the schema. Safe to call again on an existing database file
// — the schema is CREATE TABLE/INDEX IF NOT EXISTS — which is exactly
// what TestSqlitePersistsAcrossReopen in store_sqlite_test.go relies on to
// verify close+reopen durability.
func NewSqliteStore(ctx context.Context, path string) (*SqliteStore, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, storeErrorf("open sqlite database: %v", err)
	}
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		_ = db.Close()
		return nil, storeErrorf("apply sqlite schema: %v", err)
	}
	if err := applySqliteColumnMigrations(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SqliteStore{db: db}, nil
}

// applySqliteColumnMigrations runs every sqliteColumnMigrations entry
// whose column is missing (see store_sqlite_schema.go).
func applySqliteColumnMigrations(ctx context.Context, db *sql.DB) error {
	for _, m := range sqliteColumnMigrations {
		has, err := sqliteHasColumn(ctx, db, m.Table, m.Column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.ExecContext(ctx, m.Statement); err != nil {
			return storeErrorf("migrate %s.%s: %v", m.Table, m.Column, err)
		}
	}
	return nil
}

func sqliteHasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, storeErrorf("inspect %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid        int64
			name, typ  string
			notNull    int64
			defaultVal *string
			pk         int64
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			return false, storeErrorf("inspect %s: %v", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, storeErrorf("inspect %s: %v", table, err)
	}
	return false, nil
}

// Close releases the underlying database handle. Deliberately not part of
// the Store interface — Postgres's connection pool has no equivalent
// single-process-lifetime concept the interface should force on every
// backend. Callers that open a SqliteStore directly should defer Close.
func (s *SqliteStore) Close() error {
	return s.db.Close()
}

// jsonErr wraps a JSON (de)serialization failure, mirroring store.rs:28-30's
// `json_err` (`format!("serialization: {e}")`) so the wording — and the
// "serialization" substring the ported error-path tests check for — stays
// identical to the Rust reference.
func jsonErr(err error) error {
	return storeErrorf("serialization: %v", err)
}

// clampI64 saturates a uint64 into the range i64 can hold, mirroring every
// `.min(i64::MAX as u64) as i64` call site in store_sqlite.rs: SQLite (via
// database/sql's default parameter converter) rejects a uint64 whose value
// doesn't fit in an int64, and callers pass sentinels like ^uint64(0) — the
// conformance suite's "unbounded" upper bound — that must not error.
func clampI64(v uint64) int64 {
	if v > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(v)
}

// rowScanner is implemented by both *sql.Row and *sql.Rows, letting the
// row-mapping helpers below serve GetX (single row) and ListX (row
// iteration) call sites alike.
type rowScanner interface {
	Scan(dest ...any) error
}

// rowsIter is the row-iteration half of the SQL backends' result sets,
// implemented by both database/sql's *sql.Rows and pgx's Rows, letting
// listClusterRows serve SqliteStore and PostgresStore alike.
type rowsIter interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func intPtrToU64Ptr(p *int64) *uint64 {
	if p == nil {
		return nil
	}
	v := uint64(*p)
	return &v
}

func intPtrToU16Ptr(p *int64) *uint16 {
	if p == nil {
		return nil
	}
	v := uint16(*p)
	return &v
}

// --- Clusters ---

// rawCluster is one clusters row exactly as the driver returns it, before
// any JSON or enum decode. The split lets List tell a SQL-level scan
// failure (fatal) from row content the current binary can no longer decode
// (skippable).
type rawCluster struct {
	id                 string
	specJSON           string
	generation         int64
	desiredStr         string
	observedJSON       *string
	observedGeneration int64
	conditionJSON      *string
	failureCount       int64
	nextAttemptAt      int64
	createdAt          int64
	terminatedAt       *int64
}

func (r *rawCluster) scan(row rowScanner) error {
	return row.Scan(&r.id, &r.specJSON, &r.generation, &r.desiredStr, &r.observedJSON,
		&r.observedGeneration, &r.conditionJSON, &r.failureCount, &r.nextAttemptAt,
		&r.createdAt, &r.terminatedAt)
}

func (r *rawCluster) decode() (StoredCluster, error) {
	var spec core.ClusterSpec
	if err := json.Unmarshal([]byte(r.specJSON), &spec); err != nil {
		return StoredCluster{}, jsonErr(err)
	}
	desired, err := ParseDesiredState(r.desiredStr)
	if err != nil {
		return StoredCluster{}, err
	}
	var observedState *core.ClusterState
	if r.observedJSON != nil {
		var st core.ClusterState
		if err := json.Unmarshal([]byte(*r.observedJSON), &st); err != nil {
			return StoredCluster{}, jsonErr(err)
		}
		observedState = &st
	}
	var condition *core.DriftCondition
	if r.conditionJSON != nil {
		var dc core.DriftCondition
		if err := json.Unmarshal([]byte(*r.conditionJSON), &dc); err != nil {
			return StoredCluster{}, jsonErr(err)
		}
		condition = &dc
	}
	return StoredCluster{
		ID:                 core.ClusterId(r.id),
		Spec:               spec,
		Generation:         uint64(r.generation),
		Desired:            desired,
		ObservedState:      observedState,
		ObservedGeneration: uint64(r.observedGeneration),
		Condition:          condition,
		FailureCount:       uint32(r.failureCount),
		NextAttemptAt:      uint64(r.nextAttemptAt),
		CreatedAt:          uint64(r.createdAt),
		TerminatedAt:       intPtrToU64Ptr(r.terminatedAt),
	}, nil
}

func scanCluster(row rowScanner) (StoredCluster, error) {
	var r rawCluster
	if err := r.scan(row); err != nil {
		return StoredCluster{}, err
	}
	return r.decode()
}

// listClusterRows is both SQL backends' shared List body (part of the
// "same helper functions" set the Postgres port reuses). A SQL-level scan
// failure fails the List; a row whose JSON text the current binary can no
// longer decode (a spec written before an enum value was retired) is
// logged and SKIPPED so one poisoned row cannot stall listing, reconcile,
// metering and reap for every other cluster. Skipping is safe: no code
// path deletes K8s resources for clusters missing from List and
// reconcile/meter/reap iterate store rows only, so the skipped cluster is
// orphaned, never actuated against.
func listClusterRows(rows rowsIter) ([]StoredCluster, error) {
	out := make([]StoredCluster, 0)
	for rows.Next() {
		var r rawCluster
		if err := r.scan(rows); err != nil {
			return nil, err
		}
		c, err := r.decode()
		if err != nil {
			slog.Warn("skipping undecodable cluster row", "cluster", r.id, "error", err)
			continue
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list clusters: %v", err)
	}
	return out, nil
}

// tombstoneFromRow is both SQL backends' shared TombstoneByID body: a
// desired/observed_state read that never touches spec_json. The observed
// side fails closed — observed_state that will not decode reports
// not-gone rather than letting purge race a live cluster.
func tombstoneFromRow(row rowScanner, noRows error) (DesiredState, bool, bool, error) {
	var (
		desiredStr   string
		observedJSON *string
	)
	err := row.Scan(&desiredStr, &observedJSON)
	if errors.Is(err, noRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, storeErrorf("tombstone check: %v", err)
	}
	desired, err := ParseDesiredState(desiredStr)
	if err != nil {
		return "", false, false, err
	}
	var observed *core.ClusterState
	if observedJSON != nil {
		var st core.ClusterState
		if uerr := json.Unmarshal([]byte(*observedJSON), &st); uerr != nil {
			return desired, false, true, nil
		}
		observed = &st
	}
	return desired, ObservedGone(observed), true, nil
}

const clusterColumns = "id, spec_json, generation, desired, observed_state, " +
	"observed_generation, condition, failure_count, next_attempt_at, created_at, terminated_at"

// UpsertDesired mirrors store_sqlite.rs:404-465. BEGIN IMMEDIATE (via the
// _txlock=immediate DSN option) takes the write lock at transaction start,
// so two concurrent upserts serialize: the second blocks until the first
// commits, then reads the already-bumped generation, instead of both
// reading generation N under a lazily-upgraded lock and collapsing two
// spec changes into one bump.
func (s *SqliteStore) UpsertDesired(ctx context.Context, id core.ClusterId, spec core.ClusterSpec) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, storeErrorf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	var revive bool
	generation, err := func() (uint64, error) {
		var curJSON, curDesired string
		var curGen int64
		err := tx.QueryRowContext(ctx, "SELECT spec_json, generation, desired FROM clusters WHERE id = ?", string(id)).
			Scan(&curJSON, &curGen, &curDesired)
		switch {
		case err == nil:
			if curDesired == DesiredTerminated.AsStr() {
				// Store.UpsertDesired: a terminated record is re-created.
				revive = true
				return uint64(curGen) + 1, nil
			}
			var cur core.ClusterSpec
			if uerr := json.Unmarshal([]byte(curJSON), &cur); uerr != nil {
				return 0, jsonErr(uerr)
			}
			if specChanged(&cur, &spec) {
				return uint64(curGen) + 1, nil
			}
			return uint64(curGen), nil
		case errors.Is(err, sql.ErrNoRows):
			return 1, nil
		default:
			return 0, storeErrorf("read cluster: %v", err)
		}
	}()
	if err != nil {
		return 0, err
	}

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return 0, jsonErr(err)
	}
	// Keep desired/observed/condition/backoff/created_at on update (not in
	// the DO UPDATE SET list); default desired='running', observed_generation=0
	// on insert.
	if revive {
		_, err = tx.ExecContext(ctx, `
			UPDATE clusters SET spec_json = ?, generation = ?, desired = 'running',
				observed_state = NULL, observed_generation = 0, condition = NULL,
				failure_count = 0, next_attempt_at = 0, created_at = ?, terminated_at = NULL
			WHERE id = ?
		`, string(specJSON), int64(generation), int64(NowUnix()), string(id))
	} else {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO clusters (id, spec_json, generation, desired, observed_generation, created_at)
			VALUES (?, ?, ?, 'running', 0, ?)
			ON CONFLICT(id) DO UPDATE SET
				spec_json = excluded.spec_json,
				generation = excluded.generation
		`, string(id), string(specJSON), int64(generation), int64(NowUnix()))
	}
	if err != nil {
		return 0, storeErrorf("upsert cluster: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, storeErrorf("commit: %v", err)
	}
	return generation, nil
}

func (s *SqliteStore) Get(ctx context.Context, id core.ClusterId) (*StoredCluster, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+clusterColumns+" FROM clusters WHERE id = ?", string(id))
	c, err := scanCluster(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *SqliteStore) List(ctx context.Context) ([]StoredCluster, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+clusterColumns+" FROM clusters")
	if err != nil {
		return nil, storeErrorf("list clusters: %v", err)
	}
	defer func() { _ = rows.Close() }()
	return listClusterRows(rows)
}

func (s *SqliteStore) SetDesired(ctx context.Context, id core.ClusterId, desired DesiredState) error {
	if !desired.isValid() {
		return errBadDesiredState(string(desired))
	}
	isTerminated := desired == DesiredTerminated
	res, err := s.db.ExecContext(ctx,
		`UPDATE clusters SET desired = ?,
		 terminated_at = CASE WHEN ? THEN COALESCE(terminated_at, ?) ELSE NULL END
		 WHERE id = ?`,
		desired.AsStr(), isTerminated, int64(NowUnix()), string(id))
	if err != nil {
		return storeErrorf("set desired: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set desired: %v", err)
	}
	if n == 0 {
		return errNoSuchCluster(string(id))
	}
	return nil
}

func (s *SqliteStore) RemoveCluster(ctx context.Context, id core.ClusterId) (bool, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM clusters WHERE id = ?", string(id))
	if err != nil {
		return false, storeErrorf("remove cluster: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, storeErrorf("remove cluster: %v", err)
	}
	return n > 0, nil
}

func (s *SqliteStore) TombstoneByID(ctx context.Context, id core.ClusterId) (DesiredState, bool, bool, error) {
	row := s.db.QueryRowContext(ctx, "SELECT desired, observed_state FROM clusters WHERE id = ?", string(id))
	return tombstoneFromRow(row, sql.ErrNoRows)
}

func (s *SqliteStore) RecordObservation(ctx context.Context, id core.ClusterId, observed *core.ClusterState, observedGeneration uint64) error {
	var observedJSON *string
	if observed != nil {
		b, err := json.Marshal(*observed)
		if err != nil {
			return jsonErr(err)
		}
		str := string(b)
		observedJSON = &str
	}
	// MAX() keeps observed_generation monotonic (#41 stale-generation
	// fence): a restore reporting an older generation can't roll it back.
	_, err := s.db.ExecContext(ctx,
		"UPDATE clusters SET observed_state = ?, observed_generation = MAX(observed_generation, ?) WHERE id = ?",
		observedJSON, int64(observedGeneration), string(id))
	if err != nil {
		return storeErrorf("record observation: %v", err)
	}
	return nil
}

func (s *SqliteStore) SetCondition(ctx context.Context, id core.ClusterId, condition *core.DriftCondition) error {
	var conditionJSON *string
	if condition != nil {
		b, err := json.Marshal(*condition)
		if err != nil {
			return jsonErr(err)
		}
		str := string(b)
		conditionJSON = &str
	}
	_, err := s.db.ExecContext(ctx, "UPDATE clusters SET condition = ? WHERE id = ?", conditionJSON, string(id))
	if err != nil {
		return storeErrorf("set condition: %v", err)
	}
	return nil
}

func (s *SqliteStore) IsQuarantined(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM control WHERE key = 'quarantine'").Scan(&v)
	switch {
	case err == nil:
		return v == "true", nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, storeErrorf("read quarantine: %v", err)
	}
}

func (s *SqliteStore) SetQuarantine(ctx context.Context, quarantined bool) error {
	val := "false"
	if quarantined {
		val = "true"
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO control (key, value) VALUES ('quarantine', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		val)
	if err != nil {
		return storeErrorf("set quarantine: %v", err)
	}
	return nil
}

func (s *SqliteStore) RecordAttempt(ctx context.Context, id core.ClusterId, failureCount uint32, nextAttemptAt uint64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE clusters SET failure_count = ?, next_attempt_at = ? WHERE id = ?",
		int64(failureCount), int64(nextAttemptAt), string(id))
	if err != nil {
		return storeErrorf("record attempt: %v", err)
	}
	return nil
}

// --- Transactional outbox ---

func parseIntentStatus(s string) IntentStatus {
	if s == "pending" {
		return IntentStatusPending
	}
	return IntentStatusApplied
}

// BeginIntent mirrors store_sqlite.rs:628-676: opened under BEGIN
// IMMEDIATE so two reconcilers can't both treat the same key as fresh.
func (s *SqliteStore) BeginIntent(ctx context.Context, key, fingerprint string) (IntentOutcome, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IntentOutcome{}, storeErrorf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existingFP string
	err = tx.QueryRowContext(ctx, "SELECT params_fingerprint FROM intents WHERE intent_key = ?", key).Scan(&existingFP)
	var outcome IntentOutcome
	switch {
	case err == nil:
		if existingFP != fingerprint {
			outcome = IntentOutcome{Kind: IntentOutcomeParamMismatch}
		} else {
			outcome = IntentOutcome{Kind: IntentOutcomeProceed, Replay: true}
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO intents (intent_key, params_fingerprint, status, created_at) VALUES (?, ?, 'pending', ?)",
			key, fingerprint, int64(NowUnix())); err != nil {
			return IntentOutcome{}, storeErrorf("insert intent: %v", err)
		}
		outcome = IntentOutcome{Kind: IntentOutcomeProceed, Replay: false}
	default:
		return IntentOutcome{}, storeErrorf("read intent: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return IntentOutcome{}, storeErrorf("commit: %v", err)
	}
	return outcome, nil
}

func (s *SqliteStore) CompleteIntent(ctx context.Context, key, responseJSON string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE intents SET status = 'applied', response_json = ?, completed_at = ? WHERE intent_key = ?",
		responseJSON, int64(NowUnix()), key)
	if err != nil {
		return storeErrorf("complete intent: %v", err)
	}
	return nil
}

func (s *SqliteStore) GetIntent(ctx context.Context, key string) (*IntentRecord, error) {
	var (
		intentKey    string
		fingerprint  string
		statusStr    string
		responseJSON *string
		createdAt    int64
		completedAt  *int64
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT intent_key, params_fingerprint, status, response_json, created_at, completed_at FROM intents WHERE intent_key = ?",
		key).Scan(&intentKey, &fingerprint, &statusStr, &responseJSON, &createdAt, &completedAt)
	switch {
	case err == nil:
		return &IntentRecord{
			Key:               intentKey,
			ParamsFingerprint: fingerprint,
			Status:            parseIntentStatus(statusStr),
			ResponseJSON:      responseJSON,
			CreatedAt:         uint64(createdAt),
			CompletedAt:       intPtrToU64Ptr(completedAt),
		}, nil
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	default:
		return nil, storeErrorf("get intent: %v", err)
	}
}

func (s *SqliteStore) ReapIntents(ctx context.Context, appliedBefore uint64) (uint64, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM intents WHERE status = 'applied' AND completed_at IS NOT NULL AND completed_at < ?",
		clampI64(appliedBefore))
	if err != nil {
		return 0, storeErrorf("reap intents: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, storeErrorf("reap intents: %v", err)
	}
	return uint64(n), nil
}

// --- Jobs ---

func (s *SqliteStore) RecordJob(ctx context.Context, job core.JobRecord) error {
	var durationSecs *int64
	if job.DurationSecs != nil {
		v := int64(*job.DurationSecs)
		durationSecs = &v
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO jobs (id, cluster, submitter, status, duration_secs, submitted_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status = excluded.status, duration_secs = excluded.duration_secs
	`, job.Id, job.Cluster, job.Submitter, job.Status, durationSecs, int64(job.SubmittedAt))
	if err != nil {
		return storeErrorf("record job: %v", err)
	}
	return nil
}

func (s *SqliteStore) ListJobs(ctx context.Context) ([]core.JobRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, cluster, submitter, status, duration_secs, submitted_at FROM jobs ORDER BY submitted_at DESC")
	if err != nil {
		return nil, storeErrorf("list jobs: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]core.JobRecord, 0)
	for rows.Next() {
		var (
			id, cluster, submitter, status string
			durationSecs                   *int64
			submittedAt                    int64
		)
		if err := rows.Scan(&id, &cluster, &submitter, &status, &durationSecs, &submittedAt); err != nil {
			return nil, storeErrorf("list jobs: %v", err)
		}
		out = append(out, core.JobRecord{
			Id: id, Cluster: cluster, Submitter: submitter, Status: status,
			DurationSecs: intPtrToU64Ptr(durationSecs), SubmittedAt: uint64(submittedAt),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list jobs: %v", err)
	}
	return out, nil
}

// --- Pools ---

func scanPool(row rowScanner) (StoredPool, error) {
	var (
		name         string
		specJSON     string
		generation   int64
		observedJSON *string
		observedAt   *int64
		createdAt    int64
	)
	if err := row.Scan(&name, &specJSON, &generation, &observedJSON, &observedAt, &createdAt); err != nil {
		return StoredPool{}, err
	}
	var spec core.PoolSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return StoredPool{}, jsonErr(err)
	}
	return StoredPool{
		Name:         name,
		Spec:         spec,
		Generation:   uint64(generation),
		ObservedJSON: observedJSON,
		ObservedAt:   intPtrToU64Ptr(observedAt),
		CreatedAt:    uint64(createdAt),
	}, nil
}

const poolColumns = "name, spec_json, generation, observed_json, observed_at, created_at"

// UpsertPool mirrors UpsertDesired's BEGIN IMMEDIATE discipline
// (store_sqlite.rs:761-818): concurrent pool updates serialize.
func (s *SqliteStore) UpsertPool(ctx context.Context, name string, spec core.PoolSpec) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, storeErrorf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	generation, err := func() (uint64, error) {
		var curJSON string
		var curGen int64
		err := tx.QueryRowContext(ctx, "SELECT spec_json, generation FROM pools WHERE name = ?", name).
			Scan(&curJSON, &curGen)
		switch {
		case err == nil:
			var cur core.PoolSpec
			if uerr := json.Unmarshal([]byte(curJSON), &cur); uerr != nil {
				return 0, jsonErr(uerr)
			}
			if poolSpecChanged(&cur, &spec) {
				return uint64(curGen) + 1, nil
			}
			return uint64(curGen), nil
		case errors.Is(err, sql.ErrNoRows):
			return 1, nil
		default:
			return 0, storeErrorf("read pool: %v", err)
		}
	}()
	if err != nil {
		return 0, err
	}

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return 0, jsonErr(err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pools (name, spec_json, generation, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			spec_json = excluded.spec_json,
			generation = excluded.generation
	`, name, string(specJSON), int64(generation), int64(NowUnix()))
	if err != nil {
		return 0, storeErrorf("upsert pool: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, storeErrorf("commit: %v", err)
	}
	return generation, nil
}

func (s *SqliteStore) GetPool(ctx context.Context, name string) (*StoredPool, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM pools WHERE name = ?", name)
	p, err := scanPool(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *SqliteStore) ListPools(ctx context.Context) ([]StoredPool, error) {
	// ORDER BY name: ListPools must be deterministic across backends —
	// first-match consumers (GPU tenancy admission checks, queue
	// assignment) rely on seeing the same first pool on every call.
	rows, err := s.db.QueryContext(ctx, "SELECT "+poolColumns+" FROM pools ORDER BY name")
	if err != nil {
		return nil, storeErrorf("list pools: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]StoredPool, 0)
	for rows.Next() {
		p, err := scanPool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list pools: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) DeletePool(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM pools WHERE name = ?", name)
	if err != nil {
		return storeErrorf("delete pool: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("delete pool: %v", err)
	}
	if n == 0 {
		return errNoSuchPool(name)
	}
	return nil
}

func (s *SqliteStore) RecordPoolObservation(ctx context.Context, name, observedJSON string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE pools SET observed_json = ?, observed_at = ? WHERE name = ?",
		observedJSON, int64(NowUnix()), name)
	if err != nil {
		return storeErrorf("record pool observation: %v", err)
	}
	return nil
}

// --- Allocations ---

func (s *SqliteStore) UpsertAllocation(ctx context.Context, alloc core.AllocationSpec) error {
	specJSON, err := json.Marshal(alloc)
	if err != nil {
		return jsonErr(err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO allocations (pool, project, spec_json)
		VALUES (?, ?, ?)
		ON CONFLICT(pool, project) DO UPDATE SET spec_json = excluded.spec_json
	`, alloc.Pool, alloc.Project, string(specJSON))
	if err != nil {
		return storeErrorf("upsert allocation: %v", err)
	}
	return nil
}

func (s *SqliteStore) ListAllocations(ctx context.Context, pool string) ([]core.AllocationSpec, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT spec_json FROM allocations WHERE pool = ?", pool)
	if err != nil {
		return nil, storeErrorf("list allocations: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]core.AllocationSpec, 0)
	for rows.Next() {
		var specJSON string
		if err := rows.Scan(&specJSON); err != nil {
			return nil, storeErrorf("list allocations: %v", err)
		}
		var a core.AllocationSpec
		if err := json.Unmarshal([]byte(specJSON), &a); err != nil {
			return nil, jsonErr(err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list allocations: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) DeleteAllocation(ctx context.Context, pool, project string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM allocations WHERE pool = ? AND project = ?", pool, project)
	if err != nil {
		return storeErrorf("delete allocation: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("delete allocation: %v", err)
	}
	if n == 0 {
		return errNoSuchAllocation(pool, project)
	}
	return nil
}

// --- Usage samples ---

// RecordUsageSamples mirrors store_sqlite.rs:906-938: one transaction per
// batch so a tick's samples land atomically.
func (s *SqliteStore) RecordUsageSamples(ctx context.Context, samples []UsageSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storeErrorf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		"INSERT INTO usage_samples (ts, project, pool, resource, quantity, source, owner) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return storeErrorf("prepare usage insert: %v", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, smp := range samples {
		if _, err := stmt.ExecContext(ctx, clampI64(smp.Ts), smp.Project, smp.Pool, smp.Resource, smp.Quantity, smp.Source.AsStr(), smp.Owner); err != nil {
			return storeErrorf("insert usage sample: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return storeErrorf("commit: %v", err)
	}
	return nil
}

func (s *SqliteStore) UsageSamples(ctx context.Context, project, pool, owner *string, from, to uint64) ([]UsageSample, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ts, project, pool, resource, quantity, source, owner FROM usage_samples
		WHERE ts >= ? AND ts <= ?
		AND (? IS NULL OR project = ?)
		AND (? IS NULL OR pool = ?)
		AND (? IS NULL OR owner = ?)
		ORDER BY ts ASC
	`, clampI64(from), clampI64(to), project, project, pool, pool, owner, owner)
	if err != nil {
		return nil, storeErrorf("usage samples: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]UsageSample, 0)
	for rows.Next() {
		var (
			ts                                      int64
			projectVal, poolVal, resource, ownerVal string
			quantity                                float64
			sourceStr                               string
		)
		if err := rows.Scan(&ts, &projectVal, &poolVal, &resource, &quantity, &sourceStr, &ownerVal); err != nil {
			return nil, storeErrorf("usage samples: %v", err)
		}
		source, err := ParseUsageSource(sourceStr)
		if err != nil {
			return nil, err
		}
		out = append(out, UsageSample{
			Ts: uint64(ts), Project: projectVal, Pool: poolVal, Resource: resource,
			Quantity: quantity, Source: source, Owner: ownerVal,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("usage samples: %v", err)
	}
	return out, nil
}

// --- Governance policy ---

func (s *SqliteStore) GetPolicy(ctx context.Context) (*StoredPolicy, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM control WHERE key = 'policy'").Scan(&v)
	switch {
	case err == nil:
		var p StoredPolicy
		if uerr := json.Unmarshal([]byte(v), &p); uerr != nil {
			return nil, jsonErr(uerr)
		}
		return &p, nil
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	default:
		return nil, storeErrorf("get policy: %v", err)
	}
}

func (s *SqliteStore) SetPolicy(ctx context.Context, policy *StoredPolicy) error {
	b, err := json.Marshal(policy)
	if err != nil {
		return jsonErr(err)
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO control (key, value) VALUES ('policy', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		string(b))
	if err != nil {
		return storeErrorf("set policy: %v", err)
	}
	return nil
}

func (s *SqliteStore) SeedPolicy(ctx context.Context, policy *StoredPolicy) (bool, error) {
	b, err := json.Marshal(policy)
	if err != nil {
		return false, jsonErr(err)
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO control (key, value) VALUES ('policy', ?) ON CONFLICT(key) DO NOTHING",
		string(b))
	if err != nil {
		return false, storeErrorf("seed policy: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, storeErrorf("seed policy: %v", err)
	}
	return n > 0, nil
}

// --- Audit ---

const auditColumns = "seq, ts, subject, decision, reason, action, cluster, method, path, " +
	"status, latency_ms, required_json, granted_roles"

// scanAuditRow scans one audit_events row into (seq, event). When
// withChainHash is true, the caller's query must also select chain_hash as
// the row's final column; scanAuditRow then returns it as the third value
// (empty string when withChainHash is false).
func scanAuditRow(row rowScanner, withChainHash bool) (uint64, core.AuditEvent, string, error) {
	var (
		seq              int64
		ts               int64
		subject          *string
		decisionStr      string
		reason           *string
		action           *string
		cluster          *string
		method           *string
		path             *string
		status           *int64
		latencyMs        *int64
		requiredJSON     *string
		grantedRolesJSON string
		chainHash        string
	)
	dest := []any{&seq, &ts, &subject, &decisionStr, &reason, &action, &cluster,
		&method, &path, &status, &latencyMs, &requiredJSON, &grantedRolesJSON}
	if withChainHash {
		dest = append(dest, &chainHash)
	}
	if err := row.Scan(dest...); err != nil {
		return 0, core.AuditEvent{}, "", err
	}

	decision, ok := core.ParseAuditDecision(decisionStr)
	if !ok {
		return 0, core.AuditEvent{}, "", errBadAuditDecision()
	}
	var required *core.AuditRequired
	if requiredJSON != nil {
		var r core.AuditRequired
		if err := json.Unmarshal([]byte(*requiredJSON), &r); err != nil {
			return 0, core.AuditEvent{}, "", jsonErr(err)
		}
		required = &r
	}
	var grantedRoles []string
	if err := json.Unmarshal([]byte(grantedRolesJSON), &grantedRoles); err != nil {
		return 0, core.AuditEvent{}, "", jsonErr(err)
	}

	event := core.AuditEvent{
		Ts:           uint64(ts),
		Subject:      subject,
		Decision:     decision,
		Reason:       reason,
		Action:       action,
		Cluster:      cluster,
		Method:       method,
		Path:         path,
		Status:       intPtrToU16Ptr(status),
		LatencyMs:    intPtrToU64Ptr(latencyMs),
		Required:     required,
		GrantedRoles: grantedRoles,
	}
	return uint64(seq), event, chainHash, nil
}

// RecordAudit mirrors store_sqlite.rs:977-1017: the audit_lock mutex
// serializes the read-compute-insert sequence so a new row's chain hash
// always chains from the true newest row, then inserts and returns the
// autoincrement seq (== SQLite's rowid, since seq is INTEGER PRIMARY KEY).
func (s *SqliteStore) RecordAudit(ctx context.Context, event *core.AuditEvent) (uint64, error) {
	var requiredJSON *string
	if event.Required != nil {
		b, err := json.Marshal(*event.Required)
		if err != nil {
			return 0, jsonErr(err)
		}
		str := string(b)
		requiredJSON = &str
	}
	grantedRoles := event.GrantedRoles
	if grantedRoles == nil {
		grantedRoles = []string{}
	}
	grantedRolesJSON, err := json.Marshal(grantedRoles)
	if err != nil {
		return 0, jsonErr(err)
	}

	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	var prev string
	err = s.db.QueryRowContext(ctx, "SELECT chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1").Scan(&prev)
	switch {
	case err == nil:
		// prev already set.
	case errors.Is(err, sql.ErrNoRows):
		prev = AuditGenesisHash
	default:
		return 0, storeErrorf("read chain head: %v", err)
	}
	chainHash := AuditChainHash(prev, event)

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events
		(ts, subject, decision, reason, action, cluster, method, path,
		 status, latency_ms, required_json, granted_roles, chain_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, clampI64(event.Ts), event.Subject, event.Decision.AsStr(), event.Reason, event.Action,
		event.Cluster, event.Method, event.Path, event.Status, event.LatencyMs,
		requiredJSON, string(grantedRolesJSON), chainHash)
	if err != nil {
		return 0, storeErrorf("record audit: %v", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, storeErrorf("record audit: %v", err)
	}
	return uint64(seq), nil
}

func (s *SqliteStore) ListAudit(ctx context.Context, filter core.AuditFilter) ([]AuditRow, *uint64, error) {
	var b strings.Builder
	b.WriteString("SELECT " + auditColumns + " FROM audit_events WHERE 1=1")
	args := make([]any, 0, 8)

	if filter.Cursor != nil {
		b.WriteString(" AND seq < ?")
		args = append(args, clampI64(*filter.Cursor))
	}
	if filter.From != nil {
		b.WriteString(" AND ts >= ?")
		args = append(args, clampI64(*filter.From))
	}
	if filter.To != nil {
		b.WriteString(" AND ts <= ?")
		args = append(args, clampI64(*filter.To))
	}
	if filter.Subject != nil {
		b.WriteString(" AND subject = ?")
		args = append(args, *filter.Subject)
	}
	if filter.Cluster != nil {
		b.WriteString(" AND cluster = ?")
		args = append(args, *filter.Cluster)
	}
	if filter.Method != nil {
		b.WriteString(" AND method = ?")
		args = append(args, *filter.Method)
	}
	if filter.PathPrefix != nil {
		// substr(path, 1, length(?)) = ? instead of LIKE, so a prefix
		// containing % or _ can't go wildcard.
		b.WriteString(" AND substr(path, 1, length(?)) = ?")
		args = append(args, *filter.PathPrefix, *filter.PathPrefix)
	}
	if filter.MinStatus != nil {
		// NULL status rows are excluded: NULL >= n is never true in SQL.
		b.WriteString(" AND status >= ?")
		args = append(args, int64(*filter.MinStatus))
	}
	if filter.Decision != nil {
		b.WriteString(" AND decision = ?")
		args = append(args, filter.Decision.AsStr())
	}
	if filter.Reason != nil {
		b.WriteString(" AND reason = ?")
		args = append(args, *filter.Reason)
	}
	// One row beyond the page tells us whether a next page exists.
	limit := filter.EffectiveLimit()
	b.WriteString(" ORDER BY seq DESC LIMIT ?")
	args = append(args, int64(limit)+1)

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, nil, storeErrorf("list audit: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]AuditRow, 0)
	for rows.Next() {
		seq, event, _, err := scanAuditRow(rows, false)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, AuditRow{Seq: seq, Event: event})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, storeErrorf("list audit: %v", err)
	}

	var nextCursor *uint64
	if uint32(len(out)) > limit {
		out = out[:limit]
		seq := out[len(out)-1].Seq
		nextCursor = &seq
	}
	return out, nextCursor, nil
}

// AuditChain mirrors store_sqlite.rs:1089-1128.
func (s *SqliteStore) AuditChain(ctx context.Context, fromSeq *uint64, limit uint32) (AuditChainWindow, error) {
	head := AuditGenesisHash
	if fromSeq != nil && *fromSeq > 1 {
		var h string
		err := s.db.QueryRowContext(ctx,
			"SELECT chain_hash FROM audit_events WHERE seq < ? ORDER BY seq DESC LIMIT 1",
			clampI64(*fromSeq)).Scan(&h)
		switch {
		case err == nil:
			head = h
		case errors.Is(err, sql.ErrNoRows):
			// No preceding row: keep genesis.
		default:
			return AuditChainWindow{}, storeErrorf("read chain head: %v", err)
		}
	}

	var b strings.Builder
	b.WriteString("SELECT " + auditColumns + ", chain_hash FROM audit_events")
	args := make([]any, 0, 2)
	if fromSeq != nil {
		b.WriteString(" WHERE seq >= ?")
		args = append(args, clampI64(*fromSeq))
	}
	b.WriteString(" ORDER BY seq ASC LIMIT ?")
	args = append(args, int64(limit))

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return AuditChainWindow{}, storeErrorf("audit chain: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ChainedAuditRow, 0)
	for rows.Next() {
		seq, event, chainHash, err := scanAuditRow(rows, true)
		if err != nil {
			return AuditChainWindow{}, err
		}
		out = append(out, ChainedAuditRow{Seq: seq, Event: event, ChainHash: chainHash})
	}
	if err := rows.Err(); err != nil {
		return AuditChainWindow{}, storeErrorf("audit chain: %v", err)
	}
	return AuditChainWindow{Head: head, Rows: out}, nil
}

// --- Local auth: users ---

func scanLocalUser(row rowScanner) (core.LocalUserRecord, error) {
	var (
		username     string
		email        *string
		passwordHash string
		roleStr      string
		disabled     int64
		createdAt    int64
		failedLogins int64
		lockedUntil  *int64
	)
	if err := row.Scan(&username, &email, &passwordHash, &roleStr, &disabled,
		&createdAt, &failedLogins, &lockedUntil); err != nil {
		return core.LocalUserRecord{}, err
	}
	role, ok := core.ParseLocalRole(roleStr)
	if !ok {
		return core.LocalUserRecord{}, errBadLocalRole(roleStr)
	}
	return core.LocalUserRecord{
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		Disabled:     disabled != 0,
		CreatedAt:    uint64(createdAt),
		FailedLogins: uint32(failedLogins),
		LockedUntil:  intPtrToU64Ptr(lockedUntil),
	}, nil
}

const localUserColumns = "username, email, password_hash, role, disabled, created_at, failed_logins, locked_until"

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (s *SqliteStore) CreateLocalUser(ctx context.Context, username string, email *string, passwordHash string, role core.LocalRole) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO local_users (username, email, password_hash, role, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, username, email, passwordHash, role.AsStr(), int64(NowUnix()))
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return errLocalUserAlreadyExists(username)
	default:
		return storeErrorf("create local user: %v", err)
	}
}

func (s *SqliteStore) GetLocalUser(ctx context.Context, username string) (*core.LocalUserRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+localUserColumns+" FROM local_users WHERE username = ?", username)
	u, err := scanLocalUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *SqliteStore) ListLocalUsers(ctx context.Context) ([]core.LocalUserRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+localUserColumns+" FROM local_users ORDER BY username ASC")
	if err != nil {
		return nil, storeErrorf("list local users: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]core.LocalUserRecord, 0)
	for rows.Next() {
		u, err := scanLocalUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list local users: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) SetLocalUserPassword(ctx context.Context, username, passwordHash string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE local_users SET password_hash = ? WHERE username = ?", passwordHash, username)
	if err != nil {
		return storeErrorf("set local user password: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set local user password: %v", err)
	}
	if n == 0 {
		return errNoSuchLocalUser(username)
	}
	return nil
}

func (s *SqliteStore) SetLocalUserRole(ctx context.Context, username string, role core.LocalRole) error {
	res, err := s.db.ExecContext(ctx, "UPDATE local_users SET role = ? WHERE username = ?", role.AsStr(), username)
	if err != nil {
		return storeErrorf("set local user role: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set local user role: %v", err)
	}
	if n == 0 {
		return errNoSuchLocalUser(username)
	}
	return nil
}

func (s *SqliteStore) SetLocalUserDisabled(ctx context.Context, username string, disabled bool) error {
	var v int64
	if disabled {
		v = 1
	}
	res, err := s.db.ExecContext(ctx, "UPDATE local_users SET disabled = ? WHERE username = ?", v, username)
	if err != nil {
		return storeErrorf("set local user disabled: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set local user disabled: %v", err)
	}
	if n == 0 {
		return errNoSuchLocalUser(username)
	}
	return nil
}

func (s *SqliteStore) SetLoginLockout(ctx context.Context, username string, failedLogins uint32, lockedUntil *uint64) error {
	var lockedUntilArg *int64
	if lockedUntil != nil {
		v := clampI64(*lockedUntil)
		lockedUntilArg = &v
	}
	res, err := s.db.ExecContext(ctx,
		"UPDATE local_users SET failed_logins = ?, locked_until = ? WHERE username = ?",
		int64(failedLogins), lockedUntilArg, username)
	if err != nil {
		return storeErrorf("set login lockout: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set login lockout: %v", err)
	}
	if n == 0 {
		return errNoSuchLocalUser(username)
	}
	return nil
}

// RecordLoginFailure/RecordLoginSuccess implement the shared lockout state
// machine (NextLoginFailureState) against this store's own
// GetLocalUser/SetLoginLockout — same three-line body as MemoryStore's
// (the Go equivalent of the Rust trait's default method, which Go
// interfaces cannot express).
func (s *SqliteStore) RecordLoginFailure(ctx context.Context, username string) error {
	user, err := s.GetLocalUser(ctx, username)
	if err != nil {
		return err
	}
	if user == nil {
		return errNoSuchLocalUser(username)
	}
	failed, locked := NextLoginFailureState(user.FailedLogins, NowUnix())
	return s.SetLoginLockout(ctx, username, failed, locked)
}

func (s *SqliteStore) RecordLoginSuccess(ctx context.Context, username string) error {
	return s.SetLoginLockout(ctx, username, 0, nil)
}

// --- Local auth: API tokens ---

func scanApiToken(row rowScanner) (core.ApiTokenRecord, error) {
	var (
		prefix, tokenHash, username, label string
		createdAt, expiresAt               int64
		revoked                            int64
		lastUsedAt                         *int64
	)
	if err := row.Scan(&prefix, &tokenHash, &username, &label, &createdAt, &expiresAt, &revoked, &lastUsedAt); err != nil {
		return core.ApiTokenRecord{}, err
	}
	return core.ApiTokenRecord{
		Prefix:     prefix,
		TokenHash:  tokenHash,
		Username:   username,
		Label:      label,
		CreatedAt:  uint64(createdAt),
		ExpiresAt:  uint64(expiresAt),
		Revoked:    revoked != 0,
		LastUsedAt: intPtrToU64Ptr(lastUsedAt),
	}, nil
}

const apiTokenColumns = "prefix, token_hash, username, label, created_at, expires_at, revoked, last_used_at"

func (s *SqliteStore) CreateApiToken(ctx context.Context, record core.ApiTokenRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (prefix, token_hash, username, label, created_at, expires_at, revoked, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, record.Prefix, record.TokenHash, record.Username, record.Label,
		clampI64(record.CreatedAt), clampI64(record.ExpiresAt), record.Revoked, record.LastUsedAt)
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return errApiTokenAlreadyExists(record.Prefix)
	default:
		return storeErrorf("create api token: %v", err)
	}
}

func (s *SqliteStore) GetApiTokenByPrefix(ctx context.Context, prefix string) (*core.ApiTokenRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+apiTokenColumns+" FROM api_tokens WHERE prefix = ?", prefix)
	t, err := scanApiToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeErrorf("get api token: %v", err)
	}
	return &t, nil
}

func (s *SqliteStore) ListApiTokens(ctx context.Context, username string) ([]core.ApiTokenRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+apiTokenColumns+" FROM api_tokens WHERE username = ? ORDER BY created_at DESC", username)
	if err != nil {
		return nil, storeErrorf("list api tokens: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]core.ApiTokenRecord, 0)
	for rows.Next() {
		t, err := scanApiToken(rows)
		if err != nil {
			return nil, storeErrorf("list api tokens: %v", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list api tokens: %v", err)
	}
	return out, nil
}

// RevokeApiToken is owner-scoped: the UPDATE matches only rows the caller
// owns, so revoking someone else's token and revoking a nonexistent one
// are indistinguishable ("no such token") — no ownership probing.
func (s *SqliteStore) RevokeApiToken(ctx context.Context, prefix, username string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE api_tokens SET revoked = 1 WHERE prefix = ? AND username = ?", prefix, username)
	if err != nil {
		return storeErrorf("revoke api token: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("revoke api token: %v", err)
	}
	if n == 0 {
		return errNoSuchApiToken(prefix)
	}
	return nil
}

func (s *SqliteStore) TouchApiToken(ctx context.Context, prefix string, now uint64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at = ? WHERE prefix = ?", clampI64(now), prefix)
	if err != nil {
		return storeErrorf("touch api token: %v", err)
	}
	return nil
}

// --- Scoped role assignments ---

// UpsertRoleAssignment re-upsert preserves the original created_at (DO
// NOTHING on the triple's PK), matching MemoryStore.
func (s *SqliteStore) UpsertRoleAssignment(ctx context.Context, principal, role, scope string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO role_assignments (principal, role, scope, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(principal, role, scope) DO NOTHING
	`, principal, role, scope, int64(NowUnix()))
	if err != nil {
		return storeErrorf("upsert role assignment: %v", err)
	}
	return nil
}

func (s *SqliteStore) ListRoleAssignments(ctx context.Context, principal *string) ([]RoleAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT principal, role, scope, created_at FROM role_assignments
		WHERE (? IS NULL OR principal = ?)
		ORDER BY principal ASC, scope ASC, role ASC
	`, principal, principal)
	if err != nil {
		return nil, storeErrorf("list role assignments: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]RoleAssignment, 0)
	for rows.Next() {
		var a RoleAssignment
		var createdAt int64
		if err := rows.Scan(&a.Principal, &a.Role, &a.Scope, &createdAt); err != nil {
			return nil, storeErrorf("list role assignments: %v", err)
		}
		a.CreatedAt = uint64(createdAt)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list role assignments: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) DeleteRoleAssignment(ctx context.Context, principal, role, scope string) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM role_assignments WHERE principal = ? AND role = ? AND scope = ?", principal, role, scope)
	if err != nil {
		return storeErrorf("delete role assignment: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("delete role assignment: %v", err)
	}
	if n == 0 {
		return errNoSuchAssignment(principal, role, scope)
	}
	return nil
}

// --- Services ---

const serviceColumns = "name, spec_json, owner, generation, desired, observed_state, observed_url, created_at, terminated_at"

// scanService maps a services row (serviceColumns order) onto a
// StoredService; shared with PostgresStore like scanCluster.
func scanService(row rowScanner) (StoredService, error) {
	var (
		name, specJSON string
		owner          *string
		generation     int64
		desiredStr     string
		observedJSON   *string
		observedURL    *string
		createdAt      int64
		terminatedAt   *int64
	)
	if err := row.Scan(&name, &specJSON, &owner, &generation, &desiredStr, &observedJSON,
		&observedURL, &createdAt, &terminatedAt); err != nil {
		return StoredService{}, err
	}
	var spec core.ServiceSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return StoredService{}, jsonErr(err)
	}
	desired, err := ParseDesiredState(desiredStr)
	if err != nil {
		return StoredService{}, err
	}
	var observedState *core.ClusterState
	if observedJSON != nil {
		var st core.ClusterState
		if err := json.Unmarshal([]byte(*observedJSON), &st); err != nil {
			return StoredService{}, jsonErr(err)
		}
		observedState = &st
	}
	return StoredService{
		Name: name, Spec: spec, Owner: owner, Generation: uint64(generation), Desired: desired,
		ObservedState: observedState, ObservedURL: observedURL,
		CreatedAt: uint64(createdAt), TerminatedAt: intPtrToU64Ptr(terminatedAt),
	}, nil
}

// UpsertService follows UpsertDesired's transaction shape (BEGIN
// IMMEDIATE via the DSN) and its terminated-record-is-a-fresh-create rule.
func (s *SqliteStore) UpsertService(ctx context.Context, name string, spec core.ServiceSpec, owner *string) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, storeErrorf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	var revive bool
	generation, err := func() (uint64, error) {
		var curJSON, curDesired string
		var curGen int64
		err := tx.QueryRowContext(ctx, "SELECT spec_json, generation, desired FROM services WHERE name = ?", name).
			Scan(&curJSON, &curGen, &curDesired)
		switch {
		case err == nil:
			if curDesired == DesiredTerminated.AsStr() {
				revive = true
				return uint64(curGen) + 1, nil
			}
			var cur core.ServiceSpec
			if uerr := json.Unmarshal([]byte(curJSON), &cur); uerr != nil {
				return 0, jsonErr(uerr)
			}
			if serviceSpecChanged(&cur, &spec) {
				return uint64(curGen) + 1, nil
			}
			return uint64(curGen), nil
		case errors.Is(err, sql.ErrNoRows):
			return 1, nil
		default:
			return 0, storeErrorf("read service: %v", err)
		}
	}()
	if err != nil {
		return 0, err
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return 0, jsonErr(err)
	}
	if revive {
		_, err = tx.ExecContext(ctx, `
			UPDATE services SET spec_json = ?, owner = ?, generation = ?, desired = 'running',
				observed_state = NULL, observed_url = NULL, created_at = ?, terminated_at = NULL
			WHERE name = ?
		`, string(specJSON), owner, int64(generation), int64(NowUnix()), name)
	} else {
		// owner is stamped on insert only: a spec edit does not change who
		// owns the service.
		_, err = tx.ExecContext(ctx, `
			INSERT INTO services (name, spec_json, owner, generation, desired, created_at)
			VALUES (?, ?, ?, ?, 'running', ?)
			ON CONFLICT(name) DO UPDATE SET
				spec_json = excluded.spec_json,
				generation = excluded.generation
		`, name, string(specJSON), owner, int64(generation), int64(NowUnix()))
	}
	if err != nil {
		return 0, storeErrorf("upsert service: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, storeErrorf("commit: %v", err)
	}
	return generation, nil
}

func (s *SqliteStore) GetService(ctx context.Context, name string) (*StoredService, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+serviceColumns+" FROM services WHERE name = ?", name)
	c, err := scanService(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *SqliteStore) ListServices(ctx context.Context) ([]StoredService, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+serviceColumns+" FROM services ORDER BY name ASC")
	if err != nil {
		return nil, storeErrorf("list services: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]StoredService, 0)
	for rows.Next() {
		c, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list services: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) SetServiceDesired(ctx context.Context, name string, desired DesiredState) error {
	if !desired.isValid() {
		return errBadDesiredState(string(desired))
	}
	isTerminated := desired == DesiredTerminated
	res, err := s.db.ExecContext(ctx,
		`UPDATE services SET desired = ?,
		 terminated_at = CASE WHEN ? THEN COALESCE(terminated_at, ?) ELSE NULL END
		 WHERE name = ?`,
		desired.AsStr(), isTerminated, int64(NowUnix()), name)
	if err != nil {
		return storeErrorf("set service desired: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set service desired: %v", err)
	}
	if n == 0 {
		return errNoSuchService(name)
	}
	return nil
}

func (s *SqliteStore) RecordServiceObservation(ctx context.Context, name string, observed *core.ClusterState, url *string) error {
	observedJSON, err := marshalOptionalState(observed)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE services SET observed_state = ?, observed_url = ? WHERE name = ?",
		observedJSON, url, name); err != nil {
		return storeErrorf("record service observation: %v", err)
	}
	return nil
}

func (s *SqliteStore) RemoveService(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM services WHERE name = ?", name)
	if err != nil {
		return false, storeErrorf("remove service: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, storeErrorf("remove service: %v", err)
	}
	return n > 0, nil
}

// marshalOptionalState JSON-encodes an optional ClusterState for an
// observed_state column (nil stays SQL NULL).
func marshalOptionalState(observed *core.ClusterState) (*string, error) {
	if observed == nil {
		return nil, nil
	}
	b, err := json.Marshal(*observed)
	if err != nil {
		return nil, jsonErr(err)
	}
	str := string(b)
	return &str, nil
}

// --- Ephemeral Ray jobs ---

const rayJobColumns = "id, spec_json, owner, desired, status, deployment_status, cluster_name, dashboard_url, " +
	"message, submitted_at, started_at, finished_at, failure_count, next_attempt_at"

// scanRayJob maps a ray_jobs row (rayJobColumns order) onto a
// StoredRayJob; shared with PostgresStore.
func scanRayJob(row rowScanner) (StoredRayJob, error) {
	var (
		id, specJSON             string
		owner                    *string
		desiredStr               string
		status, deploymentStatus string
		clusterName, dashboard   *string
		message                  *string
		submittedAt              int64
		startedAt, finishedAt    *int64
		failureCount             int64
		nextAttemptAt            int64
	)
	if err := row.Scan(&id, &specJSON, &owner, &desiredStr, &status, &deploymentStatus, &clusterName, &dashboard,
		&message, &submittedAt, &startedAt, &finishedAt, &failureCount, &nextAttemptAt); err != nil {
		return StoredRayJob{}, err
	}
	var spec core.RayJobSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return StoredRayJob{}, jsonErr(err)
	}
	desired, err := ParseDesiredState(desiredStr)
	if err != nil {
		return StoredRayJob{}, err
	}
	return StoredRayJob{
		ID: core.ClusterId(id), Spec: spec, Owner: owner, Desired: desired,
		Status: status, DeploymentStatus: deploymentStatus,
		ClusterName: clusterName, DashboardURL: dashboard, Message: message,
		SubmittedAt: uint64(submittedAt), StartedAt: intPtrToU64Ptr(startedAt), FinishedAt: intPtrToU64Ptr(finishedAt),
		FailureCount: uint32(failureCount), NextAttemptAt: uint64(nextAttemptAt),
	}, nil
}

func (s *SqliteStore) UpsertRayJob(ctx context.Context, id core.ClusterId, spec core.RayJobSpec, owner *string) error {
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return jsonErr(err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ray_jobs (id, spec_json, owner, desired, submitted_at)
		VALUES (?, ?, ?, 'running', ?)
		ON CONFLICT(id) DO UPDATE SET
			spec_json = excluded.spec_json,
			owner = excluded.owner
	`, string(id), string(specJSON), owner, int64(NowUnix()))
	if err != nil {
		return storeErrorf("upsert job: %v", err)
	}
	return nil
}

func (s *SqliteStore) GetRayJob(ctx context.Context, id core.ClusterId) (*StoredRayJob, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+rayJobColumns+" FROM ray_jobs WHERE id = ?", string(id))
	j, err := scanRayJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *SqliteStore) ListRayJobs(ctx context.Context) ([]StoredRayJob, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+rayJobColumns+" FROM ray_jobs ORDER BY submitted_at DESC, id ASC")
	if err != nil {
		return nil, storeErrorf("list jobs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]StoredRayJob, 0)
	for rows.Next() {
		j, err := scanRayJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErrorf("list jobs: %v", err)
	}
	return out, nil
}

func (s *SqliteStore) SetRayJobDesired(ctx context.Context, id core.ClusterId, desired DesiredState) error {
	if !desired.isValid() {
		return errBadDesiredState(string(desired))
	}
	res, err := s.db.ExecContext(ctx, "UPDATE ray_jobs SET desired = ? WHERE id = ?", desired.AsStr(), string(id))
	if err != nil {
		return storeErrorf("set job desired: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeErrorf("set job desired: %v", err)
	}
	if n == 0 {
		return errNoSuchRayJob(string(id))
	}
	return nil
}

func (s *SqliteStore) RecordRayJobObservation(ctx context.Context, id core.ClusterId, obs RayJobObservation) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE ray_jobs SET status = ?, deployment_status = ?, cluster_name = ?, dashboard_url = ?,
			message = ?, started_at = ?, finished_at = ?
		WHERE id = ?
	`, obs.Status, obs.DeploymentStatus, obs.ClusterName, obs.DashboardURL, obs.Message,
		u64PtrToIntPtr(obs.StartedAt), u64PtrToIntPtr(obs.FinishedAt), string(id))
	if err != nil {
		return storeErrorf("record job observation: %v", err)
	}
	return nil
}

func (s *SqliteStore) RecordRayJobAttempt(ctx context.Context, id core.ClusterId, failureCount uint32, nextAttemptAt uint64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE ray_jobs SET failure_count = ?, next_attempt_at = ? WHERE id = ?",
		int64(failureCount), int64(nextAttemptAt), string(id))
	if err != nil {
		return storeErrorf("record job attempt: %v", err)
	}
	return nil
}

func (s *SqliteStore) RemoveRayJob(ctx context.Context, id core.ClusterId) (bool, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM ray_jobs WHERE id = ?", string(id))
	if err != nil {
		return false, storeErrorf("remove job: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, storeErrorf("remove job: %v", err)
	}
	return n > 0, nil
}

// u64PtrToIntPtr is intPtrToU64Ptr's inverse for nullable BIGINT/INTEGER
// binds (clamped like every other uint64 the SQL stores write).
func u64PtrToIntPtr(p *uint64) *int64 {
	if p == nil {
		return nil
	}
	v := clampI64(*p)
	return &v
}
