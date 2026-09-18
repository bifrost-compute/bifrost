# Usage reads fail with SQLITE_IOERR_SHORT_READ on a read-only root filesystem

**Found:** 2026-09-17 on grace. The control plane logged, every 30 seconds
for days:

```
api: store error error="store backend error: usage samples: disk I/O error (6410)"
```

`PRAGMA integrity_check` on a copy of the database answered `ok`, the
volume had 90 GB free, and every other table read and wrote normally. The
nightly in-cluster requirement runner's r14 (usage) failures on grace had
the same signature. 6410 is `SQLITE_IOERR_SHORT_READ`.

**The bug:** `UsageSamples` selects the whole window `ORDER BY ts`. Once
`usage_samples` passed a few tens of thousands of rows (grace: 31k, one
minute of metering per running cluster since the deployment), the sort
outgrew SQLite's page cache and spilled to the temp store. With the
default `temp_store=FILE` that is a file under `SQLITE_TMPDIR`/`TMPDIR`/
`/var/tmp`/`/tmp`. bifrost-pack runs the container with
`readOnlyRootFilesystem: true` and mounted nothing writable but `/data`,
so the temp file could not be created and the read failed. Nothing was
corrupt; the query simply could not scratch. Small deployments never see
it, which is why kind and the earlier grace deployment were green until the
table grew.

**Fix:** two independent halves.

1. bifrost: the SQLite DSN now carries `_pragma=temp_store(2)` (MEMORY), so
   sorts and aggregates never touch the filesystem outside the data
   directory. Applied through the DSN, not a one-off `PRAGMA`, because
   database/sql opens many connections and a statement on one would not
   reach the others. `TestSqliteUsageReadSurvivesAnUnwritableTempDir`
   reproduces the deployment (unwritable `SQLITE_TMPDIR`, 120k rows) and
   fails without the pragma.
2. bifrost-pack `59fde0c`: an emptyDir mounted at `/tmp`, so Go's
   `os.TempDir` and anything else that assumes a scratch directory has one.

**Still worth doing:** `UsageSamples` reads the entire window into memory
and the API aggregates it in Go; a `GROUP BY` in SQL, or retention on
`usage_samples`, would keep the table from growing without bound. README's
"Postgres for production" stands independently of this defect.
