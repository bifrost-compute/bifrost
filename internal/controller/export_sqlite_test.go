package controller

import "context"

// SqliteDSNForTest exposes sqliteDSN to the external test package.
func SqliteDSNForTest(path string) string { return sqliteDSN(path) }

// TempStoreForTest reads `PRAGMA temp_store` back from a pooled
// connection, so a test can prove the DSN setting reached the connections
// database/sql actually hands out (a PRAGMA run once would not).
func (s *SqliteStore) TempStoreForTest(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&v)
	return v, err
}
