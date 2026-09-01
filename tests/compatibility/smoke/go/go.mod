// Standalone module for the VAL-01 Go smoke adapter, pinned to the
// go-sql-driver/mysql version declared in tests/compatibility/driver-matrix.v1.json.
module tiproxy-smoke-go

go 1.24.0

require github.com/go-sql-driver/mysql v1.10.0

require filippo.io/edwards25519 v1.2.0 // indirect
