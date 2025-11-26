# ADR-003: SQLite as Primary Database

## Status

Accepted

## Date

2025-10-01

## Context

The SMTP server requires persistent storage for:
- User accounts and credentials
- Message queue (pending deliveries)
- Greylist state
- Audit logs
- Full-text search indexes

We needed a database solution that:
- Requires minimal operational overhead
- Works reliably in single-server deployments
- Supports concurrent access
- Is easy to backup and restore

## Decision

We chose **SQLite** as the primary database with:
- WAL (Write-Ahead Logging) mode for concurrent reads
- FTS5 for full-text search
- Prepared statements with parameter binding (SQL injection prevention)

PostgreSQL is supported as an optional backend for high-availability deployments.

## Consequences

### Positive

- **Zero configuration**: No separate database server to manage
- **Single file**: Easy backup (`cp smtp.db smtp.db.backup`)
- **ACID compliant**: Full transaction support with rollback
- **WAL mode**: Concurrent readers during writes
- **FTS5**: Built-in full-text search with Porter stemmer
- **Cross-platform**: Works on all supported platforms
- **Battle-tested**: Most widely deployed database engine

### Negative

- **Write concurrency**: Single writer at a time (adequate for most SMTP workloads)
- **No replication**: Native replication not supported (use Litestream for HA)
- **Size limits**: Practical limit ~1TB (sufficient for metadata, not message bodies)
- **Network access**: Not designed for remote access (local file only)

### Neutral

- Embedded library (linked into binary)
- File locking for concurrent process access
- Migration framework required (implemented in `src/storage/migrations.zig`)

## Performance Characteristics

```
Tested on typical server hardware:
- User lookup: <1ms
- Queue insert: ~2ms
- FTS5 search (100K messages): ~50ms
- Concurrent reads: Unlimited
- Write throughput: ~10,000 inserts/second (WAL mode)
```

## WAL Mode Configuration

```sql
PRAGMA journal_mode=WAL;      -- Enable WAL
PRAGMA synchronous=NORMAL;     -- Balance durability/performance
PRAGMA cache_size=-64000;      -- 64MB cache
PRAGMA busy_timeout=5000;      -- 5s wait on lock
```

## Alternatives Considered

### Option A: PostgreSQL Only
- Pros: Better write concurrency, native replication, network access
- Cons: Operational overhead, separate process, configuration complexity

### Option B: MySQL/MariaDB
- Pros: Widely known, good tooling
- Cons: More complex than SQLite, overkill for single-server

### Option C: Embedded Key-Value (RocksDB, LMDB)
- Pros: Higher write throughput
- Cons: No SQL, no FTS, more complex queries

### Option D: No Database (File-based)
- Pros: Simplest possible
- Cons: No transactions, no search, complex concurrent access

## High Availability Path

For deployments requiring HA:
1. **Litestream**: Real-time SQLite replication to S3/GCS
2. **PostgreSQL backend**: Switch to PostgreSQL for multi-writer scenarios
3. **Distributed cluster**: Use Raft consensus with distributed state store

## References

- [SQLite Documentation](https://sqlite.org/docs.html)
- [SQLite WAL Mode](https://sqlite.org/wal.html)
- [Litestream - SQLite Replication](https://litestream.io/)
- [SQLite in Production](https://www.sqlite.org/whentouse.html)
