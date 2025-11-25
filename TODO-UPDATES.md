# TODO Updates - SMTP Server Improvements

**Generated:** 2025-11-24
**Current Version:** v0.28.0
**Zig Version:** 0.15.1

This document outlines remaining tasks, improvements, and fixes for the SMTP server project based on a thorough analysis of the codebase.

---

## 🔴 High Priority - Critical for Production

### 1. Complete Native TLS Handshake
**Status:** 98% complete - cipher issue remains
**Location:** `src/core/tls.zig`

The native STARTTLS implementation has a remaining cipher negotiation issue. While the reverse proxy workaround is documented, completing native TLS would eliminate external dependencies.

**Tasks:**
- [ ] Debug remaining TLS 1.3 cipher suite negotiation
- [ ] Add support for TLS 1.2 fallback for legacy clients
- [ ] Implement certificate chain validation
- [ ] Add OCSP stapling support
- [ ] Implement session resumption (TLS tickets)

### 2. Complete io_uring Integration (Linux)
**Status:** Framework exists, syscall integration incomplete
**Location:** `src/infrastructure/io_uring.zig`

**Tasks:**
- [ ] Complete io_uring syscall wrappers for Linux 5.1+
- [ ] Implement io_uring-based accept loop
- [ ] Add io_uring read/write operations
- [ ] Benchmark against epoll-based implementation
- [ ] Add graceful fallback for older kernels

### 3. Implement Raft Consensus for Cluster Mode
**Status:** Placeholder exists
**Location:** `src/infrastructure/cluster.zig`

The cluster mode has basic leader election but lacks proper distributed consensus.

**Tasks:**
- [ ] Implement Raft log replication
- [ ] Add term-based leader election
- [ ] Implement log compaction and snapshotting
- [ ] Add split-brain prevention
- [ ] Implement cluster membership changes (add/remove nodes)

---

## 🟡 Medium Priority - Important Improvements

### 4. Configuration File Support
**Status:** Only environment variables supported
**Location:** `src/core/config.zig`

**Tasks:**
- [ ] Add TOML configuration file parser
- [ ] Add YAML configuration file parser (optional)
- [ ] Implement config file discovery (`/etc/smtp-server/config.toml`, `~/.config/smtp-server/config.toml`)
- [ ] Add config file validation with helpful error messages
- [ ] Support config file includes for modular configuration

### 5. Hot Configuration Reload
**Status:** Not implemented
**Location:** `src/core/config.zig`, `src/main.zig`

**Tasks:**
- [ ] Implement SIGHUP handler for config reload
- [ ] Add atomic config swapping without connection drops
- [ ] Implement graceful TLS certificate rotation
- [ ] Add rate limit adjustment without restart
- [ ] Log configuration changes with diff

### 6. Secret Management Integration
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Add HashiCorp Vault integration for secrets
- [ ] Add Kubernetes Secrets support
- [ ] Add AWS Secrets Manager support
- [ ] Add Azure Key Vault support
- [ ] Implement secret rotation without restart

### 7. Distributed Tracing Exporters
**Status:** Console exporter only
**Location:** `src/observability/trace_exporters.zig`

**Tasks:**
- [ ] Implement Jaeger OTLP exporter
- [ ] Implement DataDog APM exporter
- [ ] Implement Zipkin exporter
- [ ] Add trace sampling configuration
- [ ] Implement trace context propagation to webhooks

### 8. Request-Level Tracing
**Status:** Not implemented
**Location:** `src/core/protocol.zig`

**Tasks:**
- [ ] Add trace spans to individual SMTP commands
- [ ] Track command latency per operation
- [ ] Add span attributes for message metadata
- [ ] Implement trace correlation across relay hops

### 9. Application Metrics Enhancement
**Status:** Basic metrics exist
**Location:** `src/api/health.zig`

**Tasks:**
- [ ] Add spam detection rate metrics
- [ ] Add virus detection rate metrics
- [ ] Add authentication categorization (success/failure by method)
- [ ] Add bounce rate tracking by domain
- [ ] Add queue depth histograms
- [ ] Add message size distribution metrics

### 10. Alerting Integration
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Add webhook alerts for critical events
- [ ] Implement PagerDuty integration
- [ ] Implement Slack/Discord notifications
- [ ] Add configurable alert thresholds
- [ ] Implement alert deduplication and rate limiting

---

## 🟢 Low Priority - Nice to Have

### 11. Complete IMAP Server Integration
**Status:** Framework exists, not integrated
**Location:** `src/protocol/imap.zig`

**Tasks:**
- [ ] Complete IMAP4rev1 command handlers
- [ ] Integrate with existing storage backends
- [ ] Implement IMAP IDLE for push notifications
- [ ] Add IMAP QUOTA support
- [ ] Implement IMAP SORT and THREAD extensions
- [ ] Add IMAP connection to main server startup

### 12. Complete POP3 Server Integration
**Status:** Framework exists, not integrated
**Location:** `src/protocol/pop3.zig`

**Tasks:**
- [ ] Complete POP3 command handlers
- [ ] Integrate with mailbox storage
- [ ] Add POP3 over TLS (POP3S)
- [ ] Implement UIDL for message tracking
- [ ] Add POP3 connection to main server startup

### 13. WebSocket Real-Time Notifications
**Status:** Framework exists, not integrated
**Location:** `src/protocol/websocket.zig`

**Tasks:**
- [ ] Complete WebSocket handshake implementation
- [ ] Add authentication for WebSocket connections
- [ ] Implement notification broadcasting
- [ ] Add per-user notification channels
- [ ] Integrate with message delivery events

### 14. CalDAV/CardDAV Support
**Status:** Framework exists
**Location:** `src/protocol/caldav.zig`

**Tasks:**
- [ ] Complete CalDAV PROPFIND/PROPPATCH handlers
- [ ] Implement calendar event storage
- [ ] Add CardDAV contact storage
- [ ] Implement sync tokens for efficient sync
- [ ] Add CalDAV/CardDAV to main server

### 15. ActiveSync Support
**Status:** Framework exists
**Location:** `src/protocol/activesync.zig`

**Tasks:**
- [ ] Complete ActiveSync provisioning
- [ ] Implement email sync commands
- [ ] Add calendar sync support
- [ ] Implement contact sync
- [ ] Add device management

### 16. Webmail Client
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Design responsive web UI
- [ ] Implement email composition with rich text
- [ ] Add folder management
- [ ] Implement search interface
- [ ] Add contact management
- [ ] Implement calendar view (if CalDAV enabled)

### 17. Mobile Admin App
**Status:** Not implemented
**Location:** New project

**Tasks:**
- [ ] Design mobile-first admin interface
- [ ] Implement server status monitoring
- [ ] Add user management
- [ ] Implement queue management
- [ ] Add push notifications for alerts

### 18. Plugin System Integration
**Status:** Framework exists, not integrated with main server
**Location:** `src/core/plugin.zig`

**Tasks:**
- [ ] Add plugin loading to server startup
- [ ] Implement plugin discovery from directory
- [ ] Add plugin configuration via config file
- [ ] Implement plugin hot-reload for development
- [ ] Create example plugins (spam filter, logging, custom auth)
- [ ] Add plugin marketplace/registry concept

### 19. Machine Learning Spam Detection
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Implement Bayesian classifier for spam
- [ ] Add neural network-based detection (optional)
- [ ] Implement training pipeline from user feedback
- [ ] Add model versioning and rollback
- [ ] Integrate with existing SpamAssassin scores

### 20. Email Archiving
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Implement journal-based archiving
- [ ] Add retention policy management
- [ ] Implement legal hold functionality
- [ ] Add archive search capabilities
- [ ] Implement archive export (PST, MBOX)

### 21. Migration Tools
**Status:** Not implemented
**Location:** New CLI tool needed

**Tasks:**
- [ ] Implement migration from Postfix
- [ ] Add migration from Sendmail
- [ ] Implement migration from Exchange (via IMAP)
- [ ] Add migration from Gmail (via API)
- [ ] Create migration validation and rollback

---

## 🔧 Code Quality & Technical Debt

### 22. Centralized Error Handling
**Status:** Partially implemented
**Location:** `src/core/errors.zig`, `src/core/error_context.zig`

**Tasks:**
- [ ] Create unified error handler utility
- [ ] Reduce error handling duplication across modules
- [ ] Add error categorization (recoverable vs fatal)
- [ ] Implement error aggregation for batch operations

### 23. Replace std.debug.print with Logger
**Status:** Mixed usage throughout codebase
**Location:** Multiple files

**Tasks:**
- [ ] Audit all `std.debug.print` usage
- [ ] Replace with appropriate logger calls
- [ ] Ensure consistent log levels
- [ ] Add structured context to all log messages

### 24. Deduplicate Module Imports
**Status:** Not implemented
**Location:** `src/root.zig`

**Tasks:**
- [ ] Create common import module
- [ ] Standardize import patterns across codebase
- [ ] Document module dependencies

### 25. Pre-sized Hash Maps
**Status:** Not implemented
**Location:** Various modules

**Tasks:**
- [ ] Audit HashMap usage for hot paths
- [ ] Add capacity hints for known sizes
- [ ] Implement capacity estimation for headers
- [ ] Benchmark impact of pre-sizing

### 26. Zero-Copy Optimizations
**Status:** Partially implemented
**Location:** `src/infrastructure/zerocopy.zig`

**Tasks:**
- [ ] Audit allocation in hot paths
- [ ] Implement zero-copy header parsing
- [ ] Add zero-copy MIME boundary detection
- [ ] Reduce string duplication in protocol handler

---

## 📚 Documentation Improvements

### 27. OpenAPI Specification
**Status:** File exists but may need updates
**Location:** `docs/openapi.yaml`

**Tasks:**
- [ ] Verify all endpoints are documented
- [ ] Add request/response examples
- [ ] Generate API client SDKs
- [ ] Add Swagger UI integration

### 28. Algorithm Documentation
**Status:** Not implemented
**Location:** Various modules

**Tasks:**
- [ ] Document SPF evaluation algorithm
- [ ] Document DKIM signature verification
- [ ] Document cluster consensus algorithm
- [ ] Document encryption key derivation
- [ ] Add inline algorithm complexity notes

### 29. Architecture Decision Records
**Status:** Not implemented
**Location:** `docs/ADR/` (new directory)

**Tasks:**
- [ ] Create ADR template
- [ ] Document Zig language choice
- [ ] Document storage backend decisions
- [ ] Document authentication mechanism choices
- [ ] Document cluster architecture decisions

---

## 🧪 Testing Improvements

### 30. Load Testing at Scale
**Status:** Basic load testing exists
**Location:** `tests/load_test.zig`

**Tasks:**
- [ ] Implement 10k+ concurrent connection tests
- [ ] Add sustained throughput testing
- [ ] Implement memory leak detection under load
- [ ] Add latency percentile tracking (p50, p95, p99)
- [ ] Create benchmark comparison reports

### 31. Coverage Measurement
**Status:** Framework exists
**Location:** `tests/coverage.zig`

**Tasks:**
- [ ] Integrate with CI/CD pipeline
- [ ] Set minimum coverage thresholds
- [ ] Add coverage badges to README
- [ ] Identify and fill coverage gaps

### 32. Chaos Engineering
**Status:** Not implemented
**Location:** New test module needed

**Tasks:**
- [ ] Implement network partition simulation
- [ ] Add random process killing
- [ ] Implement disk failure simulation
- [ ] Add memory pressure testing
- [ ] Create chaos test scenarios for cluster mode

### 33. Regression Test Index
**Status:** Not implemented
**Location:** `docs/` or `tests/`

**Tasks:**
- [ ] Document past vulnerabilities
- [ ] Link each vulnerability to test case
- [ ] Create automated regression suite
- [ ] Add CVE tracking (if applicable)

---

## 🏢 Enterprise Features

### 34. Comprehensive Audit Trail
**Status:** Basic audit logging exists
**Location:** `src/observability/audit.zig`

**Tasks:**
- [ ] Log all administrative actions
- [ ] Add user CRUD audit events
- [ ] Log configuration changes with before/after
- [ ] Add ACL modification logging
- [ ] Implement audit log export

### 35. Backup/Restore CLI Enhancement
**Status:** Basic backup exists
**Location:** `src/storage/backup.zig`

**Tasks:**
- [ ] Add interactive restore wizard
- [ ] Implement point-in-time recovery
- [ ] Add backup verification command
- [ ] Implement backup encryption key management
- [ ] Add backup scheduling via CLI

### 36. Multi-Region Support
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Design cross-region replication
- [ ] Implement async message replication
- [ ] Add region-aware routing
- [ ] Implement failover between regions
- [ ] Add latency-based routing

### 37. Service Dependency Graph
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Track service dependencies (DB, storage, cache)
- [ ] Implement graceful degradation
- [ ] Add dependency health visualization
- [ ] Implement circuit breaker per dependency

### 38. Enhanced Kubernetes Support
**Status:** Basic manifests exist
**Location:** `k8s/`

**Tasks:**
- [ ] Add comprehensive resource limit documentation
- [ ] Create network policy examples
- [ ] Add service mesh integration (Istio/Linkerd)
- [ ] Implement custom metrics for HPA
- [ ] Add Helm chart

### 39. Database Migration Tool
**Status:** Basic migrations exist
**Location:** `src/storage/migrations.zig`

**Tasks:**
- [ ] Add CLI for migration management
- [ ] Implement migration dry-run
- [ ] Add migration rollback confirmation
- [ ] Create migration status command
- [ ] Add migration locking for cluster

### 40. Secure Password Reset
**Status:** Not implemented
**Location:** New module needed

**Tasks:**
- [ ] Implement token-based reset flow
- [ ] Add token expiration (configurable)
- [ ] Implement rate limiting on reset requests
- [ ] Add email notification for reset
- [ ] Log all reset attempts

---

## 🐛 Known Issues & Fixes

### 41. README Roadmap Sync
**Status:** README roadmap is outdated
**Location:** `README.md` lines 394-408

**Fix:** The README roadmap shows items as incomplete that are actually implemented:
- [x] Database-backed authentication (implemented)
- [x] DKIM signing support (implemented)
- [x] SPF validation (implemented)
- [x] Greylisting (implemented)
- [x] Spam filtering integration (implemented)
- [x] Webhook notifications (implemented)
- [x] REST API (implemented)
- [x] Web-based admin interface (implemented)
- [x] IPv6 support (implemented)
- [x] SMTP relay (implemented)
- [x] Bounce handling (implemented)

**Task:** Update README.md roadmap section to reflect actual implementation status.

### 42. Version Consistency
**Status:** Version numbers inconsistent across files
**Locations:** `README.md`, `TODO.md`, `src/core/args.zig`

**Tasks:**
- [ ] Ensure version is consistent across all files
- [ ] Add version to build output
- [ ] Consider single source of truth for version

### 43. Multi-Tenancy Integration
**Status:** Framework exists but not integrated with main server
**Location:** `src/features/multitenancy.zig`

**Tasks:**
- [ ] Integrate tenant lookup into connection handling
- [ ] Add tenant-aware rate limiting
- [ ] Implement tenant-specific configuration
- [ ] Add tenant isolation to storage backends

### 44. Cluster Mode Integration
**Status:** Framework exists but not integrated with main server
**Location:** `src/infrastructure/cluster.zig`

**Tasks:**
- [ ] Add cluster initialization to main.zig
- [ ] Implement cluster-aware queue processing
- [ ] Add cluster status to health endpoint
- [ ] Implement cluster-wide rate limiting

---

## 📊 Priority Summary

| Priority | Count | Effort Estimate |
|----------|-------|-----------------|
| 🔴 High | 3 | ~40 hours |
| 🟡 Medium | 7 | ~60 hours |
| 🟢 Low | 11 | ~120 hours |
| 🔧 Code Quality | 5 | ~20 hours |
| 📚 Documentation | 3 | ~15 hours |
| 🧪 Testing | 4 | ~25 hours |
| 🏢 Enterprise | 7 | ~80 hours |
| 🐛 Fixes | 4 | ~8 hours |

**Total Estimated Effort:** ~370 hours

---

## Quick Wins (< 2 hours each)

1. **Update README roadmap** - Sync with actual implementation status
2. **Version consistency** - Single source of truth for version
3. **Add coverage badges** - CI integration for test coverage
4. **Pre-size header HashMap** - Performance improvement
5. **Replace remaining std.debug.print** - Logging consistency

---

## Next Steps Recommendation

1. **Immediate (This Sprint):**
   - Fix README roadmap (documentation accuracy)
   - Complete io_uring integration (performance)
   - Add distributed tracing exporters (observability)

2. **Short-term (Next 2-4 Sprints):**
   - Implement config file support
   - Add hot reload capability
   - Complete IMAP integration

3. **Medium-term (Next Quarter):**
   - Implement Raft consensus for cluster
   - Add WebSocket notifications
   - Create webmail client

4. **Long-term (Next 6 Months):**
   - Multi-region support
   - Machine learning spam detection
   - Mobile admin app

---

*This document should be reviewed and updated quarterly to reflect progress and changing priorities.*
