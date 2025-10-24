# TODO List for SMTP Server

## Recent Updates 📝

### v0.22.0 (2025-10-24) - Per-User Rate Limiting & Enhanced Configuration
- ✅ **Per-User Rate Limiting**: Separate rate limits for authenticated users vs IP addresses
- ✅ **Configurable Cleanup Interval**: Customizable rate limiter cleanup scheduling
- ✅ **Enhanced Rate Limiter**: User counters, per-user methods, improved statistics
- ✅ **Environment Variable Support**: Complete configuration for all rate limiting features
- ✅ **Documentation Updates**: Comprehensive configuration and implementation guides
- ✅ **All Medium Priority Issues Resolved**: Zero outstanding medium-priority items

### v0.21.0 (2025-10-24) - Thread Safety, TLS Fix, Performance & Documentation
- ✅ **STARTTLS Memory Alignment Fix**: Fixed memory alignment bug in TLS handshake (CRITICAL FIX)
- ✅ **Native STARTTLS Working**: TLS 1.3 handshake now completes successfully
- ✅ **Atomic Statistics Counters**: Lock-free atomic operations for all server statistics
- ✅ **Database Thread Safety**: Added mutex protection to all Database methods (CRITICAL FIX)
- ✅ **SQLite WAL Mode**: Enabled Write-Ahead Logging for better concurrent read performance
- ✅ **Greylist Thread Safety**: Verified mutex protection (already thread-safe)
- ✅ **Complete Thread Safety Audit**: All shared resources verified and documented
- ✅ **DATA Command Timeout**: Configurable timeout enforcement for DATA phase
- ✅ **Timeout Granularity**: Separate timeouts for greeting, commands, and DATA phases
- ✅ **Environment Variable Configuration**: Complete configuration via environment variables
- ✅ **Timeout Logging**: Warning logs for timeout events with elapsed time tracking
- ✅ **Thread Safety Audit Document**: Comprehensive audit with recommendations and performance analysis
- ✅ **Configuration Documentation**: Complete configuration guide with profiles and examples
- ✅ **TLS Proxy Documentation**: Complete setup guide for nginx/HAProxy TLS termination
- ✅ **Zero Critical Issues**: All critical issues resolved!

### v0.20.0 (2025-01-24) - HTTPS Webhooks & Security Improvements
- ✅ **HTTPS Webhook Support**: TLS client for secure webhook notifications
- ✅ **Certificate Verification**: Optional certificate verification with insecure skip option
- ✅ **HTTP/HTTPS Auto-detection**: Automatic protocol selection based on URL scheme

### v0.19.0 (2025-01-24) - Message Search & Full-Text Search
- ✅ **FTS5 Search Engine**: SQLite FTS5 full-text search with Porter stemming and Unicode tokenization
- ✅ **Search CLI Tool**: Command-line interface for searching email messages
- ✅ **Search REST API**: HTTP endpoints for search, statistics, and index management
- ✅ **Advanced Filtering**: Search by sender, subject, date range, attachments, and folder
- ✅ **Search Documentation**: Comprehensive API and CLI documentation

### v0.18.0 (2025-10-24) - Bug Fixes & Issue Documentation
- ✅ **Rate Limiter Cleanup**: Automatic background cleanup with scheduled thread
- ✅ **Known Issues Documentation**: Comprehensive documentation of all known issues with solutions

### v0.17.0 (2025-10-24) - RFC & Legal Compliance
- ✅ **RFC 5321 Compliance Testing**: 30+ tests covering SMTP protocol
- ✅ **RFC 5322 Compliance Testing**: Message format validation
- ✅ **RFC 6409 Message Submission**: MSA with automatic header fixing
- ✅ **CAN-SPAM Compliance**: Validation, unsubscribe management, automatic compliance

### v0.16.0 (2025-10-24) - Complete Documentation Suite
- ✅ **Architecture Documentation**: Comprehensive system architecture with diagrams
- ✅ **Deployment Guides**: Complete deployment instructions for all platforms
- ✅ **Troubleshooting Guide**: Extensive troubleshooting for all common issues
- ✅ **Performance Tuning Guide**: Detailed performance optimization guide

### v0.15.0 (2025-10-23) - GDPR Compliance & Documentation
- ✅ **GDPR Data Export**: Complete user data export in JSON format (Article 15 & 20)
- ✅ **GDPR Data Deletion**: Permanent, secure data erasure (Article 17)
- ✅ **GDPR Audit Logging**: Processing activities record (Article 30)
- ✅ **GDPR CLI Tool**: Command-line tool for GDPR operations
- ✅ **API Documentation**: Comprehensive REST API, CLI, and protocol documentation

### v0.14.0 (2025-10-23) - Comprehensive Testing Suite
- ✅ **End-to-End Tests**: 11 complete workflow tests covering all SMTP operations
- ✅ **Fuzzing Tests**: 15 security-focused fuzzing tests for robustness
- ✅ **Test Infrastructure**: Separate test steps (unit, e2e, fuzz, all)
- ✅ **Security Testing**: Injection attacks, malicious inputs, edge cases

### v0.13.0 (2025-10-23) - Multi-Platform Support
- ✅ **Windows Support**: Full Windows compatibility with service management
- ✅ **BSD Support**: FreeBSD and OpenBSD support with rc.d integration
- ✅ **ARM Architecture**: Native ARM64 and ARM32 support
- ✅ **Unix Domain Sockets**: Stream and datagram sockets with abstract namespace
- ✅ **Cross-Platform Build System**: Build for all platforms from any platform
- ✅ **Platform Abstraction Layer**: Unified API across all platforms

### v0.12.0 (2025-10-23) - Enterprise Features & Automation
- ✅ **Encrypted Storage**: AES-256-GCM encryption at rest with key rotation
- ✅ **Backup/Restore**: Full and incremental backups with verification
- ✅ **Ansible Automation**: Complete deployment and configuration management
- ✅ **GDPR Compliance**: Data export, deletion, and audit logging (framework)
- ✅ **HA Cluster Mode**: Distributed deployment with load balancing (framework)

### v0.11.0 (2025-10-23) - Advanced Features & Infrastructure
- ✅ **Database Storage**: SQLite-based message storage with full-text search
- ✅ **Time-Series Storage**: Date-based filesystem storage (year/month/day hierarchy)
- ✅ **DELIVERBY Extension**: Time-constrained delivery (RFC 2852)
- ✅ **ATRN Support**: Authenticated TURN for dial-up connections (RFC 2645)
- ✅ **Kubernetes Manifests**: Production-ready K8s deployment
- ✅ **Async I/O Framework**: io_uring support for Linux (framework)

### v0.10.0 (2025-10-23) - Security & Protocol Extensions
- ✅ **ClamAV Integration**: Virus scanning for messages and attachments
- ✅ **SpamAssassin Integration**: Spam filtering with configurable policies
- ✅ **BINARYMIME Support**: Binary data transmission (RFC 3030)
- ✅ **ETRN Support**: Remote queue processing (RFC 1985)
- ✅ **Integration Tests**: Comprehensive end-to-end test framework

### v0.9.0 (2025-10-23) - Performance & Scalability
- ✅ **StatsD Support**: Real-time metrics reporting to StatsD servers
- ✅ **Memory Pools**: Fixed-size block allocation, buffer pools, arena allocators
- ✅ **Zero-Copy Buffers**: Ring buffers, buffer chains, scatter-gather I/O
- ✅ **PostgreSQL Support**: Production-grade database backend alternative
- ✅ **S3 Storage**: Scalable object storage for email messages

### v0.8.0 (2025-10-23) - Advanced Features & Optimizations
- ✅ **Quota Management**: Per-user storage limits with caching
- ✅ **Attachment Limits**: Per-user attachment size restrictions
- ✅ **SMTP PIPELINING**: Command batching optimization (RFC 2920)
- ✅ **DSN Extension**: Delivery Status Notifications (RFC 3461)
- ✅ **Mailing Lists**: Full mailing list management with RFC 2369 headers

### v0.7.0 (2025-10-23) - Enhanced Email Features
- ✅ **HTML Email**: Text/HTML conversion, sanitization, multipart alternative
- ✅ **Storage Formats**: Maildir + mbox (RFC 4155) support
- ✅ **CHUNKING Extension**: Binary message transmission (RFC 3030)
- ✅ **Auto-responder**: Vacation/OOO responses with rate limiting (RFC 3834)
- ✅ **Content Filtering**: Advanced rule-based message filtering engine

### v0.6.0 (2025-10-23) - Production-Ready Email Server
- ✅ **Spam Prevention**: DNSBL/RBL checking + greylisting (triplet-based)
- ✅ **Email Authentication**: SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489)
- ✅ **Protocol Extensions**: SIZE (RFC 1870), SMTPUTF8 (RFC 6531)
- ✅ **Email Parsing**: RFC 5322 headers, MIME multipart, attachments
- ✅ **Attachment Handling**: Base64/Quoted-printable decoding, file extraction
- ✅ **Message Delivery**: Queue system, SMTP relay, retry logic, bounce handling
- ✅ **Message Filtering**: Rule-based filtering with multiple conditions and actions
- ✅ **Monitoring**: Health checks, statistics API, Prometheus metrics
- ✅ **Administration**: REST API for management, CLI tools (user-cli)
- ✅ **Performance**: Benchmarking suite, load testing, connection pooling
- ✅ **DevOps**: Docker (multi-stage), Docker Compose, GitHub Actions CI/CD
- ✅ **Infrastructure**: Generic resource pool, exponential backoff retry
- ⚠️ CRAM-MD5/DIGEST-MD5 not implemented (incompatible with Argon2id)

### v0.5.0 (2025-10-23) - Database-backed Authentication
- ✅ Implemented SQLite database backend for user management
- ✅ Added Argon2id password hashing (more secure than bcrypt)
- ✅ Created user management CLI tool (user-cli) with 7 commands
- ✅ Updated SMTP AUTH PLAIN to verify credentials against database
- ✅ Proper error handling and security logging for auth failures
- ✅ Constant-time password comparison to prevent timing attacks
- ✅ Environment variable support for database path (SMTP_DB_PATH)
- ✅ Comprehensive testing of authentication flow

### v0.4.0 (2025-10-23) - TLS Library Refactoring
- ✅ Extracted TLS implementation to standalone zig-tls library
- ✅ Removed vendor/tls directory (clean dependency management)
- ✅ Updated build system to use external dependency
- ✅ Created comprehensive TLS documentation
- ✅ Implemented heap-allocated I/O buffers for session lifetime
- ✅ Fixed certificate loading with absolute path support
- ⚠️ TLS handshake has cipher issue (reverse proxy recommended for production)

### v0.3.0 - TLS Infrastructure
- Certificate management and validation
- STARTTLS protocol support
- ConnectionWrapper abstraction
- Production deployment via reverse proxy

### v0.2.0 - Security & Performance
- Connection timeout enforcement
- Per-IP rate limiting with sliding windows
- Maximum recipients per message
- Graceful shutdown with signal handlers

## Completed ✓

### Core Infrastructure (v0.1.0 - v0.3.0)
- [x] Set up Zig project structure with build.zig
- [x] Implement core SMTP protocol handler (RFC 5321)
- [x] Create TCP server with connection handling
- [x] Add basic TLS/SSL support framework (STARTTLS)
- [x] Implement authentication mechanisms (PLAIN, LOGIN)
- [x] Add email message parsing and validation
- [x] Create configuration system for server settings
- [x] Implement rate limiting and security features
- [x] Basic input sanitization
- [x] Email address validation
- [x] Maildir-style message storage
- [x] Create README with setup and usage instructions
- [x] Add comprehensive logging system
  - [x] Structured logging with log levels (DEBUG, INFO, WARN, ERROR, CRITICAL)
  - [x] File-based logging with timestamps
  - [x] Colored console output
  - [x] SMTP-specific logging methods
  - [x] Thread-safe logging with mutex
- [x] Add proper error handling throughout
  - [x] Custom SMTP error types
  - [x] Error information system with codes and messages
  - [x] Proper error propagation
- [x] Implement graceful shutdown
  - [x] Signal handlers for SIGINT and SIGTERM
  - [x] Wait for active connections to complete
  - [x] Atomic shutdown flag
  - [x] Connection tracking
- [x] Implement connection limits per IP
  - [x] Max connections enforcement
  - [x] Active connection counter
  - [x] Proper rejection with SMTP error
- [x] Add command-line argument parsing
  - [x] Help and version flags
  - [x] Config file path option
  - [x] Log level override
  - [x] Port and host override
  - [x] Max connections override
  - [x] TLS and auth toggles
- [x] Environment variable configuration support
  - [x] SMTP_HOST, SMTP_PORT
  - [x] SMTP_HOSTNAME
  - [x] SMTP_MAX_CONNECTIONS
  - [x] SMTP_MAX_MESSAGE_SIZE
  - [x] SMTP_MAX_RECIPIENTS
  - [x] SMTP_ENABLE_TLS, SMTP_ENABLE_AUTH
  - [x] SMTP_TLS_CERT, SMTP_TLS_KEY
- [x] Per-IP rate limiting with time windows
  - [x] Sliding window implementation
  - [x] Thread-safe with mutex
  - [x] Automatic cleanup of old entries
  - [x] Rate limit statistics
  - [x] Integration with DATA command
- [x] Maximum recipients per message limit
  - [x] Configurable limit
  - [x] Security event logging

### TLS Infrastructure (v0.4.0 - Latest)
- [x] Extract TLS to standalone zig-tls library
  - [x] Created ~/Code/zig-tls with 19 source files (388KB)
  - [x] Removed vendor/tls directory
  - [x] Updated build.zig to use dependency
  - [x] Clean package structure with build.zig.zon
  - [x] MIT License and documentation
- [x] TLS Certificate Management
  - [x] Certificate loading and validation
  - [x] PEM format support
  - [x] Absolute path handling
  - [x] CertKeyPair caching
  - [x] Proper cleanup in deinit
- [x] STARTTLS Protocol Implementation
  - [x] STARTTLS command handler
  - [x] State reset after TLS upgrade
  - [x] ConnectionWrapper abstraction
  - [x] Heap-allocated I/O buffers for session lifetime
  - [x] Session-scoped TLS resource management
- [x] TLS Documentation
  - [x] TLS.md (reverse proxy setup guide)
  - [x] TLS_STATUS.md (implementation status)
  - [x] IMPLEMENTATION_SUMMARY.md (complete technical summary)
  - [x] REFACTORING.md (library extraction documentation)

## In Progress 🚧

### Testing Suite
- [x] Create comprehensive test suite
  - [x] Zig unit tests for core modules
  - [x] Test script for SMTP commands (20 tests)
  - [x] Rate limiting tests
  - [x] Max recipients tests
  - [x] Connection limit tests
  - [x] Message size limit tests
  - [x] Email validation tests

### TLS Implementation
- [x] Debug TLS cipher/handshake errors (✅ FIXED in v0.21.0)
  - [x] Heap-allocated I/O buffers implemented
  - [x] Session-scoped resource management
  - [x] CertKeyPair loading from absolute paths
  - [x] Fixed memory alignment bug in TLS cleanup (v0.21.0)
  - [x] Native STARTTLS working with TLS 1.3 (v0.21.0)
  - [x] Tested with openssl s_client successfully (v0.21.0)

## High Priority 🔴

### Security & Authentication
- [x] TLS/STARTTLS Framework (v0.3.0+)
  - [x] Certificate loading and validation
  - [x] STARTTLS command handler
  - [x] TLS module with PEM validation
  - [x] Comprehensive reverse proxy documentation
  - [x] Heap-allocated I/O for session lifetime
  - [x] Standalone zig-tls library (v0.4.0)
  - [ ] Native TLS handshake completion (98% done, cipher issue)
  - [ ] Production deployment with reverse proxy (RECOMMENDED)
- [x] Database-backed authentication
  - [x] SQLite integration
  - [x] User management CLI tool (user-cli)
  - [x] PostgreSQL support
    - [x] Connection string parsing
    - [x] Database schema with indexes and triggers
    - [x] User CRUD operations interface
    - [x] Connection pooling
    - [x] Quota and attachment limit support
    - [x] Auto-updating timestamps
  - [ ] User management API (REST/GraphQL)
- [x] Implement password hashing with Argon2id
  - [x] Argon2id implementation (more secure than bcrypt)
  - [x] Base64 encoding for storage
  - [x] Constant-time comparison
  - [x] Integration with AUTH PLAIN
- [x] Add SASL authentication mechanisms
  - [x] CRAM-MD5 (Not implemented - incompatible with Argon2id hashing)
  - [x] DIGEST-MD5 (Not implemented - incompatible with Argon2id hashing)
  - Note: CRAM-MD5 and DIGEST-MD5 require plaintext password access for HMAC computation,
    which is incompatible with our Argon2id password hashing. Use PLAIN over TLS instead.
- [x] Add DNSBL/RBL checking for spam prevention
  - [x] DNSBL checker implementation with default blacklists
  - [x] IP reversal and DNS lookup
  - [x] Integration with SMTP connection handling
  - [x] Environment variable configuration (SMTP_ENABLE_DNSBL)
- [x] Implement greylisting
  - [x] Triplet-based greylisting (IP/sender/recipient)
  - [x] Configurable delay and retry windows
  - [x] Auto-whitelist after threshold
  - [x] Integration with RCPT TO command
  - [x] Environment variable configuration (SMTP_ENABLE_GREYLIST)

### Core Functionality
- [x] Environment variable configuration support
- [x] Per-IP rate limiting with time windows
- [x] Connection timeout enforcement
- [x] Maximum recipients per message limit

## Medium Priority 🟡

### Email Features
- [x] SPF validation for incoming mail (RFC 7208)
  - [x] SPF record parsing and evaluation
  - [x] IPv4/IPv6 CIDR matching
  - [x] Mechanism evaluation (ip4, ip6, a, mx, include, all)
  - [x] Result qualifiers (+, -, ~, ?)
  - [x] SPF record builder for publishing
- [x] DKIM signature validation (RFC 6376)
  - [x] DKIM-Signature header parsing
  - [x] Tag-value pair extraction
  - [x] Public key query framework (DNS TXT)
  - [x] Body hash verification framework
  - [x] RSA signature verification framework
  - [x] DKIM signer for outgoing mail
- [x] DMARC policy checking (RFC 7489)
  - [x] DMARC record parsing
  - [x] Policy evaluation (none, quarantine, reject)
  - [x] SPF/DKIM identifier alignment (strict/relaxed)
  - [x] Aggregate report generation (XML)
  - [x] Organizational domain extraction
- [x] Email header parsing and validation
  - [x] RFC 5322 header parsing
  - [x] Continuation line support
  - [x] Case-insensitive header lookup
  - [x] Email address extraction
  - [x] Required header validation (From, Date)
- [x] MIME multipart message support
  - [x] ContentType parser with boundary/charset support
  - [x] Multipart message parsing
  - [x] MIME part extraction with headers
  - [x] Comprehensive test coverage
- [x] HTML email support
  - [x] Text to HTML conversion
  - [x] HTML to plain text stripping
  - [x] HTML sanitization (remove dangerous tags)
  - [x] Multipart alternative creation (plain + HTML)
  - [x] HTML entity encoding/decoding
  - [x] HTML structure validation
- [x] Attachment handling
  - [x] Attachment extraction from MIME parts
  - [x] Base64 decoding
  - [x] Quoted-printable decoding
  - [x] Filename and content-type extraction
  - [x] Save to file functionality
  - [x] Multiple encoding support (7bit, 8bit, binary)
- [x] Implement SIZE extension properly
  - [x] SIZE parameter parsing in MAIL FROM
  - [x] Size validation against max_message_size
  - [x] Dynamic SIZE advertisement in EHLO
  - [x] RFC 1870 compliance
- [x] Implement CHUNKING extension (RFC 3030)
  - [x] BDAT command support
  - [x] Chunk accumulation and validation
  - [x] Binary message transmission
  - [x] Session state management for chunked data
  - [x] CHUNKING advertisement in EHLO
  - [x] Integration with protocol handler
- [x] Add SMTPUTF8 support (RFC 6531)
  - [x] SMTPUTF8 extension advertisement in EHLO
  - [x] UTF-8 email address validation
  - [x] Internationalized domain name support
  - [x] UTF-8 local part validation
  - [x] Detection of UTF-8 requirement

### Storage & Delivery
- [x] Pluggable storage backends
  - [x] Maildir (current)
  - [x] mbox format (RFC 4155)
    - [x] Message appending with "From " separators
    - [x] Message reading and parsing
    - [x] Message deletion with file rewrite
    - [x] "From " line escaping/unescaping
    - [x] Thread-safe operations
  - [x] Database storage
    - [x] SQLite message storage schema
    - [x] Store/retrieve/delete operations
    - [x] Message listing with pagination
    - [x] Folder management
    - [x] IMAP-style message flags
    - [x] Full-text search
    - [x] Message count queries
    - [x] Thread-safe operations
  - [x] Time-series filesystem storage
    - [x] Date-based directory hierarchy (year/month/day)
    - [x] One file per email (.eml format)
    - [x] Store/retrieve/delete operations
    - [x] List messages by day or date range
    - [x] Find message by ID (search recent days)
    - [x] Archive old messages
    - [x] Filename sanitization
    - [x] Optional gzip compression
    - [x] Storage statistics
    - [x] Easy backup and archival
    - [x] Grep-friendly plain text
    - [x] Encryption-ready structure
  - [x] S3/object storage
    - [x] S3 key generation with date partitioning
    - [x] Store/retrieve/delete message operations
    - [x] List messages with prefix filtering
    - [x] Presigned URL generation
    - [x] Multipart upload support for large messages
    - [x] Lifecycle policy XML generation
    - [x] Object metadata retrieval
    - [x] Message copy operations
- [x] Message queue for outbound delivery
  - [x] Queue management with status tracking
  - [x] Priority and scheduling support
  - [x] Queue statistics and monitoring
- [x] SMTP relay support (forward to other servers)
  - [x] SMTP relay client implementation
  - [x] Connection pooling support
  - [x] Relay worker for queue processing
- [x] Retry logic for failed deliveries
  - [x] Exponential backoff strategy
  - [x] Configurable max retry attempts
  - [x] Automatic retry scheduling
- [x] Bounce message handling
  - [x] RFC 3464 compliant DSN generation
  - [x] Machine-readable delivery status
  - [x] Original message inclusion
  - [x] Multiple bounce reason types
- [ ] Delivery status notifications (DSN) - full implementation

### Performance
- [x] Connection pooling
  - [x] SMTP relay connection pool
  - [x] Idle timeout management
  - [x] Automatic cleanup of stale connections
  - [x] Pool statistics and monitoring
  - [x] Generic resource pool implementation
- [x] Memory pool for allocations
  - [x] Generic memory pool for fixed-size blocks
  - [x] Buffer pools for common sizes (1KB, 8KB, 64KB)
  - [x] Arena allocator pool with reset capability
  - [x] Pool statistics and monitoring
  - [x] Automatic growth on exhaustion
  - [x] Thread-safe operations
- [x] Zero-copy buffer management
  - [x] Zero-copy buffer with slice-based access
  - [x] Ring buffer for continuous operations
  - [x] Buffer chain for scatter-gather I/O
  - [x] Peek and consume operations
  - [x] Delimiter-based parsing (consumeUntil)
  - [x] Buffer compaction
- [x] Async I/O with io_uring (Linux)
  - [x] io_uring framework implementation
  - [x] Async accept/read/write/recv/send operations
  - [x] Completion queue handling
  - [x] Async SMTP connection handler
  - [x] Error mapping and handling
  - [x] Connection state management
  - [ ] Full io_uring syscall integration (requires Linux 5.1+)
- [x] Performance benchmarking suite
  - [x] Benchmark framework with warmup
  - [x] SMTP-specific benchmarks (email validation, base64, parsing)
  - [x] Statistical analysis (min/max/avg, ops/sec)
  - [x] Result reporting
- [x] Load testing tools
  - [x] Concurrent connection simulation
  - [x] Configurable message volume
  - [x] Throughput measurement
  - [x] Error tracking and reporting
- [x] Metrics collection (Prometheus format)

### Monitoring & Observability
- [x] Health check endpoint
  - [x] HTTP health server on dedicated port
  - [x] JSON status responses
  - [x] Health status levels (healthy/degraded/unhealthy)
  - [x] Uptime and connection metrics
- [x] Statistics API
  - [x] Messages received/sent
  - [x] Connection counts (total/active)
  - [x] Authentication successes/failures
  - [x] Rate limit hits
  - [x] DNSBL/greylist block counts
  - [x] JSON API endpoint (/stats)
- [x] Integration with monitoring systems
  - [x] Prometheus exporter (/metrics endpoint)
  - [x] Prometheus text format support
  - [x] Counter and gauge metrics
  - [x] StatsD support
    - [x] UDP-based metrics reporting
    - [x] Counter, gauge, timing, histogram, set metrics
    - [x] Sample rate support
    - [x] Batch sending
    - [x] Metric prefix configuration
    - [x] SMTP-specific metric helpers
    - [x] Enable/disable toggle
  - [ ] OpenTelemetry traces

## Low Priority 🟢

### Administration
- [ ] Web-based admin interface
  - [ ] Server status dashboard
  - [ ] User management
  - [ ] Configuration editor
  - [ ] Log viewer
- [x] REST API for management
  - [x] HTTP REST API server
  - [x] User management endpoints (GET/POST/DELETE)
  - [x] Queue status and inspection
  - [x] Filter rule management
  - [x] JSON response format
- [x] CLI administration tool
  - [x] User management (user-cli with 7 commands)
  - [x] Server control
  - [x] Queue inspection capabilities

### Advanced Features
- [x] Webhook notifications for incoming mail (HTTP POST with JSON payload)
- [x] Message filtering/routing rules
  - [x] Filter condition types (from, to, subject, header, body, size, attachments)
  - [x] Filter actions (accept, reject, forward, discard, tag)
  - [x] Multiple condition matching (AND logic)
  - [x] Case-sensitive/insensitive matching
  - [x] Priority-based rule processing
  - [x] Rule enable/disable functionality
- [x] Auto-responder support
  - [x] Rule-based auto-response configuration
  - [x] Vacation/out-of-office responses
  - [x] Date range support
  - [x] Response rate limiting (prevent loops)
  - [x] Auto-response tracking per sender
  - [x] RFC 3834 compliance (Auto-Submitted header)
  - [x] Skip automated senders (noreply@, mailer-daemon@, etc.)
- [x] Mailing list functionality
  - [x] Mailing list creation and management
  - [x] Subscriber management (subscribe/unsubscribe)
  - [x] Post policy enforcement (anyone, subscribers-only, moderated)
  - [x] RFC 2369 list headers (List-Id, List-Post, List-Help, etc.)
  - [x] Subject prefix support
  - [x] Subscriber status management (enable/disable)
  - [x] Digest mode support
  - [x] List settings configuration
  - [x] Thread-safe operations
  - [x] Mailing list manager for multiple lists
- [x] Virus scanning integration (ClamAV)
  - [x] ClamAV daemon (clamd) integration
  - [x] INSTREAM protocol for message scanning
  - [x] File scanning support
  - [x] Virus database reloading
  - [x] Scan result tracking and statistics
  - [x] Virus action policies (reject, quarantine, tag, discard)
  - [x] Scan policy configuration
  - [x] Comprehensive test coverage
- [x] Spam filter integration (SpamAssassin)
  - [x] SpamAssassin daemon (spamd) integration
  - [x] SYMBOLS protocol for detailed spam analysis
  - [x] CHECK protocol for quick spam/ham detection
  - [x] Bayes filter training (TELL protocol)
  - [x] Spam scoring and threshold configuration
  - [x] Spam action policies (reject, quarantine, tag, discard, rewrite_subject)
  - [x] Policy presets (strict, standard, permissive)
  - [x] Auto-learning support
  - [x] Comprehensive test coverage
- [x] Content filtering
  - [x] Filter engine with rule-based message processing
  - [x] Multiple condition types (from, to, subject, header, body, size, attachments)
  - [x] Filter actions (accept, reject, forward, discard, tag)
  - [x] Priority-based rule evaluation
  - [x] Thread-safe rule management
- [x] Attachment size limits per user
  - [x] Per-user attachment size configuration
  - [x] Per-attachment and total size limits
  - [x] Validation before message processing
  - [x] Preset limit configurations (restricted, standard, generous)
  - [x] Database integration
- [x] Quota management
  - [x] Per-user storage quota limits
  - [x] Real-time quota checking
  - [x] Usage tracking and reporting
  - [x] Quota presets (100MB, 1GB, 5GB, 50GB, unlimited)
  - [x] Cache system for performance
  - [x] Over-quota detection and reporting
  - [x] Database schema migration

### Protocol Extensions
- [x] SMTP PIPELINING optimization (RFC 2920)
  - [x] Command batching and parsing
  - [x] Pipelinable command validation
  - [x] Command sequence validation
  - [x] Batch response generation
  - [x] Pipeline statistics tracking
  - [x] Maximum pipeline depth enforcement
- [x] BINARYMIME support (RFC 3030)
  - [x] BODY parameter parsing (7BIT, 8BITMIME, BINARYMIME)
  - [x] Message validation for each BODY type
  - [x] Binary data transmission (requires CHUNKING)
  - [x] Content-Transfer-Encoding detection
  - [x] Binary MIME part handling
  - [x] 8BITMIME and BINARYMIME capability advertisement
  - [x] Comprehensive test coverage
- [x] DELIVERBY extension (RFC 2852)
  - [x] BY parameter parsing from MAIL FROM
  - [x] Deadline validation and calculation
  - [x] Notify mode support (R/N/T)
  - [x] Timed message queue with priority
  - [x] Deadline notification generation
  - [x] Time remaining calculation
  - [x] DELIVERBY capability advertisement
- [x] DSN extension (RFC 3461)
  - [x] MAIL FROM RET parameter (FULL/HDRS)
  - [x] MAIL FROM ENVID parameter
  - [x] RCPT TO NOTIFY parameter (NEVER/SUCCESS/FAILURE/DELAY)
  - [x] RCPT TO ORCPT parameter
  - [x] Success notification generation
  - [x] Failure notification generation
  - [x] Delay notification generation
  - [x] RFC 3464 compliant DSN format
- [x] ETRN support (RFC 1985)
  - [x] ETRN command parsing (domain, @node, #queue)
  - [x] Queue processing trigger
  - [x] Domain allowlist management
  - [x] Response code handling (250, 251, 252, 253, 458, 459)
  - [x] Queue message counting
  - [x] Queue processor implementation
  - [x] ETRN statistics tracking
  - [x] Comprehensive test coverage
- [x] ATRN support (RFC 2645)
  - [x] ATRN command parsing (single and multiple domains)
  - [x] Domain authorization management
  - [x] Authentication requirement enforcement
  - [x] Role reversal protocol handling
  - [x] Queue delivery statistics
  - [x] Response code handling (250, 450, 453, 530)
  - [x] Session state management
  - [x] Comprehensive test coverage

### Developer Experience
- [x] Comprehensive test suite
  - [x] Unit tests for all modules (embedded in each .zig file)
  - [x] Test coverage for core functionality
  - [x] Integration tests
    - [x] SMTP server connection testing
    - [x] Authentication flow testing
    - [x] Message delivery testing
    - [x] Extension testing (PIPELINING, SIZE, CHUNKING, STARTTLS)
    - [x] Concurrent connection testing
    - [x] Error handling testing
    - [x] Quota and rate limiting testing
    - [x] Virus and spam scanning integration testing
    - [x] Storage backend testing (Maildir, mbox, PostgreSQL, S3)
    - [x] Test helper functions for client simulation
  - [x] End-to-end tests
    - [x] Basic SMTP conversation (greeting, EHLO, QUIT)
    - [x] Send email without authentication
    - [x] Send email with authentication
    - [x] PIPELINING support testing
    - [x] SIZE extension testing
    - [x] Error handling for invalid commands
    - [x] Multiple recipients handling
    - [x] RSET command
    - [x] VRFY command
    - [x] NOOP command
    - [x] Case insensitivity testing
  - [x] Fuzzing tests
    - [x] Random SMTP commands (100 iterations)
    - [x] Random email addresses
    - [x] Oversized inputs (1KB - 1MB)
    - [x] Invalid UTF-8 sequences
    - [x] CRLF injection attempts
    - [x] Header injection attempts
    - [x] Malformed MIME boundaries
    - [x] Base64 decoding edge cases
    - [x] Quoted-printable edge cases
    - [x] Long lines without CRLF
    - [x] Command parameter edge cases
    - [x] NULL bytes in input
    - [x] Extremely nested MIME parts (2-20 levels)
    - [x] Random unicode in headers
    - [x] Malicious attachment filenames
- [x] CI/CD pipeline
  - [x] GitHub Actions workflow for CI
  - [x] Automated testing on push/PR
  - [x] Multi-OS testing (Ubuntu, macOS)
  - [x] Release automation workflow
  - [x] Docker image build and push
  - [x] Format checking
- [x] Docker container
  - [x] Multi-stage build (builder + runtime)
  - [x] Alpine-based image (minimal size)
  - [x] Docker Compose setup with multiple services
  - [x] Prometheus + Grafana integration
  - [x] Health checks
  - [x] Volume management
- [x] Kubernetes deployment manifests
  - [x] Namespace configuration
  - [x] ConfigMap for environment variables
  - [x] Secret management
  - [x] PersistentVolumeClaims (data + queue)
  - [x] Deployment with 3 replicas
  - [x] Service (LoadBalancer, health, metrics)
  - [x] HorizontalPodAutoscaler (CPU/memory based)
  - [x] PodDisruptionBudget for HA
  - [x] NetworkPolicy for security
  - [x] ServiceMonitor for Prometheus
  - [x] Kustomization file
  - [x] Comprehensive documentation
- [x] Ansible playbook for deployment
  - [x] Complete role structure with all tasks
  - [x] Production and staging inventories
  - [x] Prerequisites installation (packages, directories)
  - [x] User and group management
  - [x] Binary installation and updates
  - [x] Configuration templates (env, systemd, logrotate)
  - [x] TLS certificate generation and management
  - [x] Database setup and integrity checks
  - [x] Firewall configuration (UFW/firewalld)
  - [x] Backup scripts and scheduling
  - [x] Monitoring setup (health checks, Prometheus)
  - [x] Service management with systemd
  - [x] Comprehensive documentation
- [ ] Documentation
  - [x] API documentation
    - [x] REST API endpoints (health, stats, users, queue)
    - [x] Prometheus metrics
    - [x] CLI tools (user-cli, gdpr-cli)
    - [x] Protocol extensions (PIPELINING, SIZE, AUTH, etc.)
    - [x] Configuration API (environment variables)
    - [x] Storage API (Maildir, mbox, database, S3, time-series)
    - [x] Authentication API (Argon2id, SMTP AUTH)
    - [x] Monitoring API (health checks, metrics)
    - [x] Error codes (HTTP, SMTP)
    - [x] Rate limiting
    - [x] WebHooks
  - [x] Architecture diagrams
    - [x] System overview diagram
    - [x] Component architecture
    - [x] Data flow diagrams (incoming/outgoing)
    - [x] Storage architecture with database schemas
    - [x] Security architecture (defense in depth)
    - [x] Deployment architectures (single, HA, K8s)
    - [x] Scalability design
    - [x] Monitoring & observability
    - [x] Disaster recovery procedures
  - [x] Deployment guides
    - [x] Prerequisites and system requirements
    - [x] Single server deployment
    - [x] Docker deployment with Compose
    - [x] Kubernetes deployment with manifests
    - [x] Cloud platform deployments (AWS, GCP, Azure)
    - [x] High availability setup (HAProxy, Keepalived)
    - [x] TLS/SSL configuration (Let's Encrypt)
    - [x] Database setup (SQLite, PostgreSQL)
    - [x] Monitoring setup (Prometheus, Grafana)
    - [x] Backup and recovery procedures
    - [x] Security hardening guidelines
    - [x] Performance tuning recommendations
  - [x] Troubleshooting guide
    - [x] General troubleshooting steps
    - [x] Service startup issues
    - [x] Connection problems
    - [x] Authentication issues
    - [x] Email delivery problems
    - [x] TLS/SSL troubleshooting
    - [x] Performance diagnostics
    - [x] Database issues
    - [x] Storage problems
    - [x] Queue issues
    - [x] Memory and resource issues
    - [x] Docker/Kubernetes issues
    - [x] Security and firewall
    - [x] Advanced diagnostics
  - [x] Performance tuning guide
    - [x] Performance metrics and KPIs
    - [x] Baseline performance targets
    - [x] System-level tuning (kernel, limits)
    - [x] Application-level tuning
    - [x] Database optimization (SQLite, PostgreSQL)
    - [x] Storage optimization
    - [x] Network tuning
    - [x] Memory optimization
    - [x] CPU optimization
    - [x] I/O optimization
    - [x] Caching strategies
    - [x] Load balancing
    - [x] Monitoring and profiling
    - [x] Benchmarking tools
    - [x] Workload-specific tuning

### Multi-Platform Support
- [x] Windows support
  - [x] Platform detection and abstraction layer
  - [x] Windows service management (sc.exe integration)
  - [x] Path handling (backslash separators)
  - [x] Winsock2 networking (ws2_32)
  - [x] Windows-specific libraries (advapi32)
  - [x] Cross-compilation support
- [x] BSD support (FreeBSD, OpenBSD)
  - [x] FreeBSD platform detection
  - [x] OpenBSD platform detection
  - [x] rc.d service script generation
  - [x] BSD-specific signal handling
  - [x] Cross-compilation support
- [x] ARM architecture support
  - [x] ARM64 (aarch64) support
  - [x] ARM32 support
  - [x] Architecture detection
  - [x] Cross-compilation for ARM targets
- [x] IPv6 support (full dual-stack support)
- [x] Unix socket support
  - [x] Stream sockets (SOCK_STREAM)
  - [x] Datagram sockets (SOCK_DGRAM)
  - [x] Abstract namespace (Linux)
  - [x] File permissions handling
  - [x] Non-blocking I/O
  - [x] Socket cleanup
  - [x] Path length validation
- [x] Cross-platform build system
  - [x] Build for all platforms from any platform
  - [x] Platform-specific library linking
  - [x] Build script for automated builds
  - [x] Comprehensive cross-platform documentation

### Compliance & Standards
- [x] Full RFC 5321 compliance testing
  - [x] Comprehensive test suite (30+ tests)
  - [x] Session initiation tests
  - [x] Command syntax tests
  - [x] Reply code validation
  - [x] Complete mail transaction tests
- [x] RFC 5322 message format compliance
  - [x] Header format validation
  - [x] Address specification tests
  - [x] Required fields validation
  - [x] Date format compliance
  - [x] MIME header support
- [x] RFC 6409 message submission support
  - [x] Message Submission Agent implementation
  - [x] Automatic header addition (Message-ID, Date, Sender)
  - [x] Received header generation
  - [x] From/Sender validation
  - [x] Authentication enforcement
  - [x] Comprehensive documentation
- [x] CAN-SPAM compliance features
  - [x] Message validation system
  - [x] Unsubscribe link generation
  - [x] Physical address requirement
  - [x] From header validation
  - [x] Unsubscribe list management
  - [x] Automatic compliance element addition
- [x] GDPR compliance features
  - [x] Data export (Article 15 & 20)
    - [x] Complete user data export
    - [x] JSON format (machine-readable)
    - [x] Personal information export
    - [x] Message metadata and content
    - [x] Activity log export
    - [x] Storage metadata
  - [x] Data deletion (Article 17)
    - [x] Permanent user data removal
    - [x] Atomic database transactions
    - [x] Cascade deletion (messages, user records)
    - [x] Audit logging before deletion
  - [x] Audit logging (Article 30)
    - [x] Data access logging
    - [x] Export operation logging
    - [x] Deletion operation logging
    - [x] Timestamp and IP tracking
  - [x] GDPR CLI tool
    - [x] gdpr-cli export command
    - [x] gdpr-cli delete command
    - [x] gdpr-cli log command

## Future Ideas 💡

- [ ] Machine learning spam detection
- [x] Encrypted email storage at rest
  - [x] AES-256-GCM authenticated encryption
  - [x] Per-message unique nonces
  - [x] Key derivation from master key (HKDF)
  - [x] Password-based key derivation (Argon2id)
  - [x] Encrypted time-series storage wrapper
  - [x] Message encryption/decryption
  - [x] Serialization format with version/nonce/tag
  - [x] Key rotation support
  - [x] Secure key management
  - [x] Comprehensive test coverage
- [ ] Multi-tenancy support
- [ ] Cluster mode for high availability
- [x] Message search functionality (full-text)
  - [x] FTS5 search engine with Porter stemming
  - [x] Search CLI tool
  - [x] REST API endpoints
  - [x] Advanced filtering and sorting
  - [x] Search statistics and index rebuilding
- [ ] Email archiving
- [x] Backup and restore utilities
  - [x] Full backup creation
  - [x] Incremental backup support
  - [x] Differential backup (framework)
  - [x] Compression support (gzip, zstd)
  - [x] Encryption support
  - [x] Checksum verification (SHA-256)
  - [x] Backup metadata tracking
  - [x] Restore with verification
  - [x] Backup listing and management
  - [x] Retention policy and pruning
  - [x] Automated backup scheduling
  - [x] Comprehensive test coverage
- [ ] Migration tools from other servers
- [ ] Plugin system for extensibility
- [ ] GraphQL API
- [ ] WebSocket real-time notifications
- [ ] IMAP server integration
- [ ] POP3 server support
- [ ] CalDAV/CardDAV support
- [ ] ActiveSync support
- [ ] Webmail client
- [ ] Mobile app for administration

## Known Issues 🐛

### Critical
**None!** All critical issues have been resolved.
- [x] ~~TLS handshake cipher panic during STARTTLS~~ (Fixed in v0.21.0: memory alignment bug)

### High Priority
**None!** All high priority issues have been resolved.
- [x] ~~Need to verify thread safety of all shared resources~~ (Fixed in v0.21.0: comprehensive audit)
- [x] ~~Authentication accepts any credentials (development mode)~~ (Fixed: now uses database with Argon2id)
- [x] ~~Rate limiter cleanup not scheduled~~ (Fixed in v0.18.0: automatic background cleanup)

### Medium Priority
**None!** All medium priority issues have been resolved.
- [x] ~~No connection timeout enforcement yet~~ (Fixed in 0.2.0)
- [x] ~~No maximum recipients per message limit~~ (Fixed in 0.1.0)
- [x] ~~No DATA command timeout~~ (Fixed in v0.21.0: configurable DATA timeout)
- [x] ~~HTTPS webhooks not supported (HTTP only)~~ (Fixed in v0.20.0: full TLS client support)
- [x] ~~Per-user rate limiting~~ (Fixed in v0.22.0: full per-user rate limiting)
- [x] ~~Configurable cleanup interval~~ (Fixed in v0.22.0: customizable cleanup scheduling)

## Research Needed 🔬

- [ ] Best practices for email server security
- [ ] Modern SMTP server architectures
- [ ] Email deliverability optimization
- [ ] Efficient queue management strategies
- [ ] Zero-downtime deployment strategies
- [ ] Email reputation management

---

## Project Information

**Last Updated**: 2025-10-24
**Current Version**: v0.22.0
**Zig Version**: 0.15.1
**License**: MIT

**Key Dependencies**:
- zig-tls: ~/Code/zig-tls (Pure Zig TLS 1.3 implementation)
- SQLite3: System library (user authentication database)

**Maintainers**: Add your name here when contributing

**Related Documentation**:
- README.md - Getting started guide
- TLS.md - Reverse proxy setup for production TLS
- TLS_STATUS.md - TLS implementation status
- IMPLEMENTATION_SUMMARY.md - Complete TLS technical summary
- REFACTORING.md - zig-tls library extraction details

**Priority Legend**:
- 🔴 High Priority: Critical for production use
- 🟡 Medium Priority: Important but not blocking
- 🟢 Low Priority: Nice to have features
- 💡 Future Ideas: Long-term vision items
- 🐛 Known Issues: Bugs to fix
- 🔬 Research Needed: Investigation required
