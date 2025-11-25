const std = @import("std");
const net = std.net;
const logger = @import("logger.zig");
const tls = @import("tls");
const cert_validator = @import("cert_validator.zig");

/// Supported TLS versions
pub const TlsVersion = enum {
    tls_1_2,
    tls_1_3,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_2 => "TLS 1.2",
            .tls_1_3 => "TLS 1.3",
        };
    }
};

/// TLS cipher suites supported by the server
/// RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2) cipher suites
pub const CipherSuite = enum(u16) {
    // TLS 1.3 cipher suites (mandatory)
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    // TLS 1.2 cipher suites (for legacy compatibility)
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,

    pub fn isSecure(self: CipherSuite) bool {
        // All listed ciphers are considered secure
        return switch (self) {
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            => true,
        };
    }

    pub fn isTls13(self: CipherSuite) bool {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            => true,
            else => false,
        };
    }

    pub fn toString(self: CipherSuite) []const u8 {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            .TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            .TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        };
    }
};

/// TLS session ticket for session resumption (RFC 5077)
pub const SessionTicket = struct {
    ticket_lifetime: u32, // Lifetime in seconds
    ticket_age_add: u32, // Random value for obfuscating ticket age
    nonce: [12]u8, // Unique nonce for this ticket
    ticket: []const u8, // Encrypted session state
    creation_time: i64, // When ticket was created

    pub fn isExpired(self: SessionTicket) bool {
        const now = std.time.timestamp();
        return (now - self.creation_time) > self.ticket_lifetime;
    }
};

/// OCSP response for stapling
pub const OcspResponse = struct {
    status: OcspStatus,
    this_update: i64,
    next_update: i64,
    response_data: []const u8,

    pub const OcspStatus = enum {
        good,
        revoked,
        unknown,
    };

    pub fn isValid(self: OcspResponse) bool {
        const now = std.time.timestamp();
        return now >= self.this_update and now <= self.next_update and self.status == .good;
    }
};

/// TLS configuration for the SMTP server
pub const TlsConfig = struct {
    enabled: bool,
    cert_path: ?[]const u8,
    key_path: ?[]const u8,
    validate_certificates: bool = true,
    allow_self_signed: bool = false,

    /// Minimum TLS version (default: TLS 1.2)
    min_version: TlsVersion = .tls_1_2,

    /// Preferred TLS version (default: TLS 1.3)
    preferred_version: TlsVersion = .tls_1_3,

    /// Enable TLS 1.2 fallback for legacy clients
    allow_tls_1_2_fallback: bool = true,

    /// Enabled cipher suites (null = use defaults)
    cipher_suites: ?[]const CipherSuite = null,

    /// Enable session tickets for session resumption
    enable_session_tickets: bool = true,

    /// Session ticket lifetime in seconds (default: 24 hours)
    session_ticket_lifetime: u32 = 86400,

    /// Enable OCSP stapling
    enable_ocsp_stapling: bool = false,

    /// OCSP responder URL (optional, can be extracted from certificate)
    ocsp_responder_url: ?[]const u8 = null,

    /// Certificate chain path (for intermediate certificates)
    cert_chain_path: ?[]const u8 = null,

    /// Get default cipher suites based on configuration
    pub fn getEnabledCipherSuites(self: TlsConfig) []const CipherSuite {
        if (self.cipher_suites) |suites| {
            return suites;
        }

        // Default cipher suites in preference order
        if (self.allow_tls_1_2_fallback) {
            return &[_]CipherSuite{
                // TLS 1.3 (preferred)
                .TLS_AES_256_GCM_SHA384,
                .TLS_CHACHA20_POLY1305_SHA256,
                .TLS_AES_128_GCM_SHA256,
                // TLS 1.2 (fallback)
                .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            };
        } else {
            // TLS 1.3 only
            return &[_]CipherSuite{
                .TLS_AES_256_GCM_SHA384,
                .TLS_CHACHA20_POLY1305_SHA256,
                .TLS_AES_128_GCM_SHA256,
            };
        }
    }
};

/// Session cache for TLS session resumption
pub const SessionCache = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(SessionTicket),
    max_sessions: usize,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, max_sessions: usize) SessionCache {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(SessionTicket).init(allocator),
            .max_sessions = max_sessions,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SessionCache) void {
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.deinit();
    }

    /// Store a session ticket
    pub fn put(self: *SessionCache, session_id: []const u8, ticket: SessionTicket) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Evict expired sessions if at capacity
        if (self.sessions.count() >= self.max_sessions) {
            self.evictExpired();
        }

        const id_copy = try self.allocator.dupe(u8, session_id);
        const ticket_copy = SessionTicket{
            .ticket_lifetime = ticket.ticket_lifetime,
            .ticket_age_add = ticket.ticket_age_add,
            .nonce = ticket.nonce,
            .ticket = try self.allocator.dupe(u8, ticket.ticket),
            .creation_time = ticket.creation_time,
        };

        try self.sessions.put(id_copy, ticket_copy);
    }

    /// Retrieve a session ticket
    pub fn get(self: *SessionCache, session_id: []const u8) ?SessionTicket {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.get(session_id)) |ticket| {
            if (!ticket.isExpired()) {
                return ticket;
            }
            // Remove expired ticket
            _ = self.sessions.remove(session_id);
        }
        return null;
    }

    /// Remove expired sessions
    fn evictExpired(self: *SessionCache) void {
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.sessions.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                self.allocator.free(removed.value.ticket);
            }
        }
    }
};

/// TLS context for managing certificates and keys
pub const TlsContext = struct {
    allocator: std.mem.Allocator,
    config: TlsConfig,
    cert_data: ?[]u8,
    key_data: ?[]u8,
    cert_chain_data: ?[]u8,
    // Store the parsed CertKeyPair to reuse across handshakes
    cert_key_pair: ?tls.config.CertKeyPair,
    logger: *logger.Logger,
    // Session cache for session resumption
    session_cache: ?*SessionCache,
    // Cached OCSP response for stapling
    ocsp_response: ?OcspResponse,
    ocsp_response_data: ?[]u8,

    pub fn init(allocator: std.mem.Allocator, cfg: TlsConfig, log: *logger.Logger) !TlsContext {
        var ctx = TlsContext{
            .allocator = allocator,
            .config = cfg,
            .cert_data = null,
            .key_data = null,
            .cert_chain_data = null,
            .cert_key_pair = null,
            .logger = log,
            .session_cache = null,
            .ocsp_response = null,
            .ocsp_response_data = null,
        };

        if (cfg.enabled) {
            try ctx.loadCertificates();
            try ctx.loadCertKeyPair();

            // Initialize session cache if session tickets enabled
            if (cfg.enable_session_tickets) {
                const cache = try allocator.create(SessionCache);
                cache.* = SessionCache.init(allocator, 10000); // Max 10k sessions
                ctx.session_cache = cache;
                log.info("TLS session resumption enabled (max 10000 sessions)", .{});
            }

            // Log TLS configuration
            log.info("TLS configuration: min={s}, preferred={s}, fallback={}", .{
                cfg.min_version.toString(),
                cfg.preferred_version.toString(),
                cfg.allow_tls_1_2_fallback,
            });

            // Log enabled cipher suites
            const suites = cfg.getEnabledCipherSuites();
            log.info("Enabled cipher suites ({d}):", .{suites.len});
            for (suites) |suite| {
                log.info("  - {s}", .{suite.toString()});
            }
        }

        return ctx;
    }

    pub fn deinit(self: *TlsContext) void {
        if (self.cert_key_pair) |*ckp| {
            var mut_ckp = ckp.*;
            mut_ckp.deinit(self.allocator);
        }
        if (self.cert_data) |data| {
            self.allocator.free(data);
        }
        if (self.key_data) |data| {
            self.allocator.free(data);
        }
        if (self.cert_chain_data) |data| {
            self.allocator.free(data);
        }
        if (self.session_cache) |cache| {
            cache.deinit();
            self.allocator.destroy(cache);
        }
        if (self.ocsp_response_data) |data| {
            self.allocator.free(data);
        }
    }

    fn loadCertificates(self: *TlsContext) !void {
        if (self.config.cert_path) |cert_path| {
            self.logger.info("Loading TLS certificate from: {s}", .{cert_path});

            const cert_file = std.fs.cwd().openFile(cert_path, .{}) catch |err| {
                self.logger.err("Failed to open certificate file: {s} - {}", .{ cert_path, err });
                return error.CertificateLoadFailed;
            };
            defer cert_file.close();

            const cert_data = try cert_file.readToEndAlloc(self.allocator, 1024 * 1024); // Max 1MB
            self.cert_data = cert_data;

            self.logger.info("Certificate loaded successfully ({d} bytes)", .{cert_data.len});
        }

        if (self.config.key_path) |key_path| {
            self.logger.info("Loading TLS private key from: {s}", .{key_path});

            const key_file = std.fs.cwd().openFile(key_path, .{}) catch |err| {
                self.logger.err("Failed to open key file: {s} - {}", .{ key_path, err });
                return error.KeyLoadFailed;
            };
            defer key_file.close();

            const key_data = try key_file.readToEndAlloc(self.allocator, 1024 * 1024); // Max 1MB
            self.key_data = key_data;

            self.logger.info("Private key loaded successfully ({d} bytes)", .{key_data.len});
        }

        if (self.cert_data == null or self.key_data == null) {
            self.logger.err("TLS enabled but certificate or key not provided", .{});
            return error.IncompleteTlsConfiguration;
        }
    }

    /// Validate certificates using the certificate validator
    pub fn validateCertificates(self: *TlsContext) !void {
        if (!self.config.validate_certificates) {
            self.logger.warn("Certificate validation disabled", .{});
            return;
        }

        if (self.cert_data) |cert| {
            // Basic PEM format check
            if (!std.mem.startsWith(u8, cert, "-----BEGIN CERTIFICATE-----")) {
                self.logger.err("Certificate does not appear to be in PEM format", .{});
                return error.InvalidCertificateFormat;
            }

            // Comprehensive validation using CertificateValidator
            var validator = cert_validator.CertificateValidator.init(self.allocator);
            validator.allow_self_signed = self.config.allow_self_signed;

            var result = validator.validateCertificate(cert) catch |err| {
                self.logger.err("Certificate validation failed: {}", .{err});
                return err;
            };
            defer result.deinit(self.allocator);

            // Log validation results
            if (!result.valid) {
                self.logger.err("Certificate validation failed:", .{});
                for (result.errors.items) |error_msg| {
                    self.logger.err("  - {s}", .{error_msg});
                }
                return error.InvalidCertificate;
            }

            // Log warnings
            if (result.warnings.items.len > 0) {
                self.logger.warn("Certificate validation warnings:", .{});
                for (result.warnings.items) |warning| {
                    self.logger.warn("  - {s}", .{warning});
                }
            }

            // Log certificate info
            if (result.subject_cn) |cn| {
                self.logger.info("Certificate subject: {s}", .{cn});
            }
            if (result.issuer_cn) |issuer| {
                self.logger.info("Certificate issuer: {s}", .{issuer});
            }
            if (result.self_signed) {
                self.logger.warn("Certificate is self-signed", .{});
            }
            if (result.expired) {
                self.logger.err("Certificate is expired", .{});
                return error.CertificateExpired;
            }
            if (result.not_yet_valid) {
                self.logger.err("Certificate is not yet valid", .{});
                return error.CertificateNotYetValid;
            }
            if (result.days_until_expiry) |days| {
                self.logger.info("Certificate expires in {d} days", .{days});
            }
        }

        if (self.key_data) |key| {
            if (!std.mem.startsWith(u8, key, "-----BEGIN") or
                !std.mem.containsAtLeast(u8, key, 1, "PRIVATE KEY-----"))
            {
                self.logger.err("Private key does not appear to be in PEM format", .{});
                return error.InvalidKeyFormat;
            }
        }

        self.logger.info("TLS certificates validated successfully", .{});
    }

    /// Load and parse the CertKeyPair for reuse across handshakes
    fn loadCertKeyPair(self: *TlsContext) !void {
        if (!self.config.enabled) return;

        const cert_path = self.config.cert_path orelse return error.TlsNotConfigured;
        const key_path = self.config.key_path orelse return error.TlsNotConfigured;

        self.logger.info("Loading TLS CertKeyPair...", .{});

        // Convert to absolute paths if needed
        var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        var key_path_buf: [std.fs.max_path_bytes]u8 = undefined;

        const abs_cert_path = if (std.fs.path.isAbsolute(cert_path))
            cert_path
        else
            try std.fs.cwd().realpath(cert_path, &cert_path_buf);

        const abs_key_path = if (std.fs.path.isAbsolute(key_path))
            key_path
        else
            try std.fs.cwd().realpath(key_path, &key_path_buf);

        const cert_key = tls.config.CertKeyPair.fromFilePathAbsolute(
            self.allocator,
            abs_cert_path,
            abs_key_path,
        ) catch |err| {
            self.logger.err("Failed to load CertKeyPair: {}", .{err});
            return error.CertKeyPairLoadFailed;
        };

        self.cert_key_pair = cert_key;
        self.logger.info("CertKeyPair loaded successfully", .{});
    }
};

/// TLS connection wrapper
/// Note: Buffers are owned by caller (Session), not by TlsConnection
pub const TlsConnection = struct {
    conn: tls.Connection,

    pub fn deinit(self: *TlsConnection) void {
        self.conn.close() catch {};
        // Note: Buffers are freed by Session, not here
    }

    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        return self.conn.read(buffer);
    }

    pub fn write(self: *TlsConnection, data: []const u8) !usize {
        return self.conn.write(data);
    }
};

/// Upgrade a plain TCP connection to TLS using tls.zig library
/// Caller must provide pre-allocated buffers that will persist for the connection's lifetime
pub fn upgradeToTls(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    ctx: *TlsContext,
    log: *logger.Logger,
    input_buf: []u8,
    output_buf: []u8,
) !TlsConnection {
    if (!ctx.config.enabled) {
        return error.TlsNotEnabled;
    }

    const cert_path = ctx.config.cert_path orelse return error.TlsNotConfigured;
    const key_path = ctx.config.key_path orelse return error.TlsNotConfigured;

    log.info("Starting TLS handshake...", .{});

    // Load certificate and key
    var auth = tls.config.CertKeyPair.fromFilePathAbsolute(
        allocator,
        cert_path,
        key_path,
    ) catch |err| {
        log.err("Failed to load certificate/key: {}", .{err});
        return error.InvalidCertificate;
    };
    defer auth.deinit(allocator);

    // Use caller-provided buffers that persist at session scope
    // These buffers MUST remain valid for the lifetime of the TLS connection

    // Create buffered reader/writer with the provided buffers
    var stream_reader = stream.reader(input_buf);
    var stream_writer = stream.writer(output_buf);

    // Get interface pointers (these point into stack-local reader/writer structs)
    const reader_iface = if (@hasField(@TypeOf(stream_reader), "interface"))
        &stream_reader.interface
    else
        stream_reader.interface();
    const writer_iface = &stream_writer.interface;

    // Perform TLS handshake
    // The handshake happens synchronously here, reading/writing through the interfaces
    const tls_conn = tls.server(reader_iface, writer_iface, .{
        .auth = &auth,
    }) catch |err| {
        log.err("TLS handshake failed: {}", .{err});
        return error.TlsHandshakeFailed;
    };

    log.info("TLS handshake successful", .{});

    return TlsConnection{
        .conn = tls_conn,
    };
}

/// Generate a self-signed certificate for testing (helper function)
/// This is for development only - use proper CA-signed certificates in production
pub fn generateSelfSignedCert(allocator: std.mem.Allocator, hostname: []const u8) !void {
    _ = allocator;
    _ = hostname;

    // This would require OpenSSL or similar
    // For development, users should generate certificates manually:
    // openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365

    return error.NotImplemented;
}

/// OCSP (Online Certificate Status Protocol) helper functions
pub const OcspHelper = struct {
    allocator: std.mem.Allocator,
    responder_url: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, responder_url: ?[]const u8) OcspHelper {
        return .{
            .allocator = allocator,
            .responder_url = responder_url,
        };
    }

    /// Fetch OCSP response for certificate stapling
    /// Note: This is a placeholder - actual OCSP request requires HTTP client
    /// and proper ASN.1 encoding/decoding
    pub fn fetchOcspResponse(self: *OcspHelper, cert_data: []const u8) !OcspResponse {
        _ = self;
        _ = cert_data;

        // In a full implementation, this would:
        // 1. Parse the certificate to extract OCSP responder URL
        // 2. Build OCSP request with certificate serial number and issuer
        // 3. Send HTTP POST to OCSP responder
        // 4. Parse OCSP response and verify signature
        // 5. Cache response until nextUpdate

        return error.NotImplemented;
    }

    /// Check if OCSP response needs refresh
    pub fn needsRefresh(response: *const OcspResponse) bool {
        const now = std.time.timestamp();
        // Refresh if within 10% of expiry
        const remaining = response.next_update - now;
        const total_validity = response.next_update - response.this_update;
        return remaining < @divFloor(total_validity, 10);
    }
};

/// TLS handshake error categories for better diagnostics
pub const TlsHandshakeError = enum {
    certificate_expired,
    certificate_revoked,
    certificate_unknown,
    certificate_chain_incomplete,
    cipher_mismatch,
    version_mismatch,
    client_hello_failed,
    server_hello_failed,
    key_exchange_failed,
    finished_verification_failed,
    unknown,

    pub fn fromError(err: anyerror) TlsHandshakeError {
        return switch (err) {
            error.TlsHandshakeFailed => .unknown,
            error.InvalidCertificate => .certificate_unknown,
            error.CertificateExpired => .certificate_expired,
            else => .unknown,
        };
    }

    pub fn toString(self: TlsHandshakeError) []const u8 {
        return switch (self) {
            .certificate_expired => "Certificate has expired",
            .certificate_revoked => "Certificate has been revoked",
            .certificate_unknown => "Certificate validation failed",
            .certificate_chain_incomplete => "Certificate chain is incomplete",
            .cipher_mismatch => "No common cipher suite found",
            .version_mismatch => "No common TLS version supported",
            .client_hello_failed => "Failed to parse ClientHello",
            .server_hello_failed => "Failed to send ServerHello",
            .key_exchange_failed => "Key exchange failed",
            .finished_verification_failed => "Finished message verification failed",
            .unknown => "Unknown handshake error",
        };
    }
};

/// TLS statistics for monitoring
pub const TlsStats = struct {
    handshakes_total: u64 = 0,
    handshakes_failed: u64 = 0,
    session_resumptions: u64 = 0,
    active_sessions: u32 = 0,
    bytes_encrypted: u64 = 0,
    bytes_decrypted: u64 = 0,

    pub fn recordHandshake(self: *TlsStats, success: bool) void {
        self.handshakes_total += 1;
        if (!success) {
            self.handshakes_failed += 1;
        }
    }

    pub fn recordSessionResumption(self: *TlsStats) void {
        self.session_resumptions += 1;
    }

    pub fn getHandshakeSuccessRate(self: *const TlsStats) f64 {
        if (self.handshakes_total == 0) return 1.0;
        const successful = self.handshakes_total - self.handshakes_failed;
        return @as(f64, @floatFromInt(successful)) / @as(f64, @floatFromInt(self.handshakes_total));
    }
};

// Tests
test "cipher suite properties" {
    const testing = std.testing;

    // TLS 1.3 cipher suites
    try testing.expect(CipherSuite.TLS_AES_256_GCM_SHA384.isTls13());
    try testing.expect(CipherSuite.TLS_AES_256_GCM_SHA384.isSecure());

    // TLS 1.2 cipher suites
    try testing.expect(!CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.isTls13());
    try testing.expect(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.isSecure());
}

test "TLS version string conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("TLS 1.2", TlsVersion.tls_1_2.toString());
    try testing.expectEqualStrings("TLS 1.3", TlsVersion.tls_1_3.toString());
}

test "session ticket expiry" {
    const testing = std.testing;

    const ticket = SessionTicket{
        .ticket_lifetime = 3600, // 1 hour
        .ticket_age_add = 12345,
        .nonce = [_]u8{0} ** 12,
        .ticket = "",
        .creation_time = std.time.timestamp() - 3601, // Created over 1 hour ago
    };

    try testing.expect(ticket.isExpired());

    const fresh_ticket = SessionTicket{
        .ticket_lifetime = 3600,
        .ticket_age_add = 12345,
        .nonce = [_]u8{0} ** 12,
        .ticket = "",
        .creation_time = std.time.timestamp(),
    };

    try testing.expect(!fresh_ticket.isExpired());
}

test "OCSP response validity" {
    const testing = std.testing;

    const now = std.time.timestamp();

    const valid_response = OcspResponse{
        .status = .good,
        .this_update = now - 3600, // 1 hour ago
        .next_update = now + 3600, // 1 hour from now
        .response_data = "",
    };

    try testing.expect(valid_response.isValid());

    const expired_response = OcspResponse{
        .status = .good,
        .this_update = now - 7200,
        .next_update = now - 3600, // Expired 1 hour ago
        .response_data = "",
    };

    try testing.expect(!expired_response.isValid());

    const revoked_response = OcspResponse{
        .status = .revoked,
        .this_update = now - 3600,
        .next_update = now + 3600,
        .response_data = "",
    };

    try testing.expect(!revoked_response.isValid());
}

test "TLS config cipher suite defaults" {
    const testing = std.testing;

    // Config with TLS 1.2 fallback enabled
    const config_with_fallback = TlsConfig{
        .enabled = true,
        .cert_path = null,
        .key_path = null,
        .allow_tls_1_2_fallback = true,
    };

    const suites_with_fallback = config_with_fallback.getEnabledCipherSuites();
    try testing.expect(suites_with_fallback.len == 9); // 3 TLS 1.3 + 6 TLS 1.2

    // Config without TLS 1.2 fallback
    const config_no_fallback = TlsConfig{
        .enabled = true,
        .cert_path = null,
        .key_path = null,
        .allow_tls_1_2_fallback = false,
    };

    const suites_no_fallback = config_no_fallback.getEnabledCipherSuites();
    try testing.expect(suites_no_fallback.len == 3); // Only TLS 1.3
}

test "TLS stats tracking" {
    const testing = std.testing;

    var stats = TlsStats{};

    stats.recordHandshake(true);
    stats.recordHandshake(true);
    stats.recordHandshake(false);

    try testing.expectEqual(@as(u64, 3), stats.handshakes_total);
    try testing.expectEqual(@as(u64, 1), stats.handshakes_failed);

    const rate = stats.getHandshakeSuccessRate();
    try testing.expectApproxEqAbs(@as(f64, 0.666), rate, 0.01);
}

test "session cache" {
    const testing = std.testing;

    var cache = SessionCache.init(testing.allocator, 100);
    defer cache.deinit();

    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ticket_data = "test-ticket-data";
    const ticket = SessionTicket{
        .ticket_lifetime = 3600,
        .ticket_age_add = 12345,
        .nonce = nonce,
        .ticket = ticket_data,
        .creation_time = std.time.timestamp(),
    };

    try cache.put("session-1", ticket);

    const retrieved = cache.get("session-1");
    try testing.expect(retrieved != null);
    try testing.expectEqual(@as(u32, 3600), retrieved.?.ticket_lifetime);

    // Non-existent session
    try testing.expect(cache.get("session-nonexistent") == null);
}
