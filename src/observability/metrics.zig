const std = @import("std");
const statsd = @import("statsd.zig");

/// Enhanced Application Metrics for SMTP Server
/// Tracks comprehensive statistics including:
/// - Message processing (sent, received, bounced, deferred)
/// - Spam/virus detection rates
/// - Authentication statistics
/// - Connection metrics
/// - Queue metrics
/// - Performance timing
///
/// ## Usage
/// ```zig
/// var metrics = try SmtpMetrics.init(allocator, "localhost", 8125, "smtp");
/// defer metrics.deinit();
///
/// metrics.recordMessageReceived("user@example.com", 1024);
/// metrics.recordSpamDetected(.spamassassin, 7.5);
/// metrics.recordAuthAttempt(.plain, true);
/// ```

/// Spam detection engine types
pub const SpamEngine = enum {
    spamassassin,
    rspamd,
    dnsbl,
    dkim,
    dmarc,
    spf,
    custom,

    pub fn toString(self: SpamEngine) []const u8 {
        return switch (self) {
            .spamassassin => "spamassassin",
            .rspamd => "rspamd",
            .dnsbl => "dnsbl",
            .dkim => "dkim",
            .dmarc => "dmarc",
            .spf => "spf",
            .custom => "custom",
        };
    }
};

/// Authentication mechanism types
pub const AuthMechanism = enum {
    plain,
    login,
    cram_md5,
    oauth2,
    external,
    api_key,

    pub fn toString(self: AuthMechanism) []const u8 {
        return switch (self) {
            .plain => "plain",
            .login => "login",
            .cram_md5 => "cram_md5",
            .oauth2 => "oauth2",
            .external => "external",
            .api_key => "api_key",
        };
    }
};

/// Message delivery status
pub const DeliveryStatus = enum {
    delivered,
    bounced,
    deferred,
    rejected,
    quarantined,

    pub fn toString(self: DeliveryStatus) []const u8 {
        return switch (self) {
            .delivered => "delivered",
            .bounced => "bounced",
            .deferred => "deferred",
            .rejected => "rejected",
            .quarantined => "quarantined",
        };
    }
};

/// Bounce type classification
pub const BounceType = enum {
    hard, // Permanent failure (invalid address)
    soft, // Temporary failure (mailbox full, server down)
    block, // Blocked by recipient
    technical, // Technical issue (DNS, network)
    policy, // Policy rejection (DMARC, etc.)

    pub fn toString(self: BounceType) []const u8 {
        return switch (self) {
            .hard => "hard",
            .soft => "soft",
            .block => "block",
            .technical => "technical",
            .policy => "policy",
        };
    }
};

/// Connection type
pub const ConnectionType = enum {
    smtp, // Port 25
    submission, // Port 587
    smtps, // Port 465
    internal, // Internal relay

    pub fn toString(self: ConnectionType) []const u8 {
        return switch (self) {
            .smtp => "smtp",
            .submission => "submission",
            .smtps => "smtps",
            .internal => "internal",
        };
    }
};

/// Comprehensive SMTP Metrics collector
pub const SmtpMetrics = struct {
    allocator: std.mem.Allocator,
    client: ?*statsd.StatsDClient,
    enabled: bool,
    mutex: std.Thread.Mutex,

    // In-memory counters for local aggregation
    counters: MetricCounters,
    gauges: MetricGauges,
    histograms: MetricHistograms,

    pub fn init(
        allocator: std.mem.Allocator,
        statsd_host: ?[]const u8,
        statsd_port: u16,
        prefix: []const u8,
    ) !SmtpMetrics {
        var client: ?*statsd.StatsDClient = null;

        if (statsd_host) |host| {
            const c = try allocator.create(statsd.StatsDClient);
            c.* = try statsd.StatsDClient.init(allocator, host, statsd_port, prefix);
            client = c;
        }

        return .{
            .allocator = allocator,
            .client = client,
            .enabled = true,
            .mutex = .{},
            .counters = MetricCounters{},
            .gauges = MetricGauges{},
            .histograms = MetricHistograms.init(),
        };
    }

    pub fn deinit(self: *SmtpMetrics) void {
        if (self.client) |c| {
            c.deinit();
            self.allocator.destroy(c);
        }
    }

    // ===== Message Metrics =====

    /// Record a message received
    pub fn recordMessageReceived(self: *SmtpMetrics, domain: []const u8, size_bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_received += 1;
        self.counters.bytes_received += size_bytes;

        if (self.client) |c| {
            c.increment("messages.received") catch {};
            c.counter("bytes.received", @intCast(size_bytes), null) catch {};
            // Per-domain metric
            const metric_name = std.fmt.allocPrint(self.allocator, "messages.received.{s}", .{domain}) catch return;
            defer self.allocator.free(metric_name);
            c.increment(metric_name) catch {};
        }
    }

    /// Record a message sent/delivered
    pub fn recordMessageSent(self: *SmtpMetrics, domain: []const u8, size_bytes: usize, delivery_time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_sent += 1;
        self.counters.bytes_sent += size_bytes;
        self.histograms.addDeliveryTime(delivery_time_ms);

        if (self.client) |c| {
            c.increment("messages.sent") catch {};
            c.counter("bytes.sent", @intCast(size_bytes), null) catch {};
            c.timing("delivery.time", @intCast(delivery_time_ms), null) catch {};
            _ = domain;
        }
    }

    /// Record a message bounce
    pub fn recordBounce(self: *SmtpMetrics, bounce_type: BounceType, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_bounced += 1;
        switch (bounce_type) {
            .hard => self.counters.bounces_hard += 1,
            .soft => self.counters.bounces_soft += 1,
            else => {},
        }

        if (self.client) |c| {
            c.increment("messages.bounced") catch {};
            const bounce_metric = std.fmt.allocPrint(self.allocator, "bounces.{s}", .{bounce_type.toString()}) catch return;
            defer self.allocator.free(bounce_metric);
            c.increment(bounce_metric) catch {};
            _ = domain;
        }
    }

    /// Record a deferred message
    pub fn recordDeferred(self: *SmtpMetrics, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_deferred += 1;

        if (self.client) |c| {
            c.increment("messages.deferred") catch {};
            _ = reason;
        }
    }

    // ===== Spam/Virus Metrics =====

    /// Record spam detection
    pub fn recordSpamDetected(self: *SmtpMetrics, engine: SpamEngine, score: f64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.spam_detected += 1;
        self.histograms.addSpamScore(score);

        if (self.client) |c| {
            c.increment("spam.detected") catch {};
            const engine_metric = std.fmt.allocPrint(self.allocator, "spam.detected.{s}", .{engine.toString()}) catch return;
            defer self.allocator.free(engine_metric);
            c.increment(engine_metric) catch {};
            c.histogram("spam.score", @intFromFloat(score * 100), null) catch {};
        }
    }

    /// Record virus detection
    pub fn recordVirusDetected(self: *SmtpMetrics, virus_name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.viruses_detected += 1;

        if (self.client) |c| {
            c.increment("virus.detected") catch {};
            _ = virus_name;
        }
    }

    /// Record message scanned (clean)
    pub fn recordMessageScanned(self: *SmtpMetrics, scan_time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_scanned += 1;
        self.histograms.addScanTime(scan_time_ms);

        if (self.client) |c| {
            c.increment("messages.scanned") catch {};
            c.timing("scan.time", @intCast(scan_time_ms), null) catch {};
        }
    }

    // ===== Authentication Metrics =====

    /// Record authentication attempt
    pub fn recordAuthAttempt(self: *SmtpMetrics, mechanism: AuthMechanism, success: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.auth_attempts += 1;
        if (success) {
            self.counters.auth_successes += 1;
        } else {
            self.counters.auth_failures += 1;
        }

        if (self.client) |c| {
            c.increment("auth.attempts") catch {};
            if (success) {
                c.increment("auth.success") catch {};
            } else {
                c.increment("auth.failure") catch {};
            }
            const mech_metric = std.fmt.allocPrint(
                self.allocator,
                "auth.{s}.{s}",
                .{ mechanism.toString(), if (success) "success" else "failure" },
            ) catch return;
            defer self.allocator.free(mech_metric);
            c.increment(mech_metric) catch {};
        }
    }

    /// Record rate limit hit
    pub fn recordRateLimitHit(self: *SmtpMetrics, limit_type: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.rate_limits_hit += 1;

        if (self.client) |c| {
            c.increment("ratelimit.hit") catch {};
            const metric = std.fmt.allocPrint(self.allocator, "ratelimit.{s}", .{limit_type}) catch return;
            defer self.allocator.free(metric);
            c.increment(metric) catch {};
        }
    }

    // ===== Connection Metrics =====

    /// Record new connection
    pub fn recordConnection(self: *SmtpMetrics, conn_type: ConnectionType, tls_enabled: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.connections_total += 1;
        self.gauges.connections_active += 1;
        if (tls_enabled) {
            self.counters.connections_tls += 1;
        }

        if (self.client) |c| {
            c.increment("connections.total") catch {};
            c.gauge("connections.active", @intCast(self.gauges.connections_active)) catch {};
            const type_metric = std.fmt.allocPrint(self.allocator, "connections.{s}", .{conn_type.toString()}) catch return;
            defer self.allocator.free(type_metric);
            c.increment(type_metric) catch {};
            if (tls_enabled) {
                c.increment("connections.tls") catch {};
            }
        }
    }

    /// Record connection closed
    pub fn recordConnectionClosed(self: *SmtpMetrics, duration_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.gauges.connections_active > 0) {
            self.gauges.connections_active -= 1;
        }
        self.histograms.addConnectionDuration(duration_ms);

        if (self.client) |c| {
            c.gauge("connections.active", @intCast(self.gauges.connections_active)) catch {};
            c.timing("connection.duration", @intCast(duration_ms), null) catch {};
        }
    }

    // ===== Queue Metrics =====

    /// Update queue size
    pub fn updateQueueSize(self: *SmtpMetrics, queue_name: []const u8, size: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.gauges.queue_size = size;

        if (self.client) |c| {
            c.gauge("queue.size", @intCast(size)) catch {};
            const metric = std.fmt.allocPrint(self.allocator, "queue.{s}.size", .{queue_name}) catch return;
            defer self.allocator.free(metric);
            c.gauge(metric, @intCast(size)) catch {};
        }
    }

    /// Record queue processing time
    pub fn recordQueueProcessTime(self: *SmtpMetrics, time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.histograms.addQueueTime(time_ms);

        if (self.client) |c| {
            c.timing("queue.process_time", @intCast(time_ms), null) catch {};
        }
    }

    // ===== DKIM/DMARC/SPF Metrics =====

    /// Record DKIM verification result
    pub fn recordDkimResult(self: *SmtpMetrics, passed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.dkim_checks += 1;
        if (passed) {
            self.counters.dkim_passed += 1;
        }

        if (self.client) |c| {
            c.increment("dkim.checked") catch {};
            if (passed) {
                c.increment("dkim.passed") catch {};
            } else {
                c.increment("dkim.failed") catch {};
            }
        }
    }

    /// Record DMARC verification result
    pub fn recordDmarcResult(self: *SmtpMetrics, policy: []const u8, passed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.dmarc_checks += 1;
        if (passed) {
            self.counters.dmarc_passed += 1;
        }

        if (self.client) |c| {
            c.increment("dmarc.checked") catch {};
            _ = policy;
            if (passed) {
                c.increment("dmarc.passed") catch {};
            } else {
                c.increment("dmarc.failed") catch {};
            }
        }
    }

    /// Record SPF verification result
    pub fn recordSpfResult(self: *SmtpMetrics, result: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.spf_checks += 1;

        if (self.client) |c| {
            c.increment("spf.checked") catch {};
            const metric = std.fmt.allocPrint(self.allocator, "spf.{s}", .{result}) catch return;
            defer self.allocator.free(metric);
            c.increment(metric) catch {};
        }
    }

    // ===== Statistics =====

    /// Get current metrics snapshot
    pub fn getSnapshot(self: *SmtpMetrics) MetricsSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        return MetricsSnapshot{
            .counters = self.counters,
            .gauges = self.gauges,
            .spam_rate = self.calculateSpamRate(),
            .bounce_rate = self.calculateBounceRate(),
            .auth_success_rate = self.calculateAuthSuccessRate(),
            .tls_rate = self.calculateTlsRate(),
            .dkim_pass_rate = self.calculateDkimPassRate(),
            .dmarc_pass_rate = self.calculateDmarcPassRate(),
        };
    }

    /// Reset all counters
    pub fn reset(self: *SmtpMetrics) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters = MetricCounters{};
        self.gauges = MetricGauges{};
        self.histograms = MetricHistograms.init();
    }

    // Internal calculation methods
    fn calculateSpamRate(self: *SmtpMetrics) f64 {
        if (self.counters.messages_received == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.spam_detected)) /
            @as(f64, @floatFromInt(self.counters.messages_received)) * 100.0;
    }

    fn calculateBounceRate(self: *SmtpMetrics) f64 {
        if (self.counters.messages_sent == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.messages_bounced)) /
            @as(f64, @floatFromInt(self.counters.messages_sent)) * 100.0;
    }

    fn calculateAuthSuccessRate(self: *SmtpMetrics) f64 {
        if (self.counters.auth_attempts == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.auth_successes)) /
            @as(f64, @floatFromInt(self.counters.auth_attempts)) * 100.0;
    }

    fn calculateTlsRate(self: *SmtpMetrics) f64 {
        if (self.counters.connections_total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.connections_tls)) /
            @as(f64, @floatFromInt(self.counters.connections_total)) * 100.0;
    }

    fn calculateDkimPassRate(self: *SmtpMetrics) f64 {
        if (self.counters.dkim_checks == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.dkim_passed)) /
            @as(f64, @floatFromInt(self.counters.dkim_checks)) * 100.0;
    }

    fn calculateDmarcPassRate(self: *SmtpMetrics) f64 {
        if (self.counters.dmarc_checks == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.dmarc_passed)) /
            @as(f64, @floatFromInt(self.counters.dmarc_checks)) * 100.0;
    }
};

/// Counter metrics
pub const MetricCounters = struct {
    // Message counters
    messages_received: u64 = 0,
    messages_sent: u64 = 0,
    messages_bounced: u64 = 0,
    messages_deferred: u64 = 0,
    messages_scanned: u64 = 0,
    bytes_received: usize = 0,
    bytes_sent: usize = 0,

    // Bounce breakdown
    bounces_hard: u64 = 0,
    bounces_soft: u64 = 0,

    // Spam/Virus
    spam_detected: u64 = 0,
    viruses_detected: u64 = 0,

    // Authentication
    auth_attempts: u64 = 0,
    auth_successes: u64 = 0,
    auth_failures: u64 = 0,
    rate_limits_hit: u64 = 0,

    // Connections
    connections_total: u64 = 0,
    connections_tls: u64 = 0,

    // Email authentication
    dkim_checks: u64 = 0,
    dkim_passed: u64 = 0,
    dmarc_checks: u64 = 0,
    dmarc_passed: u64 = 0,
    spf_checks: u64 = 0,
};

/// Gauge metrics (current values)
pub const MetricGauges = struct {
    connections_active: usize = 0,
    queue_size: usize = 0,
    memory_used: usize = 0,
};

/// Histogram data for timing metrics
pub const MetricHistograms = struct {
    delivery_times: [100]u64,
    delivery_count: usize,
    scan_times: [100]u64,
    scan_count: usize,
    connection_durations: [100]u64,
    connection_count: usize,
    queue_times: [100]u64,
    queue_count: usize,
    spam_scores: [100]f64,
    spam_score_count: usize,

    pub fn init() MetricHistograms {
        return .{
            .delivery_times = [_]u64{0} ** 100,
            .delivery_count = 0,
            .scan_times = [_]u64{0} ** 100,
            .scan_count = 0,
            .connection_durations = [_]u64{0} ** 100,
            .connection_count = 0,
            .queue_times = [_]u64{0} ** 100,
            .queue_count = 0,
            .spam_scores = [_]f64{0} ** 100,
            .spam_score_count = 0,
        };
    }

    pub fn addDeliveryTime(self: *MetricHistograms, time: u64) void {
        if (self.delivery_count < 100) {
            self.delivery_times[self.delivery_count] = time;
            self.delivery_count += 1;
        }
    }

    pub fn addScanTime(self: *MetricHistograms, time: u64) void {
        if (self.scan_count < 100) {
            self.scan_times[self.scan_count] = time;
            self.scan_count += 1;
        }
    }

    pub fn addConnectionDuration(self: *MetricHistograms, duration: u64) void {
        if (self.connection_count < 100) {
            self.connection_durations[self.connection_count] = duration;
            self.connection_count += 1;
        }
    }

    pub fn addQueueTime(self: *MetricHistograms, time: u64) void {
        if (self.queue_count < 100) {
            self.queue_times[self.queue_count] = time;
            self.queue_count += 1;
        }
    }

    pub fn addSpamScore(self: *MetricHistograms, score: f64) void {
        if (self.spam_score_count < 100) {
            self.spam_scores[self.spam_score_count] = score;
            self.spam_score_count += 1;
        }
    }
};

/// Snapshot of metrics at a point in time
pub const MetricsSnapshot = struct {
    counters: MetricCounters,
    gauges: MetricGauges,
    spam_rate: f64,
    bounce_rate: f64,
    auth_success_rate: f64,
    tls_rate: f64,
    dkim_pass_rate: f64,
    dmarc_pass_rate: f64,
};

// Tests
test "metrics initialization" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    try testing.expect(metrics.enabled);
    try testing.expectEqual(@as(u64, 0), metrics.counters.messages_received);
}

test "message metrics" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordMessageReceived("example.com", 1024);
    metrics.recordMessageReceived("example.com", 2048);

    try testing.expectEqual(@as(u64, 2), metrics.counters.messages_received);
    try testing.expectEqual(@as(usize, 3072), metrics.counters.bytes_received);
}

test "spam rate calculation" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.counters.messages_received = 100;
    metrics.counters.spam_detected = 5;

    const snapshot = metrics.getSnapshot();
    try testing.expectApproxEqAbs(@as(f64, 5.0), snapshot.spam_rate, 0.01);
}

test "auth success rate" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordAuthAttempt(.plain, true);
    metrics.recordAuthAttempt(.plain, true);
    metrics.recordAuthAttempt(.plain, false);

    const snapshot = metrics.getSnapshot();
    try testing.expectApproxEqAbs(@as(f64, 66.66), snapshot.auth_success_rate, 0.1);
}

test "connection metrics" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordConnection(.smtp, true);
    metrics.recordConnection(.submission, true);
    metrics.recordConnection(.smtp, false);

    try testing.expectEqual(@as(u64, 3), metrics.counters.connections_total);
    try testing.expectEqual(@as(u64, 2), metrics.counters.connections_tls);
    try testing.expectEqual(@as(usize, 3), metrics.gauges.connections_active);

    metrics.recordConnectionClosed(1000);
    try testing.expectEqual(@as(usize, 2), metrics.gauges.connections_active);
}
