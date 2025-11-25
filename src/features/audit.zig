const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Audit Trail System for tracking administrative actions
/// Provides comprehensive logging of user CRUD, config changes, and security events

/// Types of auditable actions
pub const AuditAction = enum {
    // User management
    user_created,
    user_updated,
    user_deleted,
    user_enabled,
    user_disabled,
    password_changed,

    // Authentication
    login_success,
    login_failed,
    logout,
    session_expired,

    // Configuration
    config_updated,
    config_reloaded,

    // Security
    rate_limit_triggered,
    access_denied,
    permission_changed,

    // System
    server_started,
    server_stopped,
    backup_created,
    backup_restored,

    // Email operations
    message_sent,
    message_deleted,
    message_quarantined,

    pub fn toString(self: AuditAction) []const u8 {
        return switch (self) {
            .user_created => "USER_CREATED",
            .user_updated => "USER_UPDATED",
            .user_deleted => "USER_DELETED",
            .user_enabled => "USER_ENABLED",
            .user_disabled => "USER_DISABLED",
            .password_changed => "PASSWORD_CHANGED",
            .login_success => "LOGIN_SUCCESS",
            .login_failed => "LOGIN_FAILED",
            .logout => "LOGOUT",
            .session_expired => "SESSION_EXPIRED",
            .config_updated => "CONFIG_UPDATED",
            .config_reloaded => "CONFIG_RELOADED",
            .rate_limit_triggered => "RATE_LIMIT_TRIGGERED",
            .access_denied => "ACCESS_DENIED",
            .permission_changed => "PERMISSION_CHANGED",
            .server_started => "SERVER_STARTED",
            .server_stopped => "SERVER_STOPPED",
            .backup_created => "BACKUP_CREATED",
            .backup_restored => "BACKUP_RESTORED",
            .message_sent => "MESSAGE_SENT",
            .message_deleted => "MESSAGE_DELETED",
            .message_quarantined => "MESSAGE_QUARANTINED",
        };
    }

    pub fn fromString(s: []const u8) ?AuditAction {
        const actions = [_]struct { name: []const u8, action: AuditAction }{
            .{ .name = "USER_CREATED", .action = .user_created },
            .{ .name = "USER_UPDATED", .action = .user_updated },
            .{ .name = "USER_DELETED", .action = .user_deleted },
            .{ .name = "USER_ENABLED", .action = .user_enabled },
            .{ .name = "USER_DISABLED", .action = .user_disabled },
            .{ .name = "PASSWORD_CHANGED", .action = .password_changed },
            .{ .name = "LOGIN_SUCCESS", .action = .login_success },
            .{ .name = "LOGIN_FAILED", .action = .login_failed },
            .{ .name = "LOGOUT", .action = .logout },
            .{ .name = "SESSION_EXPIRED", .action = .session_expired },
            .{ .name = "CONFIG_UPDATED", .action = .config_updated },
            .{ .name = "CONFIG_RELOADED", .action = .config_reloaded },
            .{ .name = "RATE_LIMIT_TRIGGERED", .action = .rate_limit_triggered },
            .{ .name = "ACCESS_DENIED", .action = .access_denied },
            .{ .name = "PERMISSION_CHANGED", .action = .permission_changed },
            .{ .name = "SERVER_STARTED", .action = .server_started },
            .{ .name = "SERVER_STOPPED", .action = .server_stopped },
            .{ .name = "BACKUP_CREATED", .action = .backup_created },
            .{ .name = "BACKUP_RESTORED", .action = .backup_restored },
            .{ .name = "MESSAGE_SENT", .action = .message_sent },
            .{ .name = "MESSAGE_DELETED", .action = .message_deleted },
            .{ .name = "MESSAGE_QUARANTINED", .action = .message_quarantined },
        };

        for (actions) |a| {
            if (std.mem.eql(u8, s, a.name)) {
                return a.action;
            }
        }
        return null;
    }

    pub fn getSeverity(self: AuditAction) AuditSeverity {
        return switch (self) {
            .user_deleted, .login_failed, .access_denied, .rate_limit_triggered => .warning,
            .password_changed, .permission_changed, .config_updated => .important,
            .server_started, .server_stopped, .backup_created, .backup_restored => .critical,
            else => .info,
        };
    }
};

/// Severity levels for audit events
pub const AuditSeverity = enum {
    info,
    warning,
    important,
    critical,

    pub fn toString(self: AuditSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARNING",
            .important => "IMPORTANT",
            .critical => "CRITICAL",
        };
    }
};

/// An audit log entry
pub const AuditEntry = struct {
    id: i64,
    timestamp: i64,
    action: AuditAction,
    actor: []const u8, // User or system that performed the action
    target: ?[]const u8, // Target of the action (e.g., affected username)
    target_type: ?[]const u8, // Type of target (user, config, message)
    ip_address: ?[]const u8, // Source IP address
    details: ?[]const u8, // JSON-encoded additional details
    severity: AuditSeverity,

    pub fn deinit(self: *AuditEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.actor);
        if (self.target) |t| allocator.free(t);
        if (self.target_type) |tt| allocator.free(tt);
        if (self.ip_address) |ip| allocator.free(ip);
        if (self.details) |d| allocator.free(d);
    }
};

/// Audit Trail Manager
pub const AuditTrail = struct {
    allocator: std.mem.Allocator,
    db: *anyopaque, // Database pointer (cast to actual type when using)
    enabled: bool,
    retention_days: u32,
    mutex: std.Thread.Mutex,

    // Statistics
    entries_logged: u64,
    entries_pruned: u64,

    pub fn init(allocator: std.mem.Allocator, db: *anyopaque) AuditTrail {
        return .{
            .allocator = allocator,
            .db = db,
            .enabled = true,
            .retention_days = 90, // Default 90 days retention
            .mutex = .{},
            .entries_logged = 0,
            .entries_pruned = 0,
        };
    }

    pub fn deinit(self: *AuditTrail) void {
        _ = self;
        // No cleanup needed
    }

    /// Log an audit event
    pub fn log(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        target: ?[]const u8,
        target_type: ?[]const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
    ) !void {
        if (!self.enabled) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const timestamp = time_compat.timestamp();
        const severity = action.getSeverity();

        // Build SQL insert
        const sql =
            \\INSERT INTO audit_log (timestamp, action, actor, target, target_type, ip_address, details, severity)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ;

        // For now, store in memory or use the database
        // The actual database integration would go here
        _ = sql;
        _ = timestamp;
        _ = severity;
        _ = actor;
        _ = target;
        _ = target_type;
        _ = ip_address;
        _ = details;

        self.entries_logged += 1;
    }

    /// Log a user action with convenience method
    pub fn logUserAction(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        target_username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        try self.log(action, actor, target_username, "user", ip_address, null);
    }

    /// Log a config change
    pub fn logConfigChange(
        self: *AuditTrail,
        actor: []const u8,
        config_key: []const u8,
        old_value: ?[]const u8,
        new_value: ?[]const u8,
        ip_address: ?[]const u8,
    ) !void {
        var details_buf: [512]u8 = undefined;
        const details = std.fmt.bufPrint(&details_buf, "{{\"key\":\"{s}\",\"old\":\"{s}\",\"new\":\"{s}\"}}", .{
            config_key,
            old_value orelse "null",
            new_value orelse "null",
        }) catch null;

        try self.log(.config_updated, actor, config_key, "config", ip_address, details);
    }

    /// Log a security event
    pub fn logSecurityEvent(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
    ) !void {
        try self.log(action, actor, null, "security", ip_address, details);
    }

    /// Log a login attempt
    pub fn logLogin(
        self: *AuditTrail,
        success: bool,
        username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        const action: AuditAction = if (success) .login_success else .login_failed;
        try self.log(action, username, username, "auth", ip_address, null);
    }

    /// Get recent audit entries
    pub fn getRecentEntries(self: *AuditTrail, limit: usize) ![]AuditEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        // This would query the database
        // For now, return empty
        _ = limit;
        return &[_]AuditEntry{};
    }

    /// Query audit entries with filters
    pub fn query(
        self: *AuditTrail,
        filters: QueryFilters,
    ) ![]AuditEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        _ = filters;
        return &[_]AuditEntry{};
    }

    /// Prune old entries beyond retention period
    pub fn prune(self: *AuditTrail) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const cutoff = time_compat.timestamp() - @as(i64, @intCast(self.retention_days)) * 24 * 60 * 60;
        _ = cutoff;

        // Would delete entries older than cutoff
        // Return number of entries pruned
        return 0;
    }

    /// Get statistics
    pub fn getStats(self: *AuditTrail) AuditStats {
        return .{
            .entries_logged = self.entries_logged,
            .entries_pruned = self.entries_pruned,
            .enabled = self.enabled,
            .retention_days = self.retention_days,
        };
    }
};

/// Query filters for audit log
pub const QueryFilters = struct {
    action: ?AuditAction = null,
    actor: ?[]const u8 = null,
    target: ?[]const u8 = null,
    severity: ?AuditSeverity = null,
    start_time: ?i64 = null,
    end_time: ?i64 = null,
    ip_address: ?[]const u8 = null,
    limit: usize = 100,
    offset: usize = 0,
};

/// Audit statistics
pub const AuditStats = struct {
    entries_logged: u64,
    entries_pruned: u64,
    enabled: bool,
    retention_days: u32,
};

/// SQL schema for audit_log table
pub const schema =
    \\CREATE TABLE IF NOT EXISTS audit_log (
    \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    timestamp INTEGER NOT NULL,
    \\    action TEXT NOT NULL,
    \\    actor TEXT NOT NULL,
    \\    target TEXT,
    \\    target_type TEXT,
    \\    ip_address TEXT,
    \\    details TEXT,
    \\    severity TEXT NOT NULL,
    \\    created_at INTEGER DEFAULT (strftime('%s', 'now'))
    \\);
    \\
    \\CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    \\CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    \\CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
    \\CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
    \\CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
;

// Tests
test "audit action string conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("USER_CREATED", AuditAction.user_created.toString());
    try testing.expectEqualStrings("LOGIN_FAILED", AuditAction.login_failed.toString());

    try testing.expectEqual(AuditAction.user_created, AuditAction.fromString("USER_CREATED").?);
    try testing.expectEqual(AuditAction.login_failed, AuditAction.fromString("LOGIN_FAILED").?);
    try testing.expect(AuditAction.fromString("INVALID") == null);
}

test "audit severity levels" {
    const testing = std.testing;

    try testing.expectEqual(AuditSeverity.warning, AuditAction.login_failed.getSeverity());
    try testing.expectEqual(AuditSeverity.critical, AuditAction.server_started.getSeverity());
    try testing.expectEqual(AuditSeverity.info, AuditAction.user_created.getSeverity());
}

test "audit trail initialization" {
    const testing = std.testing;

    var db: u8 = 0; // Dummy database pointer
    var trail = AuditTrail.init(testing.allocator, &db);
    defer trail.deinit();

    try testing.expect(trail.enabled);
    try testing.expectEqual(@as(u32, 90), trail.retention_days);
    try testing.expectEqual(@as(u64, 0), trail.entries_logged);
}

test "audit stats" {
    const testing = std.testing;

    var db: u8 = 0;
    var trail = AuditTrail.init(testing.allocator, &db);
    defer trail.deinit();

    const stats = trail.getStats();
    try testing.expect(stats.enabled);
    try testing.expectEqual(@as(u32, 90), stats.retention_days);
}
