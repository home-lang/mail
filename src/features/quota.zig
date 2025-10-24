const std = @import("std");
const database = @import("../storage/database.zig");

/// User quota management
/// Tracks storage usage and enforces limits per user
pub const QuotaManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    mutex: std.Thread.Mutex,
    // In-memory cache of quota info for performance
    quota_cache: std.StringHashMap(QuotaInfo),
    cache_ttl: i64, // Cache time-to-live in seconds

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, cache_ttl: i64) QuotaManager {
        return .{
            .allocator = allocator,
            .db = db,
            .mutex = .{},
            .quota_cache = std.StringHashMap(QuotaInfo).init(allocator),
            .cache_ttl = cache_ttl,
        };
    }

    pub fn deinit(self: *QuotaManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.quota_cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.quota_cache.deinit();
    }

    /// Set quota limit for a user (in bytes)
    pub fn setQuota(self: *QuotaManager, email: []const u8, limit_bytes: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Update database
        const query =
            \\UPDATE users SET quota_limit = ?1 WHERE email = ?2
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, limit_bytes);
        try stmt.bind(1, email);
        try stmt.exec();

        // Invalidate cache
        if (self.quota_cache.get(email)) |_| {
            const key = self.quota_cache.fetchRemove(email);
            if (key) |k| {
                self.allocator.free(k.key);
            }
        }
    }

    /// Get current quota info for a user
    pub fn getQuotaInfo(self: *QuotaManager, email: []const u8) !QuotaInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check cache first
        if (self.quota_cache.get(email)) |info| {
            const now = std.time.timestamp();
            if (now - info.cached_at < self.cache_ttl) {
                return info;
            }
        }

        // Query database
        const query =
            \\SELECT quota_limit, quota_used FROM users WHERE email = ?1
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, email);

        if (try stmt.step()) {
            const quota_limit = stmt.columnInt64(0);
            const quota_used = stmt.columnInt64(1);

            const info = QuotaInfo{
                .limit_bytes = @intCast(quota_limit),
                .used_bytes = @intCast(quota_used),
                .cached_at = std.time.timestamp(),
            };

            // Update cache
            const key = try self.allocator.dupe(u8, email);
            try self.quota_cache.put(key, info);

            return info;
        }

        return error.UserNotFound;
    }

    /// Check if a user can store a message of given size
    pub fn checkQuota(self: *QuotaManager, email: []const u8, message_size: usize) !bool {
        const info = try self.getQuotaInfo(email);

        // Unlimited quota (0 means no limit)
        if (info.limit_bytes == 0) {
            return true;
        }

        return (info.used_bytes + message_size) <= info.limit_bytes;
    }

    /// Update quota usage after storing a message
    pub fn addUsage(self: *QuotaManager, email: []const u8, bytes: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE users SET quota_used = quota_used + ?1 WHERE email = ?2
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, @as(i64, @intCast(bytes)));
        try stmt.bind(1, email);
        try stmt.exec();

        // Invalidate cache
        if (self.quota_cache.get(email)) |_| {
            const key = self.quota_cache.fetchRemove(email);
            if (key) |k| {
                self.allocator.free(k.key);
            }
        }
    }

    /// Update quota usage after deleting a message
    pub fn removeUsage(self: *QuotaManager, email: []const u8, bytes: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE users SET quota_used = MAX(0, quota_used - ?1) WHERE email = ?2
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, @as(i64, @intCast(bytes)));
        try stmt.bind(1, email);
        try stmt.exec();

        // Invalidate cache
        if (self.quota_cache.get(email)) |_| {
            const key = self.quota_cache.fetchRemove(email);
            if (key) |k| {
                self.allocator.free(k.key);
            }
        }
    }

    /// Recalculate quota usage by scanning storage
    pub fn recalculateQuota(self: *QuotaManager, email: []const u8, maildir_path: []const u8) !usize {
        _ = self;
        _ = maildir_path;

        // This would scan the user's maildir and calculate total size
        // For now, return 0 as a placeholder
        // Real implementation would:
        // 1. Open maildir directory
        // 2. Iterate through all message files
        // 3. Sum up file sizes
        // 4. Update database

        const total_bytes: usize = 0;

        const update_query =
            \\UPDATE users SET quota_used = ?1 WHERE email = ?2
        ;

        var stmt = try self.db.db.?.prepare(update_query);
        defer stmt.deinit();

        try stmt.bind(0, @as(i64, @intCast(total_bytes)));
        try stmt.bind(1, email);
        try stmt.exec();

        return total_bytes;
    }

    /// Get quota usage percentage
    pub fn getUsagePercentage(self: *QuotaManager, email: []const u8) !f64 {
        const info = try self.getQuotaInfo(email);

        if (info.limit_bytes == 0) {
            return 0.0; // Unlimited quota
        }

        const used_f: f64 = @floatFromInt(info.used_bytes);
        const limit_f: f64 = @floatFromInt(info.limit_bytes);

        return (used_f / limit_f) * 100.0;
    }

    /// Check if user is over quota warning threshold (default 90%)
    pub fn isNearQuota(self: *QuotaManager, email: []const u8, threshold: f64) !bool {
        const percentage = try self.getUsagePercentage(email);
        return percentage >= threshold;
    }

    /// Get list of users over quota
    pub fn getUsersOverQuota(self: *QuotaManager) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\SELECT email FROM users
            \\WHERE quota_limit > 0 AND quota_used > quota_limit
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        var users = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (users.items) |user| {
                self.allocator.free(user);
            }
            users.deinit();
        }

        while (try stmt.step()) {
            const email = stmt.columnText(0);
            try users.append(try self.allocator.dupe(u8, email));
        }

        return try users.toOwnedSlice();
    }

    /// Clear cache (useful after bulk operations)
    pub fn clearCache(self: *QuotaManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.quota_cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.quota_cache.clearRetainingCapacity();
    }
};

pub const QuotaInfo = struct {
    limit_bytes: usize, // 0 means unlimited
    used_bytes: usize,
    cached_at: i64, // Unix timestamp
};

/// Quota preset configurations
pub const QuotaPreset = enum {
    unlimited,
    small, // 100 MB
    medium, // 1 GB
    large, // 5 GB
    enterprise, // 50 GB

    pub fn toBytes(self: QuotaPreset) usize {
        return switch (self) {
            .unlimited => 0,
            .small => 100 * 1024 * 1024, // 100 MB
            .medium => 1024 * 1024 * 1024, // 1 GB
            .large => 5 * 1024 * 1024 * 1024, // 5 GB
            .enterprise => 50 * 1024 * 1024 * 1024, // 50 GB
        };
    }

    pub fn toString(self: QuotaPreset) []const u8 {
        return switch (self) {
            .unlimited => "Unlimited",
            .small => "100 MB",
            .medium => "1 GB",
            .large => "5 GB",
            .enterprise => "50 GB",
        };
    }
};

/// Format bytes to human-readable string
pub fn formatBytes(allocator: std.mem.Allocator, bytes: usize) ![]const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var size: f64 = @floatFromInt(bytes);
    var unit_index: usize = 0;

    while (size >= 1024.0 and unit_index < units.len - 1) {
        size /= 1024.0;
        unit_index += 1;
    }

    return try std.fmt.allocPrint(allocator, "{d:.2} {s}", .{ size, units[unit_index] });
}

test "quota preset values" {
    const testing = std.testing;

    try testing.expectEqual(@as(usize, 0), QuotaPreset.unlimited.toBytes());
    try testing.expectEqual(@as(usize, 100 * 1024 * 1024), QuotaPreset.small.toBytes());
    try testing.expectEqual(@as(usize, 1024 * 1024 * 1024), QuotaPreset.medium.toBytes());
}

test "format bytes" {
    const testing = std.testing;

    const formatted1 = try formatBytes(testing.allocator, 1024);
    defer testing.allocator.free(formatted1);
    try testing.expect(std.mem.indexOf(u8, formatted1, "KB") != null);

    const formatted2 = try formatBytes(testing.allocator, 1024 * 1024);
    defer testing.allocator.free(formatted2);
    try testing.expect(std.mem.indexOf(u8, formatted2, "MB") != null);

    const formatted3 = try formatBytes(testing.allocator, 1024 * 1024 * 1024);
    defer testing.allocator.free(formatted3);
    try testing.expect(std.mem.indexOf(u8, formatted3, "GB") != null);
}

test "quota info calculation" {
    const testing = std.testing;

    const info = QuotaInfo{
        .limit_bytes = 1024 * 1024 * 1024, // 1 GB
        .used_bytes = 512 * 1024 * 1024, // 512 MB
        .cached_at = std.time.timestamp(),
    };

    const used_f: f64 = @floatFromInt(info.used_bytes);
    const limit_f: f64 = @floatFromInt(info.limit_bytes);
    const percentage = (used_f / limit_f) * 100.0;

    try testing.expect(percentage > 49.0 and percentage < 51.0); // ~50%
}
