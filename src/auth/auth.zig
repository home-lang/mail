const std = @import("std");
const database = @import("../storage/database.zig");
const password_mod = @import("password.zig");

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const AuthBackend = struct {
    db: *database.Database,
    password_hasher: password_mod.PasswordHasher,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) AuthBackend {
        return .{
            .db = db,
            .password_hasher = password_mod.PasswordHasher.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn verifyCredentials(self: *AuthBackend, username: []const u8, password: []const u8) !bool {
        // Normalize username - if it's an email address (contains @), extract the local part
        // This allows users to login with either "chris" or "chris@11ly.org"
        const normalized_username = blk: {
            if (std.mem.indexOf(u8, username, "@")) |at_pos| {
                break :blk username[0..at_pos];
            }
            break :blk username;
        };

        // Get user from database
        var user = self.db.getUserByUsername(normalized_username) catch |err| {
            if (err == database.DatabaseError.NotFound) {
                // User not found - return false but don't leak this information
                return false;
            }
            return err;
        };
        defer user.deinit(self.allocator);

        // Check if user is enabled
        if (!user.enabled) {
            return false;
        }

        // Verify password
        return try self.password_hasher.verifyPassword(password, user.password_hash);
    }

    pub fn createUser(self: *AuthBackend, username: []const u8, password: []const u8, email: []const u8) !i64 {
        // Hash the password
        const password_hash = try self.password_hasher.hashPassword(password);
        defer self.allocator.free(password_hash);

        // Create user in database
        return try self.db.createUser(username, password_hash, email);
    }

    pub fn changePassword(self: *AuthBackend, username: []const u8, new_password: []const u8) !void {
        // Hash the new password
        const password_hash = try self.password_hasher.hashPassword(new_password);
        defer self.allocator.free(password_hash);

        // Update in database
        try self.db.updateUserPassword(username, password_hash);
    }

    /// Verify HTTP Basic Auth header and return username if valid
    /// Format: "Basic <base64(username:password)>"
    pub fn verifyBasicAuth(self: *AuthBackend, auth_header: []const u8) !?[]const u8 {
        // Check for "Basic " prefix
        if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
            return null;
        }

        // Extract base64 part
        const encoded = std.mem.trimLeft(u8, auth_header[6..], " ");

        // Decode credentials
        const creds = try decodeBasicAuthCredentials(self.allocator, encoded);
        defer {
            self.allocator.free(creds.username);
            self.allocator.free(creds.password);
        }

        // Verify credentials
        const valid = try self.verifyCredentials(creds.username, creds.password);
        if (!valid) {
            return null;
        }

        // Return username
        return try self.allocator.dupe(u8, creds.username);
    }
};

/// Decode SASL PLAIN base64 authentication (SMTP/IMAP/POP3)
/// Format: base64(\0username\0password)
pub fn decodeBase64Auth(allocator: std.mem.Allocator, encoded: []const u8) !Credentials {
    // Decode base64 authentication string
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);

    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);

    try decoder.decode(decoded, encoded);

    // Parse credentials in format: \0username\0password
    var parts = std.mem.splitSequence(u8, decoded, "\x00");
    _ = parts.next(); // Skip first empty part

    const username = parts.next() orelse return error.InvalidAuthFormat;
    const password = parts.next() orelse return error.InvalidAuthFormat;

    return Credentials{
        .username = try allocator.dupe(u8, username),
        .password = try allocator.dupe(u8, password),
    };
}

/// Decode HTTP Basic Auth credentials
/// Format: base64(username:password)
pub fn decodeBasicAuthCredentials(allocator: std.mem.Allocator, encoded: []const u8) !Credentials {
    // Decode base64 string
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);

    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);

    try decoder.decode(decoded, encoded);

    // Parse credentials in format: username:password
    const colon_pos = std.mem.indexOf(u8, decoded, ":") orelse return error.InvalidAuthFormat;
    const username = decoded[0..colon_pos];
    const password = decoded[colon_pos + 1 ..];

    return Credentials{
        .username = try allocator.dupe(u8, username),
        .password = try allocator.dupe(u8, password),
    };
}

// =============================================================================
// Password Reset Flow
// =============================================================================

/// Password reset token
pub const ResetToken = struct {
    token: [32]u8,
    token_hash: [32]u8, // Stored hash for verification
    username: []const u8,
    email: []const u8,
    created_at: i64,
    expires_at: i64,
    used: bool,
    ip_address: ?[]const u8,

    pub fn deinit(self: *ResetToken, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.email);
        if (self.ip_address) |ip| allocator.free(ip);
    }

    /// Generate token string for URL
    pub fn toUrlToken(self: *const ResetToken, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.token)});
    }

    /// Check if token is expired
    pub fn isExpired(self: *const ResetToken, current_time: i64) bool {
        return current_time > self.expires_at;
    }

    /// Check if token is valid (not used and not expired)
    pub fn isValid(self: *const ResetToken, current_time: i64) bool {
        return !self.used and !self.isExpired(current_time);
    }
};

/// Rate limiting for password reset requests
pub const ResetRateLimiter = struct {
    allocator: std.mem.Allocator,
    attempts: std.StringHashMap(AttemptInfo),
    max_attempts_per_hour: u32,
    lockout_duration_minutes: u32,

    const AttemptInfo = struct {
        count: u32,
        first_attempt: i64,
        last_attempt: i64,
        locked_until: ?i64,
    };

    pub fn init(allocator: std.mem.Allocator, max_attempts: u32, lockout_minutes: u32) ResetRateLimiter {
        return .{
            .allocator = allocator,
            .attempts = std.StringHashMap(AttemptInfo).init(allocator),
            .max_attempts_per_hour = max_attempts,
            .lockout_duration_minutes = lockout_minutes,
        };
    }

    pub fn deinit(self: *ResetRateLimiter) void {
        var iter = self.attempts.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.attempts.deinit();
    }

    /// Check if a request is allowed
    pub fn checkAllowed(self: *ResetRateLimiter, identifier: []const u8) RateLimitResult {
        const now = std.time.timestamp();

        if (self.attempts.getPtr(identifier)) |info| {
            // Check if locked out
            if (info.locked_until) |locked_until| {
                if (now < locked_until) {
                    return .{
                        .allowed = false,
                        .reason = .locked_out,
                        .retry_after = @intCast(locked_until - now),
                    };
                }
                // Lockout expired, reset
                info.locked_until = null;
                info.count = 0;
                info.first_attempt = now;
            }

            // Check if window expired (1 hour)
            if (now - info.first_attempt > 3600) {
                info.count = 0;
                info.first_attempt = now;
            }

            // Check if max attempts exceeded
            if (info.count >= self.max_attempts_per_hour) {
                info.locked_until = now + @as(i64, self.lockout_duration_minutes) * 60;
                return .{
                    .allowed = false,
                    .reason = .too_many_attempts,
                    .retry_after = @as(u32, self.lockout_duration_minutes) * 60,
                };
            }
        }

        return .{
            .allowed = true,
            .reason = .allowed,
            .retry_after = 0,
        };
    }

    /// Record an attempt
    pub fn recordAttempt(self: *ResetRateLimiter, identifier: []const u8) !void {
        const now = std.time.timestamp();

        const result = try self.attempts.getOrPut(try self.allocator.dupe(u8, identifier));
        if (result.found_existing) {
            result.value_ptr.count += 1;
            result.value_ptr.last_attempt = now;
        } else {
            result.value_ptr.* = .{
                .count = 1,
                .first_attempt = now,
                .last_attempt = now,
                .locked_until = null,
            };
        }
    }

    /// Clear attempts for an identifier (after successful reset)
    pub fn clearAttempts(self: *ResetRateLimiter, identifier: []const u8) void {
        if (self.attempts.fetchRemove(identifier)) |entry| {
            self.allocator.free(entry.key);
        }
    }
};

pub const RateLimitResult = struct {
    allowed: bool,
    reason: RateLimitReason,
    retry_after: u32, // seconds

    pub const RateLimitReason = enum {
        allowed,
        too_many_attempts,
        locked_out,
    };
};

/// Password reset manager
pub const PasswordResetManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    rate_limiter: ResetRateLimiter,
    tokens: std.StringHashMap(ResetToken),
    config: ResetConfig,
    audit_callback: ?*const fn (event: AuditEvent) void,

    pub const ResetConfig = struct {
        token_expiry_minutes: u32 = 30,
        max_attempts_per_hour: u32 = 5,
        lockout_duration_minutes: u32 = 60,
        min_password_length: u32 = 8,
        require_special_char: bool = true,
        require_number: bool = true,
        require_uppercase: bool = true,
    };

    pub const AuditEvent = struct {
        event_type: EventType,
        username: []const u8,
        email: ?[]const u8,
        ip_address: ?[]const u8,
        success: bool,
        details: ?[]const u8,
        timestamp: i64,

        pub const EventType = enum {
            reset_requested,
            reset_completed,
            reset_failed,
            token_expired,
            rate_limited,
        };
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, config: ResetConfig) PasswordResetManager {
        return .{
            .allocator = allocator,
            .db = db,
            .rate_limiter = ResetRateLimiter.init(allocator, config.max_attempts_per_hour, config.lockout_duration_minutes),
            .tokens = std.StringHashMap(ResetToken).init(allocator),
            .config = config,
            .audit_callback = null,
        };
    }

    pub fn deinit(self: *PasswordResetManager) void {
        var iter = self.tokens.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var token = entry.value_ptr.*;
            token.deinit(self.allocator);
        }
        self.tokens.deinit();
        self.rate_limiter.deinit();
    }

    /// Set audit callback
    pub fn setAuditCallback(self: *PasswordResetManager, callback: *const fn (AuditEvent) void) void {
        self.audit_callback = callback;
    }

    /// Request a password reset
    pub fn requestReset(
        self: *PasswordResetManager,
        email: []const u8,
        ip_address: ?[]const u8,
    ) !ResetRequestResult {
        const now = std.time.timestamp();

        // Check rate limiting by email
        const rate_result = self.rate_limiter.checkAllowed(email);
        if (!rate_result.allowed) {
            self.emitAudit(.{
                .event_type = .rate_limited,
                .username = "",
                .email = email,
                .ip_address = ip_address,
                .success = false,
                .details = "Rate limit exceeded",
                .timestamp = now,
            });

            return ResetRequestResult{
                .success = false,
                .token = null,
                .error_code = .rate_limited,
                .retry_after = rate_result.retry_after,
            };
        }

        // Record attempt
        try self.rate_limiter.recordAttempt(email);

        // Look up user by email
        const user = self.db.getUserByEmail(email) catch |err| {
            if (err == database.DatabaseError.NotFound) {
                // Don't reveal that email doesn't exist - return success anyway
                // but don't actually create a token
                return ResetRequestResult{
                    .success = true, // Pretend success
                    .token = null,
                    .error_code = null,
                    .retry_after = 0,
                };
            }
            return err;
        };
        defer {
            var u = user;
            u.deinit(self.allocator);
        }

        // Generate secure token
        var token_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&token_bytes);

        // Hash token for storage
        var token_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token_bytes, &token_hash, .{});

        const token = ResetToken{
            .token = token_bytes,
            .token_hash = token_hash,
            .username = try self.allocator.dupe(u8, user.username),
            .email = try self.allocator.dupe(u8, email),
            .created_at = now,
            .expires_at = now + @as(i64, self.config.token_expiry_minutes) * 60,
            .used = false,
            .ip_address = if (ip_address) |ip| try self.allocator.dupe(u8, ip) else null,
        };

        // Store token (keyed by hash)
        var hash_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&token_hash)}) catch unreachable;
        const key = try self.allocator.dupe(u8, &hash_hex);
        try self.tokens.put(key, token);

        self.emitAudit(.{
            .event_type = .reset_requested,
            .username = user.username,
            .email = email,
            .ip_address = ip_address,
            .success = true,
            .details = null,
            .timestamp = now,
        });

        return ResetRequestResult{
            .success = true,
            .token = token_bytes,
            .error_code = null,
            .retry_after = 0,
        };
    }

    /// Complete password reset with token
    pub fn completeReset(
        self: *PasswordResetManager,
        token_hex: []const u8,
        new_password: []const u8,
        ip_address: ?[]const u8,
    ) !ResetCompleteResult {
        const now = std.time.timestamp();

        // Decode token
        if (token_hex.len != 64) {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        }

        var token_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&token_bytes, token_hex) catch {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        };

        // Hash to find stored token
        var token_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token_bytes, &token_hash, .{});

        var hash_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&token_hash)}) catch unreachable;

        // Look up token
        const token_ptr = self.tokens.getPtr(&hash_hex) orelse {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        };

        // Check if valid
        if (!token_ptr.isValid(now)) {
            if (token_ptr.isExpired(now)) {
                self.emitAudit(.{
                    .event_type = .token_expired,
                    .username = token_ptr.username,
                    .email = token_ptr.email,
                    .ip_address = ip_address,
                    .success = false,
                    .details = "Token expired",
                    .timestamp = now,
                });

                return ResetCompleteResult{
                    .success = false,
                    .error_code = .token_expired,
                };
            }

            return ResetCompleteResult{
                .success = false,
                .error_code = .token_used,
            };
        }

        // Validate new password
        const password_valid = self.validatePassword(new_password);
        if (!password_valid.valid) {
            return ResetCompleteResult{
                .success = false,
                .error_code = .weak_password,
            };
        }

        // Hash and update password
        var hasher = password_mod.PasswordHasher.init(self.allocator);
        const password_hash = try hasher.hashPassword(new_password);
        defer self.allocator.free(password_hash);

        self.db.updateUserPassword(token_ptr.username, password_hash) catch |err| {
            self.emitAudit(.{
                .event_type = .reset_failed,
                .username = token_ptr.username,
                .email = token_ptr.email,
                .ip_address = ip_address,
                .success = false,
                .details = "Database update failed",
                .timestamp = now,
            });
            return err;
        };

        // Mark token as used
        token_ptr.used = true;

        // Clear rate limiting for this email
        self.rate_limiter.clearAttempts(token_ptr.email);

        self.emitAudit(.{
            .event_type = .reset_completed,
            .username = token_ptr.username,
            .email = token_ptr.email,
            .ip_address = ip_address,
            .success = true,
            .details = null,
            .timestamp = now,
        });

        return ResetCompleteResult{
            .success = true,
            .error_code = null,
        };
    }

    /// Validate password against policy
    pub fn validatePassword(self: *PasswordResetManager, password: []const u8) PasswordValidation {
        var issues = std.ArrayList([]const u8).init(self.allocator);

        if (password.len < self.config.min_password_length) {
            issues.append("Password too short") catch {};
        }

        if (self.config.require_uppercase) {
            var has_upper = false;
            for (password) |c| {
                if (c >= 'A' and c <= 'Z') {
                    has_upper = true;
                    break;
                }
            }
            if (!has_upper) {
                issues.append("Requires uppercase letter") catch {};
            }
        }

        if (self.config.require_number) {
            var has_number = false;
            for (password) |c| {
                if (c >= '0' and c <= '9') {
                    has_number = true;
                    break;
                }
            }
            if (!has_number) {
                issues.append("Requires number") catch {};
            }
        }

        if (self.config.require_special_char) {
            var has_special = false;
            const special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
            for (password) |c| {
                if (std.mem.indexOfScalar(u8, special_chars, c) != null) {
                    has_special = true;
                    break;
                }
            }
            if (!has_special) {
                issues.append("Requires special character") catch {};
            }
        }

        return PasswordValidation{
            .valid = issues.items.len == 0,
            .issues = issues.toOwnedSlice() catch &[_][]const u8{},
        };
    }

    /// Clean up expired tokens
    pub fn cleanupExpiredTokens(self: *PasswordResetManager) usize {
        const now = std.time.timestamp();
        var removed: usize = 0;

        var iter = self.tokens.iterator();
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired(now) or entry.value_ptr.used) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.tokens.fetchRemove(key)) |entry| {
                self.allocator.free(entry.key);
                var token = entry.value;
                token.deinit(self.allocator);
                removed += 1;
            }
        }

        return removed;
    }

    /// Emit audit event
    fn emitAudit(self: *PasswordResetManager, event: AuditEvent) void {
        if (self.audit_callback) |callback| {
            callback(event);
        }
    }
};

pub const ResetRequestResult = struct {
    success: bool,
    token: ?[32]u8, // Only returned for email sending
    error_code: ?ResetErrorCode,
    retry_after: u32, // seconds
};

pub const ResetCompleteResult = struct {
    success: bool,
    error_code: ?ResetErrorCode,
};

pub const ResetErrorCode = enum {
    rate_limited,
    invalid_token,
    token_expired,
    token_used,
    weak_password,
    user_not_found,
    database_error,
};

pub const PasswordValidation = struct {
    valid: bool,
    issues: []const []const u8,
};

/// Email notification for password reset
pub const ResetEmailNotifier = struct {
    allocator: std.mem.Allocator,
    smtp_host: []const u8,
    smtp_port: u16,
    from_address: []const u8,
    base_url: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        smtp_host: []const u8,
        smtp_port: u16,
        from_address: []const u8,
        base_url: []const u8,
    ) ResetEmailNotifier {
        return .{
            .allocator = allocator,
            .smtp_host = smtp_host,
            .smtp_port = smtp_port,
            .from_address = from_address,
            .base_url = base_url,
        };
    }

    /// Send password reset email
    pub fn sendResetEmail(
        self: *ResetEmailNotifier,
        to_email: []const u8,
        username: []const u8,
        token: [32]u8,
        expiry_minutes: u32,
    ) !void {
        var token_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&token_hex, "{}", .{std.fmt.fmtSliceHexLower(&token)});

        const reset_link = try std.fmt.allocPrint(self.allocator, "{s}/reset-password?token={s}", .{
            self.base_url,
            &token_hex,
        });
        defer self.allocator.free(reset_link);

        const body = try std.fmt.allocPrint(self.allocator,
            \\Hello {s},
            \\
            \\You have requested a password reset for your account.
            \\
            \\Click the link below to reset your password:
            \\{s}
            \\
            \\This link will expire in {d} minutes.
            \\
            \\If you did not request this reset, please ignore this email.
            \\
            \\Security Notice: Never share this link with anyone.
        , .{ username, reset_link, expiry_minutes });
        defer self.allocator.free(body);

        // In a real implementation, this would send via SMTP
        // For now, the body is formatted but not sent
        _ = to_email;
    }

    /// Send confirmation email after password change
    pub fn sendConfirmationEmail(
        self: *ResetEmailNotifier,
        to_email: []const u8,
        username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        const body = try std.fmt.allocPrint(self.allocator,
            \\Hello {s},
            \\
            \\Your password has been successfully changed.
            \\
            \\If you did not make this change, please contact support immediately.
            \\
            \\IP Address: {s}
            \\Time: {d}
        , .{
            username,
            ip_address orelse "Unknown",
            std.time.timestamp(),
        });
        defer self.allocator.free(body);

        // Would send via SMTP - body is formatted but not sent in this stub
        _ = to_email;
    }
};

// Tests
test "rate limiter" {
    const testing = std.testing;

    var limiter = ResetRateLimiter.init(testing.allocator, 3, 60);
    defer limiter.deinit();

    // First 3 attempts should be allowed
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");

    // 4th attempt should be rate limited
    const result = limiter.checkAllowed("test@example.com");
    try testing.expect(!result.allowed);
    try testing.expectEqual(RateLimitResult.RateLimitReason.too_many_attempts, result.reason);
}

test "reset token validation" {
    var token = ResetToken{
        .token = undefined,
        .token_hash = undefined,
        .username = "testuser",
        .email = "test@example.com",
        .created_at = 1000,
        .expires_at = 2000,
        .used = false,
        .ip_address = null,
    };

    // Valid token
    try std.testing.expect(token.isValid(1500));

    // Expired token
    try std.testing.expect(!token.isValid(2500));

    // Used token
    token.used = true;
    try std.testing.expect(!token.isValid(1500));
}
