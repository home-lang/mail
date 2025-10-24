const std = @import("std");
const crypto = std.crypto;

/// Password hashing using Argon2id (more secure than bcrypt, built into Zig std)
pub const PasswordHasher = struct {
    allocator: std.mem.Allocator,

    const hash_len = 32;
    const salt_len = 16;
    const encoded_len = 128; // Enough for argon2id encoded format

    pub fn init(allocator: std.mem.Allocator) PasswordHasher {
        return .{ .allocator = allocator };
    }

    /// Hash a password using Argon2id
    pub fn hashPassword(self: *PasswordHasher, password: []const u8) ![]u8 {
        // Generate random salt
        var salt: [salt_len]u8 = undefined;
        crypto.random.bytes(&salt);

        // Hash the password with Argon2id
        var hash: [hash_len]u8 = undefined;
        try crypto.pwhash.argon2.kdf(
            self.allocator,
            &hash,
            password,
            &salt,
            .{
                .t = 3, // 3 iterations
                .m = 65536, // 64 MB memory
                .p = 4, // 4 parallelism
            },
            .argon2id,
        );

        // Encode salt and hash as base64
        const encoder = std.base64.standard.Encoder;
        const salt_b64_len = encoder.calcSize(salt.len);
        const hash_b64_len = encoder.calcSize(hash.len);

        const salt_b64 = try self.allocator.alloc(u8, salt_b64_len);
        defer self.allocator.free(salt_b64);
        const salt_encoded = encoder.encode(salt_b64, &salt);

        const hash_b64 = try self.allocator.alloc(u8, hash_b64_len);
        defer self.allocator.free(hash_b64);
        const hash_encoded = encoder.encode(hash_b64, &hash);

        // Format: $argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>
        const encoded = try std.fmt.allocPrint(
            self.allocator,
            "$argon2id$v=19$m=65536,t=3,p=4${s}${s}",
            .{ salt_encoded, hash_encoded },
        );

        return encoded;
    }

    /// Verify a password against a hash
    pub fn verifyPassword(self: *PasswordHasher, password: []const u8, hash_str: []const u8) !bool {
        // Parse the hash string
        // Format: $argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>
        var parts = std.mem.splitSequence(u8, hash_str, "$");

        // Skip empty first part
        _ = parts.next();

        // Check algorithm
        const algo = parts.next() orelse return error.InvalidHashFormat;
        if (!std.mem.eql(u8, algo, "argon2id")) {
            return error.UnsupportedAlgorithm;
        }

        // Skip version
        _ = parts.next();

        // Skip parameters
        _ = parts.next();

        // Get salt base64
        const salt_b64 = parts.next() orelse return error.InvalidHashFormat;

        // Get hash base64
        const hash_b64 = parts.next() orelse return error.InvalidHashFormat;

        // Decode salt and hash from base64
        const decoder = std.base64.standard.Decoder;

        var salt: [salt_len]u8 = undefined;
        try decoder.decode(&salt, salt_b64);

        var expected_hash: [hash_len]u8 = undefined;
        try decoder.decode(&expected_hash, hash_b64);

        // Hash the provided password with the same salt
        var computed_hash: [hash_len]u8 = undefined;
        try crypto.pwhash.argon2.kdf(
            self.allocator,
            &computed_hash,
            password,
            &salt,
            .{
                .t = 3,
                .m = 65536,
                .p = 4,
            },
            .argon2id,
        );

        // Constant-time comparison
        return crypto.timing_safe.eql([hash_len]u8, expected_hash, computed_hash);
    }
};

test "password hashing and verification" {
    const testing = std.testing;
    var hasher = PasswordHasher.init(testing.allocator);

    const password = "test_password_123!";

    // Hash the password
    const hash = try hasher.hashPassword(password);
    defer testing.allocator.free(hash);

    // Verify correct password
    try testing.expect(try hasher.verifyPassword(password, hash));

    // Verify incorrect password
    try testing.expect(!try hasher.verifyPassword("wrong_password", hash));
}

test "hash format" {
    const testing = std.testing;
    var hasher = PasswordHasher.init(testing.allocator);

    const password = "test";
    const hash = try hasher.hashPassword(password);
    defer testing.allocator.free(hash);

    // Should start with $argon2id$
    try testing.expect(std.mem.startsWith(u8, hash, "$argon2id$"));
}
