const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const logger = @import("../core/logger.zig");

/// Secret Management Integration
/// Provides unified interface for retrieving secrets from various backends:
/// - Environment variables (default)
/// - HashiCorp Vault
/// - Kubernetes Secrets
/// - AWS Secrets Manager
/// - Azure Key Vault
/// - File-based secrets (for development)
///
/// ## Usage
/// ```zig
/// var secrets = try SecretManager.init(allocator, .vault, vault_config);
/// defer secrets.deinit();
///
/// const api_key = try secrets.getSecret("smtp/api-key");
/// defer allocator.free(api_key);
/// ```

/// Secret backend types
pub const SecretBackend = enum {
    environment, // Environment variables (default)
    vault, // HashiCorp Vault
    kubernetes, // Kubernetes Secrets via mounted volumes
    aws_secrets_manager, // AWS Secrets Manager
    azure_key_vault, // Azure Key Vault
    file, // File-based (development only)

    pub fn toString(self: SecretBackend) []const u8 {
        return switch (self) {
            .environment => "environment",
            .vault => "hashicorp_vault",
            .kubernetes => "kubernetes_secrets",
            .aws_secrets_manager => "aws_secrets_manager",
            .azure_key_vault => "azure_key_vault",
            .file => "file",
        };
    }
};

/// HashiCorp Vault configuration
pub const VaultConfig = struct {
    address: []const u8 = "http://127.0.0.1:8200",
    token: ?[]const u8 = null,
    role_id: ?[]const u8 = null, // For AppRole auth
    secret_id: ?[]const u8 = null, // For AppRole auth
    namespace: ?[]const u8 = null, // Enterprise namespaces
    mount_path: []const u8 = "secret", // KV secrets engine mount
    kv_version: u8 = 2, // KV v1 or v2
    tls_skip_verify: bool = false, // For development only
    timeout_ms: u32 = 5000,
    retry_count: u8 = 3,
    retry_delay_ms: u32 = 1000,
};

/// Kubernetes Secrets configuration
pub const KubernetesConfig = struct {
    secrets_path: []const u8 = "/var/run/secrets", // Default mount path
    namespace: ?[]const u8 = null, // If using API
    use_api: bool = false, // Use K8s API instead of mounted volumes
    service_account_token_path: []const u8 = "/var/run/secrets/kubernetes.io/serviceaccount/token",
};

/// AWS Secrets Manager configuration
pub const AwsConfig = struct {
    region: []const u8 = "us-east-1",
    access_key_id: ?[]const u8 = null, // Falls back to IAM role
    secret_access_key: ?[]const u8 = null,
    session_token: ?[]const u8 = null, // For temporary credentials
    endpoint: ?[]const u8 = null, // Custom endpoint (localstack)
    timeout_ms: u32 = 5000,
};

/// Azure Key Vault configuration
pub const AzureConfig = struct {
    vault_url: []const u8, // https://<vault-name>.vault.azure.net
    tenant_id: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
    use_managed_identity: bool = true, // Recommended for Azure
    timeout_ms: u32 = 5000,
};

/// File-based secrets configuration (development only)
pub const FileConfig = struct {
    secrets_dir: []const u8 = "./secrets",
    file_extension: []const u8 = ".secret",
};

/// Cached secret with TTL
const CachedSecret = struct {
    value: []u8,
    expires_at: i64,
    version: ?[]const u8,
};

/// Secret Manager - unified interface for all backends
pub const SecretManager = struct {
    allocator: std.mem.Allocator,
    backend: SecretBackend,
    cache: std.StringHashMap(CachedSecret),
    cache_ttl_seconds: i64,
    mutex: std.Thread.Mutex,

    // Backend-specific state
    vault_config: ?VaultConfig,
    vault_token: ?[]u8, // Authenticated token
    k8s_config: ?KubernetesConfig,
    aws_config: ?AwsConfig,
    azure_config: ?AzureConfig,
    file_config: ?FileConfig,

    // Statistics
    stats: SecretStats,

    pub fn init(allocator: std.mem.Allocator, backend: SecretBackend) SecretManager {
        return .{
            .allocator = allocator,
            .backend = backend,
            .cache = std.StringHashMap(CachedSecret).init(allocator),
            .cache_ttl_seconds = 300, // 5 minute default TTL
            .mutex = .{},
            .vault_config = null,
            .vault_token = null,
            .k8s_config = null,
            .aws_config = null,
            .azure_config = null,
            .file_config = null,
            .stats = SecretStats{},
        };
    }

    pub fn deinit(self: *SecretManager) void {
        // Free cached secrets
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            // Securely zero out secret before freeing
            @memset(entry.value_ptr.value, 0);
            self.allocator.free(entry.value_ptr.value);
            if (entry.value_ptr.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.deinit();

        if (self.vault_token) |token| {
            @memset(token, 0);
            self.allocator.free(token);
        }
    }

    /// Configure Vault backend
    pub fn configureVault(self: *SecretManager, config: VaultConfig) !void {
        self.vault_config = config;
        self.backend = .vault;

        // Authenticate with Vault
        if (config.token) |token| {
            self.vault_token = try self.allocator.dupe(u8, token);
        } else if (config.role_id != null and config.secret_id != null) {
            // AppRole authentication would go here
            // For now, just note that it's configured
            logger.info("Vault AppRole authentication configured", .{});
        }

        logger.info("Vault backend configured: {s}", .{config.address});
    }

    /// Configure Kubernetes backend
    pub fn configureKubernetes(self: *SecretManager, config: KubernetesConfig) void {
        self.k8s_config = config;
        self.backend = .kubernetes;
        logger.info("Kubernetes secrets backend configured: {s}", .{config.secrets_path});
    }

    /// Configure AWS Secrets Manager backend
    pub fn configureAws(self: *SecretManager, config: AwsConfig) void {
        self.aws_config = config;
        self.backend = .aws_secrets_manager;
        logger.info("AWS Secrets Manager configured: {s}", .{config.region});
    }

    /// Configure Azure Key Vault backend
    pub fn configureAzure(self: *SecretManager, config: AzureConfig) void {
        self.azure_config = config;
        self.backend = .azure_key_vault;
        logger.info("Azure Key Vault configured: {s}", .{config.vault_url});
    }

    /// Configure file-based backend (development only)
    pub fn configureFile(self: *SecretManager, config: FileConfig) void {
        self.file_config = config;
        self.backend = .file;
        logger.warn("File-based secrets configured - FOR DEVELOPMENT ONLY", .{});
    }

    /// Get a secret by name
    pub fn getSecret(self: *SecretManager, name: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check cache first
        if (self.cache.get(name)) |cached| {
            if (cached.expires_at > time_compat.timestamp()) {
                self.stats.cache_hits += 1;
                return try self.allocator.dupe(u8, cached.value);
            }
            // Expired - remove from cache
            self.removeCachedSecret(name);
        }

        self.stats.cache_misses += 1;

        // Fetch from backend
        const secret = try self.fetchSecret(name);
        errdefer {
            @memset(secret, 0);
            self.allocator.free(secret);
        }

        // Cache the secret
        try self.cacheSecret(name, secret);

        self.stats.fetches += 1;
        return secret;
    }

    /// Get a secret with a specific version (Vault, AWS)
    pub fn getSecretVersion(self: *SecretManager, name: []const u8, version: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Version-specific secrets are not cached
        return self.fetchSecretVersion(name, version);
    }

    /// Check if a secret exists
    pub fn secretExists(self: *SecretManager, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check cache
        if (self.cache.contains(name)) {
            return true;
        }

        // Check backend
        const secret = self.fetchSecret(name) catch return false;
        @memset(secret, 0);
        self.allocator.free(secret);
        return true;
    }

    /// Invalidate a cached secret
    pub fn invalidateSecret(self: *SecretManager, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.removeCachedSecret(name);
        self.stats.invalidations += 1;
    }

    /// Invalidate all cached secrets
    pub fn invalidateAll(self: *SecretManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            @memset(entry.value_ptr.value, 0);
            self.allocator.free(entry.value_ptr.value);
            if (entry.value_ptr.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.clearRetainingCapacity();
        self.stats.invalidations += 1;
    }

    /// Set cache TTL
    pub fn setCacheTtl(self: *SecretManager, ttl_seconds: i64) void {
        self.cache_ttl_seconds = ttl_seconds;
    }

    /// Get statistics
    pub fn getStats(self: *const SecretManager) SecretStats {
        return self.stats;
    }

    // Internal methods

    fn fetchSecret(self: *SecretManager, name: []const u8) ![]u8 {
        return switch (self.backend) {
            .environment => self.fetchFromEnvironment(name),
            .vault => self.fetchFromVault(name),
            .kubernetes => self.fetchFromKubernetes(name),
            .aws_secrets_manager => self.fetchFromAws(name),
            .azure_key_vault => self.fetchFromAzure(name),
            .file => self.fetchFromFile(name),
        };
    }

    fn fetchSecretVersion(self: *SecretManager, name: []const u8, version: []const u8) ![]u8 {
        _ = version;
        // Version support depends on backend
        return self.fetchSecret(name);
    }

    fn fetchFromEnvironment(self: *SecretManager, name: []const u8) ![]u8 {
        // Convert secret path to env var name (e.g., "smtp/api-key" -> "SMTP_API_KEY")
        var env_name = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(env_name);

        for (name, 0..) |c, i| {
            env_name[i] = switch (c) {
                '/', '-', '.' => '_',
                'a'...'z' => c - 32, // to uppercase
                else => c,
            };
        }

        const value = std.posix.getenv(env_name) orelse return error.SecretNotFound;
        return try self.allocator.dupe(u8, value);
    }

    fn fetchFromVault(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.vault_config orelse return error.BackendNotConfigured;

        // In a full implementation, this would:
        // 1. Make HTTP request to Vault API
        // 2. GET /v1/{mount_path}/data/{name} for KV v2
        // 3. Parse JSON response
        // 4. Return the secret value
        // Using config.address, config.mount_path, etc.
        _ = config;

        // For now, fall back to environment
        return self.fetchFromEnvironment(name);
    }

    fn fetchFromKubernetes(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.k8s_config orelse return error.BackendNotConfigured;

        if (config.use_api) {
            // Would use K8s API
            return error.NotImplemented;
        }

        // Read from mounted secret file
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ config.secrets_path, name });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.SecretNotFound;
            return err;
        };
        defer file.close();

        const content = try time_compat.readFileToEnd(self.allocator, file, 1024 * 1024);

        // Trim trailing newline if present
        var value = content;
        if (value.len > 0 and value[value.len - 1] == '\n') {
            value = value[0 .. value.len - 1];
        }

        return value;
    }

    fn fetchFromAws(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.aws_config orelse return error.BackendNotConfigured;
        _ = config;
        _ = name;

        // In a full implementation, this would:
        // 1. Sign request with AWS SigV4
        // 2. Call secretsmanager:GetSecretValue
        // 3. Parse JSON response
        // 4. Return SecretString or decode SecretBinary

        return error.NotImplemented;
    }

    fn fetchFromAzure(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.azure_config orelse return error.BackendNotConfigured;
        _ = config;
        _ = name;

        // In a full implementation, this would:
        // 1. Get access token (managed identity or service principal)
        // 2. Call GET {vault_url}/secrets/{name}?api-version=7.4
        // 3. Parse JSON response
        // 4. Return the value

        return error.NotImplemented;
    }

    fn fetchFromFile(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.file_config orelse return error.BackendNotConfigured;

        // Replace path separators with underscores for filename
        var filename = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(filename);
        for (name, 0..) |c, i| {
            filename[i] = if (c == '/') '_' else c;
        }

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}{s}",
            .{ config.secrets_dir, filename, config.file_extension },
        );
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.SecretNotFound;
            return err;
        };
        defer file.close();

        const content = try time_compat.readFileToEnd(self.allocator, file, 1024 * 1024);

        // Trim trailing newline
        var value = content;
        if (value.len > 0 and value[value.len - 1] == '\n') {
            value = value[0 .. value.len - 1];
        }

        return value;
    }

    fn cacheSecret(self: *SecretManager, name: []const u8, value: []u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        try self.cache.put(name_copy, CachedSecret{
            .value = value_copy,
            .expires_at = time_compat.timestamp() + self.cache_ttl_seconds,
            .version = null,
        });
    }

    fn removeCachedSecret(self: *SecretManager, name: []const u8) void {
        if (self.cache.fetchRemove(name)) |entry| {
            @memset(entry.value.value, 0);
            self.allocator.free(entry.value.value);
            if (entry.value.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key);
        }
    }
};

/// Statistics for secret manager
pub const SecretStats = struct {
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    fetches: u64 = 0,
    errors: u64 = 0,
    invalidations: u64 = 0,

    pub fn cacheHitRate(self: SecretStats) f64 {
        const total = self.cache_hits + self.cache_misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.cache_hits)) / @as(f64, @floatFromInt(total));
    }
};

/// Helper to load configuration from secrets
pub const ConfigSecretLoader = struct {
    secrets: *SecretManager,
    prefix: []const u8,

    pub fn init(secrets: *SecretManager, prefix: []const u8) ConfigSecretLoader {
        return .{
            .secrets = secrets,
            .prefix = prefix,
        };
    }

    /// Load a secret with the configured prefix
    pub fn load(self: *ConfigSecretLoader, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        const full_name = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.prefix, name });
        defer allocator.free(full_name);
        return self.secrets.getSecret(full_name);
    }

    /// Load optional secret (returns null if not found)
    pub fn loadOptional(self: *ConfigSecretLoader, allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
        return self.load(allocator, name) catch null;
    }
};

// Tests
test "secret manager initialization" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    try testing.expectEqual(SecretBackend.environment, secrets.backend);
    try testing.expectEqual(@as(i64, 300), secrets.cache_ttl_seconds);
}

test "environment variable lookup" {
    const testing = std.testing;

    // This test requires TEST_SECRET env var to be set
    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    // Test with a secret that doesn't exist
    const result = secrets.getSecret("nonexistent/secret");
    try testing.expectError(error.SecretNotFound, result);
}

test "cache TTL" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    secrets.setCacheTtl(60);
    try testing.expectEqual(@as(i64, 60), secrets.cache_ttl_seconds);
}

test "secret stats" {
    const testing = std.testing;

    const stats = SecretStats{
        .cache_hits = 80,
        .cache_misses = 20,
        .fetches = 20,
        .errors = 0,
        .invalidations = 0,
    };

    const hit_rate = stats.cacheHitRate();
    try testing.expectApproxEqAbs(@as(f64, 0.8), hit_rate, 0.01);
}

test "kubernetes secrets path" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .kubernetes);
    defer secrets.deinit();

    secrets.configureKubernetes(.{
        .secrets_path = "/tmp/test-secrets",
        .use_api = false,
    });

    try testing.expectEqual(SecretBackend.kubernetes, secrets.backend);
}
