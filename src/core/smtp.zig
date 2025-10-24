const std = @import("std");
const net = std.net;
const config = @import("config.zig");
const auth = @import("../auth/auth.zig");
const database = @import("../storage/database.zig");
const protocol = @import("protocol.zig");
const logger = @import("logger.zig");
const security = @import("../auth/security.zig");
const tls_mod = @import("tls.zig");
const dnsbl = @import("../antispam/dnsbl.zig");
const greylist_mod = @import("../antispam/greylist.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    listener: ?net.Server,
    running: bool,
    logger: *logger.Logger,
    active_connections: std.atomic.Value(u32),
    rate_limiter: security.RateLimiter,
    tls_context: ?tls_mod.TlsContext,
    db: ?*database.Database,
    auth_backend: ?*auth.AuthBackend,
    dnsbl_checker: ?dnsbl.DnsblChecker,
    greylist: ?*greylist_mod.Greylist,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: config.Config,
        log: *logger.Logger,
        db: ?*database.Database,
        auth_backend: ?*auth.AuthBackend,
        greylist: ?*greylist_mod.Greylist,
    ) !Server {
        // Rate limiter: max messages per hour per IP and per user
        const rate_limiter = security.RateLimiter.init(
            allocator,
            3600, // 1 hour window
            cfg.rate_limit_per_ip,
            cfg.rate_limit_per_user,
            cfg.rate_limit_cleanup_interval,
        );

        // Initialize TLS context if enabled
        var tls_ctx: ?tls_mod.TlsContext = null;
        if (cfg.enable_tls) {
            const tls_config = tls_mod.TlsConfig{
                .enabled = true,
                .cert_path = cfg.tls_cert_path,
                .key_path = cfg.tls_key_path,
            };
            tls_ctx = try tls_mod.TlsContext.init(allocator, tls_config, log);
        }

        // Initialize DNSBL checker if enabled
        var dnsbl_checker_opt: ?dnsbl.DnsblChecker = null;
        if (cfg.enable_dnsbl) {
            dnsbl_checker_opt = dnsbl.DnsblChecker.init(allocator, null);
            log.info("DNSBL spam checking enabled with {} blacklists", .{dnsbl.DnsblChecker.DEFAULT_BLACKLISTS.len});
        }

        return Server{
            .allocator = allocator,
            .config = cfg,
            .listener = null,
            .running = false,
            .logger = log,
            .active_connections = std.atomic.Value(u32).init(0),
            .rate_limiter = rate_limiter,
            .tls_context = tls_ctx,
            .db = db,
            .auth_backend = auth_backend,
            .dnsbl_checker = dnsbl_checker_opt,
            .greylist = greylist,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.deinit();
        }
        self.rate_limiter.deinit();
        if (self.tls_context) |*ctx| {
            var tls_ctx = ctx.*;
            tls_ctx.deinit();
        }
        self.logger.info("Server cleanup complete", .{});
    }

    pub fn start(self: *Server, shutdown_flag: *std.atomic.Value(bool)) !void {
        const address = try net.Address.parseIp(self.config.host, self.config.port);

        self.listener = try address.listen(.{
            .reuse_address = true,
        });

        self.running = true;

        self.logger.info("SMTP Server listening on {s}:{d}", .{ self.config.host, self.config.port });

        while (self.running and !shutdown_flag.load(.acquire)) {
            // Accept with timeout to allow checking shutdown flag
            const connection = self.listener.?.accept() catch |err| {
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    std.Thread.sleep(100 * std.time.ns_per_ms);
                    continue;
                }
                self.logger.err("Error accepting connection: {}", .{err});
                continue;
            };

            // Check connection limits
            const current_connections = self.active_connections.load(.monotonic);
            if (current_connections >= self.config.max_connections) {
                self.logger.warn("Max connections ({d}) reached, rejecting new connection", .{self.config.max_connections});
                _ = connection.stream.write("421 Too many connections, try again later\r\n") catch {};
                connection.stream.close();
                continue;
            }

            _ = self.active_connections.fetchAdd(1, .monotonic);

            // Get remote address for logging
            const remote_addr = connection.address;
            var addr_buf: [64]u8 = undefined;
            const addr_str = std.fmt.bufPrint(&addr_buf, "{any}", .{remote_addr}) catch "unknown";

            self.logger.logConnection(addr_str, "connected");

            // Check DNSBL if enabled
            if (self.dnsbl_checker) |*checker| {
                const is_blacklisted = checker.isBlacklisted(addr_str) catch false;
                if (is_blacklisted) {
                    self.logger.warn("Connection from {s} rejected - IP blacklisted in DNSBL", .{addr_str});
                    _ = self.active_connections.fetchSub(1, .monotonic);
                    connection.stream.close();
                    continue;
                }
            }

            // Handle connection in a new thread for concurrent processing
            const ctx = ConnectionContext{
                .server = self,
                .connection = connection,
                .remote_addr = addr_str,
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ctx}) catch |err| {
                self.logger.err("Failed to spawn connection handler: {}", .{err});
                _ = self.active_connections.fetchSub(1, .monotonic);
                connection.stream.close();
                continue;
            };
            thread.detach();
        }

        self.logger.info("Server shutting down gracefully...", .{});

        // Wait for active connections to finish (with timeout)
        var wait_count: u32 = 0;
        while (self.active_connections.load(.monotonic) > 0 and wait_count < 100) : (wait_count += 1) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }

        const remaining = self.active_connections.load(.monotonic);
        if (remaining > 0) {
            self.logger.warn("Shutdown timeout: {d} connections still active", .{remaining});
        } else {
            self.logger.info("All connections closed gracefully", .{});
        }
    }

    const ConnectionContext = struct {
        server: *Server,
        connection: net.Server.Connection,
        remote_addr: []const u8,
    };

    fn handleConnection(ctx: ConnectionContext) void {
        defer ctx.connection.stream.close();
        defer _ = ctx.server.active_connections.fetchSub(1, .monotonic);

        // Get pointer to TLS context if it exists
        var tls_ctx_ptr: ?*tls_mod.TlsContext = null;
        if (ctx.server.tls_context) |*tls_ctx| {
            tls_ctx_ptr = tls_ctx;
        }

        var session = protocol.Session.init(
            ctx.server.allocator,
            ctx.connection,
            ctx.server.config,
            ctx.server.logger,
            ctx.remote_addr,
            &ctx.server.rate_limiter,
            tls_ctx_ptr,
            ctx.server.auth_backend,
            ctx.server.greylist,
        ) catch |err| {
            ctx.server.logger.err("Failed to initialize session from {s}: {}", .{ ctx.remote_addr, err });
            return;
        };
        defer session.deinit();

        session.handle() catch |err| {
            ctx.server.logger.err("Session error from {s}: {}", .{ ctx.remote_addr, err });
        };

        ctx.server.logger.logConnection(ctx.remote_addr, "disconnected");
    }
};
