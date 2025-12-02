const std = @import("std");
const smtp = @import("core/smtp.zig");
const config = @import("core/config.zig");
const logger = @import("core/logger.zig");
const args_parser = @import("core/args.zig");
const database = @import("storage/database.zig");
const auth = @import("auth/auth.zig");
const greylist_mod = @import("antispam/greylist.zig");

// Cluster and multi-tenancy support
const cluster = @import("infrastructure/cluster.zig");
const multitenancy = @import("features/multitenancy.zig");
const metrics_mod = @import("observability/metrics.zig");
const alerting = @import("observability/alerting.zig");
const secrets = @import("security/secrets.zig");
const hot_reload = @import("core/hot_reload.zig");

// Global shutdown flag
var shutdown_requested = std.atomic.Value(bool).init(false);

// Global reload flag for SIGHUP
var reload_requested = std.atomic.Value(bool).init(false);

// Global reload manager pointer for callback
var global_reload_manager: ?*hot_reload.HotReloadManager = null;

fn reloadConfigCallback() void {
    if (global_reload_manager) |manager| {
        _ = manager.checkAndReload(&reload_requested);
    }
}

fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    shutdown_requested.store(true, .release);
}

fn reloadHandler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    reload_requested.store(true, .release);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    var cli_args = args_parser.parseArgs(allocator) catch |err| {
        if (err != error.UnknownArgument) {
            args_parser.printHelp();
        }
        return err;
    };
    defer cli_args.deinit(allocator);

    // Handle --help
    if (cli_args.help) {
        args_parser.printHelp();
        return;
    }

    // Handle --version
    if (cli_args.version) {
        args_parser.printVersion();
        return;
    }

    // Load configuration first (with CLI args and env vars)
    // Configuration validation is automatically performed during loading
    // Using var to allow hot reload to update configuration
    var cfg = config.loadConfig(allocator, cli_args) catch |err| {
        std.debug.print("Configuration validation failed: {}\n", .{err});
        return err;
    };
    defer cfg.deinit(allocator);

    // Initialize logger with configuration settings
    const log_level = cli_args.log_level orelse .info;
    const log_file = cli_args.log_file orelse "smtp-server.log";
    const log_format: logger.LogFormat = if (cfg.enable_json_logging) .json else .text;
    var log = try logger.Logger.initWithFormat(allocator, log_level, log_file, log_format);
    defer log.deinit();
    logger.setGlobalLogger(&log);

    log.info("=== SMTP Server Starting ===", .{});

    log.info("Configuration loaded and validated successfully:", .{});
    log.info("  Host: {s}:{d}", .{ cfg.host, cfg.port });
    log.info("  Max connections: {d}", .{cfg.max_connections});
    log.info("  TLS enabled: {}", .{cfg.enable_tls});
    log.info("  Auth enabled: {}", .{cfg.enable_auth});
    log.info("  Max message size: {d} bytes", .{cfg.max_message_size});

    // Handle --validate-only flag
    if (cli_args.validate_only) {
        std.debug.print("\n✓ Configuration validation successful!\n", .{});
        std.debug.print("All configuration values are within acceptable ranges.\n", .{});
        return;
    }

    // Setup signal handlers for graceful shutdown and hot reload
    const empty_set = std.posix.sigemptyset();

    const shutdown_act = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = empty_set,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &shutdown_act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &shutdown_act, null);

    // Setup SIGHUP for configuration hot reload
    const reload_act = std.posix.Sigaction{
        .handler = .{ .handler = reloadHandler },
        .mask = empty_set,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &reload_act, null);

    log.info("Signal handlers installed (SIGINT, SIGTERM for shutdown, SIGHUP for reload)", .{});

    // Initialize hot reload manager
    var reload_manager = hot_reload.HotReloadManager.init(allocator, &cfg, cli_args.config_file);
    defer reload_manager.deinit();
    global_reload_manager = &reload_manager;
    defer global_reload_manager = null;
    log.info("Hot reload manager initialized (send SIGHUP to reload configuration)", .{});

    // Initialize database and auth backend if auth is enabled
    var db: ?database.Database = null;
    var auth_backend: ?auth.AuthBackend = null;
    var db_ptr: ?*database.Database = null;
    var auth_ptr: ?*auth.AuthBackend = null;

    if (cfg.enable_auth) {
        const db_path = std.posix.getenv("SMTP_DB_PATH") orelse "./smtp.db";
        log.info("Initializing database at: {s}", .{db_path});

        db = try database.Database.init(allocator, db_path);
        errdefer if (db) |*d| d.deinit();

        db_ptr = &db.?;
        auth_backend = auth.AuthBackend.init(allocator, db_ptr.?);
        auth_ptr = &auth_backend.?;

        log.info("Database-backed authentication enabled", .{});
    } else {
        log.info("Authentication disabled", .{});
    }

    defer if (db) |*d| d.deinit();

    // Initialize greylisting if enabled
    var greylist: ?greylist_mod.Greylist = null;
    var greylist_ptr: ?*greylist_mod.Greylist = null;

    if (cfg.enable_greylist) {
        greylist = greylist_mod.Greylist.init(allocator);
        greylist_ptr = &greylist.?;
        log.info("Greylisting enabled (5 min delay, 4 hour retry window)", .{});
    }

    defer if (greylist) |*g| g.deinit();

    // Initialize metrics collection
    var smtp_metrics: ?metrics_mod.SmtpMetrics = null;
    const statsd_host = std.posix.getenv("STATSD_HOST");
    const statsd_port: u16 = blk: {
        const port_str = std.posix.getenv("STATSD_PORT") orelse "8125";
        break :blk std.fmt.parseInt(u16, port_str, 10) catch 8125;
    };

    if (statsd_host != null or std.posix.getenv("SMTP_METRICS_ENABLED") != null) {
        smtp_metrics = try metrics_mod.SmtpMetrics.init(allocator, statsd_host, statsd_port, "smtp");
        log.info("Metrics collection enabled (StatsD: {s}:{d})", .{ statsd_host orelse "local-only", statsd_port });
    }
    defer if (smtp_metrics) |*m| m.deinit();

    // Initialize alerting
    var alert_manager: ?alerting.AlertManager = null;
    if (std.posix.getenv("SMTP_ALERTING_ENABLED") != null) {
        alert_manager = alerting.AlertManager.init(allocator);

        // Configure Slack if webhook URL is provided
        if (std.posix.getenv("SLACK_WEBHOOK_URL")) |webhook_url| {
            try alert_manager.?.addSlackChannel(.{
                .webhook_url = webhook_url,
                .channel = std.posix.getenv("SLACK_CHANNEL"),
            });
            log.info("Slack alerting enabled", .{});
        }

        // Add default alert rules
        var default_rules = try alerting.createDefaultRules(allocator);
        defer default_rules.deinit(allocator);
        for (default_rules.items) |rule| {
            try alert_manager.?.addRule(rule);
        }

        log.info("Alerting enabled with {d} default rules", .{alert_manager.?.rules.items.len});
    }
    defer if (alert_manager) |*a| a.deinit();

    // Initialize secret manager
    var secret_manager: ?secrets.SecretManager = null;
    const secret_backend_str = std.posix.getenv("SECRET_BACKEND") orelse "environment";
    if (!std.mem.eql(u8, secret_backend_str, "none")) {
        secret_manager = secrets.SecretManager.init(allocator, .environment);

        if (std.mem.eql(u8, secret_backend_str, "kubernetes")) {
            secret_manager.?.configureKubernetes(.{
                .secrets_path = std.posix.getenv("K8S_SECRETS_PATH") orelse "/var/run/secrets",
            });
        } else if (std.mem.eql(u8, secret_backend_str, "vault")) {
            if (std.posix.getenv("VAULT_ADDR")) |vault_addr| {
                try secret_manager.?.configureVault(.{
                    .address = vault_addr,
                    .token = std.posix.getenv("VAULT_TOKEN"),
                });
            }
        }

        log.info("Secret management enabled (backend: {s})", .{secret_backend_str});
    }
    defer if (secret_manager) |*s| s.deinit();

    // Initialize cluster mode if enabled
    var cluster_manager: ?*cluster.ClusterManager = null;
    const enable_cluster = std.posix.getenv("SMTP_CLUSTER_ENABLED") != null;

    if (enable_cluster) {
        const node_id = std.posix.getenv("SMTP_NODE_ID") orelse "node-1";
        const cluster_port: u16 = blk: {
            const port_str = std.posix.getenv("SMTP_CLUSTER_PORT") orelse "9000";
            break :blk std.fmt.parseInt(u16, port_str, 10) catch 9000;
        };
        const enable_raft = std.posix.getenv("SMTP_RAFT_DISABLED") == null;

        const cluster_config = cluster.ClusterConfig{
            .node_id = node_id,
            .bind_address = cfg.host,
            .bind_port = cluster_port,
            .peers = &[_][]const u8{}, // Peers configured via env or discovery
            .enable_raft = enable_raft,
        };

        cluster_manager = try cluster.ClusterManager.init(allocator, cluster_config);
        try cluster_manager.?.start();

        log.info("Cluster mode enabled - Node ID: {s}, Port: {d}, Raft: {}", .{
            node_id,
            cluster_port,
            enable_raft,
        });
    }
    defer if (cluster_manager) |cm| cm.deinit();

    // Initialize multi-tenancy if enabled
    // Note: MultiTenancyManager requires a TenantDB - disabled for now
    const tenant_manager: ?*multitenancy.MultiTenancyManager = null;
    if (std.posix.getenv("SMTP_MULTITENANCY_ENABLED") != null) {
        log.info("Multi-tenancy requested but not yet configured", .{});
    }
    // tenant_manager is used in logging below

    // Create and start SMTP server
    var server = try smtp.Server.init(allocator, cfg, &log, db_ptr, auth_ptr, greylist_ptr);
    defer server.deinit();

    // Log startup summary
    log.info("Starting SMTP server...", .{});
    log.info("  Cluster mode: {}", .{enable_cluster});
    log.info("  Multi-tenancy: {}", .{tenant_manager != null});
    log.info("  Metrics: {}", .{smtp_metrics != null});
    log.info("  Alerting: {}", .{alert_manager != null});

    server.startWithReload(&shutdown_requested, &reload_requested, reloadConfigCallback) catch |err| {
        log.critical("Server error: {}", .{err});
        return err;
    };

    // Cleanup
    if (cluster_manager) |cm| {
        cm.stop();
        log.info("Cluster manager stopped", .{});
    }

    log.info("=== SMTP Server Shutdown Complete ===", .{});
}
