const std = @import("std");
const posix = std.posix;
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const tls = @import("tls");

/// CalDAV/CardDAV Server Implementation
/// RFC 4791 (CalDAV) and RFC 6352 (CardDAV)
///
/// Provides calendar and contact synchronization over WebDAV

// ============================================================================
// Configuration
// ============================================================================

pub const CalDavConfig = struct {
    port: u16 = 8008,
    ssl_port: u16 = 8443,
    enable_ssl: bool = true,
    max_connections: usize = 100,
    connection_timeout_seconds: u64 = 300,
    max_resource_size: usize = 10 * 1024 * 1024, // 10 MB
    calendar_path: []const u8 = "/var/spool/caldav/calendars",
    contacts_path: []const u8 = "/var/spool/caldav/contacts",
    enable_caldav: bool = true,
    enable_carddav: bool = true,
    // TLS configuration
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
};

// ============================================================================
// HTTP Methods
// ============================================================================

pub const HttpMethod = enum {
    get,
    put,
    post,
    delete,
    options,
    propfind,
    proppatch,
    mkcalendar,
    report,
    mkcol,
    move,
    copy,

    pub fn fromString(method: []const u8) ?HttpMethod {
        const upper = std.ascii.allocUpperString(std.heap.page_allocator, method) catch return null;
        defer std.heap.page_allocator.free(upper);

        const methods = std.StaticStringMap(HttpMethod).initComptime(.{
            .{ "GET", .get },
            .{ "PUT", .put },
            .{ "POST", .post },
            .{ "DELETE", .delete },
            .{ "OPTIONS", .options },
            .{ "PROPFIND", .propfind },
            .{ "PROPPATCH", .proppatch },
            .{ "MKCALENDAR", .mkcalendar },
            .{ "REPORT", .report },
            .{ "MKCOL", .mkcol },
            .{ "MOVE", .move },
            .{ "COPY", .copy },
        });
        return methods.get(upper);
    }
};

// ============================================================================
// CalDAV/CardDAV Session
// ============================================================================

pub const CalDavSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    username: ?[]const u8 = null,
    authenticated: bool = false,
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, auth_backend: *auth.AuthBackend) CalDavSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *CalDavSession) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
    }

    /// Handle incoming HTTP request
    pub fn handleRequest(self: *CalDavSession, config: *const CalDavConfig) !bool {
        var buffer: [8192]u8 = undefined;
        const bytes_read = self.connection.read(&buffer) catch return false;

        if (bytes_read == 0) {
            return false; // Connection closed
        }

        const request = buffer[0..bytes_read];

        // Parse HTTP request line
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return false;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_str = parts.next() orelse return false;
        const path = parts.next() orelse return false;

        const method = HttpMethod.fromString(method_str) orelse {
            try self.sendError(405, "Method Not Allowed");
            return true;
        };

        // Handle .well-known autodiscovery BEFORE authentication (per RFC 5785)
        if (std.mem.startsWith(u8, path, "/.well-known/caldav")) {
            try self.sendWellKnownRedirect("/calendars/");
            return true;
        }
        if (std.mem.startsWith(u8, path, "/.well-known/carddav")) {
            try self.sendWellKnownRedirect("/addressbooks/");
            return true;
        }

        // Check authentication (Digest or Basic Auth)
        if (!self.authenticated) {
            var auth_header: ?[]const u8 = null;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
                if (trimmed.len == 0) break;

                if (std.mem.startsWith(u8, trimmed, "Authorization:")) {
                    auth_header = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);
                    break;
                }
            }

            if (auth_header == null) {
                try self.sendAuthRequired();
                return true;
            }

            // Try Digest auth first, then fall back to Basic
            var validated_username: ?[]const u8 = null;

            if (std.mem.startsWith(u8, auth_header.?, "Digest ")) {
                validated_username = self.auth_backend.verifyDigestAuth(
                    auth_header.?,
                    method_str,
                    "CalDAV/CardDAV Server",
                ) catch |err| blk: {
                    logger.err("CalDAV Digest authentication error: {}", .{err});
                    break :blk null;
                };
            }

            // Fall back to Basic auth if Digest didn't work
            if (validated_username == null and std.mem.startsWith(u8, auth_header.?, "Basic ")) {
                validated_username = self.auth_backend.verifyBasicAuth(auth_header.?) catch |err| blk: {
                    logger.err("CalDAV Basic authentication error: {}", .{err});
                    break :blk null;
                };
            }

            if (validated_username) |username| {
                self.authenticated = true;
                self.username = username;
                logger.info("Successful CalDAV authentication for user: {s}", .{username});
            } else {
                logger.warn("Failed CalDAV authentication attempt", .{});
                try self.sendAuthRequired();
                return true;
            }
        }

        // Route request based on method and path
        try self.routeRequest(method, path, request, config);

        return true;
    }

    /// Route request to appropriate handler
    fn routeRequest(
        self: *CalDavSession,
        method: HttpMethod,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        // Handle .well-known autodiscovery
        if (std.mem.startsWith(u8, path, "/.well-known/caldav")) {
            try self.sendWellKnownRedirect("/calendars/");
            return;
        }
        if (std.mem.startsWith(u8, path, "/.well-known/carddav")) {
            try self.sendWellKnownRedirect("/addressbooks/");
            return;
        }

        switch (method) {
            .options => try self.handleOptions(path),
            .propfind => try self.handlePropfind(path, request, config),
            .get => try self.handleGet(path, config),
            .put => try self.handlePut(path, request, config),
            .delete => try self.handleDelete(path, config),
            .mkcalendar => try self.handleMkcalendar(path, config),
            .mkcol => try self.handleMkcol(path, config),
            .report => try self.handleReport(path, request, config),
            else => try self.sendError(501, "Not Implemented"),
        }
    }

    /// Send .well-known redirect
    fn sendWellKnownRedirect(self: *CalDavSession, location: []const u8) !void {
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n",
            .{location},
        );
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Handle OPTIONS request (WebDAV/CalDAV/CardDAV capabilities)
    fn handleOptions(self: *CalDavSession, path: []const u8) !void {
        _ = path;

        const response =
            "HTTP/1.1 200 OK\r\n" ++
            "DAV: 1, 2, 3, calendar-access, addressbook\r\n" ++
            "Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT\r\n" ++
            "Content-Length: 0\r\n\r\n";

        _ = try self.connection.write(response);
    }

    /// Handle PROPFIND request (property discovery)
    fn handlePropfind(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;
        _ = request;

        // Check if this is an addressbook (CardDAV) or calendar (CalDAV) request
        const is_addressbook = std.mem.startsWith(u8, path, "/addressbooks");

        // Build XML response
        var response_body: [4096]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&response_body);
        const writer = fbs.writer();

        if (is_addressbook) {
            // CardDAV response for addressbooks
            try writer.writeAll(
                \\<?xml version="1.0" encoding="utf-8" ?>
                \\<D:multistatus xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
                \\  <D:response>
                \\    <D:href>
            );
            try writer.writeAll(path);
            try writer.writeAll(
                \\</D:href>
                \\    <D:propstat>
                \\      <D:prop>
                \\        <D:resourcetype>
                \\          <D:collection/>
                \\          <CARD:addressbook/>
                \\        </D:resourcetype>
                \\        <D:displayname>Contacts</D:displayname>
                \\        <CARD:supported-address-data>
                \\          <CARD:address-data-type content-type="text/vcard" version="3.0"/>
                \\          <CARD:address-data-type content-type="text/vcard" version="4.0"/>
                \\        </CARD:supported-address-data>
                \\      </D:prop>
                \\      <D:status>HTTP/1.1 200 OK</D:status>
                \\    </D:propstat>
                \\  </D:response>
                \\</D:multistatus>
            );
        } else {
            // CalDAV response for calendars
            try writer.writeAll(
                \\<?xml version="1.0" encoding="utf-8" ?>
                \\<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
                \\  <D:response>
                \\    <D:href>
            );
            try writer.writeAll(path);
            try writer.writeAll(
                \\</D:href>
                \\    <D:propstat>
                \\      <D:prop>
                \\        <D:resourcetype>
                \\          <D:collection/>
                \\          <C:calendar/>
                \\        </D:resourcetype>
                \\        <D:displayname>Calendar</D:displayname>
                \\        <C:supported-calendar-component-set>
                \\          <C:comp name="VEVENT"/>
                \\          <C:comp name="VTODO"/>
                \\        </C:supported-calendar-component-set>
                \\      </D:prop>
                \\      <D:status>HTTP/1.1 200 OK</D:status>
                \\    </D:propstat>
                \\  </D:response>
                \\</D:multistatus>
            );
        }

        const body_len = fbs.pos;

        var header_buf: [256]u8 = undefined;
        var header_fbs = io_compat.fixedBufferStream(&header_buf);
        const header_writer = header_fbs.writer();
        try header_writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
            .{body_len},
        );

        _ = try self.connection.write(header_fbs.getWritten());
        _ = try self.connection.write(response_body[0..body_len]);
    }

    /// Handle GET request (retrieve calendar/contact resource)
    fn handleGet(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = config;

        // Check if path is a calendar event or contact
        if (std.mem.endsWith(u8, path, ".ics")) {
            // Return iCalendar data
            const ical_data =
                \\BEGIN:VCALENDAR
                \\VERSION:2.0
                \\PRODID:-//SMTP Server//CalDAV Server//EN
                \\BEGIN:VEVENT
                \\UID:event-001@smtp-server
                \\DTSTAMP:20250124T120000Z
                \\DTSTART:20250124T140000Z
                \\DTEND:20250124T150000Z
                \\SUMMARY:Test Event
                \\DESCRIPTION:This is a test calendar event
                \\END:VEVENT
                \\END:VCALENDAR
            ;

            var header_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&header_buf);
            const writer = fbs.writer();
            try writer.print(
                "HTTP/1.1 200 OK\r\nContent-Type: text/calendar; charset=utf-8\r\nETag: \"event-001\"\r\nContent-Length: {d}\r\n\r\n",
                .{ical_data.len},
            );

            _ = try self.connection.write(fbs.getWritten());
            _ = try self.connection.write(ical_data);
        } else if (std.mem.endsWith(u8, path, ".vcf")) {
            // Return vCard data
            const vcard_data =
                \\BEGIN:VCARD
                \\VERSION:3.0
                \\FN:John Doe
                \\N:Doe;John;;;
                \\EMAIL;TYPE=INTERNET:john@example.com
                \\TEL;TYPE=CELL:+1-555-1234
                \\END:VCARD
            ;

            var header_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&header_buf);
            const writer = fbs.writer();
            try writer.print(
                "HTTP/1.1 200 OK\r\nContent-Type: text/vcard; charset=utf-8\r\nETag: \"contact-001\"\r\nContent-Length: {d}\r\n\r\n",
                .{vcard_data.len},
            );

            _ = try self.connection.write(fbs.getWritten());
            _ = try self.connection.write(vcard_data);
        } else {
            try self.sendError(404, "Not Found");
        }
    }

    /// Handle PUT request (create/update calendar/contact resource)
    fn handlePut(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = path;
        _ = config;

        // Extract body from request
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            try self.sendError(400, "Bad Request");
            return;
        };

        const body = request[body_start + 4 ..];

        // Validate iCalendar or vCard format
        if (std.mem.indexOf(u8, body, "BEGIN:VCALENDAR") != null) {
            // Parse and store calendar event
            // TODO: Actual storage implementation
            try self.sendSuccess(201, "Created");
        } else if (std.mem.indexOf(u8, body, "BEGIN:VCARD") != null) {
            // Parse and store contact
            // TODO: Actual storage implementation
            try self.sendSuccess(201, "Created");
        } else {
            try self.sendError(400, "Invalid format");
        }
    }

    /// Handle DELETE request (delete calendar/contact resource)
    fn handleDelete(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = path;
        _ = config;

        // TODO: Actual deletion implementation
        try self.sendSuccess(204, "No Content");
    }

    /// Handle MKCALENDAR request (create new calendar)
    fn handleMkcalendar(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = path;
        _ = config;

        // TODO: Create calendar collection
        try self.sendSuccess(201, "Created");
    }

    /// Handle MKCOL request (create collection)
    fn handleMkcol(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = path;
        _ = config;

        // TODO: Create addressbook collection
        try self.sendSuccess(201, "Created");
    }

    /// Handle REPORT request (calendar/contact queries)
    fn handleReport(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = path;
        _ = config;

        // Check report type
        if (std.mem.indexOf(u8, request, "calendar-query") != null) {
            try self.handleCalendarQuery(request);
        } else if (std.mem.indexOf(u8, request, "addressbook-query") != null) {
            try self.handleAddressbookQuery(request);
        } else {
            try self.sendError(400, "Invalid report type");
        }
    }

    /// Handle calendar-query REPORT
    fn handleCalendarQuery(self: *CalDavSession, request: []const u8) !void {
        _ = request;

        // Build calendar query response
        const response_body =
            \\<?xml version="1.0" encoding="utf-8" ?>
            \\<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            \\  <D:response>
            \\    <D:href>/calendars/user/test/event-001.ics</D:href>
            \\    <D:propstat>
            \\      <D:prop>
            \\        <D:getetag>"event-001"</D:getetag>
            \\        <C:calendar-data>BEGIN:VCALENDAR
            \\VERSION:2.0
            \\BEGIN:VEVENT
            \\UID:event-001
            \\SUMMARY:Test Event
            \\END:VEVENT
            \\END:VCALENDAR</C:calendar-data>
            \\      </D:prop>
            \\      <D:status>HTTP/1.1 200 OK</D:status>
            \\    </D:propstat>
            \\  </D:response>
            \\</D:multistatus>
        ;

        var header_buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&header_buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
            .{response_body.len},
        );

        _ = try self.connection.write(fbs.getWritten());
        _ = try self.connection.write(response_body);
    }

    /// Handle addressbook-query REPORT
    fn handleAddressbookQuery(self: *CalDavSession, request: []const u8) !void {
        _ = request;

        // Build addressbook query response
        const response_body =
            \\<?xml version="1.0" encoding="utf-8" ?>
            \\<D:multistatus xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
            \\  <D:response>
            \\    <D:href>/addressbooks/user/test/contact-001.vcf</D:href>
            \\    <D:propstat>
            \\      <D:prop>
            \\        <D:getetag>"contact-001"</D:getetag>
            \\        <CARD:address-data>BEGIN:VCARD
            \\VERSION:3.0
            \\FN:John Doe
            \\EMAIL:john@example.com
            \\END:VCARD</CARD:address-data>
            \\      </D:prop>
            \\      <D:status>HTTP/1.1 200 OK</D:status>
            \\    </D:propstat>
            \\  </D:response>
            \\</D:multistatus>
        ;

        var header_buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&header_buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
            .{response_body.len},
        );

        _ = try self.connection.write(fbs.getWritten());
        _ = try self.connection.write(response_body);
    }

    /// Send authentication required response with Digest challenge
    fn sendAuthRequired(self: *CalDavSession) !void {
        const nonce = self.auth_backend.generateNonce() catch {
            // Fallback to Basic auth if nonce generation fails
            const response =
                "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n";
            _ = try self.connection.write(response);
            return;
        };
        // Note: Don't free nonce here - it's owned by the NonceManager and will be freed when invalidated

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Digest realm=\"CalDAV/CardDAV Server\", nonce=\"{s}\", qop=\"auth\", algorithm=MD5\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n",
            .{nonce},
        );
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Send error response
    fn sendError(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n", .{ code, message });
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Send success response
    fn sendSuccess(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n", .{ code, message });
        _ = try self.connection.write(fbs.getWritten());
    }
};

// ============================================================================
// CalDAV/CardDAV Server
// ============================================================================

pub const CalDavServer = struct {
    allocator: std.mem.Allocator,
    config: CalDavConfig,
    listener: ?socket.Server = null,
    ssl_listener: ?socket.Server = null,
    running: std.atomic.Value(bool),
    auth_backend: *auth.AuthBackend,
    cert_key_pair: ?tls.config.CertKeyPair = null,

    pub fn init(allocator: std.mem.Allocator, config: CalDavConfig, auth_backend: *auth.AuthBackend) CalDavServer {
        var server = CalDavServer{
            .allocator = allocator,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
        };

        // Load TLS certificate if configured
        if (config.enable_ssl and config.cert_path != null and config.key_path != null) {
            server.cert_key_pair = tls.config.CertKeyPair.fromFilePathAbsoluteSync(
                allocator,
                config.cert_path.?,
                config.key_path.?,
            ) catch |err| {
                logger.err("Failed to load TLS certificate for CalDAV: {}", .{err});
                return server;
            };
            logger.info("Loaded TLS certificate for CalDAV", .{});
        }

        return server;
    }

    pub fn deinit(self: *CalDavServer) void {
        self.stop();
        if (self.cert_key_pair) |*ckp| {
            ckp.deinit(self.allocator);
        }
    }

    /// Start the CalDAV/CardDAV server
    pub fn start(self: *CalDavServer) !void {
        const address = try socket.Address.parseIp("0.0.0.0", self.config.port);
        self.listener = try socket.Server.listen(address, .{
            .reuse_address = true,
        });

        self.running.store(true, .monotonic);

        logger.info("CalDAV/CardDAV server listening on port {d}", .{self.config.port});

        // Also start CalDAVS (SSL) if enabled and certs are configured
        if (self.config.enable_ssl and self.config.cert_path != null and self.config.key_path != null) {
            _ = std.Thread.spawn(.{}, startSslListener, .{self}) catch |err| {
                logger.warn("Failed to start CalDAV SSL listener: {} (CalDAV on port {d} still available)", .{ err, self.config.port });
            };
        }

        while (self.running.load(.monotonic)) {
            const connection = self.listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                logger.err("CalDAV accept error: {}", .{err});
                continue;
            };

            // Handle connection (defer in handleConnection closes the connection)
            self.handleConnection(connection, false) catch |err| {
                logger.err("CalDAV connection error: {}", .{err});
                // Note: connection.close() is handled by defer in handleConnection
            };
        }
    }

    /// Start the SSL listener (runs in separate thread)
    fn startSslListener(self: *CalDavServer) void {
        const ssl_address = socket.Address.parseIp("0.0.0.0", self.config.ssl_port) catch |err| {
            logger.err("Failed to parse CalDAV SSL address: {}", .{err});
            return;
        };

        self.ssl_listener = socket.Server.listen(ssl_address, .{
            .reuse_address = true,
        }) catch |err| {
            logger.err("Failed to start CalDAV SSL listener: {}", .{err});
            return;
        };

        logger.info("CalDAV SSL server listening on port {d} (HTTPS)", .{self.config.ssl_port});

        while (self.running.load(.monotonic)) {
            const connection = self.ssl_listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                logger.err("CalDAV SSL accept error: {}", .{err});
                continue;
            };

            // Handle SSL connection (defer in handleConnection closes the connection)
            self.handleConnection(connection, true) catch |err| {
                logger.err("CalDAV SSL connection error: {}", .{err});
                // Note: connection.close() is handled by defer in handleConnection
            };
        }
    }

    /// Stop the server
    pub fn stop(self: *CalDavServer) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*listener| {
            listener.close();
            self.listener = null;
        }
        if (self.ssl_listener) |*ssl_listener| {
            ssl_listener.close();
            self.ssl_listener = null;
        }
    }

    /// Handle client connection
    fn handleConnection(self: *CalDavServer, connection: socket.Connection, is_ssl: bool) !void {
        var session = CalDavSession.init(self.allocator, connection, self.auth_backend);
        defer {
            session.deinit();
            connection.close();
        }

        // For SSL connections, perform TLS handshake first
        var tls_cipher: ?tls.Cipher = null;

        if (is_ssl) {
            if (self.cert_key_pair == null) {
                logger.err("CalDAV SSL connection attempted but no certificate loaded", .{});
                return error.TlsNotConfigured;
            }

            logger.info("Starting TLS handshake for CalDAV connection", .{});

            var tls_server = tls.nonblock.Server.init(.{
                .auth = &self.cert_key_pair.?,
            });

            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            var recv_len: usize = 0;
            var first_read = true;

            while (!tls_server.done()) {
                // Log raw data before processing (for debugging Mail.app issues)
                if (first_read and recv_len > 0) {
                    logger.info("CalDAV TLS: first {d} bytes received, record type: {d}", .{ recv_len, recv_buf[0] });
                    if (recv_len >= 5) {
                        logger.info("CalDAV TLS: version=0x{x:0>2}{x:0>2}, length={d}", .{ recv_buf[1], recv_buf[2], @as(u16, recv_buf[3]) << 8 | recv_buf[4] });
                    }
                    first_read = false;
                }

                const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                    logger.err("CalDAV TLS handshake error: {} (recv_len={d})", .{ err, recv_len });
                    if (recv_len > 0) {
                        logger.err("CalDAV TLS: first byte=0x{x:0>2}", .{recv_buf[0]});
                    }
                    return error.TlsHandshakeFailed;
                };

                if (result.recv_pos > 0) {
                    const remaining = recv_len - result.recv_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
                    }
                    recv_len = remaining;
                }

                if (result.send.len > 0) {
                    var sent: usize = 0;
                    while (sent < result.send.len) {
                        const n = connection.write(result.send[sent..]) catch |err| {
                            logger.err("CalDAV TLS handshake write error: {}", .{err});
                            return error.TlsHandshakeFailed;
                        };
                        if (n == 0) return error.TlsHandshakeFailed;
                        sent += n;
                    }
                }

                if (!tls_server.done()) {
                    const n = connection.read(recv_buf[recv_len..]) catch |err| {
                        logger.err("CalDAV TLS handshake read error: {}", .{err});
                        return error.TlsHandshakeFailed;
                    };
                    if (n == 0) return error.TlsHandshakeFailed;
                    recv_len += n;
                }
            }

            tls_cipher = tls_server.cipher();
            logger.debug("CalDAV TLS handshake completed successfully", .{});

            // Handle TLS session - must be inside this block to access recv_buf/recv_len
            if (tls_cipher) |cipher| {
                var tls_conn = tls.nonblock.Connection.init(cipher);
                var cleartext_buf: [8192]u8 = undefined;
                var ciphertext_accum: [tls.input_buffer_len * 2]u8 = undefined;
                var ciphertext_len: usize = 0;

                // First, check if there's leftover data from handshake
                if (recv_len > 0) {
                    @memcpy(ciphertext_accum[0..recv_len], recv_buf[0..recv_len]);
                    ciphertext_len = recv_len;
                }

                // If no leftover data, read from socket
                if (ciphertext_len == 0) {
                    const bytes_read = connection.read(recv_buf[0..]) catch return;
                    if (bytes_read == 0) return;
                    @memcpy(ciphertext_accum[0..bytes_read], recv_buf[0..bytes_read]);
                    ciphertext_len = bytes_read;
                }

                const dec_result = tls_conn.decrypt(ciphertext_accum[0..ciphertext_len], &cleartext_buf) catch |err| {
                    logger.err("CalDAV TLS decrypt error: {}", .{err});
                    return;
                };

                var tls_session = TlsCalDavSession.init(self.allocator, connection, self.auth_backend, &tls_conn);
                defer tls_session.deinit();

                // Handle first request if we have cleartext from initial decrypt
                if (dec_result.cleartext.len > 0) {
                    _ = tls_session.handleRequest(&self.config, dec_result.cleartext) catch {};
                }

                // Keep connection alive for multiple requests (needed for Digest auth)
                var request_buf: [8192]u8 = undefined;
                while (true) {
                    // Read more encrypted data
                    const bytes_read = connection.read(recv_buf[0..]) catch break;
                    if (bytes_read == 0) break;

                    // Decrypt the data
                    const dec = tls_conn.decrypt(recv_buf[0..bytes_read], &cleartext_buf) catch break;

                    if (dec.cleartext.len > 0) {
                        // Copy to request buffer
                        const copy_len = @min(dec.cleartext.len, request_buf.len);
                        @memcpy(request_buf[0..copy_len], dec.cleartext[0..copy_len]);

                        // Handle the request
                        _ = tls_session.handleRequest(&self.config, request_buf[0..copy_len]) catch {};
                    }

                    // Check for connection close from client
                    if (dec.closed) break;
                }

                // Send close notify
                var close_buf: [64]u8 = undefined;
                if (tls_conn.close(&close_buf)) |close_data| {
                    _ = connection.write(close_data) catch {};
                } else |_| {}
            }
            return;
        }

        // Handle plain text session (non-SSL)
        if (!is_ssl) {
            // Plain text session
            _ = session.handleRequest(&self.config) catch {};
        }
    }
};

/// TLS-wrapped CalDAV session for encrypted connections
const TlsCalDavSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    username: ?[]const u8 = null,
    authenticated: bool = false,
    auth_backend: *auth.AuthBackend,
    tls_conn: *tls.nonblock.Connection,

    pub fn init(
        allocator: std.mem.Allocator,
        connection: socket.Connection,
        auth_backend: *auth.AuthBackend,
        tls_conn: *tls.nonblock.Connection,
    ) TlsCalDavSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .auth_backend = auth_backend,
            .tls_conn = tls_conn,
        };
    }

    pub fn deinit(self: *TlsCalDavSession) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
    }

    fn sendTls(self: *TlsCalDavSession, data: []const u8) !void {
        var send_buf: [tls.output_buffer_len]u8 = undefined;
        const enc_result = try self.tls_conn.encrypt(data, &send_buf);
        var sent: usize = 0;
        while (sent < enc_result.ciphertext.len) {
            const n = try self.connection.write(enc_result.ciphertext[sent..]);
            if (n == 0) return error.ConnectionClosed;
            sent += n;
        }
    }

    /// Send authentication required response with Digest challenge over TLS
    fn sendTlsAuthRequired(self: *TlsCalDavSession) !void {
        const nonce = self.auth_backend.generateNonce() catch {
            // Fallback to Basic auth if nonce generation fails
            try self.sendTls("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        // Note: Don't free nonce here - it's owned by the NonceManager and will be freed when invalidated

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Digest realm=\"CalDAV/CardDAV Server\", nonce=\"{s}\", qop=\"auth\", algorithm=MD5\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n",
            .{nonce},
        );
        try self.sendTls(fbs.getWritten());
    }

    pub fn handleRequest(self: *TlsCalDavSession, config: *const CalDavConfig, request: []const u8) !bool {
        _ = config;

        // Debug: log incoming request
        logger.info("CalDAV TLS received request ({d} bytes)", .{request.len});
        if (request.len > 0 and request.len < 500) {
            logger.info("CalDAV request: {s}", .{request});
        }

        // Parse HTTP request line
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return false;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_str = parts.next() orelse return false;
        const path = parts.next() orelse return false;

        const method = HttpMethod.fromString(method_str) orelse {
            try self.sendTls("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            return true;
        };

        // Handle .well-known autodiscovery BEFORE authentication (per RFC 5785)
        if (std.mem.startsWith(u8, path, "/.well-known/caldav")) {
            try self.sendTls("HTTP/1.1 301 Moved Permanently\r\nLocation: /calendars/\r\nContent-Length: 0\r\n\r\n");
            return true;
        }
        if (std.mem.startsWith(u8, path, "/.well-known/carddav")) {
            try self.sendTls("HTTP/1.1 301 Moved Permanently\r\nLocation: /addressbooks/\r\nContent-Length: 0\r\n\r\n");
            return true;
        }

        // Check authentication (Digest or Basic Auth)
        if (!self.authenticated) {
            var auth_header: ?[]const u8 = null;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
                if (trimmed.len == 0) break;

                if (std.mem.startsWith(u8, trimmed, "Authorization:")) {
                    auth_header = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);
                    break;
                }
            }

            if (auth_header == null) {
                logger.info("CalDAV: No Authorization header, sending 401", .{});
                try self.sendTlsAuthRequired();
                return true;
            }

            logger.info("CalDAV: Got Authorization header: {s}", .{auth_header.?[0..@min(auth_header.?.len, 100)]});

            // Try Digest auth first, then fall back to Basic
            var validated_username: ?[]const u8 = null;

            if (std.mem.startsWith(u8, auth_header.?, "Digest ")) {
                logger.info("CalDAV: Attempting Digest auth", .{});
                validated_username = self.auth_backend.verifyDigestAuth(
                    auth_header.?,
                    method_str,
                    "CalDAV/CardDAV Server",
                ) catch |err| blk: {
                    logger.err("CalDAV TLS Digest authentication error: {}", .{err});
                    break :blk null;
                };
                if (validated_username == null) {
                    logger.warn("CalDAV: Digest auth returned null (failed verification)", .{});
                }
            }

            // Fall back to Basic auth if Digest didn't work
            if (validated_username == null and std.mem.startsWith(u8, auth_header.?, "Basic ")) {
                logger.info("CalDAV: Attempting Basic auth", .{});
                validated_username = self.auth_backend.verifyBasicAuth(auth_header.?) catch |err| blk: {
                    logger.err("CalDAV TLS Basic authentication error: {}", .{err});
                    break :blk null;
                };
            }

            if (validated_username) |username| {
                self.authenticated = true;
                self.username = username;
                logger.info("Successful CalDAV TLS authentication for user: {s}", .{username});
            } else {
                logger.warn("CalDAV: Authentication failed, sending 401", .{});
                try self.sendTlsAuthRequired();
                return true;
            }
        }

        // Handle OPTIONS for CalDAV capabilities
        if (method == .options) {
            try self.sendTls(
                "HTTP/1.1 200 OK\r\n" ++
                    "DAV: 1, 2, 3, calendar-access, addressbook\r\n" ++
                    "Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT\r\n" ++
                    "Content-Length: 0\r\n\r\n",
            );
            return true;
        }

        // Handle PROPFIND
        if (method == .propfind) {
            // Check if this is an addressbook (CardDAV) or calendar (CalDAV) request
            const is_addressbook = std.mem.startsWith(u8, path, "/addressbooks");

            var response_body_buf: [2048]u8 = undefined;
            var response_fbs = io_compat.fixedBufferStream(&response_body_buf);
            const response_writer = response_fbs.writer();

            if (is_addressbook) {
                // CardDAV response for addressbooks
                try response_writer.writeAll(
                    \\<?xml version="1.0" encoding="utf-8" ?>
                    \\<D:multistatus xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
                    \\  <D:response>
                    \\    <D:href>
                );
                try response_writer.writeAll(path);
                try response_writer.writeAll(
                    \\</D:href>
                    \\    <D:propstat>
                    \\      <D:prop>
                    \\        <D:resourcetype>
                    \\          <D:collection/>
                    \\          <CARD:addressbook/>
                    \\        </D:resourcetype>
                    \\        <D:displayname>Contacts</D:displayname>
                    \\        <CARD:supported-address-data>
                    \\          <CARD:address-data-type content-type="text/vcard" version="3.0"/>
                    \\          <CARD:address-data-type content-type="text/vcard" version="4.0"/>
                    \\        </CARD:supported-address-data>
                    \\      </D:prop>
                    \\      <D:status>HTTP/1.1 200 OK</D:status>
                    \\    </D:propstat>
                    \\  </D:response>
                    \\</D:multistatus>
                );
            } else {
                // CalDAV response for calendars
                try response_writer.writeAll(
                    \\<?xml version="1.0" encoding="utf-8" ?>
                    \\<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
                    \\  <D:response>
                    \\    <D:href>
                );
                try response_writer.writeAll(path);
                try response_writer.writeAll(
                    \\</D:href>
                    \\    <D:propstat>
                    \\      <D:prop>
                    \\        <D:resourcetype>
                    \\          <D:collection/>
                    \\          <C:calendar/>
                    \\        </D:resourcetype>
                    \\        <D:displayname>Calendar</D:displayname>
                    \\        <C:supported-calendar-component-set>
                    \\          <C:comp name="VEVENT"/>
                    \\          <C:comp name="VTODO"/>
                    \\        </C:supported-calendar-component-set>
                    \\      </D:prop>
                    \\      <D:status>HTTP/1.1 200 OK</D:status>
                    \\    </D:propstat>
                    \\  </D:response>
                    \\</D:multistatus>
                );
            }

            const response_body = response_fbs.getWritten();

            var header_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&header_buf);
            const writer = fbs.writer();
            try writer.print(
                "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
                .{response_body.len},
            );

            try self.sendTls(fbs.getWritten());
            try self.sendTls(response_body);
            return true;
        }

        // Default: not implemented
        try self.sendTls("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "CalDAV server initialization" {
    const testing = std.testing;

    // Can't test without auth backend in unit tests
    // Just verify the config struct compiles
    const config = CalDavConfig{};
    try testing.expectEqual(@as(u16, 8008), config.port);
    try testing.expectEqual(@as(u16, 8443), config.ssl_port);
}

test "HTTP method parsing" {
    const testing = std.testing;

    try testing.expectEqual(HttpMethod.propfind, HttpMethod.fromString("PROPFIND").?);
    try testing.expectEqual(HttpMethod.mkcalendar, HttpMethod.fromString("MKCALENDAR").?);
    try testing.expectEqual(HttpMethod.report, HttpMethod.fromString("REPORT").?);
    try testing.expect(HttpMethod.fromString("INVALID") == null);
}
