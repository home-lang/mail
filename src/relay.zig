const std = @import("std");

/// SMTP relay client for forwarding messages to other servers
pub const SMTPRelay = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    our_hostname: []const u8,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, our_hostname: []const u8) !SMTPRelay {
        return .{
            .allocator = allocator,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .timeout_ms = 30000, // 30 seconds
            .our_hostname = try allocator.dupe(u8, our_hostname),
        };
    }

    pub fn deinit(self: *SMTPRelay) void {
        self.allocator.free(self.host);
        self.allocator.free(self.our_hostname);
    }

    /// Send a message via SMTP relay
    pub fn sendMessage(
        self: *SMTPRelay,
        from: []const u8,
        to: []const u8,
        data: []const u8,
    ) !void {
        // Connect to relay server
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        var buf: [1024]u8 = undefined;

        // Read greeting
        const greeting = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, greeting, "220")) {
            return error.InvalidGreeting;
        }

        // EHLO
        const ehlo_cmd = try std.fmt.allocPrint(self.allocator, "EHLO {s}\r\n", .{self.our_hostname});
        defer self.allocator.free(ehlo_cmd);
        _ = try stream.write(ehlo_cmd);

        const ehlo_response = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, ehlo_response, "250")) {
            return error.EhloFailed;
        }

        // MAIL FROM
        const mail_cmd = try std.fmt.allocPrint(self.allocator, "MAIL FROM:<{s}>\r\n", .{from});
        defer self.allocator.free(mail_cmd);
        _ = try stream.write(mail_cmd);

        const mail_response = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, mail_response, "250")) {
            return error.MailFromFailed;
        }

        // RCPT TO
        const rcpt_cmd = try std.fmt.allocPrint(self.allocator, "RCPT TO:<{s}>\r\n", .{to});
        defer self.allocator.free(rcpt_cmd);
        _ = try stream.write(rcpt_cmd);

        const rcpt_response = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, rcpt_response, "250")) {
            return error.RcptToFailed;
        }

        // DATA
        _ = try stream.write("DATA\r\n");
        const data_response = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, data_response, "354")) {
            return error.DataFailed;
        }

        // Send message data
        _ = try stream.write(data);
        if (!std.mem.endsWith(u8, data, "\r\n.\r\n")) {
            _ = try stream.write("\r\n.\r\n");
        }

        const send_response = try self.readResponse(stream, &buf);
        if (!std.mem.startsWith(u8, send_response, "250")) {
            return error.MessageSendFailed;
        }

        // QUIT
        _ = try stream.write("QUIT\r\n");
        _ = try self.readResponse(stream, &buf);
    }

    fn readResponse(self: *SMTPRelay, stream: std.net.Stream, buf: []u8) ![]const u8 {
        _ = self;
        const bytes_read = try stream.read(buf);
        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }
        return buf[0..bytes_read];
    }
};

/// Relay worker that processes queue messages
pub const RelayWorker = struct {
    allocator: std.mem.Allocator,
    queue: *@import("queue.zig").MessageQueue,
    relay: *SMTPRelay,
    running: *std.atomic.Value(bool),
    poll_interval_ms: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        queue: *@import("queue.zig").MessageQueue,
        relay: *SMTPRelay,
        running: *std.atomic.Value(bool),
    ) RelayWorker {
        return .{
            .allocator = allocator,
            .queue = queue,
            .relay = relay,
            .running = running,
            .poll_interval_ms = 1000, // 1 second
        };
    }

    /// Run the relay worker (processes queue continuously)
    pub fn run(self: *RelayWorker) !void {
        while (self.running.load(.monotonic)) {
            // Get next message from queue
            if (self.queue.getNextPending()) |msg| {
                // Try to relay the message
                self.relay.sendMessage(msg.from, msg.to, msg.data) catch |err| {
                    const err_msg = try std.fmt.allocPrint(
                        self.allocator,
                        "Relay failed: {any}",
                        .{err},
                    );
                    defer self.allocator.free(err_msg);

                    try self.queue.markForRetry(msg.id, err_msg);
                    std.log.err("Failed to relay message {s}: {any}", .{ msg.id, err });
                    continue;
                };

                // Mark as delivered
                try self.queue.markDelivered(msg.id);
                std.log.info("Successfully relayed message {s}", .{msg.id});
            } else {
                // No messages, sleep for a bit
                std.time.sleep(self.poll_interval_ms * std.time.ns_per_ms);
            }
        }
    }
};

test "SMTP relay sendMessage mock" {
    // Note: This would require a real SMTP server to test properly
    // For unit testing, we'd need to mock the network layer
    const testing = std.testing;
    _ = testing;

    // Skip actual network test
}
