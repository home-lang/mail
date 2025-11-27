const std = @import("std");
const version_info = @import("../core/version.zig");

// =============================================================================
// Webmail Client - Responsive Web Interface for Email
// =============================================================================
//
// ## Overview
// Provides a modern, responsive web interface for email management including:
// - Email composition with rich text support
// - Inbox, sent, drafts, trash folder views
// - Email search and filtering
// - Contact management integration
// - Mobile-friendly design
//
// ## Architecture
//
//   Browser <──> WebmailHandler <──> IMAP/Storage
//      │              │
//      └──> Static Assets (HTML/CSS/JS)
//
// =============================================================================

/// Webmail configuration
pub const WebmailConfig = struct {
    /// Maximum attachment size in bytes
    max_attachment_size: usize = 25 * 1024 * 1024, // 25MB
    /// Maximum number of attachments per email
    max_attachments: usize = 10,
    /// Session timeout in seconds
    session_timeout_seconds: u32 = 3600, // 1 hour
    /// Enable rich text editor
    enable_rich_text: bool = true,
    /// Enable spell check
    enable_spell_check: bool = true,
    /// Messages per page
    messages_per_page: usize = 50,
    /// Enable dark mode
    enable_dark_mode: bool = true,
    /// Custom theme CSS URL
    custom_theme_url: ?[]const u8 = null,
};

/// Email folder types
pub const FolderType = enum {
    inbox,
    sent,
    drafts,
    trash,
    spam,
    archive,
    custom,

    pub fn toString(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "Inbox",
            .sent => "Sent",
            .drafts => "Drafts",
            .trash => "Trash",
            .spam => "Spam",
            .archive => "Archive",
            .custom => "Custom",
        };
    }

    pub fn icon(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "inbox",
            .sent => "send",
            .drafts => "edit",
            .trash => "trash-2",
            .spam => "alert-triangle",
            .archive => "archive",
            .custom => "folder",
        };
    }
};

/// Email message for webmail display
pub const WebmailMessage = struct {
    id: []const u8,
    folder: FolderType,
    from: EmailAddress,
    to: []const EmailAddress,
    cc: []const EmailAddress,
    bcc: []const EmailAddress,
    subject: []const u8,
    body_text: ?[]const u8,
    body_html: ?[]const u8,
    date: i64,
    is_read: bool,
    is_starred: bool,
    is_flagged: bool,
    has_attachments: bool,
    attachments: []const Attachment,
    reply_to: ?[]const u8,
    in_reply_to: ?[]const u8,
    thread_id: ?[]const u8,

    pub const EmailAddress = struct {
        name: ?[]const u8,
        email: []const u8,

        pub fn format(self: EmailAddress, allocator: std.mem.Allocator) ![]u8 {
            if (self.name) |name| {
                return std.fmt.allocPrint(allocator, "{s} <{s}>", .{ name, self.email });
            }
            return allocator.dupe(u8, self.email);
        }
    };

    pub const Attachment = struct {
        id: []const u8,
        filename: []const u8,
        mime_type: []const u8,
        size: usize,
        content_id: ?[]const u8, // For inline attachments
    };

    /// Convert to JSON for API response
    pub fn toJson(self: *const WebmailMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.print(
            \\{{
            \\  "id": "{s}",
            \\  "folder": "{s}",
            \\  "from": {{"name": {s}, "email": "{s}"}},
            \\  "subject": "{s}",
            \\  "date": {d},
            \\  "is_read": {s},
            \\  "is_starred": {s},
            \\  "has_attachments": {s}
            \\}}
        , .{
            self.id,
            self.folder.toString(),
            if (self.from.name) |n| "\"" ++ n ++ "\"" else "null",
            self.from.email,
            self.subject,
            self.date,
            if (self.is_read) "true" else "false",
            if (self.is_starred) "true" else "false",
            if (self.has_attachments) "true" else "false",
        });

        return buffer.toOwnedSlice();
    }
};

/// Compose email request
pub const ComposeRequest = struct {
    to: []const []const u8,
    cc: ?[]const []const u8 = null,
    bcc: ?[]const []const u8 = null,
    subject: []const u8,
    body_text: ?[]const u8 = null,
    body_html: ?[]const u8 = null,
    reply_to_id: ?[]const u8 = null,
    forward_id: ?[]const u8 = null,
    draft_id: ?[]const u8 = null,
    attachments: ?[]const AttachmentUpload = null,

    pub const AttachmentUpload = struct {
        filename: []const u8,
        mime_type: []const u8,
        data: []const u8, // Base64 encoded
    };
};

/// Search parameters
pub const SearchParams = struct {
    query: ?[]const u8 = null,
    folder: ?FolderType = null,
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    has_attachment: ?bool = null,
    is_unread: ?bool = null,
    is_starred: ?bool = null,
    date_from: ?i64 = null,
    date_to: ?i64 = null,
    page: usize = 1,
    per_page: usize = 50,
};

/// Webmail session
pub const WebmailSession = struct {
    id: []const u8,
    user_id: []const u8,
    username: []const u8,
    email: []const u8,
    created_at: i64,
    last_activity: i64,
    preferences: UserPreferences,

    pub const UserPreferences = struct {
        theme: Theme = .light,
        messages_per_page: usize = 50,
        default_folder: FolderType = .inbox,
        signature: ?[]const u8 = null,
        display_name: ?[]const u8 = null,
        reply_to: ?[]const u8 = null,
        auto_save_drafts: bool = true,
        confirm_delete: bool = true,
        show_images: ShowImages = .ask,
        text_size: TextSize = .medium,

        pub const Theme = enum { light, dark, auto };
        pub const ShowImages = enum { always, never, ask };
        pub const TextSize = enum { small, medium, large };
    };
};

/// Webmail API handler
pub const WebmailHandler = struct {
    allocator: std.mem.Allocator,
    config: WebmailConfig,
    sessions: std.StringHashMap(*WebmailSession),

    pub fn init(allocator: std.mem.Allocator, config: WebmailConfig) WebmailHandler {
        return .{
            .allocator = allocator,
            .config = config,
            .sessions = std.StringHashMap(*WebmailSession).init(allocator),
        };
    }

    pub fn deinit(self: *WebmailHandler) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit();
    }

    /// Handle HTTP request
    pub fn handleRequest(self: *WebmailHandler, path: []const u8, method: []const u8, body: ?[]const u8) ![]u8 {
        _ = body;

        // Route requests
        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/webmail") or std.mem.eql(u8, path, "/webmail/")) {
                return self.serveMainPage();
            } else if (std.mem.startsWith(u8, path, "/webmail/api/")) {
                return self.handleApiGet(path[13..]);
            } else if (std.mem.startsWith(u8, path, "/webmail/static/")) {
                return self.serveStaticFile(path[16..]);
            }
        } else if (std.mem.eql(u8, method, "POST")) {
            if (std.mem.startsWith(u8, path, "/webmail/api/")) {
                return self.handleApiPost(path[13..]);
            }
        }

        return self.serveError(404, "Not Found");
    }

    fn handleApiGet(self: *WebmailHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "folders")) {
            return self.getFolders();
        } else if (std.mem.startsWith(u8, endpoint, "messages")) {
            return self.getMessages(endpoint);
        } else if (std.mem.eql(u8, endpoint, "user")) {
            return self.getUserInfo();
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn handleApiPost(self: *WebmailHandler, endpoint: []const u8) ![]u8 {
        if (std.mem.eql(u8, endpoint, "compose")) {
            return self.composeEmail();
        } else if (std.mem.eql(u8, endpoint, "search")) {
            return self.searchMessages();
        }
        return self.serveError(404, "Endpoint not found");
    }

    fn getFolders(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"folders": [
            \\  {{"type": "inbox", "name": "Inbox", "unread": 0, "icon": "inbox"}},
            \\  {{"type": "sent", "name": "Sent", "unread": 0, "icon": "send"}},
            \\  {{"type": "drafts", "name": "Drafts", "unread": 0, "icon": "edit"}},
            \\  {{"type": "trash", "name": "Trash", "unread": 0, "icon": "trash-2"}},
            \\  {{"type": "spam", "name": "Spam", "unread": 0, "icon": "alert-triangle"}},
            \\  {{"type": "archive", "name": "Archive", "unread": 0, "icon": "archive"}}
            \\]}}
        , .{});
    }

    fn getMessages(self: *WebmailHandler, _: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"messages": [], "total": 0, "page": 1, "per_page": {d}}}
        , .{self.config.messages_per_page});
    }

    fn getUserInfo(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"user": {{"email": "", "name": "", "preferences": {{}}}}}}
        , .{});
    }

    fn composeEmail(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"status": "queued", "message_id": ""}}
        , .{});
    }

    fn searchMessages(self: *WebmailHandler) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"results": [], "total": 0}}
        , .{});
    }

    fn serveError(self: *WebmailHandler, status: u16, message: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\n\r\n{{\"error\": \"{s}\"}}",
            .{ status, message, message },
        );
    }

    fn serveStaticFile(self: *WebmailHandler, _: []const u8) ![]u8 {
        return self.serveError(404, "Static file not found");
    }

    /// Serve the main webmail page
    pub fn serveMainPage(self: *WebmailHandler) ![]u8 {
        const html = webmail_html;
        return std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
    }
};

/// Embedded webmail HTML template
const webmail_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    \\    <title>Webmail - SMTP Server</title>
    \\    <style>
    \\        :root {
    \\            --primary: #4f46e5;
    \\            --primary-hover: #4338ca;
    \\            --bg: #f9fafb;
    \\            --sidebar-bg: #ffffff;
    \\            --card-bg: #ffffff;
    \\            --text: #111827;
    \\            --text-muted: #6b7280;
    \\            --border: #e5e7eb;
    \\            --success: #10b981;
    \\            --warning: #f59e0b;
    \\            --danger: #ef4444;
    \\        }
    \\
    \\        [data-theme="dark"] {
    \\            --bg: #111827;
    \\            --sidebar-bg: #1f2937;
    \\            --card-bg: #1f2937;
    \\            --text: #f9fafb;
    \\            --text-muted: #9ca3af;
    \\            --border: #374151;
    \\        }
    \\
    \\        * { margin: 0; padding: 0; box-sizing: border-box; }
    \\
    \\        body {
    \\            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            height: 100vh;
    \\            overflow: hidden;
    \\        }
    \\
    \\        .app {
    \\            display: grid;
    \\            grid-template-columns: 250px 350px 1fr;
    \\            height: 100vh;
    \\        }
    \\
    \\        @media (max-width: 1024px) {
    \\            .app { grid-template-columns: 60px 300px 1fr; }
    \\            .sidebar .folder-name { display: none; }
    \\        }
    \\
    \\        @media (max-width: 768px) {
    \\            .app { grid-template-columns: 1fr; }
    \\            .sidebar, .message-list { display: none; }
    \\            .sidebar.active, .message-list.active { display: block; }
    \\        }
    \\
    \\        .sidebar {
    \\            background: var(--sidebar-bg);
    \\            border-right: 1px solid var(--border);
    \\            padding: 16px;
    \\            overflow-y: auto;
    \\        }
    \\
    \\        .logo {
    \\            font-size: 1.25rem;
    \\            font-weight: 700;
    \\            color: var(--primary);
    \\            margin-bottom: 24px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\
    \\        .compose-btn {
    \\            width: 100%;
    \\            padding: 12px 16px;
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            font-weight: 500;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            gap: 8px;
    \\            margin-bottom: 24px;
    \\            transition: background 0.2s;
    \\        }
    \\
    \\        .compose-btn:hover { background: var(--primary-hover); }
    \\
    \\        .folders { list-style: none; }
    \\
    \\        .folder {
    \\            padding: 10px 12px;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            color: var(--text-muted);
    \\            transition: all 0.2s;
    \\        }
    \\
    \\        .folder:hover, .folder.active {
    \\            background: var(--primary);
    \\            color: white;
    \\        }
    \\
    \\        .folder-count {
    \\            margin-left: auto;
    \\            background: var(--primary);
    \\            color: white;
    \\            padding: 2px 8px;
    \\            border-radius: 10px;
    \\            font-size: 0.75rem;
    \\        }
    \\
    \\        .message-list {
    \\            background: var(--card-bg);
    \\            border-right: 1px solid var(--border);
    \\            overflow-y: auto;
    \\        }
    \\
    \\        .search-bar {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\
    \\        .search-input {
    \\            width: 100%;
    \\            padding: 10px 16px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\        }
    \\
    \\        .message-item {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            cursor: pointer;
    \\            transition: background 0.2s;
    \\        }
    \\
    \\        .message-item:hover { background: var(--bg); }
    \\        .message-item.unread { font-weight: 600; }
    \\        .message-item.active { background: rgba(79, 70, 229, 0.1); }
    \\
    \\        .message-sender {
    \\            font-size: 0.875rem;
    \\            margin-bottom: 4px;
    \\        }
    \\
    \\        .message-subject {
    \\            font-size: 0.875rem;
    \\            color: var(--text);
    \\            margin-bottom: 4px;
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\
    \\        .message-preview {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\
    \\        .message-date {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\            float: right;
    \\        }
    \\
    \\        .message-view {
    \\            background: var(--bg);
    \\            padding: 24px;
    \\            overflow-y: auto;
    \\        }
    \\
    \\        .empty-state {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            justify-content: center;
    \\            height: 100%;
    \\            color: var(--text-muted);
    \\        }
    \\
    \\        .empty-state svg {
    \\            width: 64px;
    \\            height: 64px;
    \\            margin-bottom: 16px;
    \\            opacity: 0.5;
    \\        }
    \\
    \\        .version {
    \\            position: absolute;
    \\            bottom: 16px;
    \\            left: 16px;
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\        }
    \\    </style>
    \\</head>
    \\<body>
    \\    <div class="app">
    \\        <aside class="sidebar">
    \\            <div class="logo">
    \\                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
    \\                    <polyline points="22,6 12,13 2,6"></polyline>
    \\                </svg>
    \\                Webmail
    \\            </div>
    \\
    \\            <button class="compose-btn" onclick="compose()">
    \\                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <line x1="12" y1="5" x2="12" y2="19"></line>
    \\                    <line x1="5" y1="12" x2="19" y2="12"></line>
    \\                </svg>
    \\                <span class="folder-name">Compose</span>
    \\            </button>
    \\
    \\            <ul class="folders">
    \\                <li class="folder active" data-folder="inbox">
    \\                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline>
    \\                        <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>
    \\                    </svg>
    \\                    <span class="folder-name">Inbox</span>
    \\                    <span class="folder-count" id="inbox-count">0</span>
    \\                </li>
    \\                <li class="folder" data-folder="sent">
    \\                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="22" y1="2" x2="11" y2="13"></line>
    \\                        <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
    \\                    </svg>
    \\                    <span class="folder-name">Sent</span>
    \\                </li>
    \\                <li class="folder" data-folder="drafts">
    \\                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
    \\                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
    \\                    </svg>
    \\                    <span class="folder-name">Drafts</span>
    \\                </li>
    \\                <li class="folder" data-folder="trash">
    \\                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <polyline points="3 6 5 6 21 6"></polyline>
    \\                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
    \\                    </svg>
    \\                    <span class="folder-name">Trash</span>
    \\                </li>
    \\            </ul>
    \\
    \\            <div class="version">v0.28.0</div>
    \\        </aside>
    \\
    \\        <section class="message-list">
    \\            <div class="search-bar">
    \\                <input type="text" class="search-input" placeholder="Search emails..." id="search">
    \\            </div>
    \\            <div id="messages">
    \\                <div class="message-item">
    \\                    <span class="message-date">Today</span>
    \\                    <div class="message-sender">Welcome Team</div>
    \\                    <div class="message-subject">Welcome to Webmail!</div>
    \\                    <div class="message-preview">Your email server is ready to use...</div>
    \\                </div>
    \\            </div>
    \\        </section>
    \\
    \\        <main class="message-view">
    \\            <div class="empty-state">
    \\                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
    \\                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
    \\                    <polyline points="22,6 12,13 2,6"></polyline>
    \\                </svg>
    \\                <p>Select an email to read</p>
    \\            </div>
    \\        </main>
    \\    </div>
    \\
    \\    <script>
    \\        // Folder navigation
    \\        document.querySelectorAll('.folder').forEach(folder => {
    \\            folder.addEventListener('click', () => {
    \\                document.querySelectorAll('.folder').forEach(f => f.classList.remove('active'));
    \\                folder.classList.add('active');
    \\                loadMessages(folder.dataset.folder);
    \\            });
    \\        });
    \\
    \\        // Search
    \\        document.getElementById('search').addEventListener('input', (e) => {
    \\            searchMessages(e.target.value);
    \\        });
    \\
    \\        function compose() {
    \\            alert('Compose email - Coming soon!');
    \\        }
    \\
    \\        function loadMessages(folder) {
    \\            fetch('/webmail/api/messages?folder=' + folder)
    \\                .then(r => r.json())
    \\                .then(data => console.log('Messages:', data))
    \\                .catch(e => console.error('Error:', e));
    \\        }
    \\
    \\        function searchMessages(query) {
    \\            if (query.length < 2) return;
    \\            fetch('/webmail/api/search', {
    \\                method: 'POST',
    \\                headers: {'Content-Type': 'application/json'},
    \\                body: JSON.stringify({query: query})
    \\            })
    \\            .then(r => r.json())
    \\            .then(data => console.log('Search:', data))
    \\            .catch(e => console.error('Error:', e));
    \\        }
    \\
    \\        // Dark mode
    \\        if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    \\            document.documentElement.setAttribute('data-theme', 'dark');
    \\        }
    \\
    \\        // Initial load
    \\        loadMessages('inbox');
    \\    </script>
    \\</body>
    \\</html>
;

// Tests
test "WebmailConfig defaults" {
    const config = WebmailConfig{};
    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), config.max_attachment_size);
    try std.testing.expectEqual(@as(usize, 50), config.messages_per_page);
    try std.testing.expect(config.enable_rich_text);
}

test "FolderType strings" {
    try std.testing.expectEqualStrings("Inbox", FolderType.inbox.toString());
    try std.testing.expectEqualStrings("inbox", FolderType.inbox.icon());
    try std.testing.expectEqualStrings("Sent", FolderType.sent.toString());
}

test "WebmailHandler init" {
    const allocator = std.testing.allocator;
    var handler = WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    try std.testing.expectEqual(@as(usize, 50), handler.config.messages_per_page);
}
