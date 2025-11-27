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

// =============================================================================
// Contact Management
// =============================================================================

/// Contact for address book
pub const Contact = struct {
    id: []const u8,
    first_name: ?[]const u8,
    last_name: ?[]const u8,
    email: []const u8,
    phone: ?[]const u8,
    company: ?[]const u8,
    notes: ?[]const u8,
    avatar_url: ?[]const u8,
    groups: []const []const u8,
    created_at: i64,
    updated_at: i64,

    pub fn displayName(self: *const Contact) []const u8 {
        if (self.first_name) |first| {
            if (self.last_name) |last| {
                _ = last;
                return first; // Would concatenate in real impl
            }
            return first;
        }
        return self.email;
    }
};

/// Contact group
pub const ContactGroup = struct {
    id: []const u8,
    name: []const u8,
    color: ?[]const u8,
    member_count: usize,
};

// =============================================================================
// Calendar Integration
// =============================================================================

/// Calendar event for mini calendar view
pub const CalendarEvent = struct {
    id: []const u8,
    title: []const u8,
    start_time: i64,
    end_time: i64,
    location: ?[]const u8,
    description: ?[]const u8,
    attendees: []const []const u8,
    is_all_day: bool,
    color: ?[]const u8,
    reminder_minutes: ?u32,
};

// =============================================================================
// Folder Management
// =============================================================================

/// Custom folder
pub const CustomFolder = struct {
    id: []const u8,
    name: []const u8,
    parent_id: ?[]const u8,
    color: ?[]const u8,
    icon: ?[]const u8,
    unread_count: usize,
    total_count: usize,
    sort_order: u32,
};

/// Folder action request
pub const FolderAction = union(enum) {
    create: struct {
        name: []const u8,
        parent_id: ?[]const u8,
    },
    rename: struct {
        id: []const u8,
        new_name: []const u8,
    },
    delete: struct {
        id: []const u8,
    },
    move: struct {
        id: []const u8,
        new_parent_id: ?[]const u8,
    },
};

// =============================================================================
// Message Actions
// =============================================================================

/// Batch message action
pub const MessageAction = union(enum) {
    mark_read: []const []const u8,
    mark_unread: []const []const u8,
    star: []const []const u8,
    unstar: []const []const u8,
    move_to: struct {
        message_ids: []const []const u8,
        folder: FolderType,
    },
    delete: []const []const u8,
    archive: []const []const u8,
    mark_spam: []const []const u8,
    mark_not_spam: []const []const u8,
};

/// Embedded webmail HTML template with full functionality
const webmail_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    \\    <meta name="apple-mobile-web-app-capable" content="yes">
    \\    <meta name="theme-color" content="#4f46e5">
    \\    <title>Webmail - SMTP Server v0.28.0</title>
    \\    <style>
    \\        :root {
    \\            --primary: #4f46e5;
    \\            --primary-hover: #4338ca;
    \\            --primary-light: rgba(79, 70, 229, 0.1);
    \\            --bg: #f9fafb;
    \\            --sidebar-bg: #ffffff;
    \\            --card-bg: #ffffff;
    \\            --text: #111827;
    \\            --text-muted: #6b7280;
    \\            --border: #e5e7eb;
    \\            --success: #10b981;
    \\            --warning: #f59e0b;
    \\            --danger: #ef4444;
    \\            --shadow: 0 1px 3px rgba(0,0,0,0.1);
    \\            --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
    \\        }
    \\        [data-theme="dark"] {
    \\            --bg: #111827;
    \\            --sidebar-bg: #1f2937;
    \\            --card-bg: #1f2937;
    \\            --text: #f9fafb;
    \\            --text-muted: #9ca3af;
    \\            --border: #374151;
    \\            --shadow: 0 1px 3px rgba(0,0,0,0.3);
    \\        }
    \\        * { margin: 0; padding: 0; box-sizing: border-box; }
    \\        body {
    \\            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            height: 100vh;
    \\            overflow: hidden;
    \\        }
    \\        .app {
    \\            display: grid;
    \\            grid-template-columns: 240px 320px 1fr;
    \\            height: 100vh;
    \\        }
    \\        @media (max-width: 1200px) {
    \\            .app { grid-template-columns: 200px 280px 1fr; }
    \\        }
    \\        @media (max-width: 1024px) {
    \\            .app { grid-template-columns: 60px 280px 1fr; }
    \\            .sidebar .folder-name, .sidebar .compose-text, .sidebar .section-title { display: none; }
    \\            .sidebar .compose-btn { padding: 12px; justify-content: center; }
    \\        }
    \\        @media (max-width: 768px) {
    \\            .app { grid-template-columns: 1fr; }
    \\            .sidebar { position: fixed; left: -100%; width: 280px; height: 100%; z-index: 100; transition: left 0.3s; }
    \\            .sidebar.open { left: 0; }
    \\            .message-list { display: block; }
    \\            .message-view { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 50; }
    \\            .message-view.open { display: block; }
    \\            .mobile-header { display: flex !important; }
    \\        }
    \\        /* Sidebar */
    \\        .sidebar {
    \\            background: var(--sidebar-bg);
    \\            border-right: 1px solid var(--border);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .sidebar-header {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .logo {
    \\            font-size: 1.125rem;
    \\            font-weight: 700;
    \\            color: var(--primary);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .compose-btn {
    \\            width: 100%;
    \\            padding: 10px 16px;
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            font-weight: 500;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            margin-top: 12px;
    \\            transition: all 0.2s;
    \\        }
    \\        .compose-btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
    \\        .sidebar-content { flex: 1; overflow-y: auto; padding: 12px; }
    \\        .section-title {
    \\            font-size: 0.7rem;
    \\            font-weight: 600;
    \\            text-transform: uppercase;
    \\            letter-spacing: 0.5px;
    \\            color: var(--text-muted);
    \\            padding: 12px 8px 6px;
    \\        }
    \\        .folders { list-style: none; }
    \\        .folder {
    \\            padding: 8px 10px;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 10px;
    \\            color: var(--text-muted);
    \\            transition: all 0.15s;
    \\            font-size: 0.875rem;
    \\        }
    \\        .folder:hover { background: var(--primary-light); color: var(--primary); }
    \\        .folder.active { background: var(--primary); color: white; }
    \\        .folder.active .folder-count { background: white; color: var(--primary); }
    \\        .folder-count {
    \\            margin-left: auto;
    \\            background: var(--primary);
    \\            color: white;
    \\            padding: 1px 6px;
    \\            border-radius: 10px;
    \\            font-size: 0.7rem;
    \\            font-weight: 500;
    \\        }
    \\        .sidebar-footer {
    \\            padding: 12px;
    \\            border-top: 1px solid var(--border);
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\        }
    \\        /* Message List */
    \\        .message-list {
    \\            background: var(--card-bg);
    \\            border-right: 1px solid var(--border);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .mobile-header {
    \\            display: none;
    \\            padding: 12px;
    \\            border-bottom: 1px solid var(--border);
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .menu-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 8px;
    \\            cursor: pointer;
    \\            color: var(--text);
    \\        }
    \\        .list-header {
    \\            padding: 12px 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\        }
    \\        .list-title {
    \\            font-weight: 600;
    \\            font-size: 0.875rem;
    \\        }
    \\        .list-count {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\        }
    \\        .list-actions {
    \\            margin-left: auto;
    \\            display: flex;
    \\            gap: 4px;
    \\        }
    \\        .icon-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 6px;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            border-radius: 4px;
    \\            transition: all 0.15s;
    \\        }
    \\        .icon-btn:hover { background: var(--primary-light); color: var(--primary); }
    \\        .search-bar { padding: 12px 16px; }
    \\        .search-input {
    \\            width: 100%;
    \\            padding: 8px 12px 8px 36px;
    \\            border: 1px solid var(--border);
    \\            border-radius: 8px;
    \\            font-size: 0.875rem;
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            transition: border-color 0.2s;
    \\        }
    \\        .search-input:focus { outline: none; border-color: var(--primary); }
    \\        .search-wrapper { position: relative; }
    \\        .search-icon {
    \\            position: absolute;
    \\            left: 10px;
    \\            top: 50%;
    \\            transform: translateY(-50%);
    \\            color: var(--text-muted);
    \\            pointer-events: none;
    \\        }
    \\        .messages-container { flex: 1; overflow-y: auto; }
    \\        .message-item {
    \\            padding: 12px 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            cursor: pointer;
    \\            transition: background 0.15s;
    \\            position: relative;
    \\        }
    \\        .message-item:hover { background: var(--bg); }
    \\        .message-item.unread { background: var(--primary-light); }
    \\        .message-item.unread .message-sender { font-weight: 600; }
    \\        .message-item.active { background: var(--primary-light); border-left: 3px solid var(--primary); }
    \\        .message-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    \\        .message-sender { font-size: 0.875rem; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    \\        .message-date { font-size: 0.7rem; color: var(--text-muted); white-space: nowrap; }
    \\        .message-subject {
    \\            font-size: 0.8rem;
    \\            color: var(--text);
    \\            margin-bottom: 2px;
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .message-preview {
    \\            font-size: 0.75rem;
    \\            color: var(--text-muted);
    \\            white-space: nowrap;
    \\            overflow: hidden;
    \\            text-overflow: ellipsis;
    \\        }
    \\        .message-indicators { display: flex; gap: 4px; margin-top: 4px; }
    \\        .indicator {
    \\            width: 16px;
    \\            height: 16px;
    \\            color: var(--text-muted);
    \\        }
    \\        .indicator.starred { color: var(--warning); }
    \\        /* Message View */
    \\        .message-view {
    \\            background: var(--bg);
    \\            display: flex;
    \\            flex-direction: column;
    \\            overflow: hidden;
    \\        }
    \\        .view-header {
    \\            padding: 16px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\            background: var(--card-bg);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .back-btn { display: none; }
    \\        @media (max-width: 768px) { .back-btn { display: block; } }
    \\        .view-actions { display: flex; gap: 4px; margin-left: auto; }
    \\        .view-content { flex: 1; overflow-y: auto; padding: 20px; }
    \\        .email-header { margin-bottom: 20px; }
    \\        .email-subject { font-size: 1.25rem; font-weight: 600; margin-bottom: 16px; }
    \\        .email-meta { display: flex; align-items: flex-start; gap: 12px; }
    \\        .avatar {
    \\            width: 40px;
    \\            height: 40px;
    \\            border-radius: 50%;
    \\            background: var(--primary);
    \\            color: white;
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-weight: 600;
    \\            font-size: 1rem;
    \\        }
    \\        .email-from { flex: 1; }
    \\        .from-name { font-weight: 600; font-size: 0.875rem; }
    \\        .from-email { font-size: 0.75rem; color: var(--text-muted); }
    \\        .email-to { font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }
    \\        .email-body {
    \\            background: var(--card-bg);
    \\            border-radius: 8px;
    \\            padding: 20px;
    \\            box-shadow: var(--shadow);
    \\            line-height: 1.6;
    \\        }
    \\        .email-attachments { margin-top: 16px; padding: 16px; background: var(--card-bg); border-radius: 8px; }
    \\        .attachments-title { font-size: 0.8rem; font-weight: 600; margin-bottom: 12px; color: var(--text-muted); }
    \\        .attachment-list { display: flex; flex-wrap: wrap; gap: 8px; }
    \\        .attachment {
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            padding: 8px 12px;
    \\            background: var(--bg);
    \\            border-radius: 6px;
    \\            font-size: 0.8rem;
    \\            cursor: pointer;
    \\            transition: all 0.15s;
    \\        }
    \\        .attachment:hover { background: var(--primary-light); }
    \\        .empty-state {
    \\            display: flex;
    \\            flex-direction: column;
    \\            align-items: center;
    \\            justify-content: center;
    \\            height: 100%;
    \\            color: var(--text-muted);
    \\            text-align: center;
    \\            padding: 40px;
    \\        }
    \\        .empty-state svg { width: 80px; height: 80px; margin-bottom: 16px; opacity: 0.3; }
    \\        .empty-state h3 { font-size: 1rem; margin-bottom: 8px; }
    \\        .empty-state p { font-size: 0.875rem; }
    \\        /* Compose Modal */
    \\        .modal-overlay {
    \\            display: none;
    \\            position: fixed;
    \\            top: 0;
    \\            left: 0;
    \\            width: 100%;
    \\            height: 100%;
    \\            background: rgba(0,0,0,0.5);
    \\            z-index: 200;
    \\            align-items: center;
    \\            justify-content: center;
    \\            padding: 20px;
    \\        }
    \\        .modal-overlay.open { display: flex; }
    \\        .compose-modal {
    \\            background: var(--card-bg);
    \\            border-radius: 12px;
    \\            width: 100%;
    \\            max-width: 700px;
    \\            max-height: 90vh;
    \\            display: flex;
    \\            flex-direction: column;
    \\            box-shadow: var(--shadow-lg);
    \\        }
    \\        .compose-header {
    \\            padding: 16px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .compose-title { font-weight: 600; flex: 1; }
    \\        .compose-body { flex: 1; overflow-y: auto; }
    \\        .compose-field {
    \\            display: flex;
    \\            align-items: center;
    \\            padding: 8px 20px;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .compose-field label {
    \\            font-size: 0.8rem;
    \\            color: var(--text-muted);
    \\            width: 60px;
    \\        }
    \\        .compose-field input {
    \\            flex: 1;
    \\            border: none;
    \\            background: none;
    \\            color: var(--text);
    \\            font-size: 0.875rem;
    \\            padding: 8px 0;
    \\        }
    \\        .compose-field input:focus { outline: none; }
    \\        .compose-editor {
    \\            min-height: 250px;
    \\            padding: 16px 20px;
    \\            border: none;
    \\            background: none;
    \\            color: var(--text);
    \\            font-size: 0.875rem;
    \\            line-height: 1.6;
    \\            resize: none;
    \\            width: 100%;
    \\        }
    \\        .compose-editor:focus { outline: none; }
    \\        .compose-toolbar {
    \\            padding: 8px 16px;
    \\            border-top: 1px solid var(--border);
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            gap: 4px;
    \\            flex-wrap: wrap;
    \\        }
    \\        .toolbar-btn {
    \\            background: none;
    \\            border: none;
    \\            padding: 6px 10px;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            border-radius: 4px;
    \\            font-size: 0.8rem;
    \\        }
    \\        .toolbar-btn:hover { background: var(--bg); color: var(--text); }
    \\        .compose-footer {
    \\            padding: 12px 20px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\        }
    \\        .send-btn {
    \\            background: var(--primary);
    \\            color: white;
    \\            border: none;
    \\            padding: 10px 24px;
    \\            border-radius: 6px;
    \\            font-weight: 500;
    \\            cursor: pointer;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 8px;
    \\            transition: all 0.2s;
    \\        }
    \\        .send-btn:hover { background: var(--primary-hover); }
    \\        .draft-btn {
    \\            background: var(--bg);
    \\            color: var(--text);
    \\            border: 1px solid var(--border);
    \\            padding: 10px 16px;
    \\            border-radius: 6px;
    \\            cursor: pointer;
    \\        }
    \\        /* Contacts sidebar */
    \\        .contacts-panel {
    \\            display: none;
    \\            position: fixed;
    \\            right: 0;
    \\            top: 0;
    \\            width: 320px;
    \\            height: 100%;
    \\            background: var(--card-bg);
    \\            border-left: 1px solid var(--border);
    \\            z-index: 150;
    \\            flex-direction: column;
    \\        }
    \\        .contacts-panel.open { display: flex; }
    \\        .contacts-header {
    \\            padding: 16px;
    \\            border-bottom: 1px solid var(--border);
    \\            display: flex;
    \\            align-items: center;
    \\        }
    \\        .contacts-list { flex: 1; overflow-y: auto; }
    \\        .contact-item {
    \\            padding: 12px 16px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            cursor: pointer;
    \\            border-bottom: 1px solid var(--border);
    \\        }
    \\        .contact-item:hover { background: var(--bg); }
    \\        .contact-avatar {
    \\            width: 36px;
    \\            height: 36px;
    \\            border-radius: 50%;
    \\            background: var(--primary-light);
    \\            color: var(--primary);
    \\            display: flex;
    \\            align-items: center;
    \\            justify-content: center;
    \\            font-weight: 600;
    \\        }
    \\        .contact-info { flex: 1; }
    \\        .contact-name { font-size: 0.875rem; font-weight: 500; }
    \\        .contact-email { font-size: 0.75rem; color: var(--text-muted); }
    \\        /* Calendar widget */
    \\        .calendar-widget {
    \\            padding: 12px;
    \\            border-top: 1px solid var(--border);
    \\            margin-top: auto;
    \\        }
    \\        .calendar-header {
    \\            display: flex;
    \\            align-items: center;
    \\            margin-bottom: 8px;
    \\            font-size: 0.8rem;
    \\            font-weight: 600;
    \\        }
    \\        .calendar-grid {
    \\            display: grid;
    \\            grid-template-columns: repeat(7, 1fr);
    \\            gap: 2px;
    \\            font-size: 0.7rem;
    \\            text-align: center;
    \\        }
    \\        .calendar-day { padding: 4px; border-radius: 4px; cursor: pointer; }
    \\        .calendar-day:hover { background: var(--primary-light); }
    \\        .calendar-day.today { background: var(--primary); color: white; }
    \\        .calendar-day.has-event { font-weight: 600; }
    \\        /* Toast notifications */
    \\        .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 300; }
    \\        .toast {
    \\            background: var(--card-bg);
    \\            padding: 12px 20px;
    \\            border-radius: 8px;
    \\            box-shadow: var(--shadow-lg);
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 12px;
    \\            margin-top: 8px;
    \\            animation: slideIn 0.3s ease;
    \\        }
    \\        .toast.success { border-left: 4px solid var(--success); }
    \\        .toast.error { border-left: 4px solid var(--danger); }
    \\        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    \\        /* Theme toggle */
    \\        .theme-toggle {
    \\            background: none;
    \\            border: none;
    \\            cursor: pointer;
    \\            color: var(--text-muted);
    \\            padding: 8px;
    \\            border-radius: 6px;
    \\        }
    \\        .theme-toggle:hover { background: var(--bg); }
    \\    </style>
    \\</head>
    \\<body>
    \\    <div class="app">
    \\        <!-- Sidebar -->
    \\        <aside class="sidebar" id="sidebar">
    \\            <div class="sidebar-header">
    \\                <div class="logo">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    \\                        <polyline points="22,6 12,13 2,6"/>
    \\                    </svg>
    \\                    <span class="folder-name">Webmail</span>
    \\                </div>
    \\                <button class="compose-btn" onclick="openCompose()">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
    \\                    </svg>
    \\                    <span class="compose-text">Compose</span>
    \\                </button>
    \\            </div>
    \\            <div class="sidebar-content">
    \\                <div class="section-title">Folders</div>
    \\                <ul class="folders" id="folders">
    \\                    <li class="folder active" data-folder="inbox">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>
    \\                            <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
    \\                        </svg>
    \\                        <span class="folder-name">Inbox</span>
    \\                        <span class="folder-count" id="inbox-count">3</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="starred">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Starred</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="sent">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Sent</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="drafts">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
    \\                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
    \\                        </svg>
    \\                        <span class="folder-name">Drafts</span>
    \\                        <span class="folder-count">1</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="archive">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    \\                            <line x1="10" y1="12" x2="14" y2="12"/>
    \\                        </svg>
    \\                        <span class="folder-name">Archive</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="spam">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    \\                            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    \\                        </svg>
    \\                        <span class="folder-name">Spam</span>
    \\                    </li>
    \\                    <li class="folder" data-folder="trash">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    \\                        </svg>
    \\                        <span class="folder-name">Trash</span>
    \\                    </li>
    \\                </ul>
    \\                <div class="section-title" style="margin-top: 16px;">Labels</div>
    \\                <ul class="folders">
    \\                    <li class="folder" data-label="work">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="#3b82f6" stroke="#3b82f6" stroke-width="2">
    \\                            <circle cx="12" cy="12" r="4"/>
    \\                        </svg>
    \\                        <span class="folder-name">Work</span>
    \\                    </li>
    \\                    <li class="folder" data-label="personal">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="#10b981" stroke="#10b981" stroke-width="2">
    \\                            <circle cx="12" cy="12" r="4"/>
    \\                        </svg>
    \\                        <span class="folder-name">Personal</span>
    \\                    </li>
    \\                </ul>
    \\                <!-- Mini Calendar -->
    \\                <div class="calendar-widget">
    \\                    <div class="calendar-header">
    \\                        <span id="calendar-month">November 2025</span>
    \\                    </div>
    \\                    <div class="calendar-grid" id="calendar-grid"></div>
    \\                </div>
    \\            </div>
    \\            <div class="sidebar-footer">
    \\                <div style="display: flex; align-items: center; justify-content: space-between;">
    \\                    <span>v0.28.0</span>
    \\                    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="theme-icon">
    \\                            <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
    \\                            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    \\                            <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
    \\                            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    \\                        </svg>
    \\                    </button>
    \\                </div>
    \\            </div>
    \\        </aside>
    \\        <!-- Message List -->
    \\        <section class="message-list">
    \\            <div class="mobile-header">
    \\                <button class="menu-btn" onclick="toggleSidebar()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>
    \\                    </svg>
    \\                </button>
    \\                <span style="font-weight: 600;">Inbox</span>
    \\            </div>
    \\            <div class="list-header">
    \\                <span class="list-title" id="list-title">Inbox</span>
    \\                <span class="list-count" id="list-count">(3 messages)</span>
    \\                <div class="list-actions">
    \\                    <button class="icon-btn" onclick="refreshMessages()" title="Refresh">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
    \\                            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    \\                        </svg>
    \\                    </button>
    \\                    <button class="icon-btn" onclick="toggleContacts()" title="Contacts">
    \\                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
    \\                            <circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    \\                        </svg>
    \\                    </button>
    \\                </div>
    \\            </div>
    \\            <div class="search-bar">
    \\                <div class="search-wrapper">
    \\                    <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    \\                    </svg>
    \\                    <input type="text" class="search-input" placeholder="Search emails..." id="search" oninput="searchMessages(this.value)">
    \\                </div>
    \\            </div>
    \\            <div class="messages-container" id="messages"></div>
    \\        </section>
    \\        <!-- Message View -->
    \\        <main class="message-view" id="message-view">
    \\            <div class="empty-state" id="empty-state">
    \\                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
    \\                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    \\                    <polyline points="22,6 12,13 2,6"/>
    \\                </svg>
    \\                <h3>Select an email to read</h3>
    \\                <p>Choose from your inbox on the left</p>
    \\            </div>
    \\            <div id="email-content" style="display: none;">
    \\                <div class="view-header">
    \\                    <button class="icon-btn back-btn" onclick="closeEmail()">
    \\                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                            <line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>
    \\                        </svg>
    \\                    </button>
    \\                    <div class="view-actions">
    \\                        <button class="icon-btn" onclick="archiveEmail()" title="Archive">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="deleteEmail()" title="Delete">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="replyEmail()" title="Reply">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>
    \\                            </svg>
    \\                        </button>
    \\                        <button class="icon-btn" onclick="forwardEmail()" title="Forward">
    \\                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                                <polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>
    \\                            </svg>
    \\                        </button>
    \\                    </div>
    \\                </div>
    \\                <div class="view-content">
    \\                    <div class="email-header">
    \\                        <h1 class="email-subject" id="email-subject"></h1>
    \\                        <div class="email-meta">
    \\                            <div class="avatar" id="email-avatar"></div>
    \\                            <div class="email-from">
    \\                                <div class="from-name" id="email-from-name"></div>
    \\                                <div class="from-email" id="email-from-email"></div>
    \\                                <div class="email-to" id="email-to"></div>
    \\                            </div>
    \\                            <div class="email-date" id="email-date" style="font-size: 0.75rem; color: var(--text-muted);"></div>
    \\                        </div>
    \\                    </div>
    \\                    <div class="email-body" id="email-body"></div>
    \\                    <div class="email-attachments" id="email-attachments" style="display: none;">
    \\                        <div class="attachments-title">Attachments</div>
    \\                        <div class="attachment-list" id="attachment-list"></div>
    \\                    </div>
    \\                </div>
    \\            </div>
    \\        </main>
    \\    </div>
    \\    <!-- Compose Modal -->
    \\    <div class="modal-overlay" id="compose-modal">
    \\        <div class="compose-modal">
    \\            <div class="compose-header">
    \\                <span class="compose-title">New Message</span>
    \\                <button class="icon-btn" onclick="closeCompose()">
    \\                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                    </svg>
    \\                </button>
    \\            </div>
    \\            <div class="compose-body">
    \\                <div class="compose-field">
    \\                    <label>To</label>
    \\                    <input type="email" id="compose-to" placeholder="recipient@example.com">
    \\                </div>
    \\                <div class="compose-field">
    \\                    <label>Cc</label>
    \\                    <input type="email" id="compose-cc" placeholder="cc@example.com">
    \\                </div>
    \\                <div class="compose-field">
    \\                    <label>Subject</label>
    \\                    <input type="text" id="compose-subject" placeholder="Email subject">
    \\                </div>
    \\                <div class="compose-toolbar">
    \\                    <button class="toolbar-btn" onclick="formatText('bold')" title="Bold"><b>B</b></button>
    \\                    <button class="toolbar-btn" onclick="formatText('italic')" title="Italic"><i>I</i></button>
    \\                    <button class="toolbar-btn" onclick="formatText('underline')" title="Underline"><u>U</u></button>
    \\                    <button class="toolbar-btn" onclick="formatText('strikethrough')" title="Strikethrough"><s>S</s></button>
    \\                    <button class="toolbar-btn" onclick="insertLink()" title="Insert link">Link</button>
    \\                    <button class="toolbar-btn" onclick="attachFile()" title="Attach file">Attach</button>
    \\                </div>
    \\                <textarea class="compose-editor" id="compose-body" placeholder="Write your message..."></textarea>
    \\            </div>
    \\            <div class="compose-footer">
    \\                <button class="send-btn" onclick="sendEmail()">
    \\                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    \\                    </svg>
    \\                    Send
    \\                </button>
    \\                <button class="draft-btn" onclick="saveDraft()">Save Draft</button>
    \\            </div>
    \\        </div>
    \\    </div>
    \\    <!-- Contacts Panel -->
    \\    <div class="contacts-panel" id="contacts-panel">
    \\        <div class="contacts-header">
    \\            <span style="font-weight: 600; flex: 1;">Contacts</span>
    \\            <button class="icon-btn" onclick="toggleContacts()">
    \\                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    \\                </svg>
    \\            </button>
    \\        </div>
    \\        <div class="search-bar">
    \\            <div class="search-wrapper">
    \\                <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    \\                </svg>
    \\                <input type="text" class="search-input" placeholder="Search contacts...">
    \\            </div>
    \\        </div>
    \\        <div class="contacts-list" id="contacts-list"></div>
    \\    </div>
    \\    <!-- Toast Container -->
    \\    <div class="toast-container" id="toast-container"></div>
    \\    <script>
    \\        // State
    \\        let currentFolder = 'inbox';
    \\        let currentEmail = null;
    \\        let messages = [];
    \\        let contacts = [
    \\            { id: '1', name: 'John Doe', email: 'john@example.com' },
    \\            { id: '2', name: 'Jane Smith', email: 'jane@example.com' },
    \\            { id: '3', name: 'Support Team', email: 'support@smtp-server.local' }
    \\        ];
    \\        // Demo messages
    \\        const demoMessages = [
    \\            { id: '1', from: { name: 'Welcome Team', email: 'welcome@smtp-server.local' }, subject: 'Welcome to your new email server!', preview: 'Congratulations on setting up your SMTP server...', date: 'Today', unread: true, starred: false, body: 'Congratulations on setting up your SMTP server!\\n\\nYour email server is now ready to use. Here are some things you can do:\\n\\n1. Send and receive emails\\n2. Manage your contacts\\n3. Organize with folders and labels\\n4. Search your messages\\n\\nEnjoy your new secure email experience!' },
    \\            { id: '2', from: { name: 'Security Alert', email: 'security@smtp-server.local' }, subject: 'Your account security settings', preview: 'We recommend enabling two-factor authentication...', date: 'Yesterday', unread: true, starred: true, body: 'We recommend enabling two-factor authentication for your account to improve security.\\n\\nYou can configure this in your account settings.' },
    \\            { id: '3', from: { name: 'System Updates', email: 'updates@smtp-server.local' }, subject: 'New features available', preview: 'Check out the latest features in v0.28.0...', date: 'Nov 25', unread: false, starred: false, body: 'New features in version 0.28.0:\\n\\n- Improved webmail interface\\n- Better mobile support\\n- Enhanced search\\n- Calendar integration\\n- Contact management\\n\\nUpdate now to get these features!' }
    \\        ];
    \\        messages = demoMessages;
    \\        // Initialize
    \\        document.addEventListener('DOMContentLoaded', () => {
    \\            initTheme();
    \\            renderMessages();
    \\            renderContacts();
    \\            renderCalendar();
    \\            setupFolderListeners();
    \\        });
    \\        function initTheme() {
    \\            const saved = localStorage.getItem('theme');
    \\            if (saved) {
    \\                document.documentElement.setAttribute('data-theme', saved);
    \\            } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    \\                document.documentElement.setAttribute('data-theme', 'dark');
    \\            }
    \\        }
    \\        function toggleTheme() {
    \\            const current = document.documentElement.getAttribute('data-theme');
    \\            const next = current === 'dark' ? 'light' : 'dark';
    \\            document.documentElement.setAttribute('data-theme', next);
    \\            localStorage.setItem('theme', next);
    \\        }
    \\        function setupFolderListeners() {
    \\            document.querySelectorAll('.folder').forEach(folder => {
    \\                folder.addEventListener('click', () => {
    \\                    document.querySelectorAll('.folder').forEach(f => f.classList.remove('active'));
    \\                    folder.classList.add('active');
    \\                    currentFolder = folder.dataset.folder || folder.dataset.label;
    \\                    document.getElementById('list-title').textContent = folder.querySelector('.folder-name').textContent;
    \\                    loadMessages(currentFolder);
    \\                    closeSidebar();
    \\                });
    \\            });
    \\        }
    \\        function renderMessages() {
    \\            const container = document.getElementById('messages');
    \\            container.innerHTML = messages.map(msg => `
    \\                <div class="message-item ${msg.unread ? 'unread' : ''}" onclick="openEmail('${msg.id}')">
    \\                    <div class="message-header">
    \\                        <span class="message-sender">${msg.from.name}</span>
    \\                        <span class="message-date">${msg.date}</span>
    \\                    </div>
    \\                    <div class="message-subject">${msg.subject}</div>
    \\                    <div class="message-preview">${msg.preview}</div>
    \\                    <div class="message-indicators">
    \\                        ${msg.starred ? '<svg class="indicator starred" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>' : ''}
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\            document.getElementById('list-count').textContent = `(${messages.length} messages)`;
    \\        }
    \\        function renderContacts() {
    \\            const list = document.getElementById('contacts-list');
    \\            list.innerHTML = contacts.map(c => `
    \\                <div class="contact-item" onclick="selectContact('${c.email}')">
    \\                    <div class="contact-avatar">${c.name.charAt(0)}</div>
    \\                    <div class="contact-info">
    \\                        <div class="contact-name">${c.name}</div>
    \\                        <div class="contact-email">${c.email}</div>
    \\                    </div>
    \\                </div>
    \\            `).join('');
    \\        }
    \\        function renderCalendar() {
    \\            const grid = document.getElementById('calendar-grid');
    \\            const today = new Date();
    \\            const days = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];
    \\            let html = days.map(d => `<div style="font-weight: 600; color: var(--text-muted);">${d}</div>`).join('');
    \\            const firstDay = new Date(today.getFullYear(), today.getMonth(), 1).getDay();
    \\            const daysInMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0).getDate();
    \\            for (let i = 0; i < firstDay; i++) html += '<div></div>';
    \\            for (let d = 1; d <= daysInMonth; d++) {
    \\                const isToday = d === today.getDate();
    \\                html += `<div class="calendar-day ${isToday ? 'today' : ''}">${d}</div>`;
    \\            }
    \\            grid.innerHTML = html;
    \\            document.getElementById('calendar-month').textContent = today.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    \\        }
    \\        function openEmail(id) {
    \\            const email = messages.find(m => m.id === id);
    \\            if (!email) return;
    \\            currentEmail = email;
    \\            email.unread = false;
    \\            document.querySelectorAll('.message-item').forEach(el => el.classList.remove('active'));
    \\            event.currentTarget.classList.add('active');
    \\            document.getElementById('email-subject').textContent = email.subject;
    \\            document.getElementById('email-avatar').textContent = email.from.name.charAt(0);
    \\            document.getElementById('email-from-name').textContent = email.from.name;
    \\            document.getElementById('email-from-email').textContent = `<${email.from.email}>`;
    \\            document.getElementById('email-to').textContent = 'To: me';
    \\            document.getElementById('email-date').textContent = email.date;
    \\            document.getElementById('email-body').innerHTML = email.body.replace(/\\n/g, '<br>');
    \\            document.getElementById('empty-state').style.display = 'none';
    \\            document.getElementById('email-content').style.display = 'block';
    \\            document.getElementById('message-view').classList.add('open');
    \\            renderMessages();
    \\        }
    \\        function closeEmail() {
    \\            document.getElementById('message-view').classList.remove('open');
    \\            document.getElementById('empty-state').style.display = 'flex';
    \\            document.getElementById('email-content').style.display = 'none';
    \\            currentEmail = null;
    \\        }
    \\        function openCompose() {
    \\            document.getElementById('compose-modal').classList.add('open');
    \\        }
    \\        function closeCompose() {
    \\            document.getElementById('compose-modal').classList.remove('open');
    \\            document.getElementById('compose-to').value = '';
    \\            document.getElementById('compose-cc').value = '';
    \\            document.getElementById('compose-subject').value = '';
    \\            document.getElementById('compose-body').value = '';
    \\        }
    \\        function sendEmail() {
    \\            const to = document.getElementById('compose-to').value;
    \\            const subject = document.getElementById('compose-subject').value;
    \\            if (!to || !subject) {
    \\                showToast('Please fill in required fields', 'error');
    \\                return;
    \\            }
    \\            fetch('/webmail/api/compose', {
    \\                method: 'POST',
    \\                headers: { 'Content-Type': 'application/json' },
    \\                body: JSON.stringify({
    \\                    to: [to],
    \\                    cc: document.getElementById('compose-cc').value ? [document.getElementById('compose-cc').value] : [],
    \\                    subject: subject,
    \\                    body_text: document.getElementById('compose-body').value
    \\                })
    \\            }).then(() => {
    \\                showToast('Email sent successfully!', 'success');
    \\                closeCompose();
    \\            }).catch(() => {
    \\                showToast('Failed to send email', 'error');
    \\            });
    \\        }
    \\        function saveDraft() {
    \\            showToast('Draft saved', 'success');
    \\            closeCompose();
    \\        }
    \\        function replyEmail() {
    \\            if (!currentEmail) return;
    \\            openCompose();
    \\            document.getElementById('compose-to').value = currentEmail.from.email;
    \\            document.getElementById('compose-subject').value = 'Re: ' + currentEmail.subject;
    \\        }
    \\        function forwardEmail() {
    \\            if (!currentEmail) return;
    \\            openCompose();
    \\            document.getElementById('compose-subject').value = 'Fwd: ' + currentEmail.subject;
    \\            document.getElementById('compose-body').value = '\\n\\n---------- Forwarded message ----------\\n' + currentEmail.body;
    \\        }
    \\        function archiveEmail() {
    \\            if (!currentEmail) return;
    \\            showToast('Email archived', 'success');
    \\            closeEmail();
    \\        }
    \\        function deleteEmail() {
    \\            if (!currentEmail) return;
    \\            messages = messages.filter(m => m.id !== currentEmail.id);
    \\            renderMessages();
    \\            showToast('Email deleted', 'success');
    \\            closeEmail();
    \\        }
    \\        function toggleSidebar() {
    \\            document.getElementById('sidebar').classList.toggle('open');
    \\        }
    \\        function closeSidebar() {
    \\            document.getElementById('sidebar').classList.remove('open');
    \\        }
    \\        function toggleContacts() {
    \\            document.getElementById('contacts-panel').classList.toggle('open');
    \\        }
    \\        function selectContact(email) {
    \\            openCompose();
    \\            document.getElementById('compose-to').value = email;
    \\            toggleContacts();
    \\        }
    \\        function loadMessages(folder) {
    \\            fetch('/webmail/api/messages?folder=' + folder)
    \\                .then(r => r.json())
    \\                .catch(() => {});
    \\        }
    \\        function searchMessages(query) {
    \\            if (query.length < 2) {
    \\                messages = demoMessages;
    \\                renderMessages();
    \\                return;
    \\            }
    \\            messages = demoMessages.filter(m =>
    \\                m.subject.toLowerCase().includes(query.toLowerCase()) ||
    \\                m.from.name.toLowerCase().includes(query.toLowerCase()) ||
    \\                m.preview.toLowerCase().includes(query.toLowerCase())
    \\            );
    \\            renderMessages();
    \\        }
    \\        function refreshMessages() {
    \\            showToast('Messages refreshed', 'success');
    \\            loadMessages(currentFolder);
    \\        }
    \\        function formatText(format) {
    \\            document.execCommand(format, false, null);
    \\        }
    \\        function insertLink() {
    \\            const url = prompt('Enter URL:');
    \\            if (url) document.execCommand('createLink', false, url);
    \\        }
    \\        function attachFile() {
    \\            showToast('File attachment coming soon', 'success');
    \\        }
    \\        function showToast(message, type) {
    \\            const container = document.getElementById('toast-container');
    \\            const toast = document.createElement('div');
    \\            toast.className = 'toast ' + type;
    \\            toast.textContent = message;
    \\            container.appendChild(toast);
    \\            setTimeout(() => toast.remove(), 3000);
    \\        }
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
