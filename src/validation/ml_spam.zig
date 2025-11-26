//! Machine Learning Spam Detection Module
//!
//! Provides ML-based spam detection with:
//! - Naive Bayes classifier with multinomial model
//! - Feature extraction from email content and headers
//! - Online training from user feedback
//! - Model versioning and rollback support
//! - Integration with existing spam scoring
//!
//! Usage:
//! ```zig
//! var detector = try SpamDetector.init(allocator, .{});
//! defer detector.deinit();
//!
//! // Classify a message
//! const result = try detector.classify(message);
//! if (result.is_spam) {
//!     // Handle spam
//! }
//!
//! // Train from user feedback
//! try detector.trainFromFeedback(message, .spam);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

// =============================================================================
// Configuration
// =============================================================================

pub const SpamDetectorConfig = struct {
    /// Spam probability threshold (0.0-1.0)
    spam_threshold: f64 = 0.7,

    /// Minimum word frequency to include in model
    min_word_frequency: u32 = 3,

    /// Maximum vocabulary size
    max_vocabulary_size: u32 = 100000,

    /// Smoothing parameter (Laplace smoothing)
    smoothing_alpha: f64 = 1.0,

    /// Enable header feature extraction
    use_header_features: bool = true,

    /// Enable URL feature extraction
    use_url_features: bool = true,

    /// Enable HTML feature extraction
    use_html_features: bool = true,

    /// Model storage path
    model_path: []const u8 = "/var/lib/mail/spam_model.bin",

    /// Auto-save interval (messages)
    auto_save_interval: u32 = 1000,

    /// Maximum training samples to keep in memory
    max_training_samples: u32 = 10000,
};

// =============================================================================
// Feature Extraction
// =============================================================================

pub const FeatureType = enum {
    word,
    header,
    url_count,
    url_domain,
    html_tag,
    attachment_type,
    sender_domain,
    recipient_count,
    subject_pattern,
    body_length,
    caps_ratio,
    digit_ratio,
    special_char_ratio,
};

pub const Feature = struct {
    feature_type: FeatureType,
    name: []const u8,
    value: f64,
};

pub const FeatureExtractor = struct {
    const Self = @This();

    allocator: Allocator,
    config: SpamDetectorConfig,
    stop_words: std.StringHashMap(void),

    pub fn init(allocator: Allocator, config: SpamDetectorConfig) !Self {
        var extractor = Self{
            .allocator = allocator,
            .config = config,
            .stop_words = std.StringHashMap(void).init(allocator),
        };

        // Add common stop words
        const stop_list = [_][]const u8{
            "the", "a",   "an",  "and", "or",  "but", "in",  "on",  "at",  "to",
            "for", "of",  "is",  "it",  "be",  "as",  "was", "are", "been", "have",
            "has", "had", "do",  "does", "did", "will", "would", "could", "should",
            "may", "might", "must", "can", "this", "that", "these", "those", "i",
            "you", "he",  "she", "we",  "they", "my",  "your", "his", "her", "our",
        };

        for (stop_list) |word| {
            try extractor.stop_words.put(word, {});
        }

        return extractor;
    }

    pub fn deinit(self: *Self) void {
        self.stop_words.deinit();
    }

    pub fn extractFeatures(self: *Self, message: *const EmailMessage) ![]Feature {
        var features = std.ArrayList(Feature).init(self.allocator);
        errdefer features.deinit();

        // Extract word features from body
        try self.extractWordFeatures(&features, message.body);

        // Extract word features from subject
        try self.extractWordFeatures(&features, message.subject);

        // Header features
        if (self.config.use_header_features) {
            try self.extractHeaderFeatures(&features, message);
        }

        // URL features
        if (self.config.use_url_features) {
            try self.extractUrlFeatures(&features, message.body);
        }

        // HTML features
        if (self.config.use_html_features) {
            try self.extractHtmlFeatures(&features, message.body);
        }

        // Statistical features
        try self.extractStatisticalFeatures(&features, message);

        return features.toOwnedSlice();
    }

    fn extractWordFeatures(self: *Self, features: *std.ArrayList(Feature), text: []const u8) !void {
        var word_start: ?usize = null;
        var i: usize = 0;

        while (i < text.len) : (i += 1) {
            const c = text[i];
            const is_alpha = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');

            if (is_alpha) {
                if (word_start == null) {
                    word_start = i;
                }
            } else {
                if (word_start) |start| {
                    const word = text[start..i];
                    if (word.len >= 3 and word.len <= 20) {
                        // Convert to lowercase and check stop words
                        var lower_buf: [20]u8 = undefined;
                        const lower = self.toLower(word, &lower_buf);

                        if (!self.stop_words.contains(lower)) {
                            try features.append(.{
                                .feature_type = .word,
                                .name = lower,
                                .value = 1.0,
                            });
                        }
                    }
                    word_start = null;
                }
            }
        }
    }

    fn extractHeaderFeatures(self: *Self, features: *std.ArrayList(Feature), message: *const EmailMessage) !void {
        _ = self;

        // Sender domain feature
        if (message.sender_domain.len > 0) {
            try features.append(.{
                .feature_type = .sender_domain,
                .name = message.sender_domain,
                .value = 1.0,
            });
        }

        // Recipient count
        try features.append(.{
            .feature_type = .recipient_count,
            .name = "recipient_count",
            .value = @floatFromInt(message.recipient_count),
        });

        // Check for suspicious headers
        if (message.has_precedence_bulk) {
            try features.append(.{
                .feature_type = .header,
                .name = "precedence_bulk",
                .value = 1.0,
            });
        }

        if (message.has_list_unsubscribe) {
            try features.append(.{
                .feature_type = .header,
                .name = "list_unsubscribe",
                .value = 1.0,
            });
        }
    }

    fn extractUrlFeatures(self: *Self, features: *std.ArrayList(Feature), text: []const u8) !void {
        _ = self;

        var url_count: u32 = 0;
        var i: usize = 0;

        // Simple URL detection
        while (i < text.len) : (i += 1) {
            if (i + 7 < text.len) {
                if (std.mem.eql(u8, text[i .. i + 7], "http://") or
                    (i + 8 < text.len and std.mem.eql(u8, text[i .. i + 8], "https://")))
                {
                    url_count += 1;
                    // Skip past URL
                    while (i < text.len and text[i] != ' ' and text[i] != '\n') : (i += 1) {}
                }
            }
        }

        try features.append(.{
            .feature_type = .url_count,
            .name = "url_count",
            .value = @floatFromInt(url_count),
        });

        // High URL count is suspicious
        if (url_count > 5) {
            try features.append(.{
                .feature_type = .url_count,
                .name = "high_url_count",
                .value = 1.0,
            });
        }
    }

    fn extractHtmlFeatures(self: *Self, features: *std.ArrayList(Feature), text: []const u8) !void {
        _ = self;

        var has_html = false;
        var has_script = false;
        var has_form = false;
        var has_hidden = false;

        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            if (text[i] == '<') {
                has_html = true;

                // Check for specific tags
                if (i + 7 < text.len and std.ascii.eqlIgnoreCase(text[i .. i + 7], "<script")) {
                    has_script = true;
                }
                if (i + 5 < text.len and std.ascii.eqlIgnoreCase(text[i .. i + 5], "<form")) {
                    has_form = true;
                }
                if (std.mem.indexOf(u8, text[i..@min(i + 50, text.len)], "hidden")) |_| {
                    has_hidden = true;
                }
            }
        }

        if (has_html) {
            try features.append(.{ .feature_type = .html_tag, .name = "has_html", .value = 1.0 });
        }
        if (has_script) {
            try features.append(.{ .feature_type = .html_tag, .name = "has_script", .value = 1.0 });
        }
        if (has_form) {
            try features.append(.{ .feature_type = .html_tag, .name = "has_form", .value = 1.0 });
        }
        if (has_hidden) {
            try features.append(.{ .feature_type = .html_tag, .name = "has_hidden", .value = 1.0 });
        }
    }

    fn extractStatisticalFeatures(self: *Self, features: *std.ArrayList(Feature), message: *const EmailMessage) !void {
        _ = self;

        const body = message.body;
        if (body.len == 0) return;

        var caps_count: usize = 0;
        var digit_count: usize = 0;
        var special_count: usize = 0;

        for (body) |c| {
            if (c >= 'A' and c <= 'Z') caps_count += 1;
            if (c >= '0' and c <= '9') digit_count += 1;
            if (c == '!' or c == '$' or c == '%' or c == '*' or c == '#') special_count += 1;
        }

        const body_len_f: f64 = @floatFromInt(body.len);

        try features.append(.{
            .feature_type = .caps_ratio,
            .name = "caps_ratio",
            .value = @as(f64, @floatFromInt(caps_count)) / body_len_f,
        });

        try features.append(.{
            .feature_type = .digit_ratio,
            .name = "digit_ratio",
            .value = @as(f64, @floatFromInt(digit_count)) / body_len_f,
        });

        try features.append(.{
            .feature_type = .special_char_ratio,
            .name = "special_ratio",
            .value = @as(f64, @floatFromInt(special_count)) / body_len_f,
        });

        // Body length buckets
        const len_bucket: []const u8 = if (body.len < 500)
            "body_short"
        else if (body.len < 2000)
            "body_medium"
        else if (body.len < 10000)
            "body_long"
        else
            "body_very_long";

        try features.append(.{
            .feature_type = .body_length,
            .name = len_bucket,
            .value = 1.0,
        });
    }

    fn toLower(self: *Self, word: []const u8, buf: *[20]u8) []const u8 {
        _ = self;
        const len = @min(word.len, 20);
        for (word[0..len], 0..) |c, i| {
            buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        return buf[0..len];
    }
};

// =============================================================================
// Naive Bayes Classifier
// =============================================================================

pub const NaiveBayesClassifier = struct {
    const Self = @This();

    allocator: Allocator,
    config: SpamDetectorConfig,

    // Word counts per class
    spam_word_counts: std.StringHashMap(u64),
    ham_word_counts: std.StringHashMap(u64),

    // Total counts
    spam_total_words: u64,
    ham_total_words: u64,
    spam_messages: u64,
    ham_messages: u64,

    // Vocabulary
    vocabulary_size: u64,

    // Model metadata
    version: u32,
    trained_at: i64,

    pub fn init(allocator: Allocator, config: SpamDetectorConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .spam_word_counts = std.StringHashMap(u64).init(allocator),
            .ham_word_counts = std.StringHashMap(u64).init(allocator),
            .spam_total_words = 0,
            .ham_total_words = 0,
            .spam_messages = 0,
            .ham_messages = 0,
            .vocabulary_size = 0,
            .version = 1,
            .trained_at = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free owned keys
        var spam_iter = self.spam_word_counts.keyIterator();
        while (spam_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.spam_word_counts.deinit();

        var ham_iter = self.ham_word_counts.keyIterator();
        while (ham_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.ham_word_counts.deinit();
    }

    pub fn train(self: *Self, features: []const Feature, is_spam: bool) !void {
        const word_counts = if (is_spam) &self.spam_word_counts else &self.ham_word_counts;
        const total_words = if (is_spam) &self.spam_total_words else &self.ham_total_words;

        for (features) |feature| {
            if (feature.feature_type == .word) {
                if (word_counts.getPtr(feature.name)) |count| {
                    count.* += 1;
                } else {
                    const owned_name = try self.allocator.dupe(u8, feature.name);
                    try word_counts.put(owned_name, 1);
                    self.vocabulary_size += 1;
                }
                total_words.* += 1;
            }
        }

        if (is_spam) {
            self.spam_messages += 1;
        } else {
            self.ham_messages += 1;
        }

        self.trained_at = std.time.timestamp();
    }

    pub fn classify(self: *Self, features: []const Feature) ClassificationResult {
        const total_messages = self.spam_messages + self.ham_messages;
        if (total_messages == 0) {
            return .{
                .spam_probability = 0.5,
                .ham_probability = 0.5,
                .is_spam = false,
                .confidence = 0.0,
            };
        }

        // Prior probabilities
        const p_spam = @as(f64, @floatFromInt(self.spam_messages)) / @as(f64, @floatFromInt(total_messages));
        const p_ham = @as(f64, @floatFromInt(self.ham_messages)) / @as(f64, @floatFromInt(total_messages));

        // Log probabilities to avoid underflow
        var log_p_spam = @log(p_spam);
        var log_p_ham = @log(p_ham);

        const vocab_size_f: f64 = @floatFromInt(self.vocabulary_size);
        const alpha = self.config.smoothing_alpha;

        for (features) |feature| {
            if (feature.feature_type == .word) {
                // Laplace smoothing
                const spam_count = self.spam_word_counts.get(feature.name) orelse 0;
                const ham_count = self.ham_word_counts.get(feature.name) orelse 0;

                const p_word_spam = (@as(f64, @floatFromInt(spam_count)) + alpha) /
                    (@as(f64, @floatFromInt(self.spam_total_words)) + alpha * vocab_size_f);

                const p_word_ham = (@as(f64, @floatFromInt(ham_count)) + alpha) /
                    (@as(f64, @floatFromInt(self.ham_total_words)) + alpha * vocab_size_f);

                log_p_spam += @log(p_word_spam);
                log_p_ham += @log(p_word_ham);
            }
        }

        // Convert back to probabilities
        const max_log = @max(log_p_spam, log_p_ham);
        const exp_spam = @exp(log_p_spam - max_log);
        const exp_ham = @exp(log_p_ham - max_log);
        const total = exp_spam + exp_ham;

        const spam_prob = exp_spam / total;
        const ham_prob = exp_ham / total;

        return .{
            .spam_probability = spam_prob,
            .ham_probability = ham_prob,
            .is_spam = spam_prob >= self.config.spam_threshold,
            .confidence = @abs(spam_prob - 0.5) * 2.0,
        };
    }

    pub fn save(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        var writer = file.writer();

        // Write header
        try writer.writeAll("MLSPAM01"); // Magic + version
        try writer.writeInt(u32, self.version, .little);
        try writer.writeInt(i64, self.trained_at, .little);
        try writer.writeInt(u64, self.spam_messages, .little);
        try writer.writeInt(u64, self.ham_messages, .little);
        try writer.writeInt(u64, self.vocabulary_size, .little);

        // Write spam word counts
        try writer.writeInt(u64, self.spam_word_counts.count(), .little);
        var spam_iter = self.spam_word_counts.iterator();
        while (spam_iter.next()) |entry| {
            const word = entry.key_ptr.*;
            const count = entry.value_ptr.*;
            try writer.writeInt(u32, @intCast(word.len), .little);
            try writer.writeAll(word);
            try writer.writeInt(u64, count, .little);
        }

        // Write ham word counts
        try writer.writeInt(u64, self.ham_word_counts.count(), .little);
        var ham_iter = self.ham_word_counts.iterator();
        while (ham_iter.next()) |entry| {
            const word = entry.key_ptr.*;
            const count = entry.value_ptr.*;
            try writer.writeInt(u32, @intCast(word.len), .little);
            try writer.writeAll(word);
            try writer.writeInt(u64, count, .little);
        }
    }

    pub fn load(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        var reader = file.reader();

        // Read and verify header
        var magic: [8]u8 = undefined;
        _ = try reader.readAll(&magic);
        if (!std.mem.eql(u8, &magic, "MLSPAM01")) {
            return error.InvalidModelFormat;
        }

        self.version = try reader.readInt(u32, .little);
        self.trained_at = try reader.readInt(i64, .little);
        self.spam_messages = try reader.readInt(u64, .little);
        self.ham_messages = try reader.readInt(u64, .little);
        self.vocabulary_size = try reader.readInt(u64, .little);

        // Read spam word counts
        const spam_count = try reader.readInt(u64, .little);
        var i: u64 = 0;
        while (i < spam_count) : (i += 1) {
            const word_len = try reader.readInt(u32, .little);
            const word = try self.allocator.alloc(u8, word_len);
            _ = try reader.readAll(word);
            const count = try reader.readInt(u64, .little);
            try self.spam_word_counts.put(word, count);
            self.spam_total_words += count;
        }

        // Read ham word counts
        const ham_count = try reader.readInt(u64, .little);
        i = 0;
        while (i < ham_count) : (i += 1) {
            const word_len = try reader.readInt(u32, .little);
            const word = try self.allocator.alloc(u8, word_len);
            _ = try reader.readAll(word);
            const count = try reader.readInt(u64, .little);
            try self.ham_word_counts.put(word, count);
            self.ham_total_words += count;
        }
    }
};

pub const ClassificationResult = struct {
    spam_probability: f64,
    ham_probability: f64,
    is_spam: bool,
    confidence: f64,
};

// =============================================================================
// Model Versioning
// =============================================================================

pub const ModelVersion = struct {
    version: u32,
    created_at: i64,
    spam_messages: u64,
    ham_messages: u64,
    accuracy: f64,
    path: []const u8,
};

pub const ModelVersionManager = struct {
    const Self = @This();

    allocator: Allocator,
    versions: std.ArrayList(ModelVersion),
    base_path: []const u8,
    max_versions: u32,

    pub fn init(allocator: Allocator, base_path: []const u8, max_versions: u32) Self {
        return .{
            .allocator = allocator,
            .versions = std.ArrayList(ModelVersion).init(allocator),
            .base_path = base_path,
            .max_versions = max_versions,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.versions.items) |v| {
            self.allocator.free(v.path);
        }
        self.versions.deinit();
    }

    pub fn saveVersion(self: *Self, classifier: *NaiveBayesClassifier, accuracy: f64) !u32 {
        const new_version = if (self.versions.items.len > 0)
            self.versions.items[self.versions.items.len - 1].version + 1
        else
            1;

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/model_v{d}.bin",
            .{ self.base_path, new_version },
        );

        try classifier.save(path);

        try self.versions.append(.{
            .version = new_version,
            .created_at = std.time.timestamp(),
            .spam_messages = classifier.spam_messages,
            .ham_messages = classifier.ham_messages,
            .accuracy = accuracy,
            .path = path,
        });

        // Prune old versions
        while (self.versions.items.len > self.max_versions) {
            const old = self.versions.orderedRemove(0);
            std.fs.cwd().deleteFile(old.path) catch {};
            self.allocator.free(old.path);
        }

        return new_version;
    }

    pub fn rollback(self: *Self, classifier: *NaiveBayesClassifier, version: u32) !void {
        for (self.versions.items) |v| {
            if (v.version == version) {
                try classifier.load(v.path);
                return;
            }
        }
        return error.VersionNotFound;
    }

    pub fn getLatestVersion(self: *Self) ?ModelVersion {
        if (self.versions.items.len == 0) return null;
        return self.versions.items[self.versions.items.len - 1];
    }
};

// =============================================================================
// Training Pipeline
// =============================================================================

pub const FeedbackType = enum {
    spam,
    not_spam,
};

pub const TrainingSample = struct {
    features: []Feature,
    label: FeedbackType,
    timestamp: i64,
};

pub const TrainingPipeline = struct {
    const Self = @This();

    allocator: Allocator,
    config: SpamDetectorConfig,
    classifier: NaiveBayesClassifier,
    extractor: FeatureExtractor,
    version_manager: ModelVersionManager,

    // Training buffer
    samples: std.ArrayList(TrainingSample),
    messages_since_save: u32,

    // Validation metrics
    validation_correct: u64,
    validation_total: u64,

    pub fn init(allocator: Allocator, config: SpamDetectorConfig) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .classifier = NaiveBayesClassifier.init(allocator, config),
            .extractor = try FeatureExtractor.init(allocator, config),
            .version_manager = ModelVersionManager.init(allocator, config.model_path, 5),
            .samples = std.ArrayList(TrainingSample).init(allocator),
            .messages_since_save = 0,
            .validation_correct = 0,
            .validation_total = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.samples.items) |sample| {
            self.allocator.free(sample.features);
        }
        self.samples.deinit();
        self.classifier.deinit();
        self.extractor.deinit();
        self.version_manager.deinit();
    }

    pub fn trainFromFeedback(self: *Self, message: *const EmailMessage, feedback: FeedbackType) !void {
        const features = try self.extractor.extractFeatures(message);
        errdefer self.allocator.free(features);

        try self.classifier.train(features, feedback == .spam);

        // Store sample for potential retraining
        if (self.samples.items.len < self.config.max_training_samples) {
            try self.samples.append(.{
                .features = features,
                .label = feedback,
                .timestamp = std.time.timestamp(),
            });
        } else {
            self.allocator.free(features);
        }

        self.messages_since_save += 1;

        // Auto-save
        if (self.messages_since_save >= self.config.auto_save_interval) {
            try self.saveModel();
        }
    }

    pub fn classify(self: *Self, message: *const EmailMessage) !CombinedSpamResult {
        const features = try self.extractor.extractFeatures(message);
        defer self.allocator.free(features);

        const ml_result = self.classifier.classify(features);

        return .{
            .ml_result = ml_result,
            .features_extracted = features.len,
            .model_version = self.classifier.version,
        };
    }

    pub fn saveModel(self: *Self) !void {
        const accuracy = if (self.validation_total > 0)
            @as(f64, @floatFromInt(self.validation_correct)) / @as(f64, @floatFromInt(self.validation_total))
        else
            0.0;

        _ = try self.version_manager.saveVersion(&self.classifier, accuracy);
        self.messages_since_save = 0;
    }

    pub fn loadModel(self: *Self) !void {
        if (self.version_manager.getLatestVersion()) |v| {
            try self.classifier.load(v.path);
        }
    }

    pub fn rollbackModel(self: *Self, version: u32) !void {
        try self.version_manager.rollback(&self.classifier, version);
    }

    pub fn getModelStats(self: *Self) ModelStats {
        return .{
            .version = self.classifier.version,
            .spam_messages = self.classifier.spam_messages,
            .ham_messages = self.classifier.ham_messages,
            .vocabulary_size = self.classifier.vocabulary_size,
            .trained_at = self.classifier.trained_at,
            .samples_in_buffer = self.samples.items.len,
        };
    }
};

pub const CombinedSpamResult = struct {
    ml_result: ClassificationResult,
    features_extracted: usize,
    model_version: u32,
};

pub const ModelStats = struct {
    version: u32,
    spam_messages: u64,
    ham_messages: u64,
    vocabulary_size: u64,
    trained_at: i64,
    samples_in_buffer: usize,
};

// =============================================================================
// Email Message Structure (for ML processing)
// =============================================================================

pub const EmailMessage = struct {
    subject: []const u8,
    body: []const u8,
    sender: []const u8,
    sender_domain: []const u8,
    recipients: []const []const u8,
    recipient_count: u32,
    headers: []const Header,
    has_precedence_bulk: bool,
    has_list_unsubscribe: bool,
    size: usize,

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };
};

// =============================================================================
// High-Level Spam Detector
// =============================================================================

pub const SpamDetector = struct {
    const Self = @This();

    allocator: Allocator,
    pipeline: TrainingPipeline,
    spamassassin_weight: f64,
    ml_weight: f64,

    pub fn init(allocator: Allocator, config: SpamDetectorConfig) !Self {
        return .{
            .allocator = allocator,
            .pipeline = try TrainingPipeline.init(allocator, config),
            .spamassassin_weight = 0.4,
            .ml_weight = 0.6,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pipeline.deinit();
    }

    pub fn classify(self: *Self, message: *const EmailMessage) !SpamVerdict {
        const ml_result = try self.pipeline.classify(message);

        return .{
            .is_spam = ml_result.ml_result.is_spam,
            .spam_score = ml_result.ml_result.spam_probability * 10.0, // Scale to 0-10
            .confidence = ml_result.ml_result.confidence,
            .ml_probability = ml_result.ml_result.spam_probability,
            .features_used = ml_result.features_extracted,
            .model_version = ml_result.model_version,
            .reasons = &[_][]const u8{},
        };
    }

    pub fn classifyWithSpamassassin(
        self: *Self,
        message: *const EmailMessage,
        spamassassin_score: f64,
    ) !SpamVerdict {
        const ml_result = try self.pipeline.classify(message);

        // Combine scores
        const combined_score = (ml_result.ml_result.spam_probability * self.ml_weight) +
            ((spamassassin_score / 10.0) * self.spamassassin_weight);

        return .{
            .is_spam = combined_score >= self.pipeline.config.spam_threshold,
            .spam_score = combined_score * 10.0,
            .confidence = ml_result.ml_result.confidence,
            .ml_probability = ml_result.ml_result.spam_probability,
            .spamassassin_score = spamassassin_score,
            .features_used = ml_result.features_extracted,
            .model_version = ml_result.model_version,
            .reasons = &[_][]const u8{},
        };
    }

    pub fn trainFromFeedback(self: *Self, message: *const EmailMessage, feedback: FeedbackType) !void {
        try self.pipeline.trainFromFeedback(message, feedback);
    }

    pub fn saveModel(self: *Self) !void {
        try self.pipeline.saveModel();
    }

    pub fn loadModel(self: *Self) !void {
        try self.pipeline.loadModel();
    }

    pub fn getStats(self: *Self) ModelStats {
        return self.pipeline.getModelStats();
    }
};

pub const SpamVerdict = struct {
    is_spam: bool,
    spam_score: f64, // 0-10 scale
    confidence: f64, // 0-1
    ml_probability: f64,
    spamassassin_score: ?f64 = null,
    features_used: usize,
    model_version: u32,
    reasons: []const []const u8,
};

// =============================================================================
// Tests
// =============================================================================

test "feature extraction" {
    const allocator = std.testing.allocator;

    var extractor = try FeatureExtractor.init(allocator, .{});
    defer extractor.deinit();

    const message = EmailMessage{
        .subject = "Buy cheap pills now!",
        .body = "Click here to buy http://spam.com discount pills today!!!",
        .sender = "spammer@spam.com",
        .sender_domain = "spam.com",
        .recipients = &[_][]const u8{},
        .recipient_count = 1,
        .headers = &[_]EmailMessage.Header{},
        .has_precedence_bulk = false,
        .has_list_unsubscribe = false,
        .size = 100,
    };

    const features = try extractor.extractFeatures(&message);
    defer allocator.free(features);

    try std.testing.expect(features.len > 0);
}

test "classifier training and classification" {
    const allocator = std.testing.allocator;

    var classifier = NaiveBayesClassifier.init(allocator, .{});
    defer classifier.deinit();

    // Train with some spam features
    const spam_features = [_]Feature{
        .{ .feature_type = .word, .name = "buy", .value = 1.0 },
        .{ .feature_type = .word, .name = "cheap", .value = 1.0 },
        .{ .feature_type = .word, .name = "pills", .value = 1.0 },
    };

    try classifier.train(&spam_features, true);
    try classifier.train(&spam_features, true);

    // Train with some ham features
    const ham_features = [_]Feature{
        .{ .feature_type = .word, .name = "meeting", .value = 1.0 },
        .{ .feature_type = .word, .name = "schedule", .value = 1.0 },
        .{ .feature_type = .word, .name = "project", .value = 1.0 },
    };

    try classifier.train(&ham_features, false);
    try classifier.train(&ham_features, false);

    // Classify a spammy message
    const test_features = [_]Feature{
        .{ .feature_type = .word, .name = "buy", .value = 1.0 },
        .{ .feature_type = .word, .name = "cheap", .value = 1.0 },
    };

    const result = classifier.classify(&test_features);
    try std.testing.expect(result.spam_probability > 0.5);
}

test "queue depth histogram" {
    const metrics = @import("metrics.zig");
    var histogram = metrics.QueueDepthHistogram{};

    histogram.record(5);
    histogram.record(15);
    histogram.record(100);
    histogram.record(1000);

    try std.testing.expect(histogram.samples == 4);
    try std.testing.expect(histogram.min.? == 5);
    try std.testing.expect(histogram.max.? == 1000);
}
