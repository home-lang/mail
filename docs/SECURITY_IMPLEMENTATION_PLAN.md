# Security Implementation Plan

**Date:** 2025-10-24
**Version:** v0.28.0
**Status:** In Progress

## Overview

This document outlines the complete strategic plan to fix all 16 identified security vulnerabilities in the SMTP server codebase. The implementation is organized into 7 phases with clear dependencies and testing requirements.

---

## Phase 1: Fix Critical Authentication Bypasses (Priority: CRITICAL)

**Estimated Time:** 4-6 hours
**Dependencies:** None
**Risk Level:** High (Breaking changes to protocol implementations)

### 1.1 Create Shared Authentication Interface

**File:** `src/auth/auth_backend.zig`

**Goal:** Create unified authentication backend that all protocols can use

**Implementation:**
```zig
pub const AuthBackend = struct {
    allocator: Allocator,
    db: *Database,
    security: *Security,

    pub fn verifyCredentials(self: *AuthBackend, username: []const u8, password: []const u8) !bool {
        // Query user from database
        // Verify password using Argon2id
        // Check account status (active, locked, etc.)
        // Update last login time
        // Return true if valid, false otherwise
    }

    pub fn verifyBasicAuth(self: *AuthBackend, auth_header: []const u8) !?[]const u8 {
        // Parse "Basic <base64>" header
        // Decode base64 to "username:password"
        // Call verifyCredentials
        // Return username if valid, null otherwise
    }
};
```

### 1.2 Fix IMAP Authentication Bypass

**File:** `src/protocol/imap.zig`

**Changes:**
- Add `auth_backend: *AuthBackend` to ImapSession struct
- Modify `handleLogin()` to call `auth_backend.verifyCredentials()`
- Add state validation (reject if already authenticated)
- Add rate limiting for failed login attempts
- Add security logging for auth attempts

**Lines to modify:** 333-346

### 1.3 Fix POP3 Authentication Bypass

**File:** `src/protocol/pop3.zig`

**Changes:**
- Add `auth_backend: *AuthBackend` to Pop3Session struct
- Modify `handlePass()` to validate credentials
- Ensure username is captured from `handleUser()`
- Add state validation
- Add rate limiting and logging

**Lines to modify:** 131-149

### 1.4 Fix ActiveSync Authentication Bypass

**File:** `src/protocol/activesync.zig`

**Changes:**
- Add `auth_backend: *AuthBackend` to ActiveSyncSession
- Parse HTTP Authorization header (Basic Auth)
- Call `auth_backend.verifyBasicAuth()`
- Set authenticated flag only on success
- Return HTTP 401 on failure

**Lines to modify:** 255-261

### 1.5 Fix CalDAV/CardDAV Authentication Bypass

**File:** `src/protocol/caldav.zig`

**Changes:**
- Add `auth_backend: *AuthBackend` to CalDavSession
- Parse HTTP Authorization header (Basic Auth)
- Call `auth_backend.verifyBasicAuth()`
- Implement proper 401 responses with WWW-Authenticate header
- Add Digest authentication support (optional)

**Lines to modify:** 186-194

### 1.6 Update Server Initialization

**Files:** `src/main.zig`, protocol server init functions

**Changes:**
- Initialize shared AuthBackend instance
- Pass AuthBackend to all protocol servers
- Ensure proper cleanup on shutdown

---

## Phase 2: Remove Hardcoded Credentials (Priority: HIGH)

**Estimated Time:** 2-3 hours
**Dependencies:** None
**Risk Level:** Low (Test code changes)

### 2.1 Remove S3 Test Credentials

**File:** `src/storage/s3storage.zig`

**Lines:** 309-310, 331-332, 368-369

**Changes:**
```zig
// Before:
.access_key = "test_access",
.secret_key = "test_secret",

// After:
.access_key = std.posix.getenv("AWS_ACCESS_KEY_ID") orelse return error.MissingCredentials,
.secret_key = std.posix.getenv("AWS_SECRET_ACCESS_KEY") orelse return error.MissingCredentials,
```

**Environment Variables:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION` (optional, default: us-east-1)

### 2.2 Remove Encryption Test Password

**File:** `src/storage/encryption.zig`

**Line:** 485

**Changes:**
- Remove hardcoded test password
- Use environment variable or generate random password for tests
- Update test to use `std.testing.allocator`

### 2.3 Remove WebSocket Test Key

**File:** `src/protocol/websocket.zig`

**Line:** 729

**Changes:**
- Generate random WebSocket key in tests
- Use `std.crypto.random.bytes()` for test key generation

### 2.4 Update Test Documentation

**File:** `README.md`, test documentation

**Changes:**
- Document required environment variables
- Provide example `.env.example` file
- Add setup instructions for tests

---

## Phase 3: Implement Path Sanitization (Priority: HIGH)

**Estimated Time:** 3-4 hours
**Dependencies:** None
**Risk Level:** Medium (Potential to break existing file operations)

### 3.1 Create Path Sanitization Utility

**File:** `src/core/path_sanitizer.zig`

**Implementation:**
```zig
pub const PathSanitizer = struct {
    pub fn sanitizePath(allocator: Allocator, base_path: []const u8, user_path: []const u8) ![]const u8 {
        // 1. Reject paths containing ".."
        if (std.mem.indexOf(u8, user_path, "..") != null) {
            return error.PathTraversalAttempt;
        }

        // 2. Reject absolute paths
        if (std.fs.path.isAbsolute(user_path)) {
            return error.AbsolutePathNotAllowed;
        }

        // 3. Normalize path
        const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_path, user_path });
        defer allocator.free(joined);

        // 4. Resolve to absolute path
        const resolved = try std.fs.realpathAlloc(allocator, joined);

        // 5. Verify it's within base_path
        const base_real = try std.fs.realpathAlloc(allocator, base_path);
        defer allocator.free(base_real);

        if (!std.mem.startsWith(u8, resolved, base_real)) {
            allocator.free(resolved);
            return error.PathTraversalAttempt;
        }

        return resolved;
    }

    pub fn sanitizeFilename(allocator: Allocator, filename: []const u8) ![]const u8 {
        // Remove directory separators
        // Remove null bytes
        // Limit length
        // Validate characters
    }
};
```

### 3.2 Apply to Storage Modules

**Files to update:**
- `src/storage/mbox.zig` - mbox_path sanitization
- `src/storage/backup.zig` - backup path sanitization
- `src/storage/encryption.zig` - file path sanitization
- `src/message/attachment.zig` - attachment path sanitization
- `src/protocol/caldav.zig` - calendar/contact path sanitization
- `src/api/api.zig` - uploaded file paths

**Changes:**
- Import PathSanitizer
- Wrap all file open/create operations
- Add proper error handling
- Log path traversal attempts

### 3.3 Add Security Tests

**File:** `src/core/path_sanitizer_test.zig`

**Test cases:**
- Path traversal with `../`
- Absolute paths
- Null bytes in paths
- Symlink attacks
- Unicode/encoding tricks
- Windows path separators on Unix

---

## Phase 4: Enhance Input Validation (Priority: MEDIUM)

**Estimated Time:** 3-4 hours
**Dependencies:** None
**Risk Level:** Low (Additional validation)

### 4.1 Strengthen Username Validation

**File:** `src/api/api.zig`

**Line:** 254-270

**Implementation:**
```zig
fn validateUsername(username: []const u8) !void {
    // Length check
    if (username.len == 0 or username.len > 64) {
        return error.InvalidUsernameLength;
    }

    // Character validation
    for (username) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') {
            return error.InvalidUsernameFormat;
        }
    }

    // No leading/trailing dots or dashes
    if (username[0] == '.' or username[0] == '-' or
        username[username.len - 1] == '.' or username[username.len - 1] == '-') {
        return error.InvalidUsernameFormat;
    }
}
```

### 4.2 Fix Header Injection Protection

**File:** `src/auth/security.zig`

**Line:** 360-366

**Changes:**
```zig
// Before: Only blocks \r\n\r\n
if (std.mem.indexOf(u8, header_value, "\r\n\r\n") != null) {
    return error.HeaderInjection;
}

// After: Block all CRLF sequences
if (std.mem.indexOf(u8, header_value, "\r\n") != null or
    std.mem.indexOf(u8, header_value, "\n") != null or
    std.mem.indexOf(u8, header_value, "\r") != null) {
    return error.HeaderInjection;
}
```

### 4.3 Add WebSocket Message Size Validation

**File:** `src/protocol/websocket.zig`

**Line:** 276-300

**Implementation:**
```zig
// In parseFrame function
if (payload_len > self.config.max_message_size) {
    try self.sendClose(1009, "Message too large");
    return error.MessageTooLarge;
}

// Add configuration validation
if (self.config.max_message_size > 16 * 1024 * 1024) { // 16MB max
    return error.InvalidConfiguration;
}
```

### 4.4 Email Address Validation Enhancement

**File:** `src/core/email_validator.zig`

**Changes:**
- Add stricter domain validation
- Check for suspicious TLDs
- Validate UTF-8 in internationalized emails
- Add configurable blocklist

### 4.5 Add Input Validation Tests

**File:** `src/auth/security_test.zig`

**Test cases:**
- Header injection attempts
- Username validation edge cases
- Email validation edge cases
- Large payload handling

---

## Phase 5: Add Security Testing Suite (Priority: MEDIUM)

**Estimated Time:** 4-5 hours
**Dependencies:** Phases 1-4 complete
**Risk Level:** Low (Test code only)

### 5.1 Authentication Security Tests

**File:** `src/testing/auth_security_test.zig`

**Test cases:**
```zig
test "IMAP authentication with invalid credentials" {
    // Test failed login
    // Test account lockout after N attempts
    // Test timing attack resistance
    // Test SQL injection in username
}

test "POP3 authentication rate limiting" {
    // Test rate limit enforcement
    // Test exponential backoff
    // Test IP-based limiting
}

test "ActiveSync basic auth parsing" {
    // Test malformed headers
    // Test invalid base64
    // Test missing Authorization header
}

test "CalDAV digest authentication" {
    // Test digest auth flow
    // Test nonce validation
    // Test replay attack prevention
}
```

### 5.2 Path Traversal Tests

**File:** `src/testing/path_traversal_test.zig`

**Test cases:**
- Various `../` combinations
- URL encoding tricks
- Null byte injection
- Symlink attacks
- Case sensitivity attacks

### 5.3 Input Validation Fuzzing

**File:** `src/testing/fuzz_test.zig`

**Test cases:**
- Random username generation
- Random email generation
- Random header values
- Large payloads
- Binary data in text fields

### 5.4 Cryptography Tests

**File:** `src/testing/crypto_test.zig`

**Test cases:**
- Argon2id parameter validation
- AES-GCM encryption/decryption
- Key derivation
- Random number generation
- Constant-time comparison

### 5.5 DoS Protection Tests

**File:** `src/testing/dos_test.zig`

**Test cases:**
- Connection flooding
- Large message handling
- Slowloris attacks
- Resource exhaustion
- Rate limit bypass attempts

---

## Phase 6: Update Documentation (Priority: LOW)

**Estimated Time:** 2-3 hours
**Dependencies:** Phases 1-5 complete
**Risk Level:** None

### 6.1 Update Security Audit

**File:** `docs/SECURITY_AUDIT.md`

**Changes:**
- Mark all vulnerabilities as fixed
- Add "Fixed" column with version numbers
- Add "Testing" section with test results
- Update production readiness checklist

### 6.2 Create Security Guide

**File:** `docs/SECURITY_GUIDE.md`

**Content:**
- Authentication best practices
- TLS/SSL configuration
- Environment variable setup
- Security monitoring
- Incident response procedures
- Regular maintenance tasks

### 6.3 Update Configuration Guide

**File:** `docs/CONFIGURATION.md`

**Changes:**
- Document all environment variables
- Add security configuration section
- Document rate limiting settings
- Add authentication settings

### 6.4 Update API Documentation

**File:** `docs/API_REFERENCE.md`

**Changes:**
- Document authentication requirements
- Add error responses for security failures
- Document rate limiting headers
- Add security headers documentation

---

## Phase 7: Run Comprehensive Tests (Priority: CRITICAL)

**Estimated Time:** 2-3 hours
**Dependencies:** All phases complete
**Risk Level:** High (Final validation)

### 7.1 Unit Tests

**Command:**
```bash
zig build test
```

**Expected:**
- All existing tests pass
- All new security tests pass
- No memory leaks reported
- Code coverage > 80%

### 7.2 Integration Tests

**Tests:**
- SMTP send/receive with authentication
- IMAP login and mailbox access
- POP3 login and message retrieval
- CalDAV calendar sync
- CardDAV contact sync
- ActiveSync mobile sync
- WebSocket real-time notifications

### 7.3 Security Penetration Tests

**Tools:**
- OWASP ZAP for API testing
- Burp Suite for protocol testing
- SQLMap for SQL injection
- Custom scripts for auth bypass attempts

**Tests:**
- Authentication bypass attempts
- Path traversal attempts
- Header injection attempts
- SQL injection attempts
- XSS attempts (if applicable)
- CSRF attempts

### 7.4 Performance Tests

**Tests:**
- Concurrent authentication requests
- Large file uploads
- High message throughput
- WebSocket connection limits
- Database query performance

### 7.5 Compliance Validation

**Checks:**
- RFC 5321 (SMTP) compliance
- RFC 3501 (IMAP) compliance
- RFC 1939 (POP3) compliance
- RFC 4791 (CalDAV) compliance
- RFC 6455 (WebSocket) compliance
- OWASP Top 10 coverage

---

## Implementation Order

### Week 1: Critical Fixes
**Days 1-2:**
- Phase 1.1: Create AuthBackend (4 hours)
- Phase 1.2-1.5: Fix all authentication bypasses (8 hours)
- Phase 1.6: Update server initialization (2 hours)

**Days 3-4:**
- Phase 2: Remove all hardcoded credentials (3 hours)
- Phase 3.1: Create path sanitization utility (2 hours)
- Phase 3.2: Apply to all storage modules (4 hours)
- Phase 3.3: Add path sanitization tests (2 hours)

### Week 2: Enhancement & Testing
**Days 5-6:**
- Phase 4: All input validation enhancements (8 hours)
- Phase 5.1-5.2: Auth and path security tests (4 hours)

**Days 7-8:**
- Phase 5.3-5.5: Fuzzing and DoS tests (6 hours)
- Phase 6: All documentation updates (6 hours)

**Day 9:**
- Phase 7: Comprehensive testing (8 hours)

**Day 10:**
- Final review and fixes (8 hours)

---

## Success Criteria

### Phase 1 Complete When:
- [ ] All 4 authentication bypass vulnerabilities fixed
- [ ] AuthBackend integrated across all protocols
- [ ] Authentication tests pass
- [ ] No regression in existing functionality

### Phase 2 Complete When:
- [ ] No hardcoded credentials in codebase
- [ ] Environment variables documented
- [ ] Tests use proper credential management
- [ ] CI/CD updated with env var requirements

### Phase 3 Complete When:
- [ ] PathSanitizer utility created and tested
- [ ] All file operations use sanitization
- [ ] Path traversal tests pass
- [ ] Security logging for path attempts

### Phase 4 Complete When:
- [ ] All input validation enhanced
- [ ] Header injection protection strengthened
- [ ] WebSocket size limits enforced
- [ ] Validation tests pass

### Phase 5 Complete When:
- [ ] 100+ security tests created
- [ ] All tests pass
- [ ] Code coverage > 80%
- [ ] Fuzzing finds no new issues

### Phase 6 Complete When:
- [ ] All documentation updated
- [ ] Security guide created
- [ ] Configuration examples provided
- [ ] API documentation complete

### Phase 7 Complete When:
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Security penetration tests pass
- [ ] Performance benchmarks meet targets
- [ ] RFC compliance validated

---

## Risk Mitigation

### Breaking Changes
- Create feature branch for all changes
- Run tests after each phase
- Document all API changes
- Provide migration guide if needed

### Performance Impact
- Benchmark before and after
- Profile authentication overhead
- Optimize hot paths
- Cache validation results where possible

### Backwards Compatibility
- Version all API changes
- Provide deprecation warnings
- Support legacy auth for transition period
- Document upgrade path

### Rollback Plan
- Tag release before starting
- Keep all changes in feature branch
- Create rollback script
- Document rollback procedure

---

## Monitoring & Alerting

### Security Events to Monitor
- Failed authentication attempts
- Rate limit breaches
- Path traversal attempts
- Header injection attempts
- Suspicious patterns

### Metrics to Track
- Authentication success/failure rate
- Average authentication time
- File access patterns
- Error rates by type
- Resource utilization

### Alerting Thresholds
- > 10 failed auth from single IP in 1 minute
- > 5 path traversal attempts in 1 hour
- > 100 validation errors in 1 hour
- Authentication time > 1 second
- Memory usage > 80%

---

## Post-Implementation Tasks

### Week 3: Stabilization
- Monitor production metrics
- Fix any discovered issues
- Optimize performance bottlenecks
- Collect user feedback

### Week 4: Hardening
- Conduct professional penetration test
- Address any findings
- Implement additional monitoring
- Create runbooks for incidents

### Ongoing
- Weekly dependency updates
- Monthly security audits
- Quarterly penetration tests
- Annual security review

---

**Status:** Ready to implement
**Next Step:** Begin Phase 1.1 - Create AuthBackend
