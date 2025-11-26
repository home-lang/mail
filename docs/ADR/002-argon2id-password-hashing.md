# ADR-002: Argon2id for Password Hashing

## Status

Accepted

## Date

2025-10-01

## Context

The SMTP server requires secure password storage for user authentication. We needed to select a password hashing algorithm that:
- Resists brute-force attacks
- Resists GPU/ASIC acceleration
- Is memory-hard to prevent parallel attacks
- Has been cryptographically vetted

Additionally, this decision affects which SMTP authentication mechanisms we can support.

## Decision

We chose **Argon2id** with the following parameters:
- Memory: 64 MB (`m = 65536`)
- Iterations: 3 (`t = 3`)
- Parallelism: 4 (`p = 4`)

Implementation: `std.crypto.pwhash.argon2` from Zig's standard library.

## Consequences

### Positive

- **Memory-hard**: 64MB memory requirement makes GPU attacks expensive
- **Side-channel resistant**: Argon2id combines Argon2i (data-independent) and Argon2d (faster)
- **PHC winner**: Won the Password Hashing Competition (2015), extensively analyzed
- **Configurable**: Parameters can be tuned as hardware improves
- **Modern**: Designed to address weaknesses in bcrypt and scrypt

### Negative

- **CRAM-MD5 incompatible**: Cannot implement CRAM-MD5 authentication (requires plaintext access)
- **DIGEST-MD5 incompatible**: Cannot implement DIGEST-MD5 authentication
- **Memory usage**: Each hash verification uses 64MB RAM
- **CPU intensive**: ~300ms per hash on typical server hardware

### Neutral

- Requires PLAIN authentication over TLS (secure alternative to challenge-response)
- Base64 encoding for storage in SQLite TEXT columns
- Standard library implementation (no external dependencies)

## Alternatives Considered

### Option A: bcrypt
- Pros: Widely deployed, well-understood, constant memory
- Cons: Not memory-hard, vulnerable to GPU attacks, 72-byte password limit

### Option B: scrypt
- Pros: Memory-hard, proven security
- Cons: No side-channel resistance, less configurable than Argon2

### Option C: PBKDF2
- Pros: NIST approved, widely available
- Cons: Not memory-hard, parallelizable on GPUs, needs many iterations

### Option D: Store plaintext for CRAM-MD5
- Pros: Enables challenge-response authentication
- Cons: Catastrophic if database is compromised, violates security best practices

## Security Analysis

```
Argon2id Parameters:
- Memory: 64 MB per hash
- Time: ~300ms per hash
- Attack cost for 10M passwords on GPU cluster: ~$50M+ (2025 estimates)

bcrypt (for comparison):
- Memory: ~4 KB per hash
- Attack cost for 10M passwords: ~$5K on GPU cluster
```

## References

- [RFC 9106: Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
- [Password Hashing Competition](https://www.password-hashing.net/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
