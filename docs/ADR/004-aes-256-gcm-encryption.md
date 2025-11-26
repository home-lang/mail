# ADR-004: AES-256-GCM for Encryption at Rest

## Status

Accepted

## Date

2025-10-01

## Context

Email messages stored on disk may contain sensitive information. We needed encryption at rest to protect against:
- Physical disk theft
- Unauthorized file system access
- Backup media compromise
- Cloud storage breaches

Requirements:
- Strong confidentiality guarantees
- Integrity protection (detect tampering)
- Per-message encryption keys
- Support for key rotation

## Decision

We chose **AES-256-GCM** (Galois/Counter Mode) with:
- 256-bit keys (post-quantum resistant for symmetric)
- 96-bit random nonces per message
- HKDF-SHA256 for per-message key derivation
- Argon2id for password-based key derivation

Implementation: `std.crypto.aead.aes_gcm.Aes256Gcm` from Zig's standard library.

## Consequences

### Positive

- **Authenticated encryption**: GCM provides both confidentiality and integrity
- **NIST approved**: AES-256 and GCM are FIPS 140-2 compliant
- **Hardware acceleration**: AES-NI instructions on modern CPUs (~10GB/s)
- **No padding oracle**: GCM is not vulnerable to padding attacks
- **Forward secrecy**: Per-message keys via HKDF derivation
- **Key rotation**: Version tagging allows seamless key rotation

### Negative

- **Nonce uniqueness critical**: Reusing (key, nonce) pair is catastrophic
- **96-bit nonce**: ~2^32 messages before birthday bound concerns
- **No authentication of headers**: AAD not used (simplified implementation)
- **Memory overhead**: 28 bytes per message (nonce + tag + version)

### Neutral

- Fixed 16-byte authentication tag
- Little-endian serialization format
- Key file stored separately from encrypted data

## Encryption Format

```
┌──────────┬──────────┬──────────┬────────────────┬──────────────┐
│ Version  │  Nonce   │   Tag    │ Ciphertext Len │  Ciphertext  │
│ (4 bytes)│(12 bytes)│(16 bytes)│   (4 bytes)    │  (variable)  │
└──────────┴──────────┴──────────┴────────────────┴──────────────┘
```

## Key Derivation

```
Master Key (256-bit, randomly generated or from Argon2id)
     │
     ▼
HKDF-SHA256(master_key, "message:" || message_id)
     │
     ▼
Per-Message Key (256-bit)
```

## Alternatives Considered

### Option A: ChaCha20-Poly1305
- Pros: Faster without AES-NI, constant-time, same security
- Cons: Less hardware acceleration on Intel/AMD, less FIPS compliance

### Option B: AES-256-CBC + HMAC-SHA256
- Pros: Widely understood, separate MAC
- Cons: Vulnerable to padding oracles, more complex, slower

### Option C: XChaCha20-Poly1305
- Pros: 192-bit nonces (no birthday concerns)
- Cons: Not in Zig standard library, less hardware support

### Option D: No encryption (rely on disk encryption)
- Pros: Simpler implementation
- Cons: No per-message keys, no application-level protection

## Security Considerations

1. **Nonce Generation**: Using `std.crypto.random` (CSPRNG)
2. **Key Storage**: Master key in separate file with 0600 permissions
3. **Memory Zeroing**: `@memset(key, 0)` before deallocation
4. **No Key in Logs**: Keys never logged or included in error messages

## References

- [NIST SP 800-38D: GCM Recommendation](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 5116: AEAD Interface](https://datatracker.ietf.org/doc/html/rfc5116)
- [AES-GCM Security Analysis](https://eprint.iacr.org/2011/202.pdf)
