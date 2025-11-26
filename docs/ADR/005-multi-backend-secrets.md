# ADR-005: Multi-Backend Secret Management

## Status

Accepted

## Date

2025-11-01

## Context

Production deployments require secure handling of sensitive configuration:
- Database credentials
- API keys
- TLS certificates and private keys
- Encryption master keys

Different deployment environments have different secret management solutions:
- Local development: Environment variables or files
- Kubernetes: K8s Secrets
- AWS: Secrets Manager
- Enterprise: HashiCorp Vault

We needed a unified interface that works across all environments.

## Decision

We implemented a **SecretManager** with pluggable backends:
- Environment variables (default, development)
- HashiCorp Vault (enterprise)
- Kubernetes Secrets (K8s deployments)
- AWS Secrets Manager (AWS deployments)
- Azure Key Vault (Azure deployments)
- File-based (development only)

Implementation: `src/security/secrets.zig`

## Consequences

### Positive

- **Unified API**: Same code works across all backends
- **No hardcoded secrets**: Configuration via backend selection
- **Caching**: Reduces backend calls with TTL-based cache
- **Secure memory**: Secrets zeroed before deallocation
- **Audit trail**: Backend-specific audit logging preserved

### Negative

- **Complexity**: Multiple backend implementations to maintain
- **Network dependency**: Most backends require network access
- **Latency**: First access requires backend call (then cached)
- **Partial implementations**: Some backends have stub methods

### Neutral

- Thread-safe with mutex protection
- Statistics tracking for monitoring
- ConfigSecretLoader helper for prefixed secrets

## Backend Comparison

| Backend | Auth Method | Best For | Latency |
|---------|-------------|----------|---------|
| Environment | N/A | Development, CI | <1ms |
| Vault | Token/AppRole | Enterprise | ~10ms |
| K8s Secrets | Mounted files | Kubernetes | <1ms |
| AWS SM | IAM Role | AWS cloud | ~50ms |
| Azure KV | Managed Identity | Azure cloud | ~50ms |
| File | Filesystem | Development | <1ms |

## Usage Pattern

```zig
var secrets = SecretManager.init(allocator, .vault);
try secrets.configureVault(.{
    .address = "https://vault.example.com:8200",
    .role_id = "smtp-app",
    .secret_id = std.posix.getenv("VAULT_SECRET_ID"),
});

const db_password = try secrets.getSecret("smtp/database/password");
defer {
    @memset(db_password, 0);
    allocator.free(db_password);
}
```

## Alternatives Considered

### Option A: Environment Variables Only
- Pros: Simple, universal, no dependencies
- Cons: No rotation, visible in process list, no audit

### Option B: Vault Only
- Pros: Enterprise-grade, comprehensive features
- Cons: Heavy dependency, not suitable for all deployments

### Option C: External Secret Operator (K8s)
- Pros: K8s native, syncs to K8s secrets
- Cons: K8s only, adds another component

### Option D: AWS-only with Parameter Store
- Pros: Simple AWS integration
- Cons: AWS lock-in, no enterprise features

## Security Considerations

1. **Memory handling**: All secrets zeroed with `@memset` before free
2. **Cache TTL**: Default 5 minutes, configurable per deployment
3. **No logging**: Secret values never logged
4. **Transport security**: TLS required for network backends
5. **Least privilege**: Backend credentials should be scoped to read-only

## References

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [12-Factor App: Config](https://12factor.net/config)
