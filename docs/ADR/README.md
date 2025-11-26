# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records documenting key technical decisions made in the SMTP server project.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision made along with its context and consequences. It provides a historical record of why certain decisions were made.

## ADR Format

Each ADR follows this template:
- **Title**: Short descriptive title
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: What situation led to this decision
- **Decision**: What was decided
- **Consequences**: What results from this decision

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](001-zig-programming-language.md) | Use Zig as Primary Language | Accepted | 2025-10 |
| [002](002-argon2id-password-hashing.md) | Argon2id for Password Hashing | Accepted | 2025-10 |
| [003](003-sqlite-primary-database.md) | SQLite as Primary Database | Accepted | 2025-10 |
| [004](004-aes-256-gcm-encryption.md) | AES-256-GCM for Encryption at Rest | Accepted | 2025-10 |
| [005](005-multi-backend-secrets.md) | Multi-Backend Secret Management | Accepted | 2025-11 |
| [006](006-raft-consensus-cluster.md) | Raft Consensus for Cluster Mode | Accepted | 2025-10 |

## Creating New ADRs

1. Copy the template from `000-template.md`
2. Number sequentially (next: 007)
3. Fill in all sections
4. Update this index
5. Get team review before merging
