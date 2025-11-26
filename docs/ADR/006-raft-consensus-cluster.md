# ADR-006: Raft Consensus for Cluster Mode

## Status

Accepted

## Date

2025-10-01

## Context

For high-availability deployments, the SMTP server needs to run as a cluster with:
- Automatic leader election
- State replication across nodes
- Graceful failover
- Split-brain prevention

We needed a consensus algorithm that:
- Is well-understood and proven
- Handles network partitions correctly
- Provides strong consistency guarantees
- Is implementable without external dependencies

## Decision

We chose **Raft consensus** for cluster coordination:
- Leader election with term-based voting
- Log replication for distributed state
- Heartbeat mechanism for failure detection
- Majority quorum for decisions

Implementation: `src/infrastructure/cluster.zig` and `src/infrastructure/raft.zig`

A fallback "lowest ID wins" election is available for development/testing.

## Consequences

### Positive

- **Understandable**: Raft was designed for understandability
- **Proven**: Widely deployed in etcd, Consul, CockroachDB
- **Strong consistency**: Linearizable reads and writes
- **Partition tolerance**: Correct behavior during network splits
- **No external dependencies**: Pure Zig implementation

### Negative

- **Latency overhead**: Writes require majority acknowledgment
- **Odd cluster sizes**: Best with 3, 5, 7 nodes for quorum
- **Implementation complexity**: Correct Raft is non-trivial
- **Log growth**: Requires compaction/snapshotting

### Neutral

- TCP-based communication between nodes
- Configurable election and heartbeat timeouts
- State machine approach for replicated data

## Raft Configuration

```zig
const raft_config = raft.RaftConfig{
    .node_id = "node-1",
    .peers = &[_][]const u8{"node-2:5000", "node-3:5000"},
    .election_timeout_ms = 150,      // Base election timeout
    .heartbeat_interval_ms = 50,     // Leader heartbeat
    .max_log_entries = 10000,        // Before compaction
    .snapshot_threshold = 5000,      // Entries before snapshot
};
```

## Leader Election Flow

```
1. Follower election timeout fires (randomized 150-300ms)
2. Follower becomes Candidate, increments term
3. Candidate votes for self, requests votes from peers
4. If majority votes received → become Leader
5. If higher term seen → revert to Follower
6. Leader sends heartbeats to maintain authority
```

## State Replication

```
Client → Leader → Append to log
              → Replicate to followers
              → Wait for majority ACK
              → Commit entry
              → Apply to state machine
              → Respond to client
```

## Alternatives Considered

### Option A: Paxos
- Pros: Proven, formally verified
- Cons: Complex to understand and implement, multiple variants

### Option B: ZAB (Zookeeper)
- Pros: Production-proven at scale
- Cons: More complex than Raft, less documentation

### Option C: External Coordinator (etcd/Consul)
- Pros: Battle-tested, feature-rich
- Cons: External dependency, operational overhead

### Option D: Simple Leader Election (Bully Algorithm)
- Pros: Simple to implement
- Cons: No state replication, poor partition handling

## Failure Scenarios

| Scenario | Behavior |
|----------|----------|
| Leader fails | New election, ~300ms failover |
| Follower fails | No impact if quorum maintained |
| Network partition | Minority partition becomes unavailable |
| Split brain | Term numbers prevent dual leaders |

## References

- [Raft Paper](https://raft.github.io/raft.pdf)
- [Raft Visualization](https://raft.github.io/)
- [Raft TLA+ Specification](https://github.com/ongardie/raft.tla)
- [etcd Raft Implementation](https://github.com/etcd-io/raft)
