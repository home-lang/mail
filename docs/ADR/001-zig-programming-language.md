# ADR-001: Use Zig as Primary Programming Language

## Status

Accepted

## Date

2025-10-01

## Context

We needed to choose a programming language for building a high-performance SMTP server that would be:
- Memory-safe without garbage collection pauses
- Capable of systems-level programming
- Easy to cross-compile for multiple platforms
- Performant enough for high-throughput email processing

The server needs to handle thousands of concurrent connections while maintaining low latency and predictable performance characteristics.

## Decision

We chose **Zig** (version 0.15.x) as the primary programming language for the SMTP server.

## Consequences

### Positive

- **No garbage collection**: Predictable latency without GC pauses, critical for network servers
- **Memory safety**: Compile-time checks prevent common bugs (buffer overflows, use-after-free)
- **Cross-compilation**: Single command builds for Linux, macOS, Windows, ARM from any platform
- **C interoperability**: Direct integration with SQLite, system libraries without FFI overhead
- **Small binaries**: ~2MB static binaries with no runtime dependencies
- **Explicit allocators**: Fine-grained control over memory allocation patterns
- **Comptime**: Powerful compile-time evaluation reduces runtime overhead

### Negative

- **Smaller ecosystem**: Fewer libraries compared to Go, Rust, or C
- **Language maturity**: Pre-1.0 language with occasional breaking changes
- **Learning curve**: Less common language, harder to find experienced developers
- **IDE support**: Limited tooling compared to mainstream languages
- **Documentation**: Less community documentation and examples

### Neutral

- Build system integrated into language (build.zig)
- Error handling via error unions (different from exceptions or Result types)
- Manual memory management (different from RAII or GC)

## Alternatives Considered

### Option A: Go
- Pros: Large ecosystem, excellent networking libraries, goroutines
- Cons: GC pauses (problematic for latency-sensitive operations), larger binaries

### Option B: Rust
- Pros: Memory safety, large ecosystem, good performance
- Cons: Longer compile times, steeper learning curve, complex async ecosystem

### Option C: C
- Pros: Maximum performance, universal availability, mature tooling
- Cons: Manual memory management bugs, no modern safety features

### Option D: C++
- Pros: Good performance, large ecosystem
- Cons: Complexity, long compile times, memory safety issues

## References

- [Zig Language Reference](https://ziglang.org/documentation/master/)
- [Zig's Approach to Memory Safety](https://ziglang.org/learn/overview/)
- [Zig vs C Performance](https://andrewkelley.me/post/zig-programming-language-blurs-line-between-compile-time-and-run-time.html)
