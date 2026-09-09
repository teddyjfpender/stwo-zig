//! Narrow compile/runtime root for sparse-memory prover autoresearch.
//!
//! This keeps sub-two-minute candidate measurements independent of the full
//! frontend inventory while still compiling the production import graph below
//! the RISC-V package root.

const sparse_merkle = @import("air/memory_commitment/sparse_merkle.zig");

comptime {
    _ = sparse_merkle;
}
