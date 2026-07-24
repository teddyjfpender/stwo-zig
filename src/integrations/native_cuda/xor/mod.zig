//! Preparatory Native XOR CUDA frontend adapter.
//!
//! This module emits a generic proof program from the CPU-authoritative trace.
//! It deliberately provides no proving entry point until the shared Native
//! CUDA executor consumes arbitrary proof programs without fallback.

pub const geometry = @import("geometry.zig");
pub const identities = @import("identities.zig");
pub const program = @import("program.zig");
pub const trace = @import("trace.zig");

test {
    _ = geometry;
    _ = identities;
    _ = program;
    _ = trace;
}
