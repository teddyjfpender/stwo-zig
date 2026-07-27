//! Cairo trace proving through the scalar CPU backend.

pub const prove_trace = @import("prove_trace.zig");
pub const prover = @import("prover/mod.zig");

test {
    _ = prover;
}
