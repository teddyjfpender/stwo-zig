//! Cairo trace proving through the scalar CPU backend.

pub const prove_trace = @import("prove_trace.zig");
pub const air = @import("air/mod.zig");
pub const prover = @import("prover/mod.zig");

test {
    _ = air;
    _ = prover;
}
