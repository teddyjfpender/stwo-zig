//! Cairo trace proving through the scalar CPU backend.

pub const prove_trace = @import("prove_trace.zig");
pub const prover = @import("prover/mod.zig");

test "api signature: Cairo CPU transaction satisfies the stable prover contract" {
    comptime @import("stwo_prover_api").assertProverEngine(prover.transaction.Engine);
}

test {
    _ = prove_trace;
    _ = prover;
}
