//! Compile and behavior surface for the public `stwo_prover` package module.

const std = @import("std");
const stwo_prover = @import("stwo_prover");

comptime {
    @setEvalBranchQuota(250_000);
    std.testing.refAllDeclsRecursive(stwo_prover);
}

test "stwo_prover exposes only protocol and backend-generic owners" {
    try std.testing.expect(@hasDecl(stwo_prover, "core"));
    try std.testing.expect(@hasDecl(stwo_prover, "backend"));
    try std.testing.expect(@hasDecl(stwo_prover, "prover"));
    try std.testing.expect(!@hasDecl(stwo_prover, "frontends"));
    try std.testing.expect(!@hasDecl(stwo_prover, "backends"));
}
