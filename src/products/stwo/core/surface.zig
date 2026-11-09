//! Compile and behavior surface for the public `stwo_core` package module.

const std = @import("std");
const core = @import("stwo_core");

comptime {
    @setEvalBranchQuota(100_000);
    std.testing.refAllDeclsRecursive(core);
}

test "stwo_core public field smoke" {
    const M31 = core.fields.m31.M31;
    try std.testing.expect(M31.fromCanonical(7).add(M31.fromCanonical(11)).eql(M31.fromCanonical(18)));
}
