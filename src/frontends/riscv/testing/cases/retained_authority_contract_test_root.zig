//! Focused retained live regression owner.
test {
    _ = @import("air/lang/tests/function_activation_logup_test.zig");
    _ = @import("air/guest_precompile/tests/sha256_memory_caller_test.zig");
    _ = @import("recursion/air/tests/blake3_draw_witness_test.zig");
    _ = @import("air/guest_precompile/tests/relation_test.zig");
    _ = @import("stwo_riscv_recursion");
}

test "segment-leaf claim projection keeps shared provider out of prefix" {
    const std = @import("std");
    const bundle = @import("stwo_riscv_recursion").segment_leaf_outer_bundle;
    const Q = @import("stwo_core").fields.qm31.QM31;
    var claims = std.mem.zeroes(bundle.Claims);
    claims.public.public_logup_control = Q.one();
    claims.statement.range_check = Q.one().add(Q.one());
    const prefix = claims.prefixValues();
    try std.testing.expect(prefix[17].eql(Q.one()));
    try std.testing.expect(prefix[0].isZero());
    try std.testing.expect(claims.sharedProviderValue().eql(Q.one().add(Q.one())));
}
