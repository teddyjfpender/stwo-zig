const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const program = @import("stwo_riscv_air_lang").framework.direct_constraint_program;
const authenticate = program.authenticate;
const MAX_NODES = program.MAX_NODES;

test "R-012 direct execution pruning preserves every parent catalog root over base and extension fields" {
    @setEvalBranchQuota(500_000);
    const catalog = @import("stwo_riscv_recursion_air").detached.parent_catalog;
    var full_count: usize = 0;
    var live_count: usize = 0;
    inline for (catalog.LOGICAL_ROWS) |entry| {
        const Air = entry.Air;
        var definition = if (entry.requires_location)
            try Air.build(std.testing.allocator, .generated)
        else
            try Air.build(std.testing.allocator);
        defer definition.deinit();
        const pruned = try authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        full_count += pruned.compiled_node_count;
        live_count += pruned.evaluation_node_count;
        var complete = pruned;
        complete.evaluation_node_count = complete.compiled_node_count;
        @memcpy(complete.evaluation_nodes[0..complete.compiled_node_count], complete.nodes[0..complete.compiled_node_count]);
        // Arbitrary off-trace values are essential: satisfied zero roots
        // alone cannot detect a dropped direct constraint dependency.
        for (0..4) |sample| {
            var base: [Air.LOGICAL_INPUT_COUNT]M31 = undefined;
            var secure: [Air.LOGICAL_INPUT_COUNT]QM31 = undefined;
            for (&base, &secure, 0..) |*word, *extension, index| {
                word.* = M31.fromU64((sample + 3) * (index + 17) * 1_234_567);
                extension.* = QM31.fromM31(word.*, M31.fromU64(index + 1), M31.fromU64(sample + 2), M31.fromU64(index * 31 + sample));
            }
            var base_scratch: [MAX_NODES]M31 = undefined;
            var secure_scratch: [MAX_NODES]QM31 = undefined;
            var actual_base: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            var expected_base: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            var actual_secure: [Air.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
            var expected_secure: [Air.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
            try pruned.evaluateBaseInto(&base, &base_scratch, &actual_base);
            try complete.evaluateBaseInto(&base, &base_scratch, &expected_base);
            try pruned.evaluateSecureInto(&secure, &secure_scratch, &actual_secure);
            try complete.evaluateSecureInto(&secure, &secure_scratch, &expected_secure);
            try std.testing.expectEqualDeep(expected_base, actual_base);
            try std.testing.expectEqualDeep(expected_secure, actual_secure);
        }
        std.debug.print("DIRECT_EXECUTION_PRUNING row={d} canonical_nodes={d} executed_nodes={d}\n", .{ @intFromEnum(entry.row), pruned.compiled_node_count, pruned.evaluation_node_count });
    }
    try std.testing.expect(live_count < full_count);
}
