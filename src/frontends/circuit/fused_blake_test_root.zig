//! Test root for `fused_blake/fused_blake2s_v1.zig` (stream blake-gadget):
//! runs its tests and pins its copied constants to the circuit's
//! `common/component_list.zig` and `builder/blake.zig` definitions.
//!
//!   zig test -OReleaseFast src/frontends/circuit/fused_blake_test_root.zig

const std = @import("std");
const v1 = @import("fused_blake/fused_blake2s_v1.zig");
const component_list = @import("common/component_list.zig");

test {
    _ = v1;
}

test "fused_blake2s_v1 constants match the circuit's relation ids and table shape" {
    try std.testing.expectEqual(component_list.GATE_RELATION_ID, v1.GATE_RELATION_ID);
    try std.testing.expectEqual(component_list.VERIFY_BITWISE_XOR_8_RELATION_ID, v1.XOR_8_RELATION_ID);
    // The new split tables must not collide with any existing relation id.
    const existing = [_]u32{
        component_list.GATE_RELATION_ID,              component_list.RANGE_CHECK_16_RELATION_ID,
        component_list.VERIFY_BITWISE_XOR_4_RELATION_ID, component_list.VERIFY_BITWISE_XOR_7_RELATION_ID,
        component_list.VERIFY_BITWISE_XOR_8_RELATION_ID, component_list.VERIFY_BITWISE_XOR_8_B_RELATION_ID,
        component_list.VERIFY_BITWISE_XOR_9_RELATION_ID, component_list.VERIFY_BITWISE_XOR_12_RELATION_ID,
    };
    for (existing) |id| {
        try std.testing.expect(id != v1.XOR_8_SPLIT4_RELATION_ID);
        try std.testing.expect(id != v1.XOR_8_SPLIT7_RELATION_ID);
    }
    // The existing xor_8 table is 2^16 rows: (x, y) bytes, the same table v1 uses.
    try std.testing.expectEqual(component_list.LogSizeSource{ .fixed = 16 }, component_list.component_facts.verify_bitwise_xor_8.log_size);
    // Legacy per-compression cost used by the census.
    try std.testing.expectEqual(@as(usize, 52), component_list.component_facts.blake_g_gate.trace_columns);
    try std.testing.expectEqual(@as(usize, 52), component_list.component_facts.blake_g_gate.interaction_columns);
    try std.testing.expectEqual(@as(usize, 20), component_list.component_facts.triple_xor.trace_columns);
    try std.testing.expectEqual(@as(usize, 24), component_list.component_facts.triple_xor.interaction_columns);
}
