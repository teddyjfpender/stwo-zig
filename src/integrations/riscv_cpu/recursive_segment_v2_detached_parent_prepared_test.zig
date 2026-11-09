//! Integration decoder and shared-preparation regression tests.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prepared_mod = frontend.recursion.detached_parent_prepared_v1;

test "detached parent snapshots typed rows and rejects mutable ingress and inactive claims" {
    comptime {
        const air = frontend.recursion.air;
        var active: usize = 0;
        for (air.universal_catalog.LOGICAL_ROWS, 0..) |old, index| {
            if (index >= 15 and index < 20) continue;
            const expected = switch (index) {
                10 => air.field_statement_word_v3,
                11 => air.detached_graph_input_v1,
                12 => air.detached_poseidon_graph_v1,
                13 => air.fixed_wire_v3,
                14 => air.detached_opening_accumulate4_v1,
                30 => air.qm31_mul_add_v1,
                else => old.Air,
            };
            const actual = prepared_mod.LOGICAL_ROWS[active];
            if (actual.Air != expected or actual.row != old.row or
                actual.requires_location != (old.requires_location and index != 30))
                @compileError("detached parent admitted catalog changed");
            active += 1;
        }
        if (active != prepared_mod.LOGICAL_ROWS.len)
            @compileError("detached parent admitted catalog count changed");
    }
    const allocator = std.testing.allocator;
    const prepared = try prepared_mod.testSnapshotAdmission();
    defer prepared.deinit();
    const protocol = frontend.recursion.detached_parent_protocol_v1;
    const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
    // Structural fixture only: these nonzero placeholders are not independent
    // key admission. Derive wire-decoder bounds without any witness or proof.
    var key = protocol.KeyV1{ .manifest = prepared.manifest().*, .parameters = prepared.parameters(), .preprocessed_root = @splat(1), .child_key_sha256 = @splat(@splat(1)) };
    const shape = try verifier.proofPreflightShape(allocator, &key);
    try std.testing.expectEqual(prepared.manifest().total_preprocessed_columns, shape.tree_columns[0]);
    try std.testing.expectEqual(prepared.manifest().total_main_columns, shape.tree_columns[1]);
    try std.testing.expectEqual(prepared.manifest().total_interaction_columns, shape.tree_columns[2]);
    key.version += 1;
    try std.testing.expectError(error.DetachedParentProfileMismatch, verifier.proofPreflightShape(allocator, &key));
    key.version = protocol.VERSION;
    key.pcs_config.fri_config.n_queries += 1;
    try std.testing.expectError(error.DetachedParentProfileMismatch, verifier.proofPreflightShape(allocator, &key));
}

test "detached parent Poseidon interaction policy preserves serial columns claims and pole errors" {
    try prepared_mod.testPoseidonInteractionPolicy();
}
