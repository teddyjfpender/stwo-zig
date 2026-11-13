const std = @import("std");
const inventory = @import("stwo_riscv_rv32").recursion.air.inventory;
const control = @import("stwo_riscv_air_lang").framework.control;
const fri_merkle_anchor = @import("stwo_riscv_recursion_air").fri.merkle_anchor;
const fri_merkle_leaf = @import("stwo_riscv_recursion_air").fri.merkle_leaf;
const fri_merkle_node = @import("stwo_riscv_recursion_air").fri.merkle_node;
const fri_verifier_control = @import("stwo_riscv_recursion_air").fri.verifier_control;
const fri_verifier_input = @import("stwo_riscv_recursion_air").fri.verifier_input;
const linear_ops = @import("stwo_riscv_air_lang").framework.linear_ops;
const merkle_path = @import("stwo_riscv_recursion_air").merkle.path;
const merkle_root = @import("stwo_riscv_recursion_air").merkle.root;
const pcs_deep_input = @import("stwo_riscv_recursion_air").pcs_deep_input;
const pow_check = @import("stwo_riscv_recursion_air").pow.check;
const pow_frame = @import("stwo_riscv_recursion_air").pow.frame;
const qm31_inv = @import("stwo_riscv_air_lang").framework.qm31_inv;
const qm31_mul = @import("stwo_riscv_air_lang").framework.qm31_mul;
const qm31_mul_full = @import("stwo_riscv_recursion_air").qm31.mul_full;
const query_bits = @import("stwo_riscv_recursion_air").query.bits;
const query_mapping = @import("stwo_riscv_recursion_air").query.mapping;
const relation_challenge = @import("stwo_riscv_recursion_air").relation.challenge;
const statement_input = @import("stwo_riscv_recursion_air").statement.input;
const statement_semantics_input = @import("stwo_riscv_recursion_air").statement.semantics_input;
const trace_merkle = @import("stwo_riscv_recursion_air").trace_merkle;
const transcript_air = @import("stwo_riscv_recursion_air").transcript.air;
const transcript_binding = @import("stwo_riscv_recursion_air").transcript.binding;
const transcript_payload = @import("stwo_riscv_recursion_air").transcript.payload;
const transcript_state = @import("stwo_riscv_recursion_air").transcript.state;
const transcript_word = @import("stwo_riscv_recursion_air").transcript.word;
const vm_air_composition_control = @import("stwo_riscv_recursion_air").vm_air_composition_control.Air;
const vm_air_composition_input = @import("stwo_riscv_recursion_air").vm_air_composition_input;
const vm_public_claim_hash = @import("stwo_riscv_recursion_air").vm_public_claim_hash;
const vm_public_claim_input = @import("stwo_riscv_recursion_air").vm_public_claim_input;
const vm_public_claim_semantics_input = @import("stwo_riscv_recursion_air").vm_public_claim_semantics_input;
const vm_public_io_hash = @import("stwo_riscv_recursion_air").vm_public_io_hash;
const vm_public_logup_control = @import("stwo_riscv_recursion_air").vm_public_logup_control.Air;
const vm_public_logup_input = @import("stwo_riscv_recursion_air").vm_public_logup_input;
const verifier_randomness = @import("stwo_riscv_recursion_air").verifier_randomness;

test "R-012 recursion typed-AIR inventory is explicit and cannot overclaim completion" {
    try std.testing.expectEqual(@as(usize, 35), inventory.COMPONENT_COUNT);
    const substrate = inventory.DESCRIPTORS[0];
    try std.testing.expectEqual(inventory.Component.qm31_mul_standalone, substrate.component);
    try std.testing.expectEqual(inventory.Status.typed_substrate, substrate.status);
    try std.testing.expectEqual(inventory.Authorship.typed_ir, substrate.authorship);
    try std.testing.expectEqualStrings(
        "recursion.qm31_mul.standalone.v1",
        substrate.stable_name,
    );
    try std.testing.expectEqual(@as(u32, 12), substrate.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 4), substrate.constraint_roots);
    try std.testing.expectEqual(@as(u32, 0), substrate.relation_events);
    try std.testing.expectEqual(@as(u32, 2), substrate.maximum_constraint_degree);
    try std.testing.expectEqualSlices(u8, &qm31_mul.SEMANTIC_DIGEST, &substrate.semantic_digest);

    const complete = inventory.DESCRIPTORS[1];
    try std.testing.expectEqual(inventory.Component.qm31_mul_full, complete.component);
    try std.testing.expectEqual(inventory.Status.typed_logical_component, complete.status);
    try std.testing.expectEqual(inventory.Authorship.typed_ir, complete.authorship);
    try std.testing.expectEqualStrings("recursion.qm31_mul.full.v1", complete.stable_name);
    try std.testing.expectEqual(@as(u32, 19), complete.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 13), complete.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), complete.relation_events);
    try std.testing.expectEqual(@as(u32, 3), complete.maximum_constraint_degree);
    try std.testing.expectEqual(@as(?u8, 30), complete.universal_row);
    try std.testing.expectEqualSlices(
        u8,
        &qm31_mul_full.SEMANTIC_DIGEST,
        &complete.semantic_digest,
    );

    const inversion = inventory.DESCRIPTORS[2];
    try std.testing.expectEqual(inventory.Component.qm31_inv_full, inversion.component);
    try std.testing.expectEqual(inventory.Status.typed_logical_component, inversion.status);
    try std.testing.expectEqual(inventory.Authorship.typed_ir, inversion.authorship);
    try std.testing.expectEqualStrings("recursion.qm31_inv.full.v1", inversion.stable_name);
    try std.testing.expectEqual(@as(u32, 14), inversion.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 12), inversion.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), inversion.relation_events);
    try std.testing.expectEqual(@as(u32, 3), inversion.maximum_constraint_degree);
    try std.testing.expectEqual(@as(?u8, 31), inversion.universal_row);
    try std.testing.expectEqualSlices(u8, &qm31_inv.SEMANTIC_DIGEST, &inversion.semantic_digest);

    const linear = inventory.DESCRIPTORS[3];
    try std.testing.expectEqual(inventory.Component.linear_ops_full, linear.component);
    try std.testing.expectEqual(inventory.Status.typed_logical_component, linear.status);
    try std.testing.expectEqual(inventory.Authorship.typed_ir, linear.authorship);
    try std.testing.expectEqualStrings("recursion.linear_ops.full.v1", linear.stable_name);
    try std.testing.expectEqual(@as(u32, 21), linear.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 18), linear.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), linear.relation_events);
    try std.testing.expectEqual(@as(u32, 3), linear.maximum_constraint_degree);
    try std.testing.expectEqual(@as(?u8, 32), linear.universal_row);
    try std.testing.expectEqualSlices(u8, &linear_ops.SEMANTIC_DIGEST, &linear.semantic_digest);

    const Expected = struct {
        component: inventory.Component,
        row: u8,
        stable_name: []const u8,
        main_columns: u32,
        roots: u32,
        events: u32,
        maximum_degree: u32,
        semantic_digest: [32]u8,
    };
    const expected = [_]Expected{
        .{
            .component = .transcript_air,
            .row = 1,
            .stable_name = transcript_air.STABLE_NAME,
            .main_columns = transcript_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = transcript_air.DIRECT_CONSTRAINT_COUNT,
            .events = transcript_air.RELATION_EVENT_COUNT,
            .maximum_degree = transcript_air.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = transcript_air.SEMANTIC_DIGEST,
        },
        .{
            .component = .transcript_binding,
            .row = 2,
            .stable_name = transcript_binding.STABLE_NAME,
            .main_columns = transcript_binding.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = transcript_binding.DIRECT_CONSTRAINT_COUNT,
            .events = transcript_binding.RELATION_EVENT_COUNT,
            .maximum_degree = transcript_binding.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = transcript_binding.SEMANTIC_DIGEST,
        },
        .{
            .component = .transcript_state,
            .row = 3,
            .stable_name = transcript_state.STABLE_NAME,
            .main_columns = transcript_state.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = transcript_state.DIRECT_CONSTRAINT_COUNT,
            .events = transcript_state.RELATION_EVENT_COUNT,
            .maximum_degree = transcript_state.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = transcript_state.SEMANTIC_DIGEST,
        },
        .{
            .component = .transcript_payload,
            .row = 5,
            .stable_name = transcript_payload.STABLE_NAME,
            .main_columns = transcript_payload.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = transcript_payload.DIRECT_CONSTRAINT_COUNT,
            .events = transcript_payload.RELATION_EVENT_COUNT,
            .maximum_degree = transcript_payload.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = transcript_payload.SEMANTIC_DIGEST,
        },
        .{
            .component = .transcript_word,
            .row = 4,
            .stable_name = transcript_word.STABLE_NAME,
            .main_columns = transcript_word.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = transcript_word.DIRECT_CONSTRAINT_COUNT,
            .events = transcript_word.RELATION_EVENT_COUNT,
            .maximum_degree = transcript_word.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = transcript_word.SEMANTIC_DIGEST,
        },
        .{
            .component = .pow_check,
            .row = 6,
            .stable_name = pow_check.STABLE_NAME,
            .main_columns = pow_check.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = pow_check.DIRECT_CONSTRAINT_COUNT,
            .events = pow_check.RELATION_EVENT_COUNT,
            .maximum_degree = pow_check.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = pow_check.SEMANTIC_DIGEST,
        },
        .{
            .component = .pow_frame,
            .row = 7,
            .stable_name = pow_frame.STABLE_NAME,
            .main_columns = pow_frame.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = pow_frame.DIRECT_CONSTRAINT_COUNT,
            .events = pow_frame.RELATION_EVENT_COUNT,
            .maximum_degree = pow_frame.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = pow_frame.SEMANTIC_DIGEST,
        },
        .{
            .component = .relation_challenge,
            .row = 8,
            .stable_name = relation_challenge.STABLE_NAME,
            .main_columns = relation_challenge.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = relation_challenge.DIRECT_CONSTRAINT_COUNT,
            .events = relation_challenge.RELATION_EVENT_COUNT,
            .maximum_degree = relation_challenge.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = relation_challenge.SEMANTIC_DIGEST,
        },
        .{
            .component = .verifier_randomness,
            .row = 9,
            .stable_name = verifier_randomness.STABLE_NAME,
            .main_columns = verifier_randomness.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = verifier_randomness.DIRECT_CONSTRAINT_COUNT,
            .events = verifier_randomness.RELATION_EVENT_COUNT,
            .maximum_degree = verifier_randomness.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = verifier_randomness.SEMANTIC_DIGEST,
        },
        .{
            .component = .control,
            .row = 0,
            .stable_name = control.STABLE_NAME,
            .main_columns = 0,
            .roots = 1,
            .events = 2,
            .maximum_degree = 0,
            .semantic_digest = control.SEMANTIC_DIGEST,
        },
        .{
            .component = .statement_input,
            .row = 10,
            .stable_name = statement_input.STABLE_NAME,
            .main_columns = 2,
            .roots = 2,
            .events = 4,
            .maximum_degree = 3,
            .semantic_digest = statement_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .statement_semantics_input,
            .row = 11,
            .stable_name = statement_semantics_input.STABLE_NAME,
            .main_columns = 4,
            .roots = 6,
            .events = 3,
            .maximum_degree = 4,
            .semantic_digest = statement_semantics_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_claim_input,
            .row = 12,
            .stable_name = vm_public_claim_input.STABLE_NAME,
            .main_columns = 4,
            .roots = 7,
            .events = 8,
            .maximum_degree = 4,
            .semantic_digest = vm_public_claim_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_claim_hash,
            .row = 13,
            .stable_name = vm_public_claim_hash.STABLE_NAME,
            .main_columns = vm_public_claim_hash.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = vm_public_claim_hash.DIRECT_CONSTRAINT_COUNT,
            .events = vm_public_claim_hash.RELATION_EVENT_COUNT,
            .maximum_degree = vm_public_claim_hash.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = vm_public_claim_hash.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_io_hash,
            .row = 14,
            .stable_name = vm_public_io_hash.STABLE_NAME,
            .main_columns = vm_public_io_hash.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = vm_public_io_hash.DIRECT_CONSTRAINT_COUNT,
            .events = vm_public_io_hash.RELATION_EVENT_COUNT,
            .maximum_degree = vm_public_io_hash.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = vm_public_io_hash.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_claim_semantics_input,
            .row = 15,
            .stable_name = vm_public_claim_semantics_input.STABLE_NAME,
            .main_columns = 2,
            .roots = 3,
            .events = 4,
            .maximum_degree = 3,
            .semantic_digest = vm_public_claim_semantics_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_logup_input,
            .row = 16,
            .stable_name = vm_public_logup_input.STABLE_NAME,
            .main_columns = 2,
            .roots = 3,
            .events = 5,
            .maximum_degree = 3,
            .semantic_digest = vm_public_logup_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_public_logup_control,
            .row = 17,
            .stable_name = vm_public_logup_control.STABLE_NAME,
            .main_columns = 0,
            .roots = 1,
            .events = 1,
            .maximum_degree = 0,
            .semantic_digest = vm_public_logup_control.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_air_composition_input,
            .row = 18,
            .stable_name = vm_air_composition_input.STABLE_NAME,
            .main_columns = 2,
            .roots = 7,
            .events = 9,
            .maximum_degree = 3,
            .semantic_digest = vm_air_composition_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .vm_air_composition_control,
            .row = 19,
            .stable_name = vm_air_composition_control.STABLE_NAME,
            .main_columns = 0,
            .roots = 1,
            .events = 1,
            .maximum_degree = 0,
            .semantic_digest = vm_air_composition_control.SEMANTIC_DIGEST,
        },
        .{
            .component = .query_bits,
            .row = 20,
            .stable_name = query_bits.STABLE_NAME,
            .main_columns = 34,
            .roots = 67,
            .events = 33,
            .maximum_degree = 3,
            .semantic_digest = query_bits.SEMANTIC_DIGEST,
        },
        .{
            .component = .query_mapping,
            .row = 21,
            .stable_name = query_mapping.STABLE_NAME,
            .main_columns = 34,
            .roots = 36,
            .events = 2,
            .maximum_degree = 3,
            .semantic_digest = query_mapping.SEMANTIC_DIGEST,
        },
        .{
            .component = .merkle_root,
            .row = 22,
            .stable_name = merkle_root.STABLE_NAME,
            .main_columns = 9,
            .roots = 9,
            .events = 9,
            .maximum_degree = 3,
            .semantic_digest = merkle_root.SEMANTIC_DIGEST,
        },
        .{
            .component = .trace_merkle,
            .row = 23,
            .stable_name = trace_merkle.STABLE_NAME,
            .main_columns = 42,
            .roots = 66,
            .events = 14,
            .maximum_degree = 4,
            .semantic_digest = trace_merkle.SEMANTIC_DIGEST,
        },
        .{
            .component = .pcs_deep_input,
            .row = 24,
            .stable_name = pcs_deep_input.STABLE_NAME,
            .main_columns = 2,
            .roots = 3,
            .events = 8,
            .maximum_degree = 4,
            .semantic_digest = pcs_deep_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .fri_merkle_leaf,
            .row = 25,
            .stable_name = fri_merkle_leaf.STABLE_NAME,
            .main_columns = 43,
            .roots = 67,
            .events = 14,
            .maximum_degree = 4,
            .semantic_digest = fri_merkle_leaf.SEMANTIC_DIGEST,
        },
        .{
            .component = .fri_merkle_node,
            .row = 26,
            .stable_name = fri_merkle_node.STABLE_NAME,
            .main_columns = 34,
            .roots = 34,
            .events = 5,
            .maximum_degree = 3,
            .semantic_digest = fri_merkle_node.SEMANTIC_DIGEST,
        },
        .{
            .component = .fri_merkle_anchor,
            .row = 27,
            .stable_name = fri_merkle_anchor.STABLE_NAME,
            .main_columns = 10,
            .roots = 10,
            .events = 5,
            .maximum_degree = 3,
            .semantic_digest = fri_merkle_anchor.SEMANTIC_DIGEST,
        },
        .{
            .component = .fri_verifier_control,
            .row = 28,
            .stable_name = fri_verifier_control.STABLE_NAME,
            .main_columns = 3,
            .roots = 6,
            .events = 4,
            .maximum_degree = 3,
            .semantic_digest = fri_verifier_control.SEMANTIC_DIGEST,
        },
        .{
            .component = .fri_verifier_input,
            .row = 29,
            .stable_name = fri_verifier_input.STABLE_NAME,
            .main_columns = fri_verifier_input.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = fri_verifier_input.DIRECT_CONSTRAINT_COUNT,
            .events = fri_verifier_input.RELATION_EVENT_COUNT,
            .maximum_degree = fri_verifier_input.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = fri_verifier_input.SEMANTIC_DIGEST,
        },
        .{
            .component = .merkle_path,
            .row = 33,
            .stable_name = merkle_path.STABLE_NAME,
            .main_columns = merkle_path.PHYSICAL_MAIN_COLUMN_COUNT,
            .roots = merkle_path.DIRECT_CONSTRAINT_COUNT,
            .events = merkle_path.RELATION_EVENT_COUNT,
            .maximum_degree = merkle_path.MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = merkle_path.SEMANTIC_DIGEST,
        },
    };
    for (expected) |want| {
        const descriptor = inventory.DESCRIPTORS[@intFromEnum(want.component)];
        try std.testing.expectEqual(want.component, descriptor.component);
        try std.testing.expectEqual(@as(?u8, want.row), descriptor.universal_row);
        try std.testing.expectEqualStrings(want.stable_name, descriptor.stable_name);
        try std.testing.expectEqual(inventory.Status.typed_logical_component, descriptor.status);
        try std.testing.expectEqual(inventory.Authorship.typed_ir, descriptor.authorship);
        try std.testing.expectEqual(want.main_columns, descriptor.physical_main_columns);
        try std.testing.expectEqual(want.roots, descriptor.constraint_roots);
        try std.testing.expectEqual(want.events, descriptor.relation_events);
        try std.testing.expectEqual(want.maximum_degree, descriptor.maximum_constraint_degree);
        try std.testing.expectEqualSlices(
            u8,
            &want.semantic_digest,
            &descriptor.semantic_digest,
        );
    }
}

test "R-012 admitted universal roster rows are unique and in range" {
    var seen = [_]bool{false} ** 36;
    for (inventory.DESCRIPTORS) |descriptor| {
        if (descriptor.universal_row) |row| {
            try std.testing.expect(row < seen.len);
            try std.testing.expect(!seen[row]);
            seen[row] = true;
        }
    }
}

test "R-012 admitted owners use typed compiler surface and no known manual evaluator surface" {
    const sources = [_][]const u8{
        @import("stwo_riscv_air_lang").testing.assets.framework_qm31_mul_zig,
        @import("stwo_riscv_recursion_air").testing.assets.qm31_mul_full_zig,
        @import("stwo_riscv_air_lang").testing.assets.framework_qm31_inv_zig,
        @import("stwo_riscv_air_lang").testing.assets.framework_linear_ops_zig,
        @import("stwo_riscv_air_lang").testing.assets.framework_control_zig,
        @import("stwo_riscv_recursion_air").testing.assets.query_bits_zig,
        @import("stwo_riscv_recursion_air").testing.assets.query_mapping_zig,
        @import("stwo_riscv_recursion_air").testing.assets.pow_check_zig,
        @import("stwo_riscv_recursion_air").testing.assets.pow_frame_zig,
        @import("stwo_riscv_recursion_air").testing.assets.relation_challenge_zig,
        @import("stwo_riscv_recursion_air").testing.assets.merkle_root_zig,
        @import("stwo_riscv_recursion_air").testing.assets.trace_merkle_zig,
        @import("stwo_riscv_recursion_air").testing.assets.transcript_air_zig,
        @import("stwo_riscv_recursion_air").testing.assets.transcript_binding_zig,
        @import("stwo_riscv_recursion_air").testing.assets.transcript_payload_zig,
        @import("stwo_riscv_recursion_air").testing.assets.transcript_state_zig,
        @import("stwo_riscv_recursion_air").testing.assets.transcript_word_zig,
        @import("stwo_riscv_recursion_air").testing.assets.pcs_deep_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.fri_merkle_leaf_zig,
        @import("stwo_riscv_recursion_air").testing.assets.fri_merkle_node_zig,
        @import("stwo_riscv_recursion_air").testing.assets.fri_merkle_anchor_zig,
        @import("stwo_riscv_recursion_air").testing.assets.fri_verifier_control_zig,
        @import("stwo_riscv_recursion_air").testing.assets.statement_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.statement_semantics_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_claim_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_claim_hash_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_io_hash_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_claim_semantics_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_logup_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_air_composition_input_zig,
        @import("stwo_riscv_recursion_air").testing.assets.verifier_randomness_zig,
        @import("stwo_riscv_recursion_air").testing.assets.control_slice_component_zig,
    };
    for (sources) |source| {
        try std.testing.expect(std.mem.indexOf(u8, source, "ir.Arena") != null);
        try std.testing.expect(std.mem.indexOf(u8, source, "arena.assertZero") != null);
        try std.testing.expect(std.mem.indexOf(u8, source, "FrameworkEval") == null);
        try std.testing.expect(std.mem.indexOf(u8, source, "define_component_tables") == null);
        try std.testing.expect(std.mem.indexOf(u8, source, "constraint_program.Builder") == null);
        try std.testing.expect(std.mem.indexOf(u8, source, "add_constraint") == null);
    }

    const control_wrappers = [_][]const u8{
        @import("stwo_riscv_recursion_air").testing.assets.vm_public_logup_control_zig,
        @import("stwo_riscv_recursion_air").testing.assets.vm_air_composition_control_zig,
    };
    for (control_wrappers) |source| {
        try std.testing.expect(std.mem.indexOf(u8, source, "factory.Component") != null);
        try std.testing.expect(std.mem.indexOf(u8, source, "FrameworkEval") == null);
        try std.testing.expect(std.mem.indexOf(u8, source, "add_constraint") == null);
    }
}

test "R-012 inventory profiles agree with sealed descriptor geometry" {
    for (std.enums.values(inventory.Component)) |component| {
        const descriptor = inventory.DESCRIPTORS[@intFromEnum(component)];
        const profile = try inventory.collectProfile(std.testing.allocator, component);
        try profile.validate();
        const expected_main_columns: ?u32 = if (descriptor.physical_main_columns == 0)
            null
        else
            descriptor.physical_main_columns;
        try std.testing.expectEqual(
            expected_main_columns,
            profile.physical_main_columns,
        );
        try std.testing.expectEqual(descriptor.constraint_roots, profile.constraint_roots);
        try std.testing.expectEqual(descriptor.relation_events, profile.lookup_events);
        try std.testing.expectEqual(
            descriptor.maximum_constraint_degree,
            profile.maximum_logical_constraint_degree,
        );
    }
}
