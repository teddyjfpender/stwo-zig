const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const air = @import("../v3_public_io_word_bridge_v1.zig");
const relation = @import("../v3_public_io_word_bridge_relation_v1.zig");
const source_air = @import("../blake3_memory_boundary.zig");
const source_binding = @import("../universal_relation_binding.zig").Binding(source_air);
const direct_program = @import("../direct_constraint_program.zig");
const expected_io = @import("../../segment_public_io_binding_v1.zig");
const ingress = @import("../../segment_public_io_ingress_v2.zig");

const EXPECTED = expected_io.Expected{
    .input_start = 0x1001,
    .input = &.{ 0x11, 0x22, 0x33, 0x44, 0x55 },
    .output_len_addr = 0x2000,
    .output_data_addr = 0x2005,
    .output = &.{ 0x66, 0x77 },
};

test "V3 public IO word bridge pins independent typed identity and stays inactive" {
    try std.testing.expectEqualStrings(
        air.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(try air.computeSemanticDigest(std.testing.allocator), .lower),
    );
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 4), relation.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 16), relation.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 7), plan.events.len);
    try std.testing.expect(!air.PROOF_ACTIVATION);
}

test "V3 public IO word bridge consumes actual source word and exports only selected bytes" {
    var policy = try ingress.VerifierExpectedIo.initOwned(std.testing.allocator, EXPECTED);
    defer policy.deinit();
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation.authenticate(&definition);
    var source_definition = try source_air.build(std.testing.allocator);
    defer source_definition.deinit();
    const source_plan = try source_binding.authenticate(&source_definition);
    const source_schedule = source_air.Schedule{
        .address = 0x1000,
        .clock = 0,
        .direction = .initial,
        .circuit = 7,
        .first_wire = 0x400,
        .uses = 1,
    };
    const native_bytes = [4]u8{ 0xaa, 0x11, 0x22, 0x33 };
    const source_row = try source_air.logicalRow(source_schedule, native_bytes);
    const row = try air.logicalRow(&policy, .input, 0x1000, 7, native_bytes);
    try expectConstraints(&definition, row, true);
    const source_entries = try source_plan.entries(
        &source_definition.arena,
        source_air.SEMANTIC_DIGEST,
        source_binding.events(&source_definition),
        source_row,
    );
    const bridge_entries = try plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        relation.events(&definition),
        row,
    );
    try std.testing.expect(source_entries[3].domain == .recursion_wire);
    try std.testing.expect(bridge_entries[0].domain == .recursion_wire);
    try std.testing.expect(source_entries[3].role == .emit);
    try std.testing.expect(bridge_entries[0].role == .consume);
    try std.testing.expect(source_entries[3].numerator.eql(QM31.one()));
    try std.testing.expect(bridge_entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expectEqualSlices(QM31, source_entries[3].values[0..6], bridge_entries[0].values[0..6]);
    try std.testing.expect(bridge_entries[1].numerator.isZero());
    for (1..4) |index| {
        try std.testing.expect(bridge_entries[1 + index].numerator.eql(QM31.one()));
        try std.testing.expect(bridge_entries[1 + index].values[1].eql(QM31.fromBase(M31.fromCanonical(@intCast(index - 1)))));
    }
    const wrong_source = try source_air.logicalRow(source_schedule, .{ 0xaa, 0x12, 0x22, 0x33 });
    const mismatched_entries = try source_plan.entries(
        &source_definition.arena,
        source_air.SEMANTIC_DIGEST,
        source_binding.events(&source_definition),
        wrong_source,
    );
    try std.testing.expect(!std.meta.eql(mismatched_entries[3].values, bridge_entries[0].values));
    var changed_address_row = row;
    changed_address_row[7] = M31.fromCanonical(0x1004);
    try expectConstraints(&definition, changed_address_row, false);
    var changed_node_row = row;
    changed_node_row[6] = M31.fromCanonical(0x401);
    try expectConstraints(&definition, changed_node_row, false);
    // An unselected neighbor byte is still tied to the exact source word by
    // the lookup, even though the external request does not constrain it.
    var changed_neighbor = row;
    changed_neighbor[0] = M31.fromCanonical(0xab);
    try expectConstraints(&definition, changed_neighbor, true);
    const neighbor_entries = try plan.entries(&definition.arena, air.SEMANTIC_DIGEST, relation.events(&definition), changed_neighbor);
    try std.testing.expect(!std.meta.eql(source_entries[3].values, neighbor_entries[0].values));
}

test "V3 public IO word bridge rejects changed byte length and address" {
    var policy = try ingress.VerifierExpectedIo.initOwned(std.testing.allocator, EXPECTED);
    defer policy.deinit();
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const correct_input = try air.logicalRow(&policy, .input, 0x1000, 7, .{ 0xaa, 0x11, 0x22, 0x33 });
    try expectConstraints(&definition, correct_input, true);
    const changed_input = try air.logicalRow(&policy, .input, 0x1000, 7, .{ 0xaa, 0x12, 0x22, 0x33 });
    try expectConstraints(&definition, changed_input, false);
    const correct_length = try air.logicalRow(&policy, .output_length, 0x2000, 8, .{ 2, 0, 0, 0 });
    try expectConstraints(&definition, correct_length, true);
    const changed_length = try air.logicalRow(&policy, .output_length, 0x2000, 8, .{ 3, 0, 0, 0 });
    try expectConstraints(&definition, changed_length, false);
    const correct_output = try air.logicalRow(&policy, .output, 0x2004, 8, .{ 0xfe, 0x66, 0x77, 0xfd });
    try expectConstraints(&definition, correct_output, true);
    const changed_output = try air.logicalRow(&policy, .output, 0x2004, 8, .{ 0xfe, 0x66, 0x78, 0xfd });
    try expectConstraints(&definition, changed_output, false);
    try std.testing.expectError(error.InvalidPublicIoWordAddress, air.fixedRow(&policy, .input, 0x1004, 0));
    try std.testing.expectError(error.InvalidPublicIoWordAddress, air.fixedRow(&policy, .input, 0x2000, 7));
    try std.testing.expectError(error.InvalidPublicIoWordAddress, air.fixedRow(&policy, .output_length, 0x2004, 8));
    var overlapping = EXPECTED;
    overlapping.output_data_addr = 0x2002;
    var overlapping_policy = try ingress.VerifierExpectedIo.initOwned(std.testing.allocator, overlapping);
    defer overlapping_policy.deinit();
    try std.testing.expectError(error.OverlappingOutputLengthAndBytes, air.fixedRow(&overlapping_policy, .output_length, 0x2000, 8));
    var changed_expected = EXPECTED;
    changed_expected.input = &.{ 0x11, 0x23, 0x33, 0x44, 0x55 };
    var changed_policy = try ingress.VerifierExpectedIo.initOwned(std.testing.allocator, changed_expected);
    defer changed_policy.deinit();
    const changed_fixed = try air.fixedRow(&changed_policy, .input, 0x1000, 7);
    const original_fixed = try air.fixedRow(&policy, .input, 0x1000, 7);
    try std.testing.expect(!std.meta.eql(changed_fixed, original_fixed));
    var mutable_request = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };
    var borrowed_expected = EXPECTED;
    borrowed_expected.input = &mutable_request;
    var owned_policy = try ingress.VerifierExpectedIo.initOwned(std.testing.allocator, borrowed_expected);
    defer owned_policy.deinit();
    mutable_request[1] = 0x23;
    try std.testing.expect(std.meta.eql(original_fixed, try air.fixedRow(&owned_policy, .input, 0x1000, 7)));
}

fn expectConstraints(definition: *const air.Definition, row: air.Row, valid: bool) !void {
    const program = try direct_program.authenticate(&definition.arena, air.SEMANTIC_DIGEST, air.LOGICAL_INPUT_COUNT);
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&row, &scratch, &roots);
    const all_zero = for (roots) |root| {
        if (!root.isZero()) break false;
    } else true;
    try std.testing.expectEqual(valid, all_zero);
}
