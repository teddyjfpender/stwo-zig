const std = @import("std");
const core = @import("stwo_core");
const temporal = @import("../statement_semantics_circuit_temporal_v3.zig");
const legacy = @import("../statement_semantics_circuit.zig");
const interval = @import("../temporal_interval_v3.zig");
const fixture = @import("temporal_interval_v3_test.zig");
const span = @import("../span_statement.zig");
const row11 = @import("../air/statement_semantics_input_witness.zig");
const session_mod = @import("../temporal_parent_row11_session_v3.zig");

test "V3 temporal row-11 graph pins a separate program" {
    var circuit = try temporal.build(std.testing.allocator);
    defer circuit.deinit();
    try std.testing.expect(circuit.nodeCount() > 0);
    try circuit.validate();
    try std.testing.expectEqual(temporal.INPUT_COUNT, circuit.inputCount());
    try std.testing.expectEqual(temporal.NODE_COUNT, circuit.nodeCount());
    try std.testing.expectEqual(temporal.OUTPUT_COUNT, circuit.outputCount());
    try std.testing.expectEqualSlices(u8, &temporal.IDENTITY_DIGEST, &circuit.identity_digest);
    var preprocessing = try row11.Preprocessed.init(std.testing.allocator, 11, circuit.inputBindings());
    defer preprocessing.deinit();
    try preprocessing.validate();
}

test "V3 temporal row-11 leaves legacy pinned graph unchanged" {
    var circuit = try legacy.build(std.testing.allocator);
    defer circuit.deinit();
    try circuit.validate();
    try std.testing.expectEqual(legacy.NODE_COUNT, circuit.nodeCount());
    try std.testing.expectEqual(legacy.OUTPUT_COUNT, circuit.outputCount());
    try std.testing.expectEqualSlices(u8, &legacy.IDENTITY_DIGEST, &circuit.identity_digest);
    try std.testing.expect(!std.mem.eql(u8, &legacy.IDENTITY_DIGEST, &temporal.IDENTITY_DIGEST));
}

test "V3 temporal row-11 accepts an unequal-height three-leaf fold" {
    var circuit = try temporal.build(std.testing.allocator);
    defer circuit.deinit();
    const metadata = try fixture.threeLeaves();
    const first = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const second = try interval.IntervalV3.fromLeaf(&metadata[1]);
    const third = try interval.IntervalV3.fromLeaf(&metadata[2]);
    const left = try interval.IntervalV3.fold(&first, &second);
    const parent = try interval.IntervalV3.fold(&left, &third);
    const left_words = try left.statementWords();
    const right_words = try third.statementWords();
    const parent_words = try parent.statementWords();
    const inputs = try std.testing.allocator.alloc(core.fields.qm31.QM31, temporal.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(core.fields.qm31.QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);
    try std.testing.expect(try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &right_words, &parent_words),
        inputs,
        values,
    ));

    var wrong_height = parent_words;
    wrong_height[span.canonical_layout.slot_height] = core.fields.m31.M31.fromCanonical(1);
    try std.testing.expect(!try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &right_words, &wrong_height),
        inputs,
        values,
    ));
    var wrong_child_height = right_words;
    wrong_child_height[span.canonical_layout.slot_height] = core.fields.m31.M31.fromCanonical(1);
    try std.testing.expect(!try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &wrong_child_height, &parent_words),
        inputs,
        values,
    ));
    var wrong_parent_node = parent_words;
    wrong_parent_node[span.canonical_layout.slot_node_index_start] = core.fields.m31.M31.fromCanonical(1);
    try std.testing.expect(!try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &right_words, &wrong_parent_node),
        inputs,
        values,
    ));
    try std.testing.expect(!try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&right_words, &left_words, &parent_words),
        inputs,
        values,
    ));
    var wrong_boundary = right_words;
    wrong_boundary[span.canonical_layout.entry_state_start + 4] = core.fields.m31.M31.fromCanonical(77);
    try std.testing.expect(!try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &wrong_boundary, &parent_words),
        inputs,
        values,
    ));
}

test "V3 temporal row-11 preserves 64-bit cycles across the V2 cap" {
    var circuit = try temporal.build(std.testing.allocator);
    defer circuit.deinit();
    const metadata = try fixture.threeLeavesWithCycles(.{ 8_388_608, 8_388_608, 2 });
    const first = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const second = try interval.IntervalV3.fromLeaf(&metadata[1]);
    const third = try interval.IntervalV3.fromLeaf(&metadata[2]);
    const left = try interval.IntervalV3.fold(&first, &second);
    const parent = try interval.IntervalV3.fold(&left, &third);
    const left_words = try left.statementWords();
    const right_words = try third.statementWords();
    const parent_words = try parent.statementWords();
    const inputs = try std.testing.allocator.alloc(core.fields.qm31.QM31, temporal.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(core.fields.qm31.QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);
    try std.testing.expect(try circuit.checkIntoAssumeValid(
        temporal.Witness.forBinary(&left_words, &right_words, &parent_words),
        inputs,
        values,
    ));
}

test "V3 temporal row-11 session reuses pinned graph and rejects self-rehashed rows" {
    var session = try session_mod.SessionV3.init(std.testing.allocator);
    defer session.deinit();
    try session.validate();
    try std.testing.expectEqual(session_mod.LOG_SIZE, session.preprocessed.log_size);
    var workspace = try session_mod.WorkspaceV3.init(std.testing.allocator);
    defer workspace.deinit();
    var trace = try session_mod.TraceV3.init(std.testing.allocator);
    defer trace.deinit();
    const metadata = try fixture.threeLeaves();
    const first = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const second = try interval.IntervalV3.fromLeaf(&metadata[1]);
    const third = try interval.IntervalV3.fromLeaf(&metadata[2]);
    const left = try interval.IntervalV3.fold(&first, &second);
    const pair = try interval.PairPreflightV3.init(&left, &third);
    try session.checkPair(&pair, &left, &third, &workspace);
    try session.fillTrace(&pair, &left, &third, &workspace, &trace);
    try std.testing.expectEqual(@as(usize, 1 << session_mod.LOG_SIZE), trace.main[0].len);
    try std.testing.expectEqual(core.fields.m31.M31.one(), trace.preprocessed[0][0]);
    try std.testing.expectEqual(core.fields.m31.M31.zero(), trace.preprocessed[0][temporal.INPUT_COUNT]);
    try std.testing.expectError(error.ParentProofUnavailable, session.requireVerifiedParent());

    var bad_pair = pair;
    bad_pair.global_join_cycle += 1;
    const prior_main = trace.main[0][0];
    try std.testing.expectError(error.ParentChanged, session.fillTrace(&bad_pair, &left, &third, &workspace, &trace));
    try std.testing.expectEqual(prior_main, trace.main[0][0]);
    session.preprocessed.rows[0].circuit_id += 1;
    try std.testing.expectError(error.AuthorityMismatch, session.validate());
}
