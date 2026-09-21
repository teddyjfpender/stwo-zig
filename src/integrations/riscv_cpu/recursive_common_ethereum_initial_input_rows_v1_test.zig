//! Genuine small execution exercises the production writer and shared range
//! provider. This is not a complete initial-segment wrapper proof.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const rows = @import("recursive_common_ethereum_initial_input_rows_v1.zig");
const fixture_mod = @import("recursive_common_ethereum_initial_input_lane_v1_test.zig");
const graph_mod = @import("recursive_common_ethereum_initial_input_packet_v1_test.zig");
const provider = @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig");
const air = frontend.recursion.air;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const a = std.testing.allocator;

test "Ethereum compact initial policy owned rows preserve genuine witness and exact shared range histogram" {
    const fixture = try fixture_mod.Fixture.init();
    var graph = try graph_mod.TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    var words: [rows.Packet.INPUT_COUNT]M31 = undefined;
    for (graph.packets, 0..) |packet, i| words[4 * i ..][0..4].* = packet;
    var lane_rows: [64]rows.Lane.Row = undefined;
    var packet_rows: [rows.Packet.ROW_COUNT]rows.Packet.Row = undefined;
    const histogram = try a.alloc(u32, rows.RANGE_TABLE_SIZE);
    defer a.free(histogram);
    const shape = try rows.Lane.Shape.init(40);
    try rows.generate(shape, &fixture.words, words, graph.preprocessing, &lane_rows, &packet_rows, histogram);
    try std.testing.expectEqualDeep(fixture.rows, lane_rows);
    try std.testing.expectEqualDeep(graph.rows(), packet_rows);
    var total: usize = 0;
    for (histogram) |count| total += count;
    try std.testing.expectEqual(@as(usize, 5 * 64), total);

    var definition = try rows.Lane.build(a);
    defer definition.deinit();
    const plan = try rows.Lane.Relation.authenticate(&definition);
    const table = frontend.air.lookups.tables.schema;
    const actual = try a.alloc(u32, rows.RANGE_TABLE_SIZE);
    defer a.free(actual);
    @memset(actual, 0);
    for (lane_rows) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain != .range_check_8_8) continue;
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));
        const index = try table.indexSecure(.range_check_8_8, entry.values[0..2]);
        actual[index] += 1;
    };
    try std.testing.expectEqualSlices(u32, actual, histogram);
    var ledger = air.relation_interaction.TupleLedger.init(a);
    defer ledger.deinit();
    const mask = @as(u64, 1) << @intFromEnum(frontend.air.relation.Domain.range_check_8_8);
    try plan.appendPreparedTupleContributions(&ledger, rows.LANE_COMPONENT, &lane_rows, mask);
    var range = try provider.OwnerV4.init(a, &ledger);
    defer range.deinit();
    try std.testing.expectEqual(@as(usize, 5 * 64), range.source_contribution_count);
    try range.appendTupleContributions(&ledger);
    try std.testing.expect(ledger.classify().isClosed());
    // A coherent writer still rejects a changed actual input against the
    // authenticated subtotal packet; inputs beyond the old32 cap are covered.
    var changed_input = fixture.words;
    changed_input[35] ^= 1;
    try std.testing.expectError(error.EthereumInitialInputSubtotalMismatch, rows.generate(shape, &changed_input, words, graph.preprocessing, &lane_rows, &packet_rows, histogram));
    var changed_words = words;
    changed_words[rows.Lane.SUM_SLOT * 4] = changed_words[rows.Lane.SUM_SLOT * 4].add(M31.one());
    try std.testing.expectError(error.EthereumInitialInputSubtotalMismatch, rows.generate(shape, &fixture.words, changed_words, graph.preprocessing, &lane_rows, &packet_rows, histogram));
}

test "Ethereum compact initial policy owned rows reject duplicate role publishers and preserve exact claim fanout" {
    const legacy = air.vm_public_logup_input;
    const Public = air.ethereum_public_logup_input_v1;
    const at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    var publishers = [_]Public.Relation.Row{[_]M31{M31.zero()} ** Public.LOGICAL_INPUT_COUNT} ** 7;
    for (publishers[0..6], 0..) |*row, index| {
        row[at] = M31.one();
        row[at + 1] = M31.fromCanonical(rows.Lane.ROLE_HASH_SCOPE);
        row[at + 2] = M31.fromCanonical(@intCast(index));
    }
    try rows.validateOrdinaryRolePublishers(&publishers);
    publishers[6] = publishers[5];
    try std.testing.expectError(error.DuplicateEthereumInitialRolePublisher, rows.validateOrdinaryRolePublishers(&publishers));
    publishers[6][at + 2] = M31.fromCanonical(6);
    try std.testing.expectError(error.DuplicateEthereumInitialRolePublisher, rows.validateOrdinaryRolePublishers(&publishers));
    publishers[6][at] = M31.zero();
    publishers[2][at] = M31.zero();
    try std.testing.expectError(error.MissingEthereumInitialRoleHeader, rows.validateOrdinaryRolePublishers(&publishers));
    const shape = try rows.Lane.Shape.init(675173);
    const first = frontend.recursion.vm_public_claim.canonical_layout.input_slots_start;
    var count: usize = 0;
    for (first..first + 3 * 675173) |index| count += try shape.claimSourceUses(index);
    try std.testing.expectEqual(@as(usize, 3 * 675173), count);
    try std.testing.expectEqual(@as(u32, 0), try shape.claimSourceUses(first - 1));
    try std.testing.expectEqual(@as(u32, 0), try shape.claimSourceUses(first + 3 * 675173));
}
