//! Integration parity and failure-path tests for the shared tuple owner.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const relation = frontend.recursion.air.relation_interaction;
const initial_rows = @import("recursive_common_ethereum_initial_input_rows_v1.zig");
const Owner = frontend.recursion.compact_tuple_ledger_v1.Owner;
const tables = frontend.air.lookups.tables;
const TABLE_SIZE = tables.schema.size(.range_check_8_8);
const Role = @FieldType(relation.TupleContribution, "role");
const Domain = @FieldType(relation.TupleContribution, "domain");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn appendBoth(old: *relation.TupleLedger, compact: *relation.TupleLedger, domain: Domain, component: u8, weight: QM31, values: []const QM31) !void {
    try old.append(domain, component, 0, .request, weight, values);
    try compact.append(domain, component, 0, .request, weight, values);
}

test "Ethereum compact tuple ledger matches canonical records and range provider exactly" {
    const allocator = std.testing.allocator;
    const Range = @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig").OwnerV4;
    var ordinary = relation.TupleLedger.init(allocator);
    defer ordinary.deinit();
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, q(2), &.{q(19)});
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, q(2).neg(), &.{q(19)});
    // Distinct domain, arity and extension-field coordinates cannot cancel.
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, q(1), &.{ q(1), q(2) });
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, q(1).neg(), &.{q(1)});
    try appendBoth(&ordinary, &sink, .poseidon2, 4, q(1).neg(), &.{ q(1), q(2) });
    const extension = QM31.fromU32Unchecked(1, 2, 3, 4);
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, extension, &.{ extension, q(2) });
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, extension.neg(), &.{ extension, q(2) });
    for (0..7) |_| try appendBoth(&ordinary, &sink, .range_check_8_8, 4, q(1).neg(), &.{ q(3), q(5) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 7, q(2), &.{ q(3), q(5) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 8, q(1).neg(), &.{ q(255), q(255) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 35, QM31.zero(), &.{}); // Both omit zero events.
    try std.testing.expectEqualDeep(ordinary.classify(), try compact.classify());
    try std.testing.expectEqual(@as(usize, 0), sink.contributions.items.len);
    var old_provider = try Range.init(allocator, &ordinary);
    defer old_provider.deinit();
    var new_provider = try Range.initFromCompact(allocator, &compact, null);
    defer new_provider.deinit();
    try std.testing.expectEqualDeep(old_provider.batch.counter.values, new_provider.batch.counter.values);
    try std.testing.expectEqualDeep(old_provider.relation_rows, new_provider.relation_rows);
    try std.testing.expectEqualDeep(old_provider.identity_sha256, new_provider.identity_sha256);
    try std.testing.expectEqual(old_provider.source_contribution_count, new_provider.source_contribution_count);
    try old_provider.appendTupleContributions(&ordinary);
    try new_provider.appendTupleContributions(&sink);
    try std.testing.expectEqualDeep(ordinary.classify(), try compact.classify());
    try std.testing.expectEqualDeep(ordinary.classify(), sink.classify());
    try std.testing.expectEqual(@as(usize, 3), compact.metrics().live_entries);
    try std.testing.expect(compact.metrics().peak_entries >= compact.metrics().live_entries);
    try std.testing.expectEqual(@as(usize, 9), compact.metrics().source_range_contribution_count);
}

test "Ethereum compact tuple ledger preserves cancellation counts without retained records" {
    const allocator = std.testing.allocator;
    var ordinary = relation.TupleLedger.init(allocator);
    defer ordinary.deinit();
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    for (0..64) |i| {
        try appendBoth(&ordinary, &sink, .recursion_wire, 0, q(1), &.{q(@intCast(i))});
        try appendBoth(&ordinary, &sink, .recursion_wire, 1, q(1).neg(), &.{q(@intCast(i))});
    }
    try compact.sealSourceHistogram(null, 0);
    const report = try compact.classify();
    try std.testing.expect(report.isClosed());
    try std.testing.expectEqualDeep(ordinary.classify(), report);
    try std.testing.expectEqual(@as(usize, 128), report.contribution_count);
    try std.testing.expectEqual(@as(usize, 0), compact.metrics().live_entries);
    try std.testing.expectEqual(@as(usize, 1), compact.metrics().peak_entries);
    try std.testing.expect(compact.metrics().capacity_entries > 0);
}

test "Ethereum compact tuple ledger rejects malformed range requests before cancellation" {
    inline for (.{ "arity", "value", "weight", "provider", "packet", "lane_role", "lane_weight" }) |kind| {
        var compact = try Owner.init(std.testing.allocator, true);
        defer compact.deinit();
        var sink = compact.ledger();
        defer sink.deinit();
        const tuple = if (comptime std.mem.eql(u8, kind, "arity")) &[_]QM31{q(1)} else if (comptime std.mem.eql(u8, kind, "value")) &[_]QM31{ q(256), q(2) } else &[_]QM31{ q(1), q(2) };
        const component: u8 = if (comptime std.mem.eql(u8, kind, "provider")) 35 else if (comptime std.mem.eql(u8, kind, "packet")) initial_rows.PACKET_COMPONENT else if (comptime std.mem.startsWith(u8, kind, "lane_")) initial_rows.LANE_COMPONENT else 4;
        const role: Role = if (comptime std.mem.eql(u8, kind, "lane_role")) .emit else .request;
        const weight = if (comptime std.mem.eql(u8, kind, "weight")) QM31.fromU32Unchecked(1, 1, 0, 0) else if (comptime std.mem.eql(u8, kind, "lane_weight")) q(2).neg() else q(1).neg();
        try sink.append(.range_check_8_8, component, 0, role, weight, tuple);
        try sink.append(.range_check_8_8, component, 0, role, weight.neg(), tuple);
        if (compact.validate()) |_| return error.TestExpectedError else |_| {}
        if (compact.classify()) |_| return error.TestExpectedError else |_| {}
        try std.testing.expect(!sink.classify().isClosed());
    }
}

test "Ethereum compact tuple ledger checks initial histogram and source phase exactly" {
    var compact = try Owner.init(std.testing.allocator, true);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    const bins = try std.testing.allocator.alloc(u32, TABLE_SIZE);
    defer std.testing.allocator.free(bins);
    @memset(bins, 0);
    const tuple = [_]QM31{ q(7), q(9) };
    const index = try tables.schema.indexSecure(.range_check_8_8, &tuple);
    try sink.append(.range_check_8_8, initial_rows.LANE_COMPONENT, 0, .request, q(1).neg(), &tuple);
    bins[index] = 1;
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(bins, 2));
    bins[index] = 0;
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(bins, 1));
    bins[index] = 1;
    try compact.sealSourceHistogram(bins, 1);
    try sink.append(.range_check_8_8, 35, 0, .emit, q(1), &tuple);
    try std.testing.expect((try compact.classify()).isClosed());
    try std.testing.expectEqual(@as(usize, 1), compact.source_range_contribution_count);
    try sink.append(.range_check_8_8, 2, 0, .request, q(1).neg(), &tuple);
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.validate());
}

fn exerciseAllocationFailures(allocator: std.mem.Allocator) !void {
    var compact = try Owner.init(allocator, true);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    for (0..32) |i| try sink.append(.recursion_wire, 2, 0, .request, q(1), &.{q(@intCast(i))});
    for (0..32) |i| try sink.append(.recursion_wire, 3, 0, .emit, q(1).neg(), &.{q(@intCast(i))});
    try compact.validate();
    try std.testing.expect((try compact.classify()).isClosed());
}

test "Ethereum compact tuple ledger cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseAllocationFailures, .{});
}

fn exerciseProviderAllocationFailures(allocator: std.mem.Allocator) !void {
    const Range = @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig").OwnerV4;
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    try sink.append(.range_check_8_8, 4, 0, .request, q(1).neg(), &.{ q(13), q(17) });
    var provider = Range.initFromCompact(allocator, &compact, null) catch |err| {
        // The range constructor consumes the source phase before allocating
        // its owned batch/definition/rows. Failed publication must leave no
        // balancing provider contribution or retryable source phase behind.
        try std.testing.expect(compact.source_finished);
        try std.testing.expect(!sink.classify().isClosed());
        try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(null, 0));
        return err;
    };
    defer provider.deinit();
    try std.testing.expect(compact.source_finished);
    try provider.appendTupleContributions(&sink);
    try std.testing.expect((try compact.classify()).isClosed());
}

test "Ethereum compact tuple ledger cleans up provider failures after source sealing" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseProviderAllocationFailures, .{});
}

test "Ethereum compact tuple ledger keeps map allocation failure sticky through cancellation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var compact = try Owner.init(failing.allocator(), false);
        defer compact.deinit();
        var sink = compact.ledger();
        defer sink.deinit();
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, sink.append(.recursion_wire, 2, 0, .request, q(1), &.{q(19)}));
        try std.testing.expect(failing.has_induced_failure);
        const allocations_at_failure = failing.allocations;
        failing.fail_index = std.math.maxInt(usize);
        // Restoring memory and supplying an opposite event cannot undo the
        // missing original tuple or turn the poisoned adapter into closure.
        try sink.append(.recursion_wire, 3, 0, .emit, q(1).neg(), &.{q(19)});
        try std.testing.expectEqual(allocations_at_failure, failing.allocations);
        try std.testing.expectError(error.OutOfMemory, compact.validate());
        try std.testing.expectError(error.OutOfMemory, compact.classify());
        try std.testing.expect(!sink.classify().isClosed());
        try std.testing.expectEqual(@as(usize, 0), compact.metrics().live_entries);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "Recursive streamed tuple projection matches every parent diagnostic entry" {
    @setEvalBranchQuota(1_000_000);
    inline for (frontend.recursion.air.detached_parent_catalog_v1.LOGICAL_ROWS) |entry|
        try checkStreamedProjection(entry);
}

fn checkStreamedProjection(comptime entry: anytype) !void {
    const allocator = std.testing.allocator;
    const Air = entry.Air;
    const Binding = frontend.recursion.air.universal_relation_binding.Binding(Air);
    var definition = if (entry.requires_location) try Air.build(allocator, .generated) else try Air.build(allocator);
    defer definition.deinit();
    const plan = try Binding.authenticate(&definition);
    const rows = try allocator.alloc([Air.LOGICAL_INPUT_COUNT]M31, 64);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| for (row, 0..) |*value, column| {
        value.* = M31.fromU64(if (index % 3 == 0) 0 else (index * 17 + column * 11) % 251);
    };
    const range_mask = @as(u64, 1) << @intFromEnum(Domain.range_check_8_8);
    for ([_]u64{ 0, range_mask, relation.allDomainMask() }) |mask| {
        var expected = relation.TupleLedger.init(allocator);
        defer expected.deinit();
        var actual = relation.TupleLedger.init(allocator);
        defer actual.deinit();
        for (rows) |row| for (plan.preparedEntries(row)) |event| {
            const bit = @as(u64, 1) << @as(u6, @intCast(@intFromEnum(event.domain)));
            if (mask & bit != 0)
                try expected.append(event.domain, @intFromEnum(entry.row), event.ordinal, event.role, event.numerator, event.values[0..event.arity]);
        };
        try plan.appendPreparedTupleContributions(&actual, @intFromEnum(entry.row), rows, mask);
        try std.testing.expectEqualDeep(expected.contributions.items, actual.contributions.items);
    }
}

test "Recursive shared interaction preparation preserves audited columns and failure cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, sharedInteractionCase, .{});
}

fn sharedInteractionCase(allocator: std.mem.Allocator) !void {
    const air = frontend.recursion.air;
    const Binding = air.universal_relation_binding.Binding(air.control);
    const Framework = air.framework_interaction.Runtime(Binding.Runtime);
    var definition = try air.control.build(allocator);
    defer definition.deinit();
    const plan = try Binding.authenticate(&definition);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const rows = [_]Binding.Row{
        air.control_witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 7, .args = .{ 11, 13, 17, 19 }, .terminal_mask = 0 }, .segment_leaf),
        air.control_witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 1, .tag = 23, .args = .{ 29, 31, 37, 41 }, .terminal_mask = 1 }, .segment_leaf),
    };
    var expected = try Framework.generatePrepared(allocator, &plan, &rows, 4, &relations);
    defer expected.deinit(allocator);
    var storage: [Framework.INTERACTION_COLUMN_COUNT][16]M31 = undefined;
    var columns: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;
    const plain = try air.prepared_interaction_generation.generateInto(Framework, allocator, &plan, &rows, 4, &relations, &columns, null);
    try std.testing.expect(plain.audit == null);
    try std.testing.expectEqualDeep(expected.claimed_sum, plain.claimed_sum);
    try std.testing.expectEqualDeep(expected.columns, columns);
    var ledger = relation.TupleLedger.init(allocator);
    defer ledger.deinit();
    const audited = try air.prepared_interaction_generation.generateInto(Framework, allocator, &plan, &rows, 4, &relations, &columns, .{
        .verify_domains = true,
        .tuples = .{ .ledger = &ledger, .component = 18 },
    });
    try std.testing.expectEqualDeep(expected.claimed_sum, audited.claimed_sum);
    try std.testing.expectEqualDeep(expected.columns, columns);
    const reference = try plan.auditPreparedDomainSums(allocator, &rows, &relations, expected.claimed_sum);
    try std.testing.expectEqualDeep(reference, audited.audit.?);
    var expected_ledger = relation.TupleLedger.init(allocator);
    defer expected_ledger.deinit();
    for (rows) |row| for (plan.preparedEntries(row)) |event|
        try expected_ledger.append(event.domain, 18, event.ordinal, event.role, event.numerator, event.values[0..event.arity]);
    try std.testing.expectEqualDeep(expected_ledger.contributions.items, ledger.contributions.items);
}
