//! Adversarial and allocation-failure tests for lookup source ingestion.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../../infra_trace.zig");
const trace = @import("../../../runner/trace.zig");
const counter = @import("counter.zig");
const schema = @import("schema.zig");
const subject = @import("source_ingest_core.zig");

const Error = subject.Error;
const Digest = subject.Digest;
const Shard = subject.Shard;
const FamilySource = subject.FamilySource;
const Result = subject.Result;
const ingest = subject.ingest;
const ingestGenerated = subject.ingestGenerated;
const ingestGeneratedCounters = subject.ingestGeneratedCounters;
const digestShard = subject.digestShard;
const registerGeneratedCommittedRow = subject.registerGeneratedCommittedRow;

const TestColumns = struct {
    storage: [trace.MAX_FAMILY_COLUMNS][]M31,
    len: usize,
};

fn testColumns(allocator: std.mem.Allocator, family: trace.OpcodeFamily) !TestColumns {
    var result = TestColumns{
        .storage = undefined,
        .len = trace.nColumnsForFamily(family),
    };
    var initialized: usize = 0;
    errdefer for (result.storage[0..initialized]) |column| allocator.free(column);
    for (result.storage[0..result.len]) |*column| {
        column.* = try allocator.alloc(M31, 16);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    return result;
}

fn freeTestColumns(allocator: std.mem.Allocator, columns: *TestColumns) void {
    for (columns.storage[0..columns.len]) |column| allocator.free(column);
    columns.* = undefined;
}

fn fillRows(
    allocator: std.mem.Allocator,
    columns: *TestColumns,
    family: trace.OpcodeFamily,
    rows: []const trace.TraceRow,
) !void {
    const placement = try infra.BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);
    for (rows, 0..) |row, logical_row| {
        trace.fillFamilyColumns(&columns.storage, placement.map(logical_row), row, family);
    }
}

fn testRow(opcode: @import("../../../runner/decode.zig").Opcode, index: u32) trace.TraceRow {
    const pc = 0x10000 + 4 * index;
    return .{
        .clk = 20 + index,
        .pc = pc,
        .opcode = opcode,
        .rd = 3,
        .rs1 = 1,
        .rs2 = 2,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_prev_val = 0,
        .rd_prev_clk = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = 0,
    };
}

fn auipcRow(index: u32) trace.TraceRow {
    var row = testRow(.AUIPC, index);
    row.rd = 1;
    row.imm = 0x1000;
    row.rd_val = row.pc + 0x1000;
    row.inst_word = 0x00001097;
    return row;
}

fn boundShard(
    family: trace.OpcodeFamily,
    columns: *const TestColumns,
    ordinal: u32,
    count: u32,
    n_real_rows: usize,
) Shard {
    const views: []const []const M31 = columns.storage[0..columns.len];
    var shard = Shard{
        .ordinal = ordinal,
        .shard_count = count,
        .n_real_rows = n_real_rows,
        .committed_columns = views,
        .committed_digest = undefined,
    };
    shard.committed_digest = digestShard(family, shard);
    return shard;
}

fn expectEqualResults(expected: *const Result, actual: *const Result) !void {
    try std.testing.expectEqual(expected.family_count, actual.family_count);
    try std.testing.expectEqual(expected.shard_count, actual.shard_count);
    try std.testing.expectEqual(expected.real_rows, actual.real_rows);
    try std.testing.expectEqual(expected.padded_rows, actual.padded_rows);
    try std.testing.expectEqualSlices(u64, &expected.source_entries, &actual.source_entries);
    try std.testing.expectEqualSlices(u8, &expected.manifest_digest, &actual.manifest_digest);
    try expectEqualCounters(&expected.counters, &actual.counters);
}

fn expectEqualCounters(expected: *const counter.Set, actual: *const counter.Set) !void {
    for (&expected.counters, &actual.counters) |*want, *got| {
        try std.testing.expectEqual(want.kind, got.kind);
        try std.testing.expectEqual(want.values.len, got.values.len);
        for (want.values, got.values) |want_value, got_value| {
            try std.testing.expect(want_value.eql(got_value));
        }
    }
}

test "lookup source ingestion: committed families feed all six signed tables" {
    const allocator = std.testing.allocator;
    const families = [_]trace.OpcodeFamily{ .base_alu_reg, .base_alu_imm, .lt_imm, .auipc };
    var columns: [families.len]TestColumns = undefined;
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |*item| freeTestColumns(allocator, item);
    for (families, &columns) |family, *item| {
        item.* = try testColumns(allocator, family);
        initialized += 1;
    }

    var xor = testRow(.XOR, 0);
    xor.rs1_val = 0xaa;
    xor.rs2_val = 0x55;
    xor.rd_val = 0xff;
    var xori = testRow(.XORI, 1);
    xori.rs1_val = 0xaa;
    xori.imm = 0x55;
    xori.rd_val = 0xff;
    var slti = testRow(.SLTI, 2);
    slti.rs1_val = 5;
    slti.imm = 7;
    slti.rd_val = 1;
    const auipc = auipcRow(3);
    const rows = [_]trace.TraceRow{ xor, xori, slti, auipc };
    for (families, &columns, rows) |family, *item, row| {
        try fillRows(allocator, item, family, &.{row});
    }

    var shards: [families.len]Shard = undefined;
    var sources: [families.len]FamilySource = undefined;
    for (families, &columns, &shards, &sources) |family, *item, *shard, *source| {
        shard.* = boundShard(family, item, 0, 1, 1);
        source.* = .{ .family = family, .shards = shard[0..1] };
    }
    var result = try ingest(allocator, &sources, .{});
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(u32, families.len), result.family_count);
    for (result.source_entries, result.signedTotals()) |entries_count, total| {
        try std.testing.expect(entries_count > 0);
        try std.testing.expect(!total.isZero());
    }

    // Generated production sources derive their digest instead of comparing a
    // caller-provided copy. The resulting provenance and counters must still be
    // byte-for-byte identical to strict ingestion.
    for (&shards) |*shard| shard.committed_digest = std.mem.zeroes(Digest);
    var generated = try ingestGenerated(allocator, &sources, .{});
    defer generated.deinit(allocator);
    try expectEqualResults(&result, &generated);

    // The production counter-only path skips provenance hashing, but it must
    // derive byte-identical signed multiplicities from the same columns.
    var generated_counters = try ingestGeneratedCounters(allocator, &sources, .{});
    defer generated_counters.deinit(allocator);
    try expectEqualCounters(&result.counters, &generated_counters.counters);

    // The write-through path sees the same physical cells immediately after
    // `fillFamilyColumns` writes them. Its fused counters must remain exactly
    // equal to the independent committed-buffer scan above.
    var write_through = try counter.Set.init(allocator);
    defer write_through.deinit(allocator);
    for (families, &columns) |family, *item| {
        try registerGeneratedCommittedRow(family, &item.storage, 0, &write_through);
    }
    try expectEqualCounters(&generated_counters.counters, &write_through);
}

test "lookup source ingestion: every table counter is additive across shards" {
    const allocator = std.testing.allocator;
    var first = try testColumns(allocator, .auipc);
    defer freeTestColumns(allocator, &first);
    var second = try testColumns(allocator, .auipc);
    defer freeTestColumns(allocator, &second);
    var first_rows: [16]trace.TraceRow = undefined;
    for (&first_rows, 0..) |*row, index| row.* = auipcRow(@intCast(index));
    const second_rows = [_]trace.TraceRow{auipcRow(16)};
    try fillRows(allocator, &first, .auipc, &first_rows);
    try fillRows(allocator, &second, .auipc, &second_rows);

    const shards = [_]Shard{
        boundShard(.auipc, &first, 0, 2, 16),
        boundShard(.auipc, &second, 1, 2, 1),
    };
    var combined = try ingest(allocator, &.{.{ .family = .auipc, .shards = &shards }}, .{});
    defer combined.deinit(allocator);
    const first_alone = boundShard(.auipc, &first, 0, 1, 16);
    var lhs = try ingest(allocator, &.{.{ .family = .auipc, .shards = &.{first_alone} }}, .{});
    defer lhs.deinit(allocator);
    const second_alone = boundShard(.auipc, &second, 0, 1, 1);
    var rhs = try ingest(allocator, &.{.{ .family = .auipc, .shards = &.{second_alone} }}, .{});
    defer rhs.deinit(allocator);

    for (0..schema.KIND_COUNT) |kind_index| {
        const actual = combined.counters.counters[kind_index].values;
        const left = lhs.counters.counters[kind_index].values;
        const right = rhs.counters.counters[kind_index].values;
        for (actual, left, right) |sum, a, b| {
            try std.testing.expect(sum.eql(a.add(b)));
        }
    }

    try expectIngestError(error.InvalidShardCount, &.{.{
        .family = .auipc,
        .shards = shards[0..1],
    }});
    const reordered = [_]Shard{ shards[1], shards[0] };
    try expectIngestError(error.ShardOutOfOrder, &.{.{
        .family = .auipc,
        .shards = &reordered,
    }});
    const duplicated = [_]Shard{ shards[0], shards[0] };
    try expectIngestError(error.ShardOutOfOrder, &.{.{
        .family = .auipc,
        .shards = &duplicated,
    }});
}

test "lookup source ingestion: commitment, tuple, and activity mutations fail" {
    const allocator = std.testing.allocator;
    var columns = try testColumns(allocator, .auipc);
    defer freeTestColumns(allocator, &columns);
    const row = auipcRow(0);
    try fillRows(allocator, &columns, .auipc, &.{row});
    var shard = boundShard(.auipc, &columns, 0, 1, 1);
    const original = columns.storage[15][0];
    columns.storage[15][0] = M31.fromU64(256);
    try expectIngestError(error.CommittedDigestMismatch, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});
    shard.committed_digest = digestShard(.auipc, shard);
    try expectIngestError(error.ValueOutOfRange, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});
    try expectGeneratedCounterError(error.ValueOutOfRange, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});

    columns.storage[15][0] = original;
    columns.storage[0][0] = M31.zero();
    shard.committed_digest = digestShard(.auipc, shard);
    try expectIngestError(error.InactiveRealRow, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});
    try expectGeneratedCounterError(error.InactiveRealRow, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});

    try fillRows(allocator, &columns, .auipc, &.{ row, auipcRow(1) });
    shard.committed_digest = digestShard(.auipc, shard);
    try expectIngestError(error.NonZeroPadding, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});
    try expectGeneratedCounterError(error.NonZeroPadding, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});
}

test "lookup source ingestion: the drop policy omits an unrepresentable request" {
    const allocator = std.testing.allocator;
    var columns = try testColumns(allocator, .auipc);
    defer freeTestColumns(allocator, &columns);
    try fillRows(allocator, &columns, .auipc, &.{auipcRow(0)});
    var shards = [_]Shard{boundShard(.auipc, &columns, 0, 1, 1)};
    const source = FamilySource{ .family = .auipc, .shards = &shards };
    var honest = try ingest(allocator, &.{source}, .{});
    defer honest.deinit(allocator);

    // A non-byte limb in a byte-range tuple: the shape every lookup-guarded forgery
    // has, since asking for a tuple the table does not contain is what the guard
    // detects. Production must still refuse it.
    columns.storage[15][0] = M31.fromU64(256);
    shards[0].committed_digest = digestShard(.auipc, shards[0]);
    try expectIngestError(error.ValueOutOfRange, &.{source});

    var forged = try ingest(allocator, &.{source}, .{ .unrepresentable = .drop });
    defer forged.deinit(allocator);
    // Exactly one request disappears and nothing else moves, which is what makes the
    // dropped fraction the only thing the global LogUp sum can be missing.
    var dropped: u64 = 0;
    for (honest.source_entries, forged.source_entries) |before, after| {
        try std.testing.expect(after <= before);
        dropped += before - after;
    }
    try std.testing.expectEqual(@as(u64, 1), dropped);
    var totals_moved = false;
    for (honest.signedTotals(), forged.signedTotals()) |before, after| {
        totals_moved = totals_moved or !before.eql(after);
    }
    try std.testing.expect(totals_moved);
}

fn expectIngestError(expected: Error, sources: []const FamilySource) !void {
    try std.testing.expectError(expected, ingest(std.testing.allocator, sources, .{}));
}

fn expectGeneratedCounterError(expected: Error, sources: []const FamilySource) !void {
    try std.testing.expectError(
        expected,
        ingestGeneratedCounters(std.testing.allocator, sources, .{}),
    );
}

fn ingestForAllocationFailures(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
) !void {
    var result = try ingest(allocator, sources, .{});
    defer result.deinit(allocator);
}

test "lookup source ingestion: every allocation failure rolls back" {
    const allocator = std.testing.allocator;
    var columns = try testColumns(allocator, .auipc);
    defer freeTestColumns(allocator, &columns);
    const row = auipcRow(0);
    try fillRows(allocator, &columns, .auipc, &.{row});
    const shard = boundShard(.auipc, &columns, 0, 1, 1);
    const sources = [_]FamilySource{.{ .family = .auipc, .shards = &.{shard} }};
    try std.testing.checkAllAllocationFailures(
        allocator,
        ingestForAllocationFailures,
        .{sources[0..]},
    );
}
