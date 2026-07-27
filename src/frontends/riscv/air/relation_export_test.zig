const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../infra_trace.zig");
const trace = @import("../runner/trace.zig");
const relations_mod = @import("relation_challenges.zig");
const relation_export = @import("relation_export.zig");
const claims = @import("transcript/claims.zig");

const TestColumns = struct {
    storage: [trace.MAX_FAMILY_COLUMNS][]M31,
    len: usize,
};

const ProvenanceObserver = struct {
    real_requests: usize = 0,
    padding_requests: usize = 0,

    pub fn onEntry(self: *ProvenanceObserver, location: relation_export.Location, _: relation_export.RawEntry) !void {
        if (location.opcode) |identity| {
            try std.testing.expectEqual(@as(u32, 1), identity.execution_row);
            try std.testing.expectEqual(trace.OpcodeFamily.auipc, identity.family);
            try std.testing.expectEqual(@as(u64, 0), identity.family_row);
            try std.testing.expectEqual(@as(u32, @intCast(location.declaration)), identity.request_ordinal);
            self.real_requests += 1;
        } else {
            self.padding_requests += 1;
        }
    }

    pub fn onShard(_: *ProvenanceObserver, _: relation_export.ShardEvidence) !void {}
};

fn zeroColumns(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !TestColumns {
    var result = TestColumns{
        .storage = @as([trace.MAX_FAMILY_COLUMNS][]M31, undefined),
        .len = @as(usize, trace.nColumnsForFamily(family)),
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

fn freeTestColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

fn fillCommittedRows(
    allocator: std.mem.Allocator,
    columns: *TestColumns,
    family: trace.OpcodeFamily,
    rows: []const trace.TraceRow,
) !void {
    const size = columns.storage[0].len;
    const placement = try infra.BitReversalTable.init(
        allocator,
        @intCast(std.math.log2_int(usize, size)),
    );
    defer placement.deinit(allocator);
    for (rows, 0..) |row, logical_row| {
        trace.fillFamilyColumns(&columns.storage, placement.map(logical_row), row, family);
    }
}

fn testAuipcRow(index: u32) trace.TraceRow {
    const pc = 0x10000 + 4 * index;
    return .{
        .clk = index + 1,
        .pc = pc,
        .opcode = .AUIPC,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 0x1000,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_prev_val = 0,
        .rd_prev_clk = index,
        .rd_val = pc + 0x1000,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = 0x00001097,
    };
}

fn oneShard(columns: *const TestColumns) relation_export.OpcodeShard {
    const views: []const []const M31 = columns.storage[0..columns.len];
    var shard = relation_export.OpcodeShard{
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = 1,
        .committed_columns = views,
        .main_columns_digest = undefined,
    };
    shard.main_columns_digest = relation_export.digestCommittedShard(.auipc, .auipc, shard);
    return shard;
}

test "relation export: committed opcode stream binds a fixed native claim" {
    var columns = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, columns.storage[0..columns.len]);
    const rows = [_]trace.TraceRow{testAuipcRow(0)};
    try fillCommittedRows(std.testing.allocator, &columns, .auipc, &rows);
    const shard = oneShard(&columns);
    var native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.auipc)] = QM31.fromU32Unchecked(
        329023804,
        1517245229,
        476668728,
        845289624,
    );
    const native = claims.InteractionClaim.init(native_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    var observer = ProvenanceObserver{};
    const evidence = try relation_export.exportOpcodeFamily(
        std.testing.allocator,
        .auipc,
        &.{shard},
        &relations_mod.Relations.dummy(),
        &ledger,
        &sequence,
        &observer,
    );
    try std.testing.expectEqual(@as(u64, 192), evidence.all.entries);
    try std.testing.expectEqual(@as(u64, 180), evidence.zero.entries);
    try std.testing.expectEqual(@as(u64, 12), evidence.nonzero.entries);
    try std.testing.expectEqual(@as(usize, 12), observer.real_requests);
    try std.testing.expectEqual(@as(usize, 180), observer.padding_requests);
    try std.testing.expectError(error.IncompleteClaims, ledger.finish());
    try std.testing.expectError(error.IncompleteComponents, sequence.finish());
}

test "relation export: shadow columns and self-derived claim do not cross bindings" {
    var columns = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, columns.storage[0..columns.len]);
    const rows = [_]trace.TraceRow{testAuipcRow(0)};
    try fillCommittedRows(std.testing.allocator, &columns, .auipc, &rows);
    const shard = oneShard(&columns);
    const committed_value = columns.storage[0][0];
    columns.storage[0][0] = committed_value.add(M31.one());
    var zero_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    const zero_claims = claims.InteractionClaim.init(zero_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &zero_claims);
    var sequence = relation_export.Sequence.init();
    var observer = relation_export.NullObserver{};
    try std.testing.expectError(
        error.MainColumnsDigestMismatch,
        relation_export.exportOpcodeFamily(
            std.testing.allocator,
            .auipc,
            &.{shard},
            &relations_mod.Relations.dummy(),
            &ledger,
            &sequence,
            &observer,
        ),
    );

    columns.storage[0][0] = committed_value;
    zero_sums[@intFromEnum(relation_export.Component.auipc)] = QM31.one();
    const shadow_claims = claims.InteractionClaim.init(zero_sums, &.{});
    ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &shadow_claims);
    sequence = relation_export.Sequence.init();
    try std.testing.expectError(
        error.ClaimMismatch,
        relation_export.exportOpcodeFamily(
            std.testing.allocator,
            .auipc,
            &.{shard},
            &relations_mod.Relations.dummy(),
            &ledger,
            &sequence,
            &observer,
        ),
    );
}

test "relation export: ordered two-shard family checks one aggregate claim" {
    var first = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, first.storage[0..first.len]);
    var second = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, second.storage[0..second.len]);
    var first_rows: [16]trace.TraceRow = undefined;
    for (&first_rows, 0..) |*row, index| row.* = testAuipcRow(@intCast(index));
    const second_rows = [_]trace.TraceRow{testAuipcRow(16)};
    try fillCommittedRows(std.testing.allocator, &first, .auipc, &first_rows);
    try fillCommittedRows(std.testing.allocator, &second, .auipc, &second_rows);
    const first_views: []const []const M31 = first.storage[0..first.len];
    const second_views: []const []const M31 = second.storage[0..second.len];
    var shards = [_]relation_export.OpcodeShard{
        .{
            .ordinal = 0,
            .shard_count = 2,
            .n_real_rows = 16,
            .committed_columns = first_views,
            .main_columns_digest = undefined,
        },
        .{
            .ordinal = 1,
            .shard_count = 2,
            .n_real_rows = 1,
            .committed_columns = second_views,
            .main_columns_digest = undefined,
        },
    };
    for (&shards) |*shard| {
        shard.main_columns_digest = relation_export.digestCommittedShard(.auipc, .auipc, shard.*);
    }
    var native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.auipc)] = QM31.fromU32Unchecked(
        1494796886,
        943261898,
        172869581,
        1009213607,
    );
    const native = claims.InteractionClaim.init(native_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    var observer = relation_export.NullObserver{};
    const evidence = try relation_export.exportOpcodeFamily(
        std.testing.allocator,
        .auipc,
        &shards,
        &relations_mod.Relations.dummy(),
        &ledger,
        &sequence,
        &observer,
    );
    try std.testing.expectEqual(@as(u32, 2), evidence.shard_count);
    try std.testing.expectEqual(@as(u64, 384), evidence.all.entries);
    try std.testing.expectEqual(@as(u64, 204), evidence.nonzero.entries);
    try std.testing.expectEqual(@as(u64, 180), evidence.zero.entries);

    try expectShardFailure(error.InvalidShardCount, shards[0..1]);
    const reordered = [_]relation_export.OpcodeShard{ shards[1], shards[0] };
    try expectShardFailure(error.ShardOutOfOrder, &reordered);
    const duplicated = [_]relation_export.OpcodeShard{ shards[0], shards[0] };
    try expectShardFailure(error.ShardOutOfOrder, &duplicated);
}

test "relation export: same-shape shard contents retain canonical execution order" {
    var earlier = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, earlier.storage[0..earlier.len]);
    var later = try zeroColumns(std.testing.allocator, .auipc);
    defer freeTestColumns(std.testing.allocator, later.storage[0..later.len]);
    var earlier_rows: [16]trace.TraceRow = undefined;
    var later_rows: [16]trace.TraceRow = undefined;
    for (&earlier_rows, 0..) |*row, index| row.* = testAuipcRow(@intCast(index));
    for (&later_rows, 0..) |*row, index| row.* = testAuipcRow(@intCast(index + 16));
    try fillCommittedRows(std.testing.allocator, &earlier, .auipc, &earlier_rows);
    try fillCommittedRows(std.testing.allocator, &later, .auipc, &later_rows);

    const earlier_views: []const []const M31 = earlier.storage[0..earlier.len];
    const later_views: []const []const M31 = later.storage[0..later.len];
    var reordered = [_]relation_export.OpcodeShard{
        .{
            .ordinal = 0,
            .shard_count = 2,
            .n_real_rows = 16,
            .committed_columns = later_views,
            .main_columns_digest = undefined,
        },
        .{
            .ordinal = 1,
            .shard_count = 2,
            .n_real_rows = 16,
            .committed_columns = earlier_views,
            .main_columns_digest = undefined,
        },
    };
    for (&reordered) |*shard| {
        shard.main_columns_digest = relation_export.digestCommittedShard(.auipc, .auipc, shard.*);
    }
    try expectShardFailure(error.NonCanonicalExecutionOrder, &reordered);

    var duplicated = reordered;
    duplicated[0].committed_columns = earlier_views;
    duplicated[1].committed_columns = earlier_views;
    for (&duplicated) |*shard| {
        shard.main_columns_digest = relation_export.digestCommittedShard(.auipc, .auipc, shard.*);
    }
    try expectShardFailure(error.NonCanonicalExecutionOrder, &duplicated);
}

test "relation export: complete execution ledger is exact once" {
    var sequence = try relation_export.Sequence.initForExecution(std.testing.allocator, 3);
    defer sequence.deinit(std.testing.allocator);
    try sequence.observeExecutionRow(1);
    try sequence.observeExecutionRow(3);
    try std.testing.expectError(error.DuplicateExecutionRow, sequence.observeExecutionRow(1));
    try std.testing.expectError(error.ExecutionRowOutOfRange, sequence.observeExecutionRow(4));
    try std.testing.expectError(error.IncompleteExecutionRows, sequence.validateExecutionRows());
    try sequence.observeExecutionRow(2);
    try sequence.validateExecutionRows();
}

fn expectShardFailure(expected: relation_export.Error, shards: []const relation_export.OpcodeShard) !void {
    const zero_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    const native = claims.InteractionClaim.init(zero_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    var observer = relation_export.NullObserver{};
    try std.testing.expectError(
        expected,
        relation_export.exportOpcodeFamily(
            std.testing.allocator,
            .auipc,
            shards,
            &relations_mod.Relations.dummy(),
            &ledger,
            &sequence,
            &observer,
        ),
    );
}

test "relation export: absent components are explicit zero-claim records" {
    const zero_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    const native = claims.InteractionClaim.init(zero_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    for (0..relation_export.COMPONENT_COUNT) |index| {
        const evidence = try relation_export.exportAbsentComponent(
            @enumFromInt(index),
            &ledger,
            &sequence,
        );
        try std.testing.expect(evidence.absent);
        try std.testing.expectEqual(@as(u64, 0), evidence.all.entries);
        try std.testing.expect(evidence.native_claim.isZero());
    }
    const claim_evidence = try ledger.finish();
    const aggregate = try sequence.finish();
    try std.testing.expect(claim_evidence.total.isZero());
    try std.testing.expectEqual(@as(u64, 0), aggregate.all.entries);

    var nonzero_sums = zero_sums;
    nonzero_sums[0] = QM31.one();
    const invalid_native = claims.InteractionClaim.init(nonzero_sums, &.{});
    ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &invalid_native);
    sequence = relation_export.Sequence.init();
    try std.testing.expectError(
        error.ClaimMismatch,
        relation_export.exportAbsentComponent(.auipc, &ledger, &sequence),
    );
}

test "relation export: unbound proof identities fail closed" {
    const sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    const native = claims.InteractionClaim.init(sums, &.{});
    try std.testing.expectError(
        error.UnboundPreprocessedCommitment,
        relation_export.ClaimLedger.init(.{0} ** 32, .{1} ** 32, .{2} ** 32, &native),
    );
    try std.testing.expectError(
        error.UnboundMainCommitment,
        relation_export.ClaimLedger.init(.{3} ** 32, .{0} ** 32, .{2} ** 32, &native),
    );
    try std.testing.expectError(
        error.UnboundDiagnosticInteractionCommitment,
        relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{0} ** 32, &native),
    );
}
