const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../infra_trace.zig");
const counter_mod = @import("lookups/tables/counter.zig");
const table_interaction = @import("lookups/tables/interaction.zig");
const table_schema = @import("lookups/tables/schema.zig");
const merkle = @import("memory_commitment/merkle_node.zig");
const poseidon2 = @import("memory_commitment/poseidon2_air.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const relations_mod = @import("relation_challenges.zig");
const relation_export = @import("relation_export.zig");
const components = @import("relation_export_components.zig");
const claims = @import("transcript/claims.zig");

const RecordingObserver = struct {
    locations: [8]relation_export.Location = undefined,
    entries: [8]relation_export.RawEntry = undefined,
    len: usize = 0,

    pub fn onEntry(
        self: *RecordingObserver,
        location: relation_export.Location,
        raw: relation_export.RawEntry,
    ) !void {
        if (location.row != 0) return;
        if (self.len == self.entries.len) return error.TooManyEntries;
        self.locations[self.len] = location;
        self.entries[self.len] = raw;
        self.len += 1;
    }

    pub fn onShard(_: *RecordingObserver, _: relation_export.ShardEvidence) !void {}
};

fn advanceAbsent(
    count: usize,
    ledger: *relation_export.ClaimLedger,
    sequence: *relation_export.Sequence,
) !void {
    for (0..count) |index| {
        _ = try relation_export.exportAbsentComponent(@enumFromInt(index), ledger, sequence);
    }
}

fn programClaim(
    row: program_commitment.Row,
    relations: *const relations_mod.Relations,
) !QM31 {
    var result = QM31.zero();
    for (program_interaction.rowPairsFromRow(row, relations)) |pair| {
        result = result.add(try relation_export.pairTerm(pair));
    }
    return result;
}

fn entryListClaim(list: @import("lookups/entry.zig").List, relations: *const relations_mod.Relations) !QM31 {
    var result = QM31.zero();
    for (0..list.batchCount()) |batch| {
        result = result.add(try relation_export.pairTerm(try list.pair(batch, relations)));
    }
    return result;
}

fn secureMain(comptime N: usize, values: [N]M31) [N]QM31 {
    var result: [N]QM31 = undefined;
    for (values, &result) |value, *secure| secure.* = QM31.fromBase(value);
    return result;
}

test "relation component export binds exact program columns and native claim" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const row = program_commitment.Row{
        .addr = 0x1000,
        .values = .{ 0x13, 0, 0, 0 },
        .multiplicity = 1,
        .root = 77,
    };
    var columns = try program_commitment.generateMain(allocator, &.{row}, 4);
    defer columns.deinit(allocator);
    var views: [program_commitment.N_MAIN_COLUMNS][]const M31 = undefined;
    for (columns.values, &views) |column, *view| view.* = column;
    var shard = components.CommittedShard{
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = 1,
        .committed_columns = &views,
        .main_columns_digest = undefined,
    };
    shard.main_columns_digest = components.digestCommittedShard(.program, shard);

    var native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.program)] = try programClaim(row, &relations);
    const native = claims.InteractionClaim.init(native_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    try advanceAbsent(@intFromEnum(relation_export.Component.program), &ledger, &sequence);
    var observer = relation_export.NullObserver{};
    const evidence = try components.exportInfrastructure(
        allocator,
        .program,
        &.{shard},
        &relations,
        &ledger,
        &sequence,
        &observer,
    );
    try std.testing.expectEqual(@as(u64, 112), evidence.all.entries);
    try std.testing.expectEqual(@as(u64, 7), evidence.nonzero.entries);
    try std.testing.expect(evidence.computed_claim.eql(
        native_sums[@intFromEnum(relation_export.Component.program)],
    ));

    const original = columns.values[0][0];
    columns.values[0][0] = original.add(M31.one());
    var shadow_ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var shadow_sequence = relation_export.Sequence.init();
    try advanceAbsent(
        @intFromEnum(relation_export.Component.program),
        &shadow_ledger,
        &shadow_sequence,
    );
    try std.testing.expectError(
        error.MainColumnsDigestMismatch,
        components.exportInfrastructure(
            allocator,
            .program,
            &.{shard},
            &relations,
            &shadow_ledger,
            &shadow_sequence,
            &observer,
        ),
    );
}

test "relation component export requires the committed memory selector" {
    const allocator = std.testing.allocator;
    var storage: [8][]M31 = undefined;
    var initialized: usize = 0;
    defer for (storage[0..initialized]) |column| allocator.free(column);
    for (&storage) |*column| {
        column.* = try allocator.alloc(M31, 16);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    var views: [8][]const M31 = undefined;
    for (storage, &views) |column, *view| view.* = column;
    var shard = components.CommittedShard{
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = 1,
        .committed_columns = &views,
        .main_columns_digest = undefined,
    };
    shard.main_columns_digest = components.digestCommittedShard(.memory, shard);
    const native = claims.InteractionClaim.init(
        .{QM31.zero()} ** relation_export.COMPONENT_COUNT,
        &.{},
    );
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    try advanceAbsent(@intFromEnum(relation_export.Component.memory), &ledger, &sequence);
    var observer = relation_export.NullObserver{};
    try std.testing.expectError(
        error.MissingSelector,
        components.exportInfrastructure(
            allocator,
            .memory,
            &.{shard},
            &relations_mod.Relations.dummy(),
            &ledger,
            &sequence,
            &observer,
        ),
    );
}

test "relation component export preserves Rust Merkle and Poseidon declaration shapes" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const domain_size = 16;
    const placement = try infra.BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);

    const merkle_main = [merkle.N_MAIN_COLUMNS]M31{
        M31.one(),
        M31.fromU64(4),
        M31.fromU64(30),
        M31.fromU64(11),
        M31.fromU64(22),
        M31.fromU64(33),
        M31.one(),
        M31.one(),
        M31.one(),
        M31.fromU64(44),
    };
    var merkle_storage: [merkle.N_MAIN_COLUMNS][]M31 = undefined;
    var merkle_initialized: usize = 0;
    defer for (merkle_storage[0..merkle_initialized]) |column| allocator.free(column);
    for (&merkle_storage, merkle_main) |*column, value| {
        column.* = try allocator.alloc(M31, domain_size);
        @memset(column.*, M31.zero());
        column.*[placement.map(0)] = value;
        merkle_initialized += 1;
    }
    var merkle_views: [merkle.N_MAIN_COLUMNS][]const M31 = undefined;
    for (merkle_storage, &merkle_views) |column, *view| view.* = column;
    var merkle_shard = components.CommittedShard{
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = 1,
        .committed_columns = &merkle_views,
        .main_columns_digest = undefined,
    };
    merkle_shard.main_columns_digest = components.digestCommittedShard(.merkle, merkle_shard);
    const merkle_list = merkle.entries(secureMain(merkle.N_MAIN_COLUMNS, merkle_main));
    var native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.merkle)] = try entryListClaim(merkle_list, &relations);
    const merkle_native = claims.InteractionClaim.init(native_sums, &.{});
    var merkle_ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &merkle_native);
    var merkle_sequence = relation_export.Sequence.init();
    try advanceAbsent(@intFromEnum(relation_export.Component.merkle), &merkle_ledger, &merkle_sequence);
    var merkle_observer = RecordingObserver{};
    _ = try components.exportInfrastructure(
        allocator,
        .merkle,
        &.{merkle_shard},
        &relations,
        &merkle_ledger,
        &merkle_sequence,
        &merkle_observer,
    );
    try std.testing.expectEqual(@as(usize, 5), merkle_observer.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 4, 4, 4, 2, 1 },
        &.{
            merkle_observer.entries[0].arity,
            merkle_observer.entries[1].arity,
            merkle_observer.entries[2].arity,
            merkle_observer.entries[3].arity,
            merkle_observer.entries[4].arity,
        },
    );
    for (merkle_observer.locations[0..5], 0..) |location, declaration| {
        try std.testing.expectEqual(relation_export.Component.merkle, location.component);
        try std.testing.expectEqual(declaration, location.declaration);
    }
    try std.testing.expectEqual(@as(u32, 11), merkle_observer.entries[3].values[0].toU32());
    try std.testing.expectEqual(@as(u32, 22), merkle_observer.entries[3].values[1].toU32());
    try std.testing.expectEqual(@as(u32, 33), merkle_observer.entries[4].values[0].toU32());

    const call = poseidon2.Call.narrow(11, 22);
    const poseidon_main = poseidon2.fill(call);
    var poseidon_storage: [poseidon2.N_MAIN_COLUMNS][]M31 = undefined;
    var poseidon_initialized: usize = 0;
    defer for (poseidon_storage[0..poseidon_initialized]) |column| allocator.free(column);
    for (&poseidon_storage, poseidon_main) |*column, value| {
        column.* = try allocator.alloc(M31, domain_size);
        @memset(column.*, M31.zero());
        column.*[placement.map(0)] = value;
        poseidon_initialized += 1;
    }
    var poseidon_views: [poseidon2.N_MAIN_COLUMNS][]const M31 = undefined;
    for (poseidon_storage, &poseidon_views) |column, *view| view.* = column;
    var poseidon_shard = components.CommittedShard{
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = 1,
        .committed_columns = &poseidon_views,
        .main_columns_digest = undefined,
    };
    poseidon_shard.main_columns_digest = components.digestCommittedShard(.poseidon2, poseidon_shard);
    const poseidon_list = poseidon2.entries(secureMain(poseidon2.N_MAIN_COLUMNS, poseidon_main));
    native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.poseidon2)] = try entryListClaim(poseidon_list, &relations);
    const poseidon_native = claims.InteractionClaim.init(native_sums, &.{});
    var poseidon_ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &poseidon_native);
    var poseidon_sequence = relation_export.Sequence.init();
    try advanceAbsent(@intFromEnum(relation_export.Component.poseidon2), &poseidon_ledger, &poseidon_sequence);
    var poseidon_observer = RecordingObserver{};
    _ = try components.exportInfrastructure(
        allocator,
        .poseidon2,
        &.{poseidon_shard},
        &relations,
        &poseidon_ledger,
        &poseidon_sequence,
        &poseidon_observer,
    );
    try std.testing.expectEqual(@as(usize, 4), poseidon_observer.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 16, 1, 8, 32 },
        &.{
            poseidon_observer.entries[0].arity,
            poseidon_observer.entries[1].arity,
            poseidon_observer.entries[2].arity,
            poseidon_observer.entries[3].arity,
        },
    );
    for (poseidon_observer.locations[0..4], 0..) |location, declaration| {
        try std.testing.expectEqual(relation_export.Component.poseidon2, location.component);
        try std.testing.expectEqual(declaration, location.declaration);
    }
    try std.testing.expectEqual(@as(u32, 11), poseidon_observer.entries[0].values[0].toU32());
    try std.testing.expectEqual(@as(u32, 22), poseidon_observer.entries[0].values[1].toU32());
    try std.testing.expectEqual(
        poseidon2.output(poseidon_main)[0].toU32(),
        poseidon_observer.entries[1].values[0].toU32(),
    );
}

test "relation component export binds lookup main and preprocessed buffers" {
    const allocator = std.testing.allocator;
    const kind = table_schema.Kind.range_check_m31;
    const relations = relations_mod.Relations.dummy();
    var counter = try counter_mod.Counter.init(allocator, kind);
    defer counter.deinit(allocator);
    try counter.registerRaw(
        QM31.one(),
        &.{ QM31.fromBase(M31.fromU64(7)), QM31.fromBase(M31.fromU64(3)) },
    );
    const multiplicity = try counter.committedColumn(allocator);
    defer allocator.free(multiplicity);
    var tuples = try table_schema.generatePreprocessed(allocator, kind);
    defer tuples.deinit(allocator);
    var tuple_views: [table_schema.MAX_ARITY][]const M31 = undefined;
    for (tuples.columns[0..tuples.n_columns], tuple_views[0..tuples.n_columns]) |column, *view| {
        view.* = column;
    }
    var source = components.LookupTableSource{
        .kind = kind,
        .multiplicity_column = multiplicity,
        .tuple_columns = tuple_views[0..tuples.n_columns],
        .main_columns_digest = undefined,
        .preprocessed_columns_digest = undefined,
    };
    source.main_columns_digest = components.digestLookupMain(source);
    source.preprocessed_columns_digest = components.digestLookupPreprocessed(source);
    var interaction = try table_interaction.generate(allocator, &counter, &relations);
    defer interaction.deinit(allocator);
    var native_sums = [_]QM31{QM31.zero()} ** relation_export.COMPONENT_COUNT;
    native_sums[@intFromEnum(relation_export.Component.range_check_m31)] = interaction.claim;
    const native = claims.InteractionClaim.init(native_sums, &.{});
    var ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var sequence = relation_export.Sequence.init();
    try advanceAbsent(@intFromEnum(relation_export.Component.range_check_m31), &ledger, &sequence);
    var observer = relation_export.NullObserver{};
    const evidence = try components.exportLookupTable(
        allocator,
        source,
        &relations,
        &ledger,
        &sequence,
        &observer,
    );
    try std.testing.expectEqual(@as(u64, table_schema.size(kind)), evidence.all.entries);
    try std.testing.expectEqual(@as(u64, 1), evidence.nonzero.entries);

    tuples.columns[0][0] = tuples.columns[0][0].add(M31.one());
    var shadow_ledger = try relation_export.ClaimLedger.init(.{3} ** 32, .{1} ** 32, .{2} ** 32, &native);
    var shadow_sequence = relation_export.Sequence.init();
    try advanceAbsent(
        @intFromEnum(relation_export.Component.range_check_m31),
        &shadow_ledger,
        &shadow_sequence,
    );
    try std.testing.expectError(
        error.TablePreprocessedDigestMismatch,
        components.exportLookupTable(
            allocator,
            source,
            &relations,
            &shadow_ledger,
            &shadow_sequence,
            &observer,
        ),
    );
}
