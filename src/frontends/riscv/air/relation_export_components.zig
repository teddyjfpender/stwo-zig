//! Production-buffer relation evidence for non-opcode RISC-V AIR components.
//!
//! These adapters scan the exact bit-reversed columns handed to Tree 1 (and,
//! for lookup tables, the exact tuple columns handed to Tree 0). They never
//! accept runner rows or regenerate table tuples as evidence.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const blake2 = @import("stwo_core").vcs.blake2_hash;
const infra = @import("../infra_trace.zig");
const clock = @import("clock_update_interaction.zig");
const entry = @import("lookups/entry.zig");
const table_interaction = @import("lookups/tables/interaction.zig");
const table_schema = @import("lookups/tables/schema.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");
const merkle = @import("memory_commitment/merkle_node.zig");
const poseidon2 = @import("memory_commitment/poseidon2_air.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const relation_export = @import("relation_export.zig");
const relations_mod = @import("relation_challenges.zig");

const component_column_domain = "stwo-zig/riscv/committed-component-shard/v1\x00";
const selector_column_domain = "stwo-zig/riscv/preprocessed-selector/v1\x00";
const component_manifest_domain = "stwo-zig/riscv/component-shard-manifest/v1\x00";
const table_main_domain = "stwo-zig/riscv/lookup-table-main/v1\x00";
const table_preprocessed_domain = "stwo-zig/riscv/lookup-table-preprocessed/v1\x00";
const table_manifest_domain = "stwo-zig/riscv/lookup-table-manifest/v1\x00";

pub const Error = error{
    InvalidColumnCount,
    InvalidColumnLength,
    InvalidDomainSize,
    InvalidShardCount,
    InvalidShardGeometry,
    ShardOutOfOrder,
    MainColumnsDigestMismatch,
    MissingSelector,
    UnexpectedSelector,
    SelectorDigestMismatch,
    InvalidSelector,
    InactiveRealRow,
    NonZeroPadding,
    TableMainDigestMismatch,
    TablePreprocessedDigestMismatch,
};

pub const InfrastructureKind = enum {
    program,
    memory,
    merkle,
    poseidon2,
    clock_update,
};

pub const CommittedShard = struct {
    ordinal: u32,
    shard_count: u32,
    n_real_rows: usize,
    committed_columns: []const []const M31,
    main_columns_digest: relation_export.Digest,
    selector_column: ?[]const M31 = null,
    selector_digest: ?relation_export.Digest = null,
};

pub const LookupTableSource = struct {
    kind: table_schema.Kind,
    multiplicity_column: []const M31,
    tuple_columns: []const []const M31,
    main_columns_digest: relation_export.Digest,
    preprocessed_columns_digest: relation_export.Digest,
};

pub fn exportInfrastructure(
    allocator: std.mem.Allocator,
    kind: InfrastructureKind,
    shards: []const CommittedShard,
    relations: *const relations_mod.Relations,
    ledger: *relation_export.ClaimLedger,
    sequence: *relation_export.Sequence,
    observer: anytype,
) !relation_export.ComponentEvidence {
    return switch (kind) {
        .program => exportTyped(ProgramAdapter, allocator, shards, relations, ledger, sequence, observer),
        .memory => exportTyped(MemoryAdapter, allocator, shards, relations, ledger, sequence, observer),
        .merkle => exportTyped(MerkleAdapter, allocator, shards, relations, ledger, sequence, observer),
        .poseidon2 => exportTyped(PoseidonAdapter, allocator, shards, relations, ledger, sequence, observer),
        .clock_update => exportTyped(ClockAdapter, allocator, shards, relations, ledger, sequence, observer),
    };
}

fn exportTyped(
    comptime Adapter: type,
    allocator: std.mem.Allocator,
    shards: []const CommittedShard,
    relations: *const relations_mod.Relations,
    ledger: *relation_export.ClaimLedger,
    sequence: *relation_export.Sequence,
    observer: anytype,
) !relation_export.ComponentEvidence {
    if (shards.len == 0 or shards.len > std.math.maxInt(u32))
        return error.InvalidShardCount;
    try sequence.begin(Adapter.component);
    errdefer sequence.poisoned = true;

    var component_stream = relation_export.ComponentStreams.init();
    var domain_sums = [_]QM31{QM31.zero()} ** relation_export.DOMAIN_COUNT;
    var computed_claim = QM31.zero();
    var manifest = blake2.Blake2sHasher.init();
    manifest.update(component_manifest_domain);
    updateU32(&manifest, @intFromEnum(Adapter.component));
    updateU32(&manifest, @intCast(shards.len));

    for (shards, 0..) |shard, shard_index| {
        const size = try validateShard(Adapter, shard, shard_index, shards.len);
        const main_digest = digestCommittedShard(Adapter.component, shard);
        if (!std.mem.eql(u8, &main_digest, &shard.main_columns_digest))
            return error.MainColumnsDigestMismatch;
        const selector_digest = try validateSelector(Adapter, shard, size);
        manifest.update(&main_digest);
        if (selector_digest) |digest| manifest.update(&digest);

        const placement = try infra.BitReversalTable.init(
            allocator,
            @intCast(std.math.log2_int(usize, size)),
        );
        defer placement.deinit(allocator);
        var main: [Adapter.n_columns]QM31 = undefined;
        var shard_stream = relation_export.ComponentStreams.init();
        for (0..size) |row| {
            const committed_row = placement.map(row);
            for (shard.committed_columns, &main) |column, *value| {
                value.* = QM31.fromBase(column[committed_row]);
            }
            const expected_active = if (row < shard.n_real_rows) QM31.one() else QM31.zero();
            const active = if (shard.selector_column) |selector|
                QM31.fromBase(selector[committed_row])
            else
                expected_active;
            if (!active.eql(expected_active)) return error.InvalidSelector;
            const list = try Adapter.entries(&main, active);
            var row_has_nonzero = false;
            for (list.entries[0..list.len], 0..) |relation_entry, declaration| {
                const raw = try evidenceRawEntry(Adapter, relation_entry, declaration);
                if (row >= shard.n_real_rows and !raw.numerator.isZero())
                    return error.NonZeroPadding;
                row_has_nonzero = row_has_nonzero or !raw.numerator.isZero();
                const term = try relation_export.entryTerm(relation_entry, relations);
                shard_stream.append(raw);
                component_stream.append(raw);
                const domain = @intFromEnum(raw.domain);
                domain_sums[domain] = domain_sums[domain].add(term);
                sequence.append(raw, term);
                try observer.onEntry(.{
                    .component = Adapter.component,
                    .shard = shard.ordinal,
                    .row = row,
                    .declaration = declaration,
                }, raw);
            }
            if (row < shard.n_real_rows and Adapter.require_active and !row_has_nonzero)
                return error.InactiveRealRow;
            for (0..list.batchCount()) |batch| {
                computed_claim = computed_claim.add(try relation_export.pairTerm(try list.pair(batch, relations)));
            }
        }
        const streams = shard_stream.finishStreams();
        try observer.onShard(.{
            .component = Adapter.component,
            .ordinal = shard.ordinal,
            .shard_count = shard.shard_count,
            .n_real_rows = shard.n_real_rows,
            .domain_size = size,
            .main_columns_digest = main_digest,
            .all = streams.all,
            .zero = streams.zero,
            .nonzero = streams.nonzero,
            .domains = streams.domains,
            .domain_zero = streams.domain_zero,
            .domain_nonzero = streams.domain_nonzero,
        });
    }

    var unbatched_total = QM31.zero();
    for (domain_sums) |sum| unbatched_total = unbatched_total.add(sum);
    if (!unbatched_total.eql(computed_claim)) return error.ClaimMismatch;
    const native_claim = try ledger.check(Adapter.component, computed_claim);
    sequence.end();
    return component_stream.finish(
        Adapter.component,
        domain_sums,
        computed_claim,
        native_claim,
        @intCast(shards.len),
        manifest.finalize(),
        false,
    );
}

pub fn exportLookupTable(
    allocator: std.mem.Allocator,
    source: LookupTableSource,
    relations: *const relations_mod.Relations,
    ledger: *relation_export.ClaimLedger,
    sequence: *relation_export.Sequence,
    observer: anytype,
) !relation_export.ComponentEvidence {
    const component = componentForTable(source.kind);
    const size = table_schema.size(source.kind);
    if (source.multiplicity_column.len != size) return error.InvalidColumnLength;
    if (source.tuple_columns.len != table_schema.arity(source.kind))
        return error.InvalidColumnCount;
    for (source.tuple_columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
    const main_digest = digestLookupMain(source);
    if (!std.mem.eql(u8, &main_digest, &source.main_columns_digest))
        return error.TableMainDigestMismatch;
    const preprocessed_digest = digestLookupPreprocessed(source);
    if (!std.mem.eql(u8, &preprocessed_digest, &source.preprocessed_columns_digest))
        return error.TablePreprocessedDigestMismatch;
    try sequence.begin(component);
    errdefer sequence.poisoned = true;

    const placement = try infra.BitReversalTable.init(allocator, table_schema.logSize(source.kind));
    defer placement.deinit(allocator);
    var stream = relation_export.ComponentStreams.init();
    var shard_stream = relation_export.ComponentStreams.init();
    var domain_sums = [_]QM31{QM31.zero()} ** relation_export.DOMAIN_COUNT;
    var computed_claim = QM31.zero();
    for (0..size) |row| {
        const committed_row = placement.map(row);
        var tuple = table_schema.Tuple{ .len = source.tuple_columns.len };
        for (source.tuple_columns, tuple.values[0..tuple.len]) |column, *value| {
            value.* = column[committed_row];
        }
        try table_schema.validateRow(source.kind, row, tuple.slice());
        const relation_entry = table_interaction.tableEntry(
            source.kind,
            tuple,
            source.multiplicity_column[committed_row],
        );
        const raw = try relation_export.rawEntry(relation_entry);
        const term = try relation_export.entryTerm(relation_entry, relations);
        stream.append(raw);
        shard_stream.append(raw);
        const domain = @intFromEnum(raw.domain);
        domain_sums[domain] = domain_sums[domain].add(term);
        computed_claim = computed_claim.add(term);
        sequence.append(raw, term);
        try observer.onEntry(.{
            .component = component,
            .shard = 0,
            .row = row,
            .declaration = 0,
        }, raw);
    }
    const native_claim = try ledger.check(component, computed_claim);
    sequence.end();
    var manifest = blake2.Blake2sHasher.init();
    manifest.update(table_manifest_domain);
    manifest.update(&main_digest);
    manifest.update(&preprocessed_digest);
    const streams = shard_stream.finishStreams();
    try observer.onShard(.{
        .component = component,
        .ordinal = 0,
        .shard_count = 1,
        .n_real_rows = size,
        .domain_size = size,
        .main_columns_digest = main_digest,
        .all = streams.all,
        .zero = streams.zero,
        .nonzero = streams.nonzero,
        .domains = streams.domains,
        .domain_zero = streams.domain_zero,
        .domain_nonzero = streams.domain_nonzero,
    });
    return stream.finish(
        component,
        domain_sums,
        computed_claim,
        native_claim,
        1,
        manifest.finalize(),
        false,
    );
}

pub fn digestCommittedShard(component: relation_export.Component, shard: CommittedShard) relation_export.Digest {
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(component_column_domain);
    updateU32(&hasher, @intFromEnum(component));
    updateU32(&hasher, shard.ordinal);
    updateU32(&hasher, shard.shard_count);
    updateU64(&hasher, shard.n_real_rows);
    hashColumns(&hasher, shard.committed_columns);
    return hasher.finalize();
}

pub fn digestSelector(component: relation_export.Component, shard: CommittedShard) ?relation_export.Digest {
    const selector = shard.selector_column orelse return null;
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(selector_column_domain);
    updateU32(&hasher, @intFromEnum(component));
    updateU32(&hasher, shard.ordinal);
    updateU64(&hasher, selector.len);
    hashColumn(&hasher, selector);
    return hasher.finalize();
}

pub fn digestLookupMain(source: LookupTableSource) relation_export.Digest {
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(table_main_domain);
    updateU32(&hasher, @intFromEnum(source.kind));
    hashColumn(&hasher, source.multiplicity_column);
    return hasher.finalize();
}

pub fn digestLookupPreprocessed(source: LookupTableSource) relation_export.Digest {
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(table_preprocessed_domain);
    updateU32(&hasher, @intFromEnum(source.kind));
    hashColumns(&hasher, source.tuple_columns);
    return hasher.finalize();
}

fn validateShard(
    comptime Adapter: type,
    shard: CommittedShard,
    index: usize,
    count: usize,
) Error!usize {
    if (shard.shard_count != @as(u32, @intCast(count))) return error.InvalidShardCount;
    if (shard.ordinal != @as(u32, @intCast(index))) return error.ShardOutOfOrder;
    if (shard.committed_columns.len != Adapter.n_columns) return error.InvalidColumnCount;
    const size = shard.committed_columns[0].len;
    if (size < 2 or !std.math.isPowerOfTwo(size)) return error.InvalidDomainSize;
    for (shard.committed_columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
    if (shard.n_real_rows > size) return error.InvalidShardGeometry;
    if (count > 1 and shard.n_real_rows == 0) return error.InvalidShardGeometry;
    if (index + 1 < count and shard.n_real_rows != size)
        return error.InvalidShardGeometry;
    return size;
}

fn validateSelector(comptime Adapter: type, shard: CommittedShard, size: usize) Error!?relation_export.Digest {
    if (Adapter.requires_selector and shard.selector_column == null) return error.MissingSelector;
    if ((shard.selector_column == null) != (shard.selector_digest == null))
        return error.UnexpectedSelector;
    const selector = shard.selector_column orelse return null;
    if (selector.len != size) return error.InvalidColumnLength;
    const actual = digestSelector(Adapter.component, shard).?;
    if (!std.mem.eql(u8, &actual, &shard.selector_digest.?))
        return error.SelectorDigestMismatch;
    return actual;
}

const ProgramAdapter = struct {
    const component = relation_export.Component.program;
    const n_columns = program_commitment.N_MAIN_COLUMNS;
    const requires_selector = false;
    const require_active = true;
    fn entries(main: []const QM31, _: QM31) !entry.List {
        return program_interaction.entries(main[0..n_columns].*);
    }
};

const MemoryAdapter = struct {
    const component = relation_export.Component.memory;
    const n_columns = 8;
    const requires_selector = true;
    const require_active = true;
    fn entries(main: []const QM31, active: QM31) !entry.List {
        return memory_interaction.entries(main[0..n_columns].*, active);
    }
};

const MerkleAdapter = struct {
    const component = relation_export.Component.merkle;
    const n_columns = merkle.N_MAIN_COLUMNS;
    const requires_selector = false;
    const require_active = true;
    fn entries(main: []const QM31, _: QM31) !entry.List {
        return merkle.entries(main[0..n_columns].*);
    }

    fn evidenceArity(declaration: usize) u8 {
        return switch (declaration) {
            0...2 => 4,
            // Atomic `[left, right, 0 x 14 || current]` prefix of the 32-lane tuple.
            3 => 17,
            // Retained zero-multiplicity `[left, right]` entry.
            4 => 2,
            else => unreachable,
        };
    }
};

const PoseidonAdapter = struct {
    const component = relation_export.Component.poseidon2;
    const n_columns = poseidon2.N_MAIN_COLUMNS;
    const requires_selector = false;
    const require_active = true;
    fn entries(main: []const QM31, _: QM31) !entry.List {
        return poseidon2.entries(main[0..n_columns].*);
    }

    fn evidenceArity(declaration: usize) u8 {
        return switch (declaration) {
            0 => 16,
            // Narrow mode: `[input16 || out0]` prefix of the 32-lane tuple.
            1 => 17,
            2 => 8,
            3 => 32,
            else => unreachable,
        };
    }
};

const ClockAdapter = struct {
    const component = relation_export.Component.clock_update;
    const n_columns = clock.N_MAIN_COLUMNS;
    const requires_selector = false;
    const require_active = true;
    fn entries(main: []const QM31, _: QM31) !entry.List {
        return clock.orderedEntries(try clock.Row.fromMain(main));
    }
};

/// Rust's production relation visitor hashes the value slice supplied by each
/// declaration, before `Relation::combine` implicitly extends it with zeros.
/// Keep the full relation arity for arithmetic and project only the diagnostic
/// record to that declaration shape.
fn evidenceRawEntry(
    comptime Adapter: type,
    relation_entry: entry.Entry,
    declaration: usize,
) !relation_export.RawEntry {
    var raw = try relation_export.rawEntry(relation_entry);
    if (comptime @hasDecl(Adapter, "evidenceArity")) {
        const arity = Adapter.evidenceArity(declaration);
        std.debug.assert(arity <= raw.arity);
        raw.arity = arity;
    }
    return raw;
}

fn componentForTable(kind: table_schema.Kind) relation_export.Component {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn hashColumns(hasher: *blake2.Blake2sHasher, columns: []const []const M31) void {
    updateU32(hasher, @intCast(columns.len));
    updateU64(hasher, if (columns.len == 0) 0 else columns[0].len);
    for (columns) |column| hashColumn(hasher, column);
}

fn hashColumn(hasher: *blake2.Blake2sHasher, column: []const M31) void {
    updateU64(hasher, column.len);
    for (column) |value| updateU32(hasher, value.toU32());
}

fn updateU32(hasher: *blake2.Blake2sHasher, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hasher.update(&encoded);
}

fn updateU64(hasher: *blake2.Blake2sHasher, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hasher.update(&encoded);
}
