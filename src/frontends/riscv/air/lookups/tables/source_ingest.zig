//! Exact opcode-source ingestion for the six preprocessed lookup tables.
//!
//! Inputs are the padded, bit-reversed M31 columns committed by the production
//! main trace. The adapter restores logical row order, reconstructs the pinned
//! relation-entry list, and validates and registers each row in the same pass.
//! Caller-bound sources additionally authenticate their supplied shard digest;
//! production-generated sources derive the identical manifest directly.

const std = @import("std");
const work_pool = @import("stwo_prover_engine").work_pool;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const blake2 = @import("stwo_core").vcs.blake2_hash;
const infra = @import("../../../infra_trace.zig");
const trace = @import("../../../runner/trace.zig");
const entry = @import("../entry.zig");
const opcode_entries = @import("../opcode_entries.zig");
const counter = @import("counter.zig");
const schema = @import("schema.zig");

pub const Digest = blake2.Blake2sHash;

const shard_digest_domain = "stwo-zig/riscv/table-source-shard/v1\x00";
const manifest_digest_domain = "stwo-zig/riscv/table-source-manifest/v1\x00";

pub const Error = counter.Error || error{
    DuplicateFamily,
    FamilyOutOfOrder,
    InvalidShardCount,
    ShardOutOfOrder,
    InvalidColumnCount,
    InvalidColumnLength,
    InvalidDomainSize,
    InvalidShardGeometry,
    CommittedDigestMismatch,
    InvalidCommittedRow,
    InactiveRealRow,
    NonZeroPadding,
};

pub const Shard = struct {
    ordinal: u32,
    shard_count: u32,
    n_real_rows: usize,
    committed_columns: []const []const M31,
    committed_digest: Digest,
};

pub const FamilySource = struct {
    family: trace.OpcodeFamily,
    shards: []const Shard,
};

pub const Result = struct {
    counters: counter.Set,
    family_count: u32,
    shard_count: u32,
    real_rows: u64,
    padded_rows: u64,
    source_entries: [schema.KIND_COUNT]u64,
    manifest_digest: Digest,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        self.counters.deinit(allocator);
        self.* = undefined;
    }

    pub fn signedTotals(self: *const Result) [schema.KIND_COUNT]M31 {
        var totals: [schema.KIND_COUNT]M31 = undefined;
        for (&self.counters.counters, &totals) |*table, *total| {
            total.* = table.signedTotal();
        }
        return totals;
    }
};

const Validation = struct {
    family_count: u32,
    shard_count: u32,
    real_rows: u64,
    padded_rows: u64,
    source_entries: [schema.KIND_COUNT]u64,
    manifest_digest: Digest,
};

/// What to do with an activated request whose tuple has no row in its table.
///
/// `reject` is the only correct production policy: the sources are generated from a
/// validated witness, so an unrepresentable request is a prover bug and aborting names
/// it. `drop` exists for the committed-forgery harness, which must model the adversary
/// that builds its multiplicity column by hand. Such a prover cannot add multiplicity to
/// a table row that does not exist, so it omits the request, its opcode-side fraction has
/// nothing to cancel against, and the global LogUp sum is non-zero at verification.
/// Aborting ingestion instead would replace that verdict with a prover error and leave
/// `RejectionStage.verification` unreachable for every lookup-guarded forgery.
pub const UnrepresentableRequest = enum { reject, drop };

pub const Options = struct {
    unrepresentable: UnrepresentableRequest = .reject,
};

/// Validates caller-supplied shard digests while registering each validated row
/// exactly once. Partially registered counters are destroyed on every error and
/// can therefore never escape to the caller.
pub fn ingest(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
) !Result {
    return ingestImpl(allocator, sources, options, .validate);
}

/// Production opcode columns and their shard descriptors are assembled in one
/// scope, so there is no independent digest to authenticate against. Derive the
/// bound manifest directly instead of hashing every multi-gigabyte source once
/// to fill `committed_digest` and immediately hashing it again to compare.
pub fn ingestGenerated(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
) !Result {
    if (generatedPaddedRows(sources) >= generated_parallel_row_threshold) {
        if (work_pool.getGlobalPool()) |pool| {
            return ingestGeneratedParallel(allocator, sources, options, pool);
        }
    }
    return ingestImpl(allocator, sources, options, .derive);
}

const generated_parallel_row_threshold: usize = 1 << 18;
// A complete dense counter set is about 11 MiB. Eight private sets keep the
// parallel hot loop synchronization-free while bounding extra scratch below
// 100 MiB even on hosts that expose many more pool lanes.
const max_generated_ingest_workers: usize = 8;

fn generatedPaddedRows(sources: []const FamilySource) usize {
    var rows: usize = 0;
    for (sources) |source| {
        for (source.shards) |shard| {
            if (shard.committed_columns.len == 0) return 0;
            rows = std.math.add(
                usize,
                rows,
                shard.committed_columns[0].len,
            ) catch return std.math.maxInt(usize);
        }
    }
    return rows;
}

const GeneratedShardWork = struct {
    family: trace.OpcodeFamily,
    shard: Shard,
    digest: Digest = undefined,
    counts: [schema.KIND_COUNT]u64 = .{0} ** schema.KIND_COUNT,
};

const GeneratedWorker = struct {
    allocator: std.mem.Allocator,
    work: []GeneratedShardWork,
    counters: *counter.Set,
    options: Options,
    index: usize,
    stride: usize,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        var work_index = self.index;
        while (work_index < self.work.len) : (work_index += self.stride) {
            const item = &self.work[work_index];
            item.digest = digestShard(item.family, item.shard);
            item.counts = scanShard(
                self.allocator,
                item.family,
                item.shard,
                self.counters,
                self.options,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    }
};

/// Generated shards are independent until their signed table multiplicities
/// are added. Each worker therefore scans disjoint row-major shards into a
/// private dense counter set, avoiding synchronization in the hot row loop;
/// the bounded sets are merged afterwards in canonical table-row order.
fn ingestGeneratedParallel(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
    pool: *work_pool.WorkPool,
) !Result {
    var work_count: usize = 0;
    for (sources) |source| {
        work_count = std.math.add(usize, work_count, source.shards.len) catch
            return error.InvalidShardCount;
    }
    if (work_count < 2) return ingestImpl(allocator, sources, options, .derive);

    const work = try allocator.alloc(GeneratedShardWork, work_count);
    defer allocator.free(work);
    const geometry = try prepareGeneratedWork(sources, work);

    const worker_count = @min(
        @min(pool.workerCount(), max_generated_ingest_workers),
        work.len,
    );
    if (worker_count < 2) return ingestImpl(allocator, sources, options, .derive);

    const counter_sets = try allocator.alloc(counter.Set, worker_count);
    defer allocator.free(counter_sets);
    var initialized_sets: usize = 0;
    var sets_owned = true;
    defer if (sets_owned) {
        for (counter_sets[0..initialized_sets]) |*set| set.deinit(allocator);
    };
    for (counter_sets) |*set| {
        set.* = try counter.Set.init(allocator);
        initialized_sets += 1;
    }

    const workers = try allocator.alloc(GeneratedWorker, worker_count);
    defer allocator.free(workers);
    for (workers, counter_sets, 0..) |*worker, *set, index| {
        worker.* = .{
            .allocator = allocator,
            .work = work,
            .counters = set,
            .options = options,
            .index = index,
            .stride = worker_count,
        };
    }
    var wait_group = std.Thread.WaitGroup{};
    for (workers[1..]) |*worker| {
        pool.spawnWg(&wait_group, GeneratedWorker.run, .{worker});
    }
    GeneratedWorker.run(&workers[0]);
    wait_group.wait();
    for (workers) |worker| if (worker.err) |err| return err;

    for (counter_sets[1..]) |*set| {
        mergeCounterSets(&counter_sets[0], set);
        set.deinit(allocator);
    }
    const counters = counter_sets[0];
    sets_owned = false;

    var validation = geometry;
    var manifest = blake2.Blake2sHasher.init();
    manifest.update(manifest_digest_domain);
    updateU32(&manifest, @intCast(sources.len));
    var work_index: usize = 0;
    for (sources) |source| {
        updateU32(&manifest, @intFromEnum(source.family));
        updateU32(&manifest, @intCast(source.shards.len));
        for (source.shards) |_| {
            const item = work[work_index];
            for (&validation.source_entries, item.counts) |*total, count| {
                total.* += count;
            }
            manifest.update(&item.digest);
            work_index += 1;
        }
    }
    std.debug.assert(work_index == work.len);
    validation.manifest_digest = manifest.finalize();
    return .{
        .counters = counters,
        .family_count = validation.family_count,
        .shard_count = validation.shard_count,
        .real_rows = validation.real_rows,
        .padded_rows = validation.padded_rows,
        .source_entries = validation.source_entries,
        .manifest_digest = validation.manifest_digest,
    };
}

fn prepareGeneratedWork(
    sources: []const FamilySource,
    work: []GeneratedShardWork,
) !Validation {
    var seen = [_]bool{false} ** trace.N_FAMILIES;
    var previous_family: ?usize = null;
    var validation = Validation{
        .family_count = 0,
        .shard_count = 0,
        .real_rows = 0,
        .padded_rows = 0,
        .source_entries = .{0} ** schema.KIND_COUNT,
        .manifest_digest = undefined,
    };
    var work_index: usize = 0;
    for (sources) |source| {
        const family_index = @intFromEnum(source.family);
        if (seen[family_index]) return error.DuplicateFamily;
        if (previous_family) |previous| {
            if (family_index <= previous) return error.FamilyOutOfOrder;
        }
        seen[family_index] = true;
        previous_family = family_index;
        if (source.shards.len == 0 or source.shards.len > std.math.maxInt(u32))
            return error.InvalidShardCount;
        validation.family_count += 1;
        for (source.shards, 0..) |shard, shard_index| {
            try validateShardShape(source.family, shard, shard_index, source.shards.len);
            work[work_index] = .{ .family = source.family, .shard = shard };
            work_index += 1;
            validation.shard_count += 1;
            validation.real_rows += @intCast(shard.n_real_rows);
            validation.padded_rows += @intCast(
                shard.committed_columns[0].len - shard.n_real_rows,
            );
        }
    }
    if (work_index != work.len) return error.InvalidShardCount;
    return validation;
}

fn mergeCounterSets(destination: *counter.Set, source: *const counter.Set) void {
    for (&destination.counters, &source.counters) |*dst, *src| {
        for (dst.values, src.values) |*value, addend| {
            value.* = value.add(addend);
        }
    }
}

const DigestPolicy = enum { validate, derive };

fn ingestImpl(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
    digest_policy: DigestPolicy,
) !Result {
    var counters = try counter.Set.init(allocator);
    errdefer counters.deinit(allocator);
    const validation = try validateSources(
        allocator,
        sources,
        options,
        digest_policy,
        &counters,
    );
    return .{
        .counters = counters,
        .family_count = validation.family_count,
        .shard_count = validation.shard_count,
        .real_rows = validation.real_rows,
        .padded_rows = validation.padded_rows,
        .source_entries = validation.source_entries,
        .manifest_digest = validation.manifest_digest,
    };
}

pub fn digestShard(family: trace.OpcodeFamily, shard: Shard) Digest {
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(shard_digest_domain);
    updateU32(&hasher, @intFromEnum(family));
    updateU32(&hasher, shard.ordinal);
    updateU32(&hasher, shard.shard_count);
    updateU64(&hasher, shard.n_real_rows);
    updateU32(&hasher, @intCast(shard.committed_columns.len));
    updateU64(
        &hasher,
        if (shard.committed_columns.len == 0) 0 else shard.committed_columns[0].len,
    );
    for (shard.committed_columns) |column| {
        for (column) |value| updateU32(&hasher, value.toU32());
    }
    return hasher.finalize();
}

fn validateSources(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
    digest_policy: DigestPolicy,
    counters: *counter.Set,
) !Validation {
    var seen = [_]bool{false} ** trace.N_FAMILIES;
    var previous_family: ?usize = null;
    var family_count: u32 = 0;
    var shard_count: u32 = 0;
    var real_rows: u64 = 0;
    var padded_rows: u64 = 0;
    var source_entries = [_]u64{0} ** schema.KIND_COUNT;
    var manifest = blake2.Blake2sHasher.init();
    manifest.update(manifest_digest_domain);
    updateU32(&manifest, @intCast(sources.len));

    for (sources) |source| {
        const family_index = @intFromEnum(source.family);
        if (seen[family_index]) return error.DuplicateFamily;
        if (previous_family) |previous| {
            if (family_index <= previous) return error.FamilyOutOfOrder;
        }
        seen[family_index] = true;
        previous_family = family_index;
        if (source.shards.len == 0 or source.shards.len > std.math.maxInt(u32))
            return error.InvalidShardCount;
        updateU32(&manifest, @intCast(family_index));
        updateU32(&manifest, @intCast(source.shards.len));
        family_count += 1;

        for (source.shards, 0..) |shard, shard_index| {
            try validateShardShape(source.family, shard, shard_index, source.shards.len);
            const actual_digest = digestShard(source.family, shard);
            if (digest_policy == .validate and
                !std.mem.eql(u8, &actual_digest, &shard.committed_digest))
                return error.CommittedDigestMismatch;
            const counts = try scanShard(
                allocator,
                source.family,
                shard,
                counters,
                options,
            );
            for (&source_entries, counts) |*total, count| total.* += count;
            shard_count += 1;
            real_rows += @intCast(shard.n_real_rows);
            padded_rows += @intCast(shard.committed_columns[0].len - shard.n_real_rows);
            manifest.update(&actual_digest);
        }
    }
    return .{
        .family_count = family_count,
        .shard_count = shard_count,
        .real_rows = real_rows,
        .padded_rows = padded_rows,
        .source_entries = source_entries,
        .manifest_digest = manifest.finalize(),
    };
}

fn validateShardShape(
    family: trace.OpcodeFamily,
    shard: Shard,
    index: usize,
    count: usize,
) Error!void {
    if (shard.shard_count != @as(u32, @intCast(count))) return error.InvalidShardCount;
    if (shard.ordinal != @as(u32, @intCast(index))) return error.ShardOutOfOrder;
    if (shard.committed_columns.len != trace.nColumnsForFamily(family))
        return error.InvalidColumnCount;
    const size = shard.committed_columns[0].len;
    if (size < 16 or !std.math.isPowerOfTwo(size)) return error.InvalidDomainSize;
    for (shard.committed_columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
    if (shard.n_real_rows == 0 or shard.n_real_rows > size)
        return error.InvalidShardGeometry;
    if (index + 1 < count and shard.n_real_rows != size)
        return error.InvalidShardGeometry;
}

fn scanShard(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    shard: Shard,
    counters: ?*counter.Set,
    options: Options,
) ![schema.KIND_COUNT]u64 {
    const size = shard.committed_columns[0].len;
    const placement = try infra.BitReversalTable.init(
        allocator,
        @intCast(std.math.log2_int(usize, size)),
    );
    defer placement.deinit(allocator);
    var counts = [_]u64{0} ** schema.KIND_COUNT;
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (0..size) |row| {
        const committed_row = placement.map(row);
        for (
            shard.committed_columns,
            secure[0..shard.committed_columns.len],
        ) |column, *value| value.* = QM31.fromBase(column[committed_row]);
        const list = opcode_entries.fromMain(
            family,
            secure[0..shard.committed_columns.len],
        ) catch return error.InvalidCommittedRow;
        var active = false;
        for (list.entries[0..list.len]) |relation_entry| {
            const nonzero = !relation_entry.numerator.isZero();
            active = active or nonzero;
            if (row >= shard.n_real_rows and nonzero) return error.NonZeroPadding;
            const kind = counter.kindForDomain(relation_entry.domain) orelse continue;
            if (!try representable(kind, relation_entry, options)) continue;
            if (nonzero) counts[@intFromEnum(kind)] += 1;
            // Registration is per entry rather than one `registerList` over the whole
            // row so a dropped request is dropped from the counters too, which is the
            // only thing that makes `.drop` mean anything.
            if (counters) |set| try set.get(kind).register(relation_entry);
        }
        if (row < shard.n_real_rows and !active) return error.InactiveRealRow;
    }
    return counts;
}

/// Whether this request has a row in its table, under `options`. A zero-numerator
/// request is inactive and asks for nothing, so it is representable by construction.
fn representable(
    kind: schema.Kind,
    relation_entry: entry.Entry,
    options: Options,
) Error!bool {
    if (relation_entry.arity != schema.arity(kind)) return error.InvalidArity;
    const numerator = relation_entry.numerator.tryIntoM31() catch
        return error.NonBaseFieldValue;
    if (numerator.isZero()) return true;
    _ = schema.indexSecure(kind, relation_entry.values[0..relation_entry.arity]) catch |err| {
        if (options.unrepresentable == .reject) return err;
        return false;
    };
    return true;
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
    for (&expected.counters.counters, &actual.counters.counters) |*want, *got| {
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

    columns.storage[15][0] = original;
    columns.storage[0][0] = M31.zero();
    shard.committed_digest = digestShard(.auipc, shard);
    try expectIngestError(error.InactiveRealRow, &.{.{
        .family = .auipc,
        .shards = &.{shard},
    }});

    try fillRows(allocator, &columns, .auipc, &.{ row, auipcRow(1) });
    shard.committed_digest = digestShard(.auipc, shard);
    try expectIngestError(error.NonZeroPadding, &.{.{
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
