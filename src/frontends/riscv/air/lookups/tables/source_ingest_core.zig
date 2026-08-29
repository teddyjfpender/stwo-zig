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
const blake2 = @import("stwo_core").vcs.blake2_hash;
const infra = @import("../../../infra_trace.zig");
const trace = @import("../../../runner/trace.zig");
const BaseScalar = @import("../base_scalar.zig").Scalar;
const entry = @import("../entry.zig");
const opcode_entries = @import("../opcode_entries.zig");
const counter = @import("counter.zig");
const schema = @import("schema.zig");

pub const Digest = blake2.Blake2sHash;

const base_opcode_entries = opcode_entries.Entries(BaseScalar);
const BaseEntry = entry.Builder(BaseScalar).Entry;
const BaseList = entry.Builder(BaseScalar).List;

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

/// Production result for sources generated inside this proving transaction.
///
/// The strict `Result` above carries a digest manifest because a caller-owned
/// source needs authentication. Internally generated columns are already the
/// exact buffers handed to the commitment scheme, so their only downstream
/// product is the signed counter set. Keeping this smaller result type makes
/// that trust boundary explicit and avoids hashing the full trace solely to
/// populate metadata that the proof never consumes.
pub const GeneratedCounters = struct {
    counters: counter.Set,

    pub fn deinit(self: *GeneratedCounters, allocator: std.mem.Allocator) void {
        self.counters.deinit(allocator);
        self.* = undefined;
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

/// Registers internally generated opcode columns without constructing an
/// unused provenance manifest.
///
/// This remains a fail-closed scan of the committed buffers: shard geometry,
/// every active tuple, inactive real rows, and zero padding receive the same
/// validation as strict ingestion. Only the caller-authentication digest is
/// omitted; Tree 1's polynomial commitment is the binding for these buffers.
pub fn ingestGeneratedCounters(
    allocator: std.mem.Allocator,
    sources: []const FamilySource,
    options: Options,
) !GeneratedCounters {
    var work_count: usize = 0;
    for (sources) |source| {
        work_count = std.math.add(usize, work_count, source.shards.len) catch
            return error.InvalidShardCount;
    }
    const work = try allocator.alloc(GeneratedShardWork, work_count);
    defer allocator.free(work);
    _ = try prepareGeneratedWork(sources, work);

    if (generatedPaddedRows(sources) >= generated_parallel_row_threshold) {
        if (work_pool.getGlobalPool()) |pool| {
            if (try scanGeneratedWorkParallel(
                allocator,
                work,
                options,
                pool,
                false,
            )) |counters| return .{ .counters = counters };
        }
    }

    var counters = try counter.Set.init(allocator);
    errdefer counters.deinit(allocator);
    for (work) |item| {
        _ = try scanShard(allocator, item.family, item.shard, &counters, options);
    }
    return .{ .counters = counters };
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
    derive_digest: bool,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        var work_index = self.index;
        while (work_index < self.work.len) : (work_index += self.stride) {
            const item = &self.work[work_index];
            if (self.derive_digest)
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

    const counters = (try scanGeneratedWorkParallel(
        allocator,
        work,
        options,
        pool,
        true,
    )) orelse return ingestImpl(allocator, sources, options, .derive);

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

/// Scans independent shards into private dense histograms, then reduces those
/// histograms in canonical table-row order. Returning null asks a caller with
/// too little parallel work to use its sequential path.
fn scanGeneratedWorkParallel(
    allocator: std.mem.Allocator,
    work: []GeneratedShardWork,
    options: Options,
    pool: *work_pool.WorkPool,
    derive_digest: bool,
) !?counter.Set {
    const worker_count = @min(
        @min(pool.workerCount(), max_generated_ingest_workers),
        work.len,
    );
    if (worker_count < 2) return null;

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
            .derive_digest = derive_digest,
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
        counter_sets[0].mergeFrom(set);
        set.deinit(allocator);
    }
    const counters = counter_sets[0];
    sets_owned = false;
    return counters;
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
    var base: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
    for (0..size) |row| {
        const committed_row = placement.map(row);
        for (
            shard.committed_columns,
            base[0..shard.committed_columns.len],
        ) |column, *value| value.* = BaseScalar.fromBase(column[committed_row]);
        var list: BaseList = undefined;
        base_opcode_entries.fromMainInto(
            family,
            base[0..shard.committed_columns.len],
            &list,
        ) catch return error.InvalidCommittedRow;
        const active = try registerBaseList(
            &list,
            counters,
            options,
            &counts,
            row >= shard.n_real_rows,
        );
        if (row < shard.n_real_rows and !active) return error.InactiveRealRow;
    }
    return counts;
}

/// Registers one real row immediately after the generated opcode witness has
/// written it. The caller owns the column geometry and passes the physical
/// (bit-reversed) row, so this path performs no allocation and no second trace
/// traversal. It deliberately uses the same base-field entry reconstruction
/// and table-index validation as `scanShard`; only padding validation stays in
/// the full-buffer scanner because generated padding is zero-initialized and
/// never written.
pub fn registerGeneratedCommittedRow(
    family: trace.OpcodeFamily,
    columns: *const [trace.MAX_FAMILY_COLUMNS][]M31,
    physical_row: usize,
    counters: *counter.Set,
) Error!void {
    const column_count = trace.nColumnsForFamily(family);
    var base: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
    for (
        columns[0..column_count],
        base[0..column_count],
    ) |column, *value| value.* = BaseScalar.fromBase(column[physical_row]);
    var list: BaseList = undefined;
    base_opcode_entries.fromMainInto(
        family,
        base[0..column_count],
        &list,
    ) catch return error.InvalidCommittedRow;
    if (!try registerBaseList(&list, counters, .{}, null, false))
        return error.InactiveRealRow;
}

/// Shared registration core for scanned and write-through generated rows.
/// Keeping table representability and signed-numerator handling here prevents
/// the fast path from becoming a second interpretation of the lookup AIR.
fn registerBaseList(
    list: *const BaseList,
    counters: ?*counter.Set,
    options: Options,
    counts: ?*[schema.KIND_COUNT]u64,
    padding: bool,
) Error!bool {
    var active = false;
    for (list.entries[0..list.len]) |*relation_entry| {
        const nonzero = !relation_entry.numerator.isZero();
        active = active or nonzero;
        if (padding and nonzero) return error.NonZeroPadding;
        const kind = counter.kindForDomain(relation_entry.domain) orelse continue;
        const table_row = try representableBase(kind, relation_entry, options) orelse
            continue;
        if (nonzero) {
            if (counts) |totals| totals[@intFromEnum(kind)] += 1;
        }
        // Registration is per entry rather than one `registerList` over the whole
        // row so a dropped request is dropped from the counters too, which is the
        // only thing that makes `.drop` mean anything.
        if (counters) |set| {
            const table = set.get(kind);
            table.values[table_row] = table.values[table_row].add(
                relation_entry.numerator.value,
            );
        }
    }
    return active;
}

/// Whether this request has a row in its table, under `options`. A zero-numerator
/// request is inactive and asks for nothing, so return an arbitrary in-bounds
/// row whose zero addition leaves the counter unchanged.
fn representableBase(
    kind: schema.Kind,
    relation_entry: *const BaseEntry,
    options: Options,
) Error!?usize {
    if (relation_entry.arity != schema.arity(kind)) return error.InvalidArity;
    if (relation_entry.numerator.isZero()) return 0;
    var values: [schema.MAX_ARITY]M31 = undefined;
    for (
        relation_entry.values[0..relation_entry.arity],
        values[0..relation_entry.arity],
    ) |value, *dst| dst.* = value.value;
    return schema.indexBase(kind, values[0..relation_entry.arity]) catch |err| {
        if (options.unrepresentable == .reject) return err;
        return null;
    };
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
