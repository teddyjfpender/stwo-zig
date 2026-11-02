//! Controlled generic PCS commitment/opening experiment. No AIR/FRI/PoW speed
//! claim: every arm authenticates its openings and matches reference bytes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Column = engine.pcs.ColumnEvaluation;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Hash = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
pub const Config = struct {
    native_log: u32 = 17,
    column_count: usize = 128,
    small_log: u32 = 8,
    small_columns: usize = 43,
    workers: usize = 8,
    memory_limit_bytes: usize = 48 << 30,
    tile_bytes: usize = 256 << 20,
    group_bytes: usize = 256 << 20,
    seed: u64 = 0x504353434f4d4d54,
};
pub const Variant = enum { stream8, stream32, stream64, stream128, tiled };
pub const Measurement = struct {
    variant: Variant,
    commit_ns: u64,
    opening_ns: u64,
    verify_ns: u64,
    peak_charged_bytes: usize,
    retained_coefficient_bytes: usize,
    opening_values: usize,
    opening_hashes: usize,
    root: [32]u8,
    transcript: [32]u8,
    coefficient_digest: [32]u8,
    opening_digest: [32]u8,
    verified: bool = true,
};
pub const Report = struct {
    schema: []const u8 = "generic-pcs-commit-open-profile-v1",
    scope: []const u8 = "PCS commitment and selective authenticated opening only; excludes AIR, FRI and PoW. Charged heap includes shared input reservation; excludes worker stacks/process RSS.",
    config: Config,
    source_bytes: usize,
    build_mode: []const u8 = @tagName(@import("builtin").mode),
    cpu_wide_lde: bool,
    measurements: [5]Measurement,
    complete: bool = true,
    root_and_opening_parity: bool = true,
    whole_execution_proof: bool = false,
};

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedPcsProfileConfig;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 65536);
    defer a.free(bytes);
    const parsed = try std.json.parseFromSlice(Config, a, bytes, .{});
    defer parsed.deinit();
    const report = try run(a, parsed.value);
    const json = try std.json.Stringify.valueAlloc(a, report, .{});
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

pub fn run(a: std.mem.Allocator, config: Config) !Report {
    if (config.native_log < 5 or config.native_log > 22 or config.small_log < 5 or config.small_log > config.native_log or config.column_count == 0 or config.column_count > 2048 or config.small_columns > 2048 or config.workers == 0 or config.workers > engine.work_pool.MAX_WORKERS or config.tile_bytes == 0 or config.group_bytes == 0) return error.InvalidPcsProfileConfig;
    const count = try std.math.add(usize, config.column_count, config.small_columns);
    const native_rows = @as(usize, 1) << @intCast(config.native_log);
    const small_rows = @as(usize, 1) << @intCast(config.small_log);
    const cells = try std.math.add(usize, try std.math.mul(usize, config.column_count, native_rows), try std.math.mul(usize, config.small_columns, small_rows));
    const source_bytes = try std.math.add(usize, try std.math.mul(usize, cells, @sizeOf(M)), try std.math.mul(usize, count, @sizeOf(Column)));
    if (source_bytes >= config.memory_limit_bytes) return error.PcsProfileSourceExceedsBudget;
    // One shared input, explicitly reserved against each arm's independent
    // budget. Arms run sequentially and retain no preceding scheme owner.
    const values = try a.alloc(M, cells);
    defer a.free(values);
    const columns = try a.alloc(Column, count);
    defer a.free(columns);
    var cursor: usize = 0;
    var prng = std.Random.DefaultPrng.init(config.seed);
    const rng = prng.random();
    for (columns, 0..) |*column, c| {
        const log = if (c < config.column_count) config.native_log else config.small_log;
        const rows = @as(usize, 1) << @intCast(log);
        const data = values[cursor..][0..rows];
        for (data) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        column.* = .{ .log_size = log, .values = data };
        cursor += rows;
    }
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = config.workers });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const wide_lde = if (std.posix.getenv("STWO_CAIRO_CPU_WIDE_LDE")) |value| std.mem.eql(u8, value, "1") else false;
    var report = Report{ .config = config, .source_bytes = source_bytes, .cpu_wide_lde = wide_lde, .measurements = undefined };
    for (&report.measurements, [_]Variant{ .stream8, .stream32, .stream64, .stream128, .tiled }) |*measurement, variant| {
        measurement.* = try measure(a, config, columns, source_bytes, variant);
        const reference = report.measurements[0];
        if (!std.mem.eql(u8, &measurement.root, &reference.root) or !std.mem.eql(u8, &measurement.transcript, &reference.transcript) or !std.mem.eql(u8, &measurement.coefficient_digest, &reference.coefficient_digest) or !std.mem.eql(u8, &measurement.opening_digest, &reference.opening_digest)) return error.PcsProfileParityMismatch;
    }
    return report;
}

fn measure(base: std.mem.Allocator, config: Config, columns: []Column, source_bytes: usize, variant: Variant) !Measurement {
    const budget = try Budget.create(base, config.memory_limit_bytes);
    defer budget.destroy();
    var reservation = try budget.reserveExternal(source_bytes);
    defer reservation.deinit();
    const a = budget.allocator();
    const pcs_config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var scheme = try Scheme.init(a, pcs_config);
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = Channel{};
    var timer = try std.time.Timer.start();
    switch (variant) {
        .stream8 => try scheme.commitBorrowedStreaming(a, columns, 8, &channel),
        .stream32 => try scheme.commitBorrowedStreaming(a, columns, 32, &channel),
        .stream64 => try scheme.commitBorrowedStreaming(a, columns, 64, &channel),
        .stream128 => try scheme.commitBorrowedStreaming(a, columns, 128, &channel),
        .tiled => try engine.pcs.tiled_commit.commit(B, H, &scheme, a, columns, .borrowed, .{ .tile_bytes = config.tile_bytes, .group_bytes = config.group_bytes }, &channel),
    }
    const commit_ns = timer.read();
    const tree = scheme.trees.items[0];
    const coefficients = tree.coefficients orelse return error.PcsProfileMissingCoefficients;
    if (coefficients.len != columns.len) return error.PcsProfileMissingCoefficients;
    var coefficient_hash = Hash.init(.{});
    var coefficient_bytes: usize = 0;
    for (coefficients, columns, tree.columns) |polynomial, source, retained| {
        if (polynomial.logSize() != source.log_size or retained.coefficient_values == null) return error.PcsProfileMissingCoefficients;
        coefficient_hash.update(std.mem.sliceAsBytes(polynomial.coefficients()));
        coefficient_bytes += polynomial.coefficients().len * @sizeOf(M);
    }
    const rows = @as(usize, 1) << @intCast(tree.commitment.maxLogSize());
    var queries: [70]usize = undefined;
    for (&queries, 0..) |*query, i| query.* = i * rows / queries.len;
    timer.reset();
    var opening = try tree.decommit(a, &queries);
    defer opening.deinit(a);
    const opening_ns = timer.read();
    const logs = try tree.columnLogSizes(a);
    defer a.free(logs);
    var verifier = try core.vcs_lifted.verifier.MerkleVerifierLifted(H).init(a, tree.root(), logs);
    defer verifier.deinit(a);
    timer.reset();
    try verifier.verify(a, &queries, opening.queried_values, opening.decommitment.decommitment);
    const verify_ns = timer.read();
    var opening_hash = Hash.init(.{});
    var opening_values: usize = 0;
    for (opening.queried_values) |column| {
        opening_hash.update(std.mem.sliceAsBytes(column));
        opening_values += column.len;
    }
    opening_hash.update(std.mem.sliceAsBytes(opening.decommitment.decommitment.hash_witness));
    var coefficient_digest: [32]u8 = undefined;
    var opening_digest: [32]u8 = undefined;
    coefficient_hash.final(&coefficient_digest);
    opening_hash.final(&opening_digest);
    return .{ .variant = variant, .commit_ns = commit_ns, .opening_ns = opening_ns, .verify_ns = verify_ns, .peak_charged_bytes = budget.snapshot().peak_live_bytes, .retained_coefficient_bytes = coefficient_bytes, .opening_values = opening_values, .opening_hashes = opening.decommitment.decommitment.hash_witness.len, .root = tree.root(), .transcript = channel.digestBytes(), .coefficient_digest = coefficient_digest, .opening_digest = opening_digest };
}
