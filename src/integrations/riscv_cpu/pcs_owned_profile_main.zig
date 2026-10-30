//! Generic PCS ownership diagnostic with independent policy/ownership controls.
//! Separates backend preparation policy, batch scheduling and source adoption.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const backend = @import("stwo_cpu_backend");
const Default = backend.CpuBackend;
const Adopting = backend.configured(.{ .wide_preparation = true, .source_trace_arena = true });
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Column = engine.pcs.ColumnEvaluation;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Hash = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
pub const Config = struct {
    native_log: u32 = 17,
    main_columns: usize = 128,
    provider_logs: []const u32 = &.{ 10, 8, 16, 11 },
    workers: usize = 8,
    memory_limit_bytes: usize = 16 << 30,
    seed: u64 = 0x5043534f574e4544,
};
pub const Variant = enum { default_borrowed8, policy_borrowed8, policy_borrowed64, policy_owned_arena };
pub const Measurement = struct {
    variant: Variant,
    source_generation_ns: u64,
    commit_ns: u64,
    opening_ns: u64,
    verify_ns: u64,
    peak_charged_bytes: usize,
    post_commit_live_bytes: usize,
    source_bytes: usize,
    provider_original_bytes: usize,
    retained_coefficient_bytes: usize,
    all_coefficients_adopt_source: bool,
    provider_original_unchanged: bool,
    root: [32]u8,
    transcript: [32]u8,
    coefficients_digest: [32]u8,
    opening_digest: [32]u8,
};
pub const Report = struct {
    schema: []const u8 = "generic-pcs-owned-arena-study-v1",
    scope: []const u8 = "PCS commitment and authenticated opening only; source generation outside commit timing, inside heap budget. Provider originals stay live; arena holds copies. No AIR/FRI/PoW or whole-job speedup claim.",
    build_mode: []const u8 = @tagName(@import("builtin").mode),
    config: Config,
    measurements: [4]Measurement,
    complete: bool = true,
    root_coefficients_and_opening_parity: bool = true,
};

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedPcsOwnedProfileConfig;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 65536);
    defer a.free(bytes);
    const parsed = try std.json.parseFromSlice(Config, a, bytes, .{});
    defer parsed.deinit();
    const result = try run(a, parsed.value);
    const json = try std.json.Stringify.valueAlloc(a, result, .{});
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
pub fn run(a: std.mem.Allocator, config: Config) !Report {
    try validate(config);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = config.workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var result = Report{ .config = config, .measurements = undefined };
    for (&result.measurements, [_]Variant{ .default_borrowed8, .policy_borrowed8, .policy_borrowed64, .policy_owned_arena }) |*measurement, variant| {
        measurement.* = try measure(a, config, variant);
        const reference = result.measurements[0];
        if (!std.meta.eql(measurement.root, reference.root) or !std.meta.eql(measurement.transcript, reference.transcript) or !std.meta.eql(measurement.coefficients_digest, reference.coefficients_digest) or !std.meta.eql(measurement.opening_digest, reference.opening_digest) or !measurement.provider_original_unchanged) return error.PcsOwnedProfileParityMismatch;
    }
    return result;
}
/// A single owned arm supports exhaustive allocation-failure testing without
/// hiding the public consume-on-success-and-error boundary behind test hooks.
pub fn singleOwned(a: std.mem.Allocator, config: Config) !Measurement {
    try validate(config);
    return measure(a, config, .policy_owned_arena);
}
fn validate(config: Config) !void {
    if (std.posix.getenv("STWO_CAIRO_CPU_WIDE_LDE") != null) return error.PcsOwnedProfileRequiresDefaultEnvironment;
    if (config.native_log < 5 or config.native_log > 22 or config.main_columns == 0 or config.main_columns > 2048 or config.provider_logs.len > 128 or config.workers == 0 or config.workers > engine.work_pool.MAX_WORKERS) return error.InvalidPcsOwnedProfileConfig;
    for (config.provider_logs) |log| if (log < 5 or log > config.native_log) return error.InvalidPcsOwnedProfileConfig;
}
fn measure(a: std.mem.Allocator, config: Config, variant: Variant) !Measurement {
    return switch (variant) {
        .default_borrowed8 => measureBackend(Default, a, config, variant),
        else => measureBackend(Adopting, a, config, variant),
    };
}
fn measureBackend(comptime B: type, base: std.mem.Allocator, config: Config, variant: Variant) !Measurement {
    const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
    const budget = try Budget.create(base, config.memory_limit_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const rows = @as(usize, 1) << @intCast(config.native_log);
    var provider_cells: usize = 0;
    for (config.provider_logs) |log| provider_cells = try std.math.add(usize, provider_cells, @as(usize, 1) << @intCast(log));
    const cells = try std.math.add(usize, try std.math.mul(usize, rows, config.main_columns), provider_cells);
    var timer = try std.time.Timer.start();
    const arena = try a.alloc(M, cells);
    var source_live = true;
    defer if (source_live) a.free(arena);
    const columns = try a.alloc(Column, config.main_columns + config.provider_logs.len);
    var headers_live = true;
    defer if (headers_live) a.free(columns);
    const provider_original = try a.alloc(M, provider_cells);
    defer a.free(provider_original);
    var prng = std.Random.DefaultPrng.init(config.seed);
    const rng = prng.random();
    var cursor: usize = 0;
    for (columns[0..config.main_columns]) |*column| {
        const values = arena[cursor..][0..rows];
        for (values) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        column.* = .{ .log_size = config.native_log, .values = values };
        cursor += rows;
    }
    var provider_cursor: usize = 0;
    for (columns[config.main_columns..], config.provider_logs) |*column, log| {
        const size = @as(usize, 1) << @intCast(log);
        const original = provider_original[provider_cursor..][0..size];
        for (original) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        @memcpy(arena[cursor..][0..size], original);
        column.* = .{ .log_size = log, .values = arena[cursor..][0..size] };
        provider_cursor += size;
        cursor += size;
    }
    const source_generation_ns = timer.read();
    const provider_digest = hash(std.mem.sliceAsBytes(provider_original));
    const source_start = @intFromPtr(arena.ptr);
    const source_end = source_start + arena.len * @sizeOf(M);
    const config_pcs = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var scheme = try Scheme.init(a, config_pcs);
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = Channel{};
    const backing = if (variant == .policy_owned_arena) try a.dupe([]M, &.{arena}) else null;
    timer.reset();
    if (backing) |buffers| {
        source_live = false;
        headers_live = false;
        try scheme.commitOwnedWithRecorderAndBacking(a, columns, buffers, null, &channel);
    } else {
        try scheme.commitBorrowedStreaming(a, columns, if (variant == .policy_borrowed64) 64 else 8, &channel);
    }
    const commit_ns = timer.read();
    if (source_live) {
        a.free(arena);
        source_live = false;
    }
    if (headers_live) {
        a.free(columns);
        headers_live = false;
    }
    const post_commit_live_bytes = budget.snapshot().live_bytes;
    const tree = scheme.trees.items[0];
    const coefficients = tree.coefficients orelse return error.PcsOwnedProfileMissingCoefficients;
    var coefficient_hash = Hash.init(.{});
    var all_adopted = true;
    var coefficient_bytes: usize = 0;
    for (coefficients, 0..) |polynomial, i| {
        const expected_log = if (i < config.main_columns) config.native_log else config.provider_logs[i - config.main_columns];
        if (polynomial.logSize() != expected_log or tree.columns[i].coefficient_values == null) return error.PcsOwnedProfileMissingCoefficients;
        const values = polynomial.coefficients();
        coefficient_hash.update(std.mem.sliceAsBytes(values));
        coefficient_bytes += values.len * @sizeOf(M);
        const first = @intFromPtr(values.ptr);
        all_adopted = all_adopted and first >= source_start and first + values.len * @sizeOf(M) <= source_end;
    }
    var coefficient_digest: [32]u8 = undefined;
    coefficient_hash.final(&coefficient_digest);
    const n_leaves = @as(usize, 1) << @intCast(tree.commitment.maxLogSize());
    var queries: [70]usize = undefined;
    for (&queries, 0..) |*query, i| query.* = i * n_leaves / queries.len;
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
    for (opening.queried_values) |values| opening_hash.update(std.mem.sliceAsBytes(values));
    opening_hash.update(std.mem.sliceAsBytes(opening.decommitment.decommitment.hash_witness));
    var opening_digest: [32]u8 = undefined;
    opening_hash.final(&opening_digest);
    return .{ .variant = variant, .source_generation_ns = source_generation_ns, .commit_ns = commit_ns, .opening_ns = opening_ns, .verify_ns = verify_ns, .peak_charged_bytes = budget.snapshot().peak_live_bytes, .post_commit_live_bytes = post_commit_live_bytes, .source_bytes = cells * @sizeOf(M), .provider_original_bytes = provider_cells * @sizeOf(M), .retained_coefficient_bytes = coefficient_bytes, .all_coefficients_adopt_source = all_adopted, .provider_original_unchanged = std.meta.eql(hash(std.mem.sliceAsBytes(provider_original)), provider_digest), .root = tree.root(), .transcript = channel.digestBytes(), .coefficients_digest = coefficient_digest, .opening_digest = opening_digest };
}
fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Hash.hash(bytes, &result, .{});
    return result;
}
