//! Rung R10b: the Cairo lane commits the canonical_small preprocessed trace
//! to the roots the leaf circuit interns as constants.
//!
//! Upstream `get_preprocessed_root(lifting_log_size)`
//! (`crates/cairo_verifier/src/verify.rs`, proving@5a7c5ed) hard-codes the
//! commitment of the whole canonical_small trace (`include_all_preprocessed_columns`)
//! under `Blake2sM31MerkleChannel`, whose Merkle hasher is the plain
//! Blake2s hasher, at `lifting_log_size = 20 + log_blowup_factor`. The
//! largest column has log size 20, so each root is the ordinary commitment at
//! blowup 1, 2 and 3. The expected words come from
//! `vectors/circuit/r6/cairo_statement.json`, which the oracle reads from the
//! upstream function itself.
//!
//! Heavy relative to the other R6 checks (up to 2^23-row LDEs of 156
//! columns); run it with `zig build test-circuit-leaf-cairo-roots
//! -Doptimize=ReleaseFast`.

const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const cairo = @import("cairo_frontend");
const Cpu = @import("stwo_cpu_backend").CpuBackend;

const blake2_merkle = core.vcs_lifted.blake2_merkle;
const Hasher = blake2_merkle.Blake2sPlainMerkleHasher;
const MerkleChannel = blake2_merkle.Blake2sM31MerkleChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, Hasher, MerkleChannel);

const checkpoint_path = "vectors/circuit/r6/cairo_statement.json";

fn commitRoot(allocator: std.mem.Allocator, spec: *const cairo.preprocessed.trace.Spec, log_blowup: u32) ![8]u32 {
    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, log_blowup, 1),
    };
    var scheme = try Scheme.init(allocator, config);
    defer scheme.deinit(allocator);
    const columns = try spec.materialize(allocator);
    var channel = core.channel.blake2s.Blake2sM31Channel{};
    try scheme.commitOwned(allocator, columns, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    const root = roots.items[0];
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, root[index * 4 ..][0..4], .little);
    return words;
}

test "R10b: canonical_small preprocessed roots equal get_preprocessed_root(21, 22, 23)" {
    const allocator = std.heap.smp_allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    const bytes = try std.fs.cwd().readFileAlloc(allocator, checkpoint_path, 4 * 1024 * 1024);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const roots = parsed.value.object.get("body").?.object.get("preprocessed_roots").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), roots.len);

    var spec = try cairo.preprocessed.trace.Spec.init(allocator, .canonical_small);
    defer spec.deinit();
    for (roots) |entry| {
        const lifting_log_size: u32 = @intCast(entry.array.items[0].integer);
        const log_blowup = lifting_log_size - spec.variant.maxLogSize();
        const actual = try commitRoot(allocator, &spec, log_blowup);
        var expected: [8]u32 = undefined;
        for (&expected, entry.array.items[1].array.items) |*word, value| word.* = @intCast(value.integer);
        try std.testing.expectEqual(expected, actual);
    }
}
