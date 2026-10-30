const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Union = @import("../block_v7_native_caller_union_proof_v1.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const Caller = @import("../block_v7_caller_active_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const instructions = [_]u32{ 0x001002b7, 0x10028293, 0x08028313, @import("../../isa/sha256_compression_v1.zig").encode(5, 6), @import("../../isa/custom0.zig").encodeKeccakf(5), 0x0002a023, 0x0000006f };
const original_elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, .rv32im_zkvm_ethereum_sha_v1);
const raw = blk: {
    var bytes = original_elf;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};

test "v7 native access active caller union genuine nine tree proof" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, &raw, @import("../block_v5_initial_sources_v1.zig").sha256(&raw), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../block_v7_program_image_v1.zig").Owned.init(a, &raw, &initial, .{});
    defer image.deinit();
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &raw, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var run = try session.startSegment(6);
    defer run.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    defer counters.deinit(a);
    var segment = try Support.Segment.init(a, &run.base, config, image.root.bytes, 0, .rv32im_zkvm_ethereum_sha_v1, 2, &counters);
    var native_live = true;
    defer if (native_live) segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &run);
    var witness_live = true;
    defer if (witness_live) witness.deinit();
    const caller = try Caller.ForBackend(Cpu).Stage.init(a, &witness, segment.pin.frame, 0, config, counters.get(.range_check_8_8));
    var caller_live = true;
    defer if (caller_live) caller.deinit();
    var shape = segment.owner.statement;
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    const statement = witness.statement;
    var np = segment.pin;
    np.shape = &shape;
    var cp = caller.pin(0, (try np.entry(a)).identity);
    cp.statement = &statement;
    const entries = [_]E.Entry{ try np.entry(a), try cp.entry(a) };
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    counts[@intFromEnum(E.Family.caller_fused)] = 1;
    // Explicit isolated OPEN source fixture, not a complete execution epoch.
    const epoch = try E.Epoch.init(@splat(31), config, counts, &entries, entries.len);
    var timer = try std.time.Timer.start();
    var proof = try Union.prove(a, &segment.first, segment.owner, segment.source.inputs, np, caller, cp, epoch, &entries, &pool);
    defer proof.deinit(a);
    const union_ns = timer.read();
    timer.reset();
    var normal_native = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, np, epoch, &entries);
    defer normal_native.deinit(a);
    var normal_caller = try Caller.ForBackend(Cpu).prove(a, caller, cp, epoch, &entries, &pool);
    defer normal_caller.deinit(a);
    const separate_ns = timer.read();
    const expected_native = try Native.For(Cpu).verify(a, &normal_native, np, epoch, &entries);
    const expected_caller = try Caller.ForBackend(Cpu).verify(a, &normal_caller, cp, epoch, &entries);
    caller.deinit();
    caller_live = false;
    segment.deinit();
    native_live = false;
    witness.deinit();
    witness_live = false;
    try Support.roundTrip(a, &proof.stark);
    timer.reset();
    const result = try Union.verify(a, &proof, np, cp, epoch, &entries);
    const verify_ns = timer.read();
    try std.testing.expectEqualDeep(expected_native, result.native);
    try std.testing.expectEqualDeep(expected_caller, result.caller);
    const old_claim = proof.native[0];
    proof.native[0].sum = old_claim.sum.add(core.fields.qm31.QM31.one());
    try reject(a, &proof, np, cp, epoch, &entries);
    proof.native[0] = old_claim;
    const old_sha = proof.arithmetic.sha;
    proof.arithmetic.sha[0] = old_sha[0].add(core.fields.qm31.QM31.one());
    proof.arithmetic.sha[1] = old_sha[1].sub(core.fields.qm31.QM31.one());
    try reject(a, &proof, np, cp, epoch, &entries);
    proof.arithmetic.sha = old_sha;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedUnionFixedRoot, Union.verify(a, &proof, np, cp, epoch, &entries));
    roots[0][0] ^= 1;
    std.mem.swap([32]u8, &roots[1], &roots[3]);
    try std.testing.expectError(error.UntrustedUnionPrivateRoot, Union.verify(a, &proof, np, cp, epoch, &entries));
    std.mem.swap([32]u8, &roots[1], &roots[3]);
    std.mem.swap([32]u8, &roots[5], &roots[6]);
    try reject(a, &proof, np, cp, epoch, &entries);
    std.mem.swap([32]u8, &roots[5], &roots[6]);
    const samples = proof.stark.commitment_scheme_proof.sampled_values.items;
    const saved_sample = samples[1][0][0];
    samples[1][0][0] = saved_sample.add(core.fields.qm31.QM31.one());
    try reject(a, &proof, np, cp, epoch, &entries);
    samples[1][0][0] = saved_sample;
    var bad_pin = cp;
    bad_pin.execution_identity[0] ^= 1;
    try reject(a, &proof, np, bad_pin, epoch, &entries);
    var wrong_epoch = epoch;
    wrong_epoch.digest[0] ^= 1;
    try reject(a, &proof, np, cp, wrong_epoch, &entries);
    _ = try Union.verify(a, &proof, np, cp, epoch, &entries);
    var bytes = std.Io.Writer.Allocating.init(a);
    defer bytes.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &bytes.writer, proof.stark);
    std.debug.print("V7_NATIVE_CALLER_UNION_CENSUS union_oods={d} separate_oods={d} union_queried={d} separate_queried={d}\n", .{ samplesCount(proof.stark), samplesCount(normal_native.stark) + samplesCount(normal_caller.stark), queriedCount(proof.stark), queriedCount(normal_native.stark) + queriedCount(normal_caller.stark) });
    std.debug.print("V7_NATIVE_CALLER_UNION trees=9 separate_trees=11 original_starks=1 separate_starks=2 physical_claims_preserved=true original_exports_exact=true producers_destroyed=true union_prove_ns={d} separate_prove_ns={d} fresh_verify_ns={d} proof_bytes={d} timing=shared_host_diagnostic complete_execution=false\n", .{ union_ns, separate_ns, verify_ns, bytes.written().len });
}
fn reject(a: std.mem.Allocator, p: *const Union.Proof, np: Native.Pin, cp: Caller.Pin, e: E.Epoch, entries: []const E.Entry) !void {
    if (Union.verify(a, p, np, cp, e, entries)) |_| return error.AcceptedUnionForgery else |err| if (err == error.OutOfMemory) return err;
}

fn samplesCount(proof: core.proof_suites.Blake3.Proof) usize {
    var count: usize = 0;
    for (proof.commitment_scheme_proof.sampled_values.items) |tree| for (tree) |column| {
        count += column.len;
    };
    return count;
}
fn queriedCount(proof: core.proof_suites.Blake3.Proof) usize {
    var count: usize = 0;
    for (proof.commitment_scheme_proof.queried_values.items) |tree| for (tree) |column| {
        count += column.len;
    };
    return count;
}
