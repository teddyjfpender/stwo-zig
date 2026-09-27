const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const batch = @import("block_v5_precompile_batch_v1.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;

test "block-v5 standalone typed precompile roots freshly verify under shared seal" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Api = family.ForBackend(Cpu);
    const execution_id: [32]u8 = @splat(22);
    var context = Context{ .a = a, .segment = &segment };
    defer if (context.proof) |*proof| proof.deinit(a);
    const source = batch.Source{ .context = &context, .load = Context.load };
    var collected = try batch.ForBackend(Cpu).collect(a, source, &.{.{ .index = 0, .instance_id = execution_id }}, config);
    defer collected.deinit(a);
    const record = collected.records[0];
    try std.testing.expect(profile.externalCount(&record.statement) > 0);
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        record.entry(),
    };
    const sealed = try seal.seal(pins, &entries);
    const expected_key = record.key_id;
    const first_roots = record.roots;
    try collected.prove(a, source, .{ .context = &context, .accept = Context.store }, sealed, pins, &entries, &pool);
    const codec = @import("block_v5_precompile_codec_v1.zig");
    const raw = try codec.encode(a, &context.proof.?, &record.statement, .{});
    defer a.free(raw);
    var decoded = try codec.decode(a, raw, &record.statement, config, .{});
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(a);
    const trailing = try a.alloc(u8, raw.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..raw.len], raw);
    trailing[raw.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, codec.decode(a, trailing, &record.statement, config, .{}));
    context.proof.?.deinit(a);
    context.proof = decoded;
    decoded_owned = false;
    const proof = context.proof.?;
    // Fail before consuming the real proof on a substituted independent key.
    var foreign = expected_key;
    foreign[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileKey, Api.verifyOwned(a, try clone(a, proof), &record.statement, record.total_steps, foreign, execution_id, 0, sealed, pins, &entries));
    var changed_claim = try clone(a, proof);
    changed_claim.claims.sha[0] = changed_claim.claims.sha[0].add(core.fields.qm31.QM31.one());
    if (Api.verifyOwned(a, changed_claim, &record.statement, record.total_steps, expected_key, execution_id, 0, sealed, pins, &entries)) |_|
        return error.AcceptedChangedBlockV5PrecompileClaim
    else |_| {}
    var altered_binding = family.CallerBinding{ .execution_index = 0, .execution_instance_id = execution_id, .caller_entry_index = 0, .caller_instance_id = record.instance_id, .caller_key_id = record.key_id, .first_roots = record.roots, .sealed_digest = sealed.digest };
    altered_binding.execution_instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileInstance, @import("block_v5_precompile_protocol_v1.zig").admit(altered_binding, sealed, pins, &entries));
    const sum = try batch.receive(Cpu, a, .{ .context = &context, .load = Context.take }, .{ .context = &context, .accept = Context.received }, collected.records, sealed, pins, &entries);
    const receipt = context.receipt.?;
    try std.testing.expectEqualDeep(sum, receipt.open_sum);
    try std.testing.expectEqual(@as(u32, 2), context.witness_loads);
    try std.testing.expectEqualDeep(first_roots, receipt.binding.first_roots);
    try std.testing.expectEqualDeep(expected_key, receipt.binding.caller_key_id);
    try std.testing.expectEqualDeep(sealed.digest, receipt.binding.sealed_digest);
}

const Context = struct {
    a: std.mem.Allocator,
    segment: *const runner.EthereumShaSegmentResult,
    witness_loads: u32 = 0,
    proof: ?family.Proof = null,
    receipt: ?family.OpenReceipt = null,
    fn load(raw: *anyopaque, index: u32) !Witness {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0) return error.InvalidTestPrecompileIndex;
        self.witness_loads += 1;
        return Witness.initSegment(self.a, self.segment);
    }
    fn store(raw: *anyopaque, index: u32, proof: *family.Proof) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0 or self.proof != null) return error.DuplicateTestPrecompileProof;
        self.proof = proof.*;
        proof.* = undefined;
    }
    fn take(raw: *anyopaque, index: u32) !family.Proof {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0) return error.InvalidTestPrecompileIndex;
        const proof = self.proof orelse return error.MissingTestPrecompileProof;
        self.proof = null;
        return proof;
    }
    fn received(raw: *anyopaque, receipt: family.OpenReceipt) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.receipt != null) return error.DuplicateTestPrecompileReceipt;
        self.receipt = receipt;
    }
};

fn clone(a: std.mem.Allocator, proof: family.Proof) !family.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    return .{ .stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader()), .claims = proof.claims, .key_id = proof.key_id, .instance_id = proof.instance_id };
}
