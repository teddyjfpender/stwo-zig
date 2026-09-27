//! Scoped real-native qualification: old custody remains in the native proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Boundary = @import("block_v5_program_boundary_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const Batch = @import("block_v5_program_batch_receiver_v1.zig");
const FirstPass = @import("block_v5_program_first_round_v1.zig");
const Column = engine.pcs.ColumnEvaluation;

test "block-v5 real native opcode roots bind fresh program request and global ROM proofs" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    var diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    for (3..6) |instruction| std.mem.writeInt(u32, diagnostic[640 + instruction * 4 ..][0..4], 0x0002_8393, .little);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(7);
    defer segment.deinit();
    if (!segment.base.isComplete()) return error.IncompleteProgramNativeFixture;
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    if (owner.statement.ethereum.counts.keccak_calls != 0 or owner.statement.sha.call_count != 0 or
        owner.statement.ethereum.counts.signer_calls != 0) return error.UnexpectedPrecompileProgramFetch;
    const NativeApi = Native.ForBackend(Cpu);
    const RequestApi = Request.ForBackend(Cpu);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const prepared = try NativeApi.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement,
        try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    const slots = try Request.slotsFromStatement(a, &owner.native.statement);
    defer a.free(slots);
    var fixed: std.ArrayList(Column) = .empty;
    defer fixed.deinit(a);
    try fixed.appendSlice(a, owner.native.preprocessed.items);
    try fixed.appendSlice(a, owner.hashes.preprocessed());
    const extension_fixed = try Profile.preprocessed(a, &owner.statement);
    defer {
        for (extension_fixed) |column| a.free(column.values);
        a.free(extension_fixed);
    }
    try fixed.appendSlice(a, extension_fixed);
    var extension_main = try Profile.mainWitness(a, &owner);
    defer extension_main.deinit(a);
    var main: std.ArrayList(Column) = .empty;
    defer main.deinit(a);
    try main.appendSlice(a, owner.native.main.items);
    try main.appendSlice(a, &owner.native.compact_ranges.?.columns);
    try main.appendSlice(a, try owner.hashes.main());
    try main.appendSlice(a, extension_main.columns);
    var request_first = try RequestApi.commitFirstRound(a, fixed.items, main.items, slots, prepared.id, 0, config);
    var owns_request_first = true;
    defer if (owns_request_first) request_first.deinit(a);
    var native_first = try NativeApi.commitFirstRound(a, &owner, prepared, prepared.id);
    var owns_native_first = true;
    defer if (owns_native_first) native_first.deinit(a);
    try std.testing.expectEqualDeep(native_first.roots, request_first.roots);
    const native_roots = native_first.roots;
    var fetches: u64 = 0;
    for (owner.plan.programs) |word| fetches = try std.math.add(u64, fetches, word.multiplicity);
    var first_pass = try FirstPass.ForBackend(Cpu).init(a, owner.plan.roots[0], owner.plan.program_leaves, 1);
    defer first_pass.deinit();
    try first_pass.addLegacy(&owner.plan, &owner.native.statement, prepared.id,
        native_roots, request_first.roots);
    try first_pass.addExtension(0, &owner.plan, &.{}, 0, null);
    try std.testing.expectError(error.InvalidV5ProgramExtensionCensus,
        first_pass.addExtension(0, &owner.plan, &.{}, 0, null));
    var different_instance = try FirstPass.ForBackend(Cpu).init(a, owner.plan.roots[0], owner.plan.program_leaves, 1);
    defer different_instance.deinit();
    try different_instance.add(&owner.plan, &owner.native.statement, prepared.id,
        @splat(77), native_roots, request_first.roots);
    try std.testing.expect(!std.meta.eql(first_pass.requestEntries()[0].instance_id,
        different_instance.requestEntries()[0].instance_id));
    try std.testing.expect(!std.meta.eql(first_pass.executionEntries()[0].instance_id,
        different_instance.executionEntries()[0].instance_id));
    const program_entry = try first_pass.finish(fetches, config);
    const plan = try first_pass.census.smallestTablePlan(1, fetches);
    request_first.deinit(a);
    owns_request_first = false;
    native_first.deinit(a);
    owns_native_first = false;
    var family_counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |kind|
        family_counts[@intFromEnum(kind) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(11), .source_image_digest = @splat(12),
        .native_template_id = @splat(13), .program_root = plan.program_root.bytes,
        .program_plan_digest = try plan.digest(), .memory_plan_digest = @splat(14),
        .initial_source_plan_digest = @splat(15), .config = config, .counts = family_counts };
    const roster = [_]Seal.Entry{
        program_entry,
        first_pass.executionEntries()[0],
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(31), @splat(32) } },
        first_pass.requestEntries()[0],
        .{ .family = .memory, .index = 0, .instance_id = @splat(24), .roots = .{ @splat(33), @splat(34) } },
    };
    const sealed = try Seal.seal(pins, &roster);
    try sealed.require(pins, &roster);
    const program_seal = sealed.programSeal();
    var block_channel = sealed.sharedChannel();
    var program_channel = program_seal.sharedChannel();
    try std.testing.expectEqualDeep(block_channel.digestBytes(), program_channel.digestBytes());
    const prefix = try universal.UniversalRelations.draw(a, &block_channel);
    const memory_challenges = try @import("block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    try std.testing.expectEqualDeep(prefix, memory_challenges.universal_prefix);
    var table_proved = try first_pass.proveTable(program_seal);
    defer table_proved.deinit(a);
    var request_replay = try first_pass.replayRequest(0, fixed.items, main.items,
        &owner.native.statement, prepared.id);
    defer request_replay.deinit(a);
    var request_proved = try RequestApi.prove(a, &request_replay, main.items, slots, program_seal, prepared.id, 0, native_roots);
    defer request_proved.deinit(a);
    var native_proved = try NativeApi.proveReplaying(a, &owner, prepared, prepared.id, native_roots, &pool);
    defer native_proved.proof.deinit(a);
    const native_wire = try Native.codec.encode(a, &native_proved.proof, prepared, prepared.id);
    defer a.free(native_wire);
    const table_wire = try starkBytes(a, table_proved.stark);
    defer a.free(table_wire);
    const request_wire = try starkBytes(a, request_proved.stark);
    defer a.free(request_wire);
    const Receiver = Batch.ForBackend(Cpu);
    try Receiver.verify(a, pins, &roster, sealed, plan,
        .{ .stark = table_wire, .claim = table_proved.claim }, &.{.{ .prepared = prepared,
            .wire = .{ .native_artifact = native_wire, .request_stark = request_wire,
                .request_claims = request_proved.claims } }});
    var relation_channel = program_seal.sharedChannel();
    const relations = try universal.UniversalRelations.draw(a, &relation_channel);
    const boundary = try Boundary.deriveFromPinnedNativePublic(.rv32im_zkvm_ethereum_sha_v1,
        &owner.native.statement.public_data, &relations);
    const opcode_fetches = try @import("block_v5_program_request_source_v1.zig").exactOpcodeFetchCount(
        owner.native.statement.component_descs[0..owner.native.statement.n_components]);
    try std.testing.expectEqual(fetches, try std.math.add(u64, opcode_fetches, boundary.fetch_count));
    try std.testing.expectEqual(@as(u64, 1), boundary.fetch_count);
    var changed = roster;
    changed[0].instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5ProgramTableId, Receiver.verify(a, pins,
        &changed, try Seal.seal(pins, &changed), plan,
        .{ .stark = table_wire, .claim = table_proved.claim }, &.{.{ .prepared = prepared,
            .wire = .{ .native_artifact = native_wire, .request_stark = request_wire,
                .request_claims = request_proved.claims } }}));
    changed = roster;
    changed[3].instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5ProgramRequestId, Receiver.verify(a, pins,
        &changed, try Seal.seal(pins, &changed), plan,
        .{ .stark = table_wire, .claim = table_proved.claim }, &.{.{ .prepared = prepared,
            .wire = .{ .native_artifact = native_wire, .request_stark = request_wire,
                .request_claims = request_proved.claims } }}));
    var wrong_seal = sealed;
    wrong_seal.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, Receiver.verify(a, pins,
        &roster, wrong_seal, plan,
        .{ .stark = table_wire, .claim = table_proved.claim }, &.{.{ .prepared = prepared,
            .wire = .{ .native_artifact = native_wire, .request_stark = request_wire,
                .request_claims = request_proved.claims } }}));
}

fn starkBytes(a: std.mem.Allocator, stark: core.proof_suites.Blake3.Proof) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, stark);
    return a.dupe(u8, writer.written());
}
