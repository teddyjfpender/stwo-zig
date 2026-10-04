const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const profile = @import("../blake3_ethereum_sha_profile.zig");
const family = @import("../block_v5_precompile_family_proof_v1.zig");
const seal = @import("../block_v5_source_seal_v1.zig");
const batch = @import("../block_v5_precompile_batch_v1.zig");
const Witness = @import("../block_v5_precompile_witness_v1.zig").Witness;

test "block-v5 caller PC projection shares typed roots and freshly verifies" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
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
    const State = @import("../block_v5_precompile_state_request_proof_v1.zig");
    const StateApi = State.ForBackend(Cpu);
    var witness = try Witness.initSegment(a, &segment);
    defer witness.deinit();
    var caller_first = try Api.commitFirstRound(a, &witness, record.total_steps, config, 0, execution_id);
    defer caller_first.deinit(a);
    var state_first = try StateApi.borrowFirstRound(a, &caller_first);
    defer state_first.deinit(a);
    try std.testing.expectEqualDeep(caller_first.roots, state_first.roots);
    try std.testing.expect(caller_first.scheme.trees.items[1].columns[0].values.ptr == state_first.scheme.trees.items[1].columns[0].values.ptr);
    const binding = caller_first.binding(sealed);
    var state_proof = try StateApi.prove(a, &state_first, &witness, binding, sealed, pins, &entries, record.total_steps);
    var state_owned = true;
    defer if (state_owned) state_proof.deinit(a);
    const caller_proof = try Api.prove(a, &caller_first, sealed, pins, &entries, &pool);
    const fresh = try Api.verifyOwned(a, caller_proof, &record.statement, record.total_steps, record.key_id, execution_id, 0, sealed, pins, &entries);
    var changed = try cloneState(a, state_proof);
    changed.projection.claims[0].sum = changed.projection.claims[0].sum.add(core.fields.qm31.QM31.one());
    if (StateApi.verifyOwned(a, changed, sealed, pins, &entries, &fresh, &record.statement, record.total_steps)) |_|
        return error.AcceptedChangedCallerStateClaim
    else |_| {}
    var changed_binding = fresh;
    changed_binding.binding.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileInstance, StateApi.verifyOwned(a, try cloneState(a, state_proof), sealed, pins, &entries, &changed_binding, &record.statement, record.total_steps));
    state_owned = false;
    const receipt = try StateApi.verifyOwned(a, state_proof, sealed, pins, &entries, &fresh, &record.statement, record.total_steps);
    try std.testing.expectEqual(@as(u64, profile.externalCount(&record.statement)), receipt.caller_count);
    var channel = sealed.sharedChannel();
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const bus = relations.get(@import("../../air/lang/relation.zig").Domain.registers_state);
    var expected = core.fields.qm31.QM31.zero();
    for (segment.extension.keccakf_calls.records()) |call| expected = expected.add(try retirementSum(bus, call.pc, call.execution_clock));
    for (segment.extension.signer_recovery_calls.records()) |call| expected = expected.add(try retirementSum(bus, call.pc, call.execution_clock));
    for (segment.extension.sha_calls.records()) |entry| expected = expected.add(try retirementSum(bus, entry.call.pc, entry.call.execution_clock));
    try std.testing.expectEqualDeep(expected, receipt.sum);
    std.debug.print("BLOCK_V5_CALLER_STATE same_roots=true independent_retirement_oracle=true callers={d} changed_claim_rejected=true complete=false\n", .{receipt.caller_count});
}

fn retirementSum(bus: anytype, pc: u32, clock: u32) !core.fields.qm31.QM31 {
    const Q = core.fields.qm31.QM31;
    const M = core.fields.m31.M31;
    const consumed = try bus.combineSecure(&.{ Q.fromBase(M.fromCanonical(pc)), Q.fromBase(M.fromCanonical(clock)) });
    const emitted = try bus.combineSecure(&.{ Q.fromBase(M.fromCanonical(pc + 4)), Q.fromBase(M.fromCanonical(clock + 1)) });
    return (try emitted.inv()).sub(try consumed.inv());
}
fn cloneState(a: std.mem.Allocator, proof: @import("../block_v5_precompile_state_request_proof_v1.zig").Proof) !@import("../block_v5_precompile_state_request_proof_v1.zig").Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.projection.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    const stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer {
        var owned = stark;
        owned.deinit(a);
    }
    return .{ .projection = .{ .stark = stark, .claims = try a.dupe(@import("../block_v5_program_extension_proof_v1.zig").Claim, proof.projection.claims) } };
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
