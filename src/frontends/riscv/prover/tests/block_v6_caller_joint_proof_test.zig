//! Genuine caller proof only: unrelated seal entries scope shared challenges,
//! and are deliberately not claimed as freshly verified global providers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Joint = @import("../block_v6_caller_joint_proof_v1.zig");
const Family = @import("../block_v5_precompile_family_proof_v1.zig");
const Fused = @import("../block_v5_caller_fused_proof_v1.zig");
const External = @import("../block_v5_external_memory_sidecar_proof_v1.zig");
const Schedule = @import("../block_v5_caller_fused_schedule_v1.zig").Schedule;
const Seal = @import("../block_v5_source_seal_v1.zig");

test "block-v6 caller joint actual SHA Keccak six commitments fresh verify and hostile claims" {
    try exercise(false);
}
test "block-v6 caller joint actual secp recovery Keccak six commitments fresh verify and hostile claims" {
    try exercise(true);
}
fn exercise(with_signer: bool) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const elf_mod = @import("../../runner/guest_precompile/test_elf.zig");
    const sha_diagnostic = elf_mod.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const sha_elf = elf_mod.withReleaseAbi(sha_diagnostic.len, &sha_diagnostic);
    const signer_diagnostic = elf_mod.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
    const signer_elf = elf_mod.withReleaseAbi(signer_diagnostic.len, &signer_diagnostic);
    const elf: []const u8 = if (with_signer) &signer_elf else &sha_elf;
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var setup = try session.startSegment(if (with_signer) 2 else 3);
    defer setup.deinit();
    var segment = try session.resumeSegment(setup.base.continuation.?, 4);
    defer segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, if (with_signer) 1 else 0), witness.statement.ethereum.counts.signer_calls);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = witness.total_steps };
    var physical = try Family.ForBackend(Cpu).commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
    defer physical.deinit(a);
    var counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var memory = try @import("../block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.init(a, &physical, &witness.statement, frame, 0, &counter);
    defer memory.deinit(a);
    const execution_id: [32]u8 = @splat(22);
    var first = try physical.bind(0, execution_id);
    defer first.deinit(a);
    var schedule = try Schedule.init(a, &witness.statement, witness.total_steps, frame, 0);
    defer schedule.deinit();
    const witness_root = memory.first.roots[2];
    var binding = @import("../block_v5_precompile_protocol_v1.zig").CallerBinding{ .execution_index = first.index, .caller_entry_index = first.index, .execution_instance_id = first.execution_instance_id, .caller_instance_id = first.instance_id, .caller_key_id = first.key_id, .first_roots = first.roots, .sealed_digest = @splat(0) };
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        first.entry(),
        Fused.entry(binding, witness_root, frame, 0, &schedule),
        External.packedEntry(execution_id, first.instance_id, first.key_id, first.roots, witness_root, 0, memory.slots),
    };
    var counts: [Seal.family_count]u32 = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const sealed = try Seal.seal(pins, &entries);
    binding = first.binding(sealed);
    const policy = Joint.Policy{ .statement = &witness.statement, .total_steps = witness.total_steps, .binding = binding, .witness_root = witness_root, .frame = frame, .sealed = sealed, .pins = pins, .entries = &entries };
    var proof = try Joint.ForBackend(Cpu).prove(a, &memory.first, &first, memory.inputs, policy, &pool);
    defer proof.deinit(a);
    try std.testing.expectEqual(@as(usize, 6), proof.stark.commitment_scheme_proof.commitments.items.len);
    var verified = try Joint.ForBackend(Cpu).verify(a, &proof, policy);
    defer verified.deinit(a);
    try std.testing.expectEqualDeep(binding, verified.binding);
    try std.testing.expect(verified.arithmetic_sum.eql(proof.arithmetic.componentSum()));
    var admitted = try @import("../block_v6_caller_joint_admission_v1.zig").Prepared.init(a, policy, .{});
    defer admitted.deinit();
    try admitted.validate();
    var short_claims = proof.relations;
    short_claims.memory_claims = short_claims.memory_claims[0 .. short_claims.memory_claims.len - 1];
    try std.testing.expectError(error.InvalidV5CallerCompositeClaims, @import("../block_v6_caller_joint_admission_v1.zig").EquationOwner.create(a, &admitted, &proof.arithmetic, &short_claims));
    const Codec = @import("../block_v6_caller_joint_codec_v1.zig");
    const encoded = try Codec.encode(a, &proof, &admitted, .{});
    defer a.free(encoded);
    var decoded = try Codec.decode(a, encoded, &admitted, .{});
    defer decoded.deinit(a);
    const reencoded = try Codec.encode(a, &decoded, &admitted, .{});
    defer a.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    var capture = try Joint.ForBackend(Cpu).verifyCapture(a, &decoded, admitted.policy());
    defer capture.deinit();
    try std.testing.expectEqual(@as(usize, 6), capture.proof.commitments.len);
    try std.testing.expectEqualDeep(proof.arithmetic, capture.arithmetic);
    try std.testing.expectEqualDeep(proof.relations, capture.claims);
    var recursive_capture = try @import("../block_v6_caller_joint_capture_v1.zig").ForBackend(Cpu).verify(a, &decoded, &admitted);
    defer recursive_capture.deinit();
    var composition = try @import("../../recursion/air/block_v6_caller_joint_composition_v1.zig").prepare(a, &admitted, &recursive_capture, admitted.template_id);
    defer composition.deinit();
    try composition.validate(a, &admitted, &recursive_capture, admitted.template_id);
    const evaluated = try a.alloc(core.fields.qm31.QM31, composition.values.len);
    defer a.free(evaluated);
    var changed_public = false;
    for (composition.sources, 0..) |source, i| if (source == .public_input) {
        const saved = composition.inputs[i];
        composition.inputs[i] = saved.add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, composition.circuit.evaluateInto(composition.inputs, evaluated));
        composition.inputs[i] = saved;
        changed_public = true;
        break;
    };
    try std.testing.expect(changed_public);
    try pcsLegs(a, &admitted, &recursive_capture, composition.circuit.graph(), with_signer);
    try transcriptLeg(a, &admitted, &recursive_capture);
    const wrong_wire = try a.dupe(u8, encoded);
    defer a.free(wrong_wire);
    wrong_wire[8] ^= 1;
    try std.testing.expectError(error.UntrustedJointCallerEnvelope, Codec.decode(a, wrong_wire, &admitted, .{}));
    try std.testing.expectError(error.JointCallerWireClaimLimit, Codec.decode(a, encoded, &admitted, .{ .max_claims = 1 }));
    // Independently execute the original arithmetic and fused proof routes.
    // Their roots and complete physical claims must match the conjunction;
    // proofs themselves intentionally differ because B6CJ1 has a new channel.
    var original_counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer original_counter.deinit(a);
    var original_memory = try @import("../block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.init(a, &first, &witness.statement, frame, 0, &original_counter);
    defer original_memory.deinit(a);
    try std.testing.expectEqualDeep(witness_root, original_memory.first.roots[2]);
    var original_fused = try Fused.ForBackend(Cpu).proveForCallerFirstRound(a, &original_memory.first, original_memory.inputs, &first, frame, witness_root, sealed, pins, &entries);
    defer original_fused.deinit(a);
    inline for (.{ "program_claims", "state_claims", "table_claims", "memory_claims" }) |field| try std.testing.expectEqualDeep(@field(original_fused, field), @field(proof.relations, field));
    var original_arithmetic = try Family.ForBackend(Cpu).prove(a, &first, sealed, pins, &entries, &pool);
    defer original_arithmetic.deinit(a);
    try std.testing.expectEqualDeep(original_arithmetic.claims, proof.arithmetic);
    var arithmetic_capture = try Family.ForBackend(Cpu).verifyCaptureBorrowed(a, &original_arithmetic, &witness.statement, witness.total_steps, binding.caller_key_id, execution_id, 0, sealed, pins, &entries);
    defer arithmetic_capture.deinit();
    var fused_capture = try Fused.ForBackend(Cpu).verifyCaptureBorrowedAfterFreshCaller(a, &original_fused, &arithmetic_capture.receipt, &witness.statement, witness.total_steps, frame, witness_root, sealed, pins, &entries);
    defer fused_capture.deinit();
    try std.testing.expect(verified.arithmetic_sum.eql(arithmetic_capture.receipt.open_sum));
    try std.testing.expectEqualDeep(verified.relations, fused_capture.receipt);
    // The original audit attack: opposite per-batch changes preserve the
    // aggregate, but must change the transcript and invalidate this proof.
    const batches = proof.arithmetic.ethereum.keccak_shard.batch_sums;
    const total = proof.arithmetic.componentSum();
    proof.arithmetic.ethereum.keccak_shard.batch_sums[0] = batches[0].add(core.fields.qm31.QM31.one());
    proof.arithmetic.ethereum.keccak_shard.batch_sums[1] = batches[1].sub(core.fields.qm31.QM31.one());
    try proof.arithmetic.validate(&witness.statement);
    try std.testing.expect(total.eql(proof.arithmetic.componentSum()));
    if (Joint.ForBackend(Cpu).verify(a, &proof, policy)) |unexpected| {
        var value = unexpected;
        value.deinit(a);
        return error.AcceptedCancellingPhysicalCallerClaims;
    } else |err| if (err == error.OutOfMemory) return err;
    proof.arithmetic.ethereum.keccak_shard.batch_sums = batches;
    try pointParity(a, policy, &proof);
    const original = proof.relations.program_claims[0].sum;
    proof.relations.program_claims[0].sum = original.add(core.fields.qm31.QM31.one());
    if (Joint.ForBackend(Cpu).verify(a, &proof, policy)) |unexpected| {
        var value = unexpected;
        value.deinit(a);
        return error.AcceptedChangedJointCallerClaim;
    } else |err| if (err == error.OutOfMemory) return err;
    proof.relations.program_claims[0].sum = original;
    var wrong = policy;
    wrong.witness_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEntry, Joint.ForBackend(Cpu).verify(a, &proof, wrong));
    std.debug.print("B6CJ1 signer={any} genuine_caller=true commitments=6 arithmetic_and_relations=true fresh_verified=true original_proof_parity=true cancelling_claim_attack_rejected=true global_closed=false\n", .{with_signer});
}

fn pointParity(a: std.mem.Allocator, policy: Joint.Policy, proof: *const Joint.Proof) !void {
    const C = core.air.components;
    const Profile = @import("../blake3_ethereum_sha_profile.zig");
    const Protocol = @import("../block_v5_precompile_protocol_v1.zig");
    var schedule = try Schedule.init(a, policy.statement, policy.total_steps, policy.frame, policy.sealed.register_custody_mode);
    defer schedule.deinit();
    const relations = try Protocol.drawRelations(a, policy.sealed);
    const word = try @import("../block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, policy.sealed);
    const memory = try @import("../block_memory_relation_v2.zig").Challenges.draw(a, policy.sealed);
    const original_arithmetic = try Profile.Assembly(.verifier).createBlockV5Standalone(a, policy.statement, policy.total_steps, &relations, &proof.arithmetic);
    defer original_arithmetic.destroy(a);
    const logs = try schedule.interactionLogs();
    defer a.free(logs);
    const access_logs = try schedule.witnessLogs();
    defer a.free(access_logs);
    const arithmetic_logs = try Protocol.columnLogs(a, policy.statement, .interaction);
    defer a.free(arithmetic_logs);
    var original_fused = try Fused.Components.init(a, &schedule, &proof.relations, &relations, &memory, &word, logs, access_logs, policy.sealed.register_custody_mode);
    defer original_fused.deinit();
    const fused_handles = try original_fused.verifier();
    defer a.free(fused_handles);
    const owner = try @import("../block_v6_caller_joint_components_v1.zig").Owner(false).create(a, original_arithmetic.active(), fused_handles, .{ schedule.fixed, schedule.main, access_logs, arithmetic_logs, logs }, original_fused.memory.len);
    defer owner.destroy();
    var count: usize = 0;
    for (original_arithmetic.active()) |h| count += h.nConstraints();
    for (fused_handles) |h| count += h.nConstraints();
    try std.testing.expectEqual(count, owner.nConstraints());
    const Q = core.fields.qm31.QM31;
    for ([_]Q{ Q.fromU32Unchecked(11, 23, 41, 79), Q.fromU32Unchecked(97, 53, 29, 17) }) |seed| {
        const point = core.circle.secureFieldPointFromRandomSeed(seed);
        const max_log = owner.bound - owner.split;
        var union_points = try owner.maskPoints(a, point, max_log);
        defer union_points.deinitDeep(a);
        var values = try sampleValues(a, &union_points, &.{ 0, 1, 2, 3, 4 });
        defer values.deinitDeep(a);
        var joint_accumulator = core.air.accumulation.PointEvaluationAccumulator.init(seed);
        try owner.evaluateConstraintQuotientsAtPoint(point, &values, &joint_accumulator, max_log);
        var original_accumulator = core.air.accumulation.PointEvaluationAccumulator.init(seed);
        inline for (.{ true, false }) |arithmetic| {
            const handles = if (arithmetic) original_arithmetic.active() else fused_handles;
            var points = try (C.Components{ .components = handles, .n_preprocessed_columns = schedule.fixed.len }).maskPoints(a, point, max_log, false);
            defer points.deinitDeep(a);
            var original_values = try sampleValues(a, &points, if (arithmetic) &.{ 0, 1, 3 } else &.{ 0, 1, 2, 4 });
            defer original_values.deinitDeep(a);
            for (handles) |h| try h.evaluateConstraintQuotientsAtPoint(point, &original_values, &original_accumulator, max_log);
        }
        try std.testing.expect(joint_accumulator.finalize().eql(original_accumulator.finalize()));
    }
}
fn sampleValues(a: std.mem.Allocator, points: *const core.air.components.MaskPoints, map: []const usize) !core.air.components.MaskValues {
    const Q = core.fields.qm31.QM31;
    const trees = try a.alloc([][]Q, points.items.len);
    @memset(trees, &.{});
    var result = core.air.components.MaskValues.initOwned(trees);
    errdefer result.deinitDeep(a);
    for (trees, points.items, map) |*tree, columns, mapped| {
        tree.* = try a.alloc([]Q, columns.len);
        @memset(tree.*, &.{});
        for (tree.*, columns, 0..) |*column, samples, c| {
            column.* = try a.alloc(Q, samples.len);
            const coefficient = Q.fromU32Unchecked(@intCast(c + 1), @intCast(mapped + 1), 13, 31);
            for (samples, column.*) |p, *value| value.* = coefficient.mul(p.x).add(p.y);
        }
    }
    return result;
}

fn pcsLegs(a: std.mem.Allocator, admitted: *const @import("../block_v6_caller_joint_admission_v1.zig").Prepared, captured: *const @import("../block_v6_caller_joint_capture_v1.zig").VerifiedCapture, composition: @import("../../recursion/air/composition_circuit.zig").CircuitGraph, signer: bool) !void {
    var shape = try @import("../../recursion/block_v6_caller_joint_pcs_shape_v1.zig").derive(a, admitted);
    defer shape.deinit();
    try std.testing.expectEqual(@as(usize, 6), shape.trees.len);
    const capture = &captured.original.proof;
    for (shape.columns, capture.column_log_sizes) |expected, actual| try std.testing.expectEqualSlices(u32, expected, actual);
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 2 << 30);
    defer budget.destroy();
    const scratch = budget.allocator();
    const Deep = @import("../../recursion/air/pcs_deep_circuit.zig");
    const Fri = @import("../../recursion/air/fri_verifier_circuit.zig");
    var deep = try Deep.build(scratch, shape.deepProfile());
    defer deep.deinit();
    var fri = try Fri.build(scratch, shape.friProfile());
    defer fri.deinit();
    {
        var inputs = try @import("../../recursion/pcs_arithmetic_capture.zig").Owned.init(scratch, shape.deepProfile(), capture.*);
        defer inputs.deinit();
        var evaluated = try deep.evaluate(scratch, inputs.inputs);
        defer evaluated.deinit();
        try evaluated.validateAgainst(&deep);
        const answers = try scratch.dupe(core.fields.qm31.QM31, inputs.inputs.answers);
        defer scratch.free(answers);
        var wrong = inputs.inputs;
        wrong.answers = answers;
        answers[0] = answers[0].add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, deep.evaluate(scratch, wrong));
    }
    {
        var inputs = try @import("../../recursion/fri_arithmetic_capture.zig").Owned.init(scratch, shape.friProfile(), capture.*);
        defer inputs.deinit();
        var evaluated = try fri.evaluate(scratch, inputs.inputs);
        defer evaluated.deinit();
        try evaluated.validateAgainst(&fri);
    }
    const Arithmetic = @import("../../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
    var joint = try Arithmetic.init(scratch, .{ composition, deep.graph(), fri.graph() });
    defer joint.deinit();
    std.debug.print("B6CJ_GEOMETRY signer={} family=joint composition_nodes={d} deep_nodes={d} fri_nodes={d} arithmetic_rows={any}\n", .{ signer, composition.nodes.len, deep.graph().nodes.len, fri.graph().nodes.len, joint.fused.counts });
    {
        const original = try @import("../../recursion/block_v6_provider_recursive_fixed_v1.zig").ForFamily(.caller_arithmetic).Owned.derive(a, &admitted.arithmetic, .{ .max_bytes = 2 << 30 });
        defer original.deinit();
        std.debug.print("B6CJ_GEOMETRY signer={} family=original_arithmetic composition_nodes={d} deep_nodes={d} fri_nodes={d} arithmetic_rows={any}\n", .{ signer, original.composition.circuit.graph().nodes.len, original.deep_graph.graph().nodes.len, original.fri_graph.graph().nodes.len, original.arithmetic.fused.counts });
    }
    {
        const original = try @import("../../recursion/block_v6_caller_fused_fixed_v1.zig").Owned.derive(a, &admitted.relations, captured.original.claims, .{ .max_bytes = 2 << 30 });
        defer original.deinit();
        std.debug.print("B6CJ_GEOMETRY signer={} family=original_fused composition_nodes={d} deep_nodes={d} fri_nodes={d} arithmetic_rows={any}\n", .{ signer, original.composition.circuit.graph().nodes.len, original.deep_graph.graph().nodes.len, original.fri_graph.graph().nodes.len, original.arithmetic.fused.counts });
    }
}
fn transcriptLeg(a: std.mem.Allocator, admitted: *const @import("../block_v6_caller_joint_admission_v1.zig").Prepared, captured: *const @import("../block_v6_caller_joint_capture_v1.zig").VerifiedCapture) !void {
    const Transcript = @import("../../recursion/air/block_v6_caller_joint_transcript_v1.zig");
    var plan = try Transcript.planReplay(a, admitted, captured, admitted.template_id, 2);
    defer plan.deinit();
    try std.testing.expectEqualDeep(captured.original.final_channel, plan.end);
    var cold = try @import("../../recursion/block_v6_caller_joint_fixed_transcript_v1.zig").derive(a, admitted, &captured.original.arithmetic, &captured.original.claims, 2, .{});
    defer cold.deinit();
    if (!std.meta.eql(plan.plan.id, cold.id)) {
        std.debug.print("B6CJ_TRANSCRIPT_MISMATCH live_hash={any} cold_hash={any} live_draws={d} cold_draws={d} live_outputs={d} cold_outputs={d}\n", .{ plan.plan.fixed.hashCounts(), cold.fixed.hashCounts(), plan.plan.fixed.next_draw, cold.fixed.next_draw, plan.plan.fixed.draw_outputs.len, cold.fixed.draw_outputs.len });
        for (plan.plan.fixed.draw_outputs, cold.fixed.draw_outputs, 0..) |live, fixed, i| if (!std.meta.eql(live, fixed)) {
            std.debug.print("B6CJ_FIRST_DRAW_MISMATCH index={d} live={any} fixed={any}\n", .{ i, live, fixed });
            break;
        };
        inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| {
            const live_rows = try plan.plan.fixed.nonhash_fixed.?.rows(slot);
            const cold_rows = try cold.fixed.nonhash_fixed.?.rows(slot);
            if (live_rows.len != cold_rows.len) std.debug.print("B6CJ_FIXED_LENGTH slot={d} live={d} cold={d}\n", .{ slot, live_rows.len, cold_rows.len });
            for (live_rows[0..@min(live_rows.len, cold_rows.len)], cold_rows[0..@min(live_rows.len, cold_rows.len)], 0..) |live, fixed, row| {
                if (!std.meta.eql(live, fixed)) {
                    std.debug.print("B6CJ_FIXED_DIFF slot={d} row={d} live={any} cold={any}\n", .{ slot, row, live, fixed });
                    break;
                }
            }
        }
    }
    try std.testing.expectEqualDeep(plan.plan.id, cold.id);
    try std.testing.expectEqualDeep(plan.plan.fixed.hashCounts(), cold.fixed.hashCounts());
    var seen: [66]bool = @splat(false);
    for (plan.operations) |op| if (op == .secure) {
        if (op.secure.output) |output| if (output == .universal) {
            try std.testing.expect(output.universal < seen.len);
            try std.testing.expect(!seen[output.universal]);
            seen[output.universal] = true;
        };
    };
    for (seen) |present| try std.testing.expect(present);
    // A physical-claim change must change the pre-interaction channel even
    // when its component aggregate is untouched. The full producer attack is
    // additionally rejected by fresh original verification below.
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const Statement = @import("../../recursion/air/block_v6_caller_joint_statement_v1.zig");
    var statement = try Statement.init(temp, admitted, &captured.original.arithmetic, &captured.original.claims);
    defer statement.deinit();
    statement.felts[0] = statement.felts[0].add(core.fields.qm31.QM31.one());
    var r = @import("../../recursion/air/blake3_native_recorder.zig").Recorder{ .a = temp, .universal_relations = true };
    _ = try Transcript.prefix(temp, &r, admitted, &statement);
    const original = try Joint.proofChannel(temp, admitted.policy(), &admitted.relations.schedule, &captured.original.arithmetic, &captured.original.claims);
    try std.testing.expect(!std.meta.eql(original, r.native));
}
