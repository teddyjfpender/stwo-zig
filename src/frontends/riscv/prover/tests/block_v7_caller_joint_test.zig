//! Actual caller STARK qualification. The placeholder native entry only scopes
//! this isolated challenge epoch; it is not a complete execution-root claim.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("../block_v7_execution_epoch_v1.zig");
const Caller = @import("../block_v7_caller_joint_proof_v1.zig");
const Family = @import("../block_v5_precompile_family_proof_v1.zig");
test "v7 genuine joint SHA Keccak under exact epoch and hostile claims" {
    try run(false);
}
test "v7 genuine joint recovery Keccak under exact epoch and hostile claims" {
    try run(true);
}
fn run(signer: bool) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const elf_mod = @import("../../runner/guest_precompile/test_elf.zig");
    const sha_source = elf_mod.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const sha = elf_mod.withReleaseAbi(sha_source.len, &sha_source);
    const signer_source = elf_mod.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
    const recover = elf_mod.withReleaseAbi(signer_source.len, &signer_source);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, if (signer) &recover else &sha, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var start = try session.startSegment(if (signer) 2 else 3);
    defer start.deinit();
    var segment = try session.resumeSegment(start.base.continuation.?, 4);
    defer segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, if (signer) 1 else 0), witness.statement.ethereum.counts.signer_calls);
    // Geometry evidence only: absent-family columns remain fully proved.
    // Their padded claims can be nonzero; this census never removes them.
    const P = @import("../blake3_ethereum_sha_profile.zig");
    var dormant_cells: u64 = 0;
    var total_cells: u64 = 0;
    for (P.descriptors(&witness.statement), 0..) |descriptor, component| {
        const width: u64 = @as(u64, descriptor.preprocessed_columns) + descriptor.main_columns + descriptor.interaction_columns;
        const cells = width << @intCast(descriptor.log_size);
        total_cells += cells;
        const absent = if (component < 3) witness.statement.ethereum.counts.keccak_calls == 0 else if (component < 14) witness.statement.ethereum.counts.signer_calls == 0 else witness.statement.sha.call_count == 0;
        if (absent) dormant_cells += cells;
    }
    std.debug.print("V7_CALLER_GEOMETRY signer={} original_cells={d} absent_family_cells={d} all_columns_retained=true\n", .{ signer, total_cells, dormant_cells });
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var physical = try Family.ForBackend(Cpu).commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
    defer physical.deinit(a);
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = witness.total_steps };
    var counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var memory = try @import("../block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.initForMode(a, &physical, &witness.statement, frame, 0, &counter, 1);
    defer memory.deinit(a);
    const pin = Caller.Pin{ .index = 0, .execution_index = 0, .execution_identity = @splat(42), .statement = &witness.statement, .total_steps = witness.total_steps, .frame = frame, .roots = physical.roots, .access_root = memory.first.roots[2], .config = config };
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, pin.execution_identity, &.{@splat(7)}), try pin.entry(a) };
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    counts[@intFromEnum(E.Family.caller_fused)] = 1;
    const epoch = try E.Epoch.init(@splat(11), config, counts, &entries, entries.len);
    var proof = try Caller.ForBackend(Cpu).prove(a, &memory.first, &physical, memory.inputs, pin, epoch, &entries, &pool);
    defer proof.deinit(a);
    if (std.process.hasEnvVarConstant("STWO_V7_CALLER_RECURSIVE")) {
        const Admission = @import("../block_v7_caller_joint_admission_v1.zig");
        const Capture = @import("../block_v7_caller_joint_capture_v1.zig");
        var admitted = try Admission.Prepared.init(a, pin, epoch, &entries, .{});
        defer admitted.deinit();
        var captured = try Capture.ForBackend(Cpu).verify(a, &proof, &admitted);
        defer captured.deinit();
        var shape = try @import("../../recursion/block_v7_caller_joint_pcs_shape_v1.zig").derive(a, &admitted);
        defer shape.deinit();
        try shape.deepProfile().validate();
        try shape.friProfile().validate();
        var composition = try @import("../../recursion/air/block_v7_caller_joint_composition_v1.zig").prepare(a, &admitted, &captured, admitted.template_id);
        defer composition.deinit();
        try composition.circuit.evaluateInto(composition.inputs, composition.values);
        var transcript = try @import("../../recursion/air/block_v7_caller_joint_transcript_v1.zig").planReplay(a, &admitted, &captured, admitted.template_id, 4);
        defer transcript.deinit();
        var cold_transcript = try @import("../../recursion/block_v7_caller_joint_fixed_transcript_v1.zig").derive(a, &admitted, &captured.original.arithmetic, &captured.original.claims, 4, .{});
        defer cold_transcript.deinit();
        try std.testing.expectEqualDeep(transcript.plan.id, cold_transcript.id);
        try std.testing.expectEqualDeep(transcript.plan.fixed.hashCounts(), cold_transcript.fixed.hashCounts());
        var cold_equations = try @import("../../recursion/air/block_v7_caller_joint_composition_v1.zig").compile(a, &admitted, &captured.original.arithmetic, &captured.original.claims);
        defer cold_equations.deinit();
        try std.testing.expectEqualDeep(composition.circuit.identity_digest, cold_equations.circuit.identity_digest);
        try std.testing.expectEqualDeep(composition.sources, cold_equations.sources);
        if (std.process.hasEnvVarConstant("STWO_V7_CALLER_PARENT")) {
            var prepared = try @import("../../recursion/block_v7_caller_joint_preparation_v1.zig").prepare(a, &admitted, &captured, 4, .{});
            var prepared_live = true;
            defer if (prepared_live) prepared.deinit();
            var fixed = try @import("../../recursion/block_v7_caller_joint_fixed_roster_v1.zig").Owned.derive(a, .{ .pin = admitted.pin(), .epoch = admitted.epoch, .entries = admitted.entries, .arithmetic = captured.original.arithmetic, .claims = captured.original.claims }, 4, .{});
            defer fixed.deinit();
            try fixed.validateLive(&prepared);
            if (std.process.hasEnvVarConstant("STWO_V7_CALLER_PROVE_PARENT")) {
                try qualifyParent(a, &admitted, &captured, &prepared, &prepared_live, &fixed);
            }

            std.debug.print("V7_CALLER_FULL_FIXED exact_roster_equal=true six_paths=true parent_proof_qualified={}\n", .{std.process.hasEnvVarConstant("STWO_V7_CALLER_PROVE_PARENT")});
        }
        var rejected: usize = 0;
        var public_count: usize = 0;
        for (composition.sources) |source| switch (source) {
            .public_input => public_count += 1,
            else => {},
        };
        var public_index: usize = 0;
        const mutation_stride = @max(@as(usize, 1), public_count / 16);
        for (composition.sources, 0..) |source, i| switch (source) {
            .public_input => {
                public_index += 1;
                if (public_index % mutation_stride != 0) continue;
                const saved = composition.inputs[i];
                composition.inputs[i] = saved.add(core.fields.qm31.QM31.one());
                if (composition.circuit.evaluateInto(composition.inputs, composition.values)) |_| {} else |_| {
                    rejected += 1;
                }
                composition.inputs[i] = saved;
            },
            else => {},
        };
        try std.testing.expect(rejected > 0);
        try composition.circuit.evaluateInto(composition.inputs, composition.values);
        std.debug.print("V7_CALLER_RECURSIVE signer={} composition_rows={d} rejected_public_mutations={d} exact_transcript=true cold_fixed_equal=true full_execution_qualified=false\n", .{ signer, composition.circuit.nodes.len, rejected });
    }

    try std.testing.expectEqual(@as(usize, 6), proof.stark.commitment_scheme_proof.commitments.items.len);
    const verified = try Caller.ForBackend(Cpu).verify(a, &proof, pin, epoch, &entries);
    try std.testing.expect(verified.internal_residual.isZero());
    try std.testing.expectEqual(@as(u64, @import("../blake3_ethereum_sha_profile.zig").externalCount(&witness.statement)), verified.fetch_count);
    try std.testing.expectEqual(try @import("../block_execution_external_trace_v2.zig").expectedEventCountForMode(&witness.statement, 1), verified.event_count);
    var wrong = pin;
    wrong.execution_identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7SourceEntry, Caller.ForBackend(Cpu).verify(a, &proof, wrong, epoch, &entries));
    wrong = pin;
    wrong.access_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7SourceEntry, Caller.ForBackend(Cpu).verify(a, &proof, wrong, epoch, &entries));
    const old = proof.arithmetic.ethereum.keccak_shard.batch_sums;
    const total = proof.arithmetic.componentSum();
    proof.arithmetic.ethereum.keccak_shard.batch_sums[0] = old[0].add(core.fields.qm31.QM31.one());
    proof.arithmetic.ethereum.keccak_shard.batch_sums[1] = old[1].sub(core.fields.qm31.QM31.one());
    try proof.arithmetic.validate(&witness.statement);
    try std.testing.expect(total.eql(proof.arithmetic.componentSum()));
    if (Caller.ForBackend(Cpu).verify(a, &proof, pin, epoch, &entries)) |_| return error.AcceptedV7CancellingCallerClaims else |err| if (err == error.OutOfMemory) return err;
    proof.arithmetic.ethereum.keccak_shard.batch_sums = old;
    std.debug.print("V7_CALLER signer={} fresh_verified=true six_commitments=true epoch_bound=true internal_closed=true global_closed=false events={d}\n", .{ signer, verified.event_count });
}

fn qualifyParent(a: std.mem.Allocator, admitted: *const @import("../block_v7_caller_joint_admission_v1.zig").Prepared, captured: *const @import("../block_v7_caller_joint_capture_v1.zig").VerifiedCapture, prepared: *@import("../../recursion/block_v7_caller_joint_preparation_v1.zig").Prepared, prepared_live: *bool, fixed: *const @import("../../recursion/block_v7_caller_joint_fixed_roster_v1.zig").Owned) !void {
    const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
    const Protocol = @import("../../recursion/block_v7_caller_joint_parent_protocol_v1.zig");
    const Receiver = @import("../../recursion/block_v7_caller_joint_receiver_v1.zig");
    const Profile = @import("../../recursion/block_v7_caller_joint_fixed_profile_v1.zig");
    const input = Profile.Input{ .pin = admitted.pin(), .epoch = admitted.epoch, .entries = admitted.entries, .arithmetic = captured.original.arithmetic, .claims = captured.original.claims };
    const profile = try Profile.Owned.derive(a, input, .{});
    defer profile.deinit();
    const expected_base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, fixed.fixed, fixed.context, .diagnostic_q8_pow0);
    const roster = [_]Protocol.Bus.Expected{.{ .profile = admitted.template_id, .epoch = admitted.epoch.digest, .roots = admitted.source.roots ++ .{admitted.source.access_root} }};
    const key = try Protocol.Key.fromGeometry(expected_base, fixed.wires, &roster);
    const parent_admission = try Protocol.Admission.init(key, try key.identity(), prepared.wires, .{ .children = &.{prepared.values} }, &roster);
    const Producer = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const producer = try Producer.init(a, &prepared.recursive.rows, parent_admission);
    var producer_live = true;
    defer if (producer_live) producer.deinit();
    var parent = try producer.prove(a, &prepared.recursive.rows);
    var parent_live = true;
    defer if (parent_live) parent.deinit();
    const bytes = try Parent.codec.encode(a, &parent, &parent_admission);
    defer a.free(bytes);
    parent.deinit();
    parent_live = false;
    producer.deinit();
    producer_live = false;
    prepared.deinit();
    prepared_live.* = false;
    var verified = try Receiver.verify(a, bytes, profile, key, fixed.wires);
    defer verified.deinit();
    try std.testing.expectEqualDeep(captured.original.receipt, verified.open);
    var forged_input = input;
    forged_input.arithmetic.ethereum.keccak_shard.batch_sums[0] = forged_input.arithmetic.ethereum.keccak_shard.batch_sums[0].add(core.fields.qm31.QM31.one());
    forged_input.arithmetic.ethereum.keccak_shard.batch_sums[1] = forged_input.arithmetic.ethereum.keccak_shard.batch_sums[1].sub(core.fields.qm31.QM31.one());
    const forged = try Profile.Owned.derive(a, forged_input, .{});
    defer forged.deinit();
    try std.testing.expectEqualDeep(profile.seal, forged.seal);
    try std.testing.expectError(error.InvalidProviderBatchPublicClosure, Receiver.verify(a, bytes, forged, key, fixed.wires));
    const Public = @import("../../recursion/block_v7_caller_joint_public_v1.zig");
    var expected = try Public.reconstruct(a, admitted, &input.arithmetic, &input.claims);
    defer expected.deinit();
    var mutated = try expected.clone(a);
    defer mutated.deinit();
    mutated.statement.roots_offset[2] += 1;
    try std.testing.expectError(error.UntrustedV7CallerPublicFrame, Public.requireSameFrame(mutated, expected));
    var bad_key = key;
    bad_key.preprocessed_root[0] ^= 1;
    if (Receiver.verify(a, bytes, profile, bad_key, fixed.wires)) |bad| {
        var rejected = bad;
        rejected.deinit();
        return error.AcceptedV7CallerWrongParentKey;
    } else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("V7_CALLER_PARENT proof_bytes={d} independent_cold_key=true detached_verified=true compensated_claims_rejected=true root_offset_rejected=true global_relations_open=true\n", .{bytes.len});
}
