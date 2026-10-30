//! Finite roster qualification with original executed precompile workloads.
//! The native entry scopes the challenge only; this is not an execution root.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("../block_v7_execution_epoch_v1.zig");
const Caller = @import("../block_v7_caller_active_proof_v1.zig");
const Layout = @import("../block_v7_caller_active_layout_v1.zig").Layout;
const Baseline = @import("../block_v7_caller_joint_proof_v1.zig");
const Family = @import("../block_v5_precompile_family_proof_v1.zig");
const External = @import("../block_v5_caller_external_stage_v1.zig").ForBackend(Cpu);
const Kind = enum { sha, keccak, recovery, mixed, recovery_keccak };
test "active caller SHA-only genuine proof" {
    try run(.sha);
}
test "active caller Keccak-only genuine proof" {
    try run(.keccak);
}
test "active caller recovery-only genuine proof" {
    try run(.recovery);
}
test "active caller SHA Keccak mixed genuine proof" {
    try run(.mixed);
}
test "active caller recovery Keccak mixed genuine proof" {
    try run(.recovery_keccak);
}
fn run(kind: Kind) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const Elf = @import("../../runner/guest_precompile/test_elf.zig");
    const s = Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const sha = Elf.withReleaseAbi(s.len, &s);
    const r = Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
    const recovery = Elf.withReleaseAbi(r.len, &r);
    const signer = kind == .recovery or kind == .recovery_keccak;
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, if (signer) &recovery else &sha, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var start = try session.startSegment(if (signer) 2 else if (kind == .keccak) 4 else 3);
    defer start.deinit();
    var segment = try session.resumeSegment(start.base.continuation.?, if (kind == .mixed or kind == .recovery_keccak) 3 else 1);
    defer segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    defer witness.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = witness.total_steps };
    var counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const stage = try Caller.ForBackend(Cpu).Stage.init(a, &witness, frame, 0, config, &counter);
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const pin = stage.pin(0, @splat(42));
    // The mixed case also proves the original full roster under the same
    // Universal/word challenges. Extension challenges may differ by entry,
    // but every exported global relation must agree exactly.
    var baseline_physical: ?Family.ForBackend(Cpu).PhysicalFirstRound = null;
    defer if (baseline_physical) |*owned| owned.deinit(a);
    var baseline_memory: ?External.Prepared = null;
    defer if (baseline_memory) |*owned| owned.deinit(a);
    var baseline_pin: ?Baseline.Pin = null;
    if (kind == .mixed) {
        baseline_physical = try Family.ForBackend(Cpu).commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
        baseline_memory = try External.Prepared.initForMode(a, &baseline_physical.?, &witness.statement, frame, 1, &counter, 1);
        baseline_pin = .{ .index = 1, .execution_index = 0, .execution_identity = pin.execution_identity, .statement = pin.statement, .total_steps = pin.total_steps, .frame = frame, .roots = baseline_physical.?.roots, .access_root = baseline_memory.?.first.roots[2], .config = config };
    }
    var roster: [3]E.Entry = undefined;
    roster[0] = try E.Entry.init(.native, 0, pin.execution_identity, &.{@splat(7)});
    roster[1] = try pin.entry(a);
    if (baseline_pin) |bp| roster[2] = try bp.entry(a);
    const entries = roster[0 .. 2 + @as(usize, @intFromBool(baseline_pin != null))];
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    counts[@intFromEnum(E.Family.caller_fused)] = @intCast(entries.len - 1);
    const epoch = try E.Epoch.init(@splat(11), config, counts, entries, entries.len);
    const layout = stage.layout;
    try std.testing.expectEqual(signer, layout.active[3]);
    try std.testing.expectEqual(witness.statement.ethereum.counts.keccak_calls != 0, layout.active[0]);
    try std.testing.expect(layout.active[12]);
    for (layout.active[14..]) |present| try std.testing.expectEqual(witness.statement.sha.call_count != 0, present);
    var forged_layout = layout;
    forged_layout.active[if (signer) 3 else if (kind == .keccak) 0 else 14] = false;
    try std.testing.expectError(error.UntrustedActiveCallerLayout, forged_layout.require(&witness.statement, witness.total_steps));
    const Saved = @import("block_v7_caller_active_checkpoint_test_support.zig").Saved;
    var checkpoint: ?Saved = if (kind == .mixed or kind == .sha) try Saved.init(a, stage, pin) else null;
    defer if (checkpoint) |*saved| saved.deinit();
    var proof = try Caller.ForBackend(Cpu).prove(a, stage, pin, epoch, entries, &pool);
    defer proof.deinit(a);
    stage.deinit();
    stage_live = false;
    try @import("../block_v7_execution_test_support.zig").roundTrip(a, &proof.stark);
    var captured = try Caller.ForBackend(Cpu).verifyCapture(a, &proof, pin, epoch, entries);
    defer captured.deinit();
    const result = captured.receipt;
    if (checkpoint) |*saved| try saved.qualify(pin, epoch, entries, &proof, &pool);
    if (std.process.hasEnvVarConstant("STWO_V7_ACTIVE_CALLER_PARENT") or (kind == .keccak and std.process.hasEnvVarConstant("STWO_V7_ACTIVE_CALLER_COMPOSITION_ONLY"))) try @import("block_v7_caller_active_recursive_test_support.zig").qualify(a, pin, epoch, entries, &proof, @tagName(kind));
    if (baseline_pin) |bp| {
        var original = try Baseline.ForBackend(Cpu).prove(a, &baseline_memory.?.first, &baseline_physical.?, baseline_memory.?.inputs, bp, epoch, entries, &pool);
        defer original.deinit(a);
        var original_capture = try Baseline.ForBackend(Cpu).verifyCapture(a, &original, bp, epoch, entries);
        defer original_capture.deinit();
        try std.testing.expectEqualDeep(original_capture.receipt, result);
        std.debug.print("V7_ACTIVE_CALLER_DIFFERENTIAL global_exports_exact=true original_oods={d} active_oods={d}\n", .{ original_capture.proof.sampled_values.len, captured.proof.sampled_values.len });
    }
    try std.testing.expect(result.internal_residual.isZero());
    try std.testing.expectEqual(@as(u64, @import("../blake3_ethereum_sha_profile.zig").externalCount(&witness.statement)), result.fetch_count);
    const old = proof.arithmetic.ethereum.product_base.batch_sums;
    proof.arithmetic.ethereum.product_base.batch_sums[0] = old[0].add(core.fields.qm31.QM31.one());
    proof.arithmetic.ethereum.product_base.batch_sums[1] = old[1].sub(core.fields.qm31.QM31.one());
    if (Caller.ForBackend(Cpu).verify(a, &proof, pin, epoch, entries)) |_| return error.AcceptedActiveCallerClaimForgery else |err| if (err == error.OutOfMemory) return err;
    proof.arithmetic.ethereum.product_base.batch_sums = old;
    var wrong = pin;
    wrong.access_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7SourceEntry, Caller.ForBackend(Cpu).verify(a, &proof, wrong, epoch, entries));
    if (kind == .sha or kind == .mixed) {
        const saved = proof.arithmetic.sha;
        proof.arithmetic.sha[0] = saved[0].add(core.fields.qm31.QM31.one());
        proof.arithmetic.sha[1] = saved[1].sub(core.fields.qm31.QM31.one());
        try proof.arithmetic.validate(&witness.statement);
        try std.testing.expectError(error.OodsNotMatching, Caller.ForBackend(Cpu).verify(a, &proof, pin, epoch, entries));
        proof.arithmetic.sha = saved;
    }
    if (witness.statement.sha.call_count == 0) {
        const saved = proof.arithmetic.sha;
        // Preserve the aggregate while forging two omitted physical claims.
        proof.arithmetic.sha[0] = core.fields.qm31.QM31.one();
        proof.arithmetic.sha[1] = core.fields.qm31.QM31.one().neg();
        try std.testing.expectError(error.NonzeroOmittedCallerClaim, Caller.ForBackend(Cpu).verify(a, &proof, pin, epoch, entries));
        proof.arithmetic.sha = saved;
        for (layout.active[14..]) |present| try std.testing.expect(!present);
    }
    // A producer may rewrite every self-consistent metadata copy. The fixed
    // commitment must still equal the independently reconstructed layout.
    wrong = pin;
    wrong.roots[0][0] ^= 1;
    const saved_root = proof.stark.commitment_scheme_proof.commitments.items[0];
    proof.stark.commitment_scheme_proof.commitments.items[0] = wrong.roots[0];
    const saved_entry = roster[1];
    roster[1] = try wrong.entry(a);
    const wrong_epoch = try E.Epoch.init(@splat(11), config, counts, entries, entries.len);
    try std.testing.expectError(error.UntrustedV7CallerFixedRoot, Caller.ForBackend(Cpu).verify(a, &proof, wrong, wrong_epoch, entries));
    proof.stark.commitment_scheme_proof.commitments.items[0] = saved_root;
    roster[1] = saved_entry;
    std.debug.print("V7_ACTIVE_CALLER kind={s} original_main={d} main={d} original_interaction={d} interaction={d} oods_values={d} fresh_verified=true internal_closed=true global_closed=false\n", .{ @tagName(kind), layout.original_totals[1], layout.totals[1], layout.original_totals[2], layout.totals[2], captured.proof.sampled_values.len });
}
