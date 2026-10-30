//! Genuine OPEN caller STARK, with original arithmetic and exact RAM
//! projections sharing columns. No integer-copy or WORD sidecar is built.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const P = @import("../blake3_ethereum_sha_profile.zig");
const Layout = @import("../block_v7_caller_active_layout_v1.zig").Layout;
const Ram = @import("../block_v8_caller_ram_owner_v1.zig");
const Projection = @import("../block_v8_caller_ram_projection_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Fused = @import("../block_v5_caller_fused_proof_v1.zig");
const Frame = @import("../../air/block/memory_event.zig").Frame;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
fn fresh(a: std.mem.Allocator, proof: *const S.Proof, statement: *const P.admission.Statement, steps: u32, frame: Frame, epoch: E.Epoch, arithmetic_claims: *const P.ExtensionClaim, ram_sums: []const Q, basic_claims: ?*const Fused.ClaimFrames, roots: [3][32]u8, config: core.pcs.PcsConfig) !void {
    const drawn = try epoch.draw(a);
    var extension_channel = drawn.channel;
    extension_channel.mixU32s(&.{ 0x42384344, 1 });
    const relations = try P.Relations.drawAfterVm(a, &extension_channel, drawn.word.universal_prefix);
    const owner = if (basic_claims) |claims|
        try Ram.Owner(false).initComplete(a, statement, steps, frame, &drawn, &relations, arithmetic_claims, ram_sums, claims)
    else
        try Ram.Owner(false).init(a, statement, steps, frame, &drawn, &relations, arithmetic_claims, ram_sums);
    defer owner.deinit();
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != 6 or !std.meta.eql(commitments[0..3].*, roots) or !std.meta.eql(config, proof.commitment_scheme_proof.config)) return error.UntrustedCallerRamOriginalProof;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const raw = arena.allocator();
    const original = try P.preprocessed(raw, statement);
    const fixed_columns = try owner.layout.columns(raw, 0, original);
    var fixed = try Scheme.init(a, config);
    defer fixed.deinit(a);
    var ignored = S.Channel{};
    try fixed.commitBorrowedStreaming(a, fixed_columns, 8, &ignored);
    if (!std.meta.eql(fixed.trees.items[0].root(), roots[0])) return error.UntrustedCallerRamFixedRoot;
    var channel = extension_channel;
    if (basic_claims) |claims| try Ram.recordCompleteClaims(&channel, &owner.layout, &owner.schedule, arithmetic_claims, claims, ram_sums) else try Ram.recordClaims(&channel, &owner.layout, arithmetic_claims, ram_sums);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, config);
    defer verifier.deinit(a);
    try verifier.commit(a, commitments[0], owner.schedule.fixed, &ignored);
    try verifier.commit(a, commitments[1], owner.schedule.main, &ignored);
    try verifier.commit(a, commitments[2], &.{}, &ignored);
    try verifier.commit(a, commitments[3], owner.arithmetic_logs, &channel);
    try verifier.commit(a, commitments[4], owner.ram_logs, &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, &.{owner.context.asVerifierComponent()}, &channel, &verifier, proof, &capture);
    defer capture.deinit(a);
    if (basic_claims) |claims| {
        const open = try Ram.closeComplete(&owner.schedule, arithmetic_claims, claims, ram_sums);
        try std.testing.expect(open.internal_residual.isZero());
    }
}
pub const Kind = enum { keccak, sha, recovery };
pub fn run(comptime kind: Kind) !void {
    return runInternal(kind, false);
}
pub fn runComplete(comptime kind: Kind) !void {
    return runInternal(kind, true);
}
fn runInternal(comptime kind: Kind, comptime complete_projection: bool) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const Elf = @import("../../runner/guest_precompile/test_elf.zig");
    const source = Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = Elf.withReleaseAbi(source.len, &source);
    const recovery_source = Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
    const recovery_elf = Elf.withReleaseAbi(recovery_source.len, &recovery_source);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, if (kind == .recovery) &recovery_elf else &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var start = try session.startSegment(if (kind == .keccak) 4 else if (kind == .sha) 3 else 2);
    defer start.deinit();
    var segment = try session.resumeSegment(start.base.continuation.?, 1);
    defer segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &segment);
    var witness_live = true;
    defer if (witness_live) witness.deinit();
    if (kind == .keccak) try std.testing.expectEqual(@as(u32, 1), witness.statement.ethereum.counts.keccak_calls);
    if (kind == .sha) try std.testing.expectEqual(@as(u32, 1), witness.statement.sha.call_count);
    if (kind == .recovery) try std.testing.expectEqual(@as(u32, 1), witness.statement.ethereum.counts.signer_calls);
    const statement = witness.statement;
    const steps = witness.total_steps;
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = steps };
    const layout = try Layout.derive(&statement, steps);
    var plan = try Projection.Plan.derive(a, &statement, steps, frame);
    defer plan.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    var arena_live = true;
    defer if (arena_live) arena.deinit();
    const raw = arena.allocator();
    const original_fixed = try P.preprocessed(raw, &statement);
    const original_main = try P.mainWitness(raw, &witness);
    const fixed = try layout.columns(raw, 0, original_fixed);
    const main = try layout.columns(raw, 1, original_main.columns);
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var scheme = try Scheme.init(a, config);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    var first_channel = S.Channel{};
    first_channel.mixU32s(&.{ 0x42384346, 1 });
    try scheme.commitBorrowedStreaming(a, fixed, 8, &first_channel);
    try scheme.commitBorrowedStreaming(a, main, 8, &first_channel);
    // This canonical empty tree is an adapter artifact, not an access witness.
    try scheme.commitBorrowedStreaming(a, &.{}, 8, &first_channel);
    var first_roots = try scheme.roots(a);
    defer first_roots.deinit(a);
    const roots = first_roots.items[0..3].*;
    first_channel.mixRoot(try @import("../block_v5_precompile_protocol_v1.zig").keyId(&statement, steps, config, roots[0]));
    first_channel.mixU32s(&.{ @intFromEnum(frame.clock_frame), frame.cycle_count });
    first_channel.mixU64(frame.global_first_cycle);
    const entries = [_]E.Entry{try E.Entry.init(.caller_fused, 0, first_channel.digestBytes(), &roots)};
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.caller_fused)] = 1;
    const epoch = try E.Epoch.init(@splat(29), config, counts, &entries, 1);
    const drawn = try epoch.draw(a);
    var extension_channel = drawn.channel;
    extension_channel.mixU32s(&.{ 0x42384344, 1 });
    const relations = try P.Relations.drawAfterVm(a, &extension_channel, drawn.word.universal_prefix);
    var arithmetic = try @import("../block_v7_caller_active_columns_v1.zig").interactions(a, &witness, &relations, &pool);
    var arithmetic_live = true;
    defer if (arithmetic_live) arithmetic.deinit(a);
    const arithmetic_claims = arithmetic.claim;
    const arithmetic_columns = try layout.columns(raw, 2, arithmetic.columns);
    var ram = if (complete_projection) try Ram.CompleteInteractions.generate(a, &plan, &statement, steps, frame, fixed, main, &drawn, &relations) else try Ram.Interactions.generate(a, &plan, fixed, main, &drawn);
    var ram_live = true;
    defer if (ram_live) ram.deinit();
    const ram_sums = try a.dupe(Q, if (complete_projection) ram.ram.sums else ram.sums);
    var basic_claims: ?Fused.ClaimFrames = if (complete_projection) try Fused.ClaimFrames.clone(a, &ram.basic.claims) else null;
    defer if (basic_claims) |*claims| claims.deinit(a);
    const basic_pointer = if (basic_claims) |*claims| claims else null;
    defer a.free(ram_sums);
    var forged_relations = relations;
    forged_relations.ethereum.base.memory_access.z = forged_relations.ethereum.base.memory_access.z.add(Q.one());
    try std.testing.expectError(error.UntrustedCallerRamRelations, Ram.Owner(true).init(a, &statement, steps, frame, &drawn, &forged_relations, &arithmetic_claims, ram_sums));
    const owner = if (basic_pointer) |claims| try Ram.Owner(true).initComplete(a, &statement, steps, frame, &drawn, &relations, &arithmetic_claims, ram_sums, claims) else try Ram.Owner(true).init(a, &statement, steps, frame, &drawn, &relations, &arithmetic_claims, ram_sums);
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    try std.testing.expectEqual(@as(usize, 0), owner.context.logs.items[2].len);
    var channel = extension_channel;
    if (basic_pointer) |claims| {
        _ = try Ram.closeComplete(&owner.schedule, &arithmetic_claims, claims, ram_sums);
        try Ram.recordCompleteClaims(&channel, &layout, &owner.schedule, &arithmetic_claims, claims, ram_sums);
    } else try Ram.recordClaims(&channel, &layout, &arithmetic_claims, ram_sums);
    try scheme.commitBorrowedStreaming(a, arithmetic_columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, ram.columns, 8, &channel);
    scheme_live = false;
    var proof = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, &.{owner.context.asProverComponent()}, &channel, scheme);
    defer proof.deinit(a);
    owner.deinit();
    owner_live = false;
    ram.deinit();
    ram_live = false;
    arithmetic.deinit(a);
    arithmetic_live = false;
    arena.deinit();
    arena_live = false;
    witness.deinit();
    witness_live = false;
    try fresh(a, &proof, &statement, steps, frame, epoch, &arithmetic_claims, ram_sums, basic_pointer, roots, config);
    var forged_arithmetic = arithmetic_claims;
    forged_arithmetic.ethereum.product_base.batch_sums[0] = forged_arithmetic.ethereum.product_base.batch_sums[0].add(Q.one());
    forged_arithmetic.ethereum.product_base.batch_sums[1] = forged_arithmetic.ethereum.product_base.batch_sums[1].sub(Q.one());
    if (fresh(a, &proof, &statement, steps, frame, epoch, &forged_arithmetic, ram_sums, basic_pointer, roots, config)) |_| return error.AcceptedCallerArithmeticClaimForgery else |err| if (err == error.OutOfMemory) return err;
    if (basic_pointer) |claims| {
        const program = claims.program_claims[0].sum;
        const state = claims.state_claims[0].sum;
        claims.program_claims[0].sum = program.add(Q.one());
        claims.state_claims[0].sum = state.sub(Q.one());
        if (fresh(a, &proof, &statement, steps, frame, epoch, &arithmetic_claims, ram_sums, basic_pointer, roots, config)) |_| return error.AcceptedCallerBasicClaimForgery else |err| if (err == error.OutOfMemory) return err;
        claims.program_claims[0].sum = program;
        claims.state_claims[0].sum = state;
    }
    try std.testing.expect(ram_sums.len > 1);
    ram_sums[0] = ram_sums[0].add(Q.one());
    ram_sums[1] = ram_sums[1].sub(Q.one());
    if (fresh(a, &proof, &statement, steps, frame, epoch, &arithmetic_claims, ram_sums, basic_pointer, roots, config)) |_| return error.AcceptedCallerRamClaimForgery else |err| if (err == error.OutOfMemory) return err;
}
