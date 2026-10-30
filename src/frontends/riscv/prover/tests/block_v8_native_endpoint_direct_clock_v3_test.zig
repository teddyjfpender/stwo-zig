//! Actual native RAM execution and one original STARK with direct typed AIR
//! plus every V8 projection, and NO WORD access sidecar. Global providers and
//! endpoint AIR are not included here; this is deliberately an OPEN proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Components = @import("../block_v8_native_endpoint_components_v1.zig");
const Closure = @import("../block_v8_native_endpoint_closure_v1.zig");
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Halt = @import("../block_v8_native_halt_policy_v1.zig");
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
fn verifyFresh(a: std.mem.Allocator, proof: *const S.Proof, shape: *const Shape, claims: []const Components.Claim, drawn: *const E.Drawn, config: core.pcs.PcsConfig, first_roots: [2][32]u8, halt: ?Halt.Policy) !void {
    const owner = try Components.Owner.initDirectRamV3(a, shape, claims, drawn, halt.?);
    defer owner.deinit();
    var joined = try owner.verifying();
    defer joined.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(roots[0..2].*, first_roots) or !std.meta.eql(config, proof.commitment_scheme_proof.config)) return error.UntrustedOpenEndpointNativeProof;
    var fixed_columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer {
        for (fixed_columns.items) |column| a.free(column.values);
        fixed_columns.deinit(a);
    }
    try @import("../blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, shape, 0, &fixed_columns);
    var fixed = try Scheme.init(a, config);
    defer fixed.deinit(a);
    var ignored = S.Channel{};
    try fixed.commitBorrowedStreaming(a, fixed_columns.items, 8, &ignored);
    if (!std.meta.eql(fixed.trees.items[0].root(), roots[0])) return error.UntrustedOpenEndpointNativeFixedRoot;
    var channel = drawn.channel;
    try Components.recordClaims(&channel, owner.layout.digest, claims);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, config);
    defer verifier.deinit(a);
    try verifier.commit(a, roots[0], owner.fixed, &ignored);
    try verifier.commit(a, roots[1], owner.main, &ignored);
    try verifier.commit(a, roots[2], owner.interactions, &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, joined.handles, &channel, &verifier, proof, &capture);
    defer capture.deinit(a);
}
test "direct RAM V3 genuine original q70 retains exact CPU RAM HALT and all physical claims" {
    try run(.{ .halt_address = 0x100200 });
}
fn run(halt: ?Halt.Policy) !void {
    const a = std.testing.allocator;
    const code = [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .direct_ram_max_clock = 1 << 26 });
    defer session.deinit();
    var segment = try session.startSegment(code.len - 1);
    defer segment.deinit();
    try std.testing.expectEqual(@as(u32, 63), segment.exit_cpu.regs[9]);
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(7) };
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const native = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.execution_trace, io.data, &segment.state_chain_tracker, 0);
    var native_live = true;
    defer if (native_live) native.deinit();
    try native.sealNativeOnly();
    const shape = native.statement;
    var guarded: ?Halt.Owned = if (halt) |policy| try Halt.prepare(a, &shape, native.main.items, policy) else null;
    defer if (guarded) |*value| value.deinit();
    var gap_stage = try @import("../block_v8_ram_clock_v3_stage.zig").prepare(a, &shape, guarded.?.columns);
    defer gap_stage.deinit();
    const main = gap_stage.columns;
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var scheme = try Scheme.init(a, config);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    var first_channel = S.Channel{};
    first_channel.mixU32s(&.{ 0x42384f54, 1 });
    try scheme.commitBorrowedStreaming(a, native.preprocessed.items, 8, &first_channel);
    try scheme.commitBorrowedStreaming(a, main, 8, &first_channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    const first_roots = roots.items[0..2].*;
    const entries = [_]E.Entry{try E.Entry.init(.native, 0, first_channel.digestBytes(), &first_roots)};
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    const epoch = try E.Epoch.init(@splat(19), config, counts, &entries, 1);
    const drawn = try epoch.draw(a);
    var interaction = try @import("../block_v8_native_endpoint_interactions_v3.zig").generate(a, &shape, main, &drawn);
    var interaction_live = true;
    defer if (interaction_live) interaction.deinit();
    const claims = try a.dupe(Components.Claim, interaction.claims);
    defer a.free(claims);
    const owner = try Components.Owner.initDirectRamV3(a, &shape, claims, &drawn, halt.?);
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    if (halt != null) {
        try std.testing.expectEqual(Halt.count(&shape), owner.guards.len);
        for (owner.guards) |guard| try std.testing.expectEqual(Halt.CONSTRAINT_COUNT, guard.nConstraints());
        try std.testing.expectEqual(native.main.items.len + 5 * owner.guards.len, owner.main.len);
    }
    var joined = try owner.proving();
    var joined_live = true;
    defer if (joined_live) joined.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), segment.state_chain_tracker.clock_updates_mem.items.len);
    try std.testing.expectEqual(owner.layout.slots.len + owner.clock_v3.len, claims.len);
    var channel = drawn.channel;
    try Components.recordClaims(&channel, owner.layout.digest, claims);
    try scheme.commitBorrowedStreaming(a, interaction.columns, 8, &channel);
    scheme_live = false;
    var proof = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, joined.handles, &channel, scheme);
    defer proof.deinit(a);
    // Fresh verification owns no producer columns, projections or key objects.
    joined.deinit(a);
    joined_live = false;
    owner.deinit();
    owner_live = false;
    interaction.deinit();
    interaction_live = false;
    native.deinit();
    native_live = false;
    try verifyFresh(a, &proof, &shape, claims, &drawn, config, first_roots, halt);
    if (halt != null) {
        // Same committed native arithmetic and auxiliaries; changing just the
        // independently derived policy must fail the original verifier.
        if (verifyFresh(a, &proof, &shape, claims, &drawn, config, first_roots, .{ .halt_address = 0x100100 })) |_| return error.AcceptedChangedNativeHaltPolicy else |err| if (err == error.OutOfMemory) return err;
    }
    try std.testing.expect(claims.len > 1);
    const before = claims[0].sum.add(claims[1].sum);
    claims[0].sum = claims[0].sum.add(Q.one());
    claims[1].sum = claims[1].sum.sub(Q.one());
    try std.testing.expect(before.eql(claims[0].sum.add(claims[1].sum)));
    if (verifyFresh(a, &proof, &shape, claims, &drawn, config, first_roots, halt)) |_| return error.AcceptedEndpointNativePhysicalClaimForgery else |err| if (err == error.OutOfMemory) return err;
}
