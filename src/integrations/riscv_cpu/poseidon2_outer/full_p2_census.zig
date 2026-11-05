//! UNQUALIFIED pure P2 candidate AST/padding census. No native assignment parity.
//! ACTUAL complete CPU leaf graph for the mixed native suite: P2v2 PCS/FRI,
//! raw-Blake local GKR/manifest/canonical scope+frame. Twelve-roster census
//! only; never advertised as a pure five-roster proof or Ethereum leaf.
const std = @import("std");
const Core = @import("stwo_core");
const Circuit = @import("stwo_circuit_frontend");
const B = Circuit.builder;
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const LegacyC = @import("../rv64_recursion/om31_native/common.zig");
const Public = @import("full_p2_frame.zig");
const Full = @import("full_p2_statement.zig");
const Protocol = @import("../word16_global_execution/services/poseidon2_native/worker_protocol.zig");
const Key = @import("../word16_global_execution/services/poseidon2_native/fixed_key.zig").Key;
const L = @import("layout.zig");
const M = Core.fields.m31.M31;
const Q = C.Q;
const Word = Public.Word;
const RawDigest = Public.Digest;
fn constDigest(ctx: *C.Context, bytes: [32]u8) ![8]u32 {
    _ = ctx;
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}
const Statement = struct {
    configuration: Core.pcs.PcsConfig,
    inner: *Full.Statement,
    key: *const Key,
    fixed: C.Hash,
    expected_fixed: [32]u8,
    pub fn mixPublic(self: *@This(), ctx: *C.Context, ch: *C.Channel) !void {
        try ch.mixConfig(ctx, self.configuration);
        const prefix = [_]Word{ try B.wrappers.constU32(Q, ctx, 0x50324350), try B.wrappers.constU32(Q, ctx, 2), try B.wrappers.constU32(Q, ctx, 8), try B.wrappers.constU32(Q, ctx, 0), self.inner.ordinal };
        try ch.mixU32s(ctx, &prefix);
        try ch.mixConstU32s(ctx, &try constDigest(ctx, self.key.profile.identity()));
        try ch.mixU32s(ctx, &self.inner.statement);
        try ch.mixConstU32s(ctx, &try constDigest(ctx, self.expected_fixed));
        try ch.mixConstU32s(ctx, &try constDigest(ctx, self.key.identity));
        try ch.mixRoot(ctx, self.fixed);
    }
    pub fn nTreesBeforeChallenges(_: *@This()) usize {
        return 2;
    }
    pub fn drawChallenges(_: *@This(), _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *@This(), ctx: *C.Context, ch: *C.Channel) !void {
        try ch.mixConstU32s(ctx, &.{ 0x50324d43, 2, @intCast(self.inner.claims.len) });
        try ch.mixU32s(ctx, &self.inner.manifest);
        try ch.mixFelts(ctx, self.inner.claims);
    }
    pub fn evalComposition(self: *@This(), ctx: *C.Context, point: V.Point, sampled: []const []const []const C.F, alpha: C.F, _: void) !C.F {
        return self.inner.evalComposition(ctx, point, sampled, alpha, {});
    }
};
fn snapshot(ctx: *const C.PoseidonContext) struct { eq: usize, qm31_ops: usize, m31_to_u32: usize, triple_xor: usize, blake_g_gate: usize, p2: usize } {
    const g = ctx.base.gate_counts;
    return .{ .eq = g.eq, .qm31_ops = g.qm31_ops, .m31_to_u32 = g.m31_to_u32, .triple_xor = g.triple_xor, .blake_g_gate = g.blake_g_gate, .p2 = ctx.calls.items.len };
}
fn census(ctx: *const C.PoseidonContext, configuration: Core.pcs.PcsConfig, placeholder: bool) !void {
    const cells = try ctx.census(false);
    const candidate_profile = if (configuration.fri_config.log_blowup_factor == 1) "AST-only/full-P2v2-PCS-GKR-shared-receipt-frame9/b2-q108-P20-f4/native-UNQUALIFIED/v1" else "AST-only/full-P2v2-PCS-GKR-shared-receipt-frame9/b4-q54-P0-f4/native-UNQUALIFIED/v1";
    const json = try std.json.Stringify.valueAlloc(ctx.allocator, .{ .status = "DERIVED_source_exact_full_CPU_candidate_AST;no_native_pureP2_protocol_or_recursiveproof", .candidate_profile = candidate_profile, .configuration = configuration, .assignment_is_source_shape_placeholder = placeholder, .raw = snapshot(ctx), .cells = cells, .variables = ctx.base.circuit.n_vars, .source_use_mass = ctx.usage.?.total, .internal_hash_limbs = 9, .residual_dynamic_blake_gates = ctx.base.circuit.blake_g_gate.items.len, .residual_dynamic_xor_gates = ctx.base.circuit.triple_xor.items.len, .native_assignment_compatible = false, .native_shared_challenges_compatible = false, .newGKR_receipt_framing = "domain+length+bytes->P2digest9", .frame = "domain+length+boundedraw32words->P2digest9", .external_identifiers = "source fixture's existing32byte statement/manifest identities; native pureP2 regeneration not implemented" }, .{});
    defer ctx.allocator.free(json);
    std.debug.print("P2_PURE_CPU_LEAF_CANDIDATE_CENSUS {s}\n", .{json});
}
pub const Hook = struct {
    pub fn runWithStages(a: std.mem.Allocator, setups: anytype, requests: anytype, keys: anytype, inventory: anytype, pending: anytype, encoded: anytype, native: anytype, capture: anytype, stages: anytype) !void {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const key = &keys[0];
        var alternate = key.profile.config();
        alternate.pow_bits = 20;
        alternate.fri_config.log_blowup_factor = 1;
        alternate.fri_config.n_queries = 108;
        for ([_]Core.pcs.PcsConfig{ key.profile.config(), alternate }, 0..) |configuration, variant| {
            const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometry(arena.allocator(), setups[0], configuration);
            const values = if (variant == 0) try V.proof.fromNative(arena.allocator(), native, capture, &shape) else try @import("ast_shape_values.zig").fromSourceShape(arena.allocator(), &shape);
            const trace_only = true;
            var ctx = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
            defer ctx.deinit();
            C.begin(&ctx);
            var bound = true;
            defer if (bound) {
                C.finish() catch {};
            };
            const proof = try V.proof.guess(ctx.algebra(), &values, &shape);
            const fixed_scope = proof.commitments[0];
            const main_scope = proof.commitments[1];
            var frame = Public.Frame.init(ctx.algebra());
            var inner = try Full.Statement.init(&frame, setups[0], requests[0], inventory.first_ids[0], inventory.workers[0], pending.digest, encoded[0].claims, .{ .fixed = fixed_scope, .main = main_scope, .fixed_source = key.root }, stages[0].local.?.proof, configuration, .{ .identity = key.identity, .root = key.scope(), .profile = null });
            defer inner.deinit(ctx.algebra());
            const before = snapshot(&ctx);
            var statement = Statement{ .configuration = configuration, .inner = &inner, .key = key, .fixed = proof.commitments[0], .expected_fixed = inventory.workers[0].fixed };
            _ = try V.verify(ctx.algebra(), &shape, &proof, &statement);
            const after = snapshot(&ctx);
            const output = try frame.finish();
            try ctx.setOutputs(&output);
            try C.finish();
            bound = false;
            try ctx.finalize();
            if (ctx.base.circuit.blake_g_gate.items.len != 0 or ctx.base.circuit.triple_xor.items.len != 0) return error.CandidateContainsLegacyHash;
            if (!trace_only and !try ctx.isCircuitValid()) return error.FullMixedCpuLeafRejects;

            std.debug.print("P2_PURE_CPU_CANDIDATE_PHASE trace_only={} beforePCS={any} afterPCS={any} finalized={any}\n", .{ trace_only, before, after, snapshot(&ctx) });
            try census(&ctx, configuration, variant != 0);
        }
    }
};
test "source-exact complete CPU pure P2 candidate AST padded census" {
    try @import("../word16_global_execution/services/poseidon2_native/fixture.zig").exercise(Hook);
}
