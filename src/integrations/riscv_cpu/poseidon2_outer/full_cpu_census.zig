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
const Public = @import("../rv64_recursion/om31_native/frame.zig");
const Full = @import("full_cpu_statement.zig");
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
const Bytes = struct {
    ctx: *C.Context,
    data: std.ArrayList(C.Var) = .empty,
    fn constant(self: *Bytes, byte: u8) !void {
        try self.data.append(self.ctx.scratch(), try self.ctx.constant(Q.fromBase(M.fromCanonical(byte))));
    }
    fn word(self: *Bytes, value: Word) !void {
        const raw = if (self.ctx.trace_only) 0 else B.ivalue.unpackU32(Q, self.ctx.get(value.get()));
        var octets: [4]C.Var = undefined;
        for (&octets, 0..) |*byte, i| {
            const n: u8 = @truncate(raw >> @intCast(8 * i));
            byte.* = (try B.wrappers.guessU16(Q, self.ctx, .newUnsafe(Q.fromU32Unchecked(n, 0, 0, 0)))).get();
            const complement = (try B.wrappers.guessU16(Q, self.ctx, .newUnsafe(Q.fromU32Unchecked(255 - n, 0, 0, 0)))).get();
            try self.ctx.noteWitnessByte(byte.*, value.get(), @intCast(i), false);
            try self.ctx.noteWitnessByte(complement, value.get(), @intCast(i), true);
            try self.ctx.eq(try self.ctx.add(byte.*, complement), try self.ctx.constant(Q.fromU32Unchecked(255, 0, 0, 0)));
        }
        const k = try self.ctx.constant(Q.fromU32Unchecked(256, 0, 0, 0));
        const low = try self.ctx.add(octets[0], try self.ctx.mul(octets[1], k));
        const high = try self.ctx.add(octets[2], try self.ctx.mul(octets[3], k));
        const assembled = try B.ops.fromPartialEvals(Q, self.ctx, .{ low, high, self.ctx.zero(), self.ctx.zero() });
        try self.ctx.eq(value.get(), assembled);
        try self.data.appendSlice(self.ctx.scratch(), &octets);
    }
    fn finish(self: *Bytes) !LegacyC.Hash {
        const n = self.data.items.len;
        const words = try self.ctx.scratch().alloc(Word, (n + 3) / 4);
        const k = try self.ctx.constant(Q.fromU32Unchecked(256, 0, 0, 0));
        for (words, 0..) |*output_word, i| {
            var bytes: [4]C.Var = @splat(self.ctx.zero());
            for (&bytes, 0..) |*byte, j| if (4 * i + j < n) {
                byte.* = self.data.items[4 * i + j];
            };
            const low = try self.ctx.add(bytes[0], try self.ctx.mul(bytes[1], k));
            const high = try self.ctx.add(bytes[2], try self.ctx.mul(bytes[3], k));
            output_word.* = .newUnsafe(try B.ops.fromPartialEvals(Q, self.ctx, .{ low, high, self.ctx.zero(), self.ctx.zero() }));
        }
        return B.blake.blake2sU32s(Q, self.ctx, words, n);
    }
};
fn scopeRoot(ctx: *C.Context, profile: Protocol.Profile, kind: u32, root: C.Hash) !LegacyC.Hash {
    var writer = Bytes{ .ctx = ctx };
    for ("rv64-p2v2/raw-local-scope-root/v1\x00") |byte| try writer.constant(byte);
    for (profile.identity()) |byte| try writer.constant(byte);
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, kind, .little);
    for (encoded) |byte| try writer.constant(byte);
    for (root) |limb| try writer.word(try B.blake.m31ToU32(Q, ctx, limb));
    return writer.finish();
}
const Statement = struct {
    inner: *Full.Statement,
    key: *const Key,
    fixed: C.Hash,
    expected_fixed: [32]u8,
    pub fn mixPublic(self: *@This(), ctx: *C.Context, ch: *C.Channel) !void {
        try ch.mixConfig(ctx, self.key.profile.config());
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
fn census(ctx: *const C.PoseidonContext) !void {
    const pp = Circuit.common.preprocessed;
    const sizes = Circuit.common.finalize.computePaddedSizes(pp.CircuitView.fromBuilder(&ctx.base.circuit));
    const layout = try pp.ColumnLayout.fromComponentSizes(sizes);
    const logs = try Circuit.common.component_list.circuitComponentLogSizes(&layout);
    var main: u64 = 0;
    var inter: u64 = 0;
    var fixed: u64 = 0;
    for (logs.toArray(), Circuit.common.component_list.component_facts.toArray()) |log, fact| {
        const rows = @as(u64, 1) << @intCast(log);
        main += rows * fact.trace_columns;
        inter += rows * fact.interaction_columns * 2;
    }
    for (layout.entries) |entry| fixed += @as(u64, 1) << @intCast(entry.log_size);
    const p2rows = try std.math.ceilPowerOfTwo(u64, @max(16, ctx.calls.items.len));
    const p2main = p2rows * L.MAIN_COLUMNS;
    const p2fixed = p2rows * L.FIXED_COLUMNS;
    const p2inter = p2rows * L.CLASSIC_INTERACTION_COLUMNS;
    const json = try std.json.Stringify.valueAlloc(ctx.allocator, .{ .status = "ACTUAL_complete_CPU_leaf_graph_mixed_P2PCS_rawBlakeGKR_frame;not_pure5;not_Ethereum;not_outerproof", .raw = snapshot(ctx), .old11_logs = logs, .p2_padded_rows = p2rows, .legacy_main_cells = main, .legacy_fixed_cells = fixed, .legacy_interaction_cells = inter, .p2_main_cells = p2main, .p2_fixed_cells = p2fixed, .p2_interaction_cells = p2inter, .total_main_cells = main + p2main, .total_fixed_cells = fixed + p2fixed, .total_interaction_cells = inter + p2inter, .total_trace_cells = main + fixed + inter + p2main + p2fixed + p2inter, .variables = ctx.base.circuit.n_vars, .source_use_mass = ctx.usage.?.total, .physical_profile = Protocol.Profile.fixture_b4_q54_p0_fold4, .legacy_transcripts = "localGKR/challenges/receipt;manifest-shared;scope-root canonical Blake;final frame Blake" }, .{});
    defer ctx.allocator.free(json);
    std.debug.print("P2_FULL_CPU_LEAF_CENSUS {s}\n", .{json});
}
pub const Hook = struct {
    pub fn runWithStages(a: std.mem.Allocator, setups: anytype, requests: anytype, keys: anytype, inventory: anytype, pending: anytype, encoded: anytype, native: anytype, capture: anytype, stages: anytype) !void {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const key = &keys[0];
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometry(arena.allocator(), setups[0], key.profile.config());
        const values = try V.proof.fromNative(arena.allocator(), native, capture, &shape);
        var fingerprint: ?[32]u8 = null;
        for ([_]bool{ false, true }) |trace_only| {
            var ctx = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 8) else try C.PoseidonContext.init(a, 8);
            defer ctx.deinit();
            C.begin(&ctx);
            var bound = true;
            defer if (bound) {
                C.finish() catch {};
            };
            const proof = try V.proof.guess(ctx.algebra(), &values, &shape);
            const fixed_scope = try scopeRoot(ctx.algebra(), key.profile, 0, proof.commitments[0]);
            const main_scope = try scopeRoot(ctx.algebra(), key.profile, 1, proof.commitments[1]);
            var frame = Public.Frame.init(ctx.algebra());
            var inner = try Full.Statement.init(&frame, setups[0], requests[0], inventory.first_ids[0], inventory.workers[0], pending.digest, encoded[0].claims, .{ .fixed = fixed_scope, .main = main_scope }, stages[0].local.?.proof, key.profile.config(), .{ .identity = key.identity, .root = key.scope(), .profile = null });
            defer inner.deinit(ctx.algebra());
            const before = snapshot(&ctx);
            var statement = Statement{ .inner = &inner, .key = key, .fixed = proof.commitments[0], .expected_fixed = inventory.workers[0].fixed };
            _ = try V.verify(ctx.algebra(), &shape, &proof, &statement);
            const after = snapshot(&ctx);
            const output = try frame.finish();
            var outputs: [8]C.Var = undefined;
            for (&outputs, output.words) |*v, w| v.* = w.get();
            try ctx.setOutputs(&outputs);
            try C.finish();
            bound = false;
            try ctx.finalizeForMixedCensus();
            if (!trace_only and !try ctx.isCircuitValid()) return error.FullMixedCpuLeafRejects;
            const fp = @import("../rv64_recursion/om31_native/topology_fingerprint.zig").compute(ctx.algebra());
            if (fingerprint) |expected| try std.testing.expectEqualSlices(u8, &expected, &fp.gates) else fingerprint = fp.gates;
            std.debug.print("P2_FULL_CPU_LEAF_PHASE trace_only={} beforePCS={any} afterPCS={any} finalized={any}\n", .{ trace_only, before, after, snapshot(&ctx) });
            try census(&ctx);
        }
    }
};
test "actual complete CPU P2 mixed recursive leaf padded census" {
    try @import("../word16_global_execution/services/poseidon2_native/fixture.zig").exercise(Hook);
}
