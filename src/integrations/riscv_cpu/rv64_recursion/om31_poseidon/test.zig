//! Genuine P2v2 RV64 ALU-only proof/capture -> complete dedicated P2 query circuit.
//! This is a scoped primitive gate, not a CPU execution or Ethereum proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const V = @import("mod.zig");
const C = V.common;
const O = C.O;
const Q = C.Q;
const F = V.F;
const M = core.fields.m31.M31;
const MC = core.vcs_lifted.poseidon2_profile.Om31V2;
const H = MC.MerkleHasher;
const NChannel = MC.Channel;
const CP = core.pcs.ForField(O);
const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, NChannel);
const Component = A.main_only.component.Component;
const a = std.testing.allocator;
fn component() Component {
    return .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } };
}
fn config(fold: u32) !core.pcs.PcsConfig {
    var cfg = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 2) };
    cfg.fri_config.fold_step = fold;
    return cfg;
}
fn produce(cfg: core.pcs.PcsConfig) !Prover.ExtendedProof {
    var ch = NChannel.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &ch);
    var values: [47][32]M = undefined;
    const alu = A.word16_v1.alu_experiment;
    for (0..32) |i| {
        const row = try alu.equations.witness(.add, if (i % 2 == 0) std.math.maxInt(u64) - i * 17 else i * 77731, i * 9079 + 2671);
        const logical = alu.lookup.rowToColumnsFor(Q, row);
        for (logical, 0..) |v, c| values[c][i] = v.toM31Array()[0];
    }
    @memset(&values[46], M.one());
    var columns: [47]engine.pcs.ColumnEvaluation = undefined;
    for (&columns, &values) |*col, *v| col.* = .{ .log_size = 5, .values = v };
    try scheme.commit(a, &columns, &ch);
    try scheme.commit(a, &.{}, &ch);
    const air = component();
    const components = [_]engine.air.component_prover.ForField(O).ComponentProver{air.asProverComponent()};
    owns = false;
    return Prover.prove(a, &components, &ch, scheme, .{});
}
fn geometry(arena: std.mem.Allocator, cfg: core.pcs.PcsConfig) !V.Shape {
    const logs = try arena.alloc([]const u32, 4);
    const offsets = try arena.alloc([]const []const i32, 4);
    const current = [_]i32{0};
    const previous = [_]i32{ 0, -1 };
    for (0..4) |t| {
        const columns: usize = switch (t) {
            1 => 47,
            3 => 16,
            else => 0,
        };
        const sizes = try arena.alloc(u32, columns);
        @memset(sizes, 5);
        logs[t] = sizes;
        const masks = try arena.alloc([]const i32, columns);
        for (masks, 0..) |*m, col| m.* = if (t == 1 and A.main_only.authority.previousMain(.alu, col)) &previous else &current;
        offsets[t] = masks;
    }
    return .{ .tree_column_log_sizes = logs, .mask_offsets = offsets, .global_log = 5, .composition_log_split = 1, .pcs = cfg };
}
const Statement = struct {
    config: core.pcs.PcsConfig,
    pub fn mixPublic(self: @This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConfig(ctx, self.config);
    }
    pub fn nTreesBeforeChallenges(_: @This()) usize {
        return 2;
    }
    pub fn drawChallenges(_: @This(), _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(_: @This(), _: *C.Context, _: *C.Channel) !void {}
    pub fn evalComposition(_: @This(), ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        const main = try ctx.scratch().alloc(F, sampled[1].len);
        const previous = try ctx.scratch().alloc(F, sampled[1].len);
        @memset(previous, F.zero());
        for (main, sampled[1], 0..) |*value, column, col| {
            value.* = column[0];
            if (A.main_only.authority.previousMain(.alu, col)) previous[col] = column[1];
        }
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, 5, 5) };
        try A.main_only.authority.emitFor(F, .{ .alu = {} }, &.{}, main, previous, &sink);
        return acc.finalize();
    }
};
fn capture(cfg: core.pcs.PcsConfig, native: *const V.proof.NativeProof, out: *V.proof.NativeCapture) !NChannel {
    var ch = NChannel.init();
    cfg.mixInto(&ch);
    var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const roots = native.commitment_scheme_proof.commitments.items;
    const logs = [_]u32{5} ** 47;
    try receiver.commit(a, roots[0], &.{}, &ch);
    try receiver.commit(a, roots[1], &logs, &ch);
    try receiver.commit(a, roots[2], &.{}, &ch);
    const air = component();
    const verifier = air.asVerifierComponent();
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(H, MC, a, &.{verifier}, &ch, &receiver, native, out);
    return ch;
}

test "P2v2 OM31 full native PCS FRI query circuit accepts ALU proof and exact transcript" {
    for ([_]u32{ 1, 4 }) |step| {
        const cfg = try config(step);
        var native = try produce(cfg);
        defer native.deinit(a);
        var captured: V.proof.NativeCapture = undefined;
        const channel = try capture(cfg, &native.proof, &captured);
        defer captured.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try geometry(arena.allocator(), cfg);
        const values = try V.proof.fromNative(arena.allocator(), &native.proof, &captured, &shape);
        var ctx = try C.PoseidonContext.init(a, 1);
        defer ctx.deinit();
        C.begin(&ctx);
        var bound = true;
        defer if (bound) {
            C.finish() catch {};
        };
        const proof = try V.proof.guess(ctx.algebra(), &values, &shape);
        const verified = try V.verify(ctx.algebra(), &shape, &proof, Statement{ .config = cfg });
        const words = try core.crypto.poseidon2_m31_sponge.decode(channel.digestBytes());
        for (verified.channel.raw.inner.value.digest, words) |wire, word| try std.testing.expect(ctx.algebra().get(wire).eql(Q.fromBase(word)));
        try C.finish();
        bound = false;
        try ctx.setOutputs(&.{verified.channel.raw.inner.value.digest[0]});
        try ctx.finalize();
        try std.testing.expect(try ctx.isCircuitValid());
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_ALU_only_P2_native_query_graph", .fold = step, .permutations = ctx.calls.items.len, .variables = ctx.algebra().circuit.n_vars, .classic = try ctx.census(false), .gkr = try ctx.census(true) }, .{});
        defer a.free(json);
        std.debug.print("P2_NATIVE_QUERY_CENSUS {s}\n", .{json});
        const changed = proof.auth_paths[1][0][0][0];
        ctx.algebra().value_table.items[changed.idx] = ctx.algebra().value_table.items[changed.idx].add(Q.one());
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
