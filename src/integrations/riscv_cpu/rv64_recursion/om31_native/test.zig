//! Actual CPU-built native proof -> native fresh capture -> complete primitive
//! circuit. This fixture proves ALU arithmetic, not an Ethereum execution.
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
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const NChannel = core.channel.raw_mod_m31.Om31Channel;
const CP = core.pcs.ForField(O);
const MC = struct {
    pub fn mixRoot(ch: *NChannel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
    }
};
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
test "OM31 native PCS primitive accepts actual ALU proof and matches final transcript for fold1 and4" {
    for ([_]u32{ 1, 4 }) |fold| {
        const cfg = try config(fold);
        var native = try produce(cfg);
        defer native.proof.deinit(a);
        defer native.aux.deinit(a);
        var captured: V.proof.NativeCapture = undefined;
        const native_ch = try capture(cfg, &native.proof, &captured);
        defer captured.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try geometry(arena.allocator(), cfg);
        const values = try V.proof.fromNative(arena.allocator(), &native.proof, &captured, &shape);
        var ctx = try C.Context.init(a, 0);
        defer ctx.deinit();
        C.lane.begin(&ctx);
        var active = true;
        defer if (active) C.lane.finish() catch {};
        const wires = try V.proof.guess(&ctx, &values, &shape);
        const verified = try V.verify(&ctx, &shape, &wires, Statement{ .config = cfg });
        try std.testing.expectEqual(native_ch.digestBytes(), verified.channel.raw.inner.debugDigest(&ctx));
        try std.testing.expect(verified.composition_randomness.value().eql(captured.composition_randomness));
        try std.testing.expect(verified.deep_randomness.value().eql(captured.deep_randomness));
        const expected_point = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, captured.oods_seed);
        try std.testing.expect(verified.oods_point.x.value().eql(expected_point.x));
        try std.testing.expect(verified.oods_point.y.value().eql(expected_point.y));
        for (verified.fri_input, captured.deep_answers) |wire, expected| try std.testing.expect(wire.value().eql(expected));
        for (verified.fri_alphas, captured.fri.layers) |wire, layer| try std.testing.expect(wire.value().eql(layer.folding_alpha));
        for (captured.queries.raw, 0..) |position, q| {
            var rebuilt: usize = 0;
            for (verified.queries.unpacked, 0..) |bits, i| rebuilt |= @as(usize, ctx.get(bits[q]).c0.a.v) << @intCast(i);
            try std.testing.expectEqual(position, rebuilt);
        }
        try C.lane.finish();
        active = false;
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

fn checkCircuit(values: *const V.Captured, shape: *const V.Shape, cfg: core.pcs.PcsConfig, counts: ?*circuit.builder.context.GateCounts) !bool {
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const wires = try V.proof.guess(&ctx, values, shape);
    _ = try V.verify(&ctx, shape, &wires, Statement{ .config = cfg });
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    if (counts) |out| out.* = ctx.gate_counts;
    return ctx.isCircuitValid();
}
fn delta(coordinate: usize) O {
    var coordinates = [_]M{M.zero()} ** 8;
    coordinates[coordinate] = M.one();
    return O.fromM31Array(coordinates);
}
test "OM31 native PCS binds every OODS and FRI secure coordinate with invariant topology" {
    const cfg = try config(4);
    var native = try produce(cfg);
    defer native.proof.deinit(a);
    defer native.aux.deinit(a);
    var cap: V.proof.NativeCapture = undefined;
    _ = try capture(cfg, &native.proof, &cap);
    defer cap.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try geometry(arena.allocator(), cfg);
    const values = try V.proof.fromNative(arena.allocator(), &native.proof, &cap, &shape);
    var reference: circuit.builder.context.GateCounts = undefined;
    try std.testing.expect(try checkCircuit(&values, &shape, cfg, &reference));
    const sampled = @constCast(values.sampled_values[1][0]);
    const coset = @constCast(values.layers[0].cosets[0]);
    for (0..8) |coordinate| {
        var actual: circuit.builder.context.GateCounts = undefined;
        const before = sampled[0];
        sampled[0] = before.add(delta(coordinate));
        try std.testing.expect(!try checkCircuit(&values, &shape, cfg, &actual));
        try std.testing.expectEqual(reference, actual);
        sampled[0] = before;
        const previous = coset[0];
        coset[0] = previous.add(delta(coordinate));
        try std.testing.expect(!try checkCircuit(&values, &shape, cfg, &actual));
        try std.testing.expectEqual(reference, actual);
        coset[0] = previous;
    }
}
test "OM31 native PCS rejects altered roots base openings paths nonce and terminal polynomial" {
    var cfg = try config(4);
    cfg.pow_bits = 3;
    var native = try produce(cfg);
    defer native.proof.deinit(a);
    defer native.aux.deinit(a);
    var cap: V.proof.NativeCapture = undefined;
    _ = try capture(cfg, &native.proof, &cap);
    defer cap.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try geometry(arena.allocator(), cfg);
    var values = try V.proof.fromNative(arena.allocator(), &native.proof, &cap, &shape);
    try std.testing.expect(try checkCircuit(&values, &shape, cfg, null));
    const roots = @constCast(values.commitments);
    roots[1][0] ^= 1;
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
    roots[1][0] ^= 1;
    const bases = @constCast(values.queried_values[1][0]);
    bases[0] = bases[0].add(M.one());
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
    bases[0] = bases[0].sub(M.one());
    const path = @constCast(values.auth_paths[1][0]);
    path[0][0] ^= 1;
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
    path[0][0] ^= 1;
    values.pow_nonce ^= 1;
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
    values.pow_nonce ^= 1;
    const last = @constCast(values.last_layer_coefs);
    last[0] = last[0].add(delta(7));
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
}
test "OM31 native PCS shape rejects four-coordinate composition and declaration mutations" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var shape = try geometry(arena.allocator(), try config(4));
    try shape.validate();
    shape.global_log += 1;
    try std.testing.expectError(error.InvalidCompositionTree, shape.validate());
    shape.global_log -= 1;
    const trees = @constCast(shape.tree_column_log_sizes);
    trees[3] = trees[3][0..8];
    const masks = @constCast(shape.mask_offsets);
    masks[3] = masks[3][0..8];
    try std.testing.expectError(error.InvalidCompositionTree, shape.validate());
}
test "OM31 native PCS OODS zero denominator is unsatisfied without a witness selected topology" {
    var counts: [2]circuit.builder.context.GateCounts = undefined;
    for ([_]O{ O.fromBase(M.fromCanonical(3)), O.fromM31Array(.{ M.zero(), M.one(), M.zero(), M.zero(), M.zero(), M.zero(), M.zero(), M.zero() }) }, 0..) |seed, i| {
        var ctx = try C.Context.init(a, 0);
        defer ctx.deinit();
        C.lane.begin(&ctx);
        var active = true;
        defer if (active) C.lane.finish() catch {};
        const point = V.pointFromSeed(try F.guess(&ctx, seed));
        // Use both outputs, without assuming the map itself is valid.
        _ = point.x.add(point.y);
        try C.lane.finish();
        active = false;
        try ctx.finalize(false);
        counts[i] = ctx.gate_counts;
        try std.testing.expectEqual(i == 0, try ctx.isCircuitValid());
    }
    try std.testing.expectEqual(counts[0], counts[1]);
}

test "OM31 native PCS nonconstant last polynomial and nonzero proof of work accept" {
    var cfg = try config(4);
    cfg.pow_bits = 3;
    cfg.fri_config.log_last_layer_degree_bound = 1;
    var native = try produce(cfg);
    defer native.proof.deinit(a);
    defer native.aux.deinit(a);
    var cap: V.proof.NativeCapture = undefined;
    _ = try capture(cfg, &native.proof, &cap);
    defer cap.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try geometry(arena.allocator(), cfg);
    const values = try V.proof.fromNative(arena.allocator(), &native.proof, &cap, &shape);
    try std.testing.expectEqual(@as(usize, 2), values.last_layer_coefs.len);
    try std.testing.expect(try checkCircuit(&values, &shape, cfg, null));
    @constCast(values.last_layer_coefs)[1] = values.last_layer_coefs[1].add(delta(5));
    try std.testing.expect(!try checkCircuit(&values, &shape, cfg, null));
}

test "OM31 frame worker framing shared draws and public digest match native authorities" {
    const Frame = V.frame;
    const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
    const Manifest = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
    const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
    const cfg = try config(4);
    const expected = Manifest.ExpectedWorker{ .kind = .delegation, .ordinal = 3, .statement = @splat(17), .fixed = @splat(11), .local_instances = null, .global_relations = .{ .ram = false, .kio = false, .wire = true }, .mass = .{ .ram = 0, .kio = 0, .wire = 5 } };
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    var frame = Frame.Frame.init(&ctx);
    const ordinal = try frame.guessU32(expected.ordinal);
    const statement = try frame.guessDigest(expected.statement);
    const manifest = try frame.guessDigest(@splat(19));
    const om_value = delta(7).add(O.fromBase(M.fromCanonical(23)));
    _ = try frame.guessOm(om_value);
    var legacy = W.begin(cfg, expected);
    const channel = try Frame.beginWorker(&ctx, cfg, expected.kind, ordinal.word, statement, null);
    try std.testing.expectEqual(legacy.digestBytes(), channel.raw.inner.debugDigest(&ctx));
    const fixed = Frame.Binding{ .identity = @splat(31), .root = @splat(37), .profile = .conjectured128_b2_q108_p20_fold4 };
    var writer = struct {
        ch: *W.Channel,
        pub fn constantDigest(self: *@This(), value: [32]u8) void {
            W.digest(self.ch, value);
        }
    }{ .ch = &legacy };
    Fixed.emitBindingBegin(fixed.profile, fixed.identity, fixed.root, &writer);
    const bound = try Frame.beginWorker(&ctx, cfg, expected.kind, ordinal.word, statement, fixed);
    try std.testing.expectEqual(legacy.digestBytes(), bound.raw.inner.debugDigest(&ctx));
    const shared = try Frame.drawShared(&ctx, manifest);
    const native = Manifest.drawShared(@splat(19));
    try std.testing.expect(shared.ram.offset.value().eql(native.ram.offset));
    for (shared.ram.coefficients, native.ram.coefficients) |wire, value| try std.testing.expect(wire.value().eql(value));
    try std.testing.expect(shared.kio.offset.value().eql(native.kio.offset));
    for (shared.kio.coefficients, native.kio.coefficients) |wire, value| try std.testing.expect(wire.value().eql(value));
    try std.testing.expect(shared.wire.offset.value().eql(native.wire.offset));
    for (shared.wire.coefficients, native.wire.coefficients) |wire, value| try std.testing.expect(wire.value().eql(value));
    const digest = try frame.finish();
    var hash = std.crypto.hash.blake2.Blake2s256.init(.{});
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, expected.ordinal, .little);
    hash.update(&word);
    hash.update(&expected.statement);
    hash.update(&@as([32]u8, @splat(19)));
    for (om_value.toM31Array()) |v| {
        std.mem.writeInt(u32, &word, v.v, .little);
        hash.update(&word);
    }
    var expected_digest: [32]u8 = undefined;
    hash.final(&expected_digest);
    try Frame.requireDigest(&ctx, digest, expected_digest);
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
