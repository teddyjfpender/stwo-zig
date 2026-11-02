//! End to end: a prover-built native proof (`test_fixture.zig`) is converted
//! to the fixed-width witness, verified in value mode by `verify.zig` with
//! the wide-Fibonacci statement written in builder ops, and the circuit's
//! transcript is compared with the native verifier's. One flipped proof
//! value must break the circuit; the topology must not depend on values.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const sv_circle = @import("../stark_verifier/circle.zig");
const channel_mod = @import("channel.zig");
const deep = @import("deep.zig");
const fixture_mod = @import("test_fixture.zig");
const proof_mod = @import("proof.zig");
const verify_mod = @import("verify.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const NoValue = builder.NoValue;
const Point = sv_circle.Point;
const Fixture = fixture_mod.Fixture;

/// The wide-Fibonacci statement over `Context(V)`.
fn TestStatement(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Challenges = struct {};

        statement: fixture_mod.Statement,
        config: fixture_mod.PcsConfig,

        /// `PcsConfig.mixInto`: one felt `(pow_bits, log_blowup, n_queries, log_last_layer)`.
        pub fn mixPublic(self: Self, ctx: *Context(V), channel: *channel_mod.NativeChannel) !void {
            std.debug.assert(self.config.fri_config.fold_step == 1 and self.config.lifting_log_size == null);
            const felt = try ctx.constant(QM31.fromU32Unchecked(
                self.config.pow_bits,
                self.config.fri_config.log_blowup_factor,
                @intCast(self.config.fri_config.n_queries),
                self.config.fri_config.log_last_layer_degree_bound,
            ));
            try channel.mixFelts(V, ctx, &.{felt});
        }

        pub fn nTreesBeforeChallenges(_: Self) usize {
            return 2;
        }

        pub fn drawChallenges(_: Self, _: *Context(V), _: *channel_mod.NativeChannel) !Challenges {
            return .{};
        }

        /// `mixU32s(log_n_rows, sequence_len)`.
        pub fn mixClaims(self: Self, ctx: *Context(V), channel: *channel_mod.NativeChannel) !void {
            const words = [_]builder.wrappers.U32Wrapper(Var){
                try builder.wrappers.constU32(V, ctx, self.statement.log_n_rows),
                try builder.wrappers.constU32(V, ctx, self.statement.sequence_len),
            };
            try channel.mixU32s(V, ctx, &words);
        }

        /// `evaluateConstraintQuotientsAtPoint` with the `PointEvaluationAccumulator`.
        pub fn evalComposition(self: Self, ctx: *Context(V), oods: Point(Var), sampled: []const []const []const Var, alpha: Var, _: Challenges) !Var {
            const main = sampled[1];
            if (main.len != self.statement.sequence_len) return error.ShapeMismatch;
            // `cosetVanishing`: `p = point - initial + half_step`, then `log_size - 1` doublings of `p.x`.
            const coset = core.poly.circle.canonic.CanonicCoset.new(self.statement.log_n_rows).coset();
            const shifted = try deep.addConstantPoint(V, ctx, oods, coset.half_step.sub(coset.initial));
            var x = shifted.x;
            for (1..self.statement.log_n_rows) |_| x = try sv_circle.doubleX(V, ctx, x);
            const denominator_inv = try ctx.inv(x);
            var accumulator = ctx.zero();
            var a = main[0][0];
            var b = main[1][0];
            for (main[2..]) |column| {
                const c = column[0];
                const squares = try ctx.add(try ctx.mul(a, a), try ctx.mul(b, b));
                const constraint = try ctx.sub(c, squares);
                accumulator = try ctx.add(try ctx.mul(accumulator, alpha), try ctx.mul(constraint, denominator_inv));
                a = b;
                b = c;
            }
            return accumulator;
        }
    };
}

const Mutation = enum { none, sampled_value, queried_value, fri_coset, auth_path, pow_nonce };

/// Builds the value-mode circuit for `fixture`'s proof with `mutation`
/// applied; returns whether every gate holds.
fn runCircuit(fixture: *Fixture, mutation: Mutation, gate_counts: ?*builder.context.GateCounts) !bool {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var value_proof = try proof_mod.fromNative(arena.allocator(), fixture_mod.Hasher, &fixture.proof, &fixture.capture, &fixture.shape);
    switch (mutation) {
        .none => {},
        .sampled_value => @constCast(value_proof.sampled_values[1][2])[0] = value_proof.sampled_values[1][2][0].add(QM31.one()),
        .queried_value => @constCast(value_proof.queried_values[1][0])[3] = .newUnsafe(value_proof.queried_values[1][0][3].get().add(QM31.one())),
        .fri_coset => @constCast(value_proof.fri.layers[1].cosets[2])[1] = value_proof.fri.layers[1].cosets[2][1].add(QM31.one()),
        .auth_path => @constCast(value_proof.auth_paths[2][1])[0].words[3] = builder.wrappers.u32Value(QM31, 0x1234),
        .pow_nonce => value_proof.pow_nonce[0] = builder.wrappers.u32Value(QM31, builder.ivalue.unpackU32(QM31, value_proof.pow_nonce[0].get()) ^ 1),
    }

    var ctx = try Context(QM31).init(gpa, 0);
    defer ctx.deinit();
    const wires = try proof_mod.guess(QM31, &ctx, &value_proof);
    const statement = TestStatement(QM31){ .statement = fixture.statement, .config = fixture.config };
    const verified = try verify_mod.verify(QM31, &ctx, &fixture.shape, &wires, statement);

    if (mutation == .none) {
        // The parity signals: the final digest and every transcript draw.
        try std.testing.expectEqualSlices(u8, &fixture.final_channel.digestBytes(), &verified.channel.debugDigest(&ctx));
        try std.testing.expectEqual(fixture.final_channel.n_draws, verified.channel.n_draws);
        try std.testing.expect(ctx.get(verified.composition_randomness).eql(fixture.capture.composition_randomness));
        try std.testing.expect(ctx.get(verified.deep_randomness).eql(fixture.capture.deep_randomness));
        const oods = core.circle.secureFieldPointFromRandomSeed(fixture.capture.oods_seed);
        try std.testing.expect(ctx.get(verified.oods_point.x).eql(oods.x));
        try std.testing.expect(ctx.get(verified.oods_point.y).eql(oods.y));
        for (verified.fri_input, fixture.capture.deep_answers) |wire, expected| try std.testing.expect(ctx.get(wire).eql(expected));
        for (verified.fri_alphas, fixture.capture.fri.layers) |alpha, layer| try std.testing.expect(ctx.get(alpha).eql(layer.folding_alpha));
        for (fixture.capture.queries.raw, 0..) |position, q| {
            var rebuilt: usize = 0;
            for (verified.queries.unpacked, 0..) |bits, i| rebuilt |= @as(usize, ctx.get(bits[q]).c0.a.v) << @intCast(i);
            try std.testing.expectEqual(position, rebuilt);
        }
    }
    try ctx.finalize(false);
    if (gate_counts) |out| out.* = ctx.gate_counts;
    return ctx.isCircuitValid();
}

test "e2e: a prover-built native proof verifies in the circuit and its transcript matches" {
    var fixture = try Fixture.init(std.testing.allocator, fixture_mod.default_config, fixture_mod.default_statement);
    defer fixture.deinit(std.testing.allocator);
    var gate_counts: builder.context.GateCounts = undefined;
    try std.testing.expect(try runCircuit(&fixture, .none, &gate_counts));
    std.debug.print(
        "\nnative verifier e2e gate counts (log_n_rows={d}, columns={d}, queries={d}, pow={d}): eq={d} qm31_ops={d} m31_to_u32={d} triple_xor={d} blake_g_gate={d}\n",
        .{ fixture.statement.log_n_rows, fixture.statement.sequence_len, fixture.config.fri_config.n_queries, fixture.config.pow_bits, gate_counts.eq, gate_counts.qm31_ops, gate_counts.m31_to_u32, gate_counts.triple_xor, gate_counts.blake_g_gate },
    );
}

test "e2e: every flipped proof value breaks the circuit" {
    var fixture = try Fixture.init(std.testing.allocator, fixture_mod.default_config, fixture_mod.default_statement);
    defer fixture.deinit(std.testing.allocator);
    for ([_]Mutation{ .sampled_value, .queried_value, .fri_coset, .auth_path, .pow_nonce }) |mutation| {
        try std.testing.expect(!try runCircuit(&fixture, mutation, null));
    }
}

test "e2e: a last layer of degree two verifies through the line polynomial" {
    const last_layer_config = fixture_mod.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 3, .fold_step = 1 } };
    var fixture = try Fixture.init(std.testing.allocator, last_layer_config, .{ .log_n_rows = 3, .sequence_len = 4 });
    defer fixture.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), fixture.capture.last_layer_coefficients.len);
    try std.testing.expect(try runCircuit(&fixture, .none, null));
    try std.testing.expect(!try runCircuit(&fixture, .fri_coset, null));
}

test "e2e: the topology does not depend on the proof values" {
    var fixture = try Fixture.init(std.testing.allocator, fixture_mod.default_config, fixture_mod.default_statement);
    defer fixture.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    var value_arena = std.heap.ArenaAllocator.init(gpa);
    defer value_arena.deinit();
    const value_proof = try proof_mod.fromNative(value_arena.allocator(), fixture_mod.Hasher, &fixture.proof, &fixture.capture, &fixture.shape);
    var value_ctx = try Context(QM31).init(gpa, 0);
    defer value_ctx.deinit();
    const value_wires = try proof_mod.guess(QM31, &value_ctx, &value_proof);
    _ = try verify_mod.verify(QM31, &value_ctx, &fixture.shape, &value_wires, TestStatement(QM31){ .statement = fixture.statement, .config = fixture.config });
    try value_ctx.finalize(false);

    var topology_arena = std.heap.ArenaAllocator.init(gpa);
    defer topology_arena.deinit();
    const empty = try proof_mod.emptyProof(topology_arena.allocator(), &fixture.shape);
    var topology_ctx = try Context(NoValue).init(gpa, 0);
    defer topology_ctx.deinit();
    const topology_wires = try proof_mod.guess(NoValue, &topology_ctx, &empty);
    _ = try verify_mod.verify(NoValue, &topology_ctx, &fixture.shape, &topology_wires, TestStatement(NoValue){ .statement = fixture.statement, .config = fixture.config });
    try topology_ctx.finalize(false);

    try std.testing.expectEqual(value_ctx.circuit.n_vars, topology_ctx.circuit.n_vars);
    try std.testing.expectEqual(value_ctx.gate_counts, topology_ctx.gate_counts);
    try std.testing.expectEqual(value_ctx.constantVars().len, topology_ctx.constantVars().len);
}
