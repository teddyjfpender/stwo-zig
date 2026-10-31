const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const D = K.pair2n;
const L = D.layout;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const physical = A.witness.physical;
const a = std.testing.allocator;
fn inputState(seed: u64) K.trace.State {
    var state: K.trace.State = undefined;
    for (&state, 0..) |*v, i| v.* = (seed +% i +% 1) *% 0x9e3779b97f4a7c15;
    return state;
}
fn capture(trace: *const D.trace.Trace, row: usize, scratch: *D.component.ScratchFor(Q)) void {
    const n = trace.base.size();
    const log = trace.base.log_size;
    const r = physical(row, log);
    for (&scratch.fixed, 0..) |*v, c| v.* = Q.fromBase(trace.base.fixed[c * n + r]);
    for (&scratch.main, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + r]);
    for (&scratch.shifted, K.layout.MASK_OFFSETS[1..]) |*state, offset| for (state, 0..) |*v, c| {
        const index = @as(usize, @intCast(@mod(@as(i64, @intCast(row)) + offset, @as(i64, @intCast(n)))));
        v.* = Q.fromBase(trace.main[c * n + physical(index, log)]);
    };
    const previous = physical((row + n - 1) % n, log);
    for (&scratch.previous_header, 0..) |*v, c| v.* = Q.fromBase(trace.main[(K.layout.ACTIVE_A + c) * n + previous]);
    for (&scratch.interaction, 0..) |*v, c| v.* = Q.fromM31(trace.interaction[(4 * c) * n + r], trace.interaction[(4 * c + 1) * n + r], trace.interaction[(4 * c + 2) * n + r], trace.interaction[(4 * c + 3) * n + r]);
}
test "pair2n native empty odd even padded traces preserve exact triple claim and constrain every row" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = K.equations.Challenges.draw(&channel);
    const inputs = [_]K.trace.State{ inputState(0), inputState(1), inputState(2) };
    const scratch = try a.create(D.component.ScratchFor(Q));
    defer a.destroy(scratch);
    const residuals = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(residuals);
    for (0..4) |count| {
        const log: u32 = if (count == 3) 7 else 6;
        var trace = try D.trace.Trace.init(a, inputs[0..count], 1, log);
        defer trace.deinit();
        const claim = try D.interaction.generate(&trace, ch);
        var old = try K.trace.Trace.initWithLog(a, inputs[0..count], 1, log);
        defer old.deinit();
        const oldclaim = try K.interaction.generate(&old, ch);
        try std.testing.expect(claim.eql(oldclaim));
        const n = trace.base.size();
        for (0..n) |row| {
            capture(&trace, row, scratch);
            const p = physical((row + n - 1) % n, log);
            const previous = Q.fromM31(trace.interaction[L.PREFIX * n + p], trace.interaction[(L.PREFIX + 1) * n + p], trace.interaction[(L.PREFIX + 2) * n + p], trace.interaction[(L.PREFIX + 3) * n + p]);
            var sink = A.evaluation.Sink{ .values = residuals };
            D.equations.emitFor(Q, scratch.row(), &scratch.interaction, previous, claim, ch, .{ .calls = @intCast(count), .first_id = 1 }, &sink);
            try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
            for (residuals, 0..) |v, index| if (!v.isZero()) {
                std.debug.print("pair2n count{d} row{d} constraint{d}\n", .{ count, row, index });
                return error.NonzeroNativeResidual;
            };
        }
    }
}
const Degree = struct {
    pub const rv64_external_lane = true;
    degree: u8 = 0,
    pub fn zero() Degree {
        return .{};
    }
    pub fn one() Degree {
        return .{};
    }
    pub fn fromU32(_: u32) Degree {
        return .{};
    }
    pub fn add(x: Degree, y: Degree) Degree {
        return .{ .degree = @max(x.degree, y.degree) };
    }
    pub fn sub(x: Degree, y: Degree) Degree {
        return x.add(y);
    }
    pub fn mul(x: Degree, y: Degree) Degree {
        return .{ .degree = x.degree + y.degree };
    }
    pub fn neg(x: Degree) Degree {
        return x;
    }
};
const DegreeSink = struct {
    count: usize = 0,
    max: u8 = 0,
    pub fn emit(self: *@This(), v: Degree) void {
        std.debug.assert(v.degree <= 3);
        self.count += 1;
        self.max = @max(self.max, v.degree);
    }
};
test "pair2n algebraic degree propagation bounds every residual by three without native phase assumptions" {
    const variable = Degree{ .degree = 1 };
    const scratch = try a.create(D.component.ScratchFor(Degree));
    defer a.destroy(scratch);
    @memset(&scratch.fixed, variable);
    @memset(&scratch.main, variable);
    @memset(&scratch.previous_header, variable);
    @memset(&scratch.interaction, variable);
    for (&scratch.shifted) |*s| @memset(s, variable);
    const lookup = K.equations.LookupFor(Degree){ .offset = Degree.one(), .coefficients = @splat(Degree.one()) };
    const ch = K.equations.ChallengesFor(Degree){ .chi = lookup, .xor5 = lookup, .io = .{ .offset = Degree.one(), .coefficients = @splat(Degree.one()) } };
    var sink = DegreeSink{};
    D.equations.emitFor(Degree, scratch.row(), &scratch.interaction, variable, Degree.one(), ch, .{ .calls = Degree.one(), .first_id = Degree.one(), .nonempty = Degree.one() }, &sink);
    try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
    try std.testing.expectEqual(@as(u8, 3), sink.max);
}

test "pair2n actual native2n PCS proof and fresh independently expected IO verifier" {
    const fixture = @import("../delegations/keccak/pair2n_fixture.zig");
    const inputs = [_]K.trace.State{inputState(1)};
    var encoded = try fixture.produce(a, &inputs, 1, 5, try fixture.config(false));
    defer encoded.deinit(a);
    try fixture.verify(a, &inputs, 1, 5, try fixture.config(false), encoded);
}

test "pair2n active poles reject before publication and retry while inactive inverse cannot carry ghost debt" {
    var trace = try D.trace.Trace.init(a, &.{inputState(1)}, 1, 5);
    defer trace.deinit();
    const bad = K.equations.Challenges{ .chi = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .xor5 = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .io = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) } };
    if (D.interaction.generate(&trace, bad)) |_| return error.AcceptedPole else |_| {}
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = K.equations.Challenges.draw(&channel);
    const claim = try D.interaction.generate(&trace, ch);
    const scratch = try a.create(D.component.ScratchFor(Q));
    defer a.destroy(scratch);
    const residuals = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(residuals);
    capture(&trace, 2, scratch);
    var sink = A.evaluation.Sink{ .values = residuals };
    D.equations.emitFor(Q, scratch.row(), &scratch.interaction, Q.zero(), claim, bad, .{ .calls = 1, .first_id = 1 }, &sink);
    try std.testing.expect(residuals[K.layout.DIRECT + 4].eql(Q.one().neg()));
    capture(&trace, 0, scratch);
    scratch.interaction[0] = Q.one();
    sink = .{ .values = residuals };
    D.equations.emitFor(Q, scratch.row(), &scratch.interaction, Q.zero(), claim, ch, .{ .calls = 1, .first_id = 1 }, &sink);
    try std.testing.expect(residuals[K.layout.DIRECT + 5].eql(Q.one()));
}
test "pair2n actual false prover cannot suppress active queries and valid foreign IO proofs are rejected" {
    const fixture = @import("../delegations/keccak/pair2n_fixture.zig");
    const inputs = [_]K.trace.State{inputState(3)};
    const cfg = try fixture.config(false);
    try std.testing.expectError(error.ConstraintsNotSatisfied, fixture.testing.suppressEnable(a, &inputs, 1, 5, cfg));
    const foreign = [_]K.trace.State{inputState(4)};
    var encoded = try fixture.testing.wrongWitness(a, &inputs, &foreign, 1, 5, cfg);
    defer encoded.deinit(a);
    try fixture.testing.verifyPhysical(a, &inputs, 1, 5, cfg, encoded);
    try std.testing.expectError(error.UnclosedPair2nPublicIo, fixture.verify(a, &inputs, 1, 5, cfg, encoded));
}
test "pair2n call IDs permit maximum active span and reject overflow before allocation" {
    const inputs = [_]K.trace.State{ inputState(1), inputState(2), inputState(3) };
    var trace = try D.trace.Trace.init(a, &inputs, core.fields.m31.Modulus - 3, 7);
    defer trace.deinit();
    try std.testing.expectError(error.InvalidKeccakCallId, D.trace.Trace.init(a, &inputs, core.fields.m31.Modulus - 2, 7));
}

test "pair2n existing pool 1 3 8 16 workers give identical actual native quotient and complete proof bytes" {
    const engine = @import("stwo_prover_engine");
    const fixture = @import("../delegations/keccak/pair2n_fixture.zig");
    const inputs = [_]K.trace.State{ inputState(1), inputState(2), inputState(3), inputState(4), inputState(5) };
    var control: ?[]u8 = null;
    defer if (control) |bytes| a.free(bytes);
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = if (@import("builtin").mode == .Debug) 1 << 20 else 256 << 10 });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        // N1024 selects all16 row workers; this is not a tiny serial fallback.
        var encoded = try fixture.produce(a, &inputs, 1, 10, try fixture.config(false));
        defer encoded.deinit(a);
        try fixture.verify(a, &inputs, 1, 10, try fixture.config(false), encoded);
        if (control) |bytes| try std.testing.expectEqualSlices(u8, bytes, encoded.bytes) else control = try a.dupe(u8, encoded.bytes);
    }
}
fn allocationTrace(allocator: std.mem.Allocator, ch: K.equations.Challenges) !void {
    var trace = try D.trace.Trace.init(allocator, &.{inputState(7)}, 1, 5);
    defer trace.deinit();
    trace.releaseMain();
    _ = try D.interaction.generate(&trace, ch);
}
test "pair2n released MAIN interaction construction cleans every allocation failure" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = K.equations.Challenges.draw(&channel);
    try std.testing.checkAllAllocationFailures(a, allocationTrace, .{ch});
}
