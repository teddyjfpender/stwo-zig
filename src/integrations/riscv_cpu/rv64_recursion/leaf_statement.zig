//! The RV64 Ethereum batch as a statement of the in-circuit native verifier.
//! The public prefix, the tagged challenge draws and the claim felts are
//! replayed by the transcript walkers through the circuit sink; the
//! composition polynomial at the OODS point is the batch roster's own
//! constraint code instantiated over the circuit lane; the claim closure is
//! `closure.enforce`; the eight outputs are the Blake2s of the free words.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const A = @import("../rv64_authenticated_execution.zig");
const walk = @import("transcript_walk.zig");
const public_wires = @import("public_wires.zig");
const closure = @import("closure.zig");
const lane_mod = @import("circuit_lane.zig");
const point_eval = @import("../rv64_point_evaluation.zig");

const Q = core.fields.qm31.QM31;
const builder = circuit.builder;
const Context = builder.Context(Q);
const Var = builder.Var;
const Error = builder.context.Error;
const nv = circuit.native_verifier;
const NativeChannel = nv.channel.NativeChannel;
const Point = circuit.stark_verifier.circle.Point;
const Lane = lane_mod.Lane;
const VerifyError = nv.verify.VerifyError;

/// Statement-side failures surface to the verifier as `ShapeMismatch`;
/// builder failures pass through unchanged.
fn mapError(err: anyerror) VerifyError {
    std.log.err("rv64 recursion statement: {s}", .{@errorName(err)});
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.EqFailedOnEval => error.EqFailedOnEval,
        error.TooManyVars => error.TooManyVars,
        else => error.ShapeMismatch,
    };
}

/// The channel as the circuit sink expects it: bound to one context.
pub const ChannelAdapter = struct {
    ctx: *Context,
    inner: *NativeChannel,
    pub fn mixU32s(self: *ChannelAdapter, words: []const builder.wrappers.U32Wrapper(Var)) Error!void {
        return self.inner.mixU32s(Q, self.ctx, words);
    }
    pub fn mixFelts(self: *ChannelAdapter, felts: []const Var) Error!void {
        return self.inner.mixFelts(Q, self.ctx, felts);
    }
    pub fn drawSecureFelt(self: *ChannelAdapter) Error!Var {
        return self.inner.drawSecureFelt(Q, self.ctx);
    }
    pub fn drawSecureFelts(self: *ChannelAdapter, n: usize) Error![]Var {
        return self.inner.drawSecureFelts(Q, self.ctx, n);
    }
};
pub const Sink = public_wires.CircuitSink(ChannelAdapter);

/// Everything the statement needs besides the proof: the batch's public
/// values and claims (the sink's guess values), its verification view and
/// the component roster whose constraints it evaluates.
pub const Statement = struct {
    arena: std.mem.Allocator,
    view: A.VerificationView,
    public: A.Public,
    claims: A.Claims,
    roster: *const point_eval.Roster,
    layout: closure.Layout,
    flat: point_eval.Layout.Publics,
    sink: ?Sink = null,

    pub const Challenges = struct {
        /// Every drawn challenge in draw order.
        draws: []const Var,
    };

    pub fn init(arena: std.mem.Allocator, view: A.VerificationView, public: A.Public, claims: A.Claims, roster: *const point_eval.Roster) !Statement {
        if (public.cpu.statement.cells.len != 0 or public.cpu.statement.memory_clocks.len != 0) return error.UnsupportedRv64RecursionStatement;
        if (view.has_ram != (claims.ram != null)) return error.InvalidAuthenticatedRamClaims;
        const flags = point_eval.Layout.Flags.fromView(view);
        return .{ .arena = arena, .view = view, .public = public, .claims = claims, .roster = roster, .layout = try closure.Layout.init(view, public), .flat = point_eval.Layout.Publics.init(flags) };
    }

    fn sinkFor(self: *Statement, ctx: *Context, channel: *NativeChannel) *Sink {
        if (self.sink == null) {
            const adapter = self.arena.create(ChannelAdapter) catch @panic("statement arena");
            adapter.* = .{ .ctx = ctx, .inner = channel };
            self.sink = Sink.init(ctx, adapter, self.arena);
        }
        self.sink.?.channel.ctx = ctx;
        self.sink.?.channel.inner = channel;
        return &self.sink.?;
    }

    pub fn mixPublic(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!void {
        walk.walkPublic(self.sinkFor(ctx, channel), self.view, self.public) catch |err| return mapError(err);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!Challenges {
        const sink = self.sinkFor(ctx, channel);
        walk.walkDraws(sink, self.view) catch |err| return mapError(err);
        if (sink.drawn.items.len != self.layout.total_draws) return error.ShapeMismatch;
        return .{ .draws = sink.drawn.items };
    }
    pub fn mixClaims(self: *Statement, ctx: *Context, channel: *NativeChannel) VerifyError!void {
        const sink = self.sinkFor(ctx, channel);
        walk.walkClaims(sink, self.view, self.public, self.claims) catch |err| return mapError(err);
        if (sink.claim_wires.items.len != self.layout.total_claims) return error.ShapeMismatch;
    }

    /// `Components.evalCompositionPolynomialAtPoint` over the circuit lane.
    pub fn evalComposition(self: *Statement, ctx: *Context, oods: Point(Var), sampled: []const []const []const Var, randomness: Var, challenges: Challenges) VerifyError!Var {
        const sink = &self.sink.?;
        const masks = Masks{ .sampled = sampled };
        const flat_publics = self.flatPublics(ctx) catch |err| return mapError(err);
        lane_mod.begin(ctx);
        const result = point_eval.evalCompositionAtPointFor(Lane, self.roster, .{ .x = Lane.wire(oods.x), .y = Lane.wire(oods.y) }, masks, Lane.wire(randomness), try lanes(self.arena, challenges.draws), try lanes(self.arena, sink.claim_wires.items), flat_publics);
        lane_mod.finish() catch |err| return mapError(err);
        return (result catch |err| return mapError(err)).v;
    }

    /// The flat public scalars (`rv64_point_layout.Publics`): layout-derived
    /// entries as constants, free entries as the sink's wires.
    fn flatPublics(self: *Statement, ctx: *Context) ![]Lane {
        const sink = &self.sink.?;
        const native = try point_eval.Layout.flattenPublics(self.arena, self.flat, self.public);
        const out = try self.arena.alloc(Lane, native.len);
        lane_mod.begin(ctx);
        for (out, native) |*lane, value| lane.* = Lane.fromQm31(value);
        try lane_mod.finish();
        out[self.flat.steps] = Lane.wire(try sink.role(.steps));
        for (0..8) |i| {
            out[self.flat.initial_pc + i] = Lane.wire(sink.u64s.items[0].bytes[i]);
            out[self.flat.final_pc + i] = Lane.wire(sink.u64s.items[1].bytes[i]);
        }
        if (self.flat.keccak) |start| try self.span(ctx, out[start..][0..3], .keccak_calls, .first_call_id);
        if (self.flat.secp) |starts| {
            try self.span(ctx, out[starts[0]..][0..3], .secp_calls_add, .secp_first_add);
            try self.span(ctx, out[starts[1]..][0..3], .secp_calls_double, .secp_first_double);
        }
        if (self.flat.division_count) |start| out[start] = Lane.wire(try sink.role(.division_requests));
        if (self.flat.multiplication_count) |start| out[start] = Lane.wire(try sink.role(.multiplication_requests));
        return out;
    }

    /// A service span `(calls, first_id, calls != 0)`: the flag is a
    /// witnessed Boolean with `calls * (1 - flag) = 0` and `flag = calls * inv`.
    fn span(self: *Statement, ctx: *Context, out: *[3]Lane, calls_kind: walk.Kind, first_kind: walk.Kind) !void {
        const sink = &self.sink.?;
        const calls = try sink.role(calls_kind);
        const first = try sink.role(first_kind);
        const calls_value = ctx.get(calls);
        const flag_value: Q = if (calls_value.isZero()) Q.zero() else Q.one();
        const flag = try ctx.guess(flag_value);
        const one_minus = try ctx.sub(ctx.one(), flag);
        try ctx.eq(try ctx.mul(flag, one_minus), ctx.zero());
        try ctx.eq(try ctx.mul(calls, one_minus), ctx.zero());
        const inverse = try ctx.guess(if (calls_value.isZero()) Q.zero() else try calls_value.inv());
        try ctx.eq(try ctx.mul(calls, inverse), flag);
        out[0] = Lane.wire(calls);
        out[1] = Lane.wire(first);
        out[2] = Lane.wire(flag);
    }

    /// After `verify`: the claim closure, the byte range checks and the
    /// output digest.
    pub fn finish(self: *Statement, ctx: *Context) !builder.blake.HashValue(Var) {
        const sink = &self.sink.?;
        try closure.enforce(ctx, self.layout, self.view, self.public, .{
            .u64s = sink.u64s.items,
            .digests = sink.digests.items,
            .clocks = sink.clocks.items,
            .draws = sink.drawn.items,
            .claims = sink.claim_wires.items,
        });
        try sink.rangeCheckBytes();
        return sink.bindOutputDigest();
    }

    pub fn statementWords(self: *const Statement, ctx: *const Context) ![]u32 {
        const sink = &self.sink.?;
        const words = try self.arena.alloc(u32, sink.free.items.len);
        for (words, sink.free.items) |*word, wire| word.* = builder.ivalue.unpackU32(Q, ctx.get(wire.get()));
        return words;
    }
};

fn lanes(arena: std.mem.Allocator, wires: []const Var) std.mem.Allocator.Error![]Lane {
    const out = try arena.alloc(Lane, wires.len);
    for (out, wires) |*lane, wire| lane.* = Lane.wire(wire);
    return out;
}

/// Sampled values by (tree, column, sample) as lane values (`lane.zig`
/// masks contract).
pub const Masks = struct {
    sampled: []const []const []const Var,
    pub fn count(self: Masks, tree: usize, column: usize) !usize {
        if (tree >= self.sampled.len or column >= self.sampled[tree].len) return error.InvalidRv64MaskShape;
        return self.sampled[tree][column].len;
    }
    pub fn at(self: Masks, tree: usize, column: usize, sample: usize) !Lane {
        if (sample >= try self.count(tree, column)) return error.InvalidRv64MaskShape;
        return Lane.wire(self.sampled[tree][column][sample]);
    }
};
