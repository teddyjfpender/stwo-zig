//! Pure-P2 local child verifier. Numerical transcript parity is tested separately;
//! complete execution/physical terminal binding remains a required obligation.
//! SAME local GKR transcript, closure and canonical receipt as native CPU.
//! Still a pending obligation: caller must verify cpu_oods' terminal binding
//! and all original physical AIRs under the native PCS before accepting.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const C = @import("full_p2_common.zig");
const Public = @import("full_p2_frame.zig");
const G = @import("../logup_gkr/om31_circuit_verifier.zig");
const Native = @import("../word16_global_execution/services/gkr_local/child.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Receipt = @import("../word16_global_execution/services/gkr_local/receipt.zig");
const Challenges = @import("../word16_global_execution/services/gkr_local/challenges.zig");
const Closure = @import("../word16_global_execution/services/gkr_local/closure.zig");
const B = circuit.builder;
pub const Scope = struct { statement: Public.Digest, fixed: C.Hash, main: C.Hash, ordinal: Public.Word };
pub const Pending = struct {
    artifact: engine.lookups.verifier_kernel.Artifact(C.F),
    challenges: Challenges.For(C.F),
    eta: C.F,
    receipt: C.Hash,
};
const Channel = struct {
    ctx: *C.Context,
    channel: C.Channel,
    failure: ?anyerror = null,
    pub fn mixU32s(self: *@This(), words: []const u32) void {
        if (self.failure != null) return;
        self.channel.mixConstU32s(self.ctx, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixFelts(self: *@This(), values: []const C.F) void {
        if (self.failure != null) return;
        self.channel.mixFelts(self.ctx, values) catch |err| {
            self.failure = err;
        };
    }
    pub fn drawSecureFelt(self: *@This()) C.F {
        if (self.failure != null) return C.F.zero();
        return self.channel.draw(self.ctx) catch |err| {
            self.failure = err;
            return C.F.zero();
        };
    }
    fn finish(self: *@This()) !void {
        if (self.failure) |err| return err;
        try C.lane.check();
    }
};
fn begin(ctx: *C.Context, scope: Scope, instances: []const Frame.Instance) !Channel {
    var ch = try C.Channel.init(ctx);
    try ch.mixConstU32s(ctx, &@import("pure_p2_native.zig").LOCAL_DOMAIN);
    try ch.mixU32s(ctx, &.{ try B.wrappers.constU32(C.Q, ctx, if (Frame.v3Instances(instances)) 0x53474b33 else 0x53474b31), try B.wrappers.constU32(C.Q, ctx, 8), scope.ordinal });
    try ch.mixU32s(ctx, &scope.statement);
    try ch.mixRoot(ctx, scope.fixed);
    try ch.mixRoot(ctx, scope.main);
    try ch.mixConstU32s(ctx, &.{@intCast(instances.len)});
    for (instances) |instance| {
        try ch.mixConstU32s(ctx, &Frame.originWords(instance.origin));
        try ch.mixConstU32s(ctx, &.{ instance.row_log, instance.terms });
        try ch.mixConstU32s(ctx, &.{ @truncate(instance.fixed_offset), @intCast(instance.fixed_offset >> 32) });
        try ch.mixConstU32s(ctx, &.{ @truncate(instance.main_offset), @intCast(instance.main_offset >> 32) });
    }
    return .{ .ctx = ctx, .channel = ch };
}
const Checks = struct {
    ctx: *C.Context,
    pub fn requireEq(self: @This(), left: C.F, right: C.F, _: anytype) !void {
        try C.eq(self.ctx, left, right);
    }
};
/// Typed receipt: canonical fields/roots never expand to four byte columns.
/// Raw u32s still use checked 16-bit halves and never reduce modulo M31.
const Writer = struct {
    ctx: *C.Context,
    sponge: @import("sponge.zig").ForContext(@import("context.zig").Context),
    failure: ?anyerror = null,
    fn init(ctx: *C.Context) !@This() {
        return .{ .ctx = ctx, .sponge = try @import("sponge.zig").ForContext(@import("context.zig").Context).init(try C.sidecar(ctx), .words) };
    }
    pub fn tag(self: *@This(), value: u32) void {
        if (self.failure != null) return;
        self.sponge.absorbConstU32(value) catch |err| {
            self.failure = err;
        };
    }
    fn word(self: *@This(), value: Public.Word) !void {
        const lanes = B.simd.Simd.fromPacked(&[1]C.Var{value.get()}, 4);
        for (0..4) |i| {
            const part = try B.simd.unpackIdx(C.Q, self.ctx, lanes, i);
            if (i < 2) {
                const checked = try self.ctx.guessU16(if (self.ctx.trace_only) B.ivalue.placeholder(C.Q) else self.ctx.get(part));
                try self.ctx.eq(part, checked);
                try self.sponge.absorb(checked);
            } else try self.ctx.eq(part, self.ctx.zero());
        }
    }
    pub fn integer(self: *@This(), value: anytype) void {
        if (self.failure != null) return;
        if (@TypeOf(value) == Public.Word) {
            self.word(value) catch |err| {
                self.failure = err;
                return;
            };
            self.sponge.absorbConstU32(0) catch |err| {
                self.failure = err;
            };
        } else self.sponge.absorbConstU64(@intCast(value)) catch |err| {
            self.failure = err;
        };
    }
    pub fn rawDigest(self: *@This(), words: Public.Digest) void {
        if (self.failure != null) return;
        for (words) |value| self.word(value) catch |err| {
            self.failure = err;
            return;
        };
    }
    pub fn root(self: *@This(), values: C.Hash) void {
        if (self.failure != null) return;
        self.sponge.absorbMany(&values) catch |err| {
            self.failure = err;
        };
    }
    pub fn field(self: *@This(), value: C.F) !void {
        const lanes = B.simd.Simd.fromPacked(&[2]C.Var{ value.c0.v, value.c1.v }, 8);
        for (0..8) |i| try self.sponge.absorb(try B.simd.unpackIdx(C.Q, self.ctx, lanes, i));
    }
    fn finish(self: *@This()) !C.Hash {
        if (self.failure) |err| return err;
        return self.sponge.finish();
    }
};
pub fn verify(ctx: *C.Context, scope: Scope, instances: []const Frame.Instance, proof: *const G.Proof) !Pending {
    if (instances.len == 0 or instances.len > Receipt.MAX_INSTANCES) return error.LocalGkrReceiptShape;
    var channel = try begin(ctx, scope, instances);
    const challenges = Challenges.For(C.F).drawForInstances(&channel, instances);
    const gates = try ctx.scratch().alloc(engine.lookups.gkr_verifier.ForField(C.O).Gate, instances.len);
    @memset(gates, .LogUp);
    var artifact = try engine.lookups.verifier_kernel.partiallyVerifyBatch(C.F, ctx.gpa, gates, proof, &channel, Checks{ .ctx = ctx });
    errdefer artifact.deinit(ctx.gpa);
    try channel.finish();
    if (artifact.n_variables_by_instance.len != instances.len) return error.LocalGkrPointGeometryMismatch;
    for (instances, artifact.n_variables_by_instance) |instance, n| if (n != try instance.variables() or artifact.ood_point.len < n) return error.LocalGkrPointGeometryMismatch;
    const inverses = try ctx.scratch().alloc(C.F, proof.output_claims_by_instance.len);
    for (proof.output_claims_by_instance, inverses) |pair, *inv| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        inv.* = pair[1].inv();
    }
    try Closure.closeFor(C.F, proof.output_claims_by_instance, inverses, Checks{ .ctx = ctx });
    var writer = try Writer.init(ctx);
    try @import("pure_p2_framing.zig").emit(scope, instances, proof, artifact.claims_to_verify_by_instance, &writer);
    const receipt = try writer.finish();
    const eta = channel.drawSecureFelt();
    try channel.finish();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .receipt = receipt };
}
