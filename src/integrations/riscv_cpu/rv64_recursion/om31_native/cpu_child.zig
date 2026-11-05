//! SAME local GKR transcript, closure and canonical receipt as native CPU.
//! Still a pending obligation: caller must verify cpu_oods' terminal binding
//! and all original physical AIRs under the native PCS before accepting.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Public = @import("frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Native = @import("../../word16_global_execution/services/gkr_local/child.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
const Receipt = @import("../../word16_global_execution/services/gkr_local/receipt.zig");
const Challenges = @import("../../word16_global_execution/services/gkr_local/challenges.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const B = circuit.builder;
pub const Scope = struct { statement: Public.Digest, fixed: Public.Digest, main: Public.Digest, ordinal: Public.Word };
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
    try ch.mixU32s(ctx, &.{ try B.wrappers.constU32(C.Q, ctx, if (Frame.v3Instances(instances)) 0x53474b33 else 0x53474b31), try B.wrappers.constU32(C.Q, ctx, 8), scope.ordinal });
    for ([_]Public.Digest{ scope.statement, scope.fixed, scope.main }) |digest| try ch.mixU32s(ctx, &digest);
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
/// Byte-exact Blake2s writer. Native receipt's 31-byte prefix deliberately
/// leaves every subsequent word unaligned. Byte range and packing constraints
/// preserve this encoding instead of rounding or reducing words modulo M31.
const Writer = struct {
    ctx: *C.Context,
    data: std.ArrayList(C.Var) = .empty,
    failure: ?anyerror = null,
    fn byteConstant(self: *@This(), value: u8) !void {
        try self.data.append(self.ctx.scratch(), try self.ctx.constant(C.Q.fromU32Unchecked(value, 0, 0, 0)));
    }
    fn word(self: *@This(), value: Public.Word) !void {
        const native = if (self.ctx.trace_only) 0 else B.ivalue.unpackU32(C.Q, self.ctx.get(value.get()));
        var octets: [4]C.Var = undefined;
        for (&octets, 0..) |*byte, i| {
            const n: u8 = @truncate(native >> @intCast(i * 8));
            byte.* = (try B.wrappers.guessU16(C.Q, self.ctx, .newUnsafe(C.Q.fromU32Unchecked(n, 0, 0, 0)))).get();
            const complement = (try B.wrappers.guessU16(C.Q, self.ctx, .newUnsafe(C.Q.fromU32Unchecked(255 - n, 0, 0, 0)))).get();
            try self.ctx.noteWitnessByte(byte.*, value.get(), @intCast(i), false);
            try self.ctx.noteWitnessByte(complement, value.get(), @intCast(i), true);
            try self.ctx.eq(try self.ctx.add(byte.*, complement), try self.ctx.constant(C.Q.fromU32Unchecked(255, 0, 0, 0)));
        }
        const k = try self.ctx.constant(C.Q.fromU32Unchecked(256, 0, 0, 0));
        const low = try self.ctx.add(octets[0], try self.ctx.mul(octets[1], k));
        const high = try self.ctx.add(octets[2], try self.ctx.mul(octets[3], k));
        const imag = try self.ctx.constant(C.Q.fromU32Unchecked(0, 1, 0, 0));
        try self.ctx.eq(value.get(), try self.ctx.add(low, try self.ctx.mul(high, imag)));
        try self.data.appendSlice(self.ctx.scratch(), &octets);
    }
    pub fn bytes(self: *@This(), values: anytype) void {
        if (self.failure != null) return;
        for (values) |v| {
            if (@TypeOf(v) == u8) self.byteConstant(v) catch |err| {
                self.failure = err;
                return;
            } else self.word(v) catch |err| {
                self.failure = err;
                return;
            };
        }
    }
    pub fn integer(self: *@This(), value: anytype) void {
        if (self.failure != null) return;
        if (@TypeOf(value) == Public.Word) {
            self.word(value) catch |err| {
                self.failure = err;
                return;
            };
            for (0..4) |_| self.byteConstant(0) catch |err| {
                self.failure = err;
                return;
            };
        } else {
            const n: u64 = @intCast(value);
            for (0..8) |i| self.byteConstant(@truncate(n >> @intCast(8 * i))) catch |err| {
                self.failure = err;
                return;
            };
        }
    }
    pub fn field(self: *@This(), value: C.F) !void {
        const words = try B.blake.unpackQm31sToU32Words(C.Q, self.ctx, &.{ value.c0.v, value.c1.v });
        for (words) |w| try self.word(w);
    }
    fn finish(self: *@This()) !C.Hash {
        if (self.failure) |err| return err;
        const n = self.data.items.len;
        const zero = try self.ctx.constant(C.Q.zero());
        while (self.data.items.len % 4 != 0) try self.data.append(self.ctx.scratch(), zero);
        const words = try self.ctx.scratch().alloc(Public.Word, self.data.items.len / 4);
        const k = try self.ctx.constant(C.Q.fromU32Unchecked(256, 0, 0, 0));
        const imag = try self.ctx.constant(C.Q.fromU32Unchecked(0, 1, 0, 0));
        for (words, 0..) |*out, i| {
            const b = self.data.items[4 * i ..][0..4];
            const lo = try self.ctx.add(b[0], try self.ctx.mul(b[1], k));
            const hi = try self.ctx.add(b[2], try self.ctx.mul(b[3], k));
            out.* = .newUnsafe(try self.ctx.add(lo, try self.ctx.mul(hi, imag)));
        }
        return B.blake.blake2sU32s(C.Q, self.ctx, words, n);
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
    var writer = Writer{ .ctx = ctx };
    try Receipt.emitCanonical(scope, instances, proof, artifact.claims_to_verify_by_instance, &writer);
    const receipt = try writer.finish();
    const eta = channel.drawSecureFelt();
    try channel.finish();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .receipt = receipt };
}
