//! P2v2 protocol over the existing OM31 circuit arithmetic. A scope explicitly
//! binds the dedicated Poseidon sidecar to its exact algebra context.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const Old = @import("../om31_native/common.zig");
pub const F = Old.F;
pub const Inner = Old.Inner;
pub const Q = Old.Q;
pub const O = Old.O;
pub const Var = Old.Var;
pub const Point = Old.Point;
pub const Context = Old.Context;
pub const Hash = @import("../../poseidon2_outer/sponge.zig").Hash;
pub const PoseidonContext = @import("../../poseidon2_outer/context.zig").Context;
pub const lane = Old.lane;
pub const eq = Old.eq;
pub const base = Old.base;
pub const doubleX = Old.doubleX;
pub const addPoint = Old.addPoint;
const CircuitChannel = @import("../../poseidon2_outer/channel.zig").ForContextV2(PoseidonContext, 8);
threadlocal var active: ?*PoseidonContext = null;
pub fn begin(ctx: *PoseidonContext) void {
    std.debug.assert(active == null);
    active = ctx;
    lane.begin(ctx.algebra());
}
pub fn finish() !void {
    defer active = null;
    try lane.finish();
}
pub fn sidecar(ctx: *Context) !*PoseidonContext {
    const owner = active orelse return error.PoseidonBuilderScopeRequired;
    if (owner.algebra() != ctx) return error.PoseidonBuilderScopeMismatch;
    return owner;
}
const Word = B.wrappers.U32Wrapper(Var);
const InnerChannel = struct {
    value: CircuitChannel,
    pub fn pow(self: *@This(), comptime V: type, ctx: *Context, bits: u32, nonce: [2]Word) !void {
        if (V != Q) @compileError("P2 circuit algebra is QM31");
        try self.value.pow(try sidecar(ctx), bits, nonce);
    }
    pub fn drawQueryBits(self: *@This(), comptime V: type, ctx: *Context, log: u32, count: usize) !@import("stwo_circuit_frontend").native_verifier.channel.QueryBits {
        if (V != Q) @compileError("P2 circuit algebra is QM31");
        return self.value.drawQueryBits(try sidecar(ctx), log, count);
    }
};
pub const Channel = struct {
    raw: struct { inner: InnerChannel },
    pub fn init(ctx: *Context) !@This() {
        return .{ .raw = .{ .inner = .{ .value = try CircuitChannel.init(try sidecar(ctx)) } } };
    }
    pub fn mixRoot(self: *@This(), ctx: *Context, root: Hash) !void {
        try self.raw.inner.value.mixRoot(try sidecar(ctx), root);
    }
    pub fn mixU32s(self: *@This(), ctx: *Context, words: []const Word) !void {
        try self.raw.inner.value.mixU32s(try sidecar(ctx), words);
    }
    pub fn mixU64(self: *@This(), ctx: *Context, lo: Word, hi: Word) !void {
        try self.raw.inner.value.mixU64(try sidecar(ctx), lo, hi);
    }
    pub fn mixConstU32s(self: *@This(), ctx: *Context, words: []const u32) !void {
        try self.raw.inner.value.mixConstU32s(try sidecar(ctx), words);
    }
    pub fn mixFelts(self: *@This(), ctx: *Context, values: []const F) !void {
        const fields = try ctx.scratch().alloc(CircuitChannel.Felt, values.len);
        for (fields, values) |*field, value| field.* = .{ value.c0.v, value.c1.v };
        try self.raw.inner.value.mixFelts(try sidecar(ctx), fields);
    }
    pub fn draw(self: *@This(), ctx: *Context) !F {
        const field = try self.raw.inner.value.drawSecureFelt(try sidecar(ctx));
        return F.wire(field[0], field[1]);
    }
    pub fn mixConfig(self: *@This(), ctx: *Context, config: core.pcs.PcsConfig) !void {
        var coordinates = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 8;
        coordinates[0] = core.fields.m31.M31.fromU32Unchecked(config.pow_bits);
        coordinates[1] = core.fields.m31.M31.fromU32Unchecked(config.fri_config.log_blowup_factor);
        coordinates[2] = core.fields.m31.M31.fromU32Unchecked(@intCast(config.fri_config.n_queries));
        coordinates[3] = core.fields.m31.M31.fromU32Unchecked(config.fri_config.log_last_layer_degree_bound);
        const first = F.fromM31Array(coordinates);
        if (config.fri_config.fold_step != core.fri.FOLD_STEP or config.lifting_log_size != null) {
            @memset(&coordinates, core.fields.m31.M31.zero());
            coordinates[0] = core.fields.m31.M31.fromU32Unchecked(config.fri_config.fold_step);
            coordinates[1] = core.fields.m31.M31.fromU32Unchecked(config.lifting_log_size orelse 0);
            try self.mixFelts(ctx, &.{ first, F.fromM31Array(coordinates) });
        } else try self.mixFelts(ctx, &.{first});
    }
};
