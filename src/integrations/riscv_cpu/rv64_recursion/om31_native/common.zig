//! Eight-coordinate secure wires, with base/hash words in the existing QM31 builder.
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
pub const lane = @import("../om31_circuit_lane.zig");
pub const F = lane.Lane;
pub const Inner = @import("../circuit_lane.zig").Lane;
pub const Context = lane.Context;
pub const Q = core.fields.qm31.QM31;
pub const O = core.fields.om31.OM31;
pub const Var = circuit.builder.Var;
pub const Hash = circuit.builder.blake.HashValue(Var);
pub const Point = struct { x: F, y: F };
pub fn eq(ctx: *Context, a: F, b: F) !void {
    try ctx.eq(a.c0.v, b.c0.v);
    try ctx.eq(a.c1.v, b.c1.v);
}
pub fn base(v: Var) F {
    return F.fromInner(Inner.wire(v));
}
pub fn doubleX(x: F) F {
    return x.square().double().sub(F.one());
}
pub fn addPoint(p: Point, shift: core.circle.CirclePointM31) Point {
    const x = F.fromBase(shift.x);
    const y = F.fromBase(shift.y);
    return .{ .x = p.x.mul(x).sub(p.y.mul(y)), .y = p.x.mul(y).add(p.y.mul(x)) };
}
pub const Channel = struct {
    raw: circuit.native_verifier.raw_mod_channel.Om31Channel,
    pub fn init(ctx: *Context) !Channel {
        return .{ .raw = try circuit.native_verifier.raw_mod_channel.Om31Channel.init(Q, ctx) };
    }
    pub fn mixRoot(self: *Channel, ctx: *Context, root: Hash) !void {
        try self.raw.inner.mixRoot(Q, ctx, root);
    }
    pub fn mixU32s(self: *Channel, ctx: *Context, words: []const circuit.builder.wrappers.U32Wrapper(Var)) !void {
        try self.raw.mixU32s(Q, ctx, words);
    }
    pub fn mixFelts(self: *Channel, ctx: *Context, values: []const F) !void {
        const wires = try ctx.scratch().alloc(circuit.native_verifier.raw_mod_channel.Om31Var, values.len);
        for (wires, values) |*wire, value| wire.* = .{ .c0 = value.c0.v, .c1 = value.c1.v };
        try self.raw.mixFelts(Q, ctx, wires);
    }
    pub fn mixConfig(self: *Channel, ctx: *Context, config: core.pcs.PcsConfig) !void {
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
    pub fn draw(self: *Channel, ctx: *Context) !F {
        const value = try self.raw.drawSecureFelt(Q, ctx);
        return F.wire(value.c0, value.c1);
    }
};
