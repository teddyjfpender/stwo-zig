//! Additive experimental profiles: raw32-bit words reduced modulo M31 with no
//! rejection. This does not change legacy NativeChannel or select a PCS suite.
const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const Legacy = @import("channel.zig");
const Profiles = core.channel.raw_mod_m31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const Word = builder.wrappers.U32Wrapper(Var);
pub const Om31Var = struct {
    c0: Var,
    c1: Var,
    pub fn value(self: Om31Var, ctx: *const Context(Q)) O {
        return .{ .c0 = ctx.get(self.c0), .c1 = ctx.get(self.c1) };
    }
};
fn initInner(comptime V: type, ctx: *Context(V), profile: Profiles.Profile) Error!Legacy.NativeChannel {
    var inner = try Legacy.NativeChannel.init(V, ctx);
    var tag: [8]Word = undefined;
    for (&tag, profile.tag()) |*wire, word| wire.* = try builder.wrappers.constU32(V, ctx, word);
    try inner.mixU32s(V, ctx, &tag);
    return inner;
}
fn reduceQM31(comptime V: type, ctx: *Context(V), words: *const [4]Word) Error!Var {
    var coordinates: [4]Var = undefined;
    for (&coordinates, words) |*v, word| v.* = try Legacy.wordToM31(V, ctx, word);
    return builder.ops.fromPartialEvals(V, ctx, coordinates);
}
/// All eight raw words are represented, including fffffffe/ffffffff. The
/// existing constrained packed-u32 reduction is canonical over the whole u32.
pub fn reduceBlock(comptime V: type, ctx: *Context(V), words: *const [8]Word) Error!Om31Var {
    return .{ .c0 = try reduceQM31(V, ctx, words[0..4]), .c1 = try reduceQM31(V, ctx, words[4..8]) };
}
pub const Qm31Channel = struct {
    inner: Legacy.NativeChannel,
    pub const profile = Profiles.qm31_profile;
    pub fn init(comptime V: type, ctx: *Context(V)) Error!Qm31Channel {
        return .{ .inner = try initInner(V, ctx, profile) };
    }
    pub fn mixU32s(self: *Qm31Channel, comptime V: type, ctx: *Context(V), words: []const Word) Error!void {
        try self.inner.mixU32s(V, ctx, words);
    }
    pub fn mixU64(self: *Qm31Channel, comptime V: type, ctx: *Context(V), lo: Word, hi: Word) Error!void {
        try self.inner.mixU64(V, ctx, lo, hi);
    }
    pub fn mixFelts(self: *Qm31Channel, comptime V: type, ctx: *Context(V), values: []const Var) Error!void {
        try self.inner.mixFelts(V, ctx, values);
    }
    pub fn drawU32s(self: *Qm31Channel, comptime V: type, ctx: *Context(V)) Error![8]Word {
        return self.inner.drawU32s(V, ctx);
    }
    pub fn drawSecureFelt(self: *Qm31Channel, comptime V: type, ctx: *Context(V)) Error!Var {
        const words = try self.drawU32s(V, ctx);
        for (words[4..]) |word| try ctx.markAsMaybeUnused(word.get());
        return reduceQM31(V, ctx, words[0..4]);
    }
    pub fn drawSecureFelts(self: *Qm31Channel, comptime V: type, ctx: *Context(V), count: usize) Error![]Var {
        const out = try ctx.scratch().alloc(Var, count);
        var at: usize = 0;
        while (at < count) {
            const words = try self.drawU32s(V, ctx);
            out[at] = try reduceQM31(V, ctx, words[0..4]);
            at += 1;
            if (at < count) {
                out[at] = try reduceQM31(V, ctx, words[4..8]);
                at += 1;
            } else for (words[4..]) |word| try ctx.markAsMaybeUnused(word.get());
        }
        return out;
    }
};
pub const Om31Channel = struct {
    inner: Legacy.NativeChannel,
    pub const profile = Profiles.om31_profile;
    pub fn init(comptime V: type, ctx: *Context(V)) Error!Om31Channel {
        return .{ .inner = try initInner(V, ctx, profile) };
    }
    pub fn mixU32s(self: *Om31Channel, comptime V: type, ctx: *Context(V), words: []const Word) Error!void {
        try self.inner.mixU32s(V, ctx, words);
    }
    pub fn mixU64(self: *Om31Channel, comptime V: type, ctx: *Context(V), lo: Word, hi: Word) Error!void {
        try self.inner.mixU64(V, ctx, lo, hi);
    }
    pub fn mixFelts(self: *Om31Channel, comptime V: type, ctx: *Context(V), values: []const Om31Var) Error!void {
        const count = std.math.mul(usize, values.len, 2) catch return error.TooManyVars;
        const inner = try ctx.scratch().alloc(Var, count);
        for (values, 0..) |value, i| {
            inner[2 * i] = value.c0;
            inner[2 * i + 1] = value.c1;
        }
        try self.inner.mixFelts(V, ctx, inner);
    }
    pub fn drawU32s(self: *Om31Channel, comptime V: type, ctx: *Context(V)) Error![8]Word {
        return self.inner.drawU32s(V, ctx);
    }
    pub fn drawSecureFelt(self: *Om31Channel, comptime V: type, ctx: *Context(V)) Error!Om31Var {
        const words = try self.drawU32s(V, ctx);
        return reduceBlock(V, ctx, &words);
    }
    pub fn drawSecureFelts(self: *Om31Channel, comptime V: type, ctx: *Context(V), count: usize) Error![]Om31Var {
        const out = try ctx.scratch().alloc(Om31Var, count);
        for (out) |*value| value.* = try self.drawSecureFelt(V, ctx);
        return out;
    }
};
test {
    _ = @import("raw_mod_channel_test.zig");
}
