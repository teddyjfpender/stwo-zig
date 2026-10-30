//! Dedicated v7 lookup namespace. No legacy initial/final image claims.
const std = @import("std");
const core = @import("stwo_core");
pub const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
pub const P = core.fields.packed_qm31.PackedQM31;
const Elements = @import("../air/relation_challenges.zig");
pub fn lift(comptime S: type, value: Q) S {
    if (S == Q) return value;
    return S.splat(value);
}
pub fn base(comptime S: type, value: u32) S {
    return lift(S, Q.fromBase(M.fromCanonical(value)));
}
pub fn Relation(comptime S: type, comptime n: usize) type {
    return struct {
        z: S,
        powers: [n]S,
        pub fn from(source: Elements.RelationElements(n)) @This() {
            var result: @This() = undefined;
            result.z = lift(S, source.z);
            for (&result.powers, source.alpha_powers) |*out, v| out.* = lift(S, v);
            return result;
        }
        pub fn combineSecure(self: @This(), values: [n]S) S {
            return Elements.combineGeneric(S, self.z, self.powers, values);
        }
    };
}
pub fn Challenges(comptime S: type) type {
    return struct {
        transition: Relation(S, 11),
        link: Relation(S, 13),
        interval: Relation(S, 6),
        range16: Relation(S, 1),
        pub fn from(source: Challenges(Q)) @This() {
            if (S == Q) return source;
            var out: @This() = undefined;
            inline for (.{ "transition", "link", "interval", "range16" }) |name| {
                @field(out, name).z = lift(S, @field(source, name).z);
                for (&@field(out, name).powers, @field(source, name).powers) |*v, x| v.* = lift(S, x);
            }
            return out;
        }
    };
}
pub fn draw(channel: *core.proof_suites.Blake3.Channel) Challenges(Q) {
    channel.mixU32s(&.{ 0x42374d52, 1, 11, 13, 6, 1 });
    var out: Challenges(Q) = undefined;
    inline for (.{ "transition", "link", "interval", "range16" }, .{ 11, 13, 6, 1 }) |name, n| {
        const z = channel.drawSecureFelt();
        const alpha = channel.drawSecureFelt();
        @field(out, name) = .from(Elements.RelationElements(n).init(z, alpha));
    }
    return out;
}
pub fn Term(comptime S: type) type {
    return struct {
        left: S = S.one(),
        right: S = S.one(),
        wl: S = S.zero(),
        wr: S = S.zero(),
        constant: S = S.zero(),
        pub fn fraction(self: @This()) !S {
            return self.constant.add(try self.wl.div(self.left)).add(try self.wr.div(self.right));
        }
        pub fn residual(self: @This(), change: S) S {
            return change.sub(self.constant).mul(self.left).mul(self.right).sub(self.wl.mul(self.right)).sub(self.wr.mul(self.left));
        }
    };
}
pub fn interactionConstraints(comptime S: type, comptime planes: usize, terms: [planes]Term(S), current: [4 * planes]S, previous: [4 * planes]S, normalized: [planes]S) [planes]S {
    var out: [planes]S = undefined;
    for (0..planes) |i| {
        const delta = S.fromPartialEvals(current[4 * i ..][0..4].*).sub(S.fromPartialEvals(previous[4 * i ..][0..4].*)).add(normalized[i]);
        out[i] = terms[i].residual(delta);
    }
    return out;
}
pub fn normalize(comptime n: usize, sums: [n]Q, size: u32) ![n]Q {
    if (size == 0 or size >= core.fields.m31.Modulus) return error.InvalidV7MemoryGeometry;
    var out: [n]Q = undefined;
    for (&out, sums) |*v, x| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&x)) return error.InvalidV7PhysicalClaim;
        v.* = try x.divM31(M.fromCanonical(size));
    }
    return out;
}
