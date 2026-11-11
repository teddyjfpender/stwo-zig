//! The same typed source fraction emitter is used at native and lifted OODS
//! masks. No sampled row value or binding marginal is a free proof authority.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = @import("authority.zig");
const Fr = @import("fractions.zig");
pub const laneWeightsFor = @import("../truth_local_gkr/projection.zig").laneWeightsFor;
pub fn PublicFor(comptime C: type) type {
    return struct { calls: E.CountFor(C), permutations: E.CountFor(C), first_id: E.CountFor(C) };
}
pub fn evaluate(comptime role: R.Role, comptime F: type, view: anytype, public: PublicFor(E.ConstFor(F)), ch: Fr.ChallengesFor(E.ConstFor(F)), weights: []const E.ConstFor(F)) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (weights.len != @as(usize, 1) << @intCast(@import("std").math.log2_int_ceil(u32, R.localQueries(role)))) return error.SpongeLocalProjectionShape;
    var fixed: [R.fixedWidth(role)]F = undefined;
    var main: [R.mainWidth(role)]F = undefined;
    for (&fixed, 0..) |*v, c| v.* = view.fixed(c);
    for (&main, 0..) |*v, c| v.* = view.main(c);
    const fractions = Fr.collect(F, role, &fixed, &main, public.first_id, ch);
    if (fractions.count != R.localQueries(role)) return error.SpongeLocalQuery;
    var n = E.SecureFor(F).zero();
    var d = E.SecureFor(F).zero();
    for (weights[0..R.localQueries(role)], fractions.n, fractions.d) |w, nn, dd| {
        const ww = E.splatFor(F, w);
        n = n.add(E.mulBaseFor(F, ww, nn));
        d = d.add(ww.mul(dd));
    }
    for (weights[R.localQueries(role)..]) |w| d = d.add(E.splatFor(F, w));
    return .{ n, d };
}
