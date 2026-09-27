//! Exact unsigned fragmented multiplicities and signed group-keyed providers.
//! The nine dynamic limbs require separately verified original range16 tables.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Protocol = @import("block_v5_readonly_input_global_protocol_v2.zig");
pub const Claim = struct { classification_sum: Q, read_sum: Q, range_sums: [9]Q, counts: Table.Counts };
pub fn Algebra(comptime S: type) type {
    return struct {
        fn lift(value: anytype) S {
            if (@TypeOf(value) == S) return value;
            if (S == Q) return value;
            if (S == P) return P.splat(value);
            return S.fromSecure(value);
        }
        fn constant(value: u32) S {
            return lift(Q.fromBase(M.fromCanonical(value)));
        }
        fn secure(values: []const S) S {
            var result = S.zero();
            for (values, 0..) |value, i| {
                var limbs: [4]M = @splat(M.zero());
                limbs[i] = M.one();
                result = result.add(value.mul(lift(Q.fromM31Array(limbs))));
            }
            return result;
        }
        fn combine(elements: anytype, tuple: anytype) S {
            var result = S.zero();
            for (elements.alpha_powers, tuple) |power, value| result = result.add(lift(power).mul(value));
            return result.sub(lift(elements.z));
        }
        pub fn denominators(fixed: [10]S, main: [18]S, challenges: anytype) [11]S {
            var out: [11]S = undefined;
            out[0] = combine(challenges.classification, fixed[3..8].*);
            out[1] = combine(challenges.read, fixed[8..10].* ++ fixed[6..8].*);
            for (0..9) |i| out[i + 2] = combine(challenges.word.range16, [_]S{main[i]});
            return out;
        }
        pub fn numerators(fixed: [10]S, main: [18]S) [11]S {
            var out: [11]S = undefined;
            out[0] = fixed[0].mul(main[0]).neg();
            out[1] = out[0].mul(fixed[5]);
            for (out[2..]) |*value| value.* = S.one();
            return out;
        }
        pub fn equations(fixed: [10]S, main: [18]S, prior: [18]S, current: [44]S, previous: [44]S, shifts: [11]S, challenges: anytype, totals: [8]S) [48]S {
            @setEvalBranchQuota(100000);
            var out: [48]S = undefined;
            var at: usize = 0;
            const inactive = S.one().sub(fixed[0]);
            out[at] = main[0].mul(main[17]).sub(fixed[0]);
            at += 1;
            out[at] = inactive.mul(main[0]);
            at += 1;
            out[at] = inactive.mul(main[17]);
            at += 1;
            for (main[9..17]) |carry| {
                out[at] = carry.mul(carry.sub(S.one()));
                at += 1;
            }
            for (main[9..17]) |carry| {
                out[at] = inactive.mul(carry);
                at += 1;
            }
            inline for (0..2) |which| {
                const offset = if (which == 0) 1 else 5;
                const carry_offset = if (which == 0) 9 else 13;
                const amount = if (which == 0) main[0] else main[0].mul(fixed[5]);
                inline for (0..4) |limb| {
                    const before = prior[offset + limb].mul(S.one().sub(fixed[1]));
                    const incoming = if (limb == 0) amount else main[carry_offset + limb - 1];
                    out[at] = main[offset + limb].sub(before).sub(incoming).add(main[carry_offset + limb].mul(constant(65536)));
                    at += 1;
                    out[at] = fixed[2].mul(main[offset + limb].sub(totals[4 * which + limb]));
                    at += 1;
                }
                out[at] = main[carry_offset + 3];
                at += 1;
            }
            const d = denominators(fixed, main, challenges);
            const n = numerators(fixed, main);
            for (0..11) |i| {
                const difference = secure(current[4 * i ..][0..4]).sub(secure(previous[4 * i ..][0..4])).add(shifts[i]);
                out[at] = difference.mul(d[i]).sub(n[i]);
                at += 1;
            }
            std.debug.assert(at == out.len);
            return out;
        }
    };
}
// Byte-address limbs must be independently fixed: a30-bit lower ordinal
// cannot be split by unconstrained off-domain host arithmetic. They are added
// to the original8 fixed fields and reconstructed from the admitted Plan.
pub const Spec = struct {
    pub const FIXED_COUNT = 10;
    pub const MAIN_COUNT = 18;
    pub const INTERACTION_COUNT = 44;
    pub const CONSTRAINT_COUNT = 48;
    pub const DEGREE = 3;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = ([_]bool{false}) ++ ([_]bool{true} ** 8) ++ ([_]bool{false} ** 9);
    claim: Claim,
    challenges: *const Protocol.Challenges,
    pub const Domain = struct {
        spec: Spec,
        totals: [8]Q,
        shifts: [11]Q,
        packed_totals: [8]P,
        packed_shifts: [11]P,
        pub fn evaluate(self: Domain, fixed: [10]Q, main: [18]Q, prior: [18]Q, current: [44]Q, previous: [44]Q, _: u32) ![48]Q {
            return Algebra(Q).equations(fixed, main, prior, current, previous, self.shifts, self.spec.challenges, self.totals);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [10]P, main: [18]P, prior: [18]P, current: [44]P, previous: [44]P) [48]P {
            return Algebra(P).equations(fixed, main, prior, current, previous, self.packed_shifts, self.spec.challenges, self.packed_totals);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        if (size < 2 or size > Table.MAX_FRAGMENTS or self.claim.counts.events >= core.fields.m31.Modulus or self.claim.counts.readonly > self.claim.counts.events or self.claim.counts.range_requests != 9 * @as(u64, size)) return error.InvalidReadonlyProviderClaim;
        var result = Domain{ .spec = self, .totals = undefined, .shifts = undefined, .packed_totals = undefined, .packed_shifts = undefined };
        for ([_]u64{ self.claim.counts.events, self.claim.counts.readonly }, 0..) |value, which| for (0..4) |limb| {
            const v = Q.fromBase(M.fromCanonical(@intCast((value >> @as(u6, @intCast(16 * limb))) & 65535)));
            result.totals[4 * which + limb] = v;
            result.packed_totals[4 * which + limb] = P.splat(v);
        };
        const sums = [_]Q{ self.claim.classification_sum, self.claim.read_sum } ++ self.claim.range_sums;
        for (sums, &result.shifts, &result.packed_shifts) |sum, *shift, *packed_shift| {
            shift.* = try sum.divM31(M.fromCanonical(size));
            packed_shift.* = P.splat(shift.*);
        }
        return result;
    }
    pub fn evaluate(self: Spec, fixed: [10]Q, main: [18]Q, prior: [18]Q, current: [44]Q, previous: [44]Q, size: u32) ![48]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, main, prior, current, previous, size);
    }
};
pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
