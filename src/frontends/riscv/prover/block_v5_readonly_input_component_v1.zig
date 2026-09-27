//! Classification equations over an exact ALL-RW source transition multiset.
//! The fresh receiver links this proof to real native/caller access proofs.
//! Direct source trees are unchanged; production fusion is a separate batch.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const M = core.fields.m31.M31;
const Protocol = @import("block_v5_readonly_input_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
pub const Layout = struct {
    pub const word_bits = 0;
    pub const clock = 30; // four LE16 limbs; fresh source proves their width
    pub const before = 34; // two LE16 limbs
    pub const after = 36;
    pub const interval = 38; // lower, exclusive upper, readonly, valueLE16x2
    pub const lower_gap_bits = 43;
    pub const upper_gap_bits = 73;
    pub const len = 103;
};
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
        fn bits(values: []const S) S {
            var result = S.zero();
            var power = S.one();
            for (values) |value| {
                result = result.add(value.mul(power));
                power = power.add(power);
            }
            return result;
        }
        fn secure(values: []const S) S {
            var result = S.zero();
            for (values, 0..) |value, index| {
                var limbs: [4]M = @splat(M.zero());
                limbs[index] = M.one();
                result = result.add(value.mul(lift(Q.fromM31Array(limbs))));
            }
            return result;
        }
        pub fn address(row: [Layout.len]S) [2]S {
            // Two separate bounded limbs avoid any u32/M31 reduction alias.
            return .{ bits(row[0..14]).mul(constant(4)), bits(row[14..30]) };
        }
        pub fn sourceTuple(row: [Layout.len]S) [11]S {
            return .{S.one()} ++ address(row) ++ row[Layout.clock..][0..4].* ++ row[Layout.before..][0..2].* ++ row[Layout.after..][0..2].*;
        }
        fn combine(elements: anytype, tuple: anytype) S {
            var value = S.zero();
            for (tuple, elements.alpha_powers) |cell, power| value = value.add(cell.mul(lift(power)));
            return value.sub(lift(elements.z));
        }
        pub fn denominators(row: [Layout.len]S, challenges: anytype) [4]S {
            const source = combine(challenges.word.transition, sourceTuple(row));
            return .{ source, source, combine(challenges.classification, row[Layout.interval..][0..5].*), combine(challenges.read, address(row) ++ row[Layout.interval + 3 ..][0..2].*) };
        }
        pub fn numerators(active: S, row: [Layout.len]S) [5]S {
            const readonly = active.mul(row[Layout.interval + 2]);
            return .{ active.neg(), active.sub(readonly), active, readonly, readonly };
        }
        pub fn equations(active: S, row: [Layout.len]S, current: [20]S, previous: [20]S, shifts: [5]S, challenges: anytype) [205]S {
            @setEvalBranchQuota(100000);
            var out: [205]S = undefined;
            var at: usize = 0;
            // Independent public fixed activity/census; padded source cells
            // must be zero. No inactive/OODS field shortcut is taken.
            for ([_]usize{ Layout.word_bits, Layout.lower_gap_bits, Layout.upper_gap_bits }) |offset| {
                for (row[offset..][0..30]) |value| {
                    out[at] = value.mul(value.sub(S.one()));
                    at += 1;
                }
            }
            const readonly = row[Layout.interval + 2];
            out[at] = readonly.mul(readonly.sub(S.one()));
            at += 1;
            const word = bits(row[0..30]);
            out[at] = active.mul(word.sub(row[Layout.interval]).sub(bits(row[Layout.lower_gap_bits..][0..30])));
            at += 1;
            out[at] = active.mul(row[Layout.interval + 1].sub(word).sub(S.one()).sub(bits(row[Layout.upper_gap_bits..][0..30])));
            at += 1;
            inline for (0..2) |i| {
                out[at] = active.mul(readonly).mul(row[Layout.before + i].sub(row[Layout.interval + 3 + i]));
                at += 1;
                out[at] = active.mul(readonly).mul(row[Layout.after + i].sub(row[Layout.interval + 3 + i]));
                at += 1;
            }
            for (row) |value| {
                out[at] = S.one().sub(active).mul(value);
                at += 1;
            }
            const d = denominators(row, challenges);
            const n = numerators(active, row);
            inline for (0..5) |i| {
                const difference = secure(current[4 * i ..][0..4]).sub(secure(previous[4 * i ..][0..4])).add(shifts[i]);
                out[at] = if (i < 4) difference.mul(d[i]).sub(n[i]) else difference.sub(n[i]);
                at += 1;
            }
            std.debug.assert(at == out.len);
            return out;
        }
    };
}
pub const Spec = struct {
    pub const FIXED_COUNT = 1;
    pub const MAIN_COUNT = Layout.len;
    pub const INTERACTION_COUNT = 20;
    pub const CONSTRAINT_COUNT = 205;
    pub const DEGREE = 3;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
    claim: Protocol.Claim,
    challenges: *const Protocol.Challenges,
    pub const Domain = struct {
        spec: Spec,
        shifts: [5]Q,
        packed_shifts: [5]P,
        pub fn evaluate(self: Domain, fixed: [1]Q, row: [MAIN_COUNT]Q, _: [MAIN_COUNT]Q, current: [20]Q, previous: [20]Q, _: u32) ![205]Q {
            return Algebra(Q).equations(fixed[0], row, current, previous, self.shifts, self.spec.challenges);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [1]P, row: [MAIN_COUNT]P, _: [MAIN_COUNT]P, current: [20]P, previous: [20]P) [205]P {
            return Algebra(P).equations(fixed[0], row, current, previous, self.packed_shifts, self.spec.challenges);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        if (size == 0 or size >= core.fields.m31.Modulus or self.claim.readonly_count > size) return error.InvalidReadonlyInputClaim;
        const values = [_]Q{ self.claim.source_sum, self.claim.mutable_sum, self.claim.classification_sum, self.claim.read_sum, Q.fromBase(M.fromCanonical(@intCast(self.claim.readonly_count))) };
        var result = Domain{ .spec = self, .shifts = undefined, .packed_shifts = undefined };
        for (values, &result.shifts, &result.packed_shifts) |value, *shift, *packed_shift| {
            shift.* = try value.divM31(M.fromCanonical(size));
            packed_shift.* = P.splat(shift.*);
        }
        return result;
    }
    pub fn evaluate(self: Spec, fixed: [1]Q, row: [MAIN_COUNT]Q, prior: [MAIN_COUNT]Q, current: [20]Q, previous: [20]Q, size: u32) ![205]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, row, prior, current, previous, size);
    }
};
pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);

/// Public host witness from exact original transition limbs. A fresh source
/// multiset/count equality remains mandatory before this classification is used.
pub fn witnessRow(event: @import("../air/block/memory_transition.zig").Transition, interval: Plan.Interval) ![Layout.len]M {
    if (event.space != 1 or event.address & 3 != 0 or event.clock == 0) return error.InvalidReadonlyInputSourceEvent;
    const word = event.address / 4;
    if (word < interval.lower or word >= interval.upper or interval.upper > Plan.WORD_LIMIT or
        (interval.readonly and (interval.upper != interval.lower + 1 or event.before != interval.value or event.after != interval.value)))
        return error.InvalidReadonlyInputClassification;
    var result: [Layout.len]M = @splat(M.zero());
    const offsets = [_]usize{ Layout.word_bits, Layout.lower_gap_bits, Layout.upper_gap_bits };
    const integers = [_]u32{ word, word - interval.lower, interval.upper - word - 1 };
    for (offsets, integers) |offset, integer| {
        for (0..30) |bit| result[offset + bit] = M.fromCanonical((integer >> @intCast(bit)) & 1);
    }
    const tuple = @import("block_v5_word_memory_protocol_v1.zig").transitionTuple(event);
    @memcpy(result[Layout.clock..][0..8], tuple[3..11]);
    @memcpy(result[Layout.interval..][0..5], &Protocol.intervalTuple(interval));
    return result;
}
