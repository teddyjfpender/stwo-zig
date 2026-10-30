//! New range20 provider encoding, preserving the exact native unary tuple.
//! v=b0+256*b1+65536*b2. Two byte-pair requests authenticate (b0,b1)
//! and (b2,15-b2). Since both second-pair values are bytes, their integer
//! sum15 cannot wrap M31; hence b2<=15 and v<2^20. No Boolean sidecar.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("block_v7_memory_relations_v1.zig");
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42385242;
pub const production_active = false;
pub const Spec = struct {
    pub const FIXED_COUNT = 1;
    pub const MAIN_COUNT = 4;
    pub const PLANES = 2;
    pub const INTERACTION_COUNT = 8;
    pub const CONSTRAINT_COUNT = 2;
    pub const DEGREE = 3;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [4]bool = @splat(false);
    range20: R.Relation(R.Q, 1),
    bytes: R.Relation(R.Q, 2),
    sums: [2]R.Q,
    pub fn value(comptime S: type, row: [4]S) S {
        return row[1].add(row[2].mul(R.base(S, 256))).add(row[3].mul(R.base(S, 65536)));
    }
    pub fn terms(comptime S: type, range20: R.Relation(S, 1), bytes: R.Relation(S, 2), f: [1]S, row: [4]S) [2]R.Term(S) {
        return .{
            .{ .left = range20.combineSecure(.{value(S, row)}), .wl = row[0].neg() },
            .{ .left = bytes.combineSecure(.{ row[1], row[2] }), .wl = f[0].neg(), .right = bytes.combineSecure(.{ row[3], R.base(S, 15).sub(row[3]) }), .wr = f[0].neg() },
        };
    }
    fn relation(comptime S: type, comptime n: usize, input: R.Relation(R.Q, n)) R.Relation(S, n) {
        var out: R.Relation(S, n) = undefined;
        out.z = R.lift(S, input.z);
        for (&out.powers, input.powers) |*v, q| v.* = R.lift(S, q);
        return out;
    }
    pub const Domain = struct {
        range20: R.Relation(R.Q, 1),
        bytes: R.Relation(R.Q, 2),
        range20_packed: R.Relation(R.P, 1),
        bytes_packed: R.Relation(R.P, 2),
        norm: [2]R.Q,
        pub fn evaluate(self: @This(), f: [1]R.Q, row: [4]R.Q, previous: [4]R.Q, current: [8]R.Q, before: [8]R.Q, size: u32) ![2]R.Q {
            _ = previous;
            _ = size;
            return R.interactionConstraints(R.Q, 2, terms(R.Q, self.range20, self.bytes, f, row), current, before, self.norm);
        }
        pub fn evaluatePacked(self: *const @This(), f: [1]R.P, row: [4]R.P, previous: [4]R.P, current: [8]R.P, before: [8]R.P) [2]R.P {
            _ = previous;
            return R.interactionConstraints(R.P, 2, terms(R.P, self.range20_packed, self.bytes_packed, f, row), current, before, .{ R.P.splat(self.norm[0]), R.P.splat(self.norm[1]) });
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        return .{ .range20 = self.range20, .bytes = self.bytes, .range20_packed = relation(R.P, 1, self.range20), .bytes_packed = relation(R.P, 2, self.bytes), .norm = try R.normalize(2, self.sums, size) };
    }
    pub fn evaluate(self: Spec, f: [1]R.Q, row: [4]R.Q, previous: [4]R.Q, current: [8]R.Q, before: [8]R.Q, size: u32) ![2]R.Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
    pub fn witness(v: u32, m: R.M) ![4]R.M {
        if (v >= 1 << 20) return error.InvalidRange20Value;
        return .{ m, R.M.fromCanonical(v & 255), R.M.fromCanonical((v >> 8) & 255), R.M.fromCanonical(v >> 16) };
    }
};
/// Seven distinct authenticated physical planes. Legacy six-claim APIs retain
/// their original type/schema; no R20/byte cancellation is hidden in a scalar.
pub const Profile = enum { legacy_six, bytes20_v1 };
pub fn ClaimsFor(comptime profile: Profile) type {
    return if (profile == .legacy_six) @import("block_v7_complete_union_lookup_v1.zig").Claims else struct { native: [6]R.Q, range20_bytes: R.Q };
}
pub const Claims = ClaimsFor(.bytes20_v1);
pub fn recordClaims(ch: anytype, claims: Claims) !void {
    ch.mixU32s(&.{ TAG, VERSION, 7 });
    for (claims.native) |q| {
        for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidRange20Claim;
        ch.mixFelts(&.{q});
    }
    for (claims.range20_bytes.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidRange20Claim;
    ch.mixFelts(&.{claims.range20_bytes});
}
