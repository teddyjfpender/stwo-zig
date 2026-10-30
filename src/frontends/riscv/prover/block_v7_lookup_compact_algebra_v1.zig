//! Exact native lookup tuple language, with dense and Boolean sparse encodings.
//! No new challenges: both encodings discharge the same original native tuple.
const std = @import("std");
const R = @import("block_v7_memory_relations_v1.zig");
pub const Schema = @import("../air/lookups/tables/schema.zig");
pub const Mode = enum(u32) { dense, sparse };
pub fn bits(comptime kind: Schema.Kind) usize {
    return switch (kind) {
        .bitwise => 16,
        .range_check_20 => 20,
        .range_check_8_11 => 19,
        .range_check_8_8_4 => 20,
        .range_check_8_8 => 16,
        .range_check_m31 => 15,
    };
}
pub fn For(comptime kind: Schema.Kind, comptime mode: Mode) type {
    return struct {
        const Self = @This();
        pub const FIXED_COUNT = if (mode == .dense) 1 + Schema.arity(kind) else 1;
        pub const MAIN_COUNT = if (mode == .dense) 1 else 1 + bits(kind) + (if (kind == .bitwise) @as(usize, 4) else if (kind == .range_check_m31) @as(usize, 1) else 0);
        pub const INTERACTION_COUNT = 4;
        pub const CONSTRAINT_COUNT = if (mode == .dense) 1 else bits(kind) + (if (kind == .bitwise) @as(usize, 5) else if (kind == .range_check_m31) @as(usize, 1) else 0) + 1;
        pub const DEGREE = if (mode == .sparse and kind == .bitwise) 4 else 2;
        // One composition split for the heterogeneous proof; lower-degree
        // components conservatively evaluate on the same four-way quotient split.
        pub const EXPANSION_BITS = 2;
        pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
        relation: R.Relation(R.Q, Schema.arity(kind)),
        sums: [1]R.Q,
        fn base(comptime S: type, n: u32) S {
            return R.base(S, n);
        }
        fn integer(comptime S: type, row: []const S) S {
            var value = S.zero();
            for (row, 0..) |bit, i| value = value.add(bit.mul(base(S, @as(u32, 1) << @as(u5, @intCast(i)))));
            return value;
        }
        pub fn tuple(comptime S: type, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) [Schema.arity(kind)]S {
            @setEvalBranchQuota(20000);
            if (comptime mode == .dense) return f[1..].*;
            const b = row[1..][0..bits(kind)];
            return switch (kind) {
                .range_check_20 => .{integer(S, b)},
                .range_check_8_11 => .{ integer(S, b[0..8]), integer(S, b[8..19]) },
                .range_check_8_8_4 => .{ integer(S, b[0..8]), integer(S, b[8..16]), integer(S, b[16..20]) },
                .range_check_8_8, .range_check_m31 => .{ integer(S, b[0..8]), integer(S, b[8..]) },
                .bitwise => blk: {
                    const op = row[17..21];
                    var output = S.zero();
                    for (b[0..8], b[8..16], 0..) |l, r, i| {
                        const both = l.mul(r);
                        const sum = l.add(r);
                        const result = op[0].mul(both).add(op[1].mul(sum.sub(both))).add(op[2].mul(sum.sub(both.add(both))));
                        output = output.add(result.mul(base(S, @as(u32, 1) << @as(u5, @intCast(i)))));
                    }
                    break :blk .{ integer(S, b[0..8]), integer(S, b[8..16]), output, op[1].add(op[2].mul(base(S, 2))).add(op[3].mul(base(S, 3))) };
                },
            };
        }
        pub fn direct(comptime S: type, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) [CONSTRAINT_COUNT - 1]S {
            @setEvalBranchQuota(20000);
            var out: [CONSTRAINT_COUNT - 1]S = undefined;
            if (comptime mode == .dense) return out;
            var at: usize = 0;
            for (row[1..][0..bits(kind)]) |b| {
                out[at] = b.mul(b.sub(S.one()));
                at += 1;
            }
            if (comptime kind == .bitwise) {
                var sum = S.zero();
                for (row[17..21]) |b| {
                    out[at] = b.mul(b.sub(S.one()));
                    at += 1;
                    sum = sum.add(b);
                }
                out[at] = sum.sub(S.one());
                at += 1;
            }
            if (comptime kind == .range_check_m31) {
                const values = tuple(S, f, row);
                const gap = base(S, 255).sub(values[0]).add(base(S, 127).sub(values[1]).mul(base(S, 256)));
                out[at] = gap.mul(row[MAIN_COUNT - 1]).sub(S.one());
                at += 1;
            }
            std.debug.assert(at == out.len);
            return out;
        }
        pub fn term(comptime S: type, relation: R.Relation(S, Schema.arity(kind)), f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) R.Term(S) {
            return .{ .left = relation.combineSecure(tuple(S, f, row)), .wl = row[0].neg() };
        }
        pub fn equations(comptime S: type, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S, current: [4]S, before: [4]S, relation: R.Relation(S, Schema.arity(kind)), norm: S) [CONSTRAINT_COUNT]S {
            return direct(S, f, row) ++ R.interactionConstraints(S, 1, .{term(S, relation, f, row)}, current, before, .{norm});
        }
        pub const Domain = struct {
            relation: R.Relation(R.Q, Schema.arity(kind)),
            packed_relation: R.Relation(R.P, Schema.arity(kind)),
            norm: R.Q,
            pub fn evaluate(self: @This(), f: [FIXED_COUNT]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [4]R.Q, before: [4]R.Q, size: u32) ![CONSTRAINT_COUNT]R.Q {
                _ = previous;
                _ = size;
                return equations(R.Q, f, row, current, before, self.relation, self.norm);
            }
            pub fn evaluatePacked(self: *const @This(), f: [FIXED_COUNT]R.P, row: [MAIN_COUNT]R.P, previous: [MAIN_COUNT]R.P, current: [4]R.P, before: [4]R.P) [CONSTRAINT_COUNT]R.P {
                _ = previous;
                return equations(R.P, f, row, current, before, self.packed_relation, R.P.splat(self.norm));
            }
        };
        pub fn prepareDomain(self: Self, size: u32) !Domain {
            var packed_relation: R.Relation(R.P, Schema.arity(kind)) = undefined;
            packed_relation.z = R.P.splat(self.relation.z);
            for (&packed_relation.powers, self.relation.powers) |*v, q| v.* = R.P.splat(q);
            return .{ .relation = self.relation, .packed_relation = packed_relation, .norm = (try R.normalize(1, self.sums, size))[0] };
        }
        pub fn evaluate(self: Self, f: [FIXED_COUNT]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [4]R.Q, before: [4]R.Q, size: u32) ![CONSTRAINT_COUNT]R.Q {
            return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
        }
        pub fn witness(tuple_value: Schema.Tuple, multiplicity: R.M) ![MAIN_COUNT]R.M {
            var out: [MAIN_COUNT]R.M = @splat(R.M.zero());
            out[0] = multiplicity;
            _ = try Schema.indexBase(kind, tuple_value.slice());
            if (comptime mode == .dense) return out;
            const encoded = try Schema.indexBase(kind, tuple_value.slice());
            for (out[1..][0..bits(kind)], 0..) |*v, i| v.* = R.M.fromCanonical(@intCast((encoded >> @as(u6, @intCast(i))) & 1));
            if (comptime kind == .bitwise) out[17 + tuple_value.values[3].toU32()] = R.M.one();
            if (comptime kind == .range_check_m31) out[MAIN_COUNT - 1] = try R.M.fromCanonical(@intCast(32767 - encoded)).inv();
            return out;
        }
    };
}
