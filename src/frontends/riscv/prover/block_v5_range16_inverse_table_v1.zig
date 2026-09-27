//! One bounded range16 inverse table per sealed relation challenge. Missing
//! (zero) denominators fail only when requested, exactly as batch inversion.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Relation = @import("../air/relation_challenges.zig").RelationElements(1);

pub const Table = struct {
    pub const VALUE_COUNT = 1 << 16;
    pub const RETAINED_BYTES = VALUE_COUNT * @sizeOf(Q);
    allocator: std.mem.Allocator,
    relation: Relation,
    values: []Q,

    pub fn init(a: std.mem.Allocator, relation: Relation) !Table {
        const values = try a.alloc(Q, VALUE_COUNT);
        errdefer a.free(values);
        const denominators = try a.alloc(Q, VALUE_COUNT);
        defer a.free(denominators);
        var zeros = std.StaticBitSet(VALUE_COUNT).initEmpty();
        var denominator = relation.combineBase(.{M.zero()});
        for (denominators, 0..) |*slot, index| {
            if (denominator.isZero()) zeros.set(index);
            slot.* = if (denominator.isZero()) Q.one() else denominator;
            denominator = denominator.add(relation.alpha_powers[0]);
        }
        try core.fields.batchInverseInPlace(Q, denominators, values);
        for (values, 0..) |*value, index| if (zeros.isSet(index)) {
            value.* = Q.zero();
        };
        return .{ .allocator = a, .relation = relation, .values = values };
    }

    pub fn deinit(self: *Table) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn requireRelation(self: *const Table, relation: Relation) !void {
        if (!std.meta.eql(self.relation, relation) or self.values.len != VALUE_COUNT)
            return error.ChangedV5RangeInverseChallenge;
    }

    pub fn inverse(self: *const Table, value: u32) !Q {
        if (value >= VALUE_COUNT) return error.InvalidWordRangeValue;
        const result = self.values[value];
        if (result.isZero()) return error.DivisionByZero;
        return result;
    }

    pub fn fraction(self: *const Table, value: Q, weight: Q) !Q {
        if (weight.isZero()) return Q.zero();
        const limbs = value.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidWordRangeValue;
        return (try self.inverse(limbs[0].toU32())).mul(weight);
    }
};
