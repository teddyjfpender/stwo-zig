//! A trivial external lane wrapping QM31 that counts operations. It exercises
//! the external-lane contract without any circuit; every result must equal
//! the native QM31 evaluation bit for bit.
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").rv64_air;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Ops = struct { add: usize = 0, sub: usize = 0, mul: usize = 0, neg: usize = 0, square: usize = 0, inv: usize = 0, constants: usize = 0 };
pub var ops: Ops = .{};
pub const TraceLane = struct {
    pub const rv64_external_lane = true;
    value: Q,
    pub fn zero() TraceLane {
        return .{ .value = Q.zero() };
    }
    pub fn one() TraceLane {
        return .{ .value = Q.one() };
    }
    pub fn fromU32(x: u32) TraceLane {
        ops.constants += 1;
        return .{ .value = Q.fromBase(M.fromCanonical(x)) };
    }
    pub fn fromBase(m: M) TraceLane {
        ops.constants += 1;
        return .{ .value = Q.fromBase(m) };
    }
    pub fn fromQm31(c: Q) TraceLane {
        return .{ .value = c };
    }
    pub fn fromPartialEvals(c: [4]TraceLane) TraceLane {
        return .{ .value = Q.fromPartialEvals(.{ c[0].value, c[1].value, c[2].value, c[3].value }) };
    }
    pub fn add(a: TraceLane, b: TraceLane) TraceLane {
        ops.add += 1;
        return .{ .value = a.value.add(b.value) };
    }
    pub fn sub(a: TraceLane, b: TraceLane) TraceLane {
        ops.sub += 1;
        return .{ .value = a.value.sub(b.value) };
    }
    pub fn mul(a: TraceLane, b: TraceLane) TraceLane {
        ops.mul += 1;
        return .{ .value = a.value.mul(b.value) };
    }
    pub fn neg(a: TraceLane) TraceLane {
        ops.neg += 1;
        return .{ .value = a.value.neg() };
    }
    pub fn square(a: TraceLane) TraceLane {
        ops.square += 1;
        return .{ .value = a.value.square() };
    }
    pub fn inv(a: TraceLane) TraceLane {
        ops.inv += 1;
        return .{ .value = a.value.inv() catch unreachable };
    }
};
comptime {
    air.lane.assertExternalLane(TraceLane);
}
/// Sampled-value accessor presenting the proof's QM31 masks as lane values.
pub const LaneMasks = struct {
    values: *const core.air.components.MaskValues,
    pub fn count(self: LaneMasks, tree: usize, column: usize) !usize {
        if (tree >= self.values.items.len or column >= self.values.items[tree].len) return error.InvalidRv64MaskShape;
        return self.values.items[tree][column].len;
    }
    pub fn at(self: LaneMasks, tree: usize, column: usize, index: usize) !TraceLane {
        const column_values = self.values.items[tree][column];
        if (index >= column_values.len) return error.InvalidRv64MaskShape;
        return TraceLane.fromQm31(column_values[index]);
    }
};
pub fn liftSlice(a: @import("std").mem.Allocator, values: []const Q) ![]TraceLane {
    const out = try a.alloc(TraceLane, values.len);
    for (out, values) |*lane, value| lane.* = TraceLane.fromQm31(value);
    return out;
}
pub fn liftPoint(point: core.circle.CirclePointQM31) air.geometry.PointFor(TraceLane) {
    return .{ .x = TraceLane.fromQm31(point.x), .y = TraceLane.fromQm31(point.y) };
}
