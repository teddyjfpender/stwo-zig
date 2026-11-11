//! Isolated source-model diagnostic. No production emitter imports this file.
const std = @import("std");
pub const Snapshot = struct { rows: usize, add: usize, sub: usize, mul: usize, native_mul: usize };
pub const Counts = struct {
    queries: usize = 0,
    dots: usize = 0,
    terms: usize = 0,
    empty_dots: usize = 0,
    min_dot_length: usize = std.math.maxInt(usize),
    max_dot_length: usize = 0,
    qm31_rows: usize = 0,
    qm31_add: usize = 0,
    qm31_sub: usize = 0,
    qm31_mul: usize = 0,
    native_full_mul: usize = 0,
    zero_weight_c0: usize = 0,
    zero_weight_c1: usize = 0,
    one_weight_c0: usize = 0,
    one_weight_c1: usize = 0,
    scalar_zero_id: usize = 0,
    scalar_one_id: usize = 0,
    accumulator_zero_c0: usize = 0,
    accumulator_zero_c1: usize = 0,
    scalar_input_type_is_base_wrapper: bool = true,
    numerical_nonbase_slots_checked: bool = false,
};
threadlocal var active: ?*Counts = null;
pub const Scope = struct {
    previous: ?*Counts,
    pub fn begin(counts: *Counts) Scope {
        const previous = active;
        active = counts;
        return .{ .previous = previous };
    }
    pub fn deinit(self: *Scope) void {
        active = self.previous;
    }
};
pub fn query() void {
    if (active) |c| c.queries += 1;
}
pub fn dot(length: usize) void {
    if (active) |c| {
        c.dots += 1;
        c.terms += length;
        c.empty_dots += @intFromBool(length == 0);
        c.min_dot_length = @min(c.min_dot_length, length);
        c.max_dot_length = @max(c.max_dot_length, length);
    }
}
pub fn term(w0: u32, w1: u32, scalar: u32, acc0: u32, acc1: u32) void {
    if (active) |c| {
        c.zero_weight_c0 += @intFromBool(w0 == 0);
        c.zero_weight_c1 += @intFromBool(w1 == 0);
        c.one_weight_c0 += @intFromBool(w0 == 1);
        c.one_weight_c1 += @intFromBool(w1 == 1);
        c.scalar_zero_id += @intFromBool(scalar == 0);
        c.scalar_one_id += @intFromBool(scalar == 1);
        c.accumulator_zero_c0 += @intFromBool(acc0 == 0);
        c.accumulator_zero_c1 += @intFromBool(acc1 == 0);
    }
}
pub fn delta(before: Snapshot, after: Snapshot) void {
    if (active) |c| {
        c.qm31_rows += after.rows - before.rows;
        c.qm31_add += after.add - before.add;
        c.qm31_sub += after.sub - before.sub;
        c.qm31_mul += after.mul - before.mul;
        c.native_full_mul += after.native_mul - before.native_mul;
    }
}
