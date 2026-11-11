//! Source-owned lowering only. Never decode this plan from prover/witness data.
const std = @import("std");
pub const ID = u32;
pub const Term = struct { a: ID, b: ?ID = null, coefficient: i32 };
pub const Stage = struct { coefficients: [12]i32, input: [25]ID, writer: ID };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    stages: []Stage,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.stages);
        self.* = undefined;
    }
    pub fn output(self: *const Plan) ID {
        return self.stages[self.stages.len - 1].writer;
    }
};
pub const Count = struct { rows: usize, terms: usize, temps: usize };
pub fn count(terms: []const Term) !Count {
    return countForCapacity(12, terms);
}
/// Cost model only: no runtime-selected arithmetic layout or proof profile.
pub fn countForCapacity(capacity: usize, terms: []const Term) !Count {
    if (capacity != 4 and capacity != 6 and capacity != 8 and capacity != 12) return error.MacCapacityBound;
    if (terms.len > 256) return error.Mac12ExpressionBound;
    var acc = false;
    var n: usize = 0;
    for (terms) |term| {
        if (@abs(term.coefficient) > 18) return error.Mac12CoefficientBound;
        if (term.coefficient == 0) continue;
        if (!acc and term.b == null and term.coefficient == 1) {
            acc = true;
            continue;
        }
        n += 1;
    }
    const rows = @max(@as(usize, 1), (n + capacity - 1) / capacity);
    return .{ .rows = rows, .terms = n, .temps = rows - 1 };
}
/// Failure-atomic ID custody. The caller's source program must bind distinct
/// literal ZERO/ONE writers and the exact original expression/SSA mapping.
pub fn lower(a: std.mem.Allocator, terms: []const Term, next: *ID, zero: ID, one: ID) !Plan {
    const c = try count(terms);
    if (zero == one or zero >= next.* or one >= next.*) return error.Mac12ConstantAuthority;
    for (terms) |term| if (term.a >= next.* or (term.b != null and term.b.? >= next.*)) return error.Mac12InputAuthority;
    if (next.* >= 2147483647 or c.rows >= 2147483647 - next.*) return error.Mac12IdBound;
    const stages = try a.alloc(Stage, c.rows);
    errdefer a.free(stages);
    var seed = zero;
    var selected: ?usize = null;
    for (terms, 0..) |term, i| if (term.b == null and term.coefficient == 1) {
        seed = term.a;
        selected = i;
        break;
    };
    for (stages, 0..) |*stage, i| stage.* = .{ .coefficients = @splat(0), .input = @splat(zero), .writer = next.* + @as(ID, @intCast(i)) };
    stages[0].input[24] = seed;
    for (1..stages.len) |i| stages[i].input[24] = stages[i - 1].writer;
    var at: usize = 0;
    for (terms, 0..) |term, i| {
        if (term.coefficient == 0 or selected == i) continue;
        const stage = &stages[at / 12];
        const slot = at % 12;
        stage.coefficients[slot] = term.coefficient;
        stage.input[2 * slot] = term.a;
        stage.input[2 * slot + 1] = term.b orelse one;
        at += 1;
    }
    std.debug.assert(at == c.terms);
    next.* += @intCast(c.rows);
    return .{ .allocator = a, .stages = stages };
}

/// Allocation-free, failure-atomic source lowering into caller-owned storage.
/// All shape/coefficient/ID/capacity/alias checks happen before the first write.
/// The allocating lower() remains unchanged as an independent reference.
pub fn lowerInto(out: []Stage, terms: []const Term, next: *ID, zero: ID, one: ID) ![]Stage {
    const c = try count(terms);
    if (out.len < c.rows) return error.Mac12OutputCapacity;
    const first = next.*;
    if (zero == one or zero >= first or one >= first) return error.Mac12ConstantAuthority;
    for (terms) |term| if (term.a >= first or (term.b != null and term.b.? >= first)) return error.Mac12InputAuthority;
    if (first >= 2147483647 or c.rows >= 2147483647 - first) return error.Mac12IdBound;
    const selected_out = out[0..c.rows];
    const output_start = @intFromPtr(selected_out.ptr);
    const output_end = std.math.add(usize, output_start, selected_out.len * @sizeOf(Stage)) catch return error.Mac12OutputAlias;
    const input_start = @intFromPtr(terms.ptr);
    const input_end = std.math.add(usize, input_start, terms.len * @sizeOf(Term)) catch return error.Mac12OutputAlias;
    if (terms.len != 0 and output_start < input_end and input_start < output_end) return error.Mac12OutputAlias;
    var seed = zero;
    var selected: ?usize = null;
    for (terms, 0..) |term, i| if (term.b == null and term.coefficient == 1) {
        seed = term.a;
        selected = i;
        break;
    };
    for (selected_out, 0..) |*stage, i| stage.* = .{ .coefficients = @splat(0), .input = @splat(zero), .writer = first + @as(ID, @intCast(i)) };
    selected_out[0].input[24] = seed;
    for (1..selected_out.len) |i| selected_out[i].input[24] = selected_out[i - 1].writer;
    var at: usize = 0;
    for (terms, 0..) |term, i| {
        if (term.coefficient == 0 or selected == i) continue;
        const stage = &selected_out[at / 12];
        const slot = at % 12;
        stage.coefficients[slot] = term.coefficient;
        stage.input[2 * slot] = term.a;
        stage.input[2 * slot + 1] = term.b orelse one;
        at += 1;
    }
    std.debug.assert(at == c.terms);
    next.* = first + @as(ID, @intCast(c.rows));
    return selected_out;
}
