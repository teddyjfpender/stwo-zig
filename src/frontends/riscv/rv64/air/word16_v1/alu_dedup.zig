//! Stable exact native fact grouping. No arithmetic/lookup acceptance authority.
const std = @import("std");
const core = @import("stwo_core");
const Ops = @import("operations.zig");
const A = @import("alu.zig");
pub const Fact = Ops.AluFact;
pub const WeightedFacts = struct {
    allocator: std.mem.Allocator,
    facts: []Fact,
    weights: []u32,
    pub fn deinit(self: *WeightedFacts) void {
        self.allocator.free(self.facts);
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
/// Preserve first occurrence order and every full-u64 coordinate, including W
/// high bits and ordered operands. Valid inputs may alias; no input is mutated.
pub fn deduplicate(a: std.mem.Allocator, input: []const Fact) !WeightedFacts {
    if (input.len >= core.fields.m31.Modulus) return error.AluMultiplicityMassExceeded;
    var map: std.AutoHashMapUnmanaged(Fact, usize) = .empty;
    defer map.deinit(a);
    var facts: std.ArrayList(Fact) = .empty;
    defer facts.deinit(a);
    var weights: std.ArrayList(u32) = .empty;
    defer weights.deinit(a);
    for (input) |f| {
        if (@intFromEnum(f.op) > 9 or f.c != A.nativeResult(f.op, f.a, f.b)) return error.InvalidAluFact;
        const entry = try map.getOrPut(a, f);
        if (entry.found_existing) {
            weights.items[entry.value_ptr.*] += 1;
        } else {
            entry.value_ptr.* = facts.items.len;
            try facts.append(a, f);
            try weights.append(a, 1);
        }
    }
    const fact_slice = try facts.toOwnedSlice(a);
    errdefer a.free(fact_slice);
    return .{ .allocator = a, .facts = fact_slice, .weights = try weights.toOwnedSlice(a) };
}
