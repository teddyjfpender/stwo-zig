//! Stable exact-tuple grouping; not an arithmetic acceptance authority.
//! The qualified weighted Source validates every truth fact before MAIN fill.
const std = @import("std");
const core = @import("stwo_core");
pub const Fact = @import("stwo_riscv_frontend").rv64_air.word16_v1.binary_source.Fact;
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
pub fn collect(a: std.mem.Allocator, input: []const Fact, deduplicate: bool) !WeightedFacts {
    if (input.len >= core.fields.m31.Modulus) return error.BinaryMultiplicityMassExceeded;
    var map: std.AutoHashMapUnmanaged(Fact, usize) = .empty;
    defer map.deinit(a);
    var facts: std.ArrayList(Fact) = .empty;
    defer facts.deinit(a);
    var weights: std.ArrayList(u32) = .empty;
    defer weights.deinit(a);
    for (input) |fact| {
        if (@intFromEnum(fact.op) > 2) return error.InvalidBinaryFact;
        if (deduplicate) {
            const entry = try map.getOrPut(a, fact);
            if (entry.found_existing) {
                weights.items[entry.value_ptr.*] += 1;
                continue;
            }
            entry.value_ptr.* = facts.items.len;
        }
        try facts.append(a, fact);
        try weights.append(a, 1);
    }
    const fs = try facts.toOwnedSlice(a);
    errdefer a.free(fs);
    return .{ .allocator = a, .facts = fs, .weights = try weights.toOwnedSlice(a) };
}
