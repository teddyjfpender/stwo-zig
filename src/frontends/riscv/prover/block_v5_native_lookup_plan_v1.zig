//! Field-safe groups for global lookup providers. The enclosing receiver must
//! independently derive demands and close each exact group, not only a block
//! total that could wrap after M31 characteristic-many invalid requests.
const std = @import("std");
const core = @import("stwo_core");
const schema = @import("../air/lookups/tables/schema.zig");
pub const Plan = struct {
    index: u32,
    first_execution: u32,
    execution_count: u32,
    max_requests: [schema.KIND_COUNT]u64,
    pub fn validate(self: Plan) !void {
        if (self.execution_count == 0) return error.InvalidBlockV5LookupPlan;
        _ = try std.math.add(u32, self.first_execution, self.execution_count);
        var total: u64 = 0;
        for (self.max_requests) |value| total = try std.math.add(u64, total, value);
        if (total >= core.fields.m31.Modulus)
            return error.BlockV5LookupGroupExceedsField;
    }
    pub fn identity(self: Plan) ![32]u8 {
        try self.validate();
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354c50, 1, self.index, self.first_execution, self.execution_count });
        channel.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
        for (self.max_requests) |count| channel.mixU64(count);
        return channel.digestBytes();
    }
};

pub fn nativeDemand(shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, external_retirements: u32) ![schema.KIND_COUNT]u64 {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    return @import("../air/guest_precompile/statement.zig").deriveBaseFixedTableBounds(shape.*);
}
/// Ordinary and caller memory projections prove byte limbs against the same
/// global native range8 table. Sorted packed memory has its own range16 AIR.
/// The enclosing job independently admits this execution's event bound.
pub fn sidecarMemoryDemand(event_bound: u64) ![schema.KIND_COUNT]u64 {
    var result: [schema.KIND_COUNT]u64 = @splat(0);
    result[@intFromEnum(schema.Kind.range_check_8_8)] = try std.math.mul(u64, event_bound, @import("block_execution_byte_range_v2.zig").REQUEST_COUNT);
    return result;
}
pub fn addDemand(destination: *[schema.KIND_COUNT]u64, source: [schema.KIND_COUNT]u64) !void {
    for (destination, source) |*value, addend| value.* = try std.math.add(u64, value.*, addend);
}

pub fn validateRoster(plans: []const Plan, execution_count: u32) !void {
    if (plans.len == 0 or execution_count == 0) return error.InvalidBlockV5LookupPlan;
    var next: u32 = 0;
    for (plans, 0..) |plan, index| {
        try plan.validate();
        if (plan.index != index or plan.first_execution != next)
            return error.InvalidBlockV5LookupPartition;
        next = try std.math.add(u32, next, plan.execution_count);
    }
    if (next != execution_count) return error.IncompleteBlockV5LookupPartition;
}

/// Reconstruct every group bound from admitted execution descriptors. This
/// prevents producer-chosen bounds or a different partition from becoming
/// receiver policy through serialized artifacts.
pub fn validateDemandRoster(plans: []const Plan, demands: []const [schema.KIND_COUNT]u64) !void {
    const count = std.math.cast(u32, demands.len) orelse return error.InvalidBlockV5LookupPlan;
    try validateRoster(plans, count);
    for (plans) |plan| {
        var expected: [schema.KIND_COUNT]u64 = @splat(0);
        const end = @as(usize, plan.first_execution) + plan.execution_count;
        for (demands[plan.first_execution..end]) |demand| try addDemand(&expected, demand);
        if (!std.meta.eql(expected, plan.max_requests)) return error.UntrustedBlockV5LookupDemand;
    }
}

/// Greedy contiguous packing minimizes provider instances under the admitted
/// request budget. Demands come from independently admitted native shapes,
/// never from a proof's claimed multiplicity counters.
pub fn buildRoster(a: std.mem.Allocator, demands: []const [schema.KIND_COUNT]u64, request_limit: u64) ![]Plan {
    if (demands.len == 0 or demands.len > std.math.maxInt(u32) or
        request_limit == 0 or request_limit >= core.fields.m31.Modulus)
        return error.InvalidBlockV5LookupPlan;
    var plans: std.ArrayList(Plan) = .empty;
    errdefer plans.deinit(a);
    var current = Plan{ .index = 0, .first_execution = 0, .execution_count = 0, .max_requests = @splat(0) };
    var current_total: u64 = 0;
    for (demands, 0..) |demand, index| {
        var total: u64 = 0;
        for (demand) |value| total = try std.math.add(u64, total, value);
        if (total > request_limit) return error.BlockV5LookupGroupExceedsField;
        if (current.execution_count != 0 and total > request_limit - current_total) {
            try plans.append(a, current);
            current = .{ .index = @intCast(plans.items.len), .first_execution = @intCast(index), .execution_count = 0, .max_requests = @splat(0) };
            current_total = 0;
        }
        try addDemand(&current.max_requests, demand);
        current_total += total;
        current.execution_count += 1;
    }
    try plans.append(a, current);
    try validateRoster(plans.items, @intCast(demands.len));
    return plans.toOwnedSlice(a);
}

test "native lookup planning partitions exact demands without padding" {
    const a = std.testing.allocator;
    const demands = [_][schema.KIND_COUNT]u64{ .{ 3, 0, 0, 0, 0, 0 }, .{ 0, 4, 0, 0, 0, 0 }, .{ 0, 0, 5, 0, 0, 0 }, @splat(0) };
    const plans = try buildRoster(a, &demands, 7);
    defer a.free(plans);
    try std.testing.expectEqual(@as(usize, 2), plans.len);
    try std.testing.expectEqual(@as(u32, 2), plans[0].execution_count);
    try std.testing.expectEqual(@as(u32, 2), plans[1].first_execution);
    try std.testing.expectEqual(@as(u32, 2), plans[1].execution_count);
    try validateDemandRoster(plans, &demands);
    var substituted = plans[0];
    substituted.max_requests[0] += 1;
    try std.testing.expectError(error.UntrustedBlockV5LookupDemand, validateDemandRoster(&.{ substituted, plans[1] }, &demands));
    var truncated = plans[1];
    truncated.execution_count = 1;
    try std.testing.expectError(error.IncompleteBlockV5LookupPartition, validateRoster(&.{ plans[0], truncated }, 4));
    try std.testing.expectError(error.BlockV5LookupGroupExceedsField, buildRoster(a, &demands, 4));
}
