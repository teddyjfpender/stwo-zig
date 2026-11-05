//! Operational placement from receiver-derived admission estimates. Neither
//! the cost proxy nor its frozen ordinal map enters proof/transcript authority.
const std = @import("std");
pub const max_tasks = 256;
pub const max_endpoints = 8;
pub const Plan = struct {
    count: usize,
    endpoints: [max_tasks]u8 = @splat(0),
    physical: [max_tasks]u8 = @splat(0),
    physical_load: [max_endpoints]u64 = @splat(0),
    owner_load: [max_endpoints]u64 = @splat(0),
    pub const Options = struct { cpu_count: usize = 0, scope_limit: usize = 64 };
    pub fn init(stage1: []const u64, stage2: []const u64, devices: usize, owners: usize, options: Options) !Plan {
        if (options.cpu_count > stage1.len or options.scope_limit == 0 or options.scope_limit > 64 or stage1.len == 0 or stage1.len > max_tasks or stage1.len != stage2.len or devices == 0 or owners == 0 or devices > max_endpoints or owners > max_endpoints or devices * owners > max_endpoints) return error.InvalidNativeRoutePlan;
        var out = Plan{ .count = stage1.len };
        var cost: [max_tasks]u64 = undefined;
        var order: [max_tasks]usize = undefined;
        for (stage1, stage2, 0..) |one, two, i| {
            cost[i] = try std.math.add(u64, one, two);
            order[i] = i;
        }
        const Heavier = struct {
            fn lessThan(weights: []const u64, a: usize, b: usize) bool {
                return if (weights[a] != weights[b]) weights[a] > weights[b] else a < b;
            }
        };
        std.sort.pdq(usize, order[0..out.count], @as([]const u64, cost[0..out.count]), Heavier.lessThan);
        var physical_count: [max_endpoints]usize = @splat(0);
        var owner_count: [max_endpoints]usize = @splat(0);
        var cpu_count: [max_endpoints]usize = @splat(0);
        for (order[0..out.count]) |ordinal| {
            var device: usize = max_endpoints;
            for (0..devices) |candidate| {
                var available = ordinal >= options.cpu_count;
                for (0..owners) |lane| if (cpu_count[candidate + lane * devices] < options.scope_limit) { available = true; };
                if (!available) continue;
                if (device == max_endpoints or out.physical_load[candidate] < out.physical_load[device] or
                    (out.physical_load[candidate] == out.physical_load[device] and physical_count[candidate] < physical_count[device])) device = candidate;
            }
            if (device == max_endpoints) return error.InsufficientNativeRouteCapacity;
            var endpoint: usize = max_endpoints;
            for (0..owners) |lane| {
                const candidate = device + lane * devices;
                if (ordinal < options.cpu_count and cpu_count[candidate] >= options.scope_limit) continue;
                if (endpoint == max_endpoints or out.owner_load[candidate] < out.owner_load[endpoint] or
                    (out.owner_load[candidate] == out.owner_load[endpoint] and owner_count[candidate] < owner_count[endpoint])) endpoint = candidate;
            }
            if (endpoint == max_endpoints) return error.InsufficientNativeRouteCapacity;
            if (ordinal < options.cpu_count) cpu_count[endpoint] += 1;
            out.endpoints[ordinal] = @intCast(endpoint);
            out.physical[ordinal] = @intCast(device);
            out.physical_load[device] = try std.math.add(u64, out.physical_load[device], cost[ordinal]);
            out.owner_load[endpoint] = try std.math.add(u64, out.owner_load[endpoint], cost[ordinal]);
            physical_count[device] += 1;
            owner_count[endpoint] += 1;
        }
        return out;
    }
};

test "native route planner balances immutable original ordinals across physical and owner lanes" {
    const stage1 = [_]u64{ 9, 8, 7, 6, 5, 4 };
    const stage2 = [_]u64{ 0, 0, 0, 0, 0, 0 };
    const plan = try Plan.init(&stage1, &stage2, 2, 2, .{});
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 3, 2, 2, 3 }, plan.endpoints[0..6]);
    try std.testing.expectEqualSlices(u64, &.{ 20, 19 }, plan.physical_load[0..2]);
    const repeat = try Plan.init(&stage1, &stage2, 2, 2, .{});
    try std.testing.expect(std.meta.eql(plan, repeat));
    const zero = try Plan.init(&stage2, &stage2, 2, 2, .{});
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 0, 1 }, zero.endpoints[0..6]);
    try std.testing.expectError(error.InvalidNativeRoutePlan, Plan.init(&stage1, &stage2, 5, 2, .{}));
    try std.testing.expectError(error.Overflow, Plan.init(&.{std.math.maxInt(u64)}, &.{1}, 1, 1, .{}));
}

test "native route planner honors every retained CPU scope capacity" {
    const plan = try Plan.init(&.{ 9, 8, 7, 6, 5, 4, 3 }, &.{ 1, 1, 1, 1, 1, 1, 1 }, 2, 1, .{ .cpu_count = 7, .scope_limit = 4 });
    var counts: [2]usize = @splat(0);
    for (plan.endpoints[0..7]) |endpoint| counts[endpoint] += 1;
    for (counts) |count| try std.testing.expect(count <= 4);
    try std.testing.expectError(error.InsufficientNativeRouteCapacity, Plan.init(&.{ 9, 8, 7 }, &.{ 0, 0, 0 }, 2, 1, .{ .cpu_count = 3, .scope_limit = 1 }));
}
