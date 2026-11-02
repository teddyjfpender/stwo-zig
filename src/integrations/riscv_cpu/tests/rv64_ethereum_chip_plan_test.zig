const std = @import("std");
const C = @import("../rv64_ethereum_chip_plan.zig");
const a = std.testing.allocator;
const semantics: [32]u8 = @splat(7);
const counts = C.Counts{ .division = 6270, .multiplication = 5193738, .keccak = 32835, .add = 24960, .double = 19968 };
test "fixed chip profile identity excludes counts and packs real census with exact coverage" {
    const profile = C.Profile{};
    var plan = try C.Plan.init(a, profile, semantics, 0, 213659488, counts, .{});
    defer plan.deinit();
    try plan.validate();
    try std.testing.expectEqual(@as(u32, 51), plan.cpu_instances);
    var step: u64 = 0;
    for (0..plan.cpu_instances) |i| {
        const span = try plan.cpu(@intCast(i));
        try std.testing.expectEqual(step, span.first_step);
        try std.testing.expect(span.steps <= (1 << 22) - 1);
        step += span.steps;
    }
    try std.testing.expectEqual(@as(u64, 213659488), step);
    var d: usize = 0;
    var mul: usize = 0;
    var k: usize = 0;
    var bridge: usize = 0;
    for (plan.instances) |v| switch (v.chip) {
        .division => d += 1,
        .multiplication => mul += 1,
        .keccak => k += 1,
        .keccak_bridge => bridge += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 7), d);
    try std.testing.expectEqual(@as(usize, 20), mul);
    try std.testing.expectEqual(@as(usize, 2), k);
    try std.testing.expectEqual(@as(usize, 13), bridge);
    var empty = try C.Plan.init(a, profile, semantics, 1 << 40, 1, .{}, .{});
    defer empty.deinit();
    try std.testing.expectEqualSlices(u8, &plan.profile_identity, &empty.profile_identity);
    try std.testing.expectEqual(@as(usize, 0), empty.instances.len);
    var other = profile;
    other.logs[@intFromEnum(C.Chip.keccak)] -= 1;
    try std.testing.expect(!std.mem.eql(u8, &(try profile.identity(semantics)), &(try other.identity(semantics))));
    // Whole-block BYTE is too large even before sparse providers: grouping all
    // these requests under a single challenge is explicitly forbidden.
    try std.testing.expectError(error.ByteLookupMassExceeded, plan.admitMass(@as(u64, 213909504) * 46));
    try std.testing.expectEqual(@as(u64, 0), try empty.admitMass(0));
}
test "fixed chip planner rejects gaps duplicates partial interiors and oversized admission before allocation" {
    var plan = try C.Plan.init(a, .{}, semantics, 0, 100000, .{ .division = 2050, .keccak = 3 }, .{});
    defer plan.deinit();
    try plan.validate();
    const original = plan.instances[1];
    plan.instances[1].first_id += 1;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.instances[1] = original;
    plan.instances[1].index = 0;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.instances[1] = original;
    plan.instances[0].requests -= 1;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.instances[0].requests += 1;
    plan.instances[1].log -= 1;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.instances[1] = original;
    try plan.validate();
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const fail = failing.allocator();
    try std.testing.expectError(error.InvalidChipCoverage, C.Plan.init(fail, .{}, semantics, std.math.maxInt(u64), 1, .{}, .{}));
    try std.testing.expectError(error.InvalidChipCoverage, C.Plan.init(fail, .{}, semantics, 0, 1, .{ .division = 2 }, .{}));
    try std.testing.expectError(error.InvalidChipCoverage, C.Plan.init(fail, .{}, semantics, 0, 100000, .{ .keccak = 1 }, .{ .keccak = 2147483647 }));
    var tiny = C.Profile{};
    tiny.logs[@intFromEnum(C.Chip.division)] = 5;
    try std.testing.expectError(error.ChipInstanceLimit, C.Plan.init(fail, tiny, semantics, 0, 1000000, .{ .division = 1000000 }, .{}));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}
test "word16 roles have independent immutable capacities and fail closed mass" {
    var profile = C.Profile{};
    profile.logs[@intFromEnum(C.Chip.alu)] = 5;
    profile.logs[@intFromEnum(C.Chip.binary)] = 6;
    profile.logs[@intFromEnum(C.Chip.shift)] = 7;
    var plan = try C.Plan.init(a, profile, semantics, 0, 300, .{ .alu = 33, .binary = 65, .shift = 129 }, .{});
    defer plan.deinit();
    try plan.validate();
    try std.testing.expectEqual(@as(usize, 6), plan.instances.len);
    const roles = [_]C.Chip{ .alu, .alu, .binary, .binary, .shift, .shift };
    const takes = [_]u32{ 32, 1, 64, 1, 128, 1 };
    for (plan.instances, roles, takes) |instance, role, take| {
        try std.testing.expectEqual(role, instance.chip);
        try std.testing.expectEqual(take, instance.requests);
    }
    try std.testing.expectError(error.UnqualifiedWord16Mass, plan.admitMass(0));
    var other = profile;
    other.logs[@intFromEnum(C.Chip.alu)] += 1;
    try std.testing.expect(!std.mem.eql(u8, &(try profile.identity(semantics)), &(try other.identity(semantics))));
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidChipCoverage, C.Plan.init(failing.allocator(), profile, semantics, 0, 2, .{ .alu = 1, .binary = 1, .shift = 1 }, .{}));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}
