const std = @import("std");
const C = @import("../rv64_ethereum_chip_plan.zig");
const V = @import("../rv64_ethereum_chip_coverage.zig");
const a = std.testing.allocator;
const semantics: [32]u8 = @splat(13);
fn profile() C.Profile {
    return .{ .cpu_log = 10, .logs = @splat(5) };
}
fn state(pc: u64) V.State {
    return .{ .pc = pc, .registers = @splat(0), .ram = @splat(0) };
}
fn expected() V.Expected {
    return .{ .epoch = 1 << 40, .first_cpu_index = 7, .first_step = 1 << 40, .instructions = 6, .initial = state(4096), .final = state(4120), .first_ids = .{} };
}
fn contexts() ![2]V.Context {
    const ns = V.Namespace{ .profile = try profile().identity(semantics), .epoch = expected().epoch };
    return .{
        .{ .id = .{ .namespace = ns, .index = 7 }, .first_step = expected().first_step, .steps = 5, .initial = state(4096), .final = state(4116), .counts = .{ .keccak = 5 }, .first_ids = .{} },
        .{ .id = .{ .namespace = ns, .index = 8 }, .first_step = expected().first_step + 5, .steps = 1, .initial = state(4116), .final = state(4120), .counts = .{ .keccak = 1 }, .first_ids = .{ .keccak = 6 } },
    };
}
fn constructAndRelease(allocator: std.mem.Allocator, source: []const V.Context) !void {
    var result = try V.Coverage.init(allocator, profile(), semantics, expected(), source);
    defer result.deinit();
    try result.validateAgainst(profile(), semantics, expected());
}
test "typed chip coverage supports many CPU owners per provider and multiple providers per CPU" {
    const source = try contexts();
    try std.testing.checkAllAllocationFailures(a, constructAndRelease, .{@as([]const V.Context, &source)});
    var plan = try V.Coverage.init(a, profile(), semantics, expected(), &source);
    defer plan.deinit();
    try plan.validateAgainst(profile(), semantics, expected());
    try std.testing.expect(!V.Coverage.physical_bus_closed);
    try std.testing.expectEqual(@as(u64, 2048), try plan.cpuDomainRows());
    try std.testing.expectEqual(@as(u64, 101888), try plan.admitMass(46, 0));
    var providers_for_first: usize = 0;
    var owners_for_last_pair: usize = 0;
    for (plan.links) |link| {
        if (link.tag.key.chip == .keccak and link.owner.index == 7) providers_for_first += 1;
        if (link.tag.key.chip == .keccak and link.tag.instance == 2) owners_for_last_pair += 1;
        try std.testing.expect(link.requests > 0);
        try std.testing.expectEqual(V.RequestFamily.keccak_call, link.request.family);
        try std.testing.expectEqual(@as(u64, 1 << 40), link.request.scope.epoch);
    }
    try std.testing.expectEqual(@as(usize, 3), providers_for_first);
    try std.testing.expectEqual(@as(usize, 2), owners_for_last_pair);
    try std.testing.expectEqual(@as(u32, 2), try profile().capacity(.keccak));
    // A32-row domain fits one29-row pair; no partial29-row slot is activated.
    const final_tag = try plan.providerTag(2);
    try plan.checkProviderClaimTag(2, final_tag);
    var wrong = final_tag;
    wrong.instance -= 1;
    try std.testing.expectError(error.InvalidChipClaimTag, plan.checkProviderClaimTag(2, wrong));
    wrong = final_tag;
    wrong.key.profile[0] ^= 1;
    try std.testing.expectError(error.InvalidChipClaimTag, plan.checkProviderClaimTag(2, wrong));
    wrong = final_tag;
    wrong.namespace.epoch += 1;
    try std.testing.expectError(error.InvalidChipClaimTag, plan.checkProviderClaimTag(2, wrong));
    wrong = final_tag;
    wrong.key.chip = .keccak_bridge;
    try std.testing.expectError(error.InvalidChipClaimTag, plan.checkProviderClaimTag(2, wrong));
    const original = plan.links[1];
    plan.links[1] = plan.links[0];
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.links[1] = original;
    plan.links[1].owner.index += 1;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.links[1] = original;
    plan.links[1].request.family = .division_operands;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.links[1] = original;
    try plan.validate();
}
test "typed chip coverage rejects endpoint profile namespace and request gaps before allocation" {
    const original = try contexts();
    var source = original;
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const fail = failing.allocator();
    source[1].id.namespace.profile[0] ^= 1;
    try std.testing.expectError(error.InvalidChipProfile, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].id.namespace.epoch += 1;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].first_step += 1;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].first_ids.keccak -= 1;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].initial.registers[1] = 1;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].initial.ram[0] = 1;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    source = original;
    source[1].steps = 0;
    try std.testing.expectError(error.InvalidChipCoverage, V.Coverage.init(fail, profile(), semantics, expected(), &source));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}
test "load store chip role is independently packed but its unqualified mass never admits" {
    var source = try contexts();
    source[0].counts = .{ .load_store = 5 };
    source[1].counts = .{ .load_store = 1 };
    source[1].first_ids = .{ .load_store = 6 };
    var plan = try V.Coverage.init(a, profile(), semantics, expected(), &source);
    defer plan.deinit();
    try plan.validate();
    try std.testing.expectEqual(@as(usize, 1), plan.packing.instances.len);
    try std.testing.expectEqual(C.Chip.load_store, plan.packing.instances[0].chip);
    try std.testing.expectEqual(@as(usize, 2), plan.links.len);
    for (plan.links) |link| try std.testing.expectEqual(V.RequestFamily.load_store, link.request.family);
    try std.testing.expectError(error.UnqualifiedLoadStoreMass, plan.packing.admitMass(0));
}
test "word16 typed coverage rejects role and request span substitution" {
    var source = try contexts();
    source[0].counts = .{ .alu = 3, .binary = 1, .shift = 1 };
    source[1].counts = .{ .alu = 1 };
    source[1].first_ids = .{ .alu = 4, .binary = 2, .shift = 2 };
    var plan = try V.Coverage.init(a, profile(), semantics, expected(), &source);
    defer plan.deinit();
    try plan.validate();
    try std.testing.expectEqual(@as(usize, 3), plan.packing.instances.len);
    try std.testing.expectEqual(@as(usize, 4), plan.links.len);
    try std.testing.expectEqual(V.RequestFamily.alu_word16, plan.links[0].request.family);
    try std.testing.expectEqual(V.RequestFamily.binary_word16, plan.links[2].request.family);
    try std.testing.expectEqual(V.RequestFamily.shift_word16, plan.links[3].request.family);
    const saved = plan.links[0];
    plan.links[0].request.family = .binary_word16;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.links[0] = saved;
    plan.links[0].first_id += 1;
    try std.testing.expectError(error.InvalidChipCoverage, plan.validate());
    plan.links[0] = saved;
    try std.testing.expectError(error.UnqualifiedWord16Mass, plan.admitMass(0, 0));
    try std.testing.expect(!V.Coverage.physical_bus_closed);
}
