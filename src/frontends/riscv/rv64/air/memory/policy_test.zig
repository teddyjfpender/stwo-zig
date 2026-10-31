const std = @import("std");
const authority = @import("policy.zig");
const Memory = @import("../../memory.zig").Memory;
const a = std.testing.allocator;

test "RV64 RAM policy: maximal grants preserve native read/write semantics across mapping boundaries" {
    var memory = Memory.init(a, .{});
    defer memory.deinit();
    const base = 0x1_0000_0000;
    try memory.map(.{ .start = base, .size = 256, .permissions = .{ .read = true } });
    try memory.map(.{ .start = base + 256, .size = 256, .permissions = .{ .read = true, .write = true, .execute = true } });
    try memory.map(.{ .start = base + 512, .size = 512, .permissions = .{ .read = true, .write = true } });
    try memory.map(.{ .start = base + 1024, .size = 512, .permissions = .{ .execute = true } });
    var policy = try authority.Policy.fromMemory(a, &memory);
    defer policy.deinit();
    try policy.validate();
    for ([_]authority.Span{ .word8, .chunk512 }) |span| {
        for (0..2048 / span.bytes()) |i| {
            const address = base + i * span.bytes();
            for (1..4) |raw_mask| {
                const mask: u2 = @intCast(raw_mask);
                var allowed = true;
                if (mask & 1 != 0) memory.mappings.check(address, span.bytes(), .read) catch {
                    allowed = false;
                };
                if (mask & 2 != 0) memory.mappings.check(address, span.bytes(), .write) catch {
                    allowed = false;
                };
                if (allowed) {
                    _ = try policy.find(span, address, mask);
                } else try std.testing.expectError(error.RamPolicyAccessDenied, policy.find(span, address, mask));
            }
        }
    }
    // READ merges over the W/X boundary; READ|WRITE never grants the RO half.
    _ = try policy.find(.chunk512, base, 1);
    try std.testing.expectError(error.RamPolicyAccessDenied, policy.find(.chunk512, base, 3));
}

test "RV64 RAM policy: full-width endpoints and source identity prevent narrowing or permission substitution" {
    const regions = [_]authority.Region{.{ .first = std.math.maxInt(u64) - 4095, .last = std.math.maxInt(u64), .flags = 3 }};
    var policy = try authority.Policy.init(a, &regions);
    defer policy.deinit();
    _ = try policy.find(.word8, std.math.maxInt(u64) - 7, 3);
    _ = try policy.find(.chunk512, std.math.maxInt(u64) - 511, 3);
    try std.testing.expectError(error.RamPolicyAccessDenied, policy.find(.word8, 0xffff_fff8, 3));
    try std.testing.expectError(error.MisalignedRamPolicySpan, policy.find(.word8, std.math.maxInt(u64), 3));
    var changed = regions;
    changed[0].flags |= 4;
    var x_policy = try authority.Policy.init(a, &changed);
    defer x_policy.deinit();
    try std.testing.expect(!std.meta.eql(policy.identity, x_policy.identity));
    try std.testing.expectEqualDeep(policy.grants, x_policy.grants);
    policy.grants[0].first += 8;
    try std.testing.expectError(error.NoncanonicalRamPolicyGrants, policy.validate());
}

test "RV64 RAM policy: malformed maps and empty rights fail before allocation" {
    try std.testing.expectError(error.NoncanonicalRamPolicyRegions, authority.Policy.init(a, &.{.{ .first = 8, .last = 7, .flags = 1 }}));
    try std.testing.expectError(error.NoncanonicalRamPolicyRegions, authority.Policy.init(a, &.{ .{ .first = 0, .last = 8, .flags = 1 }, .{ .first = 8, .last = 15, .flags = 3 } }));
    var policy = try authority.Policy.init(a, &.{});
    defer policy.deinit();
    try std.testing.expectError(error.EmptyRamPolicyGrant, policy.find(.word8, 0, 0));
}

fn failureFixture(allocator: std.mem.Allocator) !void {
    var policy = try authority.Policy.init(allocator, &.{ .{ .first = 0, .last = 511, .flags = 1 }, .{ .first = 512, .last = 1023, .flags = 3 } });
    defer policy.deinit();
    try policy.validate();
}

test "RV64 RAM policy: initialization cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, failureFixture, .{});
}

test "RV64 policy: immutable execution admission rejects writable code without restricting the native permission primitive" {
    var mappings = try authority.Policy.init(std.testing.allocator, &.{.{ .first = 0, .last = 4095, .flags = 7 }});
    defer mappings.deinit();
    try mappings.validate();
    _ = try mappings.find(.chunk512, 0, 3);
    try std.testing.expectError(error.WritableExecutableRv64Policy, mappings.validateImmutableExecution());
    var immutable = try authority.Policy.init(std.testing.allocator, &.{ .{ .first = 0, .last = 4095, .flags = 5 }, .{ .first = 4096, .last = 8191, .flags = 3 } });
    defer immutable.deinit();
    try immutable.validateImmutableExecution();
}
