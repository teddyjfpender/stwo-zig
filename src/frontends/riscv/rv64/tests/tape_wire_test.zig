const std = @import("std");
const rv = @import("../mod.zig");
const W = @import("../compact_tape_wire.zig");
const T = rv.compact_tape;
const a = std.testing.allocator;

test "native tape wire preserves full64bit advice and service packets independently of spare capacity" {
    for (std.enums.values(rv.execution_profile.Profile)) |profile| {
        var tape = try fixture(profile);
        defer tape.deinit();
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const file = try temp.dir.createFile("tape", .{ .read = true });
        defer file.close();
        try W.write(file, &tape);
        try std.testing.expectEqual(try W.encodedBytes(&tape), try file.getEndPos());
        try file.seekTo(0);
        var loaded = try W.readTail(a, file, .{});
        defer loaded.deinit();
        try std.testing.expectEqual(tape.initial_pc, loaded.initial_pc);
        try std.testing.expectEqual(tape.initial_clock, loaded.initial_clock);
        try std.testing.expectEqual(profile, loaded.execution_profile);
        try std.testing.expectEqualDeep(tape.steps(), loaded.steps());
        try std.testing.expectEqualSlices(u64, tape.memory_before.items, loaded.memory_before.items);
        try std.testing.expectEqualDeep(tape.service_calls.items, loaded.service_calls.items);
        try std.testing.expectEqualDeep(tape.secp_calls.items, loaded.secp_calls.items);
        const second = try temp.dir.createFile("normalized", .{ .read = true });
        defer second.close();
        try W.write(second, &loaded);
        const first_bytes = try temp.dir.readFileAlloc(a, "tape", 16384);
        defer a.free(first_bytes);
        const second_bytes = try temp.dir.readFileAlloc(a, "normalized", 16384);
        defer a.free(second_bytes);
        try std.testing.expectEqualSlices(u8, first_bytes, second_bytes);
        for (tape.storage[tape.len..]) |*unused| unused.* = .{ .next_pc = 0xffffffffffffffff, .lhs = 99, .rhs = 88, .previous_rd = 77, .result = 66, .memory_index = 55, .flags = 44 };
        try second.seekTo(0);
        try W.write(second, &tape);
        const poisoned_capacity = try temp.dir.readFileAlloc(a, "normalized", 16384);
        defer a.free(poisoned_capacity);
        try std.testing.expectEqualSlices(u8, first_bytes, poisoned_capacity);
    }
}

test "native tape wire admits header budgets before allocation and rejects malformed or trailing advice" {
    var tape = try fixture(.ethereum_services_v2);
    defer tape.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("tape", .{ .read = true });
    defer file.close();
    try W.write(file, &tape);
    const bytes = try temp.dir.readFileAlloc(a, "tape", 16384);
    defer a.free(bytes);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try file.seekTo(0);
    try std.testing.expectError(error.InvalidTapeWireGeometry, W.readTail(fail.allocator(), file, .{ .bytes = bytes.len - 1 }));
    try std.testing.expect(!fail.has_induced_failure);
    var changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    changed[28] = 1;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidTapeWireHeader, W.readTail(fail.allocator(), file, .{}));
    try std.testing.expect(!fail.has_induced_failure);
    @memcpy(changed, bytes);
    changed[8] = 255;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidTapeWireProfile, W.readTail(fail.allocator(), file, .{}));
    try std.testing.expect(!fail.has_induced_failure);
    @memcpy(changed, bytes);
    changed[W.HEADER_BYTES + 44] = 2;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidTapeWireStep, W.readTail(a, file, .{}));
    @memcpy(changed, bytes);
    const k_start = W.HEADER_BYTES + tape.len * 48 + tape.memory_before.items.len * 8;
    @memset(changed[k_start + 8 ..][0..8], 0);
    try replace(file, changed);
    try std.testing.expectError(error.InvalidTapeWireService, W.readTail(a, file, .{}));
    for ([_]usize{ 0, 7, 47, 49, bytes.len - 1 }) |length| {
        try replace(file, bytes[0..length]);
        try std.testing.expectError(error.TruncatedTapeWireData, W.readTail(a, file, .{}));
    }
    try replace(file, bytes);
    try file.seekFromEnd(0);
    try file.writeAll(&.{0});
    try file.seekTo(0);
    try std.testing.expectError(error.TrailingTapeWireData, W.readTail(a, file, .{}));
}

test "native tape wire allocation failures release partially loaded sidecars and preserve source" {
    var tape = try fixture(.ethereum_services_v2);
    defer tape.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("tape", .{ .read = true });
    defer file.close();
    try W.write(file, &tape);
    try std.testing.checkAllAllocationFailures(a, decodeAndRelease, .{file});
    try file.seekTo(0);
    var restored = try W.readTail(a, file, .{});
    defer restored.deinit();
    try std.testing.expectEqualDeep(tape.steps(), restored.steps());
}
fn decodeAndRelease(allocator: std.mem.Allocator, file: std.fs.File) !void {
    try file.seekTo(0);
    var result = try W.readTail(allocator, file, .{});
    defer result.deinit();
}
fn replace(file: std.fs.File, bytes: []const u8) !void {
    try file.seekTo(0);
    try file.setEndPos(0);
    try file.writeAll(bytes);
    try file.seekTo(0);
}
fn fixture(profile: rv.execution_profile.Profile) !T.Tape {
    const pc: u64 = (1 << 40) + 4096;
    const pointer: u64 = (1 << 48) + 8192;
    const clock: u64 = 1 << 40;
    const words = [_]u32{ 0x0021b023, 0x0001b203, 0x00000263 }; // sd, ld, taken beq+4
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 12, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = pointer, .size = 512, .permissions = .{ .read = true, .write = true } });
    for (words, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(pc + 4 * i, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.retired = clock;
    cpu.regs[2] = 0xfedcba9876543210;
    cpu.regs[3] = pointer;
    var tape = try T.Tape.init(a, 20, pc, clock, profile);
    errdefer tape.deinit();
    for (words) |_| try tape.append(try cpu.step(&memory));
    if (profile != .rv64im) {
        var call = rv.services.Call{ .call_id = 91, .clock = clock + tape.len + 1, .pc = tape.storage[tape.len - 1].next_pc, .pointer = pointer, .before = @splat(0xffffffffffffffff), .after = @splat(1) };
        try tape.appendService(call);
        call.call_id += 1;
        call.clock += 1;
        call.pc += 4;
        try tape.appendService(call);
    }
    if (profile == .ethereum_services_v1 or profile == .ethereum_services_v2) {
        for ([_]rv.ethereum_services.secp256k1.Kind{ .add, .double, .double }, 0..) |kind, i| {
            var call = rv.ethereum_services.SecpCall{ .kind = kind, .packet_format = if (profile == .ethereum_services_v2) .little_endian_words_v2 else .big_endian_bytes_v1, .call_id = if (kind == .add) 3 else i + 5, .clock = clock + tape.len + 1, .pc = tape.storage[tape.len - 1].next_pc, .pointer = pointer, .before = @splat(0), .after = @splat(0) };
            for (call.before[0..call.wordCount()], call.after[0..call.wordCount()], 0..) |*before, *after, index| {
                before.* = 0xfedcba9876543210 - index;
                after.* = index;
            }
            try tape.appendSecp(call);
        }
    }
    return tape;
}
