const std = @import("std");
const eth = @import("../ethereum_services/session.zig");
const profile = @import("../execution_profile.zig");
const memory = @import("../memory.zig");
const machine = @import("../machine.zig");
const Base = @import("../session.zig");
const a = std.testing.allocator;
fn setup(allocator: std.mem.Allocator, writable: bool) !memory.Memory {
    var mem = memory.Memory.init(allocator, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 12, .permissions = .{ .read = true, .execute = true } });
    try mem.initialize(0x1000, &.{ 0x73, 0, 0, 0, 0x73, 0, 0, 0, 0x13, 0, 0, 0 });
    try mem.map(.{ .start = 0x2fe0, .size = 192, .permissions = .{ .read = true, .write = writable } });
    var bytes: [192]u8 = undefined;
    for (0..6) |i| std.mem.writeInt(u256, bytes[32 * i ..][0..32], @intCast(i + 1), .big);
    try mem.initialize(0x2fe0, &bytes);
    return mem;
}
fn cpu(tag: u64) machine.Cpu {
    var value = machine.Cpu.init(0x1000, 0);
    value.regs[10] = 0x2fe0;
    value.regs[17] = tag;
    return value;
}
fn run(allocator: std.mem.Allocator) !void {
    var mem = try setup(allocator, true);
    defer mem.deinit();
    var session = try eth.Session.init(allocator, cpu(profile.SECP_ADD_TAG), &mem, .{ .cache_entries = 1, .max_retirements = 3 });
    defer session.deinit();
    const initial_cpu = session.keccak.base.cpu;
    const initial_pages = mem.pageCount();
    var before: [24]u64 = undefined;
    for (&before, 0..) |*v, i| v.* = try mem.load(0x2fe0 + 8 * i, 8);
    var event: eth.Event = undefined;
    const row = session.step(&event) catch |err| {
        try std.testing.expectEqualDeep(initial_cpu, session.keccak.base.cpu);
        try std.testing.expectEqual(initial_pages, mem.pageCount());
        for (before, 0..) |word, i| try std.testing.expectEqual(word, try mem.load(0x2fe0 + 8 * i, 8));
        return err;
    };
    try std.testing.expect(row == null);
    try std.testing.expect(event == .secp);
    const call = event.secp;
    try std.testing.expectEqual(@as(u64, 1), call.call_id);
    try std.testing.expectEqual(@as(u64, 1), call.clock);
    try std.testing.expectEqualDeep(initial_cpu.regs, session.keccak.base.cpu.regs);
    const values = try eth.secp256k1.execute(eth.secp256k1.get(.add), &.{ 1, 2, 3, 4, 5, 6 });
    var output: [96]u8 = undefined;
    for (call.after[0..12], 0..) |word, i| std.mem.writeInt(u64, output[8 * i ..][0..8], word, .little);
    for (eth.secp256k1.add.outputs, 0..) |wire, i| try std.testing.expectEqual(values[wire], std.mem.readInt(u256, output[32 * i ..][0..32], .big));
    try std.testing.expectEqualSlices(u64, call.before[12..], call.after[12..]);
    for (call.after, 0..) |word, i| try std.testing.expectEqual(word, try mem.load(0x2fe0 + 8 * i, 8));
    try std.testing.expectEqual(profile.SECP_ADD_TAG, call.retirement().rhs.toInt());
    session.keccak.base.cpu.regs[17] = profile.SECP_DOUBLE_TAG;
    try std.testing.expect((try session.step(&event)) == null);
    try std.testing.expectEqual(@as(u64, 1), event.secp.call_id);
    try std.testing.expectEqual(@as(u64, 2), event.secp.clock);
    try std.testing.expectEqual(@as(usize, 12), event.secp.wordCount());
    try std.testing.expect((try session.step(&event)) != null);
    try std.testing.expectError(error.StepLimit, session.step(&event));
}
test "Ethereum services: BE in-place projective packets atomic across pages and allocation failures" {
    try run(a);
    try std.testing.checkAllAllocationFailures(a, run, .{});
}
test "Ethereum services: old profiles stay trapping and bad requests cannot publish state" {
    var mem = try setup(a, false);
    defer mem.deinit();
    var session = try eth.Session.init(a, cpu(profile.SECP_ADD_TAG), &mem, .{ .cache_entries = 1 });
    defer session.deinit();
    var ordinary = try Base.Session.init(a, cpu(profile.SECP_ADD_TAG), &mem, .{ .cache_entries = 1 });
    defer ordinary.deinit();
    try std.testing.expectError(error.EnvironmentCall, ordinary.step());
    var old = try @import("../service_session.zig").Session.init(a, cpu(profile.SECP_ADD_TAG), &mem, .{ .cache_entries = 1 });
    defer old.deinit();
    var old_call: @import("../service_session.zig").Call = undefined;
    try std.testing.expectError(error.UnsupportedService, old.step(&old_call));
    var event: eth.Event = undefined;
    try std.testing.expectError(error.AccessDenied, session.step(&event));
    session.keccak.base.cpu.regs[17] = 0x100020001;
    try std.testing.expectError(error.UnsupportedService, session.step(&event));
    session.keccak.base.cpu.regs[17] = profile.SECP_ADD_TAG;
    session.keccak.base.cpu.regs[10] += 1;
    try std.testing.expectError(error.MisalignedAddress, session.step(&event));
    session.keccak.base.cpu.regs[10] = 0xffffffffffffffe0;
    try std.testing.expectError(error.AddressOverflow, session.step(&event));
    try std.testing.expectEqual(@as(u64, 0), session.keccak.base.cpu.retired);
    try std.testing.expectEqual(@as(u64, 0), session.add_calls);
    try std.testing.expectEqual(@as(u64, 0), session.double_calls);
}
fn absent(allocator: std.mem.Allocator) !void {
    var mem = memory.Memory.init(allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 4, .permissions = .{ .read = true, .execute = true } });
    try mem.initialize(0x1000, &.{ 0x73, 0, 0, 0 });
    try mem.map(.{ .start = 0x2fe0, .size = 192, .permissions = .{ .read = true, .write = true } });
    var session = try eth.Session.init(allocator, cpu(profile.SECP_ADD_TAG), &mem, .{ .cache_entries = 1 });
    defer session.deinit();
    const initial = session.keccak.base.cpu;
    const pages = mem.pageCount();
    var event: eth.Event = undefined;
    _ = session.step(&event) catch |err| {
        try std.testing.expectEqualDeep(initial, session.keccak.base.cpu);
        try std.testing.expectEqual(pages, mem.pageCount());
        try std.testing.expectEqual(@as(u64, 0), session.add_calls);
        for (0..24) |i| try std.testing.expectEqual(@as(u64, 0), try mem.load(0x2fe0 + 8 * i, 8));
        return err;
    };
    try std.testing.expectEqual(@as(u64, 1), session.add_calls);
}
test "Ethereum services: two-page output reservation failure preserves absent pages and CPU" {
    try absent(a);
    try std.testing.checkAllAllocationFailures(a, absent, .{});
}
test "Ethereum services v2: LE word packets are explicit and versions reject each other's tags" {
    var mem = try setup(a, true);
    defer mem.deinit();
    for (0..6) |i| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, @intCast(i + 1), .little);
        try mem.initialize(0x2fe0 + 32 * i, &bytes);
    }
    var v2 = try eth.Session.initWithProfile(a, cpu(profile.SECP_ADD_WORD_TAG), &mem, .{ .cache_entries = 1 }, .ethereum_services_v2);
    defer v2.deinit();
    var event: eth.Event = undefined;
    try std.testing.expect((try v2.step(&event)) == null);
    try std.testing.expectEqual(profile.SecpPacketFormat.little_endian_words_v2, event.secp.packet_format);
    try std.testing.expectEqual(profile.SECP_ADD_WORD_TAG, event.retirement().rhs.toInt());
    const values = try eth.secp256k1.execute(&eth.secp256k1.add, &.{ 1, 2, 3, 4, 5, 6 });
    for (eth.secp256k1.add.outputs, 0..) |wire, i| {
        var bytes: [32]u8 = undefined;
        for (0..4) |lane| std.mem.writeInt(u64, bytes[8 * lane ..][0..8], try mem.load(0x2fe0 + 32 * i + 8 * lane, 8), .little);
        try std.testing.expectEqual(values[wire], std.mem.readInt(u256, &bytes, .little));
    }
    v2.keccak.base.cpu.regs[17] = profile.SECP_DOUBLE_TAG;
    try std.testing.expectError(error.UnsupportedService, v2.step(&event));
    try std.testing.expectEqual(@as(u64, 1), v2.keccak.base.cpu.retired);
    var v1 = try eth.Session.init(a, cpu(profile.SECP_ADD_WORD_TAG), &mem, .{ .cache_entries = 1 });
    defer v1.deinit();
    try std.testing.expectError(error.UnsupportedService, v1.step(&event));
    try std.testing.expectEqual(@as(u64, 0), v1.keccak.base.cpu.retired);
}
