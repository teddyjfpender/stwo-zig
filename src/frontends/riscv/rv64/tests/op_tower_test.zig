const std = @import("std");
const E = @import("../ethereum_services/session.zig");
const P = @import("../execution_profile.zig");
const M = @import("../memory.zig");
const Cpu = @import("../machine.zig").Cpu;
const Tape = @import("../compact_tape.zig").Tape;
const T = E.tower.math;
const a = std.testing.allocator;
const pointer = 0x2fe0;

fn setup(writable: bool) !M.Memory {
    var mem = M.Memory.init(a, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .execute = true } });
    try mem.initialize(0x1000, &.{ 0x73, 0, 0, 0, 0x73, 0, 0, 0 });
    try mem.map(.{ .start = pointer, .size = T.WRITTEN_BYTES, .permissions = .{ .read = true, .write = writable } });
    try mem.map(.{ .start = pointer + T.WRITTEN_BYTES, .size = T.PACKET_BYTES - T.WRITTEN_BYTES, .permissions = .{ .read = true } });
    var packet: [T.PACKET_BYTES]u8 = @splat(0);
    for ([_]usize{ 0, 48, 56, 64 }, [_]u64{ 1, 3, 5, 7 }) |index, value|
        std.mem.writeInt(u64, packet[8 * index ..][0..8], value, .little);
    std.mem.writeInt(u64, packet[8 * 72 ..][0..8], 2, .little);
    std.mem.writeInt(u64, packet[8 * 76 ..][0..8], 3, .little);
    try mem.initialize(pointer, &packet);
    return mem;
}
fn cpu() Cpu {
    var value = Cpu.init(0x1000, 0);
    value.regs[P.POINTER_REGISTER] = pointer;
    value.regs[P.TAG_REGISTER] = P.OP_TOWER_TAG;
    return value;
}

test "OP tower tag is disjoint and never widens legacy curve records or v3 admission" {
    const tags = [_]u64{ P.KECCAK_TAG, P.KECCAK_SPONGE_TAG, P.SECP_ADD_TAG, P.SECP_DOUBLE_TAG, P.SECP_ADD_WORD_TAG, P.SECP_DOUBLE_WORD_TAG, P.SHA256_COMPRESS_TAG, P.ARITH256_MOD_TAG, P.MEMCPY_TAG, P.MEMSET_TAG, P.MEMCMP_TAG, P.JUMPDEST_TAG };
    for (tags) |tag| try std.testing.expect(tag != P.OP_TOWER_TAG);
    for (P.CURVE_TAGS) |tag| try std.testing.expect(tag != P.OP_TOWER_TAG);
    try std.testing.expect(!P.isV3(.ethereum_services_op_v1));
    try std.testing.expect(P.hasV3Services(.ethereum_services_op_v1));
    try std.testing.expectEqual(@as(usize, 424), @sizeOf(E.CurveCall));
    try std.testing.expectEqual(@as(usize, 40 + 8 * (T.WORDS + T.WRITTEN_WORDS)), @sizeOf(E.TowerCall));
    var mem = try setup(true);
    defer mem.deinit();
    for ([_]P.Profile{ .ethereum_services_v3, .ethereum_services_v3_zbb }) |profile| {
        var session = try E.Session.initWithProfile(a, cpu(), &mem, .{ .cache_entries = 1 }, profile);
        defer session.deinit();
        var event: E.Event = undefined;
        try std.testing.expectError(error.UnsupportedService, session.step(&event));
        try std.testing.expectEqual(@as(u64, 0), session.keccak.base.cpu.retired);
        try std.testing.expectEqual(@as(u64, 1), try mem.load(pointer, 8));
    }
}

test "OP tower execution preserves readonly tail, CPU registers and bounded tape identity" {
    var mem = try setup(true);
    defer mem.deinit();
    var session = try E.Session.initWithProfile(a, cpu(), &mem, .{ .cache_entries = 1 }, .ethereum_services_op_v1);
    defer session.deinit();
    const registers = session.keccak.base.cpu.regs;
    var event: E.Event = undefined;
    try std.testing.expect((try session.step(&event)) == null);
    try std.testing.expect(event == .tower);
    try std.testing.expectEqualDeep(registers, session.keccak.base.cpu.regs);
    try std.testing.expectEqual(@as(u64, 1), event.tower.call_id);
    try std.testing.expectEqual(@as(u64, 1), session.op_sparse034_calls);
    for (0..T.WORDS) |i| {
        const expected: u64 = if (i >= T.WRITTEN_WORDS) event.tower.before[i] else if (i == 0) 9 else if (i == 24) 10 else if (i == 32) 7 else 0;
        try std.testing.expectEqual(expected, try mem.load(pointer + 8 * i, 8));
        try std.testing.expectEqual(expected, event.tower.wordAfter(i));
    }
    var tape = try Tape.init(a, 2, 0x1000, 0, .ethereum_services_op_v1);
    defer tape.deinit();
    try tape.appendEventRef(&event);
    try std.testing.expectEqual(@as(usize, 1), tape.tower_calls.items.len);
    var wrong = event.tower;
    wrong.call_id += 2;
    try std.testing.expectError(error.InvalidTapeService, tape.appendTower(&wrong));
    try std.testing.expectEqual(@as(usize, 1), tape.len);
}

test "OP tower bad pointers, output rights and counter overflow do not publish state" {
    var mem = try setup(false);
    defer mem.deinit();
    var session = try E.Session.initWithProfile(a, cpu(), &mem, .{ .cache_entries = 1 }, .ethereum_services_op_v1);
    defer session.deinit();
    var event: E.Event = undefined;
    try std.testing.expectError(error.AccessDenied, session.step(&event));
    session.keccak.base.cpu.regs[P.POINTER_REGISTER] = pointer + 8;
    try std.testing.expectError(error.MisalignedAddress, session.step(&event));
    session.keccak.base.cpu.regs[P.POINTER_REGISTER] = 0xffffffffffffffe0;
    try std.testing.expectError(error.AddressOverflow, session.step(&event));
    session.keccak.base.cpu.regs[P.POINTER_REGISTER] = pointer;
    session.op_sparse034_calls = std.math.maxInt(u64);
    try std.testing.expectError(error.ServiceCounterOverflow, session.step(&event));
    session.op_sparse034_calls = 0;
    session.keccak.base.cpu.retired = std.math.maxInt(u64);
    // Session rejects its step limit first; direct executor must also be atomic.
    try std.testing.expectError(error.ServiceCounterOverflow, E.tower.execute(&session.keccak.base.cpu, &mem, &session.op_sparse034_calls));
    try std.testing.expectEqual(std.math.maxInt(u64), session.keccak.base.cpu.retired);
    try std.testing.expectEqual(@as(u64, 0x1000), session.keccak.base.cpu.pc);
    try std.testing.expectEqual(@as(u64, 1), try mem.load(pointer, 8));
}
