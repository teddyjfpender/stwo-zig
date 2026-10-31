const std = @import("std");
const compact = @import("../compact_tape.zig");
const isa = @import("../decode.zig");
const machine = @import("../machine.zig");
const memory = @import("../memory.zig");
const services = @import("../service_session.zig");
const Word = @import("../word.zig").Word;
const a = std.testing.allocator;
const pc: u64 = 0x100001000;
const data: u64 = 0x200000000;

fn setup(allocator: std.mem.Allocator, raw: u32) !memory.Memory {
    var mem = memory.Memory.init(allocator, .{});
    errdefer mem.deinit();
    try mem.map(.{ .start = pc, .size = 4096, .permissions = .{ .read = true, .execute = true } });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, raw, .little);
    try mem.initialize(pc, &bytes);
    try mem.map(.{ .start = data, .size = 4096, .permissions = .{ .read = true, .write = true } });
    try mem.store(data, 8, 0xfedcba9876543280);
    return mem;
}
fn register(op: u32, funct3: u32, funct7: u32) u32 {
    return op | (3 << 7) | (funct3 << 12) | (1 << 15) | (2 << 20) | (funct7 << 25);
}

test "RV64 tape: all 63 retiring instructions roundtrip full records without execution replay" {
    var raws: std.ArrayList(u32) = .empty;
    defer raws.deinit(a);
    for (0..8) |f| try raws.append(a, register(0x33, @intCast(f), 0));
    for ([_]u32{ 0, 5 }) |f| try raws.append(a, register(0x33, f, 0x20));
    for (0..8) |f| try raws.append(a, register(0x33, @intCast(f), 1));
    for ([_]u32{ 0, 1, 5 }) |f| try raws.append(a, register(0x3b, f, 0));
    for ([_]u32{ 0, 5 }) |f| try raws.append(a, register(0x3b, f, 0x20));
    for ([_]u32{ 0, 4, 5, 6, 7 }) |f| try raws.append(a, register(0x3b, f, 1));
    for (0..8) |f| try raws.append(a, 0x13 | (3 << 7) | (@as(u32, @intCast(f)) << 12) | (1 << 15));
    try raws.append(a, 0x4000d193); // srai x3,x1,0
    for ([_]u32{ 0, 1, 5 }) |f| try raws.append(a, 0x1b | (3 << 7) | (f << 12) | (1 << 15));
    try raws.append(a, 0x4000d19b); // sraiw x3,x1,0
    for (0..7) |f| try raws.append(a, 0x03 | (3 << 7) | (@as(u32, @intCast(f)) << 12) | (1 << 15));
    for (0..4) |f| try raws.append(a, 0x23 | (@as(u32, @intCast(f)) << 12) | (1 << 15) | (2 << 20));
    for ([_]u32{ 0, 1, 4, 5, 6, 7 }) |f| try raws.append(a, 0x463 | (f << 12) | (1 << 15) | (2 << 20));
    try raws.appendSlice(a, &.{ 0x008001ef, 0x000081e7, 0x800001b7, 0xfffff197, 0x0000000f });
    var covered: [65]bool = @splat(false);
    for (raws.items) |raw| for ([_]u64{ 0, 1, 0x8000000000000000, 0xffffffffffffffff }) |value| {
        const entry = try compact.Entry.decode(.rv64im, raw);
        const effects = isa.effects(entry.instruction.opcode);
        for (0..8) |offset| {
            if (effects.memory_width == 0 and offset != 0) continue;
            if (effects.memory_width != 0 and offset % effects.memory_width != 0) continue;
            var mem = try setup(a, raw);
            defer mem.deinit();
            var cpu = machine.Cpu.init(pc, 0);
            cpu.retired = 1 << 40;
            cpu.regs[1] = if (effects.memory_width != 0) data + offset else if (entry.instruction.opcode == .JALR) pc else value;
            cpu.regs[2] = value;
            cpu.regs[3] = ~value;
            var tape = try compact.Tape.init(a, 1, pc, cpu.retired, .rv64im);
            defer tape.deinit();
            const record = try cpu.step(&mem);
            try tape.append(record);
            covered[@intFromEnum(record.opcode)] = true;
            try std.testing.expectEqualDeep(record, try tape.restore(0, entry, .global));
            var local = record;
            local.clock = 1;
            try std.testing.expectEqualDeep(local, try tape.restore(0, entry, .local));
            try std.testing.expectEqual(@as(usize, @intFromBool(record.memory != null)), tape.memory_before.items.len);
            try std.testing.expectError(error.TapeFull, tape.append(record));
        }
    };
    try std.testing.expectEqual(@as(usize, 63), std.mem.count(bool, &covered, &.{true}));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(compact.Step));
    try std.testing.expect(@sizeOf(compact.Step) < @sizeOf(machine.Retirement));
}

test "RV64 tape: service ECALL advice retains profile identity and rebases clocks" {
    const call = services.Call{ .call_id = 7, .clock = 0x100000002, .pc = pc, .pointer = data, .before = @splat(0), .after = @splat(1) };
    var tape = try compact.Tape.init(a, 1, pc, call.clock - 1, .keccak_service_v1);
    defer tape.deinit();
    const record = call.retirement();
    try tape.appendService(call);
    try std.testing.expectEqualDeep(record, try tape.restore(0, try compact.Entry.decode(.keccak_service_v1, 0x73), .global));
    try std.testing.expectError(error.UnadmittedTapeInstruction, compact.Entry.decode(.rv64im, 0x73));
    try std.testing.expectError(error.UnadmittedTapeInstruction, compact.Entry.decode(.keccak_service_v1, 0x100073));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var mem = try setup(allocator, 0x00208023); // sb x2,0(x1)
    defer mem.deinit();
    var cpu = machine.Cpu.init(pc, 0);
    cpu.regs[1] = data;
    cpu.regs[2] = 0x42;
    var tape = try compact.Tape.init(allocator, 2, pc, 0, .rv64im);
    defer tape.deinit();
    const record = try cpu.step(&mem);
    tape.append(record) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), tape.len);
        try std.testing.expectEqual(@as(usize, 0), tape.memory_before.items.len);
        return err;
    };
    const entry = try compact.Entry.decode(.rv64im, record.instruction);
    try std.testing.expectEqualDeep(record, try tape.restore(0, entry, .global));
    const original = tape.storage[0];
    tape.storage[0].memory_index = compact.NO_MEMORY;
    try std.testing.expectError(error.InvalidTapeMemoryIndex, tape.restore(0, entry, .local));
    tape.storage[0] = original;
    tape.storage[0].flags = 2;
    try std.testing.expectError(error.InvalidTapeRetirement, tape.restore(0, entry, .local));
    tape.storage[0] = original;
    var changed = record;
    changed.pc = Word.fromInt(pc + 8);
    try std.testing.expectError(error.InvalidTapeRetirement, tape.append(changed));
    try std.testing.expectEqual(@as(usize, 1), tape.len);
    try std.testing.expectEqual(@as(usize, 1), tape.memory_before.items.len);
}
test "RV64 tape: ownership failures and malformed advice preserve captured prefix" {
    try allocationCase(a);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    try std.testing.expectError(error.InvalidTapeGeometry, compact.Tape.init(a, 0, pc, 0, .rv64im));
    try std.testing.expectError(error.InvalidTapeGeometry, compact.Tape.init(a, 1, pc, std.math.maxInt(u64), .rv64im));
}

test "RV64 tape: adjacent batches reuse storage and reset only proof clocks" {
    var mem = try setup(a, 0x00108093);
    defer mem.deinit();
    try mem.initialize(pc + 4, &.{ 0x93, 0x80, 0x10, 0 });
    var cpu = machine.Cpu.init(pc, 0);
    cpu.retired = std.math.maxInt(u64) - 2;
    var tape = try compact.Tape.init(a, 1, pc, cpu.retired, .rv64im);
    defer tape.deinit();
    const pointer = tape.storage.ptr;
    const entry = try compact.Entry.decode(.rv64im, 0x00108093);
    for (0..2) |_| {
        const record = try cpu.step(&mem);
        try tape.append(record);
        try std.testing.expectEqualDeep(record, try tape.restore(0, entry, .global));
        try std.testing.expectEqual(@as(u64, 1), (try tape.restore(0, entry, .local)).clock);
        tape.clearRetainingCapacity();
        try std.testing.expectEqual(pointer, tape.storage.ptr);
        try std.testing.expectEqual(@as(usize, 0), tape.len);
        try std.testing.expectEqual(cpu.retired, tape.initial_clock);
        try std.testing.expectEqual(cpu.pc, tape.initial_pc);
    }
    var invalid = (services.Call{ .call_id = 1, .clock = 0, .pc = cpu.pc, .pointer = data, .before = @splat(0), .after = @splat(0) }).retirement();
    invalid.opcode = .FENCE;
    try std.testing.expectError(error.InvalidTapeRetirement, tape.append(invalid));
}

fn mixedServices(allocator: std.mem.Allocator, mode: @import("../execution_profile.zig").Profile) !void {
    const ethereum = @import("../ethereum_services/session.zig");
    const initial_clock: u64 = 1 << 40;
    const format: @import("../execution_profile.zig").SecpPacketFormat = if (mode == .ethereum_services_v1) .big_endian_bytes_v1 else .little_endian_words_v2;
    var tape = try compact.Tape.init(allocator, 4, pc, initial_clock, mode);
    defer tape.deinit();
    const keccak = services.Call{ .call_id = 33, .clock = initial_clock + 1, .pc = pc, .pointer = data, .before = @splat(0), .after = @splat(1) };
    const add = ethereum.SecpCall{ .kind = .add, .packet_format = format, .call_id = 12, .clock = initial_clock + 2, .pc = pc + 4, .pointer = data, .before = @splat(2), .after = @splat(3) };
    const double = ethereum.SecpCall{ .kind = .double, .packet_format = format, .call_id = 7, .clock = initial_clock + 3, .pc = pc + 8, .pointer = data, .before = @splat(4), .after = @splat(5) };
    try tape.appendEvent(.{ .keccak = keccak });
    try tape.appendEvent(.{ .secp = add });
    try tape.appendEvent(.{ .secp = double });
    const entry = try compact.Entry.decode(mode, 0x73);
    for ([_]@import("../machine.zig").Retirement{ keccak.retirement(), add.retirement(), double.retirement() }, 0..) |record, i| {
        try std.testing.expectEqualDeep(record, try tape.restore(i, entry, .global));
        try std.testing.expectEqual(@as(u64, i + 1), (try tape.restore(i, entry, .local)).clock);
    }
    try std.testing.expectEqualDeep(keccak, tape.service_calls.items[0]);
    try std.testing.expectEqualDeep(add, tape.secp_calls.items[0]);
    try std.testing.expectEqualDeep(double, tape.secp_calls.items[1]);
    var repeated = add;
    repeated.pc = pc + 12;
    repeated.clock = initial_clock + 4;
    try std.testing.expectError(error.InvalidTapeService, tape.appendSecp(repeated));
    try std.testing.expectEqual(@as(usize, 3), tape.len);
    tape.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0), tape.service_calls.items.len);
    try std.testing.expectEqual(@as(usize, 0), tape.secp_calls.items.len);
    try std.testing.expectEqualDeep([2]?u64{ null, null }, tape.last_secp_ids);
    var legacy = try compact.Tape.init(allocator, 1, add.pc, add.clock - 1, .keccak_service_v1);
    defer legacy.deinit();
    try std.testing.expectError(error.InvalidTapeService, legacy.appendSecp(add));
}
test "RV64 tape: all typed service sidecars retain exact data through checked global clocks and OOM" {
    for ([_]@import("../execution_profile.zig").Profile{ .ethereum_services_v1, .ethereum_services_v2 }) |mode| {
        try mixedServices(a, mode);
        try std.testing.checkAllAllocationFailures(a, mixedServices, .{mode});
    }
}
