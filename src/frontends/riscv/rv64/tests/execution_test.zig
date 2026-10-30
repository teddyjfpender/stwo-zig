const std = @import("std");
const isa = @import("../decode.zig");
const mem = @import("../memory.zig");
const machine = @import("../machine.zig");
const elf = @import("../elf.zig");
const Word = @import("../word.zig").Word;
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const allocator = std.testing.allocator;

fn memoryWithCode(words: []const u32) !mem.Memory {
    var memory = mem.Memory.init(allocator, .{});
    errdefer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 4096, .permissions = .{ .read = true, .execute = true } });
    for (words, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(0x1000 + i * 4, &bytes);
    }
    return memory;
}

fn execute(word: u32, a: u64, b: u64) !u64 {
    var memory = try memoryWithCode(&.{word});
    defer memory.deinit();
    var cpu = machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = a;
    cpu.regs[2] = b;
    _ = try cpu.step(&memory);
    return cpu.read(3);
}

test "rv64: byte words preserve every bit without field reduction" {
    for ([_]u64{ 0, 0x80000000, 0x100000000, 0x8000000000000000, 0xffffffffffffffff }) |value| {
        try equal(value, Word.fromInt(value).toInt());
    }
}

test "rv64: six-bit shifts and reserved word encodings" {
    const slli63 = try isa.Instruction.decode(0x03f09193);
    try equal(isa.Opcode.SLLI, slli63.opcode);
    try equal(@as(i64, 63), slli63.imm);
    for ([_]u32{ 0x0200919b, 0x0200d19b, 0x023091bb, 0x0030a1bb, 0x0000100f, 0x1000202f, 0x00001073, 0, 1, 0xffffffff }) |word| {
        try std.testing.expectError(error.IllegalInstruction, isa.Instruction.decode(word));
    }
}

test "rv64: full-width and W operations use different shift and sign rules" {
    try equal(@as(u64, 0x8000000000000000), try execute(0x03f09193, 1, 0)); // slli 63
    try equal(@as(u64, 0xffffffff80000000), try execute(0x0010819b, 0x7fffffff, 0)); // addiw
    try equal(@as(u64, 0xffffffff80000000), try execute(0x0000819b, 0x1234567880000000, 0));
    try equal(@as(u64, 0x80000000), try execute(0x0000d193, 0x80000000, 0)); // srli
    try equal(@as(u64, 0xffffffff80000000), try execute(0x0000d19b, 0x80000000, 0)); // srliw 0
    try equal(@as(u64, 0xffffffff80000000), try execute(0x800001b7, 0, 0)); // lui sign extends
    try equal(@as(u64, 1), try execute(0x002091bb, 1, 32)); // sllw masks to five bits
    try equal(@as(u64, 0x100000000), try execute(0x002091b3, 1, 32)); // sll uses six
}

test "rv64: multiplication high halves retain signs and full 128-bit products" {
    try equal(@as(u64, 0xfffffffffffffffe), try execute(0x0220b1b3, 0xffffffffffffffff, 0xffffffffffffffff)); // mulhu
    try equal(@as(u64, 0), try execute(0x022091b3, 0xffffffffffffffff, 0xffffffffffffffff)); // mulh
    try equal(@as(u64, 0xffffffffffffffff), try execute(0x0220a1b3, 0xffffffffffffffff, 0xffffffffffffffff)); // mulhsu
    try equal(@as(u64, 0x4000000000000000), try execute(0x022091b3, 0x8000000000000000, 0x8000000000000000));
}

test "rv64: signed division rounds toward zero and implements architectural exceptions" {
    try equal(@as(u64, @bitCast(@as(i64, -2))), try execute(0x0220c1b3, @bitCast(@as(i64, -7)), 3));
    try equal(@as(u64, 0xffffffffffffffff), try execute(0x0220e1b3, @bitCast(@as(i64, -7)), 3));
    try equal(@as(u64, 0x8000000000000000), try execute(0x0220c1b3, 0x8000000000000000, 0xffffffffffffffff));
    try equal(@as(u64, 0), try execute(0x0220e1b3, 0x8000000000000000, 0xffffffffffffffff));
    try equal(@as(u64, 0xffffffffffffffff), try execute(0x0220d1b3, 7, 0));
    try equal(@as(u64, 7), try execute(0x0220f1b3, 7, 0));
    try equal(@as(u64, 0xffffffff80000000), try execute(0x0220c1bb, 0x80000000, 0xffffffffffffffff));
    try equal(@as(u64, 0xffffffffffffffff), try execute(0x0220d1bb, 0xffffffff, 1)); // divuw sign extends
    try equal(@as(u64, 0xffffffff80000000), try execute(0x0220f1bb, 0x80000000, 0)); // remuw zero
}

test "rv64: 64-bit memory cannot alias addresses separated by 4 GiB" {
    var memory = mem.Memory.init(allocator, .{});
    defer memory.deinit();
    for ([_]u64{ 0x2000, 0x100002000 }) |address| try memory.map(.{ .start = address, .size = 4096, .permissions = .{ .read = true, .write = true } });
    try memory.store(0x2000, 8, 0x1111222233334444);
    try memory.store(0x100002000, 8, 0xaaaabbbbccccdddd);
    try equal(@as(u64, 0x1111222233334444), try memory.load(0x2000, 8));
    try equal(@as(u64, 0xaaaabbbbccccdddd), try memory.load(0x100002000, 8));
    try equal(@as(u64, 0), try memory.load(0x100002008, 8));
    try std.testing.expectError(error.MisalignedAddress, memory.store(0x2001, 8, 1));
    try std.testing.expectError(error.UnmappedAddress, memory.load(0x3000, 8));
    try std.testing.expectError(error.AccessDenied, memory.fetch(0x2000));
    try std.testing.expectError(error.AddressOverflow, mem.endAddress(std.math.maxInt(u64), 2));
}

test "rv64: bounded memory rejects overlap and allocation before writing" {
    var memory = mem.Memory.init(allocator, .{ .max_mapped_bytes = 8192, .max_pages = 1 });
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 8192, .permissions = .{ .read = true, .write = true } });
    try memory.store(0x1000, 8, 123);
    try std.testing.expectError(error.ResourceLimit, memory.store(0x2000, 8, 456));
    try equal(@as(u64, 0), try memory.load(0x2000, 8));
    try equal(@as(u64, 123), try memory.load(0x1000, 8));
    try std.testing.expectError(error.ResourceLimit, memory.map(.{ .start = 0x4000, .size = 1, .permissions = .{} }));
    var other = mem.Memory.init(allocator, .{});
    defer other.deinit();
    try other.map(.{ .start = 0x1000, .size = 16, .permissions = .{} });
    try std.testing.expectError(error.OverlappingRegion, other.map(.{ .start = 0x1008, .size = 16, .permissions = .{} }));
}

test "rv64: loads to x0 still fault and traps preserve CPU and memory" {
    var memory = try memoryWithCode(&.{ 0x0000b003, 0x00000073, 0x00100073, 0x002000ef, 0x00000013 });
    defer memory.deinit();
    var cpu = machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = 0x100000000;
    const initial = cpu;
    try std.testing.expectError(error.UnmappedAddress, cpu.step(&memory));
    try equal(initial, cpu);
    cpu.pc = 0x1004;
    try std.testing.expectError(error.EnvironmentCall, cpu.step(&memory));
    try equal(@as(u64, 0x1004), cpu.pc);
    cpu.pc = 0x1008;
    try std.testing.expectError(error.Breakpoint, cpu.step(&memory));
    cpu.pc = 0x100c;
    try std.testing.expectError(error.MisalignedAddress, cpu.step(&memory));
    try equal(@as(u64, 0x100000000), cpu.regs[1]);
    cpu.pc = 0x1010;
    cpu.retired = std.math.maxInt(u64);
    try std.testing.expectError(error.StepLimit, cpu.step(&memory));
}

test "rv64: LD SD LW LWU retirement preserves complete addresses and values" {
    var memory = try memoryWithCode(&.{ 0x0020b023, 0x0000b183, 0x0000a203, 0x0000e283 });
    defer memory.deinit();
    try memory.map(.{ .start = 0x100002000, .size = 16, .permissions = .{ .read = true, .write = true } });
    var cpu = machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = 0x100002000;
    cpu.regs[2] = 0x1234567880000001;
    const store = try cpu.step(&memory);
    try equal(@as(u64, 0x100002000), store.memory.?.address.toInt());
    try equal(cpu.regs[2], store.memory.?.value.toInt());
    _ = try cpu.step(&memory);
    _ = try cpu.step(&memory);
    _ = try cpu.step(&memory);
    try equal(cpu.regs[2], cpu.regs[3]);
    try equal(@as(u64, 0xffffffff80000001), cpu.regs[4]);
    try equal(@as(u64, 0x80000001), cpu.regs[5]);
    try equal(@as(u64, 4), cpu.retired);
}

test "rv64: untaken misaligned branch and JALR source-destination alias" {
    var memory = try memoryWithCode(&.{ 0x00208163, 0x000080e7 });
    defer memory.deinit();
    var cpu = machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = 0x1001;
    cpu.regs[2] = 0;
    _ = try cpu.step(&memory); // BEQ is false; unused +2 target must not trap
    _ = try cpu.step(&memory); // jalr x1,x1,0 must read old x1 and clear bit zero
    try equal(@as(u64, 0x1000), cpu.pc);
    try equal(@as(u64, 0x1008), cpu.regs[1]);
}

fn put16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}
fn put32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}
fn put64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

fn executable() [136]u8 {
    var bytes = [_]u8{0} ** 136;
    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&bytes, 16, 2);
    put16(&bytes, 18, 243);
    put32(&bytes, 20, 1);
    put64(&bytes, 24, 0x100001000);
    put64(&bytes, 32, 64);
    put16(&bytes, 52, 64);
    put16(&bytes, 54, 56);
    put16(&bytes, 56, 1);
    put32(&bytes, 64, 1);
    put32(&bytes, 68, 5);
    put64(&bytes, 72, 128);
    put64(&bytes, 80, 0x100001000);
    put64(&bytes, 96, 8);
    put64(&bytes, 104, 16);
    put64(&bytes, 112, 1);
    put32(&bytes, 128, 0xfff00093); // addi x1,x0,-1
    put32(&bytes, 132, 0x0010819b); // addiw x3,x1,1
    return bytes;
}

test "rv64: ELF64 load and multi-instruction execution above 4 GiB" {
    const bytes = executable();
    const image = try elf.inspect(&bytes, .{});
    var memory = try elf.load(allocator, &bytes, .{});
    defer memory.deinit();
    var cpu = machine.Cpu.init(image.entry, 0);
    _ = try cpu.step(&memory);
    _ = try cpu.step(&memory);
    try equal(std.math.maxInt(u64), cpu.regs[1]);
    try equal(@as(u64, 0), cpu.regs[3]);
    try equal(@as(u64, 0), try memory.load(image.entry + 8, 8)); // BSS
    try std.testing.expectError(error.AccessDenied, memory.store(image.entry, 4, 0));
}

test "rv64: ELF64 rejects foreign ISA, malformed tables, oversized images and bad entries" {
    const original = executable();
    for ([_]usize{ 4, 5, 6, 18, 48, 52, 54 }) |offset| {
        var bytes = original;
        bytes[offset] ^= 0xff;
        if (elf.inspect(&bytes, .{})) |_| return error.TestUnexpectedResult else |_| {}
    }
    var bytes = original;
    put64(&bytes, 32, std.math.maxInt(u64));
    try std.testing.expectError(error.InvalidElf, elf.inspect(&bytes, .{}));
    bytes = original;
    put64(&bytes, 24, 0x100001002);
    try std.testing.expectError(error.InvalidEntry, elf.inspect(&bytes, .{}));
    bytes = original;
    put64(&bytes, 96, 17);
    try std.testing.expectError(error.InvalidSegment, elf.inspect(&bytes, .{}));
    bytes = original;
    put64(&bytes, 80, std.math.maxInt(u64) - 3);
    try std.testing.expectError(error.AddressOverflow, elf.inspect(&bytes, .{}));
    try std.testing.expectError(error.ResourceLimit, elf.inspect(&original, .{ .max_mapped_bytes = 8 }));
    for (0..original.len) |length| {
        if (elf.inspect(original[0..length], .{})) |_| return error.TestUnexpectedResult else |_| {}
    }
}

test "rv64: malformed ELF fuzz stays within bounded parser reads" {
    var prng = std.Random.DefaultPrng.init(0x52563634);
    for (0..2000) |_| {
        var bytes = executable();
        const offset = prng.random().uintLessThan(usize, bytes.len);
        bytes[offset] = prng.random().int(u8);
        _ = elf.inspect(&bytes, .{ .max_mapped_bytes = 4096 }) catch {};
    }
}

fn loadWithAllocator(failing_allocator: std.mem.Allocator) !void {
    const bytes = executable();
    var memory = try elf.load(failing_allocator, &bytes, .{});
    defer memory.deinit();
    try equal(@as(u64, 0xfff00093), try memory.load(0x100001000, 4));
}

test "rv64: ELF load releases every allocation on OOM" {
    try std.testing.checkAllAllocationFailures(allocator, loadWithAllocator, .{});
}

fn storeWithAllocator(failing_allocator: std.mem.Allocator) !void {
    var memory = mem.Memory.init(failing_allocator, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 4094, .size = 8, .permissions = .{ .read = true, .write = true } });
    const data = [_]u8{1} ** 8;
    memory.initialize(4094, &data) catch |err| {
        for (4094..4102) |address| try equal(@as(u64, 0), try memory.load(address, 1));
        return err;
    };
}

test "rv64: cross-page initialization is byte-atomic on OOM" {
    try std.testing.checkAllAllocationFailures(allocator, storeWithAllocator, .{});
}

test "rv64: ELF admission bounds region and page resources before allocation" {
    const bytes = executable();
    try std.testing.expectError(error.ResourceLimit, elf.inspect(&bytes, .{ .max_regions = 0 }));
    try std.testing.expectError(error.ResourceLimit, elf.inspect(&bytes, .{ .max_pages = 0 }));
    const info = try elf.inspect(&bytes, .{ .max_pages = 1 });
    try equal(@as(u64, 1), info.initial_pages);
    var loaded = try elf.loadImage(allocator, &bytes, .{ .max_pages = 1 });
    defer loaded.deinit();
    try equal(info, loaded.info);
    try equal(@as(usize, 1), loaded.memory.pageCount());
}

test "rv64: ELF page preflight deduplicates sub-page segments in reverse header order" {
    const original = executable();
    var bytes = [_]u8{0} ** 272;
    @memcpy(bytes[0..120], original[0..120]);
    @memcpy(bytes[120..176], original[64..120]);
    put16(&bytes, 56, 2);
    // The higher-address data segment appears first; code follows in the table.
    put32(&bytes, 68, 4);
    put64(&bytes, 72, 264);
    put64(&bytes, 80, 0x100001008);
    put64(&bytes, 104, 8);
    put64(&bytes, 128, 256);
    put64(&bytes, 160, 8);
    @memcpy(bytes[256..264], original[128..136]);
    const info = try elf.inspect(&bytes, .{ .max_pages = 1 });
    try equal(@as(u64, 1), info.initial_pages);
    var loaded = try elf.loadImage(allocator, &bytes, .{ .max_pages = 1 });
    defer loaded.deinit();
    try equal(@as(usize, 1), loaded.memory.pageCount());
    try equal(@as(u64, 0xfff00093), try loaded.memory.load(info.entry, 4));
    put64(&bytes, 80, 0x100002008);
    try std.testing.expectError(error.ResourceLimit, elf.inspect(&bytes, .{ .max_pages = 1 }));
}

test "rv64: last address code and RAM accesses preserve full width and x0" {
    const a = std.testing.allocator;
    var code = mem.Memory.init(a, .{});
    defer code.deinit();
    const pc = std.math.maxInt(u64) - 3;
    try code.map(.{ .start = pc, .size = 4, .permissions = .{ .read = true, .execute = true } });
    const jump = [_]u8{ 0x6f, 0, 0x40, 0 }; // JAL x0,4
    try code.initialize(pc, &jump);
    var cpu = machine.Cpu.init(pc, 0);
    const jumped = try cpu.step(&code);
    try std.testing.expectEqual(@as(u64, 0), cpu.pc);
    try std.testing.expectEqual(@as(u64, 0), jumped.result.toInt());
    try std.testing.expectEqual(@as(u64, 0), cpu.regs[0]);
    var data = mem.Memory.init(a, .{});
    defer data.deinit();
    try data.map(.{ .start = 0x1000, .size = 4, .permissions = .{ .read = true, .execute = true } });
    const load = [_]u8{ 0x03, 0x30, 0x01, 0 }; // LD x0,0(x2)
    try data.initialize(0x1000, &load);
    const address = std.math.maxInt(u64) - 7;
    try data.map(.{ .start = address, .size = 8, .permissions = .{ .read = true } });
    try data.initialize(address, &@as([8]u8, @splat(255)));
    cpu = machine.Cpu.init(0x1000, address);
    const loaded = try cpu.step(&data);
    try std.testing.expectEqual(std.math.maxInt(u64), loaded.result.toInt());
    try std.testing.expectEqual(address, loaded.memory.?.address.toInt());
    try std.testing.expectEqual(@as(u64, 0), cpu.regs[0]);
}
