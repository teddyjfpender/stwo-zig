//! Small execution kernels, not a proving benchmark. Setup is outside timers.
const std = @import("std");
const rv = @import("mod.zig");
const alloc = std.heap.page_allocator;
const Sample = struct { workload: []const u8, operations: u64, elapsed_ns: u64, checksum: u64 };

pub fn main() !void {
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    if (args.len != 2) return error.InvalidArguments;
    const sample = if (std.mem.eql(u8, args[1], "execution")) try execution() else if (std.mem.eql(u8, args[1], "memory")) try memory() else if (std.mem.eql(u8, args[1], "bulk")) try bulk() else return error.InvalidArguments;
    const bytes = try std.json.Stringify.valueAlloc(alloc, sample, .{});
    defer alloc.free(bytes);
    try std.fs.File.stdout().writeAll(bytes);
    try std.fs.File.stdout().writeAll("\n");
}

fn execution() !Sample {
    var mem = rv.memory.Memory.init(alloc, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 4096, .permissions = .{ .read = true, .execute = true } });
    try mem.map(.{ .start = 0x100004000, .size = 4096, .permissions = .{ .read = true, .write = true } });
    // addi x1,x1,1; sd x1,0(x2); ld x3,0(x2); xor x4,x4,x3; jal x0,-16
    const words = [_]u32{ 0x00108093, 0x00113023, 0x00013183, 0x00324233, 0xff1ff06f };
    for (words, 0..) |word, i| {
        var data: [4]u8 = undefined;
        std.mem.writeInt(u32, &data, word, .little);
        try mem.initialize(0x1000 + i * 4, &data);
    }
    try mem.store(0x100004000, 8, 0);
    var cpu = rv.machine.Cpu.init(0x1000, 0x100004000);
    var timer = try std.time.Timer.start();
    for (0..10000000) |_| _ = try cpu.step(&mem);
    const elapsed = timer.read();
    return .{ .workload = "execution", .operations = cpu.retired, .elapsed_ns = elapsed, .checksum = cpu.regs[1] ^ cpu.regs[4] ^ try mem.load(0x100004000, 8) };
}

fn memory() !Sample {
    var mem = rv.memory.Memory.init(alloc, .{});
    defer mem.deinit();
    for (0..256) |i| try mem.map(.{ .start = 0x100000000 + i * 8192, .size = 4096, .permissions = .{ .read = true, .write = true } });
    for (0..256) |i| try mem.store(0x100000000 + i * 8192, 8, i);
    var checksum: u64 = 0;
    var timer = try std.time.Timer.start();
    for (0..2000000) |i| {
        const address = 0x100000000 + (i % 256) * 8192;
        checksum +%= try mem.load(address, 8);
        try mem.store(address, 8, i);
    }
    return .{ .workload = "memory", .operations = 4000000, .elapsed_ns = timer.read(), .checksum = checksum };
}

fn bulk() !Sample {
    const bytes = try alloc.alloc(u8, 4 * 1024 * 1024);
    defer alloc.free(bytes);
    @memset(bytes, 0xa5);
    var mem = rv.memory.Memory.init(alloc, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x100000000, .size = bytes.len, .permissions = .{ .read = true, .write = true } });
    var timer = try std.time.Timer.start();
    try mem.initialize(0x100000000, bytes);
    const elapsed = timer.read();
    return .{ .workload = "bulk", .operations = bytes.len, .elapsed_ns = elapsed, .checksum = try mem.load(0x100000000, 8) +% try mem.load(0x100000000 + bytes.len - 8, 8) };
}
