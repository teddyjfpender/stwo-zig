//! Execution diagnostics only. Does not produce or verify a proof.
const std = @import("std");
const rv64 = @import("mod.zig");

const Vector = struct {
    instruction: u32,
    pc: u64,
    registers: [32]u64,
    expected_registers: [32]u64,
    expected_pc: u64,
    memory_address: u64,
    memory_before: [16]u8,
    memory_after: [16]u8,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 3) {
        std.debug.print("usage: rv64-diagnostic inspect ELF | smoke ELF | vectors JSON\n", .{});
        return error.InvalidArguments;
    }
    const bytes = try std.fs.cwd().readFileAlloc(allocator, args[2], 32 * 1024 * 1024);
    if (std.mem.eql(u8, args[1], "inspect")) {
        const image = try rv64.elf.inspect(bytes, .{});
        const json = try std.json.Stringify.valueAlloc(allocator, .{
            .profile = rv64.profile.name,
            .proof_supported = false,
            .sp1_abi_supported = false,
            .image = image,
        }, .{});
        try std.fs.File.stdout().writeAll(json);
        try std.fs.File.stdout().writeAll("\n");
    } else if (std.mem.eql(u8, args[1], "smoke")) {
        // Explicit diagnostic ABI for compiler smoke fixtures only: 64 KiB
        // stack below 8 GiB, a0 result, EBREAK stop, 100,000 retirement budget.
        // A breakpoint is reported as a stop reason, never proof of completion.
        const image = try rv64.elf.inspect(bytes, .{});
        var memory = try rv64.elf.load(std.heap.page_allocator, bytes, .{});
        defer memory.deinit();
        const stack_top: u64 = 0x200000000;
        try memory.map(.{ .start = stack_top - 65536, .size = 65536, .permissions = .{ .read = true, .write = true } });
        var cpu = rv64.machine.Cpu.init(image.entry, stack_top);
        while (cpu.retired < 100000) {
            _ = cpu.step(&memory) catch |err| switch (err) {
                error.Breakpoint => break,
                else => return err,
            };
        } else return error.StepLimit;
        const json = try std.json.Stringify.valueAlloc(allocator, .{ .stop = "breakpoint", .a0 = cpu.read(10), .retired = cpu.retired, .proof_supported = false, .sp1_abi_supported = false }, .{});
        try std.fs.File.stdout().writeAll(json);
        try std.fs.File.stdout().writeAll("\n");
    } else if (std.mem.eql(u8, args[1], "vectors") or std.mem.eql(u8, args[1], "vectors-cached")) {
        const use_cache = std.mem.eql(u8, args[1], "vectors-cached");
        var decoder = try @import("decode_cache.zig").Cache.init(allocator, 1024);
        defer decoder.deinit();
        const parsed = try std.json.parseFromSlice([]Vector, allocator, bytes, .{});
        if (parsed.value.len == 0 or parsed.value.len > 100000) return error.InvalidVectorCount;
        var seen: [@typeInfo(rv64.decode.Opcode).@"enum".fields.len]bool = @splat(false);
        for (parsed.value, 0..) |vector, i| {
            // Release each case's pages immediately; JSON has a separate arena.
            var memory = rv64.memory.Memory.init(std.heap.page_allocator, .{});
            defer memory.deinit();
            try memory.map(.{ .start = vector.pc & ~@as(u64, 4095), .size = 4096, .permissions = .{ .read = true, .execute = true } });
            try memory.map(.{ .start = vector.memory_address, .size = 16, .permissions = .{ .read = true, .write = true } });
            var instruction: [4]u8 = undefined;
            std.mem.writeInt(u32, &instruction, vector.instruction, .little);
            try memory.initialize(vector.pc, &instruction);
            try memory.initialize(vector.memory_address, &vector.memory_before);
            var cpu = rv64.machine.Cpu.init(vector.pc, 0);
            cpu.regs = vector.registers;
            const retirement = if (use_cache) try cpu.stepCached(&memory, &decoder) else try cpu.step(&memory);
            seen[@intFromEnum(retirement.opcode)] = true;
            var after: [16]u8 = undefined;
            for (&after, 0..) |*byte, j| byte.* = @intCast(try memory.load(vector.memory_address + j, 1));
            if (!std.mem.eql(u64, &cpu.regs, &vector.expected_registers) or cpu.pc != vector.expected_pc or !std.mem.eql(u8, &after, &vector.memory_after)) {
                std.debug.print("RV64 differential mismatch at case {d}, instruction 0x{x}, opcode {s}\n", .{ i, vector.instruction, @tagName(retirement.opcode) });
                for (cpu.regs, vector.expected_registers, 0..) |actual, expected, reg| {
                    if (actual != expected) std.debug.print("x{d}: actual 0x{x}, expected 0x{x}\n", .{ reg, actual, expected });
                }
                std.debug.print("pc: actual 0x{x}, expected 0x{x}\n", .{ cpu.pc, vector.expected_pc });
                return error.DifferentialMismatch;
            }
        }
        var covered: usize = 0;
        for (seen, 0..) |present, index| {
            if (index == @intFromEnum(rv64.decode.Opcode.ECALL) or index == @intFromEnum(rv64.decode.Opcode.EBREAK)) continue;
            if (!present) return error.IncompleteOpcodeCoverage;
            covered += 1;
        }
        const json = try std.json.Stringify.valueAlloc(allocator, .{ .vectors = parsed.value.len, .opcodes = covered, .expected_opcodes = seen.len - 2, .cached_decode = use_cache, .proof_supported = false }, .{});
        try std.fs.File.stdout().writeAll(json);
        try std.fs.File.stdout().writeAll("\n");
    } else return error.InvalidArguments;
}
