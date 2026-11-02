//! Shared native fixture construction only, no tests and no proving authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const CPU = @import("cpu.zig");
pub fn reg(f3: u32, rd: u32, rs1: u32, rs2: u32, sub: bool, word: bool) u32 {
    return (if (word) @as(u32, 0x3b) else 0x33) | (rd << 7) | (f3 << 12) | (rs1 << 15) | (rs2 << 20) | (if (sub) @as(u32, 0x40000000) else 0);
}
pub fn imm(f3: u32, rd: u32, rs1: u32, value: i12, word: bool) u32 {
    return (if (word) @as(u32, 0x1b) else 0x13) | (rd << 7) | (f3 << 12) | (rs1 << 15) | (@as(u32, @as(u12, @bitCast(value))) << 20);
}
pub fn branch(f3: u32, rs1: u32, rs2: u32, offset: i13) u32 {
    const value: u13 = @bitCast(offset);
    return 0x63 | (@as(u32, (value >> 11) & 1) << 7) | (@as(u32, (value >> 1) & 15) << 8) | (f3 << 12) | (rs1 << 15) | (rs2 << 20) | (@as(u32, (value >> 5) & 63) << 25) | (@as(u32, value >> 12) << 31);
}
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    words: std.ArrayList(u32),
    records: std.ArrayList(front.rv64.machine.Retirement),
    public: CPU.Public,
    pub fn init(a: std.mem.Allocator) !Fixture {
        var words: std.ArrayList(u32) = .empty;
        errdefer words.deinit(a);
        try words.appendSlice(a, &.{
            reg(0, 3, 1, 2, false, false),    reg(0, 4, 0, 1, true, false),
            reg(0, 5, 6, 7, false, true),     reg(0, 8, 9, 10, true, true),
            reg(2, 11, 12, 13, false, false), reg(3, 14, 12, 13, false, false),
            imm(0, 15, 0, -1, false),         imm(0, 16, 17, 1, true),
            imm(2, 18, 12, -1, false),        imm(3, 19, 0, -1, false),
            imm(7, 20, 15, -2, false),        imm(6, 21, 0, -2048, false),
            imm(4, 22, 20, -1, false),        reg(7, 23, 1, 2, false, false),
            reg(6, 24, 3, 4, false, false),   reg(4, 25, 5, 8, false, false),
        });
        // All six branch predicates, each taken and untaken; target skips one
        // real instruction. The mapping is the shared Operations authority.
        const cases = [_][3]u32{
            .{ 0, 0, 0 },   .{ 0, 0, 29 },  .{ 1, 0, 0 },   .{ 1, 0, 29 },
            .{ 4, 30, 29 }, .{ 4, 29, 30 }, .{ 5, 30, 29 }, .{ 5, 29, 30 },
            .{ 6, 30, 29 }, .{ 6, 29, 30 }, .{ 7, 30, 29 }, .{ 7, 29, 30 },
        };
        for (cases) |item| {
            try words.append(a, branch(item[0], item[1], item[2], 8));
            try words.append(a, reg(0, 0, 0, 0, false, false));
        }
        try words.append(a, imm(0, 26, 26, -1, false));
        try words.append(a, branch(1, 26, 0, -4)); // backward edge, three iterations
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = @intCast(words.items.len * 4), .permissions = .{ .read = true, .execute = true } });
        for (words.items, 0..) |word, index| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * index, &bytes);
        }
        var cpu = front.rv64.machine.Cpu.init(4096, 0);
        cpu.regs[1] = 0xffffffffffffffff;
        cpu.regs[2] = 1;
        cpu.regs[6] = 0x7fffffff;
        cpu.regs[7] = 1;
        cpu.regs[9] = 0x80000000;
        cpu.regs[10] = 1;
        cpu.regs[12] = 0x8000000000000000;
        cpu.regs[13] = 1;
        cpu.regs[17] = 0x7fffffff;
        cpu.regs[26] = 3;
        cpu.regs[29] = 1;
        cpu.regs[30] = 0x8000000000000000;
        cpu.regs[31] = 0xffffffffffffffff;
        const initial = cpu.regs;
        var records: std.ArrayList(front.rv64.machine.Retirement) = .empty;
        errdefer records.deinit(a);
        var clocks: [32]u32 = @splat(0);
        while (cpu.pc != 4096 + 4 * words.items.len) {
            if (records.items.len >= 63) return error.BadAluFixtureLoop;
            const record = try cpu.step(&memory);
            for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
                clocks[id] = @intCast(4 * records.items.len + slot + 1);
            };
            try records.append(a, record);
        }
        return .{ .allocator = a, .words = words, .records = records, .public = .{ .steps = @intCast(records.items.len), .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    pub fn deinit(self: *Fixture) void {
        self.words.deinit(self.allocator);
        self.records.deinit(self.allocator);
    }
};
