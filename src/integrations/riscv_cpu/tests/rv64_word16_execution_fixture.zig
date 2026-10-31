//! Native one-pass mixed integer/memory fixture. Expected pristine image is an
//! independently loaded owner; only one transient Retirement exists per step.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const X = front.rv64_air.word16_execution;
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
pub const symbols = rv.ethereum_contract.Symbols{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 };
fn r(f7: u7, rs2: u5, rs1: u5, f3: u3, rd: u5, opcode: u7) u32 {
    return @as(u32, f7) << 25 | @as(u32, rs2) << 20 | @as(u32, rs1) << 15 | @as(u32, f3) << 12 | @as(u32, rd) << 7 | opcode;
}
fn i(imm: i12, rs1: u5, f3: u3, rd: u5, opcode: u7) u32 {
    return @as(u32, @as(u12, @bitCast(imm))) << 20 | @as(u32, rs1) << 15 | @as(u32, f3) << 12 | @as(u32, rd) << 7 | opcode;
}
fn store(offset: u12, rs2: u5, rs1: u5, f3: u3) u32 {
    return @as(u32, offset >> 5) << 25 | @as(u32, rs2) << 20 | @as(u32, rs1) << 15 | @as(u32, f3) << 12 | @as(u32, offset & 31) << 7 | 0x23;
}
fn branch(offset: u13, rs2: u5, rs1: u5, f3: u3) u32 {
    return @as(u32, offset >> 12) << 31 | @as(u32, (offset >> 5) & 63) << 25 | @as(u32, rs2) << 20 | @as(u32, rs1) << 15 | @as(u32, f3) << 12 | @as(u32, (offset >> 1) & 15) << 8 | @as(u32, (offset >> 11) & 1) << 7 | 0x63;
}
pub const words = [_]u32{
    0x021000b7, // LUI x1, mapped heap
    i(-17, 0, 0, 2, 0x13),
    r(0, 2, 2, 0, 3, 0x33),
    r(0x20, 2, 0, 0, 4, 0x3b),
    i(-1, 2, 4, 5, 0x13),
    i(4, 5, 1, 6, 0x13),
    i(0x403, 2, 5, 7, 0x1b),
    r(1, 6, 5, 0, 8, 0x33),
    r(1, 4, 2, 4, 9, 0x33),
    r(1, 5, 8, 7, 10, 0x3b),
    store(0, 8, 1, 3),
    i(0, 1, 2, 11, 0x03),
    i(1, 1, 0, 12, 0x03),
    store(6, 4, 1, 1),
    i(0, 2, 2, 13, 0x13),
    branch(8, 0, 13, 5),
    i(1, 0, 0, 14, 0x13),
    0x00000797, // AUIPC x15
    0x0080086f, // JAL x16,+8
    i(2, 0, 0, 14, 0x13),
    i(12, 16, 0, 17, 0x67),
    i(3, 0, 0, 14, 0x13),
    r(0, 6, 8, 7, 18, 0x33),
    0x0000000f,
    0x0000006f,
};
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    temp: std.testing.TmpDir,
    image: Image.Owner,
    tape: rv.compact_tape.Tape,
    boundary: X.types.Boundary,
    pub fn init(a: std.mem.Allocator) !Fixture {
        var elf: [120 + 4 * words.len]u8 = @splat(0);
        @memcpy(elf[0..7], "\x7fELF\x02\x01\x01");
        std.mem.writeInt(u16, elf[16..18], 2, .little);
        std.mem.writeInt(u16, elf[18..20], 243, .little);
        std.mem.writeInt(u32, elf[20..24], 1, .little);
        std.mem.writeInt(u64, elf[24..32], 4096, .little);
        std.mem.writeInt(u64, elf[32..40], 64, .little);
        std.mem.writeInt(u16, elf[52..54], 64, .little);
        std.mem.writeInt(u16, elf[54..56], 56, .little);
        std.mem.writeInt(u16, elf[56..58], 1, .little);
        std.mem.writeInt(u32, elf[64..68], 1, .little);
        std.mem.writeInt(u32, elf[68..72], 5, .little);
        std.mem.writeInt(u64, elf[72..80], 120, .little);
        std.mem.writeInt(u64, elf[80..88], 4096, .little);
        std.mem.writeInt(u64, elf[96..104], 4 * words.len, .little);
        std.mem.writeInt(u64, elf[104..112], 4 * words.len, .little);
        std.mem.writeInt(u64, elf[112..120], 4, .little);
        for (words, 0..) |word, index| std.mem.writeInt(u32, elf[120 + 4 * index ..][0..4], word, .little);
        var temp = std.testing.tmpDir(.{});
        errdefer temp.cleanup();
        try temp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
        try temp.dir.writeFile(.{ .sub_path = "input", .data = &.{0} });
        const elf_path = try temp.dir.realpathAlloc(a, "guest.elf");
        defer a.free(elf_path);
        const input_path = try temp.dir.realpathAlloc(a, "input");
        defer a.free(input_path);
        const elf_hash = std.fmt.bytesToHex(Request.sha(&elf), .lower);
        const input_hash = std.fmt.bytesToHex(Request.sha(&.{0}), .lower);
        const config = Request.Config{ .elf = elf_path, .input = input_path, .elf_sha256 = &elf_hash, .input_sha256 = &input_hash, .expected_output = "00" ** 43, .symbols = symbols, .output_directory = "unused", .terminal_pc = 4096 + 4 * (words.len - 1), .batch_steps = 32 };
        var image = try Image.Owner.init(a, config);
        errdefer image.deinit();
        var native = try rv.ethereum_contract.load(a, symbols, &elf, &.{0});
        defer native.deinit();
        var tape = try rv.compact_tape.Tape.init(a, 32, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var cpu = rv.machine.Cpu.init(4096, symbols.stack_top);
        const initial = cpu.regs;
        var clocks: [32]u32 = @splat(0);
        while (cpu.pc != config.terminal_pc) {
            if (tape.len >= 32) return error.FixtureDidNotHalt;
            const record = try cpu.step(&native.memory);
            try tape.append(record);
            const tick = @as(u32, @intCast(4 * (tape.len - 1)));
            if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (record.writes_rd) clocks[record.rd] = tick + 3;
        }
        return .{ .allocator = a, .temp = temp, .image = image, .tape = tape, .boundary = .{ .steps = @intCast(tape.len), .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    pub fn deinit(self: *Fixture) void {
        self.tape.deinit();
        self.image.deinit();
        self.temp.cleanup();
        self.* = undefined;
    }
};
