const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const X = front.rv64_air.word16_execution;
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const symbols = @import("../../tests/rv64_word16_execution_fixture.zig").symbols;
pub const Mode = enum { honest, wrong_halt, wrong_length, wrong_output, early };
fn store(offset: u12, rs: u5, width: u3) u32 {
    return @as(u32, offset >> 5) << 25 | @as(u32, rs) << 20 | @as(u32, 1) << 15 | @as(u32, width) << 12 | @as(u32, offset & 31) << 7 | 0x23;
}
fn immediate(value: u12, rd: u5) u32 {
    return @as(u32, value) << 20 | @as(u32, rd) << 7 | 0x13;
}
pub const Fixture = struct {
    temp: std.testing.TmpDir,
    image: Image.Owner,
    tape: rv.compact_tape.Tape,
    boundary: X.types.Boundary,
    pub fn init(a: std.mem.Allocator, mode: Mode) !Fixture {
        const words = [_]u32{
            0x00c000b7, // LUI x1,0xc00: independently mapped ABI control region.
            immediate(if (mode == .wrong_halt) 2 else 1, 3),
            store(0, 3, 2),
            immediate(if (mode == .wrong_length) 42 else 43, 3),
            store(4, 3, 2),
            immediate(if (mode == .wrong_output) 1 else 0, 3),
            store(8, 3, 3),
            store(16, 0, 3),
            store(24, 0, 3),
            store(32, 0, 3),
            store(40, 0, 3),
            store(48, 0, 3),
            0x0000006f,
        };
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
        for (words, 0..) |word, j| std.mem.writeInt(u32, elf[120 + 4 * j ..][0..4], word, .little);
        var temp = std.testing.tmpDir(.{});
        errdefer temp.cleanup();
        try temp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
        try temp.dir.writeFile(.{ .sub_path = "input", .data = &.{0} });
        const ep = try temp.dir.realpathAlloc(a, "guest.elf");
        defer a.free(ep);
        const ip = try temp.dir.realpathAlloc(a, "input");
        defer a.free(ip);
        const eh = std.fmt.bytesToHex(Request.sha(&elf), .lower);
        const ih = std.fmt.bytesToHex(Request.sha(&.{0}), .lower);
        const pc = 4096 + 4 * (words.len - 1);
        const config = Request.Config{ .elf = ep, .input = ip, .elf_sha256 = &eh, .input_sha256 = &ih, .expected_output = "00" ** 43, .symbols = symbols, .output_directory = "unused", .terminal_pc = pc, .batch_steps = 32 };
        var image = try Image.Owner.init(a, config);
        errdefer image.deinit();
        var native = try rv.ethereum_contract.load(a, symbols, &elf, &.{0});
        defer native.deinit();
        var tape = try rv.compact_tape.Tape.init(a, 32, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        var cpu = rv.machine.Cpu.init(4096, symbols.stack_top);
        const initial = cpu.regs;
        var clocks: [32]u32 = @splat(0);
        while (cpu.pc != pc - @as(u64, if (mode == .early) 4 else 0)) {
            if (tape.len >= 32) return error.TerminalFixtureDidNotHalt;
            const record = try cpu.step(&native.memory);
            try tape.append(record);
            const tick = @as(u32, @intCast(4 * (tape.len - 1)));
            if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (record.writes_rd) clocks[record.rd] = tick + 3;
        }
        return .{ .temp = temp, .image = image, .tape = tape, .boundary = .{ .steps = @intCast(tape.len), .initial_pc = 4096, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = clocks } };
    }
    pub fn deinit(self: *Fixture) void {
        self.tape.deinit();
        self.image.deinit();
        self.temp.cleanup();
    }
};
