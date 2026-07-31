//! Pinned live-PPU Mooneye gate over an immutable ROM-only address space.
//!
//! Pass/failure is accepted only at Mooneye's executed `LD B,B` breakpoint.
//! The detached control proves the selected ROM cannot pass through the old
//! constant-LY headless path.

const std = @import("std");
const runner = @import("runner/mod.zig");
const machine_runner = @import("runner/machine.zig");

const MAX_STEPS: usize = 5_000_000;
const DETACHED_CONTROL_STEPS: usize = 1_000_000;
const P1: u16 = 0xff00;
const SERIAL_DATA: u16 = 0xff01;
const SERIAL_CONTROL: u16 = 0xff02;
const INTERRUPT_FLAGS: u16 = 0xff0f;
const SCY: u16 = 0xff42;
const SCX: u16 = 0xff43;
const DMA: u16 = 0xff46;
const BGP: u16 = 0xff47;
const OBP0: u16 = 0xff48;
const OBP1: u16 = 0xff49;
const WY: u16 = 0xff4a;
const WX: u16 = 0xff4b;
const INTERRUPT_ENABLE: u16 = 0xffff;

const Rom = struct {
    name: []const u8,
    sha256: []const u8,
};

// Official mts-20260714-0944-31510e1 artifact from pinned source revision
// 31510e12eea6286d36eea060a6adde755e1067aa.
const roms = [_]Rom{
    .{
        .name = "acceptance/ppu/stat_lyc_onoff.gb",
        .sha256 = "29f04aaf6b26085bca1dccfab648fb44fbf57d4aa923bca75a30167e45d8670e",
    },
    .{
        .name = "acceptance/ppu/stat_irq_blocking.gb",
        .sha256 = "604436aeb6a37badd71be0fafa526307345f1de6af757193f11fc77e09a01fc7",
    },
};

const Outcome = enum {
    pass,
    failure,
    timeout,
};

const RunResult = struct {
    outcome: Outcome,
    machine_steps: usize,
    instructions: usize,
    elapsed_mcycles: usize,
    cpu: runner.Cpu,
    ppu_before: runner.ppu_mmio.State,
    ppu_after: runner.ppu_mmio.State,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: zig run src/frontends/sm83/mooneye_ppu_gate.zig " ++
                "-O ReleaseFast -- /path/to/mts-20260714-0944-31510e1\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var directory = try std.fs.cwd().openDir(arguments[1], .{});
    defer directory.close();
    var passed: usize = 0;
    var controls_rejected: usize = 0;
    var total_instructions: usize = 0;
    var total_mcycles: usize = 0;

    for (roms) |rom| {
        const bytes = try loadPinnedRom(allocator, &directory, rom);
        defer allocator.free(bytes);

        const control = try runRom(
            allocator,
            bytes,
            false,
            DETACHED_CONTROL_STEPS,
        );
        if (control.outcome != .timeout or
            !std.meta.eql(control.ppu_before, control.ppu_after))
            return error.DetachedPpuControlFailed;
        controls_rejected += 1;

        const result = try runRom(allocator, bytes, true, MAX_STEPS);
        if (result.instructions == 0 or result.elapsed_mcycles == 0)
            return error.EmptyExecution;
        if (std.meta.eql(result.ppu_before, result.ppu_after))
            return error.InactivePpu;
        if (result.outcome != .pass) {
            std.debug.print(
                "SM83 Mooneye live PPU: {s} {s} after {d} steps " ++
                    "(PC={x:0>4} BC={x:0>4} DE={x:0>4} HL={x:0>4})\n",
                .{
                    @tagName(result.outcome),
                    rom.name,
                    result.machine_steps,
                    result.cpu.pc,
                    result.cpu.bc(),
                    result.cpu.de(),
                    result.cpu.hl(),
                },
            );
            return error.MooneyePpuFailure;
        }
        passed += 1;
        total_instructions += result.instructions;
        total_mcycles += result.elapsed_mcycles;
        std.debug.print(
            "SM83 Mooneye live PPU: pass {s} ({d} instructions, " ++
                "{d} M-cycles, {d} machine steps)\n",
            .{
                rom.name,
                result.instructions,
                result.elapsed_mcycles,
                result.machine_steps,
            },
        );
    }

    if (passed != roms.len or controls_rejected != roms.len)
        return error.InvalidPositiveCount;
    std.debug.print(
        "SM83 Mooneye live PPU frontier: selected={d} pass={d} " ++
            "detached_controls_rejected={d} instructions={d} M-cycles={d}\n",
        .{
            roms.len,
            passed,
            controls_rejected,
            total_instructions,
            total_mcycles,
        },
    );
}

fn loadPinnedRom(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    rom: Rom,
) ![]u8 {
    var file = try directory.openFile(rom.name, .{});
    defer file.close();
    if ((try file.stat()).size != runner.rom_only_memory.ROM_SIZE)
        return error.InvalidRomSize;
    const bytes = try allocator.alloc(u8, runner.rom_only_memory.ROM_SIZE);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.InvalidRomSize;

    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, rom.sha256);
    if (!std.mem.eql(u8, &actual, &expected))
        return error.RomDigestMismatch;
    return bytes;
}

fn runRom(
    allocator: std.mem.Allocator,
    rom: []const u8,
    attach_ppu: bool,
    max_steps: usize,
) !RunResult {
    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    try memory.installRomOnly(rom);
    installDmgAbcBootIo(&memory);

    var ppu = dmgAbcBootPpu();
    const ppu_before = ppu;
    if (attach_ppu) try memory.attachPpu(&ppu);
    defer if (attach_ppu) memory.detachPpu();

    var machine = try machine_runner.Machine.restore(
        &memory,
        dmgAbcBootCpu(),
        .{ .div_counter = 0xabcc },
        false,
    );
    var instructions: usize = 0;
    var elapsed_mcycles: usize = 0;

    for (0..max_steps) |step_index| {
        const result = try machine.step();
        elapsed_mcycles = std.math.add(
            usize,
            elapsed_mcycles,
            result.m_cycles,
        ) catch return error.CountOverflow;
        const trace = result.instruction orelse continue;
        instructions += 1;
        if (trace.decoded.raw_opcode != 0x40) continue;
        const outcome: ?Outcome = if (isPass(machine.cpu))
            .pass
        else if (isFailure(machine.cpu))
            .failure
        else
            null;
        if (outcome) |finished| return .{
            .outcome = finished,
            .machine_steps = step_index + 1,
            .instructions = instructions,
            .elapsed_mcycles = elapsed_mcycles,
            .cpu = machine.cpu,
            .ppu_before = ppu_before,
            .ppu_after = ppu,
        };
    }
    return .{
        .outcome = .timeout,
        .machine_steps = max_steps,
        .instructions = instructions,
        .elapsed_mcycles = elapsed_mcycles,
        .cpu = machine.cpu,
        .ppu_before = ppu_before,
        .ppu_after = ppu,
    };
}

fn dmgAbcBootCpu() runner.Cpu {
    return .{
        .a = 0x01,
        .f = 0xb0,
        .b = 0x00,
        .c = 0x13,
        .d = 0x00,
        .e = 0xd8,
        .h = 0x01,
        .l = 0x4d,
        .sp = 0xfffe,
        .pc = 0x0100,
    };
}

fn dmgAbcBootPpu() runner.ppu_mmio.State {
    // Mooneye's DMG-ABC boot-HWIO oracle exposes LCDC=91, LY=0a, LYC=00,
    // and no enabled STAT source. The hidden edge lines follow from those
    // visible values. Dot zero is the explicit M-cycle-aligned checkpoint.
    return .{
        .timing = .{
            .lcd_enabled = true,
            .line = 10,
            .dot = 0,
            .lyc = 0,
        },
        .lcdc = 0x91,
        .interrupt_flags = 0xe1,
    };
}

fn installDmgAbcBootIo(memory: *runner.Memory) void {
    memory.write(P1, 0xcf);
    memory.write(SERIAL_DATA, 0x00);
    memory.write(SERIAL_CONTROL, 0x7e);
    memory.write(INTERRUPT_FLAGS, 0xe1);
    memory.write(SCY, 0x00);
    memory.write(SCX, 0x00);
    memory.write(DMA, 0xff);
    memory.write(BGP, 0xfc);
    memory.write(OBP0, 0xff);
    memory.write(OBP1, 0xff);
    memory.write(WY, 0x00);
    memory.write(WX, 0x00);
    memory.write(INTERRUPT_ENABLE, 0x00);
}

fn isPass(cpu: runner.Cpu) bool {
    return cpu.b == 3 and cpu.c == 5 and cpu.d == 8 and cpu.e == 13 and
        cpu.h == 21 and cpu.l == 34;
}

fn isFailure(cpu: runner.Cpu) bool {
    return cpu.b == 0x42 and cpu.c == 0x42 and cpu.d == 0x42 and
        cpu.e == 0x42 and cpu.h == 0x42 and cpu.l == 0x42;
}

test "live PPU manifest and checkpoint are exact" {
    try std.testing.expectEqual(@as(usize, 2), roms.len);
    try std.testing.expectEqualStrings(
        "acceptance/ppu/stat_lyc_onoff.gb",
        roms[0].name,
    );
    try std.testing.expectEqualStrings(
        "acceptance/ppu/stat_irq_blocking.gb",
        roms[1].name,
    );
    for (roms) |rom| {
        var digest: [32]u8 = undefined;
        try std.testing.expectEqual(
            digest.len,
            (try std.fmt.hexToBytes(&digest, rom.sha256)).len,
        );
    }
    try dmgAbcBootPpu().validate();
    try std.testing.expectEqual(@as(u8, 10), dmgAbcBootPpu().timing.readLy());
}

test "magic breakpoint signatures reject one-register mutations" {
    const pass = runner.Cpu{
        .b = 3,
        .c = 5,
        .d = 8,
        .e = 13,
        .h = 21,
        .l = 34,
    };
    try std.testing.expect(isPass(pass));
    var mutated = pass;
    mutated.l -%= 1;
    try std.testing.expect(!isPass(mutated));
    try std.testing.expect(isFailure(.{
        .b = 0x42,
        .c = 0x42,
        .d = 0x42,
        .e = 0x42,
        .h = 0x42,
        .l = 0x42,
    }));
}
