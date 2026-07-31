//! Pinned ROM-only live OAM-DMA gate.
//!
//! The official Mooneye ROM must both report its register signature and leave
//! all 160 OAM bytes equal to its immutable ROM source. A detached controller
//! and a one-byte OAM mutation are explicit negative controls.

const std = @import("std");
const runner = @import("runner/mod.zig");
const live_dma = @import("runner/live_dma.zig");

const ROM_PATH = "acceptance/oam_dma/basic.gb";
const ROM_SHA256 =
    "326b747cac8cc96b62d6ee508e73b87eda24bfe29553d3d32e719f3b6d76c97c";
const SOURCE_START: u16 = 0x1200;
const MAX_STEPS: usize = 1_000_000;
const LIVE_INSTRUCTIONS: usize = 103_142;
const LIVE_MCYCLES: usize = 183_761;
const DETACHED_INSTRUCTIONS: usize = 101_576;
const DETACHED_MCYCLES: usize = 180_798;
const P1: u16 = 0xff00;
const SERIAL_DATA: u16 = 0xff01;
const SERIAL_CONTROL: u16 = 0xff02;
const INTERRUPT_FLAGS: u16 = 0xff0f;
const SCY: u16 = 0xff42;
const SCX: u16 = 0xff43;
const BGP: u16 = 0xff47;
const OBP0: u16 = 0xff48;
const OBP1: u16 = 0xff49;
const WY: u16 = 0xff4a;
const WX: u16 = 0xff4b;
const INTERRUPT_ENABLE: u16 = 0xffff;

const Outcome = enum {
    pass,
    failure,
    timeout,
};

const RunConfig = struct {
    attach_dma: bool,
    mutate_oam: bool = false,
};

const RunResult = struct {
    outcome: Outcome,
    machine_steps: usize,
    instructions: usize,
    elapsed_mcycles: usize,
    cpu: runner.Cpu,
    exact_copy: bool,
    dma_clock: u32,
    dma_idle: bool,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: zig run src/frontends/sm83/mooneye_dma_gate.zig " ++
                "-O ReleaseFast -- /path/to/mts-20260714-0944-31510e1\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var directory = try std.fs.cwd().openDir(arguments[1], .{});
    defer directory.close();
    const rom = try loadPinnedRom(allocator, &directory);
    defer allocator.free(rom);

    const detached = try runRom(allocator, rom, .{ .attach_dma = false });
    if (detached.outcome != .failure or detached.exact_copy or
        detached.instructions != DETACHED_INSTRUCTIONS or
        detached.machine_steps != DETACHED_INSTRUCTIONS or
        detached.elapsed_mcycles != DETACHED_MCYCLES or
        detached.dma_clock != 0)
        return error.DetachedDmaControlFailed;

    const live = try runRom(allocator, rom, .{ .attach_dma = true });
    if (live.outcome != .pass or !live.exact_copy or
        !live.dma_idle or live.instructions != LIVE_INSTRUCTIONS or
        live.machine_steps != LIVE_INSTRUCTIONS or
        live.elapsed_mcycles != LIVE_MCYCLES or
        live.dma_clock != LIVE_MCYCLES)
        return error.MooneyeDmaFailure;

    const mutated = try runRom(allocator, rom, .{
        .attach_dma = true,
        .mutate_oam = true,
    });
    if (mutated.outcome != .pass or mutated.exact_copy or
        mutated.instructions != LIVE_INSTRUCTIONS or
        mutated.elapsed_mcycles != LIVE_MCYCLES)
        return error.DmaMutationControlFailed;

    std.debug.print(
        "SM83 Mooneye live DMA: pass {s} ({d} instructions, {d} M-cycles, " ++
            "{d} machine steps, dma_clock={d}); " ++
            "detached={s}/{d}/{d} mutation_rejected=1\n",
        .{
            ROM_PATH,
            live.instructions,
            live.elapsed_mcycles,
            live.machine_steps,
            live.dma_clock,
            @tagName(detached.outcome),
            detached.instructions,
            detached.elapsed_mcycles,
        },
    );
}

fn loadPinnedRom(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
) ![]u8 {
    var file = try directory.openFile(ROM_PATH, .{});
    defer file.close();
    if ((try file.stat()).size != runner.rom_only_memory.ROM_SIZE)
        return error.InvalidRomSize;
    const bytes = try allocator.alloc(u8, runner.rom_only_memory.ROM_SIZE);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.InvalidRomSize;

    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ROM_SHA256);
    if (!std.mem.eql(u8, &actual, &expected))
        return error.RomDigestMismatch;
    return bytes;
}

fn runRom(
    allocator: std.mem.Allocator,
    rom: []const u8,
    config: RunConfig,
) !RunResult {
    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    try memory.installRomOnly(rom);
    installDmgAbcBootIo(&memory);

    var ppu = dmgAbcBootPpu();
    try memory.attachPpu(&ppu);
    defer memory.detachPpu();

    var controller = try live_dma.Controller.init(.{
        .page = memory.read(runner.dma.DMA_ADDRESS),
    });
    if (config.attach_dma) try memory.attachDma(&controller);
    defer if (config.attach_dma) memory.detachDma();

    var timer = runner.timer.Timer{ .div_counter = 0xabcc };
    memory.attachTimer(&timer);
    defer memory.detachTimer();
    var cpu = dmgAbcBootCpu();
    var instructions: usize = 0;
    var elapsed_mcycles: usize = 0;

    for (0..MAX_STEPS) |step_index| {
        if (cpu.halted or cpu.stopped) return error.UnexpectedCpuSleep;
        const result = try runner.step(&cpu, &memory);
        elapsed_mcycles = std.math.add(
            usize,
            elapsed_mcycles,
            result.cycle_count,
        ) catch return error.CountOverflow;
        instructions += 1;
        if (result.decoded.raw_opcode != 0x40) continue;
        const outcome: ?Outcome = if (isPass(cpu))
            .pass
        else if (isFailure(cpu))
            .failure
        else
            null;
        if (outcome) |finished| {
            if (config.mutate_oam)
                memory.bytes[runner.dma.OAM_START] ^= 1;
            return .{
                .outcome = finished,
                .machine_steps = step_index + 1,
                .instructions = instructions,
                .elapsed_mcycles = elapsed_mcycles,
                .cpu = cpu,
                .exact_copy = hasExactCopy(&memory, rom),
                .dma_clock = controller.state.clock,
                .dma_idle = controller.state.phase == .idle,
            };
        }
    }
    return .{
        .outcome = .timeout,
        .machine_steps = MAX_STEPS,
        .instructions = instructions,
        .elapsed_mcycles = elapsed_mcycles,
        .cpu = cpu,
        .exact_copy = hasExactCopy(&memory, rom),
        .dma_clock = controller.state.clock,
        .dma_idle = controller.state.phase == .idle,
    };
}

fn hasExactCopy(memory: *runner.Memory, rom: []const u8) bool {
    const source = rom[SOURCE_START .. SOURCE_START + runner.dma.OAM_LENGTH];
    const destination = memory.bytes[runner.dma.OAM_START .. runner.dma.OAM_START + runner.dma.OAM_LENGTH];
    return std.mem.eql(u8, source, destination);
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
    memory.write(runner.dma.DMA_ADDRESS, 0xff);
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

test "live DMA pin and exact-copy predicate reject mutations" {
    var digest: [32]u8 = undefined;
    try std.testing.expectEqual(
        digest.len,
        (try std.fmt.hexToBytes(&digest, ROM_SHA256)).len,
    );
    try std.testing.expectEqualStrings(
        "acceptance/oam_dma/basic.gb",
        ROM_PATH,
    );

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var rom = [_]u8{0} ** runner.rom_only_memory.ROM_SIZE;
    for (0..runner.dma.OAM_LENGTH) |index|
        rom[SOURCE_START + index] = @intCast(index);
    try memory.installRomOnly(&rom);
    @memcpy(
        memory.bytes[runner.dma.OAM_START .. runner.dma.OAM_START + runner.dma.OAM_LENGTH],
        rom[SOURCE_START .. SOURCE_START + runner.dma.OAM_LENGTH],
    );
    try std.testing.expect(hasExactCopy(&memory, &rom));
    memory.bytes[runner.dma.OAM_START + 0x9f] ^= 1;
    try std.testing.expect(!hasExactCopy(&memory, &rom));
}

test {
    _ = @import("rom_only_dma_test.zig");
}
