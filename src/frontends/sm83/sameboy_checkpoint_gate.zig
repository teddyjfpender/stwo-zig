const std = @import("std");
const sameboy = @import("checkpoint/sameboy.zig");
const cartridge = @import("cartridge/mod.zig");

const Case = struct {
    checkpoint: []const u8,
    checkpoint_sha256: []const u8,
    rom: []const u8,
    rom_sha256: []const u8,
};

const cases = [_]Case{.{
    .checkpoint = "build/traces/battle-seed-1/boundary-000000.s1",
    .checkpoint_sha256 = "c4d99e64d7a08e1828af6bdc0d9e5f930bd7315f137eb1f8d518cd5a9c9f31ea",
    .rom = "pokered_rogue_e2e.gbc",
    .rom_sha256 = "ebc21f5a683278aeb690a4cbad9576e33ee42fbe271d44e103047576d4108327",
}};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: zig build test-sameboy-checkpoint --build-file " ++
                "src/frontends/sm83/build.zig -Doptimize=ReleaseFast -- " ++
                "/path/to/PE-AGI/v1\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var directory = std.fs.cwd().openDir(arguments[1], .{}) catch |err| {
        std.debug.print(
            "SM83 SameBoy checkpoint gate: missing pinned corpus root {s}: " ++
                "{s}\n",
            .{ arguments[1], @errorName(err) },
        );
        return error.MissingPinnedCheckpointCorpus;
    };
    defer directory.close();

    var completed: usize = 0;
    var passed: usize = 0;
    var failures: usize = 0;
    for (cases) |case| {
        runCase(allocator, &directory, case) catch |err| {
            failures += 1;
            std.debug.print(
                "SM83 SameBoy checkpoint: FAILURE {s}: {s}\n",
                .{ case.checkpoint, @errorName(err) },
            );
            continue;
        };
        completed += 1;
        passed += 1;
        std.debug.print(
            "SM83 SameBoy checkpoint: PASS {s} + {s}\n",
            .{ case.checkpoint, case.rom },
        );
    }
    std.debug.print(
        "SM83 SameBoy checkpoint frontier: selected={d} completed={d} " ++
            "pass={d} failure={d} error=0\n",
        .{ cases.len, completed, passed, failures },
    );
    if (cases.len != 1 or completed != 1 or passed != 1 or failures != 0)
        return error.InvalidPositiveCount;
}

fn runCase(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    case: Case,
) !void {
    const rom = directory.readFileAlloc(
        allocator,
        case.rom,
        cartridge.header.ROM_SIZE,
    ) catch |err| {
        std.debug.print(
            "SM83 SameBoy checkpoint gate: missing pinned ROM {s}: {s}\n",
            .{ case.rom, @errorName(err) },
        );
        return error.MissingPinnedCheckpointCorpus;
    };
    defer allocator.free(rom);
    if (rom.len != cartridge.header.ROM_SIZE)
        return error.InvalidRomSize;
    try validateDigest(rom, case.rom_sha256);

    const checkpoint_bytes = directory.readFileAlloc(
        allocator,
        case.checkpoint,
        sameboy.CHECKPOINT_SIZE,
    ) catch |err| {
        std.debug.print(
            "SM83 SameBoy checkpoint gate: missing pinned checkpoint {s}: " ++
                "{s}\n",
            .{ case.checkpoint, @errorName(err) },
        );
        return error.MissingPinnedCheckpointCorpus;
    };
    defer allocator.free(checkpoint_bytes);
    if (checkpoint_bytes.len != sameboy.CHECKPOINT_SIZE)
        return error.InvalidCheckpointSize;
    try validateDigest(checkpoint_bytes, case.checkpoint_sha256);

    var checkpoint = try sameboy.import(allocator, checkpoint_bytes, rom);
    defer checkpoint.deinit();
    if (checkpoint.cpu.pc != 0x4e7e or
        checkpoint.cpu.sp != 0xdfff or
        checkpoint.cpu.af() != 0x0820 or
        checkpoint.interrupt_enable != checkpoint.system[0xffff] or
        checkpoint.interrupt_flags != checkpoint.system[0xff0f] or
        checkpoint.mapper.rom_bank_register != 1 or
        !checkpoint.mapper.ram_enabled)
    {
        return error.PinnedStateMismatch;
    }

    const timer = try checkpoint.toTimer();
    const joypad = try checkpoint.toJoypad(0);
    const ppu = try checkpoint.toPpuMmio();
    const dma = try checkpoint.toDma(0);
    if (timer.div_counter != 0x8f20 or
        timer.readDiv() != checkpoint.system[0xff04] or
        joypad.readP1() != 0xff or
        ppu.timing.line != 8 or
        ppu.timing.dot != 228 or
        ppu.timing.mode() != .transfer or
        dma.phase != .idle or
        dma.page != 0xc3)
    {
        return error.PinnedProjectionMismatch;
    }
}

fn validateDigest(bytes: []const u8, expected_hex: []const u8) !void {
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    if (!std.mem.eql(u8, &actual, &expected))
        return error.ContentDigestMismatch;
}

test "checkpoint gate pins one positive ROM and state pair" {
    try std.testing.expectEqual(@as(usize, 1), cases.len);
    try std.testing.expectEqual(@as(usize, 64), cases[0].checkpoint_sha256.len);
    try std.testing.expectEqual(@as(usize, 64), cases[0].rom_sha256.len);
    try std.testing.expect(std.mem.endsWith(
        u8,
        cases[0].checkpoint,
        "boundary-000000.s1",
    ));
}
