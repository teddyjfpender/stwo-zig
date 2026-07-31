const std = @import("std");
const runner = @import("runner/mod.zig");
const machine_runner = @import("runner/machine.zig");

const ROM_SIZE: usize = 32 * 1024;
const MAX_STEPS: usize = 5_000_000;
const SERIAL_CONTROL: u16 = 0xff02;
const LY: u16 = 0xff44;

const Rom = struct {
    name: []const u8,
    sha256: []const u8,
};

// Official mts-20260714-0944-31510e1 release artifacts for the pinned
// 31510e12eea6286d36eea060a6adde755e1067aa source revision.
const roms = [_]Rom{
    .{
        .name = "acceptance/ei_sequence.gb",
        .sha256 = "dcd7f37e8fe7d8eb38cab6732a5826e0bb0278fd1e1d9e297c28d205da1b69e1",
    },
    .{
        .name = "acceptance/intr_timing.gb",
        .sha256 = "a795a190830104a4a231935d3bd16e64a1088bb79084f80bf7d9946ca93d873d",
    },
    .{
        .name = "acceptance/interrupts/ie_push.gb",
        .sha256 = "f80df1b48ca2f81d4ec43b9c66be5f0b30f0d409603d256cc5c7cfc6241c0120",
    },
    .{
        .name = "acceptance/halt_ime1_timing.gb",
        .sha256 = "09d9be4ebdd7645a6b208f18b1354f4b75420ae567dcf27ac404ed6f934d2efa",
    },
    .{
        .name = "acceptance/ei_timing.gb",
        .sha256 = "e5fa88f83727e79912f2c69b91b8e3c1351c0b50ac26203a60c7a6c21e825dbc",
    },
    .{
        .name = "acceptance/rapid_di_ei.gb",
        .sha256 = "4bcfbee2dcdca7895afff7947742ec942166aeb4899f07995863149ef360f7f0",
    },
    .{
        .name = "acceptance/reti_intr_timing.gb",
        .sha256 = "a98440bfb0e4f29ef762515e4b842e2777bc35445a30903ed86799cf18dc5c55",
    },
    .{
        .name = "acceptance/bits/mem_oam.gb",
        .sha256 = "eba5d165aaa55e7d4a1d1d910ea312a55c78157923c29fbbc34031709390f1de",
    },
    .{
        .name = "acceptance/bits/reg_f.gb",
        .sha256 = "4b193e887ee3ac82b38b796729e1503e9a78da3e1140f8bd5600d0884f2e2627",
    },
    .{
        .name = "acceptance/div_timing.gb",
        .sha256 = "382a9cd42a60ef0a3f03ef834d476a32907f1b3a42b40de5bd3d9705ae9a9734",
    },
    .{
        .name = "acceptance/instr/daa.gb",
        .sha256 = "1498d92d70592a07a2493ef764609916616f0b023b21408189e277201e6c14c1",
    },
    .{
        .name = "acceptance/pop_timing.gb",
        .sha256 = "4b658ab238b46319f24fa890faf9f337f03ce8769c05be6540742c9aaaf5773a",
    },
    .{
        .name = "acceptance/timer/tim00.gb",
        .sha256 = "2193036c1628efd9ba86e5729292ef716d6ff3178cfa2abb9797709cd40252e8",
    },
    .{
        .name = "acceptance/timer/div_write.gb",
        .sha256 = "2be1e4da6fa24b9123d2a8bae47dd0d6f5e97e1855186c0c0f49e6d213eebfff",
    },
    .{
        .name = "acceptance/timer/tima_reload.gb",
        .sha256 = "1ca70c725bd1e027b07d3058839bd140eccddd9f4ca41305c4f8ab3acaff8a98",
    },
    .{
        .name = "acceptance/timer/rapid_toggle.gb",
        .sha256 = "59fe311058895c39475f74bcffb7d4f29272edb74e75d2cfe860c1a9d033b68a",
    },
    .{
        .name = "acceptance/timer/tima_write_reloading.gb",
        .sha256 = "7d9a6d5ada792596621f8bfdf257112887b2dd01d98e0f91a253afd6e05d0540",
    },
    .{
        .name = "acceptance/timer/tma_write_reloading.gb",
        .sha256 = "e48ff98d4f363b92e92bdabe86253fcf63f648964e3a61e73d52aedcba3e5ab2",
    },
    .{
        .name = "acceptance/timer/tim00_div_trigger.gb",
        .sha256 = "5cafdf474dfa7507b0db596118ad7bc65a6d5d652ee4232263dd028e7f2462b7",
    },
    .{
        .name = "acceptance/timer/tim01.gb",
        .sha256 = "b6f5043eae7fd2b2c3dc098ff16f664c8eb5699523616d84274669cf90c17fe7",
    },
    .{
        .name = "acceptance/timer/tim01_div_trigger.gb",
        .sha256 = "73c1e2677a2a122a285aa052e232153b133873c68cbcbf1cf41aa3d0a1b80a96",
    },
    .{
        .name = "acceptance/timer/tim10.gb",
        .sha256 = "fe3b0b292341d5ff26c9db3f6c9f3ba8a3d6e8b63977c61767a457962bd1faed",
    },
    .{
        .name = "acceptance/timer/tim10_div_trigger.gb",
        .sha256 = "d83c7acf20a0315486ed77db4f873db40fff6099564f8e250df66274a304b1b9",
    },
    .{
        .name = "acceptance/timer/tim11.gb",
        .sha256 = "624fd3ad3ede2790095162cfa212e488825072a0ecc287ff0e88da6c5d7040f1",
    },
    .{
        .name = "acceptance/timer/tim11_div_trigger.gb",
        .sha256 = "3f60bc3d2ba63bd9209706332dd6d0ef59ad09ada8dede0caa9e2e5132ed102e",
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
    cpu: runner.Cpu,
};

const Selection = struct {
    directory: []const u8,
    rom_index: ?usize,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const selection = parseSelection(arguments) catch |err| {
        std.debug.print(
            "usage: zig run src/frontends/sm83/mooneye_gate.zig " ++
                "-O ReleaseFast -- /path/to/mts-20260714-0944-31510e1 " ++
                "[--rom acceptance/release-relative.gb]\n",
            .{},
        );
        return err;
    };

    var directory = std.fs.cwd().openDir(selection.directory, .{}) catch |err| {
        std.debug.print(
            "SM83 Mooneye gate: cannot open {s}: {s}\n",
            .{ selection.directory, @errorName(err) },
        );
        return err;
    };
    defer directory.close();

    const selected = if (selection.rom_index) |index|
        roms[index..][0..1]
    else
        roms[0..];
    const expected_selected: usize =
        if (selection.rom_index == null) roms.len else 1;
    if (selected.len == 0 or selected.len != expected_selected)
        return error.InvalidSelectionCount;

    for (selected) |rom| try validateDigest(&directory, rom);

    var passed: usize = 0;
    var failed: usize = 0;
    var timed_out: usize = 0;
    var execution_errors: usize = 0;
    var completed: usize = 0;
    var total_instructions: usize = 0;
    var total_machine_steps: usize = 0;
    for (selected) |rom| {
        const result = runRom(allocator, &directory, rom.name) catch |err| {
            execution_errors += 1;
            std.debug.print(
                "SM83 Mooneye: ERROR {s}: {s}\n",
                .{ rom.name, @errorName(err) },
            );
            continue;
        };
        if (result.instructions == 0 or result.machine_steps == 0) {
            execution_errors += 1;
            std.debug.print(
                "SM83 Mooneye: ERROR {s}: empty execution\n",
                .{rom.name},
            );
            continue;
        }
        completed += 1;
        total_instructions = std.math.add(
            usize,
            total_instructions,
            result.instructions,
        ) catch return error.CountOverflow;
        total_machine_steps = std.math.add(
            usize,
            total_machine_steps,
            result.machine_steps,
        ) catch return error.CountOverflow;
        switch (result.outcome) {
            .pass => passed += 1,
            .failure => failed += 1,
            .timeout => timed_out += 1,
        }
        std.debug.print(
            "SM83 Mooneye: {s} {s} ({d} instructions, {d} machine steps, " ++
                "PC={x:0>4} BC={x:0>4} DE={x:0>4} HL={x:0>4})\n",
            .{
                @tagName(result.outcome),
                rom.name,
                result.instructions,
                result.machine_steps,
                result.cpu.pc,
                result.cpu.bc(),
                result.cpu.de(),
                result.cpu.hl(),
            },
        );
    }
    std.debug.print(
        "SM83 Mooneye focused frontier: selected={d} completed={d} " ++
            "pass={d} failure={d} timeout={d} error={d} " ++
            "instructions={d} machine_steps={d}\n",
        .{
            selected.len,
            completed,
            passed,
            failed,
            timed_out,
            execution_errors,
            total_instructions,
            total_machine_steps,
        },
    );
    if (completed != selected.len or passed != selected.len or
        failed != 0 or timed_out != 0 or execution_errors != 0)
        return error.MooneyeFailure;
}

fn parseSelection(arguments: []const []const u8) !Selection {
    if (arguments.len == 2) return .{
        .directory = arguments[1],
        .rom_index = null,
    };
    if (arguments.len != 4 or
        !std.mem.eql(u8, arguments[2], "--rom"))
        return error.InvalidArguments;
    return .{
        .directory = arguments[1],
        .rom_index = findRom(arguments[3]) orelse
            return error.UnpinnedRomSelection,
    };
}

fn findRom(name: []const u8) ?usize {
    for (roms, 0..) |rom, index|
        if (std.mem.eql(u8, rom.name, name)) return index;
    return null;
}

fn validateDigest(directory: *std.fs.Dir, rom: Rom) !void {
    var file = try directory.openFile(rom.name, .{});
    defer file.close();
    if ((try file.stat()).size != ROM_SIZE) return error.InvalidRomSize;
    var bytes: [ROM_SIZE]u8 = undefined;
    if (try file.readAll(&bytes) != bytes.len) return error.InvalidRomSize;
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, rom.sha256);
    if (!std.mem.eql(u8, &actual, &expected)) {
        std.debug.print(
            "SM83 Mooneye: {s} digest mismatch: expected {s}, got {x}\n",
            .{ rom.name, rom.sha256, actual },
        );
        return error.RomDigestMismatch;
    }
}

fn runRom(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    name: []const u8,
) !RunResult {
    var file = try directory.openFile(name, .{});
    defer file.close();
    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    if (try file.readAll(memory.bytes[0..ROM_SIZE]) != ROM_SIZE)
        return error.TruncatedRom;

    // Mooneye's documented headless fast path treats LY and SC reads of 0xff
    // as missing PPU/serial hardware and reports at the first magic breakpoint.
    memory.write(LY, 0xff);
    memory.write(SERIAL_CONTROL, 0xff);
    var machine = machine_runner.Machine.init(&memory, .{
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
    });
    var instructions: usize = 0;

    for (0..MAX_STEPS) |step_index| {
        const result = try machine.step();
        const trace = result.instruction orelse continue;
        instructions += 1;
        if (trace.decoded.raw_opcode != 0x40) continue;
        if (isPass(machine.cpu)) {
            return .{
                .outcome = .pass,
                .machine_steps = step_index + 1,
                .instructions = instructions,
                .cpu = machine.cpu,
            };
        }
        if (isFailure(machine.cpu)) {
            return .{
                .outcome = .failure,
                .machine_steps = step_index + 1,
                .instructions = instructions,
                .cpu = machine.cpu,
            };
        }
    }
    return .{
        .outcome = .timeout,
        .machine_steps = MAX_STEPS,
        .instructions = instructions,
        .cpu = machine.cpu,
    };
}

fn isPass(cpu: runner.Cpu) bool {
    return cpu.b == 3 and cpu.c == 5 and cpu.d == 8 and cpu.e == 13 and
        cpu.h == 21 and cpu.l == 34;
}

fn isFailure(cpu: runner.Cpu) bool {
    return cpu.b == 0x42 and cpu.c == 0x42 and cpu.d == 0x42 and
        cpu.e == 0x42 and cpu.h == 0x42 and cpu.l == 0x42;
}

test "Mooneye magic breakpoint signatures are exact" {
    try std.testing.expect(isPass(.{
        .b = 3,
        .c = 5,
        .d = 8,
        .e = 13,
        .h = 21,
        .l = 34,
    }));
    try std.testing.expect(!isPass(.{
        .b = 3,
        .c = 5,
        .d = 8,
        .e = 13,
        .h = 21,
        .l = 33,
    }));
    try std.testing.expect(isFailure(.{
        .b = 0x42,
        .c = 0x42,
        .d = 0x42,
        .e = 0x42,
        .h = 0x42,
        .l = 0x42,
    }));
}

test "Mooneye focused manifest is exact unique and parseable" {
    try std.testing.expectEqual(@as(usize, 25), roms.len);
    for (roms, 0..) |rom, index| {
        try std.testing.expect(std.mem.startsWith(
            u8,
            rom.name,
            "acceptance/",
        ));
        try std.testing.expect(std.mem.endsWith(u8, rom.name, ".gb"));
        var digest: [32]u8 = undefined;
        const parsed = try std.fmt.hexToBytes(&digest, rom.sha256);
        try std.testing.expectEqual(@as(usize, digest.len), parsed.len);
        for (roms[0..index]) |previous|
            try std.testing.expect(!std.mem.eql(u8, rom.name, previous.name));
    }
}

test "Mooneye selector accepts only exact pinned release paths" {
    const full = try parseSelection(&.{ "gate", "release" });
    try std.testing.expectEqualStrings("release", full.directory);
    try std.testing.expectEqual(@as(?usize, null), full.rom_index);

    const selected = try parseSelection(&.{
        "gate",
        "release",
        "--rom",
        "acceptance/ei_timing.gb",
    });
    try std.testing.expectEqualStrings("release", selected.directory);
    try std.testing.expectEqual(
        findRom("acceptance/ei_timing.gb"),
        selected.rom_index,
    );
    try std.testing.expect(selected.rom_index != null);

    try std.testing.expectError(
        error.UnpinnedRomSelection,
        parseSelection(&.{
            "gate",
            "release",
            "--rom",
            "acceptance/not-pinned.gb",
        }),
    );
    try std.testing.expectError(
        error.UnpinnedRomSelection,
        parseSelection(&.{
            "gate",
            "release",
            "--rom",
            "../acceptance/ei_timing.gb",
        }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseSelection(&.{
            "gate",
            "release",
            "--unknown",
            "acceptance/ei_timing.gb",
        }),
    );
}
