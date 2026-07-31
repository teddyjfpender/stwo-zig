const std = @import("std");
const runner = @import("runner/mod.zig");
const machine_runner = @import("runner/machine.zig");

const ROM_SIZE: usize = 32 * 1024;
const MAX_STEPS: usize = 50_000_000;
const SERIAL_CAPACITY: usize = 4096;
const SERIAL_DATA: u16 = 0xff01;
const SERIAL_CONTROL: u16 = 0xff02;

const Rom = struct {
    name: []const u8,
    sha256: []const u8,
};

const roms = [_]Rom{
    .{ .name = "01-special.gb", .sha256 = "fe61349cbaee10cc384b50f356e541c90d1bc380185716706b5d8c465a03cf89" },
    .{ .name = "02-interrupts.gb", .sha256 = "fb90b0d2b9501910c49709abda1d8e70f757dc12020ebf8409a7779bbfd12229" },
    .{ .name = "03-op sp,hl.gb", .sha256 = "ca553e606d9b9c86fbd318f1b916c6f0b9df0cf1774825d4361a3fdff2e5a136" },
    .{ .name = "04-op r,imm.gb", .sha256 = "7686aa7a39ef3d2520ec1037371b5f94dc283fbbfd0f5051d1f64d987bdd6671" },
    .{ .name = "05-op rp.gb", .sha256 = "d504adfa0a4c4793436a154f14492f044d38b3c6db9efc44138f3c9ad138b775" },
    .{ .name = "06-ld r,r.gb", .sha256 = "17ada54b0b9c1a33cd5429fce5b765e42392189ca36da96312222ffe309e7ed1" },
    .{ .name = "07-jr,jp,call,ret,rst.gb", .sha256 = "ab31d3daaaa3a98bdbd9395b64f48c1bdaa889aba5b19dd5aaff4ec2a7d228a3" },
    .{ .name = "08-misc instrs.gb", .sha256 = "974a71fe4c67f70f5cc6e98d4dc8c096057ff8a028b7bfa9f7a4330038cf8b7e" },
    .{ .name = "09-op r,r.gb", .sha256 = "b28e1be5cd95f22bd1ecacdd33c6f03e607d68870e31a47b15a0229033d5ba2a" },
    .{ .name = "10-bit ops.gb", .sha256 = "7f5b8e488c6988b5aaba8c2a74529b7c180c55a58449d5ee89d606a07c53514a" },
    .{ .name = "11-op a,(hl).gb", .sha256 = "0ec0cf9fda3f00becaefa476df6fb526c434abd9d4a4beac237c2c2692dac5d3" },
};

const RunResult = struct {
    machine_steps: usize,
    instructions: usize,
    serial_bytes: usize,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: zig build test-blargg-flat --build-file " ++
                "src/frontends/sm83/build.zig -Doptimize=ReleaseFast -- " ++
                "/path/to/gb-test-roms/cpu_instrs/individual\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var directory = std.fs.cwd().openDir(
        arguments[1],
        .{ .iterate = true },
    ) catch |err| {
        std.debug.print(
            "SM83 Blargg flat gate: cannot open {s}: {s}\n",
            .{ arguments[1], @errorName(err) },
        );
        return err;
    };
    defer directory.close();
    try validateRomSet(&directory);
    for (roms) |rom| try validateDigest(&directory, rom);

    var passed: usize = 0;
    for (roms) |rom| {
        const result = try runRom(allocator, &directory, rom.name);
        passed += 1;
        std.debug.print(
            "SM83 Blargg flat: PASS {s} ({d} instructions, {d} machine " ++
                "steps, {d} serial bytes)\n",
            .{
                rom.name,
                result.instructions,
                result.machine_steps,
                result.serial_bytes,
            },
        );
    }
    if (passed != roms.len) {
        std.debug.print(
            "SM83 Blargg flat gate: expected {d}/{d} positive results, " ++
                "got {d}/{d}\n",
            .{ roms.len, roms.len, passed, roms.len },
        );
        return error.InvalidPositiveCount;
    }
    std.debug.print(
        "SM83 Blargg flat: PASS ({d}/{d})\n",
        .{ passed, roms.len },
    );
}

fn validateRomSet(directory: *std.fs.Dir) !void {
    var iterator = directory.iterate();
    var found: usize = 0;
    while (try iterator.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".gb"))
            continue;
        if (!isRequiredRom(entry.name)) {
            std.debug.print(
                "SM83 Blargg flat gate: unexpected ROM {s}; pass the exact " ++
                    "cpu_instrs/individual directory\n",
                .{entry.name},
            );
            return error.UnexpectedRom;
        }
        found += 1;
    }
    if (found != roms.len) {
        std.debug.print(
            "SM83 Blargg flat gate: expected the exact {d}-ROM individual " ++
                "suite; found {d}\n",
            .{ roms.len, found },
        );
        return error.InvalidRomSet;
    }
}

fn isRequiredRom(name: []const u8) bool {
    for (roms) |required|
        if (std.mem.eql(u8, name, required.name)) return true;
    return false;
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
            "SM83 Blargg flat gate: {s} content hash mismatch: expected " ++
                "{s}, got {x}\n",
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
    var file = directory.openFile(name, .{}) catch |err| {
        std.debug.print(
            "SM83 Blargg flat gate: missing {s}: {s}\n",
            .{ name, @errorName(err) },
        );
        return err;
    };
    defer file.close();
    const stat = try file.stat();
    if (stat.size != ROM_SIZE) {
        std.debug.print(
            "SM83 Blargg flat gate: {s} must be exactly {d} bytes, got {d}\n",
            .{ name, ROM_SIZE, stat.size },
        );
        return error.InvalidRomSize;
    }

    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    const read = try file.readAll(memory.bytes[0..ROM_SIZE]);
    if (read != ROM_SIZE) return error.TruncatedRom;
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
    var serial: [SERIAL_CAPACITY]u8 = undefined;
    var serial_len: usize = 0;
    var instructions: usize = 0;

    for (0..MAX_STEPS) |step_index| {
        const result = machine.step() catch |err| {
            std.debug.print(
                "SM83 Blargg flat gate: {s} machine failed: {s}\n",
                .{ name, @errorName(err) },
            );
            printState(name, step_index, machine.cpu, serial[0..serial_len]);
            return err;
        };
        const trace = result.instruction orelse continue;
        instructions += 1;
        for (trace.activeCycles()) |cycle| {
            if (cycle.action != .write or
                cycle.address != SERIAL_CONTROL or
                cycle.value != 0x81)
            {
                continue;
            }
            if (serial_len == serial.len) {
                std.debug.print("SM83 Blargg flat gate: serial overflow\n", .{});
                printState(name, step_index + 1, machine.cpu, &serial);
                return error.SerialOutputOverflow;
            }
            serial[serial_len] = memory.read(SERIAL_DATA);
            serial_len += 1;
            const output = serial[0..serial_len];
            if (std.mem.indexOf(u8, output, "Failed") != null) {
                std.debug.print("SM83 Blargg flat gate: reported Failed\n", .{});
                printState(name, step_index + 1, machine.cpu, output);
                return error.BlarggFailure;
            }
            if (std.mem.indexOf(u8, output, "Passed") != null)
                return .{
                    .machine_steps = step_index + 1,
                    .instructions = instructions,
                    .serial_bytes = serial_len,
                };
        }
    }
    std.debug.print(
        "SM83 Blargg flat gate: did not report Passed within {d} machine steps\n",
        .{MAX_STEPS},
    );
    printState(name, MAX_STEPS, machine.cpu, serial[0..serial_len]);
    return error.StepLimitExceeded;
}

fn printState(
    name: []const u8,
    machine_steps: usize,
    cpu: runner.Cpu,
    serial: []const u8,
) void {
    std.debug.print(
        "SM83 Blargg flat gate: {s} after {d} machine steps: PC={x:0>4} " ++
            "SP={x:0>4} A={x:0>2} F={x:0>2} BC={x:0>4} DE={x:0>4} " ++
            "HL={x:0>4} IME={any} pending={any} halted={any} stopped={any}\n" ++
            "serial output:\n{s}\n",
        .{
            name,
            machine_steps,
            cpu.pc,
            cpu.sp,
            cpu.a,
            cpu.f,
            cpu.bc(),
            cpu.de(),
            cpu.hl(),
            cpu.ime,
            cpu.ime_enable_pending,
            cpu.halted,
            cpu.stopped,
            serial,
        },
    );
}
