//! Writes a small real-I/O Ethereum-SHA job for exercising the actual block-v4
//! candidate, producer, and detached verifier commands. These files are a
//! local smoke fixture, not an independently trusted policy or proof receipt.
const std = @import("std");
const preflight = @import("prover/blake3_execution_preflight.zig");
const source = @import("prover/block_v4_cpu_runner_source.zig");
const custom0 = @import("isa/custom0.zig");
const test_elf = @import("runner/guest_precompile/test_elf.zig");

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();

    // This is the real-I/O/Keccak program used by the two-segment complete
    // receiver fixture. A single exact terminal segment exercises the CLI
    // lifecycle without requiring a second copy of the proof harness.
    const instructions = [_]u32{
        0x0010_00b7, // LUI x1,0x100: I/O base.
        0x2000_a103, // LW x2,0x200(x1): public input word.
        0x0020_a423, // SW x2,8(x1): output word.
        0x0040_0193, // ADDI x3,x0,4.
        0x0030_a223, // SW x3,4(x1): output length.
        0x3000_8293, // ADDI x5,x1,0x300: Keccak state.
        custom0.encodeKeccakf(5),
        0x0010_0193, // ADDI x3,x0,1.
        0x0030_a023, // SW x3,0(x1): halt flag.
        0x0000_006f,
    };
    var elf = test_elf.buildReleaseProgram(instructions.len, &instructions, 1024, .rv32im_zkvm_ethereum_sha_v1);
    const symbols = 640 + instructions.len * 4 + 1024;
    std.mem.writeInt(u32, elf[symbols + 8 * 16 + 4 ..][0..4], 0x0010_0200, .little);
    std.mem.writeInt(u32, elf[symbols + 9 * 16 + 4 ..][0..4], 0x0010_0204, .little);
    const input = [_]u8{ 0x2a, 0x17, 0x09, 0x01 };
    const planned = try preflight.runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, &elf, &input, &input, 1 << 22);
    const budget = std.math.cast(u32, planned.last.cycle) orelse return error.SmokeScheduleTooLong;
    if (budget == 0 or budget > 1 << 22 or planned.required_terminal_cycles > budget)
        return error.SmokeScheduleTooLong;
    const schedule = try std.fmt.allocPrint(a, "[{d}]", .{budget});

    try std.fs.cwd().makeDir(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try write(dir, "smoke.elf", &elf);
    try write(dir, "input.bin", &input);
    try write(dir, "oracle.bin", &input);
    try write(dir, "schedule.json", schedule);
    const schedule_sha = std.fmt.bytesToHex(source.sha256(schedule), .lower);
    const elf_sha = std.fmt.bytesToHex(source.sha256(&elf), .lower);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .scope = "smoke_fixture_only_no_proof_authority",
        .max_segment_cycles = budget,
        .segment_count = 1,
        .elf_sha256 = elf_sha[0..],
        .schedule_sha256 = schedule_sha[0..],
        .input_bytes = input.len,
    }, .{ .whitespace = .indent_2 });
    try write(dir, "fixture-report.json", report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}

fn write(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
