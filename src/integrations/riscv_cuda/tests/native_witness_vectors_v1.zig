//! Independent CPU oracle inputs for the generated CUDA typed row writers.
//! This is a numerical parity fixture generator, not a proving path.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const trace = frontend.runner.trace;
const witness = @import("../native_witness_exports_v1.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const local_zero = frontend.air.x0_native_envelope;
const LocalWriter = @import("../native_local_zero_witness_exports_v1.zig");
const cases = [_][]const u8{
    "shift_logic",         "mem_ls",               "mul_div",     "alu_test",        "branch_fib",       "jal_jalr",
    "mulhu_only",          "memcpy_loop",          "bubble_sort", "sieve_primes",    "gcd_euclid",       "collatz",
    "xorshift_prng",       "fib_iter",             "fence",       "declared_region", "multi_shard_addi", "crypto/sha2_input",
    "crypto/keccak_input", "crypto/poseidon2_m31",
};

fn word(file: std.fs.File, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try file.writeAll(&bytes);
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 2 or args.len > 3) return error.ExpectedOutputFile;
    const pruned = args.len == 3 and std.mem.eql(u8, args[2], "local-zero-pruned");
    const use_local_zero = pruned or (args.len == 3 and std.mem.eql(u8, args[2], "local-zero"));
    if (args.len == 3 and !use_local_zero) return error.InvalidVectorMode;
    var rows: [trace.N_FAMILIES]std.ArrayList(trace.TraceRow) = @splat(.empty);
    defer for (&rows) |*family| family.deinit(a);
    var selectors = [_]bool{false} ** @typeInfo(frontend.runner.Opcode).@"enum".fields.len;
    for (cases) |name| {
        const path = try std.fmt.allocPrint(a, "vectors/riscv_elfs/{s}.elf", .{name});
        defer a.free(path);
        const elf = try std.fs.cwd().readFileAlloc(a, path, 8 << 20);
        defer a.free(elf);
        var result = try frontend.runner.run(a, elf, 200_000);
        defer result.deinit();
        for (result.execution_trace.rows.items) |row| {
            const family = try trace.proofOpcodeFamily(row.opcode);
            const target = &rows[@intFromEnum(family)];
            const selector = @intFromEnum(row.opcode);
            if (target.items.len < 1024 or !selectors[selector]) {
                try trace.validateFamilyRow(row, family);
                try target.append(a, row);
                selectors[selector] = true;
            }
        }
    }
    const file = try std.fs.cwd().createFile(args[1], .{ .exclusive = true });
    defer file.close();
    try file.writeAll(if (use_local_zero) "RVWZ1\x00\x00\x00" else "RVWN1\x00\x00\x00");
    try word(file, trace.N_FAMILIES);
    const plans_path = if (pruned) try std.fmt.allocPrint(a, "{s}.plans", .{args[1]}) else null;
    defer if (plans_path) |p| a.free(p);
    const plans_file: ?std.fs.File = if (plans_path) |p| try std.fs.cwd().createFile(p, .{ .exclusive = true }) else null;
    defer if (plans_file) |f| f.close();
    if (plans_file) |f| {
        try word(f, 0x58305031);
        try word(f, trace.N_FAMILIES);
        try word(f, @sizeOf(LocalWriter.Pruned.Recipe) / 4);
    }
    var total_rows: usize = 0;
    var total_words: usize = 0;
    inline for (comptime std.enums.values(trace.OpcodeFamily)) |family| {
        const selected = rows[@intFromEnum(family)].items;
        if (selected.len == 0) return error.MissingFamilyCoverage;
        // Force a non-empty zero padding tail, even for a power-of-two count.
        const padded = try std.math.ceilPowerOfTwo(usize, selected.len + 1);
        const width = if (use_local_zero) LocalWriter.Writer(family).column_count else witness.Writer(family).column_count;
        var old_program = if (use_local_zero) try frontend.air.extract.runtime_program.buildLookups(a, family) else null;
        defer if (old_program) |*program| program.deinit();
        const recipe = if (pruned) try LocalWriter.Pruned.Recipe.fromProgram(a, family, &old_program.?) else LocalWriter.Pruned.Recipe{};
        if (plans_file) |f| try f.writeAll(std.mem.asBytes(&recipe));
        const predecessors = if (old_program) |*program| try local_zero.predecessorColumns(family, program) else [_]u32{ 0, 0, 0 };
        const output = try a.alloc(u32, padded * width);
        defer a.free(output);
        @memset(output, 0);
        var columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
        for (0..width) |column|
            columns[column] = @as([*]M31, @ptrCast(output.ptr + padded * column))[0..padded];
        var clock = try std.time.Timer.start();
        for (selected, 0..) |row, index| {
            // Production Zig authority is the independent oracle for nvcc's
            // compilation of the C-backend lowering of that same authority.
            try trace.validateFamilyRow(row, family);
            const physical = if (use_local_zero) @import("stwo_core").utils.bitReverseIndex(
                @import("stwo_core").utils.cosetIndexToCircleDomainIndex(index, @intCast(std.math.log2_int(usize, padded))),
                @intCast(std.math.log2_int(usize, padded)),
            ) else index;
            trace.fillFamilyColumns(&columns, physical, row, family);
            if (use_local_zero) {
                var cells: [trace.MAX_FAMILY_COLUMNS]M31 = undefined;
                const old_width = witness.Writer(family).column_count;
                for (columns[0..old_width], cells[0..old_width]) |column, *cell| cell.* = column[physical];
                try local_zero.normalizePredecessors(family, cells[0..old_width], &old_program.?);
                try local_zero.fillHints(family, cells[0..old_width], cells[old_width..width]);
                for (columns[0..width], cells[0..width]) |column, cell| column[physical] = cell;
                if (pruned) {
                    var got: [trace.MAX_FAMILY_COLUMNS]u32 = undefined;
                    const encoded = witness.encode(row);
                    const status = LocalWriter.Writer(family).runPruned(&encoded, @ptrCast(&recipe), &got, 1, 0);
                    if (status != 0) return error.InvalidPrunedNativeWitness;
                    for (cells[0..width], got[0..width]) |want, value| if (want.v != value) return error.PrunedNativeWitnessMismatch;
                }
            }
        }
        const cpu_ns = clock.read();
        try word(file, @intFromEnum(family));
        try word(file, @intCast(selected.len));
        try word(file, @intCast(padded));
        try word(file, @intCast(width));
        try word(file, @truncate(cpu_ns));
        try word(file, @intCast(cpu_ns >> 32));
        // A boundary mutation is rejected exactly when the existing authority
        // rejects it. Do not invent stricter semantics for the CUDA exporter.
        var mutated = witness.encode(selected[0]);
        mutated[0] = 0;
        var scratch: [trace.MAX_FAMILY_COLUMNS]u32 = undefined;
        try word(file, if (pruned) LocalWriter.Writer(family).runPruned(&mutated, @ptrCast(&recipe), &scratch, 1, 0) else if (use_local_zero) LocalWriter.Writer(family).run(&mutated, &predecessors, &scratch, 1, 0) else witness.Writer(family).run(&mutated, &scratch, 1, 0));
        if (use_local_zero) for (predecessors) |column| try word(file, column);
        for (selected) |row| for (witness.encode(row)) |value| try word(file, value);
        for (output) |value| try word(file, value);
        total_rows += selected.len;
        total_words += output.len;
        std.debug.print("NATIVE_WITNESS_VECTOR family={s} active={d} padded={d} columns={d} cpu_ns={d}\n", .{ @tagName(family), selected.len, padded, width, cpu_ns });
    }
    std.debug.print("NATIVE_WITNESS_VECTORS families={d} selectors={d} rows={d} field_words={d}\n", .{ trace.N_FAMILIES, std.mem.count(bool, &selectors, &.{true}), total_rows, total_words });
}
