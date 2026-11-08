//! Exact semantic preflight for the C-013 Poseidon2 guest pair.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const corpus = @import("corpus.zig");
const protocol = @import("capture_protocol.zig");

const runner = frontend.runner;
const lanes = corpus.lanes;

const Options = struct {
    software_elf: []const u8,
    precompile_elf: []const u8,
    shape: protocol.Shape = .poseidon2_dominant,
    call_count: usize = 8,
    max_steps: ?usize = null,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = parseOptions(args) catch |failure| {
        try writeUsage(std.fs.File.stderr().deprecatedWriter());
        return failure;
    };

    const software_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        options.software_elf,
        16 * 1024 * 1024,
    );
    defer allocator.free(software_elf);
    const precompile_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        options.precompile_elf,
        16 * 1024 * 1024,
    );
    defer allocator.free(precompile_elf);
    const input = try corpus.makeInput(allocator, options.call_count);
    defer allocator.free(input);
    const max_steps = options.max_steps orelse
        try corpus.defaultMaxStepsForBackground(
            options.call_count,
            options.shape.backgroundPermutationsPerCall(),
        );

    // Exact profile separation is part of admission, not a convention of the
    // benchmark launcher.
    try expectProfileRejections(
        allocator,
        software_elf,
        precompile_elf,
        input,
        max_steps,
    );

    var software = try runner.runWithInput(
        allocator,
        software_elf,
        input,
        max_steps,
    );
    defer software.deinit();
    var precompile = try runner.runPoseidon2ExtensionWithInput(
        allocator,
        precompile_elf,
        input,
        max_steps,
    );
    defer precompile.deinit();

    if (software.completion_reason != .halt_flag or
        precompile.base.completion_reason != .halt_flag)
    {
        return error.UnprovableGuestCompletion;
    }
    const expected_output_bytes = try std.math.mul(
        usize,
        options.call_count,
        lanes * @sizeOf(u32),
    );
    if (software.output_len != expected_output_bytes or
        precompile.base.output_len != expected_output_bytes)
    {
        return error.OutputLengthMismatch;
    }
    const software_output = software.output orelse return error.MissingSoftwareOutput;
    const precompile_output = precompile.base.output orelse
        return error.MissingPrecompileOutput;
    if (!std.mem.eql(u8, software_output, precompile_output)) {
        return error.GuestOutputMismatch;
    }
    try validateCallRecords(input, precompile_output, &precompile);

    var output_digest: [32]u8 = undefined;
    var input_digest: [32]u8 = undefined;
    var software_elf_digest: [32]u8 = undefined;
    var precompile_elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &input_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(software_output, &output_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(software_elf, &software_elf_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(precompile_elf, &precompile_elf_digest, .{});
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const output_hex = std.fmt.bytesToHex(output_digest, .lower);
    const software_elf_hex = std.fmt.bytesToHex(software_elf_digest, .lower);
    const precompile_elf_hex = std.fmt.bytesToHex(precompile_elf_digest, .lower);

    try std.fs.File.stdout().deprecatedWriter().print(
        \\{{"schema":"stwo.c013.poseidon2-pair-check.v2","shape":"{s}",
        \\"background_permutations_per_call":{d},"call_count":{d},
        \\"input_bytes":{d},"output_bytes":{d},"software_steps":{d},
        \\"precompile_steps":{d},"precompile_calls":{d},
        \\"input_sha256":"{s}","output_sha256":"{s}",
        \\"software_elf_sha256":"{s}","precompile_elf_sha256":"{s}"}}\n
    , .{
        @tagName(options.shape),
        options.shape.backgroundPermutationsPerCall(),
        options.call_count,
        input.len,
        software_output.len,
        software.step_count,
        precompile.base.step_count,
        precompile.calls.len(),
        &input_hex,
        &output_hex,
        &software_elf_hex,
        &precompile_elf_hex,
    });
}

fn parseOptions(args: []const []const u8) !Options {
    var software_elf: ?[]const u8 = null;
    var precompile_elf: ?[]const u8 = null;
    var shape: protocol.Shape = .poseidon2_dominant;
    var shape_seen = false;
    var call_count: usize = 8;
    var max_steps: ?usize = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or
            std.mem.eql(u8, argument, "-h"))
        {
            try writeUsage(std.fs.File.stdout().deprecatedWriter());
            std.process.exit(0);
        } else if (std.mem.eql(u8, argument, "--software-elf") and
            index + 1 < args.len)
        {
            index += 1;
            software_elf = args[index];
        } else if (std.mem.eql(u8, argument, "--precompile-elf") and
            index + 1 < args.len)
        {
            index += 1;
            precompile_elf = args[index];
        } else if (std.mem.eql(u8, argument, "--shape") and
            index + 1 < args.len)
        {
            if (shape_seen) return error.DuplicateArgument;
            index += 1;
            shape = std.meta.stringToEnum(protocol.Shape, args[index]) orelse
                return error.InvalidShape;
            shape_seen = true;
        } else if (std.mem.eql(u8, argument, "--calls") and
            index + 1 < args.len)
        {
            index += 1;
            call_count = try std.fmt.parseInt(usize, args[index], 10);
        } else if (std.mem.eql(u8, argument, "--max-steps") and
            index + 1 < args.len)
        {
            index += 1;
            max_steps = try std.fmt.parseInt(usize, args[index], 10);
        } else return error.InvalidArgument;
    }
    if (call_count > corpus.maximum_calls) return error.CallCountOutOfRange;
    return .{
        .software_elf = software_elf orelse return error.MissingSoftwareElf,
        .precompile_elf = precompile_elf orelse return error.MissingPrecompileElf,
        .shape = shape,
        .call_count = call_count,
        .max_steps = max_steps,
    };
}

fn writeUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: riscv-poseidon2-pair-check --software-elf PATH
        \\       --precompile-elf PATH
        \\       [--shape core_only|balanced_core_and_poseidon2|poseidon2_dominant]
        \\       [--calls N] [--max-steps N]
        \\
        \\Runs byte-identical deterministic inputs through the portable RV32IM
        \\and admitted CUSTOM-0 guests, checks exact outputs and call records,
        \\then emits one machine-readable identity record. This is a semantic
        \\preflight, not a proving-speed receipt.
        \\
    );
}

fn expectProfileRejections(
    allocator: std.mem.Allocator,
    software_elf: []const u8,
    precompile_elf: []const u8,
    input: []const u8,
    max_steps: usize,
) !void {
    if (runner.runWithInput(
        allocator,
        precompile_elf,
        input,
        max_steps,
    )) |unexpected| {
        var owned = unexpected;
        owned.deinit();
        return error.BaseRunnerAdmittedPrecompileElf;
    } else |failure| if (failure != error.RequiredCapabilityUnavailable) {
        return failure;
    }
    if (runner.runPoseidon2ExtensionWithInput(
        allocator,
        software_elf,
        input,
        max_steps,
    )) |unexpected| {
        var owned = unexpected;
        owned.deinit();
        return error.ExtensionRunnerAdmittedSoftwareElf;
    } else |failure| if (failure != error.MissingAdmissionNote) {
        return failure;
    }
}

fn validateCallRecords(
    input: []const u8,
    output: []const u8,
    run: *const runner.Poseidon2RunResult,
) !void {
    if (run.calls.len() != run.execution_rows.rows().len) {
        return error.ExtensionAuthorityLengthMismatch;
    }
    const call_count = std.mem.readInt(u32, input[0..4], .little);
    if (run.calls.len() != call_count) return error.ExtensionCallCountMismatch;
    for (run.calls.records(), 0..) |record, call| {
        for (0..lanes) |lane| {
            const word_index = call * lanes + lane;
            const input_value = std.mem.readInt(
                u32,
                input[4 * (word_index + 1) ..][0..4],
                .little,
            );
            const output_value = std.mem.readInt(
                u32,
                output[4 * word_index ..][0..4],
                .little,
            );
            if (record.input[lane] != input_value or
                record.output[lane] != output_value)
            {
                return error.ExtensionCallRecordMismatch;
            }
        }
        if (run.execution_rows.rows()[call].call_index != call) {
            return error.ExtensionExecutionOrderMismatch;
        }
    }
}
