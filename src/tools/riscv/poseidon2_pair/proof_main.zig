//! One-shot verified CPU proof comparison for the exact C-013 guest pair.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const corpus = @import("corpus.zig");
const attempt = @import("proof_attempt.zig");

const Options = struct {
    software_elf: []const u8,
    precompile_elf: []const u8,
    calls: usize = 1,
    max_steps: ?usize = null,
    secure: bool = false,
};

const functional_config = core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = parseOptions(args) catch |failure| {
        try usage(std.fs.File.stderr().deprecatedWriter());
        return failure;
    };
    const software_elf = try readElf(allocator, options.software_elf);
    defer allocator.free(software_elf);
    const precompile_elf = try readElf(allocator, options.precompile_elf);
    defer allocator.free(precompile_elf);
    const input = try corpus.makeInput(allocator, options.calls);
    defer allocator.free(input);
    const max_steps = options.max_steps orelse try corpus.defaultMaxSteps(options.calls);
    const pcs_config = if (options.secure)
        frontend.prover_mod.SECURE_PCS_CONFIG
    else
        functional_config;

    var software = try attempt.software(
        allocator,
        software_elf,
        input,
        max_steps,
        pcs_config,
    );
    defer software.deinit(allocator);
    var precompile = try attempt.precompile(
        allocator,
        precompile_elf,
        input,
        max_steps,
        pcs_config,
    );
    defer precompile.deinit(allocator);
    if (!std.mem.eql(u8, software.output, precompile.output))
        return error.ProvedGuestOutputMismatch;

    var input_digest: [32]u8 = undefined;
    var output_digest: [32]u8 = undefined;
    var software_elf_digest: [32]u8 = undefined;
    var precompile_elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &input_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(software.output, &output_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(software_elf, &software_elf_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(precompile_elf, &precompile_elf_digest, .{});
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const output_hex = std.fmt.bytesToHex(output_digest, .lower);
    const software_elf_hex = std.fmt.bytesToHex(software_elf_digest, .lower);
    const precompile_elf_hex = std.fmt.bytesToHex(precompile_elf_digest, .lower);
    try std.fs.File.stdout().deprecatedWriter().print(
        \\{{"schema":"stwo.c013.poseidon2-cpu-proof-attempt.v1",
        \\"security":"{s}","calls":{d},"max_steps":{d},
        \\"pcs":{{"pow_bits":{d},"log_blowup_factor":{d},"queries":{d},"fold_step":{d}}},
        \\"input_sha256":"{s}","output_sha256":"{s}",
        \\"software_elf_sha256":"{s}","precompile_elf_sha256":"{s}",
        \\"software":{f},"precompile":{f}}}\n
    , .{
        if (options.secure) "secure" else "functional",
        options.calls,
        max_steps,
        pcs_config.pow_bits,
        pcs_config.fri_config.log_blowup_factor,
        pcs_config.fri_config.n_queries,
        pcs_config.fri_config.fold_step,
        &input_hex,
        &output_hex,
        &software_elf_hex,
        &precompile_elf_hex,
        ArmJson{ .metrics = software },
        ArmJson{ .metrics = precompile },
    });
}

const ArmJson = struct {
    metrics: attempt.Metrics,

    pub fn format(
        self: ArmJson,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const digest = std.fmt.bytesToHex(self.metrics.proof_sha256, .lower);
        try writer.print(
            \\{{"execution_steps":{d},"execution_ns":{d},"proving_ns":{d},
            \\"proof_encoding_ns":{d},"verification_ns":{d},
            \\"verified_request_ns":{d},"proof_wire_bytes":{d},
            \\"proof_sha256":"{s}","preprocessed_cells":{d},
            \\"main_cells":{d},"interaction_cells":{d}}}
        , .{
            self.metrics.execution_steps,
            self.metrics.execution_ns,
            self.metrics.proving_ns,
            self.metrics.proof_encoding_ns,
            self.metrics.verification_ns,
            self.metrics.verified_request_ns,
            self.metrics.proof_wire_bytes,
            &digest,
            self.metrics.preprocessed_cells,
            self.metrics.main_cells,
            self.metrics.interaction_cells,
        });
    }
};

fn parseOptions(args: []const []const u8) !Options {
    var result = Options{
        .software_elf = "",
        .precompile_elf = "",
    };
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--software-elf") and index + 1 < args.len) {
            index += 1;
            result.software_elf = args[index];
        } else if (std.mem.eql(u8, arg, "--precompile-elf") and index + 1 < args.len) {
            index += 1;
            result.precompile_elf = args[index];
        } else if (std.mem.eql(u8, arg, "--calls") and index + 1 < args.len) {
            index += 1;
            result.calls = try std.fmt.parseInt(usize, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--max-steps") and index + 1 < args.len) {
            index += 1;
            result.max_steps = try std.fmt.parseInt(usize, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--secure")) {
            result.secure = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try usage(std.fs.File.stdout().deprecatedWriter());
            std.process.exit(0);
        } else return error.InvalidArgument;
    }
    if (result.software_elf.len == 0) return error.MissingSoftwareElf;
    if (result.precompile_elf.len == 0) return error.MissingPrecompileElf;
    if (result.calls > corpus.maximum_calls) return error.CallCountOutOfRange;
    return result;
}

fn readElf(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024);
}

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: riscv-poseidon2-pair-proof --software-elf PATH
        \\       --precompile-elf PATH [--calls N] [--max-steps N] [--secure]
        \\
        \\Produces and independently verifies one CPU proof for each exact arm.
        \\The default functional PCS profile is development evidence only; secure
        \\mode is an opt-in correctness sample. Neither mode is a C-013 receipt.
        \\
    );
}
