//! One-workload, proof-independent recursion-shape inspector.
//!
//! The executable runs the canonical guest, builds the production commitment
//! witness and statement, and stops before trace-column construction. Its
//! exclusive JSON output is shape evidence, never performance evidence.

const std = @import("std");
const atomic_file = @import("atomic_file");
const build_identity = @import("build_identity");
const product_identity = @import("product_identity");
const frontend = @import("stwo_riscv_frontend");
const profile_registry = @import("recursive_csp_profile_registry");
const shape_inspection = frontend.statement_shape_inspection;

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STEPS: usize = 10_000_000;

const Options = struct {
    elf_path: []const u8,
    input_path: []const u8,
    report_out: []const u8,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = parseOptions(arguments) catch |err| {
        try usage(std.fs.File.stderr().deprecatedWriter());
        return err;
    };

    const elf = try std.fs.cwd().readFileAlloc(
        allocator,
        options.elf_path,
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf);
    try frontend.runner.elf_loader.validateReleaseAbi(elf);
    const input = try std.fs.cwd().readFileAlloc(
        allocator,
        options.input_path,
        MAX_FILE_BYTES,
    );
    defer allocator.free(input);

    var run = try frontend.runner.runWithInput(
        allocator,
        elf,
        input,
        MAX_STEPS,
    );
    defer run.deinit();
    try frontend.prover_mod.admitRunForProving(&run);
    const output = try canonicalPublicOutputAlloc(allocator, &run);
    defer allocator.free(output);
    const output_hex = try allocator.alloc(u8, output.len * 2);
    defer allocator.free(output_hex);
    encodeHex(output_hex, output);

    var public = try frontend.diagnostics.public_values.derive(allocator, &run);
    defer public.deinit(allocator);
    const facts = try shape_inspection.inspect(
        allocator,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        public.data,
    );
    const selected_profile = try profile_registry.select(.{
        .component_count = facts.component_count,
        .infrastructure_count = facts.infrastructure_count,
        .preprocessed_column_count = facts.preprocessed_column_count,
        .main_column_count = facts.main_column_count,
        .interaction_column_count = facts.interaction_column_count,
        .maximum_column_log_degree = facts.maximum_column_log_degree,
    });

    const elf_hex = hexDigest(sha256(elf));
    const input_hex = hexDigest(sha256(input));
    const profile_hex = hexDigest(selected_profile.shapeSha256());
    const registry_hex = hexDigest(profile_registry.registrySha256());
    const report = .{
        .schema = "stwo.riscv.recursion-shape-inspection.v2",
        .schema_version = 2,
        .classification = "proof_independent_shape_evidence_not_performance_evidence",
        .source = .{
            .elf_path = options.elf_path,
            .elf_sha256 = &elf_hex,
            .input_path = options.input_path,
            .input_sha256 = &input_hex,
            .observed_output_hex = output_hex,
            .execution_cycles = run.step_count,
        },
        .producer = .{
            .name = "stwo-zig-riscv-recursion-shape-inspector",
            .optimization_mode = product_identity.optimize,
            .implementation_commit = build_identity.implementation_commit,
            .implementation_dirty = build_identity.implementation_dirty,
            .product_identity_sha256 = product_identity.identity_sha256,
        },
        .method = .{
            .statement_authority = "production_commitment_witness_and_statement_geometry",
            .proof_constructed = false,
            .trace_columns_constructed = false,
            .dimensions_inferred_from_cycles = false,
            .max_steps = MAX_STEPS,
        },
        .facts = facts,
        .profile_registry = .{
            .schema = "stwo.riscv.recursion-csp-profile-registry.v1",
            .schema_version = profile_registry.FORMAT_VERSION,
            .registry_sha256 = &registry_hex,
            .profile_count = profile_registry.ENTRIES.len,
            .canonical_case_count = profile_registry.CANONICAL_CASE_COUNT,
        },
        .selected_profile = .{
            .profile_id = selected_profile.name(),
            .profile_shape_sha256 = &profile_hex,
            .canonical_case_count = selected_profile.canonical_case_count,
            .implementation_status = @tagName(
                selected_profile.implementation_status,
            ),
            .outer_executable = selected_profile.outerExecutable(),
        },
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(encoded);
    try atomic_file.writeExclusive(allocator, options.report_out, encoded);
}

fn parseOptions(arguments: []const []const u8) !Options {
    var elf_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var report_out: ?[]const u8 = null;
    var index: usize = 1;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--help") or
            std.mem.eql(u8, argument, "-h"))
        {
            try usage(std.fs.File.stdout().deprecatedWriter());
            std.process.exit(0);
        } else if (std.mem.eql(u8, argument, "--elf")) {
            if (elf_path != null) return error.DuplicateArgument;
            elf_path = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--input")) {
            if (input_path != null) return error.DuplicateArgument;
            input_path = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--report-out")) {
            if (report_out != null) return error.DuplicateArgument;
            report_out = try next(arguments, &index);
        } else return error.UnknownArgument;
    }
    const result = Options{
        .elf_path = elf_path orelse return error.MissingElf,
        .input_path = input_path orelse return error.MissingInput,
        .report_out = report_out orelse return error.MissingReportOutput,
    };
    if (std.mem.eql(u8, result.elf_path, result.input_path) or
        std.mem.eql(u8, result.elf_path, result.report_out) or
        std.mem.eql(u8, result.input_path, result.report_out))
    {
        return error.PathCollision;
    }
    return result;
}

fn next(arguments: []const []const u8, index: *usize) ![]const u8 {
    if (index.* + 1 >= arguments.len) return error.MissingArgumentValue;
    index.* += 1;
    const value = arguments[index.*];
    if (value.len == 0) return error.MissingArgumentValue;
    return value;
}

fn canonicalPublicOutputAlloc(
    allocator: std.mem.Allocator,
    run: *const frontend.runner.RunResult,
) ![]u8 {
    if (run.output_words.len == 0 or
        run.output_words[0].addr != run.output_len_addr or
        run.output_words[0].value != run.output_len)
    {
        return error.InvalidPublicOutput;
    }
    const output_len: usize = @intCast(run.output_len);
    const expected_word_count = std.math.divCeil(
        usize,
        output_len,
        @sizeOf(u32),
    ) catch return error.InvalidPublicOutput;
    if (run.output_words.len != expected_word_count + 1)
        return error.InvalidPublicOutput;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    for (run.output_words[1..], 0..) |word, index| {
        if (word.addr != run.output_data_addr + index * @sizeOf(u32))
            return error.InvalidPublicOutput;
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, word.value, .little);
        const start = index * encoded.len;
        const count = @min(encoded.len, output.len - start);
        @memcpy(output[start..][0..count], encoded[0..count]);
        for (encoded[count..]) |padding| {
            if (padding != 0) return error.InvalidPublicOutput;
        }
    }
    return output;
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn hexDigest(digest: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

fn encodeHex(destination: []u8, source: []const u8) void {
    std.debug.assert(destination.len == source.len * 2);
    const digits = "0123456789abcdef";
    for (source, 0..) |byte, index| {
        destination[index * 2] = digits[byte >> 4];
        destination[index * 2 + 1] = digits[byte & 0x0f];
    }
}

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: stwo-zig-riscv-recursion-shape-inspector
        \\       --elf PATH --input PATH --report-out PATH
        \\
        \\Builds the exact production statement and emits fixed-profile shape
        \\admission facts. It does not construct trace columns or a proof.
        \\
    );
}
