//! Fresh-process A/A admission attempt for C-013.
//!
//! Both labels run one byte-identical `multi_shard_addi` ELF through the same
//! ordinary RV32IM execution, proof, encoding, and independent verification
//! boundary. The child emits one line and never compares or retries attempts.

const std = @import("std");
const build_identity = @import("build_identity");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");
const attempt = @import("proof_attempt.zig");
const capture = @import("capture_protocol.zig");
const protocol = @import("calibration_protocol.zig");
const schedule = @import("capture_schedule.zig");

const process_usage = prover_engine.measurement.process_usage;
const empty_sha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Receipt children reserve stdout for one JSON record and stderr for actual
/// failures. Imported informational logs are deliberately suppressed.
pub const std_options: std.Options = .{ .log_level = .warn };

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
    const options = protocol.parseOptions(args) catch |failure| {
        try usage(std.fs.File.stderr().deprecatedWriter());
        if (failure == error.HelpRequested) return;
        return failure;
    };
    if (options.phase == .calibration) try validateScheduledAttempt(options);

    const executable_digest = try hashSelf();
    try requireDigest(
        options.expected_executable_sha256,
        executable_digest,
        error.ExecutableDigestMismatch,
    );
    const elf = try std.fs.cwd().readFileAlloc(
        allocator,
        options.elf_path,
        16 * 1024 * 1024,
    );
    defer allocator.free(elf);
    const elf_digest = digestBytes(elf);
    try requireDigest(
        options.expected_elf_sha256,
        elf_digest,
        error.ElfDigestMismatch,
    );
    const pcs_config = switch (options.security) {
        .functional => functional_config,
        .secure => frontend.prover_mod.SECURE_PCS_CONFIG,
    };

    const resources_before = try process_usage.sample();
    var metrics = try attempt.software(
        allocator,
        elf,
        &.{},
        options.max_steps orelse protocol.default_max_steps,
        pcs_config,
    );
    defer metrics.deinit(allocator);
    const resources_after = try process_usage.sample();
    const resources = try process_usage.difference(
        resources_before,
        resources_after,
    );
    if (options.phase == .calibration and !resources.available())
        return error.RequiredProcessUsageUnavailable;
    if (metrics.output.len != 0) return error.UnexpectedCalibrationOutput;

    const elf_hex = std.fmt.bytesToHex(elf_digest, .lower);
    const executable_hex = std.fmt.bytesToHex(executable_digest, .lower);
    const proof_hex = std.fmt.bytesToHex(metrics.proof_sha256, .lower);
    const report = protocol.Report{
        .schema = protocol.schema,
        .status = "verified",
        .label = @tagName(options.label),
        .security = @tagName(options.security),
        .phase = @tagName(options.phase),
        .workload = protocol.workload,
        .schedule_sha256 = if (options.phase == .calibration)
            capture.capture_schedule_sha256
        else
            null,
        .sample_index = options.sample_index,
        .max_steps = options.max_steps orelse protocol.default_max_steps,
        .input_bytes = 0,
        .output_bytes = 0,
        .input_sha256 = empty_sha256,
        .output_sha256 = empty_sha256,
        .elf_sha256 = &elf_hex,
        .executable_sha256 = &executable_hex,
        .proof_sha256 = &proof_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_tree = if (build_identity.implementation_tree_available)
            build_identity.implementation_tree
        else
            null,
        .implementation_dirty = build_identity.implementation_dirty,
        .dirty_content_sha256 = if (build_identity.dirty_content_sha256_available)
            build_identity.dirty_content_sha256
        else
            null,
        .pcs = .{
            .pow_bits = pcs_config.pow_bits,
            .log_blowup_factor = pcs_config.fri_config.log_blowup_factor,
            .queries = pcs_config.fri_config.n_queries,
            .fold_step = pcs_config.fri_config.fold_step,
        },
        .metrics = .{
            .execution_steps = metrics.execution_steps,
            .execution_ns = metrics.execution_ns,
            .proving_ns = metrics.proving_ns,
            .proof_encoding_ns = metrics.proof_encoding_ns,
            .verification_ns = metrics.verification_ns,
            .verified_request_ns = metrics.verified_request_ns,
            .proof_wire_bytes = metrics.proof_wire_bytes,
            .preprocessed_cells = metrics.preprocessed_cells,
            .main_cells = metrics.main_cells,
            .interaction_cells = metrics.interaction_cells,
        },
        .resources = .{
            .scope = capture.resource_scope,
            .source = @tagName(resources.source),
            .lifetime_peak_physical_footprint_bytes = resources.lifetime_peak_physical_footprint_bytes,
            .process_cpu_ns = resources.process_cpu_ns,
            .energy_nj = resources.energy_nj,
            .instructions = resources.instructions,
            .cycles = resources.cycles,
            .unavailable_reason = resources.unavailable_reason,
        },
    };
    try report.validate();
    try writeJsonLine(report);
}

fn validateScheduledAttempt(options: protocol.Options) !void {
    const expected = try schedule.calibrationAttemptAt(options.sample_index);
    const label: protocol.Label = switch (expected.arm) {
        .a => .a,
        .a_control => .a_control,
    };
    if (label != options.label) return error.CaptureScheduleAttemptMismatch;
}

fn requireDigest(
    expected: ?[32]u8,
    actual: [32]u8,
    failure: anyerror,
) !void {
    if (expected) |pinned| {
        if (!std.mem.eql(u8, &pinned, &actual)) return failure;
    }
}

fn digestBytes(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashSelf() ![32]u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fs.selfExePath(&path_buffer);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0)
        return error.InvalidExecutable;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var measured: u64 = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        measured = try std.math.add(u64, measured, count);
    }
    const after = try file.stat();
    if (measured != before.size or before.size != after.size or
        before.inode != after.inode or before.mtime != after.mtime)
    {
        return error.ExecutableChangedDuringMeasurement;
    }
    return hash.finalResult();
}

fn writeJsonLine(value: anytype) !void {
    var buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(value, .{}, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: riscv-c013-aa-proof-child --label a|a_control
        \\       --security functional|secure
        \\       --phase diagnostic|calibration --elf PATH
        \\       --sample-index N [--max-steps N]
        \\       [--schedule-sha256 HEX]
        \\       [--expected-elf-sha256 HEX]
        \\       [--expected-executable-sha256 HEX]
        \\
        \\Calibration attempts require secure PCS and all three digest pins.
        \\The child runs one label only and emits one independently verified
        \\report; it never retries or computes a performance verdict.
        \\
    );
}
