const std = @import("std");
const protocol = @import("capture_protocol.zig");

test "C-013 proof child options require pins outside diagnostics" {
    const zeros = "00" ** 32;
    const args = [_][]const u8{
        "child",             "--arm",                          "software",                "--security",                   "secure",
        "--phase",           "measured",                       "--shape",                 "poseidon2_dominant",           "--elf",
        "guest.elf",         "--calls",                        "8",                       "--sample-index",               "17",
        "--schedule-sha256", protocol.capture_schedule_sha256, "--expected-input-sha256", zeros,                          "--expected-output-sha256",
        zeros,               "--expected-elf-sha256",          zeros,                     "--expected-executable-sha256", zeros,
    };
    const parsed = try protocol.parseOptions(&args);
    try std.testing.expectEqual(protocol.Arm.software, parsed.arm);
    try std.testing.expectEqual(protocol.Security.secure, parsed.security);
    try std.testing.expectEqual(protocol.Phase.measured, parsed.phase);
    try std.testing.expectEqual(@as(usize, 17), parsed.sample_index);

    const missing_pin = [_][]const u8{
        "child",     "--arm",   "software", "--security",         "secure",
        "--phase",   "warmup",  "--shape",  "poseidon2_dominant", "--elf",
        "guest.elf", "--calls", "0",        "--sample-index",     "0",
    };
    try std.testing.expectError(
        error.MissingCaptureDigestPin,
        protocol.parseOptions(&missing_pin),
    );
}

test "C-013 workload shapes pin exact source-identical portable work" {
    const balanced = protocol.Options{
        .arm = .precompile,
        .security = .secure,
        .phase = .diagnostic,
        .shape = .balanced_core_and_poseidon2,
        .elf_path = "guest.elf",
        .calls = 1,
        .sample_index = 0,
        .max_steps = null,
        .expected_schedule_sha256 = null,
        .expected_input_sha256 = null,
        .expected_output_sha256 = null,
        .expected_elf_sha256 = null,
        .expected_executable_sha256 = null,
    };
    try balanced.validate();
    try std.testing.expectEqual(
        @as(usize, 15),
        protocol.Shape.core_only.backgroundPermutationsPerCall(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        protocol.Shape.balanced_core_and_poseidon2.backgroundPermutationsPerCall(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        protocol.Shape.poseidon2_dominant.backgroundPermutationsPerCall(),
    );
}

test "C-013 proof child rejects duplicate arm authority" {
    const args = [_][]const u8{
        "child",      "--arm",      "software",           "--arm",
        "precompile", "--security", "secure",             "--phase",
        "diagnostic", "--shape",    "poseidon2_dominant", "--elf",
        "guest.elf",  "--calls",    "1",                  "--sample-index",
        "0",
    };
    try std.testing.expectError(
        error.DuplicateArgument,
        protocol.parseOptions(&args),
    );
}

test "C-013 proof child rejects calibration and schedule drift" {
    const zeros = "00" ** 32;
    const calibration = protocol.Options{
        .arm = .software,
        .security = .secure,
        .phase = .calibration,
        .shape = .core_only,
        .elf_path = "guest.elf",
        .calls = 0,
        .sample_index = 0,
        .max_steps = null,
        .expected_schedule_sha256 = [_]u8{0} ** 32,
        .expected_input_sha256 = [_]u8{0} ** 32,
        .expected_output_sha256 = [_]u8{0} ** 32,
        .expected_elf_sha256 = [_]u8{0} ** 32,
        .expected_executable_sha256 = [_]u8{0} ** 32,
    };
    try std.testing.expectError(error.InvalidChildPhase, calibration.validate());
    const drifted = [_][]const u8{
        "child",             "--arm",                 "software",                "--security",                   "secure",
        "--phase",           "warmup",                "--shape",                 "core_only",                    "--elf",
        "guest.elf",         "--calls",               "0",                       "--sample-index",               "0",
        "--schedule-sha256", zeros,                   "--expected-input-sha256", zeros,                          "--expected-output-sha256",
        zeros,               "--expected-elf-sha256", zeros,                     "--expected-executable-sha256", zeros,
    };
    try std.testing.expectError(
        error.CaptureScheduleMismatch,
        protocol.parseOptions(&drifted),
    );
}

test "C-013 proof child report closes geometry identity and timing" {
    const digest = "00" ** 32;
    var report = protocol.Report{
        .schema = protocol.schema,
        .status = "verified",
        .arm = "precompile",
        .security = "secure",
        .phase = "measured",
        .shape = "poseidon2_dominant",
        .background_permutations_per_call = 0,
        .schedule_sha256 = protocol.capture_schedule_sha256,
        .calls = 1,
        .sample_index = 3,
        .max_steps = 200_000,
        .input_bytes = 68,
        .output_bytes = 64,
        .extension_calls = 1,
        .input_sha256 = digest,
        .output_sha256 = digest,
        .elf_sha256 = digest,
        .executable_sha256 = digest,
        .proof_sha256 = digest,
        .implementation_commit = "00" ** 20,
        .implementation_tree = "11" ** 20,
        .implementation_dirty = false,
        .dirty_content_sha256 = null,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .queries = 70,
            .fold_step = 1,
        },
        .metrics = .{
            .execution_steps = 77,
            .execution_ns = 3,
            .proving_ns = 5,
            .proof_encoding_ns = 2,
            .verification_ns = 7,
            .verified_request_ns = 15,
            .proof_wire_bytes = 1,
            .preprocessed_cells = 1,
            .main_cells = 1,
            .interaction_cells = 1,
        },
        .resources = .{
            .scope = protocol.resource_scope,
            .source = "unsupported",
            .lifetime_peak_physical_footprint_bytes = null,
            .process_cpu_ns = null,
            .energy_nj = null,
            .instructions = null,
            .cycles = null,
            .unavailable_reason = "fixture",
        },
    };
    try report.validate();
    report.metrics.verified_request_ns -= 1;
    try std.testing.expectError(error.InvalidReportTiming, report.validate());
    report.metrics.verified_request_ns += 1;
    report.output_bytes -= 1;
    try std.testing.expectError(error.InvalidReportGeometry, report.validate());
    report.output_bytes += 1;
    report.background_permutations_per_call = 1;
    try std.testing.expectError(error.InvalidReportGeometry, report.validate());
}
