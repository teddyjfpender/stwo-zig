const std = @import("std");
const capture = @import("capture_protocol.zig");
const protocol = @import("calibration_protocol.zig");

const zero_digest: [32]u8 = @splat(0);

test "C-013 A/A calibration requires secure pinned authority" {
    const diagnostic = protocol.Options{
        .label = .a,
        .security = .functional,
        .phase = .diagnostic,
        .elf_path = "multi_shard_addi.elf",
        .sample_index = 0,
        .max_steps = null,
        .expected_schedule_sha256 = null,
        .expected_elf_sha256 = null,
        .expected_executable_sha256 = null,
    };
    try diagnostic.validate();

    var insecure = diagnostic;
    insecure.phase = .calibration;
    insecure.expected_schedule_sha256 = try parseScheduleDigest();
    insecure.expected_elf_sha256 = zero_digest;
    insecure.expected_executable_sha256 = zero_digest;
    try std.testing.expectError(error.InsecureCalibration, insecure.validate());

    var missing = insecure;
    missing.security = .secure;
    missing.expected_elf_sha256 = null;
    try std.testing.expectError(
        error.MissingCaptureDigestPin,
        missing.validate(),
    );

    var admitted = insecure;
    admitted.security = .secure;
    try admitted.validate();
}

test "C-013 A/A options reject schedule drift and duplicate authority" {
    const args = [_][]const u8{
        "child",      "--label",        "a",       "--label",    "a_control",
        "--security", "functional",     "--phase", "diagnostic", "--elf",
        "guest.elf",  "--sample-index", "0",
    };
    try std.testing.expectError(
        error.DuplicateArgument,
        protocol.parseOptions(&args),
    );

    var drift = protocol.Options{
        .label = .a_control,
        .security = .secure,
        .phase = .calibration,
        .elf_path = "guest.elf",
        .sample_index = 79,
        .max_steps = protocol.default_max_steps,
        .expected_schedule_sha256 = zero_digest,
        .expected_elf_sha256 = zero_digest,
        .expected_executable_sha256 = zero_digest,
    };
    try std.testing.expectError(
        error.CaptureScheduleMismatch,
        drift.validate(),
    );
    drift.expected_schedule_sha256 = try parseScheduleDigest();
    try drift.validate();
}

fn parseScheduleDigest() ![32]u8 {
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, capture.capture_schedule_sha256);
    return result;
}
