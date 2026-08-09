//! Structural pins for the profiled verified-request boundary.
//!
//! A mock engine cannot prove where production I/O, verification, snapshots,
//! and artifact publication sit around a real monotonic timer. These checks
//! therefore bind the production adapter itself, following the same pattern as
//! `staged_pcs_profile_test.zig`.

const std = @import("std");

const ADAPTER_SOURCE = @embedFile("../proof_adapter.zig");

fn between(start_token: []const u8, end_token: []const u8) ![]const u8 {
    const start = std.mem.indexOf(u8, ADAPTER_SOURCE, start_token) orelse
        return error.StartTokenMissing;
    const tail = ADAPTER_SOURCE[start..];
    const end = std.mem.indexOf(u8, tail, end_token) orelse
        return error.EndTokenMissing;
    return tail[0..end];
}

fn expectOrdered(source: []const u8, tokens: []const []const u8) !void {
    var cursor: usize = 0;
    for (tokens) |token| {
        const relative = std.mem.indexOf(u8, source[cursor..], token) orelse {
            std.debug.print("missing ordered adapter token: {s}\n", .{token});
            return error.AdapterBoundaryTokenMissing;
        };
        cursor += relative + token.len;
    }
}

test "profiled phase clocks partition guest proof and native verification" {
    const run_prove = try between("fn runProve(", "\nfn runBenchmark(");
    try expectOrdered(run_prove, &.{
        "Sha256.hash(input_bytes",
        "Recorder.initWithOptions(",
        "var profile_phase_timer: ?std.time.Timer",
        "runner.runWithInput",
        "const guest_execution_ns: ?u64",
        "proveRiscVWithEngineAndPublicDataUsingChannel(",
        "const proving_including_witness_ns: ?u64",
        "serializeProof(",
        "verifyRiscVWithEngineUsingChannel(",
        "error.TranscriptStateDigestMismatch",
        "const verification_ns = verification_timer.read();",
        "const telemetry_after = try Engine.telemetrySnapshot();",
        "recorder.snapshot(allocator)",
        "verified_request_attempt.Attempt.capture(",
        "artifact_mod.writeArtifact",
    });
}

test "request clock and flat graph capture are absent on unprofiled attempts" {
    const run_prove = try between("fn runProve(", "\nfn runBenchmark(");
    for ([_][]const u8{
        "profiled_sample_index: ?usize",
        ".{ .capture_tasks = profiled_sample_index != null }",
        "if (profiled_sample_index != null)\n        try std.time.Timer.start()",
        "if (profiled_sample_index) |index|",
    }) |token| {
        try std.testing.expect(std.mem.indexOf(u8, run_prove, token) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, run_prove, "profile_attempt") == null);
}

test "profiled benchmark binds every measured sample to the new timing authority" {
    const run_benchmark = try between("fn runBenchmark(", "\n/// Cryptographically verifies");
    try expectOrdered(run_benchmark, &.{
        "if (benchmark.profiled and is_sample) sample_index else null",
        "verified_request_attempt.requireProfiled(",
        "retained_profiled_reports[retained_profiled_report_count] = parsed",
        "retained_profiled_report_count != benchmark.samples",
        "verified_request_attempt.PROFILED_BENCHMARK_SCHEMA",
        ".timing_authority = if (benchmark.profiled) .{} else null",
        ".verified_request_attempts = if (benchmark.profiled) profiled_attempts else null",
        ".emit_null_optional_fields = false",
    });
    try std.testing.expect(
        std.mem.indexOf(u8, run_benchmark, "else\n            \"riscv_proof_v2\"") != null,
    );
}

test "the structural fixture still covers the production adapter" {
    try std.testing.expect(ADAPTER_SOURCE.len > 1024);
    try std.testing.expect((try between("fn runProve(", "\nfn runBenchmark(")).len > 1024);
    try std.testing.expect((try between(
        "fn runBenchmark(",
        "\n/// Cryptographically verifies",
    )).len > 1024);
}
