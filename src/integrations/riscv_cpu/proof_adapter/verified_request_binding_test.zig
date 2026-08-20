//! Structural pins for the profiled verified-request boundary.
//!
//! A mock engine cannot prove where production I/O, verification, snapshots,
//! and artifact publication sit around a real monotonic timer. These checks
//! therefore bind the production adapter itself, following the same pattern as
//! `staged_pcs_profile_test.zig`.

const std = @import("std");
const stwo = @import("stwo");

const ADAPTER_SOURCE = @embedFile("../proof_adapter.zig");

fn between(start_token: []const u8, end_token: []const u8) ![]const u8 {
    return sourceBetween(ADAPTER_SOURCE, start_token, end_token);
}

fn sourceBetween(
    source: []const u8,
    start_token: []const u8,
    end_token: []const u8,
) ![]const u8 {
    const start = std.mem.indexOf(u8, source, start_token) orelse
        return error.StartTokenMissing;
    const tail = source[start..];
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
        "proof_phase_meter.Meter.init(",
        "proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(",
        "proveRiscVWithEngineAndPublicDataUsingChannel(",
        "const proving_including_witness_ns: ?u64",
        "const witness_ns: ?u64",
        "const proving_ns: ?u64",
        "serializeProof(",
        "verifyRiscVWithEngineUsingChannel(",
        "error.TranscriptStateDigestMismatch",
        "const verification_ns = verification_timer.read();",
        "const telemetry_after = try Engine.telemetrySnapshot();",
        "recorder.snapshot(allocator)",
        "requireNativeOnlyStages(profile.stages)",
        "verified_request_attempt.Attempt.capture(",
        "artifact_mod.writeArtifact",
    });
}

test "request clock and flat graph capture are absent on unprofiled attempts" {
    const run_prove = try between("fn runProve(", "\nfn runBenchmark(");
    for ([_][]const u8{
        "profiled_sample_index: ?usize",
        ".capture_tasks = profiled_sample_index != null,",
        ".capture_work = profiled_sample_index != null,",
        "if (profiled_sample_index != null)\n        try std.time.Timer.start()",
        "if (profiled_sample_index != null)\n        try prover.proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(",
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
        std.mem.indexOf(
            u8,
            run_benchmark,
            "else\n            benchmark_report.NATIVE_BENCHMARK_SCHEMA",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, run_benchmark, ".recursion_enabled = false") != null,
    );
}

test "ordinary product prove path has no execution policy or recursive call" {
    const run_prove = try between("fn runProve(", "\nfn runBenchmark(");
    try std.testing.expect(std.mem.indexOf(
        u8,
        run_prove,
        "proveRiscVWithEngineAndPublicDataUsingChannel(",
    ) != null);
    for ([_][]const u8{
        "proveRiscVWithEngineAndPublicDataUsingChannelAndExecution(",
        "StatementAdmission",
        "recursive_fri_outer",
        "proveRecursive",
        "proveOuter",
    }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, run_prove, forbidden) == null);
    }
}

test "ordinary public prove API types expose no execution policy parameter" {
    const prover = stwo.frontends.riscv.prover_mod;
    const ExecutionOptions = prover.ExecutionOptions;
    const ordinary = @typeInfo(@TypeOf(prover.proveRiscVWithEngineAndPublicData)).@"fn";
    const explicit = @typeInfo(
        @TypeOf(prover.proveRiscVWithEngineAndPublicDataWithExecution),
    ).@"fn";
    const channel_ordinary = @typeInfo(
        @TypeOf(prover.proveRiscVWithEngineAndPublicDataUsingChannel),
    ).@"fn";
    const channel_explicit = @typeInfo(
        @TypeOf(prover.proveRiscVWithEngineAndPublicDataUsingChannelAndExecution),
    ).@"fn";
    const channel_metered = @typeInfo(
        @TypeOf(prover.proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter),
    ).@"fn";

    try std.testing.expectEqual(ordinary.params.len + 1, explicit.params.len);
    try std.testing.expectEqual(
        channel_ordinary.params.len + 1,
        channel_explicit.params.len,
    );
    try std.testing.expect(explicit.params[explicit.params.len - 1].type.? == ExecutionOptions);
    try std.testing.expect(
        channel_explicit.params[channel_explicit.params.len - 1].type.? == ExecutionOptions,
    );
    try std.testing.expect(
        channel_metered.params[channel_metered.params.len - 1].type.? ==
            *prover.proof_phase_meter.Meter,
    );
    inline for (ordinary.params) |parameter| {
        if (parameter.type) |T| try std.testing.expect(T != ExecutionOptions);
    }
    inline for (channel_ordinary.params) |parameter| {
        if (parameter.type) |T| try std.testing.expect(T != ExecutionOptions);
    }
}

test "the structural fixture still covers the production adapter" {
    try std.testing.expect(ADAPTER_SOURCE.len > 1024);
    try std.testing.expect((try between("fn runProve(", "\nfn runBenchmark(")).len > 1024);
    try std.testing.expect((try between(
        "fn runBenchmark(",
        "\n/// Cryptographically verifies",
    )).len > 1024);
}
