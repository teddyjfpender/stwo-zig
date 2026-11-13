//! Pins the live full-width request, verification and publication boundary.
const std = @import("std");
const stwo = @import("stwo");
const REQUEST = @embedFile("blake3_execution_request.zig");
const PRODUCT = @embedFile("blake3_execution_product.zig");

fn expectOrdered(source: []const u8, tokens: []const []const u8) !void {
    var cursor: usize = 0;
    for (tokens) |token| {
        const offset = std.mem.indexOf(u8, source[cursor..], token) orelse
            return error.AdapterBoundaryTokenMissing;
        cursor += offset + token.len;
    }
}

test "profiled phase clocks partition guest proof and native verification" {
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, REQUEST, "Timer.start()"));
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, REQUEST, "timer.read()"));
    try expectOrdered(REQUEST, &.{
        "Timer.start()",                             "admitRunForProving(base_run)",                       "const execution_end = timer.read()",
        "Owner.initCompactRun",                      "run.deinit()",                                       "run_alive = false",
        "const witness_end = timer.read()",          "owner.admission()",                                  "PreparedVerifier.initCompact",
        "const admission_end = timer.read()",        "try Api.prove",                                      "const proving_end = timer.read()",
        "Artifact.encode",                           "prepared.deinit()",                                  "prepared_alive = false",
        "result.proof.deinit(a)",                    "proof_alive = false",                                "owner.deinit()",
        "owner_alive = false",                       "const artifact_end = timer.read()",                  "verifyPublic(a, encoded.bytes, encoded.statement_id",
        "error.TranscriptStateDigestMismatch",       "const end = timer.read()",                           ".public = verified",
        ".execution_ns = execution_end",             ".witness_ns = witness_end - execution_end",          ".admission_ns = admission_end - witness_end",
        ".proving_ns = proving_end - admission_end", ".artifact_encoding_ns = artifact_end - proving_end", ".fresh_verification_ns = end - artifact_end",
        ".total_ns = end",
    });
}

test "full-width phase timing never captures a flat task graph" {
    for ([_][]const u8{ "Recorder.init", "recorder.snapshot", "capture_tasks", "capture_work" }) |token|
        try std.testing.expect(std.mem.indexOf(u8, REQUEST, token) == null);
    try expectOrdered(PRODUCT, &.{
        ".profile_kind = \"phase_timings\"", ".profiled = switch (options.mode)",
        ".prove => false",                   ".bench => |b| b.profiled",
    });
}

test "profiled benchmark binds every measured sample to the new timing authority" {
    try expectOrdered(PRODUCT, &.{
        "if (samples == 0) return error.NoBenchmarkSamples",                                                "std.math.add(usize, warmups, samples)",
        "for (0..count) |index|",                                                                           "try request.execute",
        "defer result.deinit(a)",                                                                           "error.NonDeterministicStatement",
        "error.NonDeterministicTranscript",                                                                 "error.NonDeterministicExecution",
        "if (index < warmups) continue",                                                                    "timings[index - warmups] = result.timing",
        "devices[index - warmups] = result.device",                                                         "ordered[index - warmups] = result.timing.total_ns",
        "if (index + 1 == count)",                                                                          "verified_public = result.public",
        ".exclusive = true",                                                                                "file.writeAll(result.artifact.bytes)",
        ".schema = \"riscv_full_width_execution_v2\"",                                                      ".verified_in_process = true",
        ".recursion_enabled = false",                                                                       ".verified_samples = samples",
        ".timing_partition = \"execution+witness+admission+proving+artifact_encoding+fresh_verification\"",
    });
}

test "ordinary product prove path has no execution policy or recursive call" {
    try expectOrdered(REQUEST, &.{ "try Api.prove", "try Api.proveCompact", "Artifact.encode", "verifyPublic" });
    for ([_][]const u8{ "StatementAdmission", "recursive_fri_outer", "proveRecursive", "proveOuter", "CpuCompositionExecutionRequest" }) |token|
        try std.testing.expect(std.mem.indexOf(u8, REQUEST, token) == null);
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
    try std.testing.expect(REQUEST.len > 1024 and PRODUCT.len > 1024);
    try std.testing.expectError(error.AdapterBoundaryTokenMissing, expectOrdered("verify encode", &.{ "encode", "verify" }));
    try std.testing.expectError(error.AdapterBoundaryTokenMissing, expectOrdered("encode", &.{"verify"}));
}
