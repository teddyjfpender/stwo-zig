//! Structural pins for the full-width execution transaction boundary.
//!
//! A mock engine cannot prove where production I/O, verification, and artifact
//! publication sit around a real monotonic timer. These checks therefore bind
//! the production transaction itself, following the same pattern as
//! `staged_pcs_profile_test.zig`.
//!
//! The adapter was split: `proof_adapter.zig` is now a thin facade that routes
//! through `profile_router.zig` into `blake3_execution_product.zig` (the
//! sampled benchmark/prove loop and the report) and
//! `blake3_execution_request.zig` (one timed execute-prove-verify request). The
//! stage-profile recorder and the `verified_request_attempt` timing authority
//! no longer sit on the product path: every sample is a freshly verified
//! request whose phase partition is the single `Timing` struct, so the pins
//! below bind that partition and the sample binding directly.

const std = @import("std");
const stwo = @import("stwo");

const REQUEST_SOURCE = @embedFile("blake3_execution_request.zig");
const PRODUCT_SOURCE = @embedFile("blake3_execution_product.zig");
const ROUTER_SOURCE = @embedFile("profile_router.zig");
const FACADE_SOURCE = @embedFile("../proof_adapter.zig");

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

/// The single timed request: guest execution through fresh verification.
fn requestExecute() ![]const u8 {
    return sourceBetween(REQUEST_SOURCE, "pub fn execute(", "\n}\n");
}

/// The sampled prove/benchmark loop and the report it publishes.
fn productLoop() ![]const u8 {
    const start = std.mem.indexOf(u8, PRODUCT_SOURCE, "fn runInternal(") orelse
        return error.StartTokenMissing;
    return PRODUCT_SOURCE[start..];
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

test "phase clocks partition guest execution, proving and fresh verification" {
    const execute = try requestExecute();
    // One monotonic timer, read at every phase boundary, in execution order.
    try expectOrdered(execute, &.{
        "var timer = try std.time.Timer.start();",
        "validateReleaseAbiForProfile(elf, profile)",
        "runner.runWithInput(",
        "prover.admitRunForProving(base_run)",
        "const execution_end = timer.read();",
        "initCompactRun(",
        "const witness_end = timer.read();",
        "owner.admission()",
        "PreparedVerifier.initCompact(",
        "const admission_end = timer.read();",
        "Api.proveCompact(",
        "const proving_end = timer.read();",
        "Artifact.encode(",
        "const artifact_end = timer.read();",
        ".verifyPublic(",
        "error.TranscriptStateDigestMismatch",
        "const end = timer.read();",
    });
    // The report's partition is the differences of those boundaries, and the
    // total is the final read, so the phases sum to the sample.
    try expectOrdered(execute, &.{
        ".execution_ns = execution_end,",
        ".witness_ns = witness_end - execution_end,",
        ".admission_ns = admission_end - witness_end,",
        ".proving_ns = proving_end - admission_end,",
        ".artifact_encoding_ns = artifact_end - proving_end,",
        ".fresh_verification_ns = end - artifact_end,",
        ".total_ns = end,",
    });
    // Verification runs on the CPU backend against the encoded bytes, after the
    // witness and the proof object have been destroyed.
    try expectOrdered(execute, &.{
        "result.proof.deinit(a);\n    proof_alive = false;",
        "owner.deinit();\n    owner_alive = false;",
        "ForBackend(@import(\"stwo_cpu_backend\").CpuBackend).verifyPublic(",
    });
}

test "stage-profile capture is absent from the execution transaction" {
    // The old adapter captured a stage-profile recorder and flat task graph on
    // profiled samples only. The transaction has no capture at all now:
    // `profiled` is echoed from the request into the report and drives nothing.
    for ([_][]const u8{ REQUEST_SOURCE, PRODUCT_SOURCE, ROUTER_SOURCE }) |source| {
        for ([_][]const u8{
            "stage_profile",
            "Recorder",
            "capture_tasks",
            "capture_work",
            "profile_attempt",
            "profiled_sample_index",
            "verified_request_attempt",
        }) |token| {
            try std.testing.expect(std.mem.indexOf(u8, source, token) == null);
        }
    }
    const loop = try productLoop();
    try std.testing.expect(std.mem.indexOf(
        u8,
        loop,
        ".profiled = switch (options.mode) {\n            .prove => false,\n            .bench => |b| b.profiled,\n        },",
    ) != null);
}

test "benchmark binds every measured sample to a freshly verified request" {
    const loop = try productLoop();
    try expectOrdered(loop, &.{
        "const count = try std.math.add(usize, warmups, samples);",
        "for (0..count) |index| {",
        "request.execute(Engine, backend == .metal, profile, a, elf, input, pcs_profile.select(options.protocol), budget);",
        "return error.NonDeterministicStatement;",
        "return error.NonDeterministicTranscript;",
        "return error.NonDeterministicExecution;",
        "if (index < warmups) continue;",
        "timings[index - warmups] = result.timing;",
        "devices[index - warmups] = result.device;",
        "ordered[index - warmups] = result.timing.total_ns;",
        "if (options.proof_temporary) |path|",
        "try file.writeAll(result.artifact.bytes);",
        ".schema = \"riscv_full_width_execution_v2\",",
        ".verified_in_process = true,",
        ".recursion_enabled = false,",
        ".samples = samples,",
        ".verified_samples = samples,",
        ".timing_partition = \"execution+witness+admission+proving+artifact_encoding+fresh_verification\",",
        ".timings = timings,",
        ".emit_null_optional_fields = false",
    });
    // Warmups and samples both flow from the requested mode; `prove` is the
    // one-sample, zero-warmup degenerate case of the same loop.
    try expectOrdered(loop, &.{
        "const warmups: usize = switch (options.mode) {\n        .prove => 0,",
        "const samples: usize = switch (options.mode) {\n        .prove => 1,",
        "if (samples == 0) return error.NoBenchmarkSamples;",
    });
}

test "ordinary product prove path has no execution policy or recursive call" {
    const execute = try requestExecute();
    try std.testing.expect(std.mem.indexOf(u8, execute, "Api.proveCompact(") != null);
    for ([_][]const u8{ REQUEST_SOURCE, PRODUCT_SOURCE, ROUTER_SOURCE, FACADE_SOURCE }) |source| {
        for ([_][]const u8{
            "proveRiscVWithEngineAndPublicDataUsingChannelAndExecution(",
            "StatementAdmission",
            "recursive_fri_outer",
            "proveRecursive",
            "proveOuter",
        }) |forbidden| {
            try std.testing.expect(std.mem.indexOf(u8, source, forbidden) == null);
        }
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

test "the structural fixture still covers the production transaction" {
    // The facade must still route every prove/bench request into the product
    // transaction, or the pins above would bind dead code.
    try std.testing.expect(std.mem.indexOf(
        u8,
        FACADE_SOURCE,
        "return profile_router.run(Engine, backend, allocator, elf_path, input_path, options, process_identity);",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        ROUTER_SOURCE,
        "@import(\"blake3_execution_product.zig\").runForProfile(",
    ) != null);
    try std.testing.expect((try requestExecute()).len > 1024);
    try std.testing.expect((try productLoop()).len > 1024);
}
