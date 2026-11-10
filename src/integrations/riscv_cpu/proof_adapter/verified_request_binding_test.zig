//! Structural contracts for the connected full-width request transaction.
const std = @import("std");
const stwo = @import("stwo");
const ADAPTER_SOURCE = @embedFile("../proof_adapter.zig");
const ROUTER_SOURCE = @embedFile("profile_router.zig");
const REQUEST_SOURCE = @embedFile("blake3_execution_request.zig");
const PRODUCT_SOURCE = @embedFile("blake3_execution_product.zig");

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

test "full-width phase clocks partition execution through fresh verification" {
    try expectOrdered(REQUEST_SOURCE, &.{
        "var timer = try std.time.Timer.start();",
        "try prover.admitRunForProving(base_run);",
        "const execution_end = timer.read();",
        "const witness_end = timer.read();",
        "const admission_end = timer.read();",
        "const proving_end = timer.read();",
        "const artifact_end = timer.read();",
        "const end = timer.read();",
        ".execution_ns = execution_end,",
        ".witness_ns = witness_end - execution_end,",
        ".admission_ns = admission_end - witness_end,",
        ".proving_ns = proving_end - admission_end,",
        ".artifact_encoding_ns = artifact_end - proving_end,",
        ".fresh_verification_ns = end - artifact_end,",
        ".total_ns = end,",
    });
}

test "full-width ownership closes before independent CPU verification and publication" {
    for ([_][]const u8{
        "defer if (run_alive) run.deinit();",
        "defer if (owner_alive) owner.deinit();",
        "defer if (prepared_alive) prepared.deinit();",
        "defer if (proof_alive) result.proof.deinit(a);",
    }) |token| try std.testing.expect(std.mem.indexOf(u8, REQUEST_SOURCE, token) != null);
    try expectOrdered(REQUEST_SOURCE, &.{
        "const encoded = try Artifact.encode(",
        "prepared.deinit();",
        "errdefer a.free(encoded.bytes);",
        "result.proof.deinit(a);",
        "owner.deinit();",
        "const verified = try Artifact.ForBackend(@import(\"stwo_cpu_backend\").CpuBackend).verifyPublic(",
        "error.TranscriptStateDigestMismatch;",
        "return .{ .public = verified,",
    });
}

test "full-width benchmarks bind every measured sample to verified deterministic results" {
    try expectOrdered(PRODUCT_SOURCE, &.{
        "if (samples == 0) return error.NoBenchmarkSamples;",
        "const count = try std.math.add(usize, warmups, samples);",
        "for (0..count) |index|",
        "var result = try request.execute(",
        "defer result.deinit(a);",
        "error.NonDeterministicStatement;",
        "error.NonDeterministicTranscript;",
        "error.NonDeterministicExecution;",
        "if (index < warmups) continue;",
        "timings[index - warmups] = result.timing;",
        "if (index + 1 == count)",
        "verified_public = result.public;",
        "std.crypto.hash.sha2.Sha256.hash(result.artifact.bytes,",
        "try file.writeAll(result.artifact.bytes);",
        ".verified_in_process = true,",
        ".verified_samples = samples,",
        ".timings = timings,",
    });
}

test "ordinary full-width routing admits only the declared execution profiles" {
    try std.testing.expect(std.mem.indexOf(u8, ADAPTER_SOURCE, "return error.LegacyProofGenerationRemoved;") != null);
    try expectOrdered(ROUTER_SOURCE, &.{
        "const requested = try requestedExecutionProfile(",
        "return switch (requested)",
        "inline .rv32im_zkvm_v1, .rv32im_zkvm_poseidon2_v1, .rv32im_zkvm_ethereum_v1",
        "@import(\"blake3_execution_product.zig\").runForProfile(",
        "else => error.UnsupportedExecutionProfile,",
    });
    try std.testing.expect(std.mem.indexOf(u8, PRODUCT_SOURCE, ".recursion_enabled = false,") != null);
}

test "full-width structural fixtures cover the connected production owners" {
    for ([_][]const u8{ ADAPTER_SOURCE, ROUTER_SOURCE, REQUEST_SOURCE, PRODUCT_SOURCE }) |source|
        try std.testing.expect(source.len > 1024);
    try expectOrdered(ADAPTER_SOURCE, &.{
        "const profile_router = @import(\"proof_adapter/profile_router.zig\");",
        "return profile_router.run(",
    });
    try expectOrdered(PRODUCT_SOURCE, &.{
        "const request = @import(\"blake3_execution_request.zig\");",
        "var result = try request.execute(",
    });
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
