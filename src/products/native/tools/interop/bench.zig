//! Interop proof benchmark execution and reporting.

const std = @import("std");
const stwo = @import("root").stwo;
const cli_mod = @import("cli.zig");
const examples = @import("examples.zig");

const proof_wire = stwo.interop.proof_wire;
const Cli = cli_mod.Cli;
const BenchProofCodec = cli_mod.BenchProofCodec;
const pcsConfigFromCli = cli_mod.pcsConfigFromCli;
const proveModeToString = cli_mod.proveModeToString;
const proveExample = examples.proveExample;
const verifyExample = examples.verifyExample;
const exampleName = examples.exampleName;

const BenchTiming = struct {
    warmups: usize,
    repeats: usize,
    samples_seconds: []const f64,
    min_seconds: f64,
    max_seconds: f64,
    avg_seconds: f64,
};

const BenchProofMetrics = struct {
    proof_wire_bytes: usize,
    commitments_count: usize,
    decommitments_count: usize,
    trace_decommit_hashes: usize,
    fri_inner_layers_count: usize,
    fri_first_layer_witness_len: usize,
    fri_last_layer_poly_len: usize,
    fri_decommit_hashes_total: usize,
};

const BenchReport = struct {
    runtime: []const u8,
    example: []const u8,
    prove_mode: []const u8,
    include_all_preprocessed_columns: bool,
    prove: BenchTiming,
    verify: BenchTiming,
    proof_metrics: BenchProofMetrics,
};

pub fn runBench(allocator: std.mem.Allocator, cli: Cli) !void {
    const example = cli.example orelse return error.MissingExample;
    if (cli.bench_repeats == 0) return error.InvalidBenchRepeats;
    const config = try pcsConfigFromCli(cli);

    const prove_samples = try allocator.alloc(f64, cli.bench_repeats);
    defer allocator.free(prove_samples);
    const verify_samples = try allocator.alloc(f64, cli.bench_repeats);
    defer allocator.free(verify_samples);

    const total_runs = cli.bench_warmups + cli.bench_repeats;
    for (0..total_runs) |run_idx| {
        const start_ns = std.time.nanoTimestamp();
        var output = try proveExample(allocator, config, cli, example);
        errdefer output.proof.deinit(allocator);
        const encoded = try encodeProofForBench(allocator, cli.bench_proof_codec, output.proof);
        defer allocator.free(encoded);
        const end_ns = std.time.nanoTimestamp();
        output.proof.deinit(allocator);

        if (run_idx >= cli.bench_warmups) {
            const sample_idx = run_idx - cli.bench_warmups;
            const elapsed_ns = end_ns - start_ns;
            prove_samples[sample_idx] = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        }
    }

    var baseline = try proveExample(allocator, config, cli, example);
    errdefer baseline.proof.deinit(allocator);
    const encoded_proof = try encodeProofForBench(allocator, cli.bench_proof_codec, baseline.proof);
    defer allocator.free(encoded_proof);
    const encoded_json_proof = try proof_wire.encodeProofBytes(allocator, baseline.proof);
    defer allocator.free(encoded_json_proof);
    baseline.proof.deinit(allocator);
    const metrics = try collectProofMetricsFromWire(allocator, encoded_json_proof);

    for (0..total_runs) |run_idx| {
        const start_ns = std.time.nanoTimestamp();
        const decoded_proof = try decodeProofForBench(allocator, cli.bench_proof_codec, encoded_proof);
        try verifyExample(allocator, config, baseline.statement, decoded_proof);
        const end_ns = std.time.nanoTimestamp();

        if (run_idx >= cli.bench_warmups) {
            const sample_idx = run_idx - cli.bench_warmups;
            const elapsed_ns = end_ns - start_ns;
            verify_samples[sample_idx] = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        }
    }

    const report = BenchReport{
        .runtime = "zig",
        .example = exampleName(example),
        .prove_mode = proveModeToString(cli.prove_mode),
        .include_all_preprocessed_columns = cli.include_all_preprocessed_columns,
        .prove = summarizeBenchTiming(cli.bench_warmups, cli.bench_repeats, prove_samples),
        .verify = summarizeBenchTiming(cli.bench_warmups, cli.bench_repeats, verify_samples),
        .proof_metrics = metrics,
    };

    const rendered = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(rendered);
    try std.fs.File.stdout().writeAll(rendered);
    try std.fs.File.stdout().writeAll("\n");
}

fn encodeProofForBench(
    allocator: std.mem.Allocator,
    codec: BenchProofCodec,
    proof: proof_wire.Proof,
) ![]u8 {
    return switch (codec) {
        .json => proof_wire.encodeProofBytes(allocator, proof),
        .binary => proof_wire.encodeProofBytesBinary(allocator, proof),
    };
}

fn decodeProofForBench(
    allocator: std.mem.Allocator,
    codec: BenchProofCodec,
    encoded: []const u8,
) !proof_wire.Proof {
    return switch (codec) {
        .json => proof_wire.decodeProofBytes(allocator, encoded),
        .binary => proof_wire.decodeProofBytesBinary(allocator, encoded),
    };
}

fn summarizeBenchTiming(warmups: usize, repeats: usize, samples: []const f64) BenchTiming {
    var min_v = samples[0];
    var max_v = samples[0];
    var sum: f64 = 0.0;
    for (samples) |value| {
        if (value < min_v) min_v = value;
        if (value > max_v) max_v = value;
        sum += value;
    }
    return .{
        .warmups = warmups,
        .repeats = repeats,
        .samples_seconds = samples,
        .min_seconds = min_v,
        .max_seconds = max_v,
        .avg_seconds = sum / @as(f64, @floatFromInt(samples.len)),
    };
}

fn collectProofMetricsFromWire(
    allocator: std.mem.Allocator,
    encoded_proof: []const u8,
) !BenchProofMetrics {
    const parsed = try std.json.parseFromSlice(proof_wire.ProofWire, allocator, encoded_proof, .{
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();

    const wire = parsed.value;
    var trace_decommit_hashes: usize = 0;
    for (wire.decommitments) |decommitment| {
        trace_decommit_hashes += decommitment.hash_witness.len;
    }

    var fri_decommit_hashes_total = wire.fri_proof.first_layer.decommitment.hash_witness.len;
    for (wire.fri_proof.inner_layers) |layer| {
        fri_decommit_hashes_total += layer.decommitment.hash_witness.len;
    }

    return .{
        .proof_wire_bytes = encoded_proof.len,
        .commitments_count = wire.commitments.len,
        .decommitments_count = wire.decommitments.len,
        .trace_decommit_hashes = trace_decommit_hashes,
        .fri_inner_layers_count = wire.fri_proof.inner_layers.len,
        .fri_first_layer_witness_len = wire.fri_proof.first_layer.fri_witness.len,
        .fri_last_layer_poly_len = wire.fri_proof.last_layer_poly.len,
        .fri_decommit_hashes_total = fri_decommit_hashes_total,
    };
}
