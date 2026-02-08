const std = @import("std");
const stwo = @import("stwo.zig");

const m31 = stwo.core.fields.m31;
const fri = stwo.core.fri;
const pcs = stwo.core.pcs;
const blake = stwo.examples.blake;
const plonk = stwo.examples.plonk;
const poseidon = stwo.examples.poseidon;
const state_machine = stwo.examples.state_machine;
const wide_fibonacci = stwo.examples.wide_fibonacci;
const xor = stwo.examples.xor;
const std_shims_verifier_profile = stwo.std_shims.verifier_profile;
const examples_artifact = stwo.interop.examples_artifact;
const proof_wire = stwo.interop.proof_wire;

const M31 = m31.M31;

const Mode = enum {
    generate,
    verify,
    verify_std_shims,
    bench,
};

const Example = enum {
    blake,
    plonk,
    poseidon,
    state_machine,
    wide_fibonacci,
    xor,
};

const ProveMode = enum {
    prove,
    prove_ex,
};

const Cli = struct {
    mode: Mode,
    example: ?Example = null,
    artifact_path: []const u8,
    prove_mode: ProveMode = .prove,
    include_all_preprocessed_columns: bool = false,

    pow_bits: u32 = 0,
    fri_log_blowup: u32 = 1,
    fri_log_last_layer: u32 = 0,
    fri_n_queries: usize = 3,

    sm_log_n_rows: u32 = 5,
    sm_initial_0: u32 = 9,
    sm_initial_1: u32 = 3,

    blake_log_n_rows: u32 = 5,
    blake_n_rounds: u32 = 10,

    plonk_log_n_rows: u32 = 5,

    poseidon_log_n_instances: u32 = 8,

    wf_log_n_rows: u32 = 5,
    wf_sequence_len: u32 = 16,

    xor_log_size: u32 = 5,
    xor_log_step: u32 = 2,
    xor_offset: usize = 3,

    bench_warmups: usize = 1,
    bench_repeats: usize = 5,
};

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

const ExampleStatement = union(Example) {
    blake: blake.Statement,
    plonk: plonk.Statement,
    poseidon: poseidon.Statement,
    state_machine: state_machine.PreparedStatement,
    wide_fibonacci: wide_fibonacci.Statement,
    xor: xor.Statement,
};

const ExampleProveOutput = struct {
    statement: ExampleStatement,
    proof: proof_wire.Proof,
};

pub fn main() !void {
    const gpa = std.heap.c_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    const cli = parseArgs(args) catch |err| {
        printUsage();
        return err;
    };

    switch (cli.mode) {
        .generate => try runGenerate(gpa, cli),
        .verify => try runVerify(gpa, cli),
        .verify_std_shims => try runVerifyStdShims(gpa, cli),
        .bench => try runBench(gpa, cli),
    }
}

fn runBench(allocator: std.mem.Allocator, cli: Cli) !void {
    const example = cli.example orelse return error.MissingExample;
    if (cli.bench_repeats == 0) return error.InvalidBenchRepeats;
    const config = try pcsConfigFromCli(cli);

    const prove_samples = try allocator.alloc(f64, cli.bench_repeats);
    defer allocator.free(prove_samples);
    const verify_samples = try allocator.alloc(f64, cli.bench_repeats);
    defer allocator.free(verify_samples);

    const total_runs = cli.bench_warmups + cli.bench_repeats;
    for (0..total_runs) |run_idx| {
        var prove_arena = std.heap.ArenaAllocator.init(allocator);
        defer prove_arena.deinit();
        const prove_alloc = prove_arena.allocator();

        const start_ns = std.time.nanoTimestamp();
        const output = try proveExample(prove_alloc, config, cli, example);
        _ = try proof_wire.encodeProofBytes(prove_alloc, output.proof);
        const end_ns = std.time.nanoTimestamp();

        if (run_idx >= cli.bench_warmups) {
            const sample_idx = run_idx - cli.bench_warmups;
            const elapsed_ns = end_ns - start_ns;
            prove_samples[sample_idx] = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        }
    }

    var baseline_arena = std.heap.ArenaAllocator.init(allocator);
    defer baseline_arena.deinit();
    const baseline_alloc = baseline_arena.allocator();

    const baseline = try proveExample(baseline_alloc, config, cli, example);
    const encoded_proof = try proof_wire.encodeProofBytes(baseline_alloc, baseline.proof);
    const metrics = try collectProofMetricsFromWire(baseline_alloc, encoded_proof);

    for (0..total_runs) |run_idx| {
        var verify_arena = std.heap.ArenaAllocator.init(allocator);
        defer verify_arena.deinit();
        const verify_alloc = verify_arena.allocator();

        const start_ns = std.time.nanoTimestamp();
        const decoded_proof = try proof_wire.decodeProofBytes(verify_alloc, encoded_proof);
        try verifyExample(verify_alloc, config, baseline.statement, decoded_proof);
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

fn proveExample(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    cli: Cli,
    example: Example,
) !ExampleProveOutput {
    switch (example) {
        .blake => {
            const statement: blake.Statement = .{
                .log_n_rows = cli.blake_log_n_rows,
                .n_rounds = cli.blake_n_rounds,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try blake.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .blake = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try blake.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .blake = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .plonk => {
            const statement: plonk.Statement = .{
                .log_n_rows = cli.plonk_log_n_rows,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try plonk.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .plonk = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try plonk.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .plonk = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .poseidon => {
            const statement: poseidon.Statement = .{
                .log_n_instances = cli.poseidon_log_n_instances,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try poseidon.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .poseidon = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try poseidon.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .poseidon = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .state_machine => {
            const initial_state: state_machine.State = .{
                try m31FromCanonical(cli.sm_initial_0),
                try m31FromCanonical(cli.sm_initial_1),
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try state_machine.prove(
                        allocator,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                    );
                    break :blk .{
                        .statement = .{ .state_machine = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try state_machine.proveEx(
                        allocator,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .state_machine = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .wide_fibonacci => {
            const statement: wide_fibonacci.Statement = .{
                .log_n_rows = cli.wf_log_n_rows,
                .sequence_len = cli.wf_sequence_len,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try wide_fibonacci.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .wide_fibonacci = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try wide_fibonacci.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .wide_fibonacci = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .xor => {
            const statement: xor.Statement = .{
                .log_size = cli.xor_log_size,
                .log_step = cli.xor_log_step,
                .offset = cli.xor_offset,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try xor.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .xor = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try xor.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .xor = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
    }
}

fn verifyExample(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    statement: ExampleStatement,
    proof: proof_wire.Proof,
) !void {
    switch (statement) {
        .blake => |s| try blake.verify(allocator, config, s, proof),
        .plonk => |s| try plonk.verify(allocator, config, s, proof),
        .poseidon => |s| try poseidon.verify(allocator, config, s, proof),
        .state_machine => |s| try state_machine.verify(allocator, config, s, proof),
        .wide_fibonacci => |s| try wide_fibonacci.verify(allocator, config, s, proof),
        .xor => |s| try xor.verify(allocator, config, s, proof),
    }
}

fn verifyExampleStdShims(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    statement: ExampleStatement,
    proof: proof_wire.Proof,
) !void {
    switch (statement) {
        .blake => |s| try std_shims_verifier_profile.verifyBlake(allocator, config, s, proof),
        .plonk => |s| try std_shims_verifier_profile.verifyPlonk(allocator, config, s, proof),
        .poseidon => |s| try std_shims_verifier_profile.verifyPoseidon(allocator, config, s, proof),
        .state_machine => |s| try std_shims_verifier_profile.verifyStateMachine(allocator, config, s, proof),
        .wide_fibonacci => |s| try std_shims_verifier_profile.verifyWideFibonacci(allocator, config, s, proof),
        .xor => |s| try std_shims_verifier_profile.verifyXor(allocator, config, s, proof),
    }
}

fn exampleName(example: Example) []const u8 {
    return switch (example) {
        .blake => "blake",
        .plonk => "plonk",
        .poseidon => "poseidon",
        .state_machine => "state_machine",
        .wide_fibonacci => "wide_fibonacci",
        .xor => "xor",
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

fn runGenerate(allocator: std.mem.Allocator, cli: Cli) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const gen_alloc = arena.allocator();

    const example = cli.example orelse return error.MissingExample;
    const config = try pcsConfigFromCli(cli);
    const prove_mode = proveModeToString(cli.prove_mode);

    switch (example) {
        .blake => {
            const statement: blake.Statement = .{
                .log_n_rows = cli.blake_log_n_rows,
                .n_rounds = cli.blake_n_rounds,
            };
            var proved_statement: blake.Statement = undefined;
            const proof: blake.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try blake.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try blake.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "blake",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = examples_artifact.blakeStatementToWire(proved_statement),
                .plonk_statement = null,
                .poseidon_statement = null,
                .state_machine_statement = null,
                .wide_fibonacci_statement = null,
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .plonk => {
            const statement: plonk.Statement = .{
                .log_n_rows = cli.plonk_log_n_rows,
            };
            var proved_statement: plonk.Statement = undefined;
            const proof: plonk.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try plonk.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try plonk.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "plonk",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = null,
                .plonk_statement = examples_artifact.plonkStatementToWire(proved_statement),
                .poseidon_statement = null,
                .state_machine_statement = null,
                .wide_fibonacci_statement = null,
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .poseidon => {
            const statement: poseidon.Statement = .{
                .log_n_instances = cli.poseidon_log_n_instances,
            };
            var proved_statement: poseidon.Statement = undefined;
            const proof: poseidon.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try poseidon.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try poseidon.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "poseidon",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = null,
                .plonk_statement = null,
                .poseidon_statement = examples_artifact.poseidonStatementToWire(proved_statement),
                .state_machine_statement = null,
                .wide_fibonacci_statement = null,
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .state_machine => {
            const initial_state: state_machine.State = .{
                try m31FromCanonical(cli.sm_initial_0),
                try m31FromCanonical(cli.sm_initial_1),
            };
            var statement: state_machine.PreparedStatement = undefined;
            const proof: state_machine.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try state_machine.prove(
                        gen_alloc,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                    );
                    statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try state_machine.proveEx(
                        gen_alloc,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                        cli.include_all_preprocessed_columns,
                    );
                    statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "state_machine",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = null,
                .plonk_statement = null,
                .poseidon_statement = null,
                .state_machine_statement = examples_artifact.stateMachineStatementToWire(statement),
                .wide_fibonacci_statement = null,
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .wide_fibonacci => {
            const statement: wide_fibonacci.Statement = .{
                .log_n_rows = cli.wf_log_n_rows,
                .sequence_len = cli.wf_sequence_len,
            };
            var proved_statement: wide_fibonacci.Statement = undefined;
            const proof: wide_fibonacci.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try wide_fibonacci.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try wide_fibonacci.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "wide_fibonacci",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = null,
                .plonk_statement = null,
                .poseidon_statement = null,
                .state_machine_statement = null,
                .wide_fibonacci_statement = examples_artifact.wideFibonacciStatementToWire(proved_statement),
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .xor => {
            const statement: xor.Statement = .{
                .log_size = cli.xor_log_size,
                .log_step = cli.xor_log_step,
                .offset = cli.xor_offset,
            };
            var proved_statement: xor.Statement = undefined;
            const proof: xor.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try xor.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    const output = try xor.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    break :blk output.proof.proof;
                },
            };

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);

            try examples_artifact.writeArtifact(gen_alloc, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "xor",
                .prove_mode = prove_mode,
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .blake_statement = null,
                .plonk_statement = null,
                .poseidon_statement = null,
                .state_machine_statement = null,
                .wide_fibonacci_statement = null,
                .xor_statement = examples_artifact.xorStatementToWire(proved_statement),
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
    }
}

fn runVerify(allocator: std.mem.Allocator, cli: Cli) !void {
    return runVerifyImpl(allocator, cli, false);
}

fn runVerifyStdShims(allocator: std.mem.Allocator, cli: Cli) !void {
    return runVerifyImpl(allocator, cli, true);
}

fn runVerifyImpl(allocator: std.mem.Allocator, cli: Cli, use_std_shims: bool) !void {
    const parsed = try examples_artifact.readArtifact(allocator, cli.artifact_path);
    defer parsed.deinit();

    const artifact = parsed.value;
    if (artifact.schema_version != examples_artifact.SCHEMA_VERSION) {
        return error.UnsupportedSchemaVersion;
    }
    if (!std.mem.eql(u8, artifact.exchange_mode, examples_artifact.EXCHANGE_MODE)) {
        return error.UnsupportedExchangeMode;
    }
    if (!std.mem.eql(u8, artifact.upstream_commit, examples_artifact.UPSTREAM_COMMIT)) {
        return error.UnsupportedUpstreamCommit;
    }
    if (!isSupportedGenerator(artifact.generator)) {
        return error.UnsupportedGenerator;
    }
    if (artifact.prove_mode) |mode| {
        if (!isSupportedProveMode(mode)) return error.UnsupportedProveMode;
    }

    const config = try examples_artifact.pcsConfigFromWire(artifact.pcs_config);
    const proof_bytes = try examples_artifact.hexToBytesAlloc(allocator, artifact.proof_bytes_hex);
    defer allocator.free(proof_bytes);

    const proof = try proof_wire.decodeProofBytes(allocator, proof_bytes);

    if (std.mem.eql(u8, artifact.example, "blake")) {
        const statement_wire = artifact.blake_statement orelse return error.MissingBlakeStatement;
        const statement = try examples_artifact.blakeStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyBlake(allocator, config, statement, proof);
        } else {
            try blake.verify(allocator, config, statement, proof);
        }
        return;
    }
    if (std.mem.eql(u8, artifact.example, "plonk")) {
        const statement_wire = artifact.plonk_statement orelse return error.MissingPlonkStatement;
        const statement = try examples_artifact.plonkStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyPlonk(allocator, config, statement, proof);
        } else {
            try plonk.verify(allocator, config, statement, proof);
        }
        return;
    }
    if (std.mem.eql(u8, artifact.example, "poseidon")) {
        const statement_wire = artifact.poseidon_statement orelse return error.MissingPoseidonStatement;
        const statement = try examples_artifact.poseidonStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyPoseidon(allocator, config, statement, proof);
        } else {
            try poseidon.verify(allocator, config, statement, proof);
        }
        return;
    }
    if (std.mem.eql(u8, artifact.example, "state_machine")) {
        const statement_wire = artifact.state_machine_statement orelse return error.MissingStateMachineStatement;
        const statement = try examples_artifact.stateMachineStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyStateMachine(allocator, config, statement, proof);
        } else {
            try state_machine.verify(allocator, config, statement, proof);
        }
        return;
    }
    if (std.mem.eql(u8, artifact.example, "wide_fibonacci")) {
        const statement_wire = artifact.wide_fibonacci_statement orelse return error.MissingWideFibonacciStatement;
        const statement = try examples_artifact.wideFibonacciStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyWideFibonacci(allocator, config, statement, proof);
        } else {
            try wide_fibonacci.verify(allocator, config, statement, proof);
        }
        return;
    }
    if (std.mem.eql(u8, artifact.example, "xor")) {
        const statement_wire = artifact.xor_statement orelse return error.MissingXorStatement;
        const statement = try examples_artifact.xorStatementFromWire(statement_wire);
        if (use_std_shims) {
            try std_shims_verifier_profile.verifyXor(allocator, config, statement, proof);
        } else {
            try xor.verify(allocator, config, statement, proof);
        }
        return;
    }
    return error.UnknownExample;
}

fn isSupportedGenerator(generator: []const u8) bool {
    return std.mem.eql(u8, generator, "rust") or std.mem.eql(u8, generator, "zig");
}

fn isSupportedProveMode(mode: []const u8) bool {
    return std.mem.eql(u8, mode, "prove") or std.mem.eql(u8, mode, "prove_ex");
}

fn proveModeToString(mode: ProveMode) []const u8 {
    return switch (mode) {
        .prove => "prove",
        .prove_ex => "prove_ex",
    };
}

fn parseArgs(args: []const []const u8) !Cli {
    var mode: ?Mode = null;
    var example: ?Example = null;
    var artifact_path: ?[]const u8 = null;
    var prove_mode: ProveMode = .prove;
    var include_all_preprocessed_columns = false;

    var pow_bits: u32 = 0;
    var fri_log_blowup: u32 = 1;
    var fri_log_last_layer: u32 = 0;
    var fri_n_queries: usize = 3;

    var sm_log_n_rows: u32 = 5;
    var sm_initial_0: u32 = 9;
    var sm_initial_1: u32 = 3;

    var blake_log_n_rows: u32 = 5;
    var blake_n_rounds: u32 = 10;

    var plonk_log_n_rows: u32 = 5;

    var poseidon_log_n_instances: u32 = 8;

    var wf_log_n_rows: u32 = 5;
    var wf_sequence_len: u32 = 16;

    var xor_log_size: u32 = 5;
    var xor_log_step: u32 = 2;
    var xor_offset: usize = 3;

    var bench_warmups: usize = 1;
    var bench_repeats: usize = 5;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const flag = args[i];
        if (!std.mem.startsWith(u8, flag, "--")) return error.InvalidArgument;
        if (i + 1 >= args.len) return error.MissingArgumentValue;

        const value = args[i + 1];
        i += 1;

        if (std.mem.eql(u8, flag, "--mode")) {
            mode = parseMode(value) orelse return error.InvalidMode;
        } else if (std.mem.eql(u8, flag, "--example")) {
            example = parseExample(value) orelse return error.InvalidExample;
        } else if (std.mem.eql(u8, flag, "--artifact")) {
            artifact_path = value;
        } else if (std.mem.eql(u8, flag, "--prove-mode")) {
            prove_mode = parseProveMode(value) orelse return error.InvalidProveMode;
        } else if (std.mem.eql(u8, flag, "--include-all-preprocessed-columns")) {
            include_all_preprocessed_columns = try parseBool(value);
        } else if (std.mem.eql(u8, flag, "--pow-bits")) {
            pow_bits = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-log-blowup")) {
            fri_log_blowup = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-log-last-layer")) {
            fri_log_last_layer = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-n-queries")) {
            fri_n_queries = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--sm-log-n-rows")) {
            sm_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--sm-initial-0")) {
            sm_initial_0 = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--sm-initial-1")) {
            sm_initial_1 = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--blake-log-n-rows")) {
            blake_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--blake-n-rounds")) {
            blake_n_rounds = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--plonk-log-n-rows")) {
            plonk_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--poseidon-log-n-instances")) {
            poseidon_log_n_instances = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--wf-log-n-rows")) {
            wf_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--wf-sequence-len")) {
            wf_sequence_len = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-size")) {
            xor_log_size = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-step")) {
            xor_log_step = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-offset")) {
            xor_offset = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--bench-warmups")) {
            bench_warmups = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--bench-repeats")) {
            bench_repeats = try parseInt(usize, value);
        } else {
            return error.InvalidArgument;
        }
    }

    return .{
        .mode = mode orelse return error.MissingMode,
        .example = example,
        .artifact_path = artifact_path orelse return error.MissingArtifactPath,
        .prove_mode = prove_mode,
        .include_all_preprocessed_columns = include_all_preprocessed_columns,
        .pow_bits = pow_bits,
        .fri_log_blowup = fri_log_blowup,
        .fri_log_last_layer = fri_log_last_layer,
        .fri_n_queries = fri_n_queries,
        .sm_log_n_rows = sm_log_n_rows,
        .sm_initial_0 = sm_initial_0,
        .sm_initial_1 = sm_initial_1,
        .blake_log_n_rows = blake_log_n_rows,
        .blake_n_rounds = blake_n_rounds,
        .plonk_log_n_rows = plonk_log_n_rows,
        .poseidon_log_n_instances = poseidon_log_n_instances,
        .wf_log_n_rows = wf_log_n_rows,
        .wf_sequence_len = wf_sequence_len,
        .xor_log_size = xor_log_size,
        .xor_log_step = xor_log_step,
        .xor_offset = xor_offset,
        .bench_warmups = bench_warmups,
        .bench_repeats = bench_repeats,
    };
}

fn parseMode(value: []const u8) ?Mode {
    if (std.mem.eql(u8, value, "generate")) return .generate;
    if (std.mem.eql(u8, value, "verify")) return .verify;
    if (std.mem.eql(u8, value, "verify_std_shims")) return .verify_std_shims;
    if (std.mem.eql(u8, value, "bench")) return .bench;
    return null;
}

fn parseExample(value: []const u8) ?Example {
    if (std.mem.eql(u8, value, "blake")) return .blake;
    if (std.mem.eql(u8, value, "plonk")) return .plonk;
    if (std.mem.eql(u8, value, "poseidon")) return .poseidon;
    if (std.mem.eql(u8, value, "state_machine")) return .state_machine;
    if (std.mem.eql(u8, value, "wide_fibonacci")) return .wide_fibonacci;
    if (std.mem.eql(u8, value, "xor")) return .xor;
    return null;
}

fn parseProveMode(value: []const u8) ?ProveMode {
    if (std.mem.eql(u8, value, "prove")) return .prove;
    if (std.mem.eql(u8, value, "prove_ex")) return .prove_ex;
    return null;
}

fn parseBool(value: []const u8) !bool {
    if (std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "0") or std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10);
}

fn pcsConfigFromCli(cli: Cli) !pcs.PcsConfig {
    return .{
        .pow_bits = cli.pow_bits,
        .fri_config = try fri.FriConfig.init(
            cli.fri_log_last_layer,
            cli.fri_log_blowup,
            cli.fri_n_queries,
        ),
    };
}

fn m31FromCanonical(value: u32) !M31 {
    if (value >= m31.Modulus) return error.NonCanonicalM31;
    return M31.fromCanonical(value);
}

fn printUsage() void {
    std.debug.print(
        "usage:\n" ++
            "  zig run src/interop_cli.zig -- --mode generate --example <blake|plonk|poseidon|state_machine|wide_fibonacci|xor> --artifact <path> [options]\n" ++
            "    [--prove-mode <prove|prove_ex>] [--include-all-preprocessed-columns <0|1>]\n" ++
            "  zig run src/interop_cli.zig -- --mode verify --artifact <path>\n" ++
            "  zig run src/interop_cli.zig -- --mode verify_std_shims --artifact <path>\n" ++
            "  zig run src/interop_cli.zig -- --mode bench --example <blake|plonk|poseidon|state_machine|wide_fibonacci|xor> --artifact <ignored> [options]\n" ++
            "    [--bench-warmups <n>] [--bench-repeats <n>]\n",
        .{},
    );
}
