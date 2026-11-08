//! Native proof artifact generation and verification.

const std = @import("std");
const stwo = @import("root").stwo;
const cli_mod = @import("cli.zig");

const blake = stwo.examples.blake;
const plonk = stwo.examples.plonk;
const poseidon = stwo.examples.poseidon;
const state_machine = stwo.examples.state_machine;
const wide_fibonacci = stwo.examples.wide_fibonacci;
const xor = stwo.examples.xor;
const std_shims_verifier_profile = stwo.std_shims.verifier_profile;
const stage_profile = stwo.prover.stage_profile;
const examples_artifact = stwo.interop.examples_artifact;
const proof_wire = stwo.interop.proof_wire;

const Cli = cli_mod.Cli;
const isSupportedGenerator = cli_mod.isSupportedGenerator;
const isSupportedProveMode = cli_mod.isSupportedProveMode;
const pcsConfigFromCli = cli_mod.pcsConfigFromCli;
const proveModeToString = cli_mod.proveModeToString;
const m31FromCanonical = cli_mod.m31FromCanonical;

fn writeStageProfile(
    allocator: std.mem.Allocator,
    recorder: *stage_profile.Recorder,
    path: []const u8,
) !void {
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    const rendered = try std.json.Stringify.valueAlloc(allocator, profile, .{});
    defer allocator.free(rendered);
    try std.fs.cwd().writeFile(.{
        .sub_path = path,
        .data = rendered,
    });
}

pub fn runGenerate(allocator: std.mem.Allocator, cli: Cli) !void {
    const gen_alloc = allocator;

    const example = cli.example orelse return error.MissingExample;
    if (cli.stage_profile_out != null and example != .wide_fibonacci) {
        return error.UnsupportedStageProfileExample;
    }
    const config = try pcsConfigFromCli(cli);
    const prove_mode = proveModeToString(cli.prove_mode);

    switch (example) {
        .blake => {
            const statement: blake.Request = .{
                .log_n_rows = cli.blake_log_n_rows,
                .n_rounds = cli.blake_n_rounds,
            };
            var proved_statement: blake.Statement = undefined;
            var proof: blake.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try blake.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    var output = try blake.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            defer gen_alloc.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);
            defer gen_alloc.free(proof_bytes_hex);

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
            var proof: plonk.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try plonk.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    var output = try plonk.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            defer gen_alloc.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);
            defer gen_alloc.free(proof_bytes_hex);

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
            var proof: poseidon.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try poseidon.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    var output = try poseidon.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            defer gen_alloc.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);
            defer gen_alloc.free(proof_bytes_hex);

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
            var proof: state_machine.Proof = switch (cli.prove_mode) {
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
                    var output = try state_machine.proveEx(
                        gen_alloc,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                        cli.include_all_preprocessed_columns,
                    );
                    statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            defer gen_alloc.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(gen_alloc, proof_bytes);
            defer gen_alloc.free(proof_bytes_hex);

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
            var maybe_stage_recorder: ?stage_profile.Recorder = null;
            defer if (maybe_stage_recorder) |*recorder| recorder.deinit();
            const stage_recorder = if (cli.stage_profile_out != null) blk: {
                maybe_stage_recorder = stage_profile.Recorder.init(gen_alloc, "zig", "wide_fibonacci");
                break :blk &maybe_stage_recorder.?;
            } else null;

            var proof: wide_fibonacci.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = if (stage_recorder) |recorder|
                        try wide_fibonacci.proveProfiled(gen_alloc, config, statement, recorder)
                    else
                        try wide_fibonacci.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    var output = if (stage_recorder) |recorder|
                        try wide_fibonacci.proveExProfiled(
                            gen_alloc,
                            config,
                            statement,
                            cli.include_all_preprocessed_columns,
                            recorder,
                        )
                    else
                        try wide_fibonacci.proveEx(
                            gen_alloc,
                            config,
                            statement,
                            cli.include_all_preprocessed_columns,
                        );
                    proved_statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = blk: {
                var proof_encode_stage = try stage_profile.StageScope.begin(
                    stage_recorder,
                    "proof_wire_encode",
                    "Proof wire encode",
                );
                defer proof_encode_stage.end();
                break :blk try proof_wire.encodeProofBytes(gen_alloc, proof);
            };
            defer gen_alloc.free(proof_bytes);

            {
                var artifact_write_stage = try stage_profile.StageScope.begin(
                    stage_recorder,
                    "artifact_write",
                    "Artifact write",
                );
                defer artifact_write_stage.end();
                try examples_artifact.writeNativeProofArtifact(
                    gen_alloc,
                    cli.artifact_path,
                    config,
                    prove_mode,
                    .{ .wide_fibonacci = proved_statement },
                    proof_bytes,
                );
            }
            if (cli.stage_profile_out) |path| {
                try writeStageProfile(gen_alloc, &maybe_stage_recorder.?, path);
            }
        },
        .xor => {
            const statement: xor.Statement = .{
                .log_size = cli.xor_log_size,
                .log_step = cli.xor_log_step,
                .offset = cli.xor_offset,
            };
            var proved_statement: xor.Statement = undefined;
            var proof: xor.Proof = switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try xor.prove(gen_alloc, config, statement);
                    proved_statement = output.statement;
                    break :blk output.proof;
                },
                .prove_ex => blk: {
                    var output = try xor.proveEx(
                        gen_alloc,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    proved_statement = output.statement;
                    const owned_proof = output.proof.proof;
                    output.proof.aux.deinit(gen_alloc);
                    break :blk owned_proof;
                },
            };
            defer proof.deinit(gen_alloc);

            const proof_bytes = try proof_wire.encodeProofBytes(gen_alloc, proof);
            defer gen_alloc.free(proof_bytes);
            try examples_artifact.writeNativeProofArtifact(
                gen_alloc,
                cli.artifact_path,
                config,
                prove_mode,
                .{ .xor = proved_statement },
                proof_bytes,
            );
        },
    }
}

pub fn runVerify(allocator: std.mem.Allocator, cli: Cli) !void {
    return runVerifyImpl(allocator, cli, false);
}

pub fn runVerifyStdShims(allocator: std.mem.Allocator, cli: Cli) !void {
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
    if (!examples_artifact.pcsConfigsEqual(config, proof.commitment_scheme_proof.config)) {
        return error.ProofConfigMismatch;
    }

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
