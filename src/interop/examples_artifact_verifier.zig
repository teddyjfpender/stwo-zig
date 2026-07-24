//! Bounded verification boundary for versioned Native proof artifacts.

const std = @import("std");
const artifacts = @import("examples_artifact.zig");
const proof_wire = @import("proof_wire.zig");
const blake = @import("../examples/blake.zig");
const plonk = @import("../examples/plonk.zig");
const plonk_logup = @import("../examples/plonk_logup.zig");
const poseidon = @import("../examples/poseidon.zig");
const state_machine = @import("../examples/state_machine.zig");
const wide_fibonacci = @import("../examples/wide_fibonacci.zig");
const xor = @import("../examples/xor.zig");

pub const Generator = enum { rust, zig };
pub const Example = enum {
    blake,
    plonk,
    plonk_logup,
    poseidon,
    state_machine,
    wide_fibonacci,
    xor,
};
pub const SecurityPolicy = enum { secure, functional, smoke };

pub const Verification = struct {
    claimed_generator: Generator,
    example: Example,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub fn verifyPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    security_policy: SecurityPolicy,
) !Verification {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, artifacts.MAX_ARTIFACT_BYTES);
    defer allocator.free(raw);
    return verifyBytes(allocator, raw, security_policy);
}

pub fn verifyBytes(
    allocator: std.mem.Allocator,
    raw: []const u8,
    security_policy: SecurityPolicy,
) !Verification {
    var parsed = try artifacts.parseArtifact(allocator, raw);
    defer parsed.deinit();
    return verifyArtifact(allocator, parsed.value, security_policy);
}

pub fn verifyArtifact(
    allocator: std.mem.Allocator,
    artifact: artifacts.InteropArtifact,
    security_policy: SecurityPolicy,
) !Verification {
    if (artifact.schema_version != artifacts.SCHEMA_VERSION)
        return error.UnsupportedSchemaVersion;
    if (!std.mem.eql(u8, artifact.exchange_mode, artifacts.EXCHANGE_MODE))
        return error.UnsupportedExchangeMode;
    if (!std.mem.eql(u8, artifact.upstream_commit, artifacts.UPSTREAM_COMMIT))
        return error.UnsupportedUpstreamCommit;
    const generator: Generator = std.meta.stringToEnum(Generator, artifact.generator) orelse
        return error.UnsupportedGenerator;
    if (artifact.prove_mode) |mode| {
        if (!std.mem.eql(u8, mode, "prove") and !std.mem.eql(u8, mode, "prove_ex"))
            return error.UnsupportedProveMode;
    }

    const pcs_config = try artifacts.pcsConfigFromWire(artifact.pcs_config);
    try requireSecurityPolicy(pcs_config, security_policy);
    const proof_bytes = try artifacts.hexToBytesAlloc(allocator, artifact.proof_bytes_hex);
    defer allocator.free(proof_bytes);
    const proof_sha256 = digest(proof_bytes);
    var proof = try proof_wire.decodeProofBytes(allocator, proof_bytes);
    if (!artifacts.pcsConfigsEqual(pcs_config, proof.commitment_scheme_proof.config)) {
        proof.deinit(allocator);
        return error.ProofConfigMismatch;
    }

    const example = std.meta.stringToEnum(Example, artifact.example) orelse {
        proof.deinit(allocator);
        return error.UnknownExample;
    };
    validateStatementShape(artifact, example) catch |err| {
        proof.deinit(allocator);
        return err;
    };
    switch (example) {
        .blake => {
            const wire = artifact.blake_statement orelse {
                proof.deinit(allocator);
                return error.MissingBlakeStatement;
            };
            const statement = artifacts.blakeStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try blake.verify(allocator, pcs_config, statement, proof);
        },
        .plonk => {
            const wire = artifact.plonk_statement orelse {
                proof.deinit(allocator);
                return error.MissingPlonkStatement;
            };
            const statement = artifacts.plonkStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try plonk.verify(allocator, pcs_config, statement, proof);
        },
        .plonk_logup => {
            const wire = artifact.plonk_logup_statement orelse {
                proof.deinit(allocator);
                return error.MissingPlonkLogupStatement;
            };
            const statement = artifacts.plonkLogupStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try plonk_logup.verify(allocator, pcs_config, statement, proof);
        },
        .poseidon => {
            const wire = artifact.poseidon_statement orelse {
                proof.deinit(allocator);
                return error.MissingPoseidonStatement;
            };
            const statement = artifacts.poseidonStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try poseidon.verify(allocator, pcs_config, statement, proof);
        },
        .state_machine => {
            const wire = artifact.state_machine_statement orelse {
                proof.deinit(allocator);
                return error.MissingStateMachineStatement;
            };
            const statement = artifacts.stateMachineStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try state_machine.verify(allocator, pcs_config, statement, proof);
        },
        .wide_fibonacci => {
            const wire = artifact.wide_fibonacci_statement orelse {
                proof.deinit(allocator);
                return error.MissingWideFibonacciStatement;
            };
            const statement = artifacts.wideFibonacciStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try wide_fibonacci.verify(allocator, pcs_config, statement, proof);
        },
        .xor => {
            const wire = artifact.xor_statement orelse {
                proof.deinit(allocator);
                return error.MissingXorStatement;
            };
            const statement = artifacts.xorStatementFromWire(wire) catch |err| {
                proof.deinit(allocator);
                return err;
            };
            try xor.verify(allocator, pcs_config, statement, proof);
        },
    }
    return .{
        .claimed_generator = generator,
        .example = example,
        .proof_bytes = proof_bytes.len,
        .proof_sha256 = proof_sha256,
    };
}

fn requireSecurityPolicy(config: anytype, policy: SecurityPolicy) !void {
    const SecurityMinimum = struct { pow_bits: u32, n_queries: usize };
    const minimum: SecurityMinimum = switch (policy) {
        .secure => .{ .pow_bits = @as(u32, 26), .n_queries = @as(usize, 70) },
        .functional => .{ .pow_bits = @as(u32, 10), .n_queries = @as(usize, 3) },
        .smoke => .{ .pow_bits = @as(u32, 0), .n_queries = @as(usize, 3) },
    };
    if (config.pow_bits < minimum.pow_bits or
        config.fri_config.n_queries < minimum.n_queries or
        config.fri_config.log_blowup_factor != 1 or
        config.fri_config.log_last_layer_degree_bound != 0 or
        config.fri_config.fold_step != 1 or
        config.lifting_log_size != null)
        return error.InsufficientSecurityPolicy;
}

fn validateStatementShape(artifact: artifacts.InteropArtifact, example: Example) !void {
    const present = [_]bool{
        artifact.blake_statement != null,
        artifact.plonk_statement != null,
        artifact.plonk_logup_statement != null,
        artifact.poseidon_statement != null,
        artifact.state_machine_statement != null,
        artifact.wide_fibonacci_statement != null,
        artifact.xor_statement != null,
    };
    var count: usize = 0;
    for (present) |is_present| count += @intFromBool(is_present);
    if (count != 1) return error.InvalidStatementShape;
    const expected_present = switch (example) {
        .blake => present[0],
        .plonk => present[1],
        .plonk_logup => present[2],
        .poseidon => present[3],
        .state_machine => present[4],
        .wide_fibonacci => present[5],
        .xor => present[6],
    };
    if (!expected_present) return error.InvalidStatementShape;
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

test "artifact verifier: statement union is exact" {
    const base = artifacts.InteropArtifact{
        .schema_version = artifacts.SCHEMA_VERSION,
        .upstream_commit = artifacts.UPSTREAM_COMMIT,
        .exchange_mode = artifacts.EXCHANGE_MODE,
        .generator = "zig",
        .example = "wide_fibonacci",
        .pcs_config = .{
            .pow_bits = 0,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
                .fold_step = 1,
            },
        },
        .wide_fibonacci_statement = .{ .log_n_rows = 5, .sequence_len = 8 },
        .proof_bytes_hex = "",
    };
    try validateStatementShape(base, .wide_fibonacci);
    var ambiguous = base;
    ambiguous.plonk_statement = .{ .log_n_rows = 5 };
    try std.testing.expectError(
        error.InvalidStatementShape,
        validateStatementShape(ambiguous, .wide_fibonacci),
    );
    try std.testing.expectError(error.InvalidStatementShape, validateStatementShape(base, .plonk));
}

test "artifact verifier: verifier policy rejects prover-selected weak parameters" {
    const fri = @import("stwo_core").fri;
    const pcs = @import("stwo_core").pcs;
    const weak = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 0),
    };
    try std.testing.expectError(
        error.InsufficientSecurityPolicy,
        requireSecurityPolicy(weak, .secure),
    );
    const secure = pcs.PcsConfig{
        .pow_bits = 26,
        .fri_config = try fri.FriConfig.init(0, 1, 70),
    };
    try requireSecurityPolicy(secure, .secure);
}
