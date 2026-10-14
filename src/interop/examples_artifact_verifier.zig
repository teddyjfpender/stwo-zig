//! Bounded verification boundary for versioned Native proof artifacts.

const std = @import("std");
const artifacts = @import("examples_artifact.zig");
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const blake = @import("stwo_native_examples").blake;
const plonk = @import("stwo_native_examples").plonk;
const plonk_logup = @import("stwo_native_examples").plonk_logup;
const poseidon = @import("stwo_native_examples").poseidon;
const state_machine = @import("stwo_native_examples").state_machine;
const wide_fibonacci = @import("stwo_native_examples").wide_fibonacci;
const xor = @import("stwo_native_examples").xor;

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

/// The mode comes from the installed verifier, not from the artifact's proof
/// bytes or an artifact-supplied selector. The version/exchange tuple is also
/// pinned here so a caller cannot relabel CAS05 as legacy postcard.
pub const InstalledKey = struct {
    schema_version: u32,
    exchange_mode: []const u8,
    upstream_commit: []const u8,
    pcs_mode: pcs.format_admission.Mode,
    security_policy: SecurityPolicy,

    pub fn nativeLegacy(policy: SecurityPolicy) InstalledKey {
        return .{
            .schema_version = artifacts.SCHEMA_VERSION,
            .exchange_mode = artifacts.EXCHANGE_MODE,
            .upstream_commit = artifacts.UPSTREAM_COMMIT,
            .pcs_mode = .legacy_postcard,
            .security_policy = policy,
        };
    }
};

/// Reserved candidate envelope only. No installed Native product selects it.
pub const CAS05_CANDIDATE_SCHEMA_VERSION: u32 = 2;
pub const CAS05_CANDIDATE_EXCHANGE_MODE = "proof_exchange_cas05_candidate_v1";

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
    return verifyBytesWithInstalledKey(allocator, raw, InstalledKey.nativeLegacy(security_policy));
}

/// The caller supplies a profile independently of the proof artifact. This
/// slice does not authenticate a serialized S31 verification key. The Native
/// product calls this through `verifyBytes` with its fixed legacy v1 profile.
pub fn verifyBytesWithInstalledKey(
    allocator: std.mem.Allocator,
    raw: []const u8,
    key: InstalledKey,
) !Verification {
    var parsed = try artifacts.parseArtifact(allocator, raw);
    defer parsed.deinit();
    return verifyArtifactWithInstalledKey(allocator, parsed.value, key);
}

pub fn verifyArtifact(
    allocator: std.mem.Allocator,
    artifact: artifacts.InteropArtifact,
    security_policy: SecurityPolicy,
) !Verification {
    return verifyArtifactWithInstalledKey(allocator, artifact, InstalledKey.nativeLegacy(security_policy));
}

pub fn verifyArtifactWithInstalledKey(
    allocator: std.mem.Allocator,
    artifact: artifacts.InteropArtifact,
    key: InstalledKey,
) !Verification {
    try requireInstalledKeyArtifact(key, artifact);
    const generator: Generator = std.meta.stringToEnum(Generator, artifact.generator) orelse
        return error.UnsupportedGenerator;
    if (artifact.prove_mode) |mode| {
        if (!std.mem.eql(u8, mode, "prove") and !std.mem.eql(u8, mode, "prove_ex"))
            return error.UnsupportedProveMode;
    }

    const pcs_config = if (key.pcs_mode == .legacy_postcard) blk: {
        const config = try artifacts.pcsConfigFromWire(artifact.pcs_config);
        try requireSecurityPolicy(config, key.security_policy);
        break :blk config;
    } else null;
    const proof_bytes = try artifacts.hexToBytesAlloc(allocator, artifact.proof_bytes_hex);
    defer allocator.free(proof_bytes);
    _ = try pcs.format_admission.candidate(key.pcs_mode, proof_bytes);
    // CAS05's header can be inspected, but no installed path may decode it as
    // a legacy StarkProof or call the experimental checker as production PCS.
    if (key.pcs_mode != .legacy_postcard) return error.Cas05NotProduction;
    const proof_sha256 = digest(proof_bytes);
    var proof = try proof_wire.decodeProofBytes(allocator, proof_bytes);
    if (!artifacts.pcsConfigsEqual(pcs_config.?, proof.commitment_scheme_proof.config)) {
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
            try blake.verify(allocator, pcs_config.?, statement, proof);
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
            try plonk.verify(allocator, pcs_config.?, statement, proof);
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
            try plonk_logup.verify(allocator, pcs_config.?, statement, proof);
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
            try poseidon.verify(allocator, pcs_config.?, statement, proof);
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
            try state_machine.verify(allocator, pcs_config.?, statement, proof);
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
            try wide_fibonacci.verify(allocator, pcs_config.?, statement, proof);
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
            try xor.verify(allocator, pcs_config.?, statement, proof);
        },
    }
    return .{
        .claimed_generator = generator,
        .example = example,
        .proof_bytes = proof_bytes.len,
        .proof_sha256 = proof_sha256,
    };
}

fn requireInstalledKeyArtifact(key: InstalledKey, artifact: artifacts.InteropArtifact) !void {
    const expected_version: u32 = switch (key.pcs_mode) {
        .legacy_postcard => artifacts.SCHEMA_VERSION,
        .cas05_sparse_v6 => CAS05_CANDIDATE_SCHEMA_VERSION,
    };
    const expected_exchange: []const u8 = switch (key.pcs_mode) {
        .legacy_postcard => artifacts.EXCHANGE_MODE,
        .cas05_sparse_v6 => CAS05_CANDIDATE_EXCHANGE_MODE,
    };
    if (key.schema_version != expected_version or
        !std.mem.eql(u8, key.exchange_mode, expected_exchange) or
        !std.mem.eql(u8, key.upstream_commit, artifacts.UPSTREAM_COMMIT))
        return error.InvalidInstalledKey;
    if (artifact.schema_version != key.schema_version)
        return error.UnsupportedSchemaVersion;
    if (!std.mem.eql(u8, artifact.exchange_mode, key.exchange_mode))
        return error.UnsupportedExchangeMode;
    if (!std.mem.eql(u8, artifact.upstream_commit, key.upstream_commit))
        return error.UnsupportedUpstreamCommit;
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

fn expectSerializedAdmissionError(
    expected: anyerror,
    artifact: artifacts.InteropArtifact,
    key: InstalledKey,
) !void {
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, artifact, .{});
    defer std.testing.allocator.free(encoded);
    try std.testing.expectError(expected, verifyBytesWithInstalledKey(std.testing.allocator, encoded, key));
}

test "artifact verifier: installed key binds serialized PCS mode, schema, and version before decode" {
    const alloc = std.testing.allocator;
    const header = [_]u8{ 'S', '3', '1', 'C', 'A', 'S', '0', '5', 6, 0, 0, 0, 16, 0, 0, 0 };
    const hex = try artifacts.bytesToHexAlloc(alloc, &header);
    defer alloc.free(hex);
    var artifact = artifacts.InteropArtifact{
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
        .proof_bytes_hex = hex,
    };
    const legacy = InstalledKey.nativeLegacy(.smoke);
    try expectSerializedAdmissionError(error.WrongProofFormat, artifact, legacy);
    const serialized = try std.json.Stringify.valueAlloc(alloc, artifact, .{});
    defer alloc.free(serialized);
    const injected = try std.mem.concat(alloc, u8, &.{ "{\"pcs_mode\":\"cas05_sparse_v6\",", serialized[1..] });
    defer alloc.free(injected);
    try std.testing.expectError(error.UnknownField, verifyBytesWithInstalledKey(alloc, injected, legacy));

    artifact.schema_version = CAS05_CANDIDATE_SCHEMA_VERSION;
    try expectSerializedAdmissionError(error.UnsupportedSchemaVersion, artifact, legacy);
    artifact.schema_version = artifacts.SCHEMA_VERSION;
    artifact.exchange_mode = CAS05_CANDIDATE_EXCHANGE_MODE;
    try expectSerializedAdmissionError(error.UnsupportedExchangeMode, artifact, legacy);
    artifact.exchange_mode = artifacts.EXCHANGE_MODE;
    artifact.upstream_commit = "forged-upstream";
    try expectSerializedAdmissionError(error.UnsupportedUpstreamCommit, artifact, legacy);
    artifact.upstream_commit = artifacts.UPSTREAM_COMMIT;

    var mislabeled = legacy;
    mislabeled.schema_version = CAS05_CANDIDATE_SCHEMA_VERSION;
    try expectSerializedAdmissionError(error.InvalidInstalledKey, artifact, mislabeled);
    mislabeled = legacy;
    mislabeled.upstream_commit = "forged-upstream";
    try expectSerializedAdmissionError(error.InvalidInstalledKey, artifact, mislabeled);

    var cas05_key = legacy;
    cas05_key.pcs_mode = .cas05_sparse_v6;
    cas05_key.schema_version = CAS05_CANDIDATE_SCHEMA_VERSION;
    cas05_key.exchange_mode = CAS05_CANDIDATE_EXCHANGE_MODE;
    artifact.schema_version = CAS05_CANDIDATE_SCHEMA_VERSION;
    artifact.exchange_mode = CAS05_CANDIDATE_EXCHANGE_MODE;
    try expectSerializedAdmissionError(error.Cas05NotProduction, artifact, cas05_key);

    var old = header;
    old[8] = 5;
    const old_hex = try artifacts.bytesToHexAlloc(alloc, &old);
    defer alloc.free(old_hex);
    artifact.proof_bytes_hex = old_hex;
    try expectSerializedAdmissionError(error.UnsupportedProofVersion, artifact, cas05_key);
    artifact.proof_bytes_hex = "00";
    try expectSerializedAdmissionError(error.WrongProofFormat, artifact, cas05_key);
}
