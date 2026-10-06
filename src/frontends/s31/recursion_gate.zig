//! First S31 recursive-verifier adapter. Only the full circuit-v1 gate
//! profile has the eleven-component roster expected by CircuitStatement.
//! The caller must independently authenticate the source, key, and native
//! proof before this conversion. The in-circuit verifier itself constrains
//! the entire child STARK verification, including transcript and FRI.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");

const QM31 = core.fields.qm31.QM31;
const Proof = cpu.Internal.CircuitProof;
const NoValue = circuit.builder.NoValue;
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

pub const Expected = struct {
    preprocessed_root: [32]u8,
    circuit_hash: [32]u8,
    child_key_digest: [32]u8,
    public_words: [8]u32,
};

/// Audit-only corruption of distinct verifier inputs. These are applied
/// after native proof conversion, so rejection exercises the circuit itself.
pub const Mutation = enum { preprocessed_root, trace_root, claimed_sum, channel_salt, fri_witness, fri_last_layer };

fn hashWords(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, bytes[4 * index ..][0..4], .little);
    return words;
}

/// S31 v2 recursive output. The bound verifier constrains the child root
/// separately and embeds this key digest as eight fixed circuit constants.
/// The personalization separates this output from other 64-byte hashes.
pub fn statementDigest(key_digest: [32]u8, child_words: [8]u32) [8]u32 {
    var preimage: [64]u8 = undefined;
    @memcpy(preimage[0..32], &key_digest);
    for (child_words, 0..) |word, index|
        std.mem.writeInt(u32, preimage[32 + 4 * index ..][0..4], word, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&preimage, &digest, .{ .context = "S31RCV2!".* });
    return hashWords(digest);
}

fn authenticateProjection(projection_bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(projection_bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), projection_sha256))
        return error.InvalidProjection;
}

/// Witness-independent verifier topology for the exact child proof geometry.
/// This is separately rebuilt before proving the outer circuit.
pub fn topology(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    child_key_digest: [32]u8,
    child_root: [32]u8,
) !circuit.builder.Context(NoValue) {
    try authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = pcs,
        .preprocessed_column_log_sizes = layout,
    };
    var proof_config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(allocator, &layout, pcs);
    defer proof_config.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const empty = try circuit.stark_verifier.proof.emptyProof(scratch.allocator(), proof_config);
    return circuit.statements.circuit_verifier.buildVerificationCircuitBound(
        NoValue,
        allocator,
        &table,
        &config,
        undefined,
        &empty,
        .{ .output_digest = undefined },
        .{ .key_digest = child_key_digest, .preprocessed_root = child_root },
    );
}

/// Build and satisfy the existing full-circuit recursive verifier using
/// proof material retained by the S31 prover. `expected` comes from the
/// sealed child key and its checked public assignment, never from the proof.
/// The returned circuit is ready for outer proof construction and must be
/// deinitialized by the caller.
pub fn verifyChild(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.preprocessed.ColumnLayout,
    child: *const Proof,
    expected: Expected,
) !circuit.builder.Context(QM31) {
    return verifyChildWithMutation(allocator, projection_bytes, layout, child, expected, null);
}

pub fn verifyChildWithMutation(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.preprocessed.ColumnLayout,
    child: *const Proof,
    expected: Expected,
    mutation: ?Mutation,
) !circuit.builder.Context(QM31) {
    if (child.chip_claimed_sum != null) return error.UnsupportedRecursiveProfile;
    if (!std.mem.eql(u8, &child.circuit_hash, &expected.circuit_hash)) return error.ChildCircuitHashMismatch;
    const actual_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        child.pcs_config.fri_config.log_blowup_factor,
        expected.preprocessed_root,
    );
    if (!std.mem.eql(u8, &actual_hash, &expected.circuit_hash)) return error.ChildCircuitHashMismatch;
    const roots = child.stark_proof.proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &expected.preprocessed_root))
        return error.ChildPreprocessedRootMismatch;
    var adapted = try cpu.verifier_proof.prepare(allocator, child);
    defer adapted.deinit();
    return verifyPreparedWithMutation(allocator, projection_bytes, layout, child.pcs_config, &adapted, expected, mutation);
}

/// Verify a proof reconstructed from an already accepted native S31NAT1
/// proof. The caller must have verified that proof against this exact layout,
/// PCS, preprocessed root, circuit hash, and eight public words.
pub fn verifyPrepared(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    adapted: *const cpu.verifier_proof.VerifierProof,
    expected: Expected,
) !circuit.builder.Context(QM31) {
    return verifyPreparedWithMutation(allocator, projection_bytes, layout, pcs, adapted, expected, null);
}

pub fn verifyPreparedWithMutation(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    adapted: *const cpu.verifier_proof.VerifierProof,
    expected: Expected,
    mutation: ?Mutation,
) !circuit.builder.Context(QM31) {
    const actual_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        expected.preprocessed_root,
    );
    if (!std.mem.eql(u8, &actual_hash, &expected.circuit_hash)) return error.ChildCircuitHashMismatch;
    // Circuit output wires are raw u32 words. S31 leaf statements enforce
    // canonical M31 values at their own boundary; recursive outputs may use
    // every bit pattern, including words above the M31 modulus.
    if (adapted.config.n_preprocessed_columns != layout.entries.len or
        adapted.config.log_trace_size != layout.traceLogSize() or
        !std.meta.eql(adapted.config.fri, pcs.fri_config)) return error.ChildProofConfigMismatch;
    try authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var proof_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &adapted.proof, adapted.config);
    var root_words = hashWords(expected.preprocessed_root);
    if (mutation) |change| switch (change) {
        .preprocessed_root => root_words[0] ^= 1,
        .trace_root => proof_values.trace_root = circuit.builder.blake.hashValue(QM31, @splat(0)),
        .claimed_sum => proof_values.claimed_sums[0] = proof_values.claimed_sums[0].add(QM31.one()),
        .channel_salt => proof_values.channel_salt = proof_values.channel_salt.add(QM31.one()),
        .fri_witness => proof_values.fri.witness[0][0] = proof_values.fri.witness[0][0].add(QM31.one()),
        .fri_last_layer => proof_values.fri.last_layer_coefs[0] = proof_values.fri.last_layer_coefs[0].add(QM31.one()),
    };
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = pcs,
        .preprocessed_column_log_sizes = layout,
    };
    return circuit.statements.circuit_verifier.verifyCircuitBound(
        allocator,
        &table,
        &config,
        circuit.builder.blake.hashValue(QM31, root_words),
        &proof_values,
        .{ .output_digest = circuit.builder.blake.hashValue(QM31, expected.public_words) },
        .{ .key_digest = expected.child_key_digest, .preprocessed_root = expected.preprocessed_root },
    );
}
