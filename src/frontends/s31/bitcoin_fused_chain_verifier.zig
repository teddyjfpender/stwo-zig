//! Sealed host boundary for the one-header, genesis-anchored S31FCF01 proof.
//! The verifier builds the value-free circuit and SHA fixed columns itself.
//! This format verifies a generic checkpoint anchor inside one fused fold;
//! it does not authenticate a second fused fold as its child.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const s31 = @import("stwo_s31_prototype");
const anchor = @import("bitcoin_chain_anchor.zig");
const fold = @import("bitcoin_chain_fold.zig");
const chain = @import("bitcoin_chain_verifier.zig");
const native = s31.sha_fused_fold_native_verifier;
const profile = s31.sha_fused_fold_profile;

const QM31 = core.fields.qm31.QM31;
const projection_bytes = @embedFile("s31_air_projection");
const air_bytes = @embedFile("s31_air_programs");
const key_schema = "s31-bitcoin-fused-chain-verification-key-v1";
const statement_schema = "s31-bitcoin-fused-chain-statement-v1";
const profile_name = "bitcoin-mainnet-genesis-one-header-fused-sha256d-v1";
pub const step: u32 = 0;
pub const genesis_display_hash = chain.genesis_display_hash;

pub const Fri = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    last_layer_degree_bound: u32,
    queries: u32,
    fold_step: u32,
};
pub const child_fri: Fri = .{ .pow_bits = 26, .log_blowup_factor = 1, .last_layer_degree_bound = 0, .queries = 70, .fold_step = 4 };
pub const outer_fri: Fri = .{ .pow_bits = 26, .log_blowup_factor = 1, .last_layer_degree_bound = 0, .queries = 70, .fold_step = 1 };

pub const Key = struct {
    schema: []const u8,
    profile: []const u8,
    proof_magic: []const u8,
    checkpoint_block_hash: []const u8,
    checkpoint_root: [8]u32,
    step: u32,
    anchor_preprocessed_root: []const u8,
    fused_fixed_root: []const u8,
    fused_key_digest: []const u8,
    fused_source_digest: []const u8,
    sha_gate_addresses: [56]u32,
    n_vars: u32,
    padded: chain.Rows,
    trace_log_size: u32,
    child_fri: Fri,
    outer_fri: Fri,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
};

pub const Statement = struct {
    schema: []const u8,
    verification_key_sha256: []const u8,
    step: u32,
    current_block_hash: []const u8,
    current_block_timestamp: u32,
    last_timestamps: [11]u32,
    public_words: [8]u32,
};

pub const Material = struct {
    checkpoint_root: [8]u32,
    anchor_root: [32]u8,
    fused_key: native.Key,
};

pub const VerifiedKey = struct {
    material: Material,
    key_sha256: [32]u8,
};

fn sameHex(raw: [32]u8, claimed: []const u8) bool {
    return std.mem.eql(u8, claimed, &std.fmt.bytesToHex(raw, .lower));
}

fn addressesFromWires(wires: s31.bitcoin_fold_step.ShaBoundaryWires) [56]u32 {
    var addresses: [56]u32 = undefined;
    for (wires.header, 0..) |wire, i| addresses[i] = wire.idx;
    for (wires.digest, 0..) |wire, i| addresses[40 + i] = wire.idx;
    return addresses;
}

fn friConfig(config: Fri) !core.pcs.config_v2.FriConfigV2 {
    return core.pcs.config_v2.FriConfigV2.init(
        config.pow_bits,
        config.last_layer_degree_bound,
        config.log_blowup_factor,
        config.queries,
        config.fold_step,
    );
}

/// Rebuild both fixed commitments from independently compiled, value-free
/// topology. The checkpoint, component geometry, SHA boundary and FRI policy
/// are verifier constants, never supplied by proof bytes.
pub fn deriveMaterial(allocator: std.mem.Allocator) !Material {
    const checkpoint_root = try chain.blockHashRoot(chain.genesis_display_hash);
    const targets = circuit.common.finalize.ComponentSizes{
        .eq = chain.expected_rows.eq,
        .qm31_ops = chain.expected_rows.qm31_ops,
        .m31_to_u32 = chain.expected_rows.m31_to_u32,
        .triple_xor = chain.expected_rows.triple_xor,
        .blake_g_gate = chain.expected_rows.blake_g,
    };
    var anchor_topology = try anchor.build(circuit.builder.NoValue, allocator, checkpoint_root, targets);
    defer anchor_topology.deinit();
    var anchor_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_topology.circuit);
    defer anchor_pp.deinit(allocator);
    const child_layout = anchor_pp.layout();
    const child_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(try friConfig(child_fri), child_layout.traceLogSize());
    const anchor_root = try anchor_pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);

    var boundary: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
    var outer_topology = try fold.fusedTopology(allocator, projection_bytes, child_layout, child_pcs, anchor_root, checkpoint_root, step, &boundary);
    defer outer_topology.deinit();
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &outer_topology, targets);
    const n_vars: u32 = @intCast(outer_topology.circuit.n_vars);
    const addresses = addressesFromWires(boundary);
    var outer_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &outer_topology.circuit, .{ .addresses = addresses });
    defer outer_pp.deinit(allocator);
    if (!outer_pp.layout().eql(&child_layout)) return error.FusedFoldPaddedGeometryMismatch;
    const statement: s31.sha_fused_private_join_profile.PublicStatement = .{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = addresses, .first_call_id = 1 },
    };
    const outer_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(try friConfig(outer_fri), @max(outer_pp.layout().traceLogSize(), 8));
    const fused_key = try native.deriveKey(allocator, profile.trustedFoldSourceDigest(), &outer_pp, n_vars, statement, outer_pcs);
    return .{ .checkpoint_root = checkpoint_root, .anchor_root = anchor_root, .fused_key = fused_key };
}

pub fn generateKeyJson(allocator: std.mem.Allocator, checkpoint_block_hash: []const u8) ![]u8 {
    if (!std.mem.eql(u8, checkpoint_block_hash, chain.genesis_display_hash)) return error.FusedFoldRequiresGenesisCheckpoint;
    const material = try deriveMaterial(allocator);
    const anchor_hex = std.fmt.bytesToHex(material.anchor_root, .lower);
    const fixed_hex = std.fmt.bytesToHex(material.fused_key.fixed_root, .lower);
    const digest_hex = std.fmt.bytesToHex(material.fused_key.digest, .lower);
    const source_hex = std.fmt.bytesToHex(material.fused_key.source_digest, .lower);
    const projection_hex = std.fmt.bytesToHex(chain.sha256(projection_bytes), .lower);
    const air_hex = std.fmt.bytesToHex(chain.sha256(air_bytes), .lower);
    const key: Key = .{
        .schema = key_schema,
        .profile = profile_name,
        .proof_magic = profile.magic,
        .checkpoint_block_hash = chain.genesis_display_hash,
        .checkpoint_root = material.checkpoint_root,
        .step = step,
        .anchor_preprocessed_root = &anchor_hex,
        .fused_fixed_root = &fixed_hex,
        .fused_key_digest = &digest_hex,
        .fused_source_digest = &source_hex,
        .sha_gate_addresses = material.fused_key.statement.config.gate_addresses,
        .n_vars = material.fused_key.n_vars,
        .padded = chain.expected_rows,
        .trace_log_size = material.fused_key.circuit_layout.traceLogSize(),
        .child_fri = child_fri,
        .outer_fri = outer_fri,
        .projection_sha256 = &projection_hex,
        .air_bundle_sha256 = &air_hex,
    };
    return std.json.Stringify.valueAlloc(allocator, key, .{});
}

pub fn validateKey(allocator: std.mem.Allocator, key_bytes: []const u8, expected_sha256: [32]u8) !VerifiedKey {
    const digest = chain.sha256(key_bytes);
    if (!std.mem.eql(u8, &digest, &expected_sha256)) return error.WrongVerificationKeyDigest;
    var parsed = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const key = parsed.value;
    if (!std.mem.eql(u8, key.schema, key_schema) or !std.mem.eql(u8, key.profile, profile_name) or
        !std.mem.eql(u8, key.proof_magic, profile.magic) or key.step != step or
        !std.meta.eql(key.padded, chain.expected_rows) or !std.meta.eql(key.child_fri, child_fri) or
        !std.meta.eql(key.outer_fri, outer_fri)) return error.InvalidFusedBitcoinKeyProfile;
    if (!std.mem.eql(u8, key.checkpoint_block_hash, chain.genesis_display_hash)) return error.FusedFoldRequiresGenesisCheckpoint;
    const material = try deriveMaterial(allocator);
    if (!std.meta.eql(key.checkpoint_root, material.checkpoint_root) or
        !sameHex(material.anchor_root, key.anchor_preprocessed_root) or
        !sameHex(material.fused_key.fixed_root, key.fused_fixed_root) or
        !sameHex(material.fused_key.digest, key.fused_key_digest) or
        !sameHex(material.fused_key.source_digest, key.fused_source_digest) or
        !std.meta.eql(key.sha_gate_addresses, material.fused_key.statement.config.gate_addresses) or
        key.n_vars != material.fused_key.n_vars or
        key.trace_log_size != material.fused_key.circuit_layout.traceLogSize() or
        !sameHex(chain.sha256(projection_bytes), key.projection_sha256) or
        !sameHex(chain.sha256(air_bytes), key.air_bundle_sha256)) return error.FusedBitcoinKeyTopologyMismatch;
    return .{ .material = material, .key_sha256 = digest };
}

fn statementWords(key: VerifiedKey, block_hash: []const u8, block_timestamp: u32) ![8]u32 {
    const current_root = try chain.blockHashRoot(block_hash);
    const times = s31.bitcoin_fold_digest.advanceTimes(s31.bitcoin_fold_digest.initialTimes(), block_timestamp);
    return s31.bitcoin_fold_digest.statementDigest(key.material.fused_key.fixed_root, step, key.material.checkpoint_root, current_root, times);
}

pub fn generateStatementJson(allocator: std.mem.Allocator, key: VerifiedKey, current_block_hash: []const u8, current_block_timestamp: u32) ![]u8 {
    const words = try statementWords(key, current_block_hash, current_block_timestamp);
    const key_hex = std.fmt.bytesToHex(key.key_sha256, .lower);
    const statement: Statement = .{
        .schema = statement_schema,
        .verification_key_sha256 = &key_hex,
        .step = step,
        .current_block_hash = current_block_hash,
        .current_block_timestamp = current_block_timestamp,
        .last_timestamps = s31.bitcoin_fold_digest.advanceTimes(s31.bitcoin_fold_digest.initialTimes(), current_block_timestamp),
        .public_words = words,
    };
    return std.json.Stringify.valueAlloc(allocator, statement, .{});
}

/// Parse named Bitcoin fields and recompute the eight raw u32 public words.
/// Keeping this separate from STARK decoding lets callers inspect a statement
/// before paying the cost of native verification.
pub fn validateStatement(allocator: std.mem.Allocator, key: VerifiedKey, statement_bytes: []const u8) ![8]QM31 {
    var parsed = try std.json.parseFromSlice(Statement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const statement = parsed.value;
    if (!std.mem.eql(u8, statement.schema, statement_schema) or !sameHex(key.key_sha256, statement.verification_key_sha256))
        return error.InvalidFusedBitcoinStatement;
    if (statement.step != step) return error.FusedFoldSupportsOnlyStepZero;
    const expected_times = s31.bitcoin_fold_digest.advanceTimes(s31.bitcoin_fold_digest.initialTimes(), statement.current_block_timestamp);
    if (!std.meta.eql(statement.last_timestamps, expected_times)) return error.InvalidFusedBitcoinTimestamps;
    const expected = try statementWords(key, statement.current_block_hash, statement.current_block_timestamp);
    if (!std.meta.eql(statement.public_words, expected)) return error.InvalidFusedBitcoinStatement;
    var outputs: [8]QM31 = undefined;
    for (expected, &outputs) |word, *output| output.* = circuit.builder.ivalue.packU32(QM31, word);
    return outputs;
}

pub fn verifyProof(allocator: std.mem.Allocator, key: VerifiedKey, statement_bytes: []const u8, proof_bytes: []const u8) !void {
    const outputs = try validateStatement(allocator, key, statement_bytes);
    return native.verifyBytes(allocator, .{ .key = key.material.fused_key, .public_outputs = &outputs }, proof_bytes);
}

/// One-call entry point when the application stores the trusted key bytes and
/// their independently pinned digest rather than a cached `VerifiedKey`.
pub fn verifyPinned(
    allocator: std.mem.Allocator,
    key_bytes: []const u8,
    pinned_key_sha256: [32]u8,
    statement_bytes: []const u8,
    proof_bytes: []const u8,
) !void {
    const key = try validateKey(allocator, key_bytes, pinned_key_sha256);
    return verifyProof(allocator, key, statement_bytes, proof_bytes);
}
