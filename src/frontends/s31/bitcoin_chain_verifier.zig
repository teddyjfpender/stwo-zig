//! Sealed-key host boundary for the experimental Bitcoin hash-chain fold.
//! A caller must pin the exact SHA256 of the key bytes. The verifier rebuilds
//! both AIR roots from the checkpoint and checks the native STARK proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const s31 = @import("stwo_s31_prototype");
const anchor = @import("bitcoin_chain_anchor.zig");
const fold = @import("bitcoin_chain_fold.zig");
const native = @import("native_verifier.zig");

const M31 = core.fields.m31.M31;
const projection_bytes = @embedFile("s31_air_projection");
const air_bytes = @embedFile("s31_air_programs");
const schema = "s31-bitcoin-chain-verification-key-v3";
const statement_schema = "s31-bitcoin-chain-statement-v2";
const profile = "bitcoin-mainnet-genesis-first-epoch-sha256d-mtp-v3";
pub const genesis_display_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
pub const first_epoch_last_step: u32 = 2014; // step 0 is block height 1.

pub const Rows = struct {
    eq: usize,
    qm31_ops: usize,
    m31_to_u32: usize,
    triple_xor: usize,
    blake_g: usize,

    fn componentSizes(self: Rows) circuit.common.finalize.ComponentSizes {
        return .{
            .eq = self.eq,
            .qm31_ops = self.qm31_ops,
            .m31_to_u32 = self.m31_to_u32,
            .triple_xor = self.triple_xor,
            .blake_g_gate = self.blake_g,
        };
    }
};
pub const expected_rows: Rows = .{
    .eq = 32768,
    .qm31_ops = 2097152,
    .m31_to_u32 = 262144,
    .triple_xor = 131072,
    .blake_g = 2097152,
};
pub const Fri = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    last_layer_degree_bound: u32,
    queries: u32,
    fold_step: u32,
};
pub const expected_fri: Fri = .{
    .pow_bits = 26,
    .log_blowup_factor = 1,
    .last_layer_degree_bound = 0,
    .queries = 70,
    .fold_step = 4,
};
pub const Key = struct {
    schema: []const u8,
    profile: []const u8,
    checkpoint_block_hash: []const u8,
    checkpoint_root: [8]u32,
    max_step: u32,
    anchor_preprocessed_root: []const u8,
    fold_preprocessed_root: []const u8,
    fold_circuit_hash: []const u8,
    padded: Rows,
    trace_log_size: u32,
    fri: Fri,
    projection_sha256: []const u8,
    air_bundle_sha256: []const u8,
};
pub const Statement = struct {
    schema: []const u8,
    verification_key_sha256: []const u8,
    step: u32,
    current_block_hash: []const u8,
    last_timestamps: [11]u32,
    public_words: [8]u32,
};
pub const Material = struct {
    checkpoint_root: [8]u32,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    anchor_root: [32]u8,
    fold_root: [32]u8,
    fold_hash: [32]u8,
};
pub const VerifiedKey = struct {
    material: Material,
    key_sha256: [32]u8,
    max_step: u32,
};

pub fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn parseDisplayHash(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidBlockHashHex;
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch return error.InvalidBlockHashHex;
    if (!std.mem.eql(u8, hex, &std.fmt.bytesToHex(bytes, .lower))) return error.NonCanonicalBlockHashHex;
    std.mem.reverse(u8, &bytes);
    return bytes;
}

pub fn blockHashRoot(display_hex: []const u8) ![8]u32 {
    const raw = try parseDisplayHash(display_hex);
    var limbs: [16]M31 = undefined;
    for (&limbs, 0..) |*limb, i|
        limb.* = M31.fromCanonical(std.mem.readInt(u16, raw[2 * i ..][0..2], .little));
    const state = s31.poseidon2.leafWords(&limbs);
    var words: [8]u32 = undefined;
    for (state, &words) |word, *out| out.* = word.toU32();
    return words;
}

pub fn deriveMaterial(allocator: std.mem.Allocator, checkpoint_display_hex: []const u8) !Material {
    const checkpoint_root = try blockHashRoot(checkpoint_display_hex);
    const targets = expected_rows.componentSizes();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(targets);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        layout.traceLogSize(),
    );
    const anchor_root = blk: {
        var ctx = try anchor.build(circuit.builder.NoValue, allocator, checkpoint_root, targets);
        defer ctx.deinit();
        var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
        defer pp.deinit(allocator);
        if (!pp.layout().eql(&layout)) return error.AnchorGeometryMismatch;
        break :blk try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    };
    var topology = try fold.topology(allocator, projection_bytes, layout, pcs, anchor_root, checkpoint_root, 0);
    defer topology.deinit();
    const raw = circuit.common.finalize.rawComponentSizes(circuit.common.preprocessed.CircuitView.fromBuilder(&topology.circuit));
    if (!std.meta.eql(raw.map(circuit.common.finalize.paddedSize), targets)) return error.FoldGeometryMismatch;
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology);
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer pp.deinit(allocator);
    if (!pp.layout().eql(&layout)) return error.FoldGeometryMismatch;
    const fold_root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const fold_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        fold_root,
    );
    return .{
        .checkpoint_root = checkpoint_root,
        .layout = layout,
        .pcs = pcs,
        .anchor_root = anchor_root,
        .fold_root = fold_root,
        .fold_hash = fold_hash,
    };
}

fn sameHex(raw: [32]u8, claimed: []const u8) bool {
    return std.mem.eql(u8, claimed, &std.fmt.bytesToHex(raw, .lower));
}

pub fn generateKeyJson(
    allocator: std.mem.Allocator,
    checkpoint_display_hex: []const u8,
    max_step: u32,
) ![]u8 {
    if (!std.mem.eql(u8, checkpoint_display_hex, genesis_display_hash)) return error.FirstEpochRequiresGenesisCheckpoint;
    if (max_step > first_epoch_last_step) return error.FirstEpochRetargetUnsupported;
    const material = try deriveMaterial(allocator, checkpoint_display_hex);
    const anchor_hex = std.fmt.bytesToHex(material.anchor_root, .lower);
    const fold_hex = std.fmt.bytesToHex(material.fold_root, .lower);
    const hash_hex = std.fmt.bytesToHex(material.fold_hash, .lower);
    const projection_hex = std.fmt.bytesToHex(sha256(projection_bytes), .lower);
    const air_hex = std.fmt.bytesToHex(sha256(air_bytes), .lower);
    const key: Key = .{
        .schema = schema,
        .profile = profile,
        .checkpoint_block_hash = checkpoint_display_hex,
        .checkpoint_root = material.checkpoint_root,
        .max_step = max_step,
        .anchor_preprocessed_root = &anchor_hex,
        .fold_preprocessed_root = &fold_hex,
        .fold_circuit_hash = &hash_hex,
        .padded = expected_rows,
        .trace_log_size = material.layout.traceLogSize(),
        .fri = expected_fri,
        .projection_sha256 = &projection_hex,
        .air_bundle_sha256 = &air_hex,
    };
    return std.json.Stringify.valueAlloc(allocator, key, .{});
}

pub fn validateKey(
    allocator: std.mem.Allocator,
    key_bytes: []const u8,
    expected_sha256: [32]u8,
) !VerifiedKey {
    const actual_digest = sha256(key_bytes);
    if (!std.mem.eql(u8, &actual_digest, &expected_sha256)) return error.WrongVerificationKeyDigest;
    var parsed = try std.json.parseFromSlice(Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const key = parsed.value;
    if (!std.mem.eql(u8, key.schema, schema) or !std.mem.eql(u8, key.profile, profile) or
        !std.meta.eql(key.padded, expected_rows) or !std.meta.eql(key.fri, expected_fri))
        return error.InvalidBitcoinChainKeyProfile;
    if (!std.mem.eql(u8, key.checkpoint_block_hash, genesis_display_hash)) return error.FirstEpochRequiresGenesisCheckpoint;
    if (key.max_step > first_epoch_last_step) return error.FirstEpochRetargetUnsupported;
    const material = try deriveMaterial(allocator, key.checkpoint_block_hash);
    if (!std.meta.eql(key.checkpoint_root, material.checkpoint_root) or
        key.trace_log_size != material.layout.traceLogSize() or
        !sameHex(material.anchor_root, key.anchor_preprocessed_root) or
        !sameHex(material.fold_root, key.fold_preprocessed_root) or
        !sameHex(material.fold_hash, key.fold_circuit_hash) or
        !sameHex(sha256(projection_bytes), key.projection_sha256) or
        !sameHex(sha256(air_bytes), key.air_bundle_sha256))
        return error.BitcoinChainKeyTopologyMismatch;
    return .{ .material = material, .key_sha256 = actual_digest, .max_step = key.max_step };
}

pub fn generateStatementJson(
    allocator: std.mem.Allocator,
    key: VerifiedKey,
    step: u32,
    current_block_hash: []const u8,
    last_timestamps: [11]u32,
) ![]u8 {
    if (step > key.max_step) return error.BitcoinChainStepExceedsKeyLimit;
    const current_root = try blockHashRoot(current_block_hash);
    const words = try s31.bitcoin_fold_digest.statementDigest(
        key.material.fold_root,
        step,
        key.material.checkpoint_root,
        current_root,
        last_timestamps,
    );
    const key_hex = std.fmt.bytesToHex(key.key_sha256, .lower);
    const statement: Statement = .{
        .schema = statement_schema,
        .verification_key_sha256 = &key_hex,
        .step = step,
        .current_block_hash = current_block_hash,
        .last_timestamps = last_timestamps,
        .public_words = words,
    };
    return std.json.Stringify.valueAlloc(allocator, statement, .{});
}

pub fn verifyProof(
    allocator: std.mem.Allocator,
    key: VerifiedKey,
    statement_bytes: []const u8,
    proof_bytes: []const u8,
) !void {
    var parsed = try std.json.parseFromSlice(Statement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const statement = parsed.value;
    if (!std.mem.eql(u8, statement.schema, statement_schema) or
        !sameHex(key.key_sha256, statement.verification_key_sha256))
        return error.InvalidBitcoinChainStatement;
    if (statement.step > key.max_step) return error.BitcoinChainStepExceedsKeyLimit;
    const current_root = try blockHashRoot(statement.current_block_hash);
    const expected = try s31.bitcoin_fold_digest.statementDigest(
        key.material.fold_root,
        statement.step,
        key.material.checkpoint_root,
        current_root,
        statement.last_timestamps,
    );
    if (!std.meta.eql(statement.public_words, expected)) return error.InvalidBitcoinChainStatement;
    var bundle = try cpu.air.parse(allocator, air_bytes);
    defer bundle.deinit();
    try native.verify(
        allocator,
        &key.material.layout,
        &bundle,
        key.material.pcs,
        key.material.fold_root,
        key.material.fold_hash,
        expected,
        proof_bytes,
    );
}
