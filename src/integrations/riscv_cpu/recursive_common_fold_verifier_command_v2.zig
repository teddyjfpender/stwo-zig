//! Durable inputs and a fresh-process entry point for explicit-key verification.
//! The expected key hash is supplied separately by the caller. Exporting a key
//! from a proof fixture does not independently authenticate its circuit.
const std = @import("std");
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const public = @import("recursive_field_node_public_v2.zig");
const cohort = @import("recursive_common_fold_secure_cohort_v2.zig");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const MAX_JSON_BYTES: usize = 1024 * 1024;

pub const KeyFile = struct {
    format_version: u32,
    common_fold_schema: u16,
    key: verifier.Key,
};
pub const EthereumKeyFile = struct {
    format_version: u32,
    common_fold_schema: u16,
    key: verifier.EthereumKeyV1,
};
pub const PublicInputs = struct {
    format_version: u32,
    common_fold_schema: u16,
    node: public.NodePublicV2,
    claims: verifier.Claims,
    interaction_pow_nonce: u64,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub fn decodeKey(allocator: std.mem.Allocator, bytes: []const u8, expected_sha256: [32]u8) !verifier.Key {
    return decodeKeyFile(KeyFile, allocator, bytes, expected_sha256);
}

pub fn decodeEthereumKey(allocator: std.mem.Allocator, bytes: []const u8, expected_sha256: [32]u8) !verifier.EthereumKeyV1 {
    return decodeKeyFile(EthereumKeyFile, allocator, bytes, expected_sha256);
}

fn decodeKeyFile(comptime File: type, allocator: std.mem.Allocator, bytes: []const u8, expected_sha256: [32]u8) !@FieldType(File, "key") {
    if (bytes.len == 0 or bytes.len > MAX_JSON_BYTES) return error.VerifierJsonSizeMismatch;
    if (!std.mem.eql(u8, &hash(bytes), &expected_sha256)) return error.VerifierKeyHashMismatch;
    const value = try decode(File, allocator, bytes);
    _ = try value.key.validate();
    return value.key;
}

pub fn decodeInputs(allocator: std.mem.Allocator, bytes: []const u8) !PublicInputs {
    const value = try decode(PublicInputs, allocator, bytes);
    try value.node.validate();
    if (value.proof_bytes == 0 or value.proof_bytes > artifact.MAX_CANONICAL_PROOF_BYTES) return error.VerifierProofSizeMismatch;
    return value;
}

fn decode(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !T {
    if (bytes.len == 0 or bytes.len > MAX_JSON_BYTES) return error.VerifierJsonSizeMismatch;
    const parsed = try std.json.parseFromSlice(T, allocator, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
    defer parsed.deinit();
    const value = parsed.value;
    if (value.format_version != 1 or value.common_fold_schema != cohort.SCHEMA_VERSION) return error.VerifierInputVersionMismatch;
    // These transport types contain only fixed arrays, tuples and scalars.
    return value;
}

pub fn writeBundle(allocator: std.mem.Allocator, path: []const u8, key: verifier.Key, node: public.NodePublicV2, claims: verifier.Claims, nonce: u64, proof: []const u8) ![32]u8 {
    return writeBundleFile(KeyFile, allocator, path, key, node, claims, nonce, proof);
}

pub fn writeEthereumBundle(allocator: std.mem.Allocator, path: []const u8, key: verifier.EthereumKeyV1, node: public.NodePublicV2, claims: verifier.Claims, nonce: u64, proof: []const u8) ![32]u8 {
    return writeBundleFile(EthereumKeyFile, allocator, path, key, node, claims, nonce, proof);
}

fn writeBundleFile(comptime File: type, allocator: std.mem.Allocator, path: []const u8, key: @FieldType(File, "key"), node: public.NodePublicV2, claims: verifier.Claims, nonce: u64, proof: []const u8) ![32]u8 {
    _ = try key.validate();
    try node.validate();
    if (proof.len == 0 or proof.len > artifact.MAX_CANONICAL_PROOF_BYTES) return error.VerifierProofSizeMismatch;
    const key_bytes = try std.json.Stringify.valueAlloc(allocator, File{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .key = key }, .{});
    defer allocator.free(key_bytes);
    const input_bytes = try std.json.Stringify.valueAlloc(allocator, PublicInputs{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .node = node, .claims = claims, .interaction_pow_nonce = nonce, .proof_bytes = proof.len, .proof_sha256 = hash(proof) }, .{});
    defer allocator.free(input_bytes);
    if (key_bytes.len > MAX_JSON_BYTES or input_bytes.len > MAX_JSON_BYTES) return error.VerifierJsonSizeMismatch;
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    if (File == EthereumKeyFile) {
        const io = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
        try io.writeReplayFile(dir, "key.json", key_bytes);
        try io.writeReplayFile(dir, "inputs.json", input_bytes);
        try io.writeReplayFile(dir, "proof.bin", proof);
    } else {
        try dir.writeFile(.{ .sub_path = "key.json", .data = key_bytes });
        try dir.writeFile(.{ .sub_path = "inputs.json", .data = input_bytes });
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = proof });
    }
    return hash(key_bytes);
}

const Receipt = struct {
    verified: bool = true,
    common_fold_schema: u16 = cohort.SCHEMA_VERSION,
    proof_bytes: usize,
    verify_ns: u64,
    request_ns: u64 = 0,
    output_digest: [8]u32,
    transcript_digest: [8]u32,
    captured_shape: bool = false,
};

fn verifyPaths(comptime File: type, allocator: std.mem.Allocator, args: []const []const u8) !Receipt {
    if (args[1].len != 64) return error.InvalidExpectedKeyHash;
    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, args[1]) catch return error.InvalidExpectedKeyHash;
    const key_json = try std.fs.cwd().readFileAlloc(allocator, args[0], MAX_JSON_BYTES);
    defer allocator.free(key_json);
    const key = try decodeKeyFile(File, allocator, key_json, expected);
    const inputs_json = try std.fs.cwd().readFileAlloc(allocator, args[2], MAX_JSON_BYTES);
    defer allocator.free(inputs_json);
    const inputs = try decodeInputs(allocator, inputs_json);
    const proof = try std.fs.cwd().readFileAlloc(allocator, args[3], inputs.proof_bytes);
    defer allocator.free(proof);
    if (proof.len != inputs.proof_bytes or !std.mem.eql(u8, &hash(proof), &inputs.proof_sha256)) return error.VerifierProofIdentityMismatch;
    var timer = try std.time.Timer.start();
    var capture: verifier.ProofCapture = undefined;
    const capture_shape = args.len == 5;
    const terminal = if (File == EthereumKeyFile)
        if (capture_shape)
            try key.verifyWithCapture(allocator, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof, &capture)
        else
            try key.verify(allocator, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof)
    else if (capture_shape)
        try verifier.verifyWithCapture(allocator, &key, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof, &capture)
    else
        try verifier.verify(allocator, &key, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof);
    const verify_ns = timer.read();
    defer if (capture_shape) capture.deinit(allocator);
    if (capture_shape) try writeShape(allocator, args[4], if (File == EthereumKeyFile) &key.key else &key, expected, inputs.proof_sha256, &capture);
    return .{ .proof_bytes = proof.len, .verify_ns = verify_ns, .output_digest = inputs.node.output_digest, .transcript_digest = terminal, .captured_shape = capture_shape };
}

/// Export only after successful verification. The JSON is diagnostic transport;
/// importing it cannot mint a live child or production registry admission.
fn writeShape(allocator: std.mem.Allocator, path: []const u8, key: *const verifier.Key, key_hash: [32]u8, proof_hash: [32]u8, capture: *const verifier.ProofCapture) !void {
    const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
    const protocol = @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1.secureParent();
    const logs = try key.validate();
    if (capture.column_log_sizes.len != 4 or capture.column_log_sizes[3].len == 0) return error.InvalidFixedProofShape;
    const composition_log = capture.column_log_sizes[3][0];
    for (capture.column_log_sizes[3]) |log| if (log != composition_log) return error.InvalidFixedProofShape;
    const degree = try std.math.sub(u32, composition_log, protocol.fri_log_blowup_factor);
    const shape = try @import("recursive_fixed_proof_shape_v3.zig").sealFromCapture(capture, manifest.COMPONENT_COUNT, std.math.cast(u8, degree) orelse return error.InvalidFixedProofShape, try manifest.tableLayoutIdentityForDerivedManifest(&key.manifest, logs));
    try shape.validateAgainstPcs(protocol.fri_log_blowup_factor, protocol.fri_query_count, protocol.fri_fold_step, protocol.fri_log_last_layer_degree_bound);
    const bytes = try std.json.Stringify.valueAlloc(allocator, .{ .format_version = @as(u32, 1), .common_fold_schema = cohort.SCHEMA_VERSION, .key_sha256 = key_hash, .proof_sha256 = proof_hash, .shape = shape }, .{});
    defer allocator.free(bytes);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const ethereum = args.len > 1 and std.mem.eql(u8, args[1], "--ethereum-v1");
    const paths = args[if (ethereum) @as(usize, 2) else 1..];
    if (paths.len != 4 and paths.len != 5) {
        std.debug.print("usage: recursive-common-fold-verify-v2 [--ethereum-v1] KEY_JSON EXPECTED_KEY_SHA256 INPUTS_JSON PROOF_BIN [SHAPE_JSON]\n", .{});
        return error.InvalidArguments;
    }
    var timer = try std.time.Timer.start();
    var receipt = if (ethereum) try verifyPaths(EthereumKeyFile, allocator, paths) else try verifyPaths(KeyFile, allocator, paths);
    receipt.request_ns = timer.read();
    const output = if (ethereum)
        try std.json.Stringify.valueAlloc(allocator, .{ .endpoint = "verified_ethereum_field_fold", .ethereum_profile_version = @as(u32, 1), .verification = receipt }, .{})
    else
        try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(output);
    try std.fs.File.stdout().writeAll(output);
    try std.fs.File.stdout().writeAll("\n");
}

fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

test "common-fold verifier transport authenticates key and rejects version drift" {
    const allocator = std.testing.allocator;
    const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
    var logs = [_]u32{4} ** 36;
    logs[34] = @import("recursive_common_fold_field_public_v2.zig").MINIMUM_POSEIDON_LOG_SIZE;
    logs[35] = 16;
    var key = verifier.Key{ .manifest = try manifest.buildForDerivedLogSizes(logs), .parameters = undefined, .preprocessed_root = .{1} ** 8, .poseidon_rows = 1 };
    inline for (&key.parameters) |*parameters| @memset(parameters, @import("stwo_core").fields.m31.M31.zero());
    const encoded = try std.json.Stringify.valueAlloc(allocator, KeyFile{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .key = key }, .{});
    defer allocator.free(encoded);
    const decoded = try decodeKey(allocator, encoded, hash(encoded));
    try std.testing.expectEqualDeep(key, decoded);
    try std.testing.expectError(error.VerifierKeyHashMismatch, decodeKey(allocator, encoded, .{0} ** 32));
    const stale = try std.json.Stringify.valueAlloc(allocator, KeyFile{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION - 1, .key = key }, .{});
    defer allocator.free(stale);
    try std.testing.expectError(error.VerifierInputVersionMismatch, decodeKey(allocator, stale, hash(stale)));
    const missing_version = try std.json.Stringify.valueAlloc(allocator, .{ .key = key }, .{});
    defer allocator.free(missing_version);
    try std.testing.expectError(error.MissingField, decodeKey(allocator, missing_version, hash(missing_version)));
    const node = try @import("recursive_common_fold_field_public_v2_test.zig").emptyLeaf(210, "verifier-transport");
    const Q = @import("stwo_core").fields.qm31.QM31;
    const inputs = PublicInputs{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .node = node, .claims = .{ .values = .{Q.zero()} ** 36, .poseidon_partials = .{Q.zero()} ** 2 }, .interaction_pow_nonce = 0xffffffffffffffff, .proof_bytes = 1, .proof_sha256 = hash("x") };
    const input_json = try std.json.Stringify.valueAlloc(allocator, inputs, .{});
    defer allocator.free(input_json);
    try std.testing.expectEqualDeep(inputs, try decodeInputs(allocator, input_json));

    // The Ethereum mode must admit its own namespace explicitly; neither key
    // transport may silently reinterpret the other profile.
    const ethereum_key = verifier.EthereumKeyV1{ .key = key };
    const ethereum_json = try std.json.Stringify.valueAlloc(allocator, EthereumKeyFile{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .key = ethereum_key }, .{});
    defer allocator.free(ethereum_json);
    try std.testing.expectEqualDeep(ethereum_key, try decodeEthereumKey(allocator, ethereum_json, hash(ethereum_json)));
    try std.testing.expectError(error.VerifierKeyHashMismatch, decodeEthereumKey(allocator, ethereum_json, .{0} ** 32));
    if (decodeKey(allocator, ethereum_json, hash(ethereum_json))) |_| return error.EthereumKeyAcceptedAsLegacy else |_| {}
    if (decodeEthereumKey(allocator, encoded, hash(encoded))) |_| return error.LegacyKeyAcceptedAsEthereum else |_| {}
    var wrong_profile = ethereum_key;
    wrong_profile.execution_profile += 1;
    const wrong_json = try std.json.Stringify.valueAlloc(allocator, EthereumKeyFile{ .format_version = 1, .common_fold_schema = cohort.SCHEMA_VERSION, .key = wrong_profile }, .{});
    defer allocator.free(wrong_json);
    try std.testing.expectError(error.InvalidEthereumFoldVerifierKey, decodeEthereumKey(allocator, wrong_json, hash(wrong_json)));

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const pin = try writeEthereumBundle(allocator, path, ethereum_key, node, inputs.claims, inputs.interaction_pow_nonce, "x");
    try std.testing.expectEqualDeep(hash(ethereum_json), pin);
    try std.testing.expectEqualDeep(pin, try writeEthereumBundle(allocator, path, ethereum_key, node, inputs.claims, inputs.interaction_pow_nonce, "x"));
    try std.testing.expectError(error.WrapperReplayContentMismatch, writeEthereumBundle(allocator, path, ethereum_key, node, inputs.claims, inputs.interaction_pow_nonce, "changed"));
    const retained_inputs = try temporary.dir.readFileAlloc(allocator, "inputs.json", MAX_JSON_BYTES);
    defer allocator.free(retained_inputs);
    try std.testing.expectEqualDeep(inputs, try decodeInputs(allocator, retained_inputs));
}
