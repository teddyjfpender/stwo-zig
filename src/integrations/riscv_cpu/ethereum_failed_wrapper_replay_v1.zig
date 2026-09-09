//! Cold diagnostic replay of a failed raw proof. Custody metadata never becomes
//! an artifact statement or a freshness receipt. The ordinary kernel rebuilds
//! authority and verifies the raw bytes before returning any verified value.
const std = @import("std");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const proof_mod = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const METADATA_ENV = "STWO_ETHEREUM_FAILED_WRAPPER_METADATA";
const MAX_METADATA_BYTES = 1024 * 1024;

const Metadata = struct {
    format_version: u32,
    verified: bool,
    failure: []const u8,
    proof_sha256: []const u8,
    proof_bytes: usize,
    session: artifact.SessionV1,
    interaction_pow_nonce: u64,
};

pub const UnverifiedCase = opaque {
    pub fn load(allocator: std.mem.Allocator, metadata_path: []const u8) !*UnverifiedCase {
        const encoded = try std.fs.cwd().readFileAlloc(allocator, metadata_path, MAX_METADATA_BYTES);
        defer allocator.free(encoded);
        const parsed = try std.json.parseFromSlice(Metadata, allocator, encoded, .{});
        defer parsed.deinit();
        const metadata = parsed.value;
        try validateFlags(metadata.format_version, metadata.verified, metadata.failure);
        if (metadata.proof_bytes == 0 or metadata.proof_bytes > artifact.MAX_CANONICAL_PROOF_BYTES)
            return error.InvalidFailedWrapperCustody;
        const digest = try parseDigest(metadata.proof_sha256);
        try metadata.session.validate();
        if (metadata.session.source_kind != .ethereum_incremental_leaf_wrapper_v4)
            return error.InvalidFailedWrapperSessionKind;
        const case_digest = caseIdentity(digest, metadata.session.identity_sha256, metadata.interaction_pow_nonce);
        const case_hex = std.fmt.bytesToHex(case_digest, .lower);
        const directory_path = std.fs.path.dirname(metadata_path) orelse return error.InvalidFailedWrapperCustody;
        if (!std.mem.eql(u8, std.fs.path.basename(directory_path), &case_hex)) return error.InvalidFailedWrapperCustody;
        var metadata_name: [69]u8 = undefined;
        _ = try std.fmt.bufPrint(&metadata_name, "{s}.json", .{metadata.proof_sha256});
        if (!std.mem.eql(u8, std.fs.path.basename(metadata_path), &metadata_name)) return error.InvalidFailedWrapperCustody;
        var directory = try std.fs.cwd().openDir(directory_path, .{});
        defer directory.close();
        var proof_name: [68]u8 = undefined;
        _ = try std.fmt.bufPrint(&proof_name, "{s}.bin", .{metadata.proof_sha256});
        const bytes = try directory.readFileAlloc(allocator, &proof_name, artifact.MAX_CANONICAL_PROOF_BYTES);
        errdefer allocator.free(bytes);
        try validateProofCustody(digest, metadata.proof_bytes, bytes);
        const storage = try allocator.create(Storage);
        storage.* = .{ .allocator = allocator, .proof_bytes = bytes, .session = metadata.session, .interaction_pow_nonce = metadata.interaction_pow_nonce, .proof_digest = digest };
        return @ptrCast(storage);
    }

    pub fn deinit(self: *UnverifiedCase) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        const allocator = storage.allocator;
        allocator.free(storage.proof_bytes);
        allocator.destroy(storage);
    }
    pub fn proofBytes(self: *const UnverifiedCase) []const u8 {
        return data(self).proof_bytes;
    }
    pub fn session(self: *const UnverifiedCase) *const artifact.SessionV1 {
        return &data(self).session;
    }
    pub fn nonce(self: *const UnverifiedCase) u64 {
        return data(self).interaction_pow_nonce;
    }
    const Storage = struct {
        allocator: std.mem.Allocator,
        proof_bytes: []u8,
        session: artifact.SessionV1,
        interaction_pow_nonce: u64,
        proof_digest: [32]u8,
    };
    fn data(self: *const UnverifiedCase) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};

/// `materialized` must be freshly reconstructed from independently reopened
/// native leaf artifacts and the complete program. No producer state is used.
/// A different rejection is not evidence that the retained OODS failure was
/// reproduced; malformed custody or changed session/profile must fail the gate.
pub fn replayFromEnvironment(comptime Engine: type, allocator: std.mem.Allocator, materialized: anytype) !void {
    const metadata_path = try std.process.getEnvVarOwned(allocator, METADATA_ENV);
    defer allocator.free(metadata_path);
    const retained = try UnverifiedCase.load(allocator, metadata_path);
    defer retained.deinit();
    try replayOodsRejection(Engine, allocator, materialized, retained);
}

pub fn replayOodsRejection(comptime Engine: type, allocator: std.mem.Allocator, materialized: anytype, retained: *const UnverifiedCase) !void {
    const Kernel = proof_mod.Types(Engine).CoreV4.KernelV4;
    const digest = std.fmt.bytesToHex(UnverifiedCase.data(retained).proof_digest, .lower);
    var fresh = Kernel.verifyDiagnosticProofBytes(allocator, .{ .materialized = materialized }, retained.session(), retained.nonce(), retained.proofBytes()) catch |err| {
        std.debug.print("ETHEREUM_FAILED_WRAPPER_REPLAY sha256={s} verifier_error={s} fresh_inputs=true verified=false\n", .{ digest, @errorName(err) });
        if (err != error.OodsNotMatching) return err;
        return;
    };
    defer fresh.deinit();
    std.debug.print("ETHEREUM_FAILED_WRAPPER_REPLAY sha256={s} outcome=unexpected_verification_success fresh_inputs=true\n", .{digest});
    return error.FailedWrapperUnexpectedlyVerified;
}

fn validateFlags(format: u32, verified: bool, failure: []const u8) !void {
    if (format != 1 or verified or !std.mem.eql(u8, failure, "ConstraintsNotSatisfied"))
        return error.InvalidFailedWrapperCustody;
}
fn parseDigest(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidFailedWrapperCustody;
    for (hex) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidFailedWrapperCustody;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, hex);
    return digest;
}
fn validateProofCustody(expected: [32]u8, byte_count: usize, bytes: []const u8) !void {
    var actual: [32]u8 = undefined;
    Sha256.hash(bytes, &actual, .{});
    if (bytes.len == 0 or bytes.len != byte_count or !std.meta.eql(actual, expected))
        return error.InvalidFailedWrapperCustody;
}
fn caseIdentity(proof_digest: [32]u8, session_identity: [32]u8, nonce: u64) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/failed-wrapper-custody/v1\x00");
    hash.update(&proof_digest);
    hash.update(&session_identity);
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, nonce, .little);
    hash.update(&encoded);
    return hash.finalResult();
}

test "Ethereum failed wrapper replay rejects altered custody and success metadata" {
    // Custody-only probe. The separate retained-proof gate must run the actual
    // kernel with fresh native inputs and observe OodsNotMatching.
    const bytes = "unverified custody probe";
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualDeep(digest, try parseDigest(&hex));
    try validateFlags(1, false, "ConstraintsNotSatisfied");
    try std.testing.expectError(error.InvalidFailedWrapperCustody, validateFlags(2, false, "ConstraintsNotSatisfied"));
    try std.testing.expectError(error.InvalidFailedWrapperCustody, validateFlags(1, true, "ConstraintsNotSatisfied"));
    try std.testing.expectError(error.InvalidFailedWrapperCustody, validateFlags(1, false, "OtherFailure"));
    try validateProofCustody(digest, bytes.len, bytes);
    try std.testing.expectError(error.InvalidFailedWrapperCustody, validateProofCustody(digest, bytes.len + 1, bytes));
    var changed = bytes.*;
    changed[0] ^= 1;
    try std.testing.expectError(error.InvalidFailedWrapperCustody, validateProofCustody(digest, bytes.len, &changed));
    try std.testing.expectError(error.InvalidFailedWrapperCustody, parseDigest("../proof"));
    var bad_hex = hex;
    bad_hex[0] = 'A';
    try std.testing.expectError(error.InvalidFailedWrapperCustody, parseDigest(&bad_hex));
    const identity = caseIdentity(digest, .{7} ** 32, 11);
    try std.testing.expect(!std.meta.eql(identity, caseIdentity(digest, .{7} ** 32, 12)));
    try std.testing.expect(!std.meta.eql(identity, caseIdentity(digest, .{8} ** 32, 11)));
}
