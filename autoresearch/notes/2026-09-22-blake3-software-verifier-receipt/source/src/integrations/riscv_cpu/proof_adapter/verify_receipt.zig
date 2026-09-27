//! Canonical machine-readable result for independent RISC-V verification.

const std = @import("std");

pub const Input = struct {
    artifact_kind: []const u8,
    artifact_schema_version: u32,
    release_status: []const u8,
    security_policy: []const u8,
    statement_sha256: [32]u8,
    proof_bytes: usize,
    proof_sha256: [32]u8,
    transcript_state_blake2s: [32]u8 = [_]u8{0} ** 32,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: [32]u8,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    if (input.artifact_schema_version != 4) return error.ProofSuiteMismatch;
    const statement_hex = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const proof_hex = std.fmt.bytesToHex(input.proof_sha256, .lower);
    const transcript_state_hex = std.fmt.bytesToHex(input.transcript_state_blake2s, .lower);
    const executable_hex = std.fmt.bytesToHex(input.executable_sha256, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = "riscv_verify_v1",
        .status = "verified",
        .artifact_kind = input.artifact_kind,
        .artifact_schema_version = input.artifact_schema_version,
        .release_status = input.release_status,
        .security_policy = input.security_policy,
        .statement_sha256 = &statement_hex,
        .proof_bytes = input.proof_bytes,
        .proof_sha256 = &proof_hex,
        .transcript_state_blake2s = &transcript_state_hex,
        .implementation_commit = input.implementation_commit,
        .implementation_dirty = input.implementation_dirty,
        .executable_sha256 = &executable_hex,
    }, .{});
}

/// A completed canonical channel supplies the receipt; envelope admission must
/// agree before JSON allocation. Legacy output remains byte-for-byte stable.
pub fn encodeWithReceipt(allocator: std.mem.Allocator, input: Input, receipt: anytype) ![]u8 {
    const suite = @tagName(receipt.suite);
    if (std.mem.eql(u8, suite, "blake2s")) {
        if (receipt.version != 1 or input.artifact_schema_version != 4)
            return error.ProofSuiteMismatch;
        var legacy = input;
        legacy.transcript_state_blake2s = receipt.digest;
        return encode(allocator, legacy);
    }
    if (!std.mem.eql(u8, suite, "blake3") or receipt.version != 2 or
        input.artifact_schema_version != 5) return error.ProofSuiteMismatch;
    const statement_hex = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const proof_hex = std.fmt.bytesToHex(input.proof_sha256, .lower);
    const transcript_hex = std.fmt.bytesToHex(receipt.digest, .lower);
    const executable_hex = std.fmt.bytesToHex(input.executable_sha256, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = "riscv_verify_v2",
        .status = "verified",
        .artifact_kind = input.artifact_kind,
        .artifact_schema_version = input.artifact_schema_version,
        .release_status = input.release_status,
        .security_policy = input.security_policy,
        .statement_sha256 = &statement_hex,
        .proof_bytes = input.proof_bytes,
        .proof_sha256 = &proof_hex,
        .transcript_receipt = .{ .suite = suite, .version = receipt.version, .digest = &transcript_hex },
        .implementation_commit = input.implementation_commit,
        .implementation_dirty = input.implementation_dirty,
        .executable_sha256 = &executable_hex,
    }, .{});
}

test "verification receipt is one canonical JSON object" {
    const encoded = try encode(std.testing.allocator, .{
        .artifact_kind = "stwo_riscv_proof",
        .artifact_schema_version = 4,
        .release_status = "not_release_gated",
        .security_policy = "functional",
        .statement_sha256 = [_]u8{0xab} ** 32,
        .proof_bytes = 17,
        .proof_sha256 = [_]u8{0xcd} ** 32,
        .transcript_state_blake2s = [_]u8{0xef} ** 32,
        .implementation_commit = "12" ** 20,
        .implementation_dirty = false,
        .executable_sha256 = [_]u8{0x34} ** 32,
    });
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqualStrings(
        "{\"schema\":\"riscv_verify_v1\",\"status\":\"verified\"," ++
            "\"artifact_kind\":\"stwo_riscv_proof\",\"artifact_schema_version\":4," ++
            "\"release_status\":\"not_release_gated\",\"security_policy\":\"functional\"," ++
            "\"statement_sha256\":\"" ++ "ab" ** 32 ++ "\",\"proof_bytes\":17," ++
            "\"proof_sha256\":\"" ++ "cd" ** 32 ++ "\"," ++
            "\"transcript_state_blake2s\":\"" ++ "ef" ** 32 ++ "\"," ++
            "\"implementation_commit\":\"" ++ "12" ** 20 ++ "\"," ++
            "\"implementation_dirty\":false,\"executable_sha256\":\"" ++
            "34" ** 32 ++ "\"}",
        encoded,
    );

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
}

test "versioned verifier receipt preserves legacy and rejects suite relabeling" {
    const allocator = std.testing.allocator;
    var input = Input{
        .artifact_kind = "stwo_riscv_proof", .artifact_schema_version = 4,
        .release_status = "not_release_gated", .security_policy = "secure",
        .statement_sha256 = [_]u8{1} ** 32, .proof_bytes = 17,
        .proof_sha256 = [_]u8{2} ** 32, .transcript_state_blake2s = [_]u8{3} ** 32,
        .implementation_commit = "12" ** 20, .implementation_dirty = false,
        .executable_sha256 = [_]u8{4} ** 32,
    };
    const Receipt = struct { suite: enum { blake2s, blake3, unknown }, version: u16, digest: [32]u8 };
    var receipt = Receipt{ .suite = .blake2s, .version = 1, .digest = input.transcript_state_blake2s };
    const old = try encode(allocator, input);
    defer allocator.free(old);
    const legacy = try encodeWithReceipt(allocator, input, receipt);
    defer allocator.free(legacy);
    try std.testing.expectEqualStrings(old, legacy);
    receipt.suite = .blake3;
    receipt.version = 2;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.ProofSuiteMismatch, encodeWithReceipt(failing.allocator(), input, receipt));
    input.artifact_schema_version = 5;
    try std.testing.expectError(error.ProofSuiteMismatch, encode(failing.allocator(), input));
    const modern = try encodeWithReceipt(allocator, input, receipt);
    defer allocator.free(modern);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, modern, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("riscv_verify_v2", object.get("schema").?.string);
    try std.testing.expect(!object.contains("transcript_state_blake2s"));
    const transcript = object.get("transcript_receipt").?.object;
    try std.testing.expectEqualStrings("blake3", transcript.get("suite").?.string);
    try std.testing.expectEqual(@as(i64, 2), transcript.get("version").?.integer);
    try std.testing.expectEqualStrings("03" ** 32, transcript.get("digest").?.string);
    receipt.version = 1;
    try std.testing.expectError(error.ProofSuiteMismatch, encodeWithReceipt(failing.allocator(), input, receipt));
    receipt.suite = .unknown;
    try std.testing.expectError(error.ProofSuiteMismatch, encodeWithReceipt(failing.allocator(), input, receipt));
}
