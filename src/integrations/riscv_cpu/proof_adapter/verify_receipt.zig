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
    transcript_state_blake2s: [32]u8,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: [32]u8,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
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
