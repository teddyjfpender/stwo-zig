//! Product verification route for the full-width BLAKE3 base artifact.
const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const artifact_validation = @import("artifact_validation.zig");
const pcs_profile = @import("pcs_profile.zig");
const artifact = stwo.frontends.riscv.prover_mod.blake3_execution_artifact;
pub const hasMagic = artifact.hasMagic;

pub fn verifyPath(comptime Engine: type, a: std.mem.Allocator, path: []const u8, policy: pcs_profile.Protocol, expected: [32]u8, elf_path: []const u8, input_path: ?[]const u8) !void {
    const suite = stwo.core.proof_suites.Blake3;
    if (comptime Engine.Hasher != suite.Hasher or Engine.Channel != suite.Channel or Engine.MerkleChannel != suite.MerkleChannel) return error.ProofSuiteMismatch;
    const limits = artifact.Limits{};
    const raw = try std.fs.cwd().readFileAlloc(a, path, limits.max_bytes);
    defer a.free(raw);
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, limits.max_elf_bytes);
    defer a.free(elf);
    const input: []const u8 = if (input_path) |input_file| try std.fs.cwd().readFileAlloc(a, input_file, limits.manifest.statement.max_input_bytes) else &.{};
    defer if (input_path != null) a.free(input);
    if (comptime @hasDecl(Engine, "warmup")) try Engine.warmup();
    const transcript = try artifact.ForBackend(Engine.Backend).verify(a, raw, expected, pcs_profile.select(policy), elf, input, limits);
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &proof_digest, .{});
    const process = try artifact_validation.measureProcessIdentity(a);
    const statement_hex = std.fmt.bytesToHex(expected, .lower);
    const proof_hex = std.fmt.bytesToHex(proof_digest, .lower);
    const transcript_hex = std.fmt.bytesToHex(transcript, .lower);
    const executable_hex = std.fmt.bytesToHex(process.executable_sha256, .lower);
    const receipt = try std.json.Stringify.valueAlloc(a, .{
        .schema = "riscv_full_width_verify_v1",
        .status = "verified",
        .artifact_magic = artifact.MAGIC,
        .proof_suite = "blake3",
        .release_status = "experimental_full_width",
        .security_policy = @tagName(policy),
        .statement_blake3 = &statement_hex,
        .proof_bytes = raw.len,
        .proof_sha256 = &proof_hex,
        .transcript_digest_blake3 = &transcript_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = &executable_hex,
    }, .{});
    defer a.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}
