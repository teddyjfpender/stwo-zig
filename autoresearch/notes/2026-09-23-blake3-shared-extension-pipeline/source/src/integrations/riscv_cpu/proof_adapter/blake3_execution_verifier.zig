//! Product verification route for the full-width BLAKE3 base artifact.
const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const artifact_validation = @import("artifact_validation.zig");
const pcs_profile = @import("pcs_profile.zig");
pub const hasMagic = stwo.frontends.riscv.prover_mod.blake3_execution_artifact.hasMagic;

pub fn verifyPath(comptime Engine: type, a: std.mem.Allocator, path: []const u8, policy: pcs_profile.Protocol, expected: [32]u8, elf_path: []const u8, input_path: ?[]const u8) !void {
    return verifyProfile(Engine, false, a, path, policy, expected, elf_path, input_path);
}
pub fn verifyProfile(comptime Engine: type, comptime ethereum: bool, a: std.mem.Allocator, path: []const u8, policy: pcs_profile.Protocol, expected: [32]u8, elf_path: []const u8, input_path: ?[]const u8) !void {
    return verifyForExecutionProfile(Engine, if (ethereum) .rv32im_zkvm_ethereum_v1 else .rv32im_zkvm_v1, a, path, policy, expected, elf_path, input_path);
}
pub fn verifyCspPath(comptime Engine: type, a: std.mem.Allocator, path: []const u8, expected: [32]u8, elf_path: []const u8, input_path: []const u8) !void {
    return verifyInternal(Engine, .rv32im_zkvm_ethereum_v1, true, a, path, .secure, expected, elf_path, input_path);
}
pub fn verifyForExecutionProfile(comptime Engine: type, comptime profile: stwo.frontends.riscv.isa.execution_profile.ExecutionProfile, a: std.mem.Allocator, path: []const u8, policy: pcs_profile.Protocol, expected: [32]u8, elf_path: []const u8, input_path: ?[]const u8) !void {
    return verifyInternal(Engine, profile, false, a, path, policy, expected, elf_path, input_path);
}
fn verifyInternal(comptime Engine: type, comptime profile: stwo.frontends.riscv.isa.execution_profile.ExecutionProfile, comptime csp_ecdsa: bool, a: std.mem.Allocator, path: []const u8, policy: pcs_profile.Protocol, expected: [32]u8, elf_path: []const u8, input_path: ?[]const u8) !void {
    const artifact = stwo.frontends.riscv.prover_mod.blake3_profile_artifact.ForExecutionProfile(profile);
    const suite = stwo.core.proof_suites.Blake3;
    if (comptime Engine.Hasher != suite.Hasher or Engine.Channel != suite.Channel or Engine.MerkleChannel != suite.MerkleChannel) return error.ProofSuiteMismatch;
    const limits = artifact.Limits{};
    const raw = try std.fs.cwd().readFileAlloc(a, path, limits.max_bytes);
    defer a.free(raw);
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, limits.max_elf_bytes);
    defer a.free(elf);
    const input: []const u8 = if (input_path) |input_file| try std.fs.cwd().readFileAlloc(a, input_file, limits.manifest.statement.max_input_bytes) else &.{};
    defer if (input_path != null) a.free(input);
    const verified = try artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyPublic(a, raw, expected, pcs_profile.select(policy), elf, input, limits);
    if (csp_ecdsa) try verified.validateCspEcdsa(input);
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &proof_digest, .{});
    const process = try artifact_validation.measureProcessIdentity(a);
    const statement_hex = std.fmt.bytesToHex(expected, .lower);
    const proof_hex = std.fmt.bytesToHex(proof_digest, .lower);
    const transcript_hex = std.fmt.bytesToHex(verified.transcript, .lower);
    const output_hex = std.fmt.bytesToHex(verified.output_sha256, .lower);
    const elf_hex = std.fmt.bytesToHex(verified.elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(verified.input_sha256, .lower);
    const executable_hex = std.fmt.bytesToHex(process.executable_sha256, .lower);
    const receipt = try std.json.Stringify.valueAlloc(a, .{
        .schema = "riscv_full_width_verify_v1",
        .status = "verified",
        .artifact_magic = artifact.MAGIC,
        .proof_suite = "blake3",
        .execution_profile = @tagName(profile),
        .release_status = "experimental_full_width",
        .security_policy = @tagName(policy),
        .statement_blake3 = &statement_hex,
        .proof_bytes = raw.len,
        .total_steps = verified.steps,
        .pcs_config = pcs_profile.select(policy),
        .csp_ecdsa = csp_ecdsa,
        .signer_calls = verified.signer_calls,
        .keccak_calls = verified.keccak_calls,
        .halt_flag = verified.halt_flag,
        .output_len = verified.output_len,
        .output_sha256 = &output_hex,
        .elf_sha256 = &elf_hex,
        .input_sha256 = &input_hex,
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
