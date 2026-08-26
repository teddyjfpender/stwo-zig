//! External publication identity for the authenticated Poseidon2 profile.
//!
//! `STWGPF01` authenticates the complete profile statement and proof.  The
//! benchmark publication additionally binds the exact source ELF, input bytes,
//! selected PCS policy, and protocol manifest.  This digest is recomputed by a
//! fresh verifier from the retained envelope and caller-selected source files.

const std = @import("std");
const stwo = @import("stwo");

pub const ARTIFACT_KIND = "stwo_riscv_guest_poseidon2_proof";
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;
pub const ARTIFACT_MAGIC = "STWGPF01";
pub const PROFILE_IDENTITY = "rv32im-zkvm-poseidon2-v1";
pub const PROFILE_VERSION: u16 = 1;
pub const PROFILE_MANIFEST_SHA256 =
    "265df524ca93ba5f240aec9e5ce2f9f616c302850410ee812c220aa3e59fb891";
pub const RECEIPT_SCHEMA = "riscv_guest_poseidon2_verify_v1";
pub const TASK_PROFILE_EXAMPLE = PROFILE_IDENTITY;

const digest_domain = "stwo-zig/riscv/guest-poseidon2-publication/v1\x00";

pub fn statementDigest(
    protocol: []const u8,
    pcs_config: stwo.core.pcs.PcsConfig,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    authenticated_statement_sha256: [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hashString(&hash, protocol);
    hashString(&hash, PROFILE_IDENTITY);
    hashInt(&hash, u16, PROFILE_VERSION);
    hash.update(&manifestDigest());
    hashInt(&hash, u32, pcs_config.pow_bits);
    hashInt(&hash, u32, pcs_config.fri_config.log_blowup_factor);
    hashInt(&hash, u32, pcs_config.fri_config.log_last_layer_degree_bound);
    hashInt(&hash, u64, pcs_config.fri_config.n_queries);
    hashInt(&hash, u32, pcs_config.fri_config.fold_step);
    if (pcs_config.lifting_log_size) |lifting| {
        hashInt(&hash, u8, 1);
        hashInt(&hash, u32, lifting);
    } else {
        hashInt(&hash, u8, 0);
    }
    hash.update(&elf_sha256);
    hash.update(&input_sha256);
    hash.update(&authenticated_statement_sha256);
    return hash.finalResult();
}

pub fn manifestDigest() [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, PROFILE_MANIFEST_SHA256) catch unreachable;
    return result;
}

pub fn assertProductCapability(
    comptime capabilities: type,
    comptime expected_backend: []const u8,
) void {
    if (!@hasDecl(capabilities, "guest_poseidon2"))
        @compileError("product does not declare the Poseidon2 guest profile");
    const declared = capabilities.guest_poseidon2;
    if (!std.mem.eql(u8, capabilities.backend, expected_backend) or
        !std.mem.eql(u8, declared.profile, PROFILE_IDENTITY) or
        declared.version != PROFILE_VERSION or
        !std.mem.eql(u8, declared.capability, stwo.frontends.riscv.isa.execution_profile.poseidon2_capability) or
        !std.mem.eql(u8, declared.manifest_sha256, PROFILE_MANIFEST_SHA256) or
        !std.mem.eql(u8, declared.caller_component, "riscv_guest_poseidon2_caller_v1") or
        !std.mem.eql(u8, declared.provider_component, "riscv_guest_poseidon2_provider_v1") or
        declared.execution_placement.len == 0 or declared.runtime_requirement.len == 0 or
        declared.backend_fallback_allowed)
    {
        @compileError("product Poseidon2 capability authority drifted");
    }
}

fn hashString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hashInt(hash, u64, value.len);
    hash.update(value);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (ARTIFACT_MAGIC.len != 8) @compileError("guest proof magic must remain fixed width");
    if (PROFILE_MANIFEST_SHA256.len != 64)
        @compileError("guest manifest digest must be lowercase SHA-256");
}

test "publication identity binds source, policy, and authenticated statement" {
    const config = stwo.frontends.riscv.prover_mod.SECURE_PCS_CONFIG;
    const baseline = statementDigest("secure", config, .{0} ** 32, .{1} ** 32, .{2} ** 32);
    const changed_elf = statementDigest("secure", config, .{3} ** 32, .{1} ** 32, .{2} ** 32);
    const changed_input = statementDigest("secure", config, .{0} ** 32, .{3} ** 32, .{2} ** 32);
    const changed_statement = statementDigest("secure", config, .{0} ** 32, .{1} ** 32, .{3} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &baseline, &changed_elf));
    try std.testing.expect(!std.mem.eql(u8, &baseline, &changed_input));
    try std.testing.expect(!std.mem.eql(u8, &baseline, &changed_statement));
    try std.testing.expectEqualSlices(
        u8,
        &stwo.frontends.riscv.air.guest_precompile.manifest.canonical_digest_golden,
        &manifestDigest(),
    );
}
