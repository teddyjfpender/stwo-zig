//! Transcript/capture identity and checkpoint validation; records stay with their canonical verifier.
const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const statement = @import("stwo_riscv_rv32").air.statement;
const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
const ethereum_context = @import("../recursion/ethereum_leaf_context.zig");
const ethereum_transcript = @import("guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const TRANSCRIPT_DOMAIN =
    "stwo.riscv.incremental-ethereum-transcript.v4\x00";
const CAPTURE_DOMAIN =
    "stwo.riscv.incremental-ethereum-fresh-capture.v4\x00";
const FreshVerifiedCaptureV4 = @import("incremental_ethereum_verifier.zig").FreshVerifiedCaptureV4;

pub fn incrementalRoots(
    native: *const statement_v2.RiscVStatementV2,
) !struct { entry: u32, exit: u32 } {
    return .{
        .entry = native.core.public_data.initial_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
        .exit = native.core.public_data.final_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
    };
}

pub fn transcriptIdentity(
    native: *const statement_v2.RiscVStatementV2,
    profile: anytype,
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    relations: *const ethereum_transcript.Relations,
    ethereum_air: *const ethereum_context.ContextV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRANSCRIPT_DOMAIN);
    hashU32Digest(&hash, native.authority_id);
    hashU32Digest(&hash, native.public_data.wireId());
    hash.update(&profile.identity_sha256);
    hash.update(&profile.bridge_geometry.identity_sha256);
    hash.update(&ethereum_air.statement_sha256);
    hash.update(&ethereum_air.claim_sha256);
    hashInt(&hash, u64, base_claim.interaction_pow);
    hashQm31(&hash, extension_claim.componentSum());
    hashQm31(&hash, bridge_claim);
    var base_draws: [@import("stwo_riscv_air_lang").evaluation.relation_challenges.DRAW_COUNT]QM31 =
        undefined;
    relations.base.writeDraws(&base_draws) catch unreachable;
    for (base_draws) |draw| hashQm31(&hash, draw);
    return hash.finalResult();
}

pub fn captureIdentity(
    comptime Engine: type,
    comptime Profile: type,
    capture: *const FreshVerifiedCaptureV4(Engine, Profile),
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, capture.format_version);
    hash.update(&capture.proof_capture_sha256);
    hash.update(&capture.transcript_identity_sha256);
    hash.update(&capture.profile.identity_sha256);
    hash.update(&capture.role_aware_public.public_boundary_identity_sha256);
    hash.update(&capture.public_sums.identity_sha256);
    hash.update(&capture.ethereum_air.identity_digest);
    hashU32Digest(&hash, capture.receipt.identity);
    hashU32Digest(&hash, capture.transcript_final_digest);
    hashInt(&hash, u32, capture.transcript_final_draw_count);
    return hash.finalResult();
}

pub fn validateTranscriptCheckpoint(
    digest: [8]u32,
    draw_count: u32,
) !void {
    if (draw_count >= m31.Modulus)
        return error.InvalidIncrementalEthereumFreshCapture;
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.InvalidIncrementalEthereumFreshCapture;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidIncrementalEthereumFreshCapture;
}

pub fn hashQm31(hash: *std.crypto.hash.sha2.Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

pub fn hashU32Digest(hash: *std.crypto.hash.sha2.Sha256, value: [8]u32) void {
    for (value) |word| hashInt(hash, u32, word);
}

pub fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
