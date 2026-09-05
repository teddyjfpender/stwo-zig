//! Transcript binding for the two exact Ethereum h1 public residuals.
//!
//! The statement-word boundary is intentionally domain-tagged as such. It is
//! never passed through the temporal-parent wire-boundary mixer, whose domain
//! is `recursion_wire`. Cold verification replays this function from a freshly
//! reconstructed and sealed H1 boundary receipt.

const std = @import("std");
const stwo_core = @import("stwo_core");

const boundary_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_boundary_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x4842_3131; // "HB11"

pub fn mixBoundaryReceipt(
    transcript: anytype,
    receipt: boundary_mod.ClosureReceiptV1,
) !void {
    try receipt.validate();
    try requireCanonical(receipt.statement.claimed_sum);
    try requireCanonical(receipt.verifier_input.claimed_sum);
    transcript.mixU32s(&.{
        BOUNDARY_TRANSCRIPT_DOMAIN,
        FORMAT_VERSION,
        SCHEMA_VERSION,
        @intFromEnum(receipt.statement.domain),
        receipt.statement.tuple_count,
        @intFromEnum(receipt.verifier_input.domain),
        receipt.verifier_input.tuple_count,
    });
    transcript.mixU32s(&digestWords(receipt.custody_identity_sha256));
    transcript.mixU32s(&digestWords(receipt.materialized_identity_sha256));
    transcript.mixU32s(&digestWords(receipt.generated_interactions_sha256));
    transcript.mixU32s(&digestWords(receipt.parent_statement_sha256));
    transcript.mixU32s(&digestWords(
        receipt.statement.tuple_provenance_sha256,
    ));
    transcript.mixU32s(&digestWords(
        receipt.verifier_input.tuple_provenance_sha256,
    ));
    transcript.mixU32s(&digestWords(receipt.identity_sha256));
    transcript.mixFelts(&.{
        receipt.statement.claimed_sum,
        receipt.verifier_input.claimed_sum,
    });
}

pub fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        const start = index * @sizeOf(u32);
        word.* = std.mem.readInt(
            u32,
            value[start..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

fn requireCanonical(value: QM31) !void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus)
            return error.NonCanonicalEthereumPoseidonH1Boundary;
}

comptime {
    if (BOUNDARY_TRANSCRIPT_DOMAIN >= m31.Modulus or
        boundary_mod.PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 transcript contract drifted");
    }
}
