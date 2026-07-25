//! Development Cairo CUDA proof publication boundary.
//!
//! Stage execution remains deliberately outside this module. A caller supplies
//! a strictly decoded terminal result, immutable statement bytes, authenticated
//! product identities, and then invokes the pinned Rust verifier hook on the
//! published envelope.

const std = @import("std");
const compact = @import("../../../frontends/cairo/compact_verifier_interchange.zig");
const prover = @import("../../../frontends/cairo/prover.zig");
const terminal_decode = @import("terminal_decode.zig");

pub const EnvelopeSummary = compact.EnvelopeSummary;
pub const ProvenanceIdentities = compact.CompactProvenanceIdentities;

pub fn writeEnvelope(
    writer: *std.Io.Writer,
    proof: terminal_decode.CanonicalProof,
    statement: []const u8,
    identities: ProvenanceIdentities,
) !EnvelopeSummary {
    // Revalidate runtime evidence at the publication boundary so callers
    // cannot decode a terminal allocation and subsequently substitute claims.
    try proof.terminal_read.validate(
        try terminalTransportBytes(proof),
    );
    return compact.writeEnvelopeV1(
        writer,
        proof.protocol,
        statement,
        proof.bytes(),
        identities,
    );
}

/// Adapter-compatible hook for `frontends/cairo/rust_oracle.zig`.
pub fn verifyWithOracle(
    comptime Oracle: type,
    oracle: *Oracle,
    allocator: std.mem.Allocator,
    envelope_path: []const u8,
) !prover.OracleEvidence {
    const evidence: prover.OracleEvidence = try oracle.verifyCairo(
        allocator,
        envelope_path,
    );
    if (!evidence.verified or
        !std.mem.eql(u8, evidence.envelope_abi, prover.canonical_envelope_abi) or
        !std.mem.eql(
            u8,
            evidence.verification_mode,
            prover.canonical_verification_mode,
        ) or
        !std.mem.eql(
            u8,
            evidence.stwo_cairo_revision,
            prover.pinned_stwo_cairo_revision,
        ) or
        !std.mem.eql(
            u8,
            evidence.stwo_revision,
            prover.pinned_stwo_revision,
        ))
    {
        return error.InvalidRustOracleEvidence;
    }
    return evidence;
}

fn terminalTransportBytes(
    proof: terminal_decode.CanonicalProof,
) !usize {
    const words = try terminal_decode.transportWordCount(
        std.heap.page_allocator,
        proof.protocol,
    );
    return std.math.mul(usize, words, @sizeOf(u32)) catch
        error.GeometryOverflow;
}
