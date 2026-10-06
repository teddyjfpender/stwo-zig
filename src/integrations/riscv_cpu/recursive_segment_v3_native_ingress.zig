//! Prove one globally positioned, leaf-local segment through the bounded V2 AIR.
//!
//! This is native proof ingress only. The verified link is checked by the host;
//! a recursive circuit must still constrain its global metadata and link words.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const prover = frontend.prover_mod;
const recursion = frontend.recursion;
const M31 = core.fields.m31.M31;

pub fn Verified(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        proof_bytes: []u8,
        global_metadata: recursion.segment_leaf_local_authority_v3.MetadataV3,
        link: recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
        capture: prover.VerifiedSegmentV2CaptureForEngine(Engine),

        const Self = @This();

        pub fn validate(self: *const Self) !void {
            try self.capture.validate();
            try self.link.validateAgainst(
                &self.global_metadata,
                &self.capture.public_data.data,
                &self.capture.receipt,
            );
        }

        pub fn deinit(self: *Self) void {
            self.capture.deinit(self.allocator);
            self.allocator.free(self.proof_bytes);
            self.* = undefined;
        }
    };
}

/// `source` keeps the original runner result alive through native proving.
/// The returned capture, proof bytes, global metadata and link own their data
/// independently of that result. The proof is serialized and decoded after
/// producer destruction, then freshly verified before any result is returned.
pub fn proveAndVerify(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source: *const recursion.segment_leaf_local_authority_v3.SourceV3,
    pcs_config: core.pcs.PcsConfig,
    session_id: recursion.segment_statement_v2.Digest,
) !Verified(Engine) {
    comptime {
        if (Engine.Hasher != recursion.engine.Hasher)
            @compileError("V3 native ingress requires the recursive Poseidon2 proof suite");
    }
    const global_metadata = try source.metadata();
    var projection = try recursion.segment_leaf_local_projection_v3.ProjectionV3.init(source);
    const local_source = try projection.sourceV2(source, session_id);
    const words = try allocator.alloc(M31, try local_source.canonicalWordCount());
    defer allocator.free(words);
    _ = try local_source.encodeCanonical(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(words);

    var output = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        pcs_config,
        &projection.local_result,
        null,
        public_data,
    );
    var output_owned = true;
    defer if (output_owned) output.deinit(allocator);
    try output.statement.validateSegmentResult(&projection.local_result);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, encoded.writer(allocator), output.proof);
    const native_statement = output.statement;
    if (native_statement.public_data.canonical_words.ptr != words.ptr or
        native_statement.public_data.canonical_words.len != words.len)
        return error.NativeStatementOwnerMismatch;
    const native_claim = output.interaction_claim.*;
    output.deinit(allocator);
    output_owned = false;

    try recursion.proof_ingress.validateV2ForVerifierConfig(
        encoded.items,
        &native_statement,
        pcs_config,
        encoded.items.len,
    );
    var stream = std.io.fixedBufferStream(encoded.items);
    var decoded = try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader());
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(allocator);
    if (stream.pos != encoded.items.len) return error.InvalidProofShape;

    var capture: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    var channel = Engine.Channel{};
    decoded_owned = false; // The verifier consumes the decoded proof on either outcome.
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        pcs_config,
        native_statement,
        decoded,
        &native_claim,
        &channel,
        &capture,
    );
    errdefer capture.deinit(allocator);
    try capture.validate();
    const link = try recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3.init(
        &global_metadata,
        &capture.public_data.data,
        &capture.receipt,
    );
    try projection.validateAgainst(source);
    const proof_bytes = try encoded.toOwnedSlice(allocator);
    errdefer allocator.free(proof_bytes);
    var result: Verified(Engine) = .{
        .allocator = allocator,
        .proof_bytes = proof_bytes,
        .global_metadata = global_metadata,
        .link = link,
        .capture = capture,
    };
    try result.validate();
    return result;
}
