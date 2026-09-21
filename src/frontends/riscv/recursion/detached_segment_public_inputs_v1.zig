//! Expected-public statement claim shared by detached verification and recording.
const std = @import("std");
const core = @import("stwo_core");
const source = @import("segment_leaf_statement_contract_v2.zig");
const PublicData = @import("../air/public_data_v2.zig").PublicDataV2;
const universal = @import("air/universal_challenges.zig");
const QM31 = core.fields.qm31.QM31;

/// The caller independently admits the source manifest and both verifier key
/// IDs. Expected wire metadata is authenticated here; a supplied context hash
/// or producer receipt cannot stand in for its canonical temporal preimage.
pub fn statementClaim(
    expected: *const PublicData,
    admitted_keys: *const source.VerifierKeyAuthorityV2,
    admitted_source_manifest: *const source.ManifestV2,
    relations: *const universal.UniversalRelations,
) !QM31 {
    const metadata = try expected.metadata();
    try admitted_keys.validate();
    try admitted_source_manifest.validate();
    const exact_manifest = try source.ManifestV2.init(expected.words().len);
    if (!std.meta.eql(exact_manifest, admitted_source_manifest.*))
        return error.SegmentV2PublicInputManifestMismatch;
    const context = try source.nativeContext(&metadata, admitted_keys, admitted_source_manifest);
    const context_words = try context.canonicalWords();
    try relations.validate();
    var sink = NativeStatementSink{ .challenge = relations.get(source.STATEMENT_RELATION_DOMAIN) };
    try emitStatementTerms(expected.words(), &context_words, &sink);
    return sink.claim;
}

/// Canonical expected-public multiset order. The sink decides whether each
/// inverse is evaluated natively or recorded as an authenticated AIR equation.
pub fn emitStatementTerms(wire: anytype, context: anytype, sink: anytype) !void {
    for (wire, 0..) |word, index| try sink.term(source.WIRE_SCOPE, index, word);
    for (context, 0..) |word, index| try sink.term(source.CONTEXT_SCOPE, index, word);
}
const NativeStatementSink = struct {
    challenge: *const universal.Elements,
    claim: QM31 = QM31.zero(),
    pub fn term(self: *NativeStatementSink, scope: u32, index: usize, value: core.fields.m31.M31) !void {
        const event = source.statementEvent(scope, index, value);
        self.claim = self.claim.add(try (try self.challenge.combineBase(&event.tuple)).inv());
    }
};

/// Checks public-input equality; it does not verify the STARK. The caller must
/// also verify the same row36 claim through the canonical component adapter.
pub fn verifyStatementClaim(
    expected: *const PublicData,
    admitted_keys: *const source.VerifierKeyAuthorityV2,
    admitted_source_manifest: *const source.ManifestV2,
    relations: *const universal.UniversalRelations,
    claimed_sum: QM31,
) !void {
    for (claimed_sum.toM31Array()) |limb|
        if (limb.toU32() >= core.fields.m31.Modulus)
            return error.SegmentV2PublicInputClaimMismatch;
    if (!(try statementClaim(expected, admitted_keys, admitted_source_manifest, relations)).eql(claimed_sum))
        return error.SegmentV2PublicInputClaimMismatch;
}
