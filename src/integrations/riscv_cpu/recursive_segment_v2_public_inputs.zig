//! Expected-public binding for the existing SegmentV2 statement source.
//! Row36 emits only statement/context tuples, so its authenticated STARK claim
//! can be compared directly with this verifier-derived positive sum. Internal
//! lookup closure and the AIR's emission multiplicity remain unchanged.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const source = frontend.recursion.segment_leaf_authority_v2;
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const universal = frontend.recursion.air.universal_challenges;
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

const fixture = frontend.testing.public_data_v2_test_support;

fn testKeys() !source.VerifierKeyAuthorityV2 {
    return source.VerifierKeyAuthorityV2.init(fixture.id("segment-key"), fixture.id("parent-key"));
}

test "SegmentV2 expected public claim matches the active row36 AIR" {
    const allocator = std.testing.allocator;
    var input = try fixture.Fixture.init();
    const words = try fixture.encode(allocator, &input.leftSource());
    defer allocator.free(words);
    const data = try PublicData.authenticate(words);
    const keys = try testKeys();
    const manifest = try source.ManifestV2.init(words.len);
    const relations = universal.UniversalRelations.dummy();
    const expected = try statementClaim(&data, &keys, &manifest, &relations);
    try verifyStatementClaim(&data, &keys, &manifest, &relations, expected);

    // Exercise the actual typed relation, rather than a second tuple formula.
    const Air = frontend.recursion.segment_leaf_outer_air_v2.Statement;
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try Air.authenticate(&definition);
    const context = try source.nativeContext(&try data.metadata(), &keys, &manifest);
    const context_words = try context.canonicalWords();
    var actual = QM31.zero();
    inline for (.{ words, context_words[0..] }, .{ source.WIRE_SCOPE, source.CONTEXT_SCOPE }) |values, scope| {
        for (values, 0..) |value, index| {
            const event = source.statementEvent(scope, index, value);
            const row = Air.logicalRow(event.tuple[2], core.fields.m31.M31.one(), event.tuple[0], event.tuple[1]);
            const claims = try plan.rowClaims(&definition.arena, Air.SEMANTIC_DIGEST, .{definition.event}, row, &relations);
            actual = actual.add(claims.total());
        }
    }
    try std.testing.expect(expected.eql(actual));
}

test "SegmentV2 expected public claim rejects changed wire keys manifest and claim" {
    const allocator = std.testing.allocator;
    var original = try fixture.Fixture.init();
    var changed = try fixture.Fixture.initWithRegister7(42);
    const words = try fixture.encode(allocator, &original.leftSource());
    defer allocator.free(words);
    const changed_words = try fixture.encode(allocator, &changed.leftSource());
    defer allocator.free(changed_words);
    const data = try PublicData.authenticate(words);
    const other = try PublicData.authenticate(changed_words);
    const keys = try testKeys();
    const manifest = try source.ManifestV2.init(words.len);
    const relations = universal.UniversalRelations.dummy();
    const claim = try statementClaim(&data, &keys, &manifest, &relations);
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, verifyStatementClaim(&other, &keys, &manifest, &relations, claim));
    const other_keys = try source.VerifierKeyAuthorityV2.init(fixture.id("other-segment-key"), keys.recursive_parent_vk_id);
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, verifyStatementClaim(&data, &other_keys, &manifest, &relations, claim));
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, verifyStatementClaim(&data, &keys, &manifest, &relations, claim.add(QM31.one())));
    const other_manifest = try source.ManifestV2.init(words.len + 1);
    try std.testing.expectError(error.SegmentV2PublicInputManifestMismatch, statementClaim(&data, &keys, &other_manifest, &relations));
    // Mutate the retained borrowed wire after authentication. Even a formerly
    // authenticated PublicData value must recheck its current ingress bytes.
    const saved = words[0];
    defer words[0] = saved;
    words[0] = saved.add(core.fields.m31.M31.one());
    if (statementClaim(&data, &keys, &manifest, &relations)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

test "SegmentV2 expected public claim rejects a zero relation denominator" {
    const allocator = std.testing.allocator;
    var input = try fixture.Fixture.init();
    const words = try fixture.encode(allocator, &input.leftSource());
    defer allocator.free(words);
    const data = try PublicData.authenticate(words);
    const keys = try testKeys();
    const manifest = try source.ManifestV2.init(words.len);
    var relations = universal.UniversalRelations.dummy();
    const domain = @intFromEnum(source.STATEMENT_RELATION_DOMAIN);
    const first = source.statementEvent(source.WIRE_SCOPE, 0, words[0]);
    var element = universal.Elements.init(3, QM31.zero(), relations.elements[domain].alpha);
    element.z = try element.combineBase(&first.tuple);
    relations.elements[domain] = element;
    try std.testing.expectError(error.DivisionByZero, statementClaim(&data, &keys, &manifest, &relations));
}
