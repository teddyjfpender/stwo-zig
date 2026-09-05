const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const public_support = @import("../air/public_data_v2_test_support.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const statement = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const profile_v2 = @import("vm_air_profile_v2.zig");
const support = @import("ethereum_leaf_context_v1_test_support.zig");
const subject = @import("vm_leaf_context_v2.zig");

test "SegmentV2 VM leaf ContextV2 retains exact verifier instance authority" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var context = try fixture.context();
    defer context.deinit();
    const capture_authority = try fixture.captureAuthority();

    try context.validate();
    try context.validateAuthorityValues(
        &fixture.owned_public,
        &fixture.receipt,
        &fixture.native_sums,
        capture_authority,
    );
    try std.testing.expectEqual(@as(u32, 30), context.profile.physical_component_count);
    try std.testing.expectEqual(@as(u32, 352), context.profile.interaction_column_count);
    try std.testing.expectEqual(@as(usize, 88), context.detailed_claims.len);
    try std.testing.expectEqual(@as(u32, 88), context.profile.input_profile.claimed_sum_count);
    try std.testing.expectEqual(
        context.profile.input_profile.sampled_value_count,
        context.base_sampled_value_count,
    );
    try std.testing.expectEqual(
        capture_authority.full_sampled_value_count,
        context.full_proof_capture_sampled_value_count,
    );
    try std.testing.expect(
        context.full_proof_capture_sampled_value_count >
            context.base_sampled_value_count,
    );
    for (context.canonical_claims) |value|
        try std.testing.expect(value.isZero());

    const reconstructed = try context.reconstructStatement(
        &fixture.owned_public.data,
    );
    try std.testing.expectEqual(
        fixture.native.authority_id,
        reconstructed.authority_id,
    );
}

test "SegmentV2 VM leaf ContextV2 rejects claim public receipt and capture mutations" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var context = try fixture.context();
    defer context.deinit();
    const capture_authority = try fixture.captureAuthority();

    context.detailed_claims[0] = QM31.one();
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.detailed_claims[0] = QM31.zero();
    try context.validate();

    context.canonical_claims[0] = QM31.one();
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.canonical_claims[0] = QM31.zero();
    try context.validate();

    context.relation_draws[0] = context.relation_draws[0].add(QM31.one());
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.relation_draws[0] = context.relation_draws[0].sub(QM31.one());
    try context.validate();

    context.public_wire_id[0] ^= 1;
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.public_wire_id[0] ^= 1;
    context.verified_receipt_identity[0] ^= 1;
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.verified_receipt_identity[0] ^= 1;
    context.proof_capture_sha256[0] ^= 1;
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.proof_capture_sha256[0] ^= 1;
    try context.validate();

    var wrong_capture = capture_authority;
    wrong_capture.sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPublicAuthority,
        context.validateAuthorityValues(
            &fixture.owned_public,
            &fixture.receipt,
            &fixture.native_sums,
            wrong_capture,
        ),
    );

    var wrong_receipt = fixture.receipt;
    wrong_receipt.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifiedReceipt,
        context.validateAuthorityValues(
            &fixture.owned_public,
            &wrong_receipt,
            &fixture.native_sums,
            capture_authority,
        ),
    );

    context.profile.entries[19].constraint_count += 1;
    try std.testing.expectError(error.InvalidStatementShape, context.validate());

    context.profile.entries[19].constraint_count -= 1;
    context.base_sampled_value_count += 1;
    try std.testing.expectError(error.InvalidContextCounts, context.validate());
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    words: []@import("stwo_core").fields.m31.M31,
    owned_public: statement_v2.OwnedPublicDataV2,
    native: statement_v2.RiscVStatementV2,
    manifest: lookup_physical_v2.Manifest,
    authenticated: lookup_physical_v2.AuthenticatedStatement,
    claim: *statement.RiscVInteractionClaim,
    relations: relations_mod.Relations,
    native_sums: statement_v2.NativePublicSums,
    receipt: statement_v2.VerifiedReceipt,
    facts: []profile_v2.Facts,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var public_fixture = try public_support.Fixture.init();
        const source = public_fixture.leftSource();
        const words = try public_support.encode(allocator, &source);
        errdefer allocator.free(words);
        const borrowed = try public_data_v2.PublicDataV2.authenticate(words);
        var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
            allocator,
            &borrowed,
        );
        errdefer owned_public.deinit();
        const projected = try statement_v2.canonicalCorePublicData(
            &owned_public.data,
        );
        var core = support.retainedSegmentZeroCore();
        core.initial_pc = projected.initial_pc;
        core.final_pc = projected.final_pc;
        core.total_steps = projected.clock;
        core.public_data = projected;
        const native = try statement_v2.RiscVStatementV2.init(
            core,
            owned_public.data,
        );
        var manifest = lookup_physical_v2.Manifest.native();
        const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            &native.core,
            &manifest,
        );
        const claim = try allocator.create(statement.RiscVInteractionClaim);
        errdefer allocator.destroy(claim);
        claim.initZeroInto();
        claim.n_components = native.core.n_components;
        claim.n_infra = native.core.n_infra;
        const relations = relations_mod.Relations.dummy();
        const native_sums = try statement_v2.NativePublicSums.init(
            &owned_public.data,
            &relations,
        );
        const receipt = try native.verifiedReceipt();
        const facts = try profile_v2.testing.expectedFacts(
            allocator,
            &native.core,
            &manifest,
        );
        errdefer allocator.free(facts);
        return .{
            .allocator = allocator,
            .words = words,
            .owned_public = owned_public,
            .native = native,
            .manifest = manifest,
            .authenticated = authenticated,
            .claim = claim,
            .relations = relations,
            .native_sums = native_sums,
            .receipt = receipt,
            .facts = facts,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.facts);
        self.allocator.destroy(self.claim);
        self.owned_public.deinit();
        self.allocator.free(self.words);
        self.* = undefined;
    }

    fn context(self: *Fixture) !subject.ContextV2 {
        const capture_authority = try self.captureAuthority();
        return subject.testing.initFromFacts(
            self.allocator,
            &self.native,
            self.claim,
            &self.relations,
            &self.manifest,
            &self.authenticated,
            self.facts,
            capture_authority,
            &self.receipt,
            &self.native_sums,
        );
    }

    fn captureAuthority(self: *const Fixture) !subject.CaptureAuthority {
        const base_sampled_value_count = try @import(
            "vm_composition_base_geometry_v2.zig",
        ).expectedSampledValueCount(&self.native.core, &self.manifest);
        return .{
            .full_sampled_value_count = try std.math.add(
                u32,
                base_sampled_value_count,
                17,
            ),
            .sha256 = .{0x5a} ** 32,
        };
    }
};
