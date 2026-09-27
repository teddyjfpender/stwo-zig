//! Acceptance and adversarial evidence for the role-separated R-008 substrate.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const aggregation_fixture = @import("../../aggregation/test_fixture.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const subject = @import("split_component_assembly.zig");

const Fixture = struct {
    manifest: aggregation_fixture.TwoLeafFixture,
    storage: [2]aggregation_manifest.PreparedLeafV1,
    session: aggregation_manifest.PreparedSessionV1,
    relations: guest_relations.Poseidon2V1Relations,
    caller_claim: caller_component.Claim,
    provider_claim: provider_component.Claim,

    fn init() !Fixture {
        var result: Fixture = undefined;
        result.manifest = aggregation_fixture.twoLeaves(1);
        result.session = try aggregation_manifest.prepare(
            result.manifest.view(),
            result.manifest.accepted,
            &result.storage,
        );
        // `PreparedSessionV1` borrows the final storage address. Rebind after
        // returning the by-value fixture so the tests never retain a moved
        // stack pointer.
        result.session.leaves = &result.storage;
        result.relations = try subject.bindSessionGuestRelation(
            &result.session,
            guest_relations.Poseidon2V1Relations.dummy(),
        );
        const caller_authority = try subject.resolveCallerAuthority(&result.session, 0);
        const provider_authority = try subject.resolveProviderAuthority(&result.session, 1);
        var caller_sums = [_]QM31{QM31.zero()} ** caller_component.batch_count;
        caller_sums[subject.caller_guest_batch] = felt(17).neg();
        var provider_sums = [_]QM31{QM31.zero()} ** provider_component.batch_count;
        provider_sums[subject.provider_guest_batch] = felt(17);
        result.caller_claim = try caller_component.Claim.canonical(
            caller_authority.construction,
            caller_sums,
        );
        result.provider_claim = try provider_component.Claim.canonical(
            provider_authority.construction,
            provider_sums,
        );
        return result;
    }

    fn rebind(self: *Fixture) void {
        self.session.leaves = &self.storage;
    }
};

fn replayFor(
    session: *const aggregation_manifest.PreparedSessionV1,
    index: u32,
) subject.VerifierReplayIdentity {
    const leaf = session.leaf(index) catch unreachable;
    return .{
        .statement_digest = leaf.descriptor.leaf_statement_digest,
        .air_artifact_digest = leaf.descriptor.leaf_air_artifact_digest,
        .preprocessed_root = leaf.descriptor.preprocessed_root,
        .main_root = leaf.descriptor.main_root,
    };
}

fn candidates(fixture: *const Fixture) !struct {
    caller: subject.CallerCandidate,
    provider: subject.ProviderCandidate,
} {
    return .{
        .caller = try subject.candidateCallerAfterStarkVerification(
            &fixture.session,
            0,
            replayFor(&fixture.session, 0),
            &fixture.relations,
            QM31.zero(),
            QM31.zero(),
            fixture.caller_claim,
        ),
        .provider = try subject.candidateProviderAfterStarkVerification(
            &fixture.session,
            1,
            replayFor(&fixture.session, 1),
            &fixture.relations,
            fixture.provider_claim,
        ),
    };
}

fn felt(value: u32) QM31 {
    return QM31.fromU32Unchecked(value, 0, 0, 0);
}

fn expectContext(expected: anytype, actual: *const anyopaque) !void {
    try std.testing.expectEqual(@intFromPtr(expected), @intFromPtr(actual));
}

test "split assemblies place one caller after core and one standalone provider" {
    var fixture = try Fixture.init();
    fixture.rebind();
    const core = support.coreFixture(1);
    const caller_authority = try subject.resolveCallerAuthority(&fixture.session, 0);
    const provider_authority = try subject.resolveProviderAuthority(&fixture.session, 1);

    var base_components: [2]caller_component.CallerComponent = undefined;
    var base_provers: [2]prover_component.ComponentProver = undefined;
    var base_verifiers: [2]core_air_components.Component = undefined;
    for (&base_components, 0..) |*component, index| {
        const offset = 8 * index;
        component.* = try caller_component.CallerComponent.initProver(
            caller_authority.construction,
            fixture.caller_claim,
            .{
                .is_first_col_idx = offset,
                .is_active_col_idx = offset + 1,
                .main_col_offset = offset,
                .interaction_col_offset = offset,
            },
            &fixture.relations,
        );
        base_provers[index] = component.asProverComponent();
        base_verifiers[index] = component.asVerifierComponent();
    }

    var caller_prover: subject.CallerProverAssembly = undefined;
    try caller_prover.initInto(
        &core,
        caller_authority.construction,
        &fixture.relations,
        &base_provers,
        fixture.caller_claim,
    );
    var caller_verifier: subject.CallerVerifierAssembly = undefined;
    try caller_verifier.initInto(
        &core,
        caller_authority.construction,
        &fixture.relations,
        &base_verifiers,
        fixture.caller_claim,
    );
    var provider_prover: subject.ProviderProverAssembly = undefined;
    try provider_prover.initInto(
        provider_authority.construction,
        &fixture.relations,
        fixture.provider_claim,
    );
    var provider_verifier: subject.ProviderVerifierAssembly = undefined;
    try provider_verifier.initInto(
        provider_authority.construction,
        &fixture.relations,
        fixture.provider_claim,
    );

    try std.testing.expectEqual(@as(usize, 3), caller_prover.active().len);
    try std.testing.expectEqual(@as(usize, 3), caller_verifier.active().len);
    try std.testing.expectEqual(@as(usize, 1), provider_prover.active().len);
    try std.testing.expectEqual(@as(usize, 1), provider_verifier.active().len);
    for (0..base_components.len) |index| {
        try expectContext(&base_components[index], caller_prover.active()[index].ctx);
        try expectContext(&base_components[index], caller_verifier.active()[index].ctx);
    }
    try expectContext(&caller_prover.caller, caller_prover.active()[2].ctx);
    try expectContext(&caller_verifier.caller, caller_verifier.active()[2].ctx);
    try expectContext(&provider_prover.provider, provider_prover.active()[0].ctx);
    try expectContext(&provider_verifier.provider, provider_verifier.active()[0].ctx);

    const placement = try subject.callerPlacement(&core);
    try std.testing.expectEqual(
        @as(usize, core.nPreprocessedColumns()),
        placement.is_first_col_idx,
    );
    try std.testing.expectEqual(
        @as(usize, core.nMainColumns()),
        placement.main_col_offset,
    );
    try std.testing.expectEqual(
        @as(usize, core.nInteractionColumns()),
        placement.interaction_col_offset,
    );
    try std.testing.expectEqual(@as(usize, 0), subject.provider_placement.main_col_offset);
    try std.testing.expectEqual(@as(usize, 0), subject.provider_placement.interaction_col_offset);
}

test "shared session draw and local exported remainders are exact" {
    var fixture = try Fixture.init();
    fixture.rebind();
    try subject.validateSessionGuestRelation(&fixture.session, &fixture.relations);
    try subject.verifyCallerLocalRemainder(
        (try subject.resolveCallerAuthority(&fixture.session, 0)).construction,
        QM31.zero(),
        QM31.zero(),
        fixture.caller_claim,
    );
    try subject.verifyProviderLocalRemainder(
        (try subject.resolveProviderAuthority(&fixture.session, 1)).construction,
        fixture.provider_claim,
    );
    try std.testing.expect(
        subject.callerExportedGuestSum(fixture.caller_claim)
            .add(subject.providerExportedGuestSum(fixture.provider_claim))
            .isZero(),
    );

    var wrong_relations = fixture.relations;
    wrong_relations.guest_poseidon2_io = .init(felt(91), felt(92));
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        subject.validateSessionGuestRelation(&fixture.session, &wrong_relations),
    );
    var wrong_powers = fixture.relations;
    wrong_powers.guest_poseidon2_io.alpha_powers[7] = felt(93);
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        subject.validateSessionGuestRelation(&fixture.session, &wrong_powers),
    );

    var bad_caller = fixture.caller_claim;
    bad_caller.batch_sums[0] = felt(1);
    bad_caller.component_sum = bad_caller.component_sum.add(felt(1));
    try std.testing.expectError(
        error.UnclosedCallerLocalRelations,
        subject.verifyCallerLocalRemainder(
            (try subject.resolveCallerAuthority(&fixture.session, 0)).construction,
            QM31.zero(),
            QM31.zero(),
            bad_caller,
        ),
    );
}

test "candidate pair closes only in canonical order and rejects omission" {
    var fixture = try Fixture.init();
    fixture.rebind();
    const pair = try candidates(&fixture);
    const closed = try subject.closePair(&fixture.session, pair.caller, pair.provider);
    try std.testing.expect(closed.closed);
    try std.testing.expect(closed.residual_guest_sum.isZero());

    try std.testing.expectError(
        error.MissingCallerProof,
        subject.closeOptionalPair(&fixture.session, .{
            .caller = null,
            .provider = pair.provider,
        }),
    );
    try std.testing.expectError(
        error.MissingProviderProof,
        subject.closeOptionalPair(&fixture.session, .{
            .caller = pair.caller,
            .provider = null,
        }),
    );

    const swapped_caller = subject.CallerCandidate{
        .summary = pair.provider.summary,
    };
    const swapped_provider = subject.ProviderCandidate{
        .summary = pair.caller.summary,
    };
    try std.testing.expectError(
        error.NonCanonicalPair,
        subject.closePair(&fixture.session, swapped_caller, swapped_provider),
    );
}

test "cross-session and replay identity substitution reject before closure" {
    var fixture = try Fixture.init();
    fixture.rebind();
    var other_manifest = aggregation_fixture.twoLeaves(1);
    other_manifest.descriptors[0].main_root[0] ^= 1;
    var other_storage: [2]aggregation_manifest.PreparedLeafV1 = undefined;
    var other_session = try aggregation_manifest.prepare(
        other_manifest.view(),
        other_manifest.accepted,
        &other_storage,
    );
    other_session.leaves = &other_storage;
    const pair = try candidates(&fixture);
    try std.testing.expectError(
        error.SessionMismatch,
        subject.closePair(&other_session, pair.caller, pair.provider),
    );

    var wrong_replay = replayFor(&fixture.session, 0);
    wrong_replay.main_root[0] ^= 1;
    try std.testing.expectError(
        error.MainRootMismatch,
        subject.candidateCallerAfterStarkVerification(
            &fixture.session,
            0,
            wrong_replay,
            &fixture.relations,
            QM31.zero(),
            QM31.zero(),
            fixture.caller_claim,
        ),
    );

    try std.testing.expectError(
        error.LeafRoleMismatch,
        subject.candidateCallerAfterStarkVerification(
            &fixture.session,
            1,
            replayFor(&fixture.session, 1),
            &fixture.relations,
            QM31.zero(),
            QM31.zero(),
            fixture.caller_claim,
        ),
    );
}

test "split boundary remains explicitly non-recursive and non-proof-binding" {
    try std.testing.expect(subject.RESEARCH_ONLY);
    try std.testing.expect(!subject.VERIFIES_STARK_PROOFS);
    try std.testing.expect(!subject.PROVES_CALL_COMMITMENT);
    try std.testing.expect(!subject.RECURSIVE_PAIR_VERIFICATION);
    try std.testing.expectEqual(@as(usize, 76), subject.caller_guest_batch);
    try std.testing.expectEqual(@as(usize, 1), subject.provider_guest_batch);
    try std.testing.expect(aggregation_types.RELATION_ARITY == 32);
}
