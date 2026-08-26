const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const authority = @import("segment_leaf_outer_authority_v2.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const native_relations = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation = @import("../air/lang/relation.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");

const test_support = @import("segment_leaf_outer_authority_v2_test_support.zig");
const OwnedTraces = test_support.OwnedTraces;
const expectedStatementClaim = test_support.expectedStatementClaim;
const expectedPublicLogUpClaim = test_support.expectedPublicLogUpClaim;
const expectedVerifierInputClaim = test_support.expectedVerifierInputClaim;
const expectedPublicationBridgeClaim = test_support.expectedPublicationBridgeClaim;
const expectSecureBase = test_support.expectSecureBase;
const expectStatementRow = test_support.expectStatementRow;
const expectM31 = test_support.expectM31;
const sentinel = test_support.sentinel;
const relationBit = test_support.relationBit;

test "segment leaf outer V2 authenticates every authority event and all 55 public LogUp words" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try source_v2.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const native = native_relations.Relations.dummy();
    const outer = universal.UniversalRelations.dummy();

    const shape = try authority.preflight(&data, &keys);
    try std.testing.expectEqual(@as(u8, 2), shape.manifest.component_count);
    try std.testing.expect(!shape.manifest.frozen_v1_compatible);
    try std.testing.expectEqual(
        words.len + source_v2.CONTEXT_WORD_COUNT,
        shape.manifest.components[0].logical_rows,
    );
    try std.testing.expectEqual(
        @as(u32, source_v2.LOGUP_PUBLICATION_WORD_COUNT),
        shape.manifest.components[1].logical_rows,
    );
    try std.testing.expectEqual(
        @as(u32, 64),
        shape.manifest.components[1].trace_rows,
    );
    try std.testing.expectEqual(
        shape.manifest.components[0].logical_rows +
            source_v2.LOGUP_PUBLICATION_WORD_COUNT,
        try shape.manifest.totalLogicalEvents(),
    );
    try std.testing.expectEqual(@as(usize, 0), shape.hot_heap_allocations);

    var typed_authority = try authority.AuthorityV2.init(std.testing.allocator);
    defer typed_authority.deinit();
    var workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer workspace.deinit();
    var owned = try OwnedTraces.init(std.testing.allocator, &shape.manifest);
    defer owned.deinit();
    owned.fill(sentinel());

    var prepared: authority.PreparedOuterAuthorityV2 = undefined;
    try authority.prepareInto(
        &prepared,
        &workspace,
        &typed_authority,
        owned.traces(),
        &data,
        &keys,
        &native,
        &outer,
    );
    try prepared.validateAgainst(&data, &keys, &native, &outer);
    try std.testing.expect(!prepared.productionReady());
    try std.testing.expectEqual(
        shape.manifest.components[0].logical_rows,
        prepared.statement_event_count,
    );
    try std.testing.expectEqual(
        @as(u32, 55),
        prepared.public_logup_word_count,
    );

    const context_words = try prepared.source.context.canonicalWords();
    for (words, 0..) |word, logical_row| {
        try expectStatementRow(
            owned.traces().statement,
            shape.manifest.components[0].trace_log_size,
            logical_row,
            source_v2.WIRE_SCOPE,
            logical_row,
            word,
        );
    }
    for (context_words, 0..) |word, context_index| {
        const logical_row = words.len + context_index;
        try expectStatementRow(
            owned.traces().statement,
            shape.manifest.components[0].trace_log_size,
            logical_row,
            source_v2.CONTEXT_SCOPE,
            context_index,
            word,
        );
    }
    for (
        shape.manifest.components[0].logical_rows..shape.manifest.components[0].trace_rows,
    ) |logical_row| {
        const row = framework.committedRow(
            logical_row,
            shape.manifest.components[0].trace_log_size,
        );
        try expectM31(0, owned.statement_preprocessed[0][row]);
        try expectM31(0, owned.statement_preprocessed[1][row]);
        try expectM31(0, owned.statement_preprocessed[2][row]);
        try expectM31(0, owned.statement_main[0][row]);
    }

    const logup_words = try prepared.public_logup.canonicalWords();
    for (logup_words, 0..) |word, logical_row| {
        const row = framework.committedRow(
            logical_row,
            authority.PUBLIC_LOGUP_TRACE_LOG_SIZE,
        );
        try expectM31(1, owned.public_logup_preprocessed[0][row]);
        try expectM31(logical_row, owned.public_logup_preprocessed[1][row]);
        try std.testing.expect(word.eql(owned.public_logup_main[0][row]));
    }
    for (source_v2.LOGUP_PUBLICATION_WORD_COUNT..authority.PUBLIC_LOGUP_TRACE_ROWS) |
        logical_row,
    | {
        const row = framework.committedRow(
            logical_row,
            authority.PUBLIC_LOGUP_TRACE_LOG_SIZE,
        );
        try expectM31(0, owned.public_logup_preprocessed[0][row]);
        try expectM31(0, owned.public_logup_preprocessed[1][row]);
        try expectM31(0, owned.public_logup_main[0][row]);
    }

    const expected_statement = try expectedStatementClaim(
        &prepared,
        &data,
        &outer,
    );
    const expected_logup = try expectedPublicLogUpClaim(&prepared, &outer);
    const expected_verifier = try expectedVerifierInputClaim(&prepared, &outer);
    const expected_bridge = try expectedPublicationBridgeClaim(&prepared, &outer);
    try std.testing.expect(expected_statement.eql(prepared.statement_claim));
    try std.testing.expect(expected_logup.eql(prepared.public_logup_claim));
    try std.testing.expect(
        expected_verifier.eql(prepared.closure.verifier_input_consume),
    );
    try std.testing.expect(
        expected_bridge.eql(prepared.closure.publication_bridge_emit),
    );
    try std.testing.expect(
        expected_logup.eql(prepared.closure.publicLogUpClaim()),
    );
    try std.testing.expectEqual(
        relationBit(.recursion_statement_word) |
            relationBit(.recursion_verifier_input_word) |
            relationBit(.recursion_wire),
        prepared.closure.checked_domain_mask,
    );
    try std.testing.expect(!prepared.closure.locally_closed);
}

test "segment leaf outer V2 source37 plan emits exact circuit44 custody tuples" {
    var typed_authority = try authority.AuthorityV2.init(std.testing.allocator);
    defer typed_authority.deinit();

    const value = M31.fromCanonical(0x1234);
    const index = M31.fromCanonical(17);
    const entries = try typed_authority.public_logup_plan.entries(
        &typed_authority.public_logup_definition.arena,
        air_v2.PublicLogUp.SEMANTIC_DIGEST,
        typed_authority.public_logup_definition.events,
        air_v2.PublicLogUp.logicalRow(value, M31.one(), index),
    );
    try std.testing.expectEqual(
        relation.Domain.recursion_verifier_input_word,
        entries[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, entries[0].role);
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try expectSecureBase(source_v2.SEGMENT_V2_VERIFIER_ID, entries[0].values[0]);
    try expectSecureBase(source_v2.PUBLIC_LOGUP_V2_KIND, entries[0].values[1]);
    try std.testing.expect(entries[0].values[2].eql(QM31.fromBase(index)));
    try std.testing.expect(entries[0].values[3].isZero());
    try std.testing.expect(entries[0].values[4].eql(QM31.fromBase(value)));

    try std.testing.expectEqual(relation.Domain.recursion_wire, entries[1].domain);
    try std.testing.expectEqual(relation.Role.emit, entries[1].role);
    try std.testing.expect(entries[1].numerator.eql(QM31.one()));
    try expectSecureBase(
        source_v2.PUBLICATION_BRIDGE_CIRCUIT_ID,
        entries[1].values[0],
    );
    try std.testing.expect(entries[1].values[1].eql(QM31.fromBase(index)));
    try std.testing.expect(entries[1].values[2].eql(QM31.fromBase(value)));
    for (entries[1].values[3..6]) |zero|
        try std.testing.expect(zero.isZero());

    const inactive = try typed_authority.public_logup_plan.entries(
        &typed_authority.public_logup_definition.arena,
        air_v2.PublicLogUp.SEMANTIC_DIGEST,
        typed_authority.public_logup_definition.events,
        air_v2.PublicLogUp.logicalRow(M31.zero(), M31.zero(), M31.zero()),
    );
    for (inactive) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "segment leaf outer V2 consumes only verifier-captured compensation and exports row34 calls" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try source_v2.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const native = native_relations.Relations.dummy();
    const outer = universal.UniversalRelations.dummy();
    const shape = try authority.preflight(&data, &keys);
    var typed_authority = try authority.AuthorityV2.init(std.testing.allocator);
    defer typed_authority.deinit();
    var workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer workspace.deinit();
    var owned = try OwnedTraces.init(std.testing.allocator, &shape.manifest);
    defer owned.deinit();

    var component_descs: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = 10,
    };
    var infra_descs: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    infra_descs[0] = .{
        .kind = .program,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = 4,
    };
    const core_public = try statement_v2.canonicalCorePublicData(&data);
    const core = statement_v1.RiscVStatement{
        .n_components = 1,
        .component_descs = component_descs,
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .total_steps = core_public.clock,
        .public_data = core_public,
        .n_infra = 1,
        .infra_descs = infra_descs,
    };
    const statement = try statement_v2.RiscVStatementV2.init(core, data);
    const receipt = try statement.verifiedReceipt();
    const native_sums = try statement_v2.NativePublicSums.init(&data, &native);

    var prepared: authority.PreparedNativeVerifierOuterAuthorityV2 = undefined;
    try authority.prepareNativeVerifierInto(
        &prepared,
        &workspace,
        &typed_authority,
        owned.traces(),
        &data,
        &keys,
        &native,
        &native_sums,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
        &outer,
    );
    try prepared.validateAgainst(
        &data,
        &keys,
        &native,
        &native_sums,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
        &outer,
    );
    try std.testing.expect(!prepared.productionReady());
    try std.testing.expectEqual(
        source_v2.VERIFIED_NATIVE_LOGUP_TAG,
        prepared.public_logup.wire_tag,
    );
    try std.testing.expect(std.meta.eql(
        prepared.public_logup.statement_authority_id,
        prepared.authority_hash_plan.statement_authority_id,
    ));
    try std.testing.expect(std.meta.eql(
        native_sums.identity,
        prepared.public_logup.native_public_sums_identity,
    ));

    const calls = try std.testing.allocator.alloc(
        poseidon2_air.Call,
        try prepared.authorityPoseidonCallCount(),
    );
    defer std.testing.allocator.free(calls);
    try prepared.appendAuthorityPoseidonCallsInto(
        calls,
        &data,
        &receipt,
        core.component_descs[0..core.n_components],
        core.infra_descs[0..core.n_infra],
    );
    const final_output = poseidon2_air.output(poseidon2_air.fill(calls[calls.len - 1]));
    for (final_output[0..receipt.authority_id.len], receipt.authority_id) |actual, expected|
        try expectM31(expected, actual);

    var bad_receipt = receipt;
    bad_receipt.wire_id[0] +%= 1;
    var rejected: authority.PreparedNativeVerifierOuterAuthorityV2 = undefined;
    @memset(std.mem.asBytes(&rejected), 0x67);
    const rejected_before = std.mem.asBytes(&rejected).*;
    owned.fill(sentinel());
    try std.testing.expectError(
        error.InvalidVerifiedReceipt,
        authority.prepareNativeVerifierInto(
            &rejected,
            &workspace,
            &typed_authority,
            owned.traces(),
            &data,
            &keys,
            &native,
            &native_sums,
            &bad_receipt,
            core.component_descs[0..core.n_components],
            core.infra_descs[0..core.n_infra],
            &outer,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &rejected_before,
        std.mem.asBytes(&rejected),
    );
    for (owned.storage) |word| try std.testing.expect(word.eql(sentinel()));
}

test "segment leaf outer V2 verifier and publication are fail atomic" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try source_v2.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const native = native_relations.Relations.dummy();
    const outer = universal.UniversalRelations.dummy();
    const shape = try authority.preflight(&data, &keys);
    var typed_authority = try authority.AuthorityV2.init(std.testing.allocator);
    defer typed_authority.deinit();
    var prover_workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer prover_workspace.deinit();
    var verifier_workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer verifier_workspace.deinit();
    var owned = try OwnedTraces.init(std.testing.allocator, &shape.manifest);
    defer owned.deinit();
    var prepared: authority.PreparedOuterAuthorityV2 = undefined;
    try authority.prepareInto(
        &prepared,
        &prover_workspace,
        &typed_authority,
        owned.traces(),
        &data,
        &keys,
        &native,
        &outer,
    );

    var verification: authority.AuthorityVerificationV2 = undefined;
    @memset(std.mem.asBytes(&verification), 0xa5);
    const verification_before = std.mem.asBytes(&verification).*;
    owned.public_logup_main[0][0] = owned.public_logup_main[0][0].add(M31.one());
    try std.testing.expectError(
        error.TraceMismatch,
        authority.verifyAuthorityInto(
            &verification,
            &verifier_workspace,
            &typed_authority,
            owned.traces(),
            &prepared,
            &data,
            &keys,
            &native,
            &outer,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &verification_before,
        std.mem.asBytes(&verification),
    );
    owned.public_logup_main[0][0] = owned.public_logup_main[0][0].sub(M31.one());

    try authority.verifyAuthorityInto(
        &verification,
        &verifier_workspace,
        &typed_authority,
        owned.traces(),
        &prepared,
        &data,
        &keys,
        &native,
        &outer,
    );
    try verification.validateAgainst(&prepared);
    try std.testing.expect(!verification.outer_stark_verified);
    try std.testing.expect(!verification.productionReady());

    var publication: authority.VerifiedAuthorityPublicationV2 = undefined;
    try authority.publishVerifiedInto(
        &publication,
        &verification,
        &prepared,
        &data,
        &native,
    );
    try publication.validateAgainst(&prepared, &data, &native);
    try std.testing.expect(!publication.productionReady());
    try std.testing.expect(!publication.outer_stark_verified);

    var bad_verification = verification;
    bad_verification.identity[0] +%= 1;
    var rejected: authority.VerifiedAuthorityPublicationV2 = undefined;
    @memset(std.mem.asBytes(&rejected), 0x6d);
    const rejected_before = std.mem.asBytes(&rejected).*;
    try std.testing.expectError(
        error.InvalidVerification,
        authority.publishVerifiedInto(
            &rejected,
            &bad_verification,
            &prepared,
            &data,
            &native,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &rejected_before,
        std.mem.asBytes(&rejected),
    );

    try std.testing.expectError(
        error.NativeV2ProofApiUnavailable,
        authority.publishProductionInto(&rejected, &verification),
    );
    try std.testing.expectEqualSlices(
        u8,
        &rejected_before,
        std.mem.asBytes(&rejected),
    );
}

test "segment leaf outer V2 rejects cross-domain aggregate cancellation" {
    const statement = QM31.fromU32Unchecked(3, 5, 7, 11);
    const verifier_input = QM31.fromU32Unchecked(13, 17, 19, 23);
    const bridge = QM31.fromU32Unchecked(29, 31, 37, 41);
    const closure = authority.BoundaryClosureV2.init(
        statement,
        verifier_input,
        bridge,
    );
    try closure.validate();
    try closure.validateCounterparts(
        statement.neg(),
        verifier_input.neg(),
        bridge.neg(),
    );

    const delta = QM31.fromU32Unchecked(43, 47, 53, 59);
    const epsilon = QM31.fromU32Unchecked(61, 67, 71, 73);
    const wrong_statement = statement.neg().add(delta);
    const wrong_verifier = verifier_input.neg().sub(delta).add(epsilon);
    const wrong_bridge = bridge.neg().sub(epsilon);
    try std.testing.expect(
        statement.add(verifier_input).add(bridge)
            .add(wrong_statement).add(wrong_verifier).add(wrong_bridge).isZero(),
    );
    try std.testing.expectError(
        error.CrossDomainClosureMismatch,
        closure.validateCounterparts(
            wrong_statement,
            wrong_verifier,
            wrong_bridge,
        ),
    );
}

test "segment leaf outer V2 retained hot path performs zero heap allocations" {
    var fixture = try support.Fixture.init();
    const source = fixture.rightSource();
    const words = try support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    const keys = try source_v2.VerifierKeyAuthorityV2.init(
        support.id("segment-leaf-v2-vk"),
        support.id("recursive-parent-v2-vk"),
    );
    const native = native_relations.Relations.dummy();
    const outer = universal.UniversalRelations.dummy();
    const shape = try authority.preflight(&data, &keys);
    var typed_authority = try authority.AuthorityV2.init(std.testing.allocator);
    defer typed_authority.deinit();
    var prover_workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer prover_workspace.deinit();
    var verifier_workspace = try authority.WorkspaceV2.init(
        std.testing.allocator,
        &shape.manifest,
    );
    defer verifier_workspace.deinit();
    var owned = try OwnedTraces.init(std.testing.allocator, &shape.manifest);
    defer owned.deinit();

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const measured_allocator = measured.allocator();
    const saved_authority_allocator = typed_authority.allocator;
    const saved_prover_allocator = prover_workspace.allocator;
    const saved_prover_statement_allocator =
        prover_workspace.statement_interaction.allocator;
    const saved_prover_logup_allocator =
        prover_workspace.public_logup_interaction.allocator;
    const saved_verifier_allocator = verifier_workspace.allocator;
    const saved_verifier_statement_allocator =
        verifier_workspace.statement_interaction.allocator;
    const saved_verifier_logup_allocator =
        verifier_workspace.public_logup_interaction.allocator;
    typed_authority.allocator = measured_allocator;
    prover_workspace.allocator = measured_allocator;
    prover_workspace.statement_interaction.allocator = measured_allocator;
    prover_workspace.public_logup_interaction.allocator = measured_allocator;
    verifier_workspace.allocator = measured_allocator;
    verifier_workspace.statement_interaction.allocator = measured_allocator;
    verifier_workspace.public_logup_interaction.allocator = measured_allocator;
    defer {
        verifier_workspace.public_logup_interaction.allocator =
            saved_verifier_logup_allocator;
        verifier_workspace.statement_interaction.allocator =
            saved_verifier_statement_allocator;
        verifier_workspace.allocator = saved_verifier_allocator;
        prover_workspace.public_logup_interaction.allocator =
            saved_prover_logup_allocator;
        prover_workspace.statement_interaction.allocator =
            saved_prover_statement_allocator;
        prover_workspace.allocator = saved_prover_allocator;
        typed_authority.allocator = saved_authority_allocator;
    }

    var prepared: authority.PreparedOuterAuthorityV2 = undefined;
    try authority.prepareInto(
        &prepared,
        &prover_workspace,
        &typed_authority,
        owned.traces(),
        &data,
        &keys,
        &native,
        &outer,
    );
    var verification: authority.AuthorityVerificationV2 = undefined;
    try authority.verifyAuthorityInto(
        &verification,
        &verifier_workspace,
        &typed_authority,
        owned.traces(),
        &prepared,
        &data,
        &keys,
        &native,
        &outer,
    );
    var publication: authority.VerifiedAuthorityPublicationV2 = undefined;
    try authority.publishVerifiedInto(
        &publication,
        &verification,
        &prepared,
        &data,
        &native,
    );
    try std.testing.expectEqual(@as(usize, 0), measured.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), measured.allocated_bytes);
}

test "segment leaf outer V2 semantic identities and digest types are pinned" {
    try std.testing.expectEqualSlices(
        u8,
        &air_v2.Statement.SEMANTIC_DIGEST,
        &try air_v2.Statement.computeSemanticDigest(std.testing.allocator),
    );
    try std.testing.expectEqualSlices(
        u8,
        &air_v2.PublicLogUp.SEMANTIC_DIGEST,
        &try air_v2.PublicLogUp.computeSemanticDigest(std.testing.allocator),
    );
    const row11_digest = try air_v2.StatementSemanticsV2.computeSemanticDigest(
        std.testing.allocator,
    );
    try std.testing.expectEqualSlices(
        u8,
        &air_v2.StatementSemanticsV2.SEMANTIC_DIGEST,
        &row11_digest,
    );
    try std.testing.expectEqual(@as(usize, 0), authority.HOT_PREPARE_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 0), authority.HOT_VERIFY_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 0), authority.HOT_PUBLISH_HEAP_ALLOCATIONS);
    try std.testing.expect(authority.NATIVE_V2_PROOF_API_AVAILABLE);
    try std.testing.expect(!authority.OUTER_STARK_VERIFICATION_AVAILABLE);
    try std.testing.expect(!authority.PRODUCTION_ACTIVATION);
    comptime {
        if (@TypeOf(@as(authority.OuterManifestV2, undefined).identity) !=
            authority.NativeDigest)
        {
            @compileError("native manifest identity changed representation");
        }
        if (@TypeOf(@as(authority.OuterManifestV2, undefined).authority_sha_id) !=
            authority.Sha256Digest)
        {
            @compileError("SHA typed-AIR authority changed representation");
        }
    }
}
