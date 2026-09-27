const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const verifier_types = @import("stwo_core").verifier_types;

const component_order = @import("../../air/component_order.zig");
const lookup_table_schema = @import("../../air/lookups/tables/schema.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const public_data = @import("../../air/public_data.zig");
const base_statement = @import("../../air/statement.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const bulk_relations = @import("../../air/guest_precompile/bulk_memcpy_relations_v1.zig");
const bulk_stark = @import("../../air/guest_precompile/bulk_memcpy_stark_component_v1.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const combined_authority = @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");

test "candidate leaf lifts ordinary split-one handles without replacing callbacks" {
    const OrdinaryCaller = bulk_stark.ComponentWithCompositionLogSplit(
        bulk_contract.Caller,
        1,
    );
    const claim = try bulk_contract.CallerClaim.canonical(
        1,
        1,
        .{QM31.zero()} ** bulk_contract.Caller.batch_count,
    );
    const relations = bulk_relations.Relations.dummy();
    const component = try OrdinaryCaller.init(
        claim,
        .{
            .preprocessed_offset = 0,
            .main_offset = 0,
            .interaction_offset = 0,
        },
        &relations,
    );

    const ordinary_prover = component.asProverComponent();
    const lifted_prover = try integration.liftOrdinaryProverComponent(
        ordinary_prover,
    );
    try std.testing.expectEqual(@as(u32, 1), ordinary_prover.compositionLogSplit());
    try std.testing.expectEqual(
        ordinary_prover.maxConstraintLogDegreeBound() + 1,
        lifted_prover.maxConstraintLogDegreeBound(),
    );
    try std.testing.expectEqual(@as(u32, 2), lifted_prover.compositionLogSplit());
    try std.testing.expectEqual(
        ordinary_prover.maxConstraintLogDegreeBound() -
            ordinary_prover.compositionLogSplit(),
        lifted_prover.maxConstraintLogDegreeBound() -
            lifted_prover.compositionLogSplit(),
    );
    try std.testing.expect(lifted_prover.ctx == ordinary_prover.ctx);
    try std.testing.expect(lifted_prover.vtable == ordinary_prover.vtable);
    try std.testing.expect(ordinary_prover.prepare_domain_evaluator != null);
    try std.testing.expect(
        lifted_prover.prepare_domain_evaluator ==
            ordinary_prover.prepare_domain_evaluator,
    );
    try std.testing.expect(
        lifted_prover.domain_parallel_evaluator ==
            ordinary_prover.domain_parallel_evaluator,
    );
    try std.testing.expectError(
        error.EthereumCandidateLeafOrdinaryCompositionGeometryMismatch,
        integration.liftOrdinaryProverComponent(lifted_prover),
    );

    const ordinary_verifier = component.asVerifierComponent();
    const lifted_verifier = try integration.liftOrdinaryVerifierComponent(
        ordinary_verifier,
    );
    try std.testing.expectEqual(
        ordinary_verifier.maxConstraintLogDegreeBound() + 1,
        lifted_verifier.maxConstraintLogDegreeBound(),
    );
    try std.testing.expectEqual(@as(u32, 2), lifted_verifier.compositionLogSplit());
    try std.testing.expectEqual(
        ordinary_verifier.maxConstraintLogDegreeBound() -
            ordinary_verifier.compositionLogSplit(),
        lifted_verifier.maxConstraintLogDegreeBound() -
            lifted_verifier.compositionLogSplit(),
    );
    try std.testing.expect(lifted_verifier.ctx == ordinary_verifier.ctx);
    try std.testing.expect(lifted_verifier.vtable == ordinary_verifier.vtable);
    try std.testing.expectError(
        error.EthereumCandidateLeafOrdinaryCompositionGeometryMismatch,
        integration.liftOrdinaryVerifierComponent(lifted_verifier),
    );
}

test "candidate leaf profile rejects every placement and authority mutation" {
    const core = admittedCore(2);
    const extension = try ethereum_statement.Statement.canonical(
        &core,
        1,
        1,
        secpShapes(1),
    );
    var elf_digest = [_]u8{0} ** 32;
    elf_digest[0] = 1;
    const authority = try combined_authority.Authority.create(elf_digest);
    const base_interaction_columns: u32 = @intCast(core.nInteractionColumns() + 7);
    const profile = try profile_mod.Profile.create(
        &core,
        &extension,
        base_interaction_columns,
        authority,
        1,
        8,
        1,
    );
    try profile.validate(&core, &extension, base_interaction_columns);
    try std.testing.expectEqual(@as(u8, 2), profile_mod.composition_log_split);
    try std.testing.expectEqual(
        @as(usize, 16),
        verifier_types.compositionColumnCount(
            profile_mod.composition_log_split,
            4,
        ).?,
    );
    for (profile.components) |component| try std.testing.expectEqual(
        profile_mod.composition_log_split,
        component.composition_log_split,
    );

    try expectRejected(profile.validate(
        &core,
        &extension,
        base_interaction_columns + 1,
    ));

    var wrong_extension = extension;
    wrong_extension.components[0].main_columns += 1;
    try expectRejected(profile.validate(
        &core,
        &wrong_extension,
        base_interaction_columns,
    ));
    wrong_extension = extension;
    const first = wrong_extension.components[0];
    wrong_extension.components[0] = wrong_extension.components[1];
    wrong_extension.components[1] = first;
    try expectRejected(profile.validate(
        &core,
        &wrong_extension,
        base_interaction_columns,
    ));

    var wrong = profile;
    wrong.authority.guest_elf_sha256[0] ^= 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
    wrong = profile;
    wrong.bulk_memcpy_call_count += 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
    wrong = profile;
    wrong.bulk_memcpy_word_row_count += 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
    wrong = profile;
    wrong.stack_swap_call_count += 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
    wrong = profile;
    wrong.components[0].composition_log_split = 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
    wrong = profile;
    wrong.placements.stack_swap_words.interaction_offset += 1;
    try expectRejected(wrong.validate(
        &core,
        &extension,
        base_interaction_columns,
    ));
}

test "candidate leaf claims bind all four profile descriptors and call closure" {
    const core = admittedCore(2);
    const extension = try ethereum_statement.Statement.canonical(
        &core,
        1,
        1,
        secpShapes(1),
    );
    var elf_digest = [_]u8{0} ** 32;
    elf_digest[0] = 2;
    const profile = try profile_mod.Profile.create(
        &core,
        &extension,
        @intCast(core.nInteractionColumns()),
        try combined_authority.Authority.create(elf_digest),
        1,
        8,
        1,
    );
    const claims = integration.Claims{
        .bulk_memcpy_caller = try bulk_contract.CallerClaim.canonical(
            profile.components[0].log_size,
            profile.components[0].n_rows,
            .{QM31.zero()} ** bulk_contract.Caller.batch_count,
        ),
        .bulk_memcpy_words = try bulk_contract.WordClaim.canonical(
            profile.components[1].log_size,
            profile.components[1].n_rows,
            .{QM31.zero()} ** bulk_contract.Word.batch_count,
        ),
        .stack_swap_caller = try swap_contract.CallerClaim.canonical(
            profile.components[2].log_size,
            profile.components[2].n_rows,
            .{QM31.zero()} ** swap_contract.Caller.batch_count,
        ),
        .stack_swap_words = try swap_contract.WordClaim.canonical(
            profile.components[3].log_size,
            profile.components[3].n_rows,
            .{QM31.zero()} ** swap_contract.Word.batch_count,
        ),
    };
    try claims.validate(&profile);
    try std.testing.expect(claims.componentSum().isZero());

    var wrong_profile = profile;
    wrong_profile.components[3].log_size += 1;
    try expectRejected(claims.validate(&wrong_profile));
}

test "candidate leaf trace blocks instantiate every profile-bound column family" {
    const core = admittedCore(2);
    const extension = try ethereum_statement.Statement.canonical(
        &core,
        1,
        1,
        secpShapes(1),
    );
    var elf_digest = [_]u8{0} ** 32;
    elf_digest[0] = 3;
    const profile = try profile_mod.Profile.create(
        &core,
        &extension,
        @intCast(core.nInteractionColumns()),
        try combined_authority.Authority.create(elf_digest),
        1,
        8,
        1,
    );

    var caller_storage = [_]M31{M31.zero()} ** 2;
    var bulk_word_storage = [_]M31{M31.zero()} ** 8;
    var swap_word_storage = [_]M31{M31.zero()} ** 16;
    var blocks: integration.TraceBlocks = undefined;
    setColumns(&blocks.bulk_caller_preprocessed, &caller_storage);
    setColumns(&blocks.bulk_word_preprocessed, &bulk_word_storage);
    setColumns(&blocks.swap_caller_preprocessed, &caller_storage);
    setColumns(&blocks.swap_word_preprocessed, &swap_word_storage);
    setColumns(&blocks.bulk_caller_main, &caller_storage);
    setColumns(&blocks.bulk_word_main, &bulk_word_storage);
    setColumns(&blocks.swap_caller_main, &caller_storage);
    setColumns(&blocks.swap_word_main, &swap_word_storage);
    setColumns(&blocks.bulk_caller_interaction, &caller_storage);
    setColumns(&blocks.bulk_word_interaction, &bulk_word_storage);
    setColumns(&blocks.swap_caller_interaction, &caller_storage);
    setColumns(&blocks.swap_word_interaction, &swap_word_storage);
    blocks.log_sizes = .{
        profile.components[0].log_size,
        profile.components[1].log_size,
        profile.components[2].log_size,
        profile.components[3].log_size,
    };
    try blocks.validateAgainst(&profile);

    blocks.swap_word_main[0] = swap_word_storage[0..15];
    try std.testing.expectError(
        error.InvalidTraceShape,
        blocks.validateAgainst(&profile),
    );
}

fn expectRejected(result: anytype) !void {
    if (result) |_| return error.ExpectedCandidateLeafMutationRejection else |_| {}
}

fn setColumns(columns: anytype, values: []const M31) void {
    for (columns) |*column| column.* = values;
}

fn secpShapes(signer_calls: u32) ethereum_statement.SecpShapes {
    const singleton = ethereum_statement.Shape{ .log_size = 1, .n_rows = 1 };
    return .{
        .product_base = singleton,
        .product_scalar = singleton,
        .linear_base = singleton,
        .linear_scalar = singleton,
        .point = singleton,
        .split = singleton,
        .scalar = singleton,
        .table = singleton,
        .recovery = .{ .log_size = 1, .n_rows = signer_calls },
        .byte = .{ .log_size = 8, .n_rows = 256 },
        .recovery_caller = .{ .log_size = 1, .n_rows = signer_calls },
    };
}

fn admittedCore(external_retirements: u32) base_statement.RiscVStatement {
    var core = support.coreFixture(external_retirements);
    core.public_data.completion = public_data.Completion.canonicalSelfLoop(
        core.final_pc,
    );
    const clock_update = core.infra_descs[2];
    core.infra_descs[2] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    core.infra_descs[3] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    core.infra_descs[4] = clock_update;
    var index: usize = 5;
    for (component_order.lookupTables()) |kind| {
        core.infra_descs[index] = .{
            .kind = base_statement.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        index += 1;
    }
    core.n_infra = @intCast(index);
    return core;
}
