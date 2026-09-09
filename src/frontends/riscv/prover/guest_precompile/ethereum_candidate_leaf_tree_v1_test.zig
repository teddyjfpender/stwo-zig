const std = @import("std");

const component_order = @import("../../air/component_order.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const lookup_table_schema = @import("../../air/lookups/tables/schema.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const public_data = @import("../../air/public_data.zig");
const base_statement = @import("../../air/statement.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const combined_authority = @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const admission_mod = @import("ethereum_candidate_leaf_admission_v1.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");
const tree_mod = @import("ethereum_candidate_leaf_tree_v1.zig");

test "candidate leaf trees derive exact authenticated append-only logs" {
    const core = admittedCore(4);
    const extension = try ethereum_statement.Statement.canonical(
        &core,
        1,
        1,
        secpShapes(1),
    );
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &core,
        &manifest,
    );
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(&core, &manifest),
    );
    const profile = try profile_mod.Profile.create(
        &core,
        &extension,
        base_interaction_columns,
        try fixtureAuthority(1),
        1,
        8,
        1,
    );
    var logs = try tree_mod.logSizes(
        std.testing.allocator,
        &core,
        &extension,
        &manifest,
        &authenticated,
        &profile,
    );
    defer logs.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        @as(usize, profile.totals.preprocessed_columns),
        logs.tree0.len,
    );
    try std.testing.expectEqual(
        @as(usize, profile.totals.main_columns),
        logs.tree1.len,
    );
    try std.testing.expectEqual(
        @as(usize, profile.totals.interaction_columns),
        logs.tree2.len,
    );
    try expectCandidateTail(logs.tree0, &profile, .preprocessed);
    try expectCandidateTail(logs.tree1, &profile, .main);
    try expectCandidateTail(logs.tree2, &profile, .interaction);
    try std.testing.expectEqual(
        @as(usize, 128),
        tree_mod.candidate_interaction_column_count,
    );

    var wrong = profile;
    wrong.totals.interaction_columns += 1;
    try std.testing.expectError(
        error.EthereumCandidateLeafProfileMismatch,
        tree_mod.logSizes(
            std.testing.allocator,
            &core,
            &extension,
            &manifest,
            &authenticated,
            &wrong,
        ),
    );
}

test "candidate leaf admission binds retirement, memory, and table demand" {
    const core = admittedCore(4);
    const extension = try ethereum_statement.Statement.canonical(
        &core,
        1,
        1,
        secpShapes(1),
    );
    const profile = try profile_mod.Profile.create(
        &core,
        &extension,
        @intCast(core.nInteractionColumns()),
        try fixtureAuthority(2),
        1,
        8,
        1,
    );
    const admission = try admission_mod.validate(
        &core,
        &extension,
        @intCast(core.nInteractionColumns()),
        &profile,
        .proof,
    );
    try std.testing.expectEqual(@as(u32, 2), admission.candidate_retirements);
    try std.testing.expectEqual(@as(u32, 4), admission.total_external_retirements);
    try std.testing.expectEqual(
        @as(u64, 32),
        admission.candidate_extra_memory_terms,
    );
    try std.testing.expectEqual(
        extension.admission.extra_memory_terms + 32,
        admission.total_extra_memory_terms,
    );
    try std.testing.expectEqual(
        extension.admission.memory_relation_terms + 32,
        admission.expected_memory_relation_terms,
    );
    const range20 = @intFromEnum(lookup_table_schema.Kind.range_check_20);
    const range8 = @intFromEnum(lookup_table_schema.Kind.range_check_8_8);
    try std.testing.expectEqual(
        extension.admission.extended_fixed_table_bounds[range20] + 37,
        admission.extended_fixed_table_bounds[range20],
    );
    try std.testing.expectEqual(
        extension.admission.extended_fixed_table_bounds[range8] + 22,
        admission.extended_fixed_table_bounds[range8],
    );

    var wrong = admission;
    wrong.candidate_extra_memory_terms += 1;
    try std.testing.expectError(
        error.EthereumCandidateLeafAdmissionMismatch,
        wrong.validateAgainst(
            &core,
            &extension,
            @intCast(core.nInteractionColumns()),
            &profile,
        ),
    );
}

const ColumnFamily = enum { preprocessed, main, interaction };

fn expectCandidateTail(
    logs: []const u32,
    profile: *const profile_mod.Profile,
    family: ColumnFamily,
) !void {
    var additional: usize = 0;
    for (profile.components) |descriptor| additional += switch (family) {
        .preprocessed => descriptor.preprocessed_columns,
        .main => descriptor.main_columns,
        .interaction => descriptor.interaction_columns,
    };
    var cursor = logs.len - additional;
    for (profile.components) |descriptor| {
        const count: usize = switch (family) {
            .preprocessed => descriptor.preprocessed_columns,
            .main => descriptor.main_columns,
            .interaction => descriptor.interaction_columns,
        };
        for (logs[cursor..][0..count]) |log_size|
            try std.testing.expectEqual(descriptor.log_size, log_size);
        cursor += count;
    }
    try std.testing.expectEqual(logs.len, cursor);
}

fn fixtureAuthority(tag: u8) !combined_authority.Authority {
    var elf_digest = [_]u8{0} ** 32;
    elf_digest[0] = tag;
    return combined_authority.Authority.create(elf_digest);
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
