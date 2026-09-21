const std = @import("std");
const subject = @import("lookup_physical_manifest_v2.zig");
const composition = @import("opcode_composition_manifest.zig");
const statement_mod = @import("../statement.zig");

test "lookup polynomial v2: physical manifest pins the full native cohort" {
    var manifest = subject.Manifest.native();
    try manifest.validate();
    try std.testing.expectEqual(@as(u16, 17), manifest.family_count);
    try std.testing.expectEqual(@as(u32, 243), manifest.total_lookup_entries);
    try std.testing.expectEqual(@as(u32, 138), manifest.total_batches);
    try std.testing.expectEqual(
        @as(u32, 552),
        manifest.total_interaction_columns,
    );
    try std.testing.expectEqual(@as(u32, 646), manifest.total_main_columns);
    try std.testing.expectEqual(@as(u32, 34), manifest.total_adapters);

    var previous_claim_end: u32 = 0;
    var previous_interaction_end: u32 = 0;
    for (&manifest.entries, 0..) |*entry, index| {
        try std.testing.expectEqual(
            composition.TRANSCRIPT_ORDER[index],
            entry.family,
        );
        try std.testing.expectEqual(previous_claim_end, entry.detailed_claim_offset);
        try std.testing.expectEqual(
            previous_interaction_end,
            entry.interaction_column_offset,
        );
        try std.testing.expectEqual(
            entry.lookup_authority.batch_count,
            entry.detailed_claim_count,
        );
        try std.testing.expectEqual(
            4 * entry.detailed_claim_count,
            entry.interaction_column_count,
        );
        try subject.validatePinnedEntry(entry);
        previous_claim_end += entry.detailed_claim_count;
        previous_interaction_end += entry.interaction_column_count;
    }
    try std.testing.expectEqual(manifest.total_batches, previous_claim_end);
    try std.testing.expectEqual(
        manifest.total_interaction_columns,
        previous_interaction_end,
    );
}

test "lookup polynomial v2: physical manifest is deterministic and compiler-identical" {
    const first = subject.Manifest.native();
    const second = subject.Manifest.native();
    try std.testing.expectEqualDeep(first, second);
    try first.auditAgainstCompiler(std.testing.allocator);
}

test "lookup polynomial v2: physical manifest mutation fleet fails closed" {
    const canonical = subject.Manifest.native();
    const Mutation = enum {
        version,
        total_batches,
        family_order,
        adapter_offset,
        main_offset,
        claim_offset,
        program_identity,
        batch_width,
        manifest_identity,
    };
    const mutations = std.enums.values(Mutation);
    for (mutations) |mutation| {
        var candidate = canonical;
        switch (mutation) {
            .version => candidate.format_version += 1,
            .total_batches => candidate.total_batches -= 1,
            .family_order => candidate.entries[0].family = .base_alu_imm,
            .adapter_offset => candidate.entries[1].lookup_adapter_index += 1,
            .main_offset => candidate.entries[2].main_column_offset += 1,
            .claim_offset => candidate.entries[3].detailed_claim_offset += 1,
            .program_identity => candidate.entries[4].lookup_authority.program_identity[0] ^= 1,
            .batch_width => candidate.entries[5].batches.values[0].entry_count = 1,
            .manifest_identity => candidate.identity[0] ^= 1,
        }
        if (candidate.validate()) |_| {
            return error.ExpectedManifestRejection;
        } else |_| {}
    }
}

test "lookup polynomial v2: statement admission binds shard geometry and activation" {
    var manifest = subject.Manifest.native();
    var statement = canonicalStatement();
    const first = try subject.AuthenticatedStatement.init(&statement, &manifest);
    const second = try subject.AuthenticatedStatement.init(&statement, &manifest);
    try std.testing.expectEqualDeep(first, second);
    try first.validateAgainst(&statement, &manifest);
    try std.testing.expectEqual(@as(u32, 17), first.component_count);
    try std.testing.expectEqual(@as(u32, 646), first.opcode_main_columns);
    try std.testing.expectEqual(@as(u32, 552), first.opcode_interaction_columns);
    try std.testing.expectEqual(@as(u32, 138), first.detailed_claim_count);

    var wrong_statement = statement;
    wrong_statement.component_descs[0].n_columns += 1;
    try std.testing.expectError(
        error.InvalidMainGeometry,
        first.validateAgainst(&wrong_statement, &manifest),
    );
    wrong_statement = statement;
    std.mem.swap(
        @TypeOf(wrong_statement.component_descs[0]),
        &wrong_statement.component_descs[0],
        &wrong_statement.component_descs[1],
    );
    try std.testing.expectError(
        error.InvalidFamilyOrder,
        first.validateAgainst(&wrong_statement, &manifest),
    );

    var wrong_token = first;
    wrong_token.statement_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidStatementIdentity,
        wrong_token.validateAgainst(&statement, &manifest),
    );
    wrong_token = first;
    wrong_token.activation_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidActivationIdentity,
        wrong_token.validateAgainst(&statement, &manifest),
    );
}

pub fn canonicalStatement() statement_mod.RiscVStatement {
    var result: statement_mod.RiscVStatement = undefined;
    result.n_components = subject.FAMILY_COUNT;
    for (composition.TRANSCRIPT_ORDER, 0..) |family, index| {
        result.component_descs[index] = .{
            .family = family,
            .log_size = 5,
            .n_rows = 32,
            .n_columns = @intCast(composition.mainColumnCount(family)),
        };
    }
    result.initial_pc = 0;
    result.final_pc = 4;
    result.total_steps = 1;
    result.public_data = undefined;
    result.n_infra = 0;
    return result;
}
