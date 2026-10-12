test {
    _ = @import("recursion/segment_leaf_wrapper_cohort_views_v3.zig");
}

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const views_mod = @import("recursion/segment_leaf_wrapper_cohort_views_v3.zig");
const direct = @import("recursion/air/segment_leaf_wrapper_roster_direct_v4.zig");
const v2 = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const catalog = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const program_mod = @import("recursion/ethereum_leaf_link_program_v3.zig");
const fixture = @import("wrapper_roster_v3_test_root.zig");
const call_buffer = @import("recursion/segment_leaf_wrapper_cohort_calls_v3.zig");
const provider = @import("recursion/segment_leaf_wrapper_cohort_provider_v3.zig");
const typed_rows = @import("recursion/segment_leaf_wrapper_cohort_typed_rows_v4.zig");
const word_air = @import("recursion/air/transcript_program_v2_field_source_v1.zig");
const word_witness = @import("recursion/transcript_program_v2_field_word_witness_v1.zig");
const hash_witness = @import("recursion/segment_leaf_wrapper_field_hash_witness_v3.zig");
const source_air = @import("recursion/air/ethereum_leaf_link_source_v1.zig");
const program_field = @import("recursion/transcript_program_v2_field_authority_v1.zig");
const channel = @import("recursion/poseidon2_channel.zig");
const framework = @import("recursion/air/framework_interaction.zig");
const universal = @import("recursion/air/universal_challenges.zig");

test "direct 47-row PlanV4 maps V2 main columns with only old row34 scratch" {
    const allocator = std.testing.allocator;
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const plan = try direct.Plan.build(allocator, &base, &program, .{ .program_words = 100, .base_poseidon_calls = 1193 });
    const destination = try allocator.alloc([]M31, plan.total_main_columns);
    defer allocator.free(destination);
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (destination[item.main_offset..][0..item.geometry.main_columns]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
        }
    }
    defer for (destination) |column| allocator.free(column);
    var views = try views_mod.Views.initForPlan(allocator, &base, &plan, destination, direct.MAIN_TREE_INDEX);
    defer views.deinit();
    try std.testing.expectEqual(@as(usize, base.total_main_columns), views.columns.len);
    const old_regular = base.placements[18].?.main_offset;
    const new_regular = plan.placements[18].?.main_offset;
    views.columns[old_regular][0] = M31.fromCanonical(19);
    try std.testing.expectEqual(@as(u32, 19), destination[new_regular][0].toU32());
    const old_provider = base.placements[34].?.main_offset;
    const new_provider = plan.placements[34].?.main_offset;
    views.columns[old_provider][0] = M31.fromCanonical(29);
    try std.testing.expectEqual(@as(u32, 29), views.old_provider_scratch[0].toU32());
    try std.testing.expect(destination[new_provider][0].isZero());
    try std.testing.expectEqual(
        @as(usize, base.placements[34].?.geometry.main_columns) << @intCast(base.placements[34].?.geometry.log_size),
        views.old_provider_scratch.len,
    );

    const calls = try allocator.alloc(call_buffer.Call, plan.poseidon_calls.total);
    defer allocator.free(calls);
    for (calls, 0..) |*call, i| call.* = .{ .input = @splat(@intCast(i + 1)), .io = true };
    const parts = [_][]const call_buffer.Call{
        calls[0..1193], calls[1193..1270], calls[1270..1277], calls[1277..1290],
    };
    var buffer = try call_buffer.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider.Writer.initForDirectPlan(allocator, &plan, &buffer, &parts);
    try std.testing.expectEqual(plan.placements[34].?.geometry.log_size, try writer.logSize());
    const wrong_parts = [_][]const call_buffer.Call{
        calls[0..1193], calls[1193..1269], calls[1269..1277], calls[1277..1290],
    };
    var wrong_buffer = try call_buffer.Buffer.init(allocator, &wrong_parts);
    defer wrong_buffer.deinit();
    try std.testing.expectError(
        error.DirectProviderCallLayoutMismatch,
        provider.Writer.initForDirectPlan(allocator, &plan, &wrong_buffer, &wrong_parts),
    );

    const pp = try allocator.alloc([]M31, plan.total_preprocessed_columns);
    defer allocator.free(pp);
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (pp[item.preprocessed_offset..][0..item.geometry.preprocessed_columns]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
        }
    }
    defer for (pp) |column| allocator.free(column);
    const words = [_]M31{M31.fromCanonical(17)} ** 100;
    var word_rows = try word_witness.WordsV1.init(allocator, &words, word_air.PROGRAM_WORD_SCOPE);
    defer word_rows.deinit();
    try typed_rows.fillPreprocessed(word_air, &plan, .program_words, word_rows.rows, pp);
    try typed_rows.fillMain(word_air, &plan, .program_words, word_rows.rows, destination);
    const program_placement = plan.placements[42].?;
    const first_word_row = framework.committedRow(0, program_placement.geometry.log_size);
    try std.testing.expectEqual(@as(u32, 17), destination[program_placement.main_offset][first_word_row].toU32());
    try std.testing.expectEqual(@as(u32, 17), pp[program_placement.preprocessed_offset + 1][first_word_row].toU32());
    try std.testing.expectError(error.DirectTypedRowDestinationNotFresh, typed_rows.fillMain(word_air, &plan, .program_words, word_rows.rows, destination));
    try std.testing.expectError(error.DirectTypedRowGeometryMismatch, typed_rows.fillMain(word_air, &plan, .program_hash, word_rows.rows, destination));

    var hash_rows = try hash_witness.HashV1.init(
        allocator,
        &words,
        program_field.PROGRAM_DOMAIN,
        word_air.PROGRAM_WORD_SCOPE,
        source_air.PROGRAM_AUTHORITY_KIND,
        hash_witness.PROGRAM_STEP_BASE,
        channel.hashCanonicalWords(&words, program_field.PROGRAM_DOMAIN),
    );
    defer hash_rows.deinit();
    try typed_rows.fillHashPreprocessed(&plan, .program_hash, &hash_rows, pp);
    try typed_rows.fillHashMain(&plan, .program_hash, &hash_rows, destination);
    const hash_placement = plan.placements[43].?;
    const first_hash_row = framework.committedRow(0, hash_placement.geometry.log_size);
    try std.testing.expectEqual(@as(u32, 1), destination[hash_placement.main_offset][first_hash_row].toU32());

    const io = try allocator.alloc([]M31, plan.total_interaction_columns);
    defer allocator.free(io);
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (io[item.interaction_offset..][0..item.geometry.interaction_columns]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
        }
    }
    defer for (io) |column| allocator.free(column);
    const relations = universal.UniversalRelations.dummy();
    var word_interaction = try word_rows.generateInteraction(allocator, &relations);
    defer word_interaction.deinit(allocator);
    const word_claim = try typed_rows.fillInteraction(&plan, .program_words, &word_interaction, io);
    try std.testing.expect(word_claim.eql(word_interaction.claims.total()));
    try std.testing.expectEqualDeep(word_interaction.columns[0], io[program_placement.interaction_offset]);
    var hash_interaction = try hash_rows.generateInteraction(allocator, &relations);
    defer hash_interaction.deinit(allocator);
    const hash_claim = try typed_rows.fillInteraction(&plan, .program_hash, &hash_interaction, io);
    try std.testing.expect(hash_claim.eql(hash_interaction.claims.total()));
    try std.testing.expectError(error.DirectTypedRowDestinationNotFresh, typed_rows.fillInteraction(&plan, .program_hash, &hash_interaction, io));
}
