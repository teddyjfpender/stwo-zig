const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const air = @import("stwo_riscv_recursion").air.segment_publication_input_provider;
const binding = @import("stwo_riscv_recursion").air.segment_publication_input_provider_relation;
const witness = @import("stwo_riscv_recursion").air.segment_publication_input_provider_witness;
const authority = @import("stwo_riscv_recursion").segment_publication_input_provider_authority;
const exact_support = @import("stwo_riscv_recursion").testing.segment_publication_input_provider_test_support;

test "publication provider preserves all 88 retained segment claims and rejects source mutation" {
    const allocator = std.testing.allocator;
    const support = @import("../ethereum_leaf_context_test_support.zig");
    var fixture = try exact_support.Fixture.initWithCore(allocator, support.retainedSegmentZeroCore());
    defer fixture.deinit();
    const source = try witness.preflight(fixture.inputs());
    try std.testing.expectEqual(@as(u32, 88), source.shape.claim_count);
    try std.testing.expectEqual(@as(u32, 407), source.shape.logical_row_count);
    try std.testing.expectEqual(@as(usize, 512), source.shape.traceRowCount());
    var owner = try authority.AuthorityV2.init(allocator);
    defer owner.deinit();
    var workspace = try authority.WorkspaceV2.initForShape(allocator, source.shape);
    defer workspace.deinit();
    var output = try authority.WorkspaceV2.initForShape(allocator, source.shape);
    defer output.deinit();
    var prepared: authority.PreparedAuthorityV2 = undefined;
    try authority.prepareInto(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations);
    try authority.verifyTrace(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations);
    try std.testing.expectError(error.AliasedDestination, authority.verifyTrace(&prepared, &workspace, &owner, workspace.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    var row: usize = witness.LUP2_WORD_COUNT;
    for (source.detailed_claims) |claim| {
        for (claim.toM31Array()) |limb| {
            try std.testing.expect(limb.eql(output.stagedTrace().main[0][row]));
            try workspace.relation_events[row].validate(source.shape);
            row += 1;
        }
    }
    try std.testing.expectEqual(source.shape.logical_row_count, row);
    for (output.stagedTrace().main[0][row..]) |word| try std.testing.expect(word.isZero());

    const output_before = try allocator.dupe(M31, output.storage);
    defer allocator.free(output_before);
    fixture.sources.vm_context.detailed_claims[87] = fixture.sources.vm_context.detailed_claims[87].add(QM31.one());
    try std.testing.expectError(error.InvalidPreparedSource, witness.writeInto(&source, .{
        .main = output.stagedTrace().main,
        .preprocessed = output.stagedTrace().preprocessed,
        .logical_rows = output.logical_rows,
        .relation_events = output.relation_events,
    }));
    try std.testing.expectEqualSlices(M31, output_before, output.storage);
    fixture.sources.vm_context.detailed_claims[87] = fixture.sources.vm_context.detailed_claims[87].sub(QM31.one());

    var wrong_workspace = try authority.WorkspaceV2.init(allocator);
    defer wrong_workspace.deinit();
    const prepared_before = prepared;
    try std.testing.expectError(error.WorkspaceMismatch, authority.prepareInto(&prepared, &wrong_workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    try std.testing.expectEqualDeep(prepared_before, prepared);
    try std.testing.expectEqualSlices(M31, output_before, output.storage);

    const logical_rows = workspace.logical_rows;
    workspace.logical_rows = std.mem.bytesAsSlice(binding.Row, std.mem.sliceAsBytes(workspace.storage[0 .. logical_rows.len * air.LOGICAL_INPUT_COUNT]));
    defer workspace.logical_rows = logical_rows;
    try std.testing.expectError(error.AliasedDestination, authority.prepareInto(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    try std.testing.expectEqualDeep(prepared_before, prepared);
    try std.testing.expectEqualSlices(M31, output_before, output.storage);
}
