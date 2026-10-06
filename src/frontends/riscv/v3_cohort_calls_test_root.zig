const std = @import("std");
const core = @import("stwo_core");
const schedule = @import("recursion/segment_leaf_wrapper_cohort_calls_v3.zig");
const provider = @import("recursion/segment_leaf_wrapper_cohort_provider_v3.zig");
const universal = @import("recursion/air/universal_challenges.zig");
const provider_relations = @import("recursion/air/universal_provider_relations.zig");
const poseidon_air = @import("air/memory_commitment/poseidon2_air.zig");

test "direct leaf row34 writes exact ordered Poseidon calls" {
    const allocator = std.testing.allocator;
    const calls = [_]schedule.Call{
        .{ .input = @splat(1), .io = true },
        .{ .input = @splat(2), .io = true },
        .{ .input = @splat(3), .io = true },
        .{ .input = @splat(4), .io = true },
        .{ .input = @splat(5), .io = true },
        .{ .input = @splat(6), .io = true },
        .{ .input = @splat(7), .io = true },
    };
    // Direct wrapper order: native verifier, metadata, link, native program.
    var parts = [_][]const schedule.Call{
        calls[0..3], calls[3..5], calls[5..6], calls[6..7],
    };
    var buffer = try schedule.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    try std.testing.expectEqual(@as(u32, 4), buffer.log_size);
    try std.testing.expectEqual(@as(usize, 3), buffer.ranges[1].start);
    const writer = try provider.Writer.init(allocator, &buffer, &parts);
    try writer.requireLogSize(4);
    try std.testing.expectError(error.PoseidonProviderGeometryMismatch, writer.requireLogSize(5));

    var preprocessed = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 16;
    try writer.fillPreprocessedInto(&preprocessed);
    const committed_first = committedRow(0);
    try std.testing.expectEqual(@as(u32, 1), preprocessed[committed_first].toU32());
    for (preprocessed, 0..) |value, row| if (row != committed_first) try std.testing.expect(value.isZero());
    var main: [provider.MAIN_COLUMNS][]core.fields.m31.M31 = undefined;
    for (&main) |*column| column.* = try allocator.alloc(core.fields.m31.M31, 16);
    defer for (main) |column| allocator.free(column);
    try writer.fillMainInto(&main);
    for (buffer.calls, 0..) |call, logical_row| {
        const expected = poseidon_air.fill(call);
        for (main, expected) |column, value|
            try std.testing.expect(column[committedRow(logical_row)].eql(value));
    }
    const dummy = universal.UniversalRelations.dummy();
    const relations = try provider_relations.SharedProviderRelations.init(&dummy);
    var interaction = try writer.generateInteraction(&relations);
    defer interaction.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 16), interaction.columns[0].len);

    // Source order and multiplicity are checked before any subsequent write.
    main[0][0] = core.fields.m31.M31.fromCanonical(123);
    buffer.calls[4].input[0] ^= 1;
    try std.testing.expectError(error.PoseidonCallBufferMismatch, writer.fillMainInto(&main));
    try std.testing.expectEqual(@as(u32, 123), main[0][0].toU32());
    buffer.calls[4].input[0] ^= 1;
    buffer.ranges[2].start -= 1;
    try std.testing.expectError(error.PoseidonCallBufferMismatch, writer.fillMainInto(&main));
    buffer.ranges[2].start += 1;
    const saved = parts[2];
    parts[2] = parts[3];
    try std.testing.expectError(error.PoseidonCallBufferMismatch, writer.fillMainInto(&main));
    parts[2] = saved;
    parts[3] = calls[7..7];
    try std.testing.expectError(error.PoseidonCallBufferMismatch, writer.fillMainInto(&main));
}

fn committedRow(logical: usize) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, 4), 4);
}
