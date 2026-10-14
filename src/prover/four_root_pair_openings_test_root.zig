//! Honest four-root source-pair proof control. No AIR, OOD, or FRI proof is
//! accepted by this test; it exercises the production plain Merkle shape.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const M31 = core.fields.m31.M31;
const source = core.pcs.four_root_pair_openings_experimental;
const wire = core.pcs.four_root_pair_wire_experimental;

fn word(value: u32) M31 {
    return M31.fromCanonical(value);
}

test "CAS10 four plain Gate roots authenticate synchronized source pairs" {
    const alloc = std.testing.allocator;
    const fixed = [_]M31{ word(1), word(2), word(3), word(4) };
    const main = [_]M31{ word(5), word(6), word(7), word(8) };
    const interaction = [_]M31{ word(9), word(10) };
    var composition_words: [8][4]M31 = undefined;
    var composition: [8][]const M31 = undefined;
    for (&composition_words, &composition, 0..) |*words, *column, i| {
        for (words, 0..) |*value, row| value.* = word(@intCast(20 + 4 * i + row));
        column.* = words[0..];
    }
    const fixed_columns = [_][]const M31{fixed[0..]};
    const main_columns = [_][]const M31{main[0..]};
    const interaction_columns = [_][]const M31{interaction[0..]};
    const raw = [_]usize{ 1, 1, 3 };
    var proof = try prover.pcs.four_root_pair_openings_experimental.prove(
        alloc,
        .{
            .columns = .{
                &fixed_columns, &main_columns, &interaction_columns,
                &composition,
            },
            .lifting_log_size = 2,
            .raw_queries = &raw,
        },
    );
    defer proof.deinit();
    try std.testing.expectEqual(@as(usize, 8), proof.expected.column_log_sizes[3].len);
    try std.testing.expectEqualSlices(M31, &[_]M31{ word(9), word(10), word(9), word(10), word(9), word(10) }, proof.openings[2].queried_values[0]);
    try source.verify(alloc, proof.expected, proof.openings);
    const encoded = try wire.encode(alloc, proof.expected, proof.openings);
    defer alloc.free(encoded);
    try wire.verifyEncoded(alloc, encoded, proof.expected);
    try std.testing.expectError(error.TruncatedFourRootPairWire, wire.verifyEncoded(alloc, encoded[0 .. encoded.len - 1], proof.expected));
    try std.testing.expectError(error.InvalidFourRootPairShape, source.pairPositions(alloc, &[_]usize{4}, 2));
}
