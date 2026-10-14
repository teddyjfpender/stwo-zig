//! Experimental XDM05 source-tree geometry and authentication tests.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.transposed_sparse_heights_experimental;
const source = core.pcs.transposed_merkle_sparse_heights_experimental;
const M31 = core.fields.m31.M31;

test "XDM05 one-height source opens authenticated duplicate pairs" {
    const allocator = std.testing.allocator;
    var values: [32]M31 = undefined;
    for (&values, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i + 1));
    const top = [_][]const M31{&values};
    const heights = [_][]const []const M31{&top};
    var tree = try host.Commitment.commit(allocator, &heights, 3);
    defer tree.deinit();
    const raw = [_]usize{ 7, 7, 18 };
    const wire = try tree.encodeOpenings(allocator, &raw);
    defer allocator.free(wire);
    try source.validateEncoding(wire, tree.profile, tree.root());
    var opened = try source.verifyAndCollect(allocator, wire, tree.profile, tree.root(), &raw);
    defer opened.deinit();
    for (raw, 0..) |position, q| {
        const base = source.pairBase(position, 0);
        for (0..2) |row|
            try std.testing.expectEqual(values[base + row], opened.at(0, q, row, 0));
    }
    var changed = try allocator.dupe(u8, wire);
    defer allocator.free(changed);
    changed[8] = 4;
    try std.testing.expectError(error.UnsupportedProofVersion, source.verifyAndCollect(
        allocator,
        changed,
        tree.profile,
        tree.root(),
        &raw,
    ));
    changed[8] = 5;
    const header: usize = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 + 2 + 32;
    changed[header + 4] ^= 1;
    if (source.verifyAndCollect(allocator, changed, tree.profile, tree.root(), &raw)) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.AcceptedChangedSourceValue;
    } else |err| switch (err) {
        error.DuplicateProjectedValue, error.RootMismatch => {},
        else => return err,
    }
}

test "XDM05 absent height hashes upper parent, authenticates gapped rows and saves bytes" {
    const allocator = std.testing.allocator;
    const top_values = [_]M31{M31.fromCanonical(3)} ** 64;
    const lower_values = [_]M31{M31.fromCanonical(5)} ** 16;
    const bottom_values = [_]M31{M31.fromCanonical(7)} ** 8;
    const inserted_zeros = [_]M31{M31.zero()} ** 32;
    const h0 = [_][]const M31{&top_values};
    const h1 = [_][]const M31{};
    const h1_explicit = [_][]const M31{&inserted_zeros};
    const h2 = [_][]const M31{&lower_values};
    const h3 = [_][]const M31{&bottom_values};
    const heights = [_][]const []const M31{ &h0, &h1, &h2, &h3 };
    var tree = try host.Commitment.commit(allocator, &heights, 3);
    defer tree.deinit();
    const raw = [_]usize{ 1, 9, 47 };
    const wire = try tree.encodeOpenings(allocator, &raw);
    defer allocator.free(wire);
    var opened = try source.verifyAndCollect(allocator, wire, tree.profile, tree.root(), &raw);
    defer opened.deinit();
    try std.testing.expectEqual(@as(u16, 0), opened.profile.columns[1]);
    for (raw, 0..) |position, q| {
        const base2 = source.pairBase(position, 2);
        const base3 = source.pairBase(position, 3);
        for (0..2) |row| {
            try std.testing.expectEqual(lower_values[base2 + row], opened.at(2, q, row, 0));
            try std.testing.expectEqual(bottom_values[base3 + row], opened.at(3, q, row, 0));
        }
    }
    const explicit = [_][]const []const M31{ &h0, &h1_explicit, &h2, &h3 };
    var with_inserted_zeros = try host.Commitment.commit(allocator, &explicit, 3);
    defer with_inserted_zeros.deinit();
    const explicit_wire = try with_inserted_zeros.encodeOpenings(allocator, &raw);
    defer allocator.free(explicit_wire);
    const root = tree.root();
    const different_root = with_inserted_zeros.root();
    try std.testing.expect(!std.mem.eql(u8, &root, &different_root));
    try std.testing.expectEqual(wire.len + raw.len * 2 * @sizeOf(M31), explicit_wire.len);

    // The height-2 row sits above an absent height. Its field words must
    // still be authenticated through the ordinary upper-parent at height 1.
    var tampered_row = try allocator.dupe(u8, wire);
    defer allocator.free(tampered_row);
    const header: usize = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 + 2 * heights.len + 32;
    const height2_first_word = header + 4 + 2 * h0.len * @sizeOf(M31);
    tampered_row[height2_first_word] ^= 1;
    try std.testing.expectError(error.RootMismatch, source.verifyAndCollect(
        allocator,
        tampered_row,
        tree.profile,
        root,
        &raw,
    ));

    var changed = try allocator.dupe(u8, wire);
    defer allocator.free(changed);
    const counts_at: usize = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4;
    std.mem.writeInt(u16, changed[counts_at + 2 ..][0..2], 1, .little);
    try std.testing.expectError(error.UnexpectedSparseProfile, source.verifyAndCollect(
        allocator,
        changed,
        tree.profile,
        tree.root(),
        &raw,
    ));
    try std.testing.expectError(error.UnsupportedProofFormat, core.pcs.transposed_merkle_sparse.validateEncoding(
        wire,
        .{
            .largest_log_size = 6,
            .height_count = 4,
            .columns = .{ 1, 1, 1, 1, 0, 0, 0, 0 },
            .query_count = 3,
        },
        root,
    ));
}

test "XDM05 opens all Gate height positions with ten absent levels" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var heights = [_][]const []const M31{&[_][]const M31{}} ** 17;
    const present = [_]usize{ 0, 2, 4, 6, 11, 12, 16 };
    for (present) |height| {
        const values = try a.alloc(M31, @as(usize, 1) << @intCast(20 - height));
        @memset(values, M31.fromCanonical(@intCast(height + 3)));
        const columns = try a.alloc([]const M31, 1);
        columns[0] = values;
        heights[height] = columns;
    }
    var tree = try host.Commitment.commit(a, &heights, 3);
    defer tree.deinit();
    const raw = [_]usize{ 1, 12_345, (@as(usize, 1) << 20) - 1 };
    const encoded = try tree.encodeOpenings(a, &raw);
    var opened = try source.verifyAndCollect(a, encoded, tree.profile, tree.root(), &raw);
    defer opened.deinit();
    for (present) |height| for (0..raw.len) |q| for (0..2) |row|
        try std.testing.expectEqual(M31.fromCanonical(@intCast(height + 3)), opened.at(height, q, row, 0));
    for (0..17) |height| {
        if (std.mem.indexOfScalar(usize, &present, height) == null)
            try std.testing.expectEqual(@as(u16, 0), opened.profile.columns[height]);
    }
}
