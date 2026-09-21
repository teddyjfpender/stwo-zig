const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const component = @import("query_mapping.zig");
const base = @import("query_mapping_witness.zig");
const subject = @import("query_mapping_witness_heterogeneous_v2.zig");

const VM_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const LEFT_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const RIGHT_HEIGHTS = [_]u32{ 10, 10, 9, 10 };
const VM_FOLDS = [_]u32{ 4, 4 };
const LEFT_FOLDS = [_]u32{ 4, 4 };
const RIGHT_FOLDS = [_]u32{ 8, 4 };

const VM_PROFILE = profile(3, 9, &VM_HEIGHTS, &VM_FOLDS);
const LEFT_PROFILE = profile(5, 9, &LEFT_HEIGHTS, &LEFT_FOLDS);
const RIGHT_PROFILE = profile(7, 10, &RIGHT_HEIGHTS, &RIGHT_FOLDS);

test "R-012 query mapping V2 binds distinct child domains and routes" {
    var reference = try subject.Reference.seal(
        VM_PROFILE,
        LEFT_PROFILE,
        RIGHT_PROFILE,
    );
    var preprocessing = try subject.Preprocessed.init(std.testing.allocator, &reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(&reference);

    const left_start = try laneRows(VM_PROFILE);
    const right_start = left_start + try laneRows(LEFT_PROFILE);
    try std.testing.expectEqual(base.LEFT_RECURSION_VERIFIER_ID, preprocessing.rows[left_start].verifier_id);
    try std.testing.expectEqual(base.RIGHT_RECURSION_VERIFIER_ID, preprocessing.rows[right_start].verifier_id);
    try std.testing.expectEqual(@as(u32, 1 << 8), preprocessing.rows[left_start].position_weights[8]);
    try std.testing.expectEqual(@as(u32, 1 << 9), preprocessing.rows[right_start].position_weights[9]);
    try std.testing.expect(
        !std.meta.eql(reference.lanes[1].profile, reference.lanes[2].profile),
    );
    const query_bits = try reference.queryBitsReference();
    try query_bits.validate();
    try std.testing.expectEqual(LEFT_PROFILE.query_count, query_bits.left.query_count);
    try std.testing.expectEqual(RIGHT_PROFILE.query_count, query_bits.right.query_count);
    try std.testing.expectEqual(
        RIGHT_PROFILE.lifting_log_size,
        query_bits.right.lifting_log_size,
    );

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try base.Binding.canonical(&definition);
    const executor = try base.Executor.init(&definition, &binding);
    const prepared = try preprocessing.prepare(&reference);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const storage = try std.testing.allocator.alloc(
        M31,
        base.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(storage);
    var columns: [base.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try preprocessing.generatePreprocessedInto(
        &reference,
        prepared,
        &executor,
        &columns,
    );
    try std.testing.expectEqual(M31.fromCanonical(base.RIGHT_RECURSION_VERIFIER_ID), columns[3][right_start]);
}

test "R-012 query mapping V2 rejects resealed rows and lane substitution" {
    var reference = try subject.Reference.seal(
        VM_PROFILE,
        LEFT_PROFILE,
        RIGHT_PROFILE,
    );
    var preprocessing = try subject.Preprocessed.init(std.testing.allocator, &reference);
    defer preprocessing.deinit();

    const original = reference.lanes[2];
    reference.lanes[2] = reference.lanes[1];
    try std.testing.expectError(
        error.InvalidHeterogeneousMappingAuthority,
        reference.validate(),
    );
    reference.lanes[2] = original;

    const right_start = try laneRows(VM_PROFILE) + try laneRows(LEFT_PROFILE);
    var forged = try preprocessing.prepare(&reference);
    preprocessing.rows[right_start].position_weights[0] ^= 1;
    preprocessing.authority_sha256 = preprocessing.computedAuthoritySha256();
    forged.authority_sha256 = preprocessing.authority_sha256;
    try preprocessing.validateAgainst(&reference);
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validatePrepared(&reference, forged),
    );
}

fn profile(
    query_count: u32,
    lifting_log_size: u32,
    tree_heights: []const u32,
    fold_widths: []const u32,
) base.LaneProfile {
    return .{
        .query_count = query_count,
        .lifting_log_size = lifting_log_size,
        .tree_heights = tree_heights,
        .fri_fold_widths = fold_widths,
    };
}

fn laneRows(value: base.LaneProfile) !usize {
    return value.query_count * (value.tree_heights.len + 2 * value.fri_fold_widths.len + 2);
}
