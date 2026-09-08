const std = @import("std");

const subject =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");

test "campaign provider geometry synthetic two-leaf maximum is checked" {
    const identities = [2][32]u8{ identity(10), identity(50) };
    const authority = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    try subject.testing.validateForTwo(&authority);
    try std.testing.expectEqual(@as(u32, 2), authority.leaf_count);
    try std.testing.expectEqual(@as(u32, 5), authority.maximum_active_tuple_count);
    try std.testing.expectEqual(@as(u32, 0), authority.maximum_leaf_index);
    try std.testing.expectEqual(
        @as(u32, 8),
        authority.provider_geometry.role_io_tuple_capacity,
    );
    try std.testing.expectEqual(
        @as(u32, 150),
        authority.provider_geometry.role_io_word_count,
    );
    try std.testing.expectEqual(
        @as(u32, 19),
        authority.provider_geometry.role_io_call_count,
    );
    try std.testing.expectEqual(
        @as(u32, 144),
        authority.provider_geometry.provider_active_row_count,
    );
    try std.testing.expectEqual(
        @as(u32, 8),
        authority.provider_geometry.provider_log_size,
    );
    try std.testing.expectEqual(
        @as(u32, 256),
        authority.provider_geometry.provider_row_capacity,
    );
    try authority.validateStructure();
    try std.testing.expectEqual(@as(u32, 5), authority.active_tuple_counts[0]);
    try std.testing.expectEqualSlices(
        u8,
        &identities[1],
        &authority.fresh_input_identities[1],
    );
}

test "campaign provider geometry binds order but not maximum position" {
    const identities = [2][32]u8{ identity(10), identity(50) };
    const left_max = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    const right_max = try subject.testing.mintForTwo(.{ 3, 5 }, identities);
    try std.testing.expectEqualSlices(
        u8,
        &left_max.geometry_identity_sha256,
        &right_max.geometry_identity_sha256,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &left_max.authority_identity_sha256,
        &right_max.authority_identity_sha256,
    ));

    const reversed = try subject.testing.mintForTwo(
        .{ 5, 3 },
        .{ identities[1], identities[0] },
    );
    try std.testing.expectEqualSlices(
        u8,
        &left_max.geometry_identity_sha256,
        &reversed.geometry_identity_sha256,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &left_max.ordered_input_identity_sha256,
        &reversed.ordered_input_identity_sha256,
    ));

    const larger = try subject.testing.mintForTwo(.{ 9, 3 }, identities);
    try std.testing.expectEqual(
        @as(u32, 16),
        larger.provider_geometry.role_io_tuple_capacity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &left_max.geometry_identity_sha256,
        &larger.geometry_identity_sha256,
    ));
}

test "campaign provider geometry admits empty active prefixes and rejects forgery" {
    const identities = [2][32]u8{ identity(10), identity(50) };
    const empty_prefix = try subject.testing.mintForTwo(.{ 0, 3 }, identities);
    try subject.testing.validateForTwo(&empty_prefix);
    try std.testing.expectEqual(@as(u32, 0), empty_prefix.active_tuple_counts[0]);
    try std.testing.expectEqual(@as(u32, 3), empty_prefix.maximum_active_tuple_count);
    const all_empty = try subject.testing.mintForTwo(.{ 0, 0 }, identities);
    try subject.testing.validateForTwo(&all_empty);
    try std.testing.expectEqual(@as(u32, 0), all_empty.maximum_active_tuple_count);
    try std.testing.expectEqual(
        @as(u32, 1),
        all_empty.provider_geometry.role_io_tuple_capacity,
    );
    var zero_identity = identities;
    zero_identity[1] = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.InvalidCampaignProviderGeometryInputV4,
        subject.testing.mintForTwo(.{ 2, 3 }, zero_identity),
    );

    var authority = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    authority.provider_geometry.provider_log_size += 1;
    try std.testing.expectError(
        error.EthereumIncrementalFieldScheduleMismatchV4Schema3,
        subject.testing.validateForTwo(&authority),
    );
    authority = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    authority.maximum_active_tuple_count = 4;
    try std.testing.expectError(
        error.CampaignProviderGeometryMismatchV4,
        subject.testing.validateForTwo(&authority),
    );
    authority = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    authority.active_tuple_counts[1] += 1;
    try std.testing.expectError(
        error.CampaignProviderGeometryMismatchV4,
        subject.testing.validateForTwo(&authority),
    );
    authority = try subject.testing.mintForTwo(.{ 5, 3 }, identities);
    authority.fresh_input_identities[1][0] ^= 1;
    try std.testing.expectError(
        error.CampaignProviderGeometryMismatchV4,
        subject.testing.validateForTwo(&authority),
    );
    try std.testing.expectEqual(@as(usize, 210), subject.PRODUCTION_LEAF_COUNT);
    try std.testing.expect(subject.PRODUCTION_MINT_REQUIRES_FRESH_INPUTS);
    try std.testing.expect(!subject.CALLER_AUTHORED_MAXIMUM_ADMITTED);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
}

test "runtime campaign provider geometry admits authenticated non-power-of-two counts" {
    inline for (.{ 2, 3, 5 }) |count| {
        var counts: [count]u32 = undefined;
        var identities: [count][32]u8 = undefined;
        for (&counts, &identities, 0..) |*active, *value, index| {
            active.* = @intCast(3 + index * 2);
            value.* = identity(@intCast(20 + index * 17));
        }
        var campaign_identity = identity(@intCast(90 + count));
        var authority = try subject.testing.mintOwnedFromObservations(
            std.testing.allocator,
            campaign_identity,
            &counts,
            &identities,
        );
        defer authority.deinit();
        try authority.validateStructure();
        try std.testing.expectEqual(@as(u32, count), authority.view().leaf_count);
        try std.testing.expectEqual(
            counts[count - 1],
            authority.view().maximum_active_tuple_count,
        );
        try std.testing.expectEqual(
            std.math.ceilPowerOfTwo(u32, counts[count - 1]) catch unreachable,
            authority.view().provider_geometry.role_io_tuple_capacity,
        );
        try std.testing.expectEqualSlices(
            u8,
            &campaign_identity,
            &authority.view().campaign_inventory.table_identity_sha256,
        );
    }
}

test "runtime campaign provider geometry binds inventory and rejects duplicate order" {
    const counts = [_]u32{ 3, 5, 4 };
    const identities = [_][32]u8{ identity(11), identity(31), identity(51) };
    var left = try subject.testing.mintOwnedFromObservations(
        std.testing.allocator,
        identity(71),
        &counts,
        &identities,
    );
    defer left.deinit();
    var right = try subject.testing.mintOwnedFromObservations(
        std.testing.allocator,
        identity(72),
        &counts,
        &identities,
    );
    defer right.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &left.view().geometry_identity_sha256,
        &right.view().geometry_identity_sha256,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &left.view().authority_identity_sha256,
        &right.view().authority_identity_sha256,
    ));

    const duplicate = [_][32]u8{ identities[0], identities[1], identities[1] };
    try std.testing.expectError(
        error.InvalidCampaignProviderGeometryInputV4,
        subject.testing.mintOwnedFromObservations(
            std.testing.allocator,
            identity(71),
            &counts,
            &duplicate,
        ),
    );
}

test "runtime campaign clone owns immutable observations after source destruction" {
    var counts = [_]u32{ 3, 5 };
    var identities = [_][32]u8{ identity(11), identity(31) };
    var retained = blk: {
        var original = try subject.testing.mintOwnedFromObservations(
            std.testing.allocator,
            identity(71),
            &counts,
            &identities,
        );
        defer original.deinit();
        var clone = try original.clone(std.testing.allocator);
        errdefer clone.deinit();
        try std.testing.expect(original.view().active_tuple_counts.ptr != clone.view().active_tuple_counts.ptr);
        try std.testing.expect(original.view().fresh_input_identities.ptr != clone.view().fresh_input_identities.ptr);
        try std.testing.expectEqualSlices(u8, &original.view().authority_identity_sha256, &clone.view().authority_identity_sha256);
        break :blk clone;
    };
    defer retained.deinit();
    counts[0] = 99;
    identities[0][0] ^= 1;
    try retained.validateStructure();
    try std.testing.expectEqualSlices(u32, &.{ 3, 5 }, retained.view().active_tuple_counts);
    try std.testing.expect(@TypeOf(retained.view().active_tuple_counts) == []const u32);
    try std.testing.expect(@TypeOf(retained.view().fresh_input_identities) == []const [32]u8);
    // The direct immutable clone must release each partial buffer if either
    // allocation or the final private-storage allocation fails.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneWithAllocator, .{&retained});
    try retained.validateStructure();
}

fn cloneWithAllocator(allocator: std.mem.Allocator, source: *const subject.OwnedCampaignProviderGeometryV4) !void {
    var clone = try source.clone(allocator);
    defer clone.deinit();
    try clone.validateStructure();
    try std.testing.expectEqualDeep(source.view().*, clone.view().*);
}

fn identity(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*value, index|
        value.* = seed +% @as(u8, @intCast(index));
    return result;
}
