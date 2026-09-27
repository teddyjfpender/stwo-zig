//! Metadata/transport guards only; no proof is generated or freshly verified.
const std = @import("std");
const Module = @import("block_v5_cpu_bundle_store_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const limits: Module.Limits = .{ .max_files = 16, .max_file_bytes = 4096, .max_total_bytes = 8192, .max_metadata_bytes = 1 << 20, .max_manifest_bytes = 4096, .max_claims = 32, .max_proof_bytes = 2048 };
fn policy(comptime family: Module.Family, index: u32) Module.Policy {
    return .{ .expected = .{ .family = family, .index = index, .policy_digest = @splat(1), .config = Profile.diagnostic_q8_pow0.config(), .roots = .{ @splat(2), @splat(3), @splat(0) }, .claim_count = 1, .geometry = .{ .tree_count = 4, .tree_columns = .{ 6, 1, 4, 16, 0 }, .max_column_log = 6, .max_merkle_log = 7 } } };
}
test "bundle reader reuse: sparse indices family boundaries and failed slots stay exact" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = Profile.diagnostic_q8_pow0.config();
    const policies = [_]Module.Policy{ policy(.request, 0), policy(.rom, 3), policy(.rom, std.math.maxInt(u32)), policy(.range16, 9) };
    var files: [policies.len]Module.FilePin = undefined;
    for (policies, &files) |p, *pin| pin.* = .{ .family = p.expected.family, .index = p.expected.index, .byte_len = 1, .sha256 = @splat(1) };
    var reader = try Module.Store.initReader(a, tmp.dir, &policies, &files, config, limits);
    defer reader.deinit();
    var denied = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.UnadmittedV5BundleIndex, reader.takeWithAllocator(denied.allocator(), .rom, 0));
    try std.testing.expectError(error.UnadmittedV5BundleIndex, reader.takeWithAllocator(denied.allocator(), .request, 3));
    try std.testing.expectError(error.UnadmittedV5BundleIndex, reader.takeWithAllocator(denied.allocator(), .ram_lanes, 9));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
    inline for (.{ .request, .rom, .rom, .range16 }, .{ 0, 3, std.math.maxInt(u32), 9 }) |family, index| {
        try std.testing.expectError(error.FileNotFound, reader.takeWithAllocator(denied.allocator(), family, index));
        try std.testing.expectError(error.RepeatedV5BundleLoad, reader.takeWithAllocator(denied.allocator(), family, index));
    }
    try reader.requireConsumed();
    // Binary lookup is only available through original admission of exact order.
    const unsorted = [_]Module.Policy{ policies[2], policies[1] };
    try std.testing.expectError(error.NoncanonicalV5BundlePolicies, Module.Store.initWriter(a, tmp.dir, &unsorted, config, limits));
    try std.testing.expectError(error.NoncanonicalV5BundlePolicies, Module.Store.initWriter(a, tmp.dir, &.{ policies[1], policies[1] }, config, limits));
}
