const std = @import("std");
const core = @import("stwo_core");
const F = @import("recursion/block_v7_lookup_compact_fixed_shape_v1.zig");
const L = @import("prover/block_v7_lookup_compact_layout_v1.zig");
const A = @import("prover/block_v7_lookup_compact_algebra_v1.zig");
test "compact lookup cold q70 PCS shape removes Cartesian FRI floor without proof inputs" {
    const a = std.testing.allocator;
    var channel = core.proof_suites.Blake3.Channel{};
    const universal = try @import("recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try @import("recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70), .lifting_log_size = null };
    var dense = try F.originalDense(a, config, relations, .{});
    defer dense.deinit();
    const baseline = try F.Census.derive(&dense);
    try std.testing.expectEqual(@as(u32, 21), baseline.lifting_log);
    std.debug.print("lookup_cold_shape mode=original_dense metadata_q=70 metadata_pow=26 census={any}\n", .{baseline});
    for ([2]bool{ false, true }) |mixed| {
        var modes: [6]A.Mode = @splat(.sparse);
        var logs: [6]u32 = @splat(4);
        if (mixed) {
            modes[5] = .dense;
            logs[5] = 15;
        }
        const layout = try L.Layout.init(modes, logs);
        var compact = try F.compact(a, layout, config, relations, .{});
        defer compact.deinit();
        const census = try F.Census.derive(&compact);
        try std.testing.expectEqual(@as(u32, if (mixed) 16 else 5), census.lifting_log);
        try std.testing.expectEqual(@as(u32, if (mixed) 17 else 6), census.composition_log);
        try std.testing.expectEqual(@as(u32, 2), census.composition_split);
        try std.testing.expect(census.fri_rounds < baseline.fri_rounds);
        // The wider sparse rows are charged explicitly, not hidden by the much
        // smaller domains or described as a universal verifier-work reduction.
        try std.testing.expect(census.oods_secure_fields > baseline.oods_secure_fields);
        std.debug.print("lookup_cold_shape mode={s} metadata_q=70 metadata_pow=26 census={any}\n", .{ if (mixed) "mixed_dense_m31" else "all_sparse", census });
    }
}

test "compact profile rejects mutated derived config and composition aliases" {
    const Source = @import("prover/block_v7_lookup_compact_proof_v1.zig");
    const Profile = @import("recursion/block_v7_lookup_compact_fixed_profile_v1.zig");
    const E = @import("prover/block_v7_execution_epoch_v1.zig");
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const plan = @import("prover/block_v5_native_lookup_plan_v1.zig").Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(4) };
    const layout = try L.Layout.init(@splat(.sparse), @splat(4));
    const roots: [2][32]u8 = .{ @splat(3), @splat(4) };
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(7), &.{ @splat(1), @splat(2) }), try Source.firstEntry(plan, layout, roots) };
    var counts: E.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try E.Epoch.init(@splat(71), config, counts, &entries, entries.len);
    const selected = Profile.Input{ .policy = .{ .plan = plan, .layout = layout, .roots = roots, .epoch = epoch, .entries = &entries }, .claims = @splat(core.fields.qm31.QM31.zero()) };
    const profile = try Profile.Owned.derive(a, selected, .{});
    defer profile.deinit();
    const original_config = profile.config;
    profile.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedCompactLookupFixedProfile, profile.validate());
    profile.config = original_config;
    profile.shape.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedCompactLookupFixedProfile, profile.validate());
    profile.shape.config = original_config;
    inline for (.{ "mask_log", "lifting_log", "composition_log", "split" }) |name| {
        const old = @field(profile.shape, name);
        @field(profile.shape, name) += 1;
        try std.testing.expectError(error.UntrustedCompactLookupFixedProfile, profile.validate());
        @field(profile.shape, name) = old;
    }
    profile.lifting_log += 1;
    try std.testing.expectError(error.UntrustedCompactLookupFixedProfile, profile.validate());
    profile.lifting_log -= 1;
    try profile.validate();
}
