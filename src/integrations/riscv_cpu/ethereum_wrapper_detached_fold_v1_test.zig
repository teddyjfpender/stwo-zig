const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const subject = @import("ethereum_wrapper_detached_fold_v1.zig");
const shape_mod = @import("ethereum_wrapper_child_shape_v1.zig");
const manifest = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const fixture = @import("ethereum_wrapper_root_verifier_v1_test.zig");

fn fixtureManifest() manifest.Manifest {
    var logs: manifest.LogSizesV4 = @splat(4);
    logs[34] = manifest.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest.RANGE_LOG_SIZE;
    return manifest.buildForDerivedLogSizes(logs) catch unreachable;
}

test "Ethereum field fold derives selected wire dimensions from admitted manifest" {
    @setEvalBranchQuota(50_000_000);
    const selected = comptime fixtureManifest();
    const Adapter = subject.TypesForManifest(selected);
    const key = try fixture.testKey();
    const owner = try shape_mod.OwnedV1.create(std.testing.allocator, &key);
    defer owner.deinit();
    try std.testing.expectEqualDeep(owner.wireDimensions(), try shape_mod.dimensionsForManifest(&selected));
    try std.testing.expectEqual(@sizeOf(Adapter.Fixed.WireV2), @sizeOf(recursion.fixed_wire.FixedStarkProofWire(shape_mod.dimensionsForManifest(&selected) catch unreachable)));
    try std.testing.expect(!subject.FOLD_ADMISSION_AVAILABLE);
    // Compile the real existing cohort constructor against the thin policy.
    // This creates no child or fold proof and exercises no unverified fixture.
    std.mem.doNotOptimizeAway(&Adapter.Cohort.init);
    std.mem.doNotOptimizeAway(&Adapter.Cohort.initEthereumDetachedFold);
}

test "Ethereum field fold rejects wrong selected shape before proof parsing" {
    @setEvalBranchQuota(50_000_000);
    const wrong_dimensions = comptime blk: {
        var d = shape_mod.dimensionsForManifest(&fixtureManifest()) catch unreachable;
        d.sampled_value_count += 1;
        break :blk d;
    };
    const Adapter = subject.Types(wrong_dimensions);
    const key = try fixture.testKey();
    const session = try fixture.testSession(key.session_fields);
    const public = @import("recursive_field_node_public_v2.zig");
    var words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (session.parent_statement_words, &words) |word, *out| out.* = word.toU32();
    const node = try public.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0), words, [_]u32{9} ** 8);
    const claims: @import("ethereum_wrapper_root_verifier_v1.zig").ClaimsV1 = .{ .values = @splat(core.fields.qm31.QM31.zero()), .poseidon_partials = @splat(core.fields.qm31.QM31.zero()) };
    try std.testing.expectError(error.EthereumFoldChildShapeMismatch, Adapter.Child.init(std.testing.allocator, &key, &node, claims, 0, &.{}));
}
