//! Focused actual-device parity for commitment-scoped circle-LDE batching.

const std = @import("std");
const runtime_mod = @import("runtime.zig");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const twiddles = @import("stwo_prover_engine").poly.twiddles;

const M31 = m31.M31;

test "metal: one circle LDE command preserves two independent groups" {
    const allocator = std.testing.allocator;
    const backing = std.heap.page_allocator;
    const base_log_size: u32 = 12;
    const extended_log_size: u32 = 13;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);

    const base_domain = canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);

    const sync_base_a = try backing.alloc(M31, base_len);
    defer backing.free(sync_base_a);
    const sync_base_b = try backing.alloc(M31, base_len);
    defer backing.free(sync_base_b);
    const batch_base_a = try backing.alloc(M31, base_len);
    defer backing.free(batch_base_a);
    const batch_base_b = try backing.alloc(M31, base_len);
    defer backing.free(batch_base_b);
    const sync_extended_a = try backing.alloc(M31, extended_len);
    defer backing.free(sync_extended_a);
    const sync_extended_b = try backing.alloc(M31, extended_len);
    defer backing.free(sync_extended_b);
    const batch_extended_a = try backing.alloc(M31, extended_len);
    defer backing.free(batch_extended_a);
    const batch_extended_b = try backing.alloc(M31, extended_len);
    defer backing.free(batch_extended_b);

    for (sync_base_a, sync_base_b, 0..) |*a, *b, row| {
        a.* = M31.fromCanonical(@intCast((row * 8191 + 43) % m31.Modulus));
        b.* = M31.fromCanonical(@intCast((row * 65537 + 97) % m31.Modulus));
    }
    @memcpy(batch_base_a, sync_base_a);
    @memcpy(batch_base_b, sync_base_b);

    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var sync_source_a = [_][]const M31{sync_base_a};
    var sync_source_b = [_][]const M31{sync_base_b};
    var sync_bases_a = [_][]M31{sync_base_a};
    var sync_bases_b = [_][]M31{sync_base_b};
    var sync_extended_columns_a = [_][]M31{sync_extended_a};
    var sync_extended_columns_b = [_][]M31{sync_extended_b};
    const sync_a = try runtime.transformCircleLdeInto(
        allocator,
        &sync_source_a,
        &sync_bases_a,
        &sync_extended_columns_a,
        sync_extended_a,
        0,
        extended_len,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
    );
    const sync_b = try runtime.transformCircleLdeInto(
        allocator,
        &sync_source_b,
        &sync_bases_b,
        &sync_extended_columns_b,
        sync_extended_b,
        0,
        extended_len,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
    );

    var batch = try runtime.beginCircleLdeBatch();
    defer runtime.destroyCircleLdeBatch(&batch);
    var batch_source_a = [_][]const M31{batch_base_a};
    var batch_source_b = [_][]const M31{batch_base_b};
    var batch_bases_a = [_][]M31{batch_base_a};
    var batch_bases_b = [_][]M31{batch_base_b};
    var batch_extended_columns_a = [_][]M31{batch_extended_a};
    var batch_extended_columns_b = [_][]M31{batch_extended_b};
    const batched_a = try runtime.transformCircleLdeIntoBatch(
        &batch,
        allocator,
        &batch_source_a,
        &batch_bases_a,
        &batch_extended_columns_a,
        batch_extended_a,
        0,
        extended_len,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
    );
    const batched_b = try runtime.transformCircleLdeIntoBatch(
        &batch,
        allocator,
        &batch_source_b,
        &batch_bases_b,
        &batch_extended_columns_b,
        batch_extended_b,
        0,
        extended_len,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
    );
    const stats = try runtime.finishCircleLdeBatch(&batch);

    try std.testing.expectEqual(@as(u64, 2), stats.encoded_operations);
    try std.testing.expect(stats.gpu_milliseconds > 0.0);
    try std.testing.expectEqualDeep(sync_a.execution, batched_a.execution);
    try std.testing.expectEqualDeep(sync_b.execution, batched_b.execution);
    try std.testing.expectEqualSlices(M31, sync_base_a, batch_base_a);
    try std.testing.expectEqualSlices(M31, sync_base_b, batch_base_b);
    try std.testing.expectEqualSlices(M31, sync_extended_a, batch_extended_a);
    try std.testing.expectEqualSlices(M31, sync_extended_b, batch_extended_b);
}
