//! Durable sponge custody: rows replay the original immutable shared Plan.
const std = @import("std");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge;
pub fn row(source: *const K.source.Source, comptime kind: K.layout.Kind, logical: usize) ![K.layout.main(kind)]@import("stwo_core").fields.m31.M31 {
    if (source.kind != kind or logical >= source.size() or source.rows != source.plan.rows(kind)) return error.InvalidSpongeGkrMetadata;
    return source.plan.row(kind, logical, source.first_id);
}
pub fn retireLocal(source: *K.source.Source) void {
    source.releaseMain();
    inline for (.{ "fixed", "counts16", "counts8", "counts_and", "interaction" }) |field| {
        source.allocator.free(@field(source, field));
        @field(source, field) = &.{};
    }
}
/// The Plan is shared by both sources and must be charged ONCE by its owner.
pub fn retainedPlanBytes(plan: *const K.source.Plan) !usize {
    var result: usize = 0;
    inline for (.{ "calls", "words", "perms", "row_call" }) |field| {
        const values = @field(plan, field);
        result = try std.math.add(usize, result, try std.math.mul(usize, values.len, @sizeOf(@typeInfo(@TypeOf(values)).pointer.child)));
    }
    return result;
}

/// Every message window has18 word slots per permutation. This bounds all
/// retained Plan copies from admitted call/permutation counts before building.
pub fn requestUpperBound(counts: @import("../types.zig").SpongeCounts) !usize {
    const words = try std.math.mul(usize, counts.perms, K.types.SLOTS);
    const calls = try std.math.mul(usize, counts.calls, @sizeOf(K.types.Call));
    const word_bytes = try std.math.mul(usize, words, @sizeOf(K.types.State));
    const permutations = try std.math.mul(usize, counts.perms, @sizeOf([2][25]u64) + @sizeOf(u32));
    return std.math.add(usize, @sizeOf(K.source.Plan), try std.math.add(usize, calls, try std.math.add(usize, word_bytes, permutations)));
}
/// Plan.init also constructs one call's u64 word vector and permutation output
/// at a time. Conservatively bound that call by the entire admitted inventory.
/// Source MAIN/fixed/histogram buffers are separate caller-owned task floors.
pub fn sourceAllocationUpperBound(counts: @import("../types.zig").SpongeCounts) !usize {
    const words = try std.math.mul(usize, counts.perms, K.types.SLOTS);
    const helper = try std.math.add(usize, try std.math.mul(usize, words, @sizeOf(u64)), try std.math.mul(usize, counts.perms, @sizeOf([2][25]u64)));
    return std.math.add(usize, try requestUpperBound(counts), helper);
}

pub fn localUpperBound(kind: K.layout.Kind, log: u32) !usize {
    if (log < 5 or log > 22) return error.InvalidSpongeGkrMetadata;
    const rows = @as(usize, 1) << @intCast(log);
    const fixed = try std.math.mul(usize, rows, K.layout.FIXED * 4);
    return std.math.add(usize, fixed, (65536 + 256 + @as(usize, if (kind == .perm) 65536 else 0)) * @sizeOf(u64));
}
