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
