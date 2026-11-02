//! Bulk metadata custody after local child sealing. Keep only RAM obligations;
//! never retain a second MAIN, fixed table, or range histogram for stage two.
const std = @import("std");
const B = @import("stwo_riscv_frontend").rv64_air.crypto.bulk_memory;
fn release(a: std.mem.Allocator, slice: anytype) void {
    a.free(slice.*);
    slice.* = &.{};
}
/// Caller must have sealed MAIN and constructed its durable local binding.
/// Idempotent; tombstones remain safe for Source.deinit. Does not close RAM.
pub fn retireLocal(source: *B.source.Source) void {
    source.releaseMain();
    inline for (.{ "fixed", "counts16", "counts8", "interaction", "multiplicity" }) |field| release(source.allocator, &@field(source, field));
    if (@import("bulk_projection.zig").ramTerms(source.kind) == 0) {
        inline for (.{ "calls", "words", "row_call", "row_word", "call_row", "row_pending" }) |field| release(source.allocator, &@field(source, field));
    }
}
/// Exact requested-byte custody, excluding the source header/allocator overhead.
/// The worker admission planner still rejects v3 until an independent request-
/// derived upper bound and the weighted OWNER support analysis are qualified.
pub fn retainedBytes(source: *const B.source.Source) !usize {
    var result: usize = 0;
    inline for (.{ "calls", "words", "row_call", "row_word", "call_row", "row_pending" }) |field| {
        const slice = @field(source, field);
        result = try std.math.add(usize, result, try std.math.mul(usize, slice.len, @sizeOf(@typeInfo(@TypeOf(slice)).pointer.child)));
    }
    return result;
}
