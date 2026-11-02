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
/// Request-derived worker bounds are separate from this measured custody;
/// neither quantity is a bound on allocator overhead or whole-process RSS.
pub fn retainedBytes(source: *const B.source.Source) !usize {
    var result: usize = 0;
    inline for (.{ "calls", "words", "row_call", "row_word", "call_row", "row_pending" }) |field| {
        const slice = @field(source, field);
        result = try std.math.add(usize, result, try std.math.mul(usize, slice.len, @sizeOf(@typeInfo(@TypeOf(slice)).pointer.child)));
    }
    return result;
}

/// Source.init currently copies the complete shard's call/word inventory into
/// each kind. Charge those copies, not just the rows selected by this kind.
pub fn requestUpperBound(counts: @import("../types.zig").BulkCounts, kind: B.layout.Kind) !usize {
    if (@import("bulk_projection.zig").ramTerms(kind) == 0) return 0;
    return inventoryUpperBound(counts, kind);
}
fn inventoryUpperBound(counts: @import("../types.zig").BulkCounts, kind: B.layout.Kind) !usize {
    const calls = counts.ecalls();
    var words: u64 = 0;
    inline for (.{ "copy_words", "set_words", "ucopy_rows", "cmp_words" }) |field|
        words = try std.math.add(u64, words, @field(counts, field));
    words = try std.math.add(u64, words, try std.math.mul(u64, counts.jump_rows, 9));
    const call_bytes = try std.math.mul(u64, calls, @sizeOf(B.types.Call) + @sizeOf(u32));
    const word_bytes = try std.math.mul(u64, words, @sizeOf(B.types.Word));
    const index_bytes = try std.math.mul(u64, counts.rows(kind), 2 * @sizeOf(u32) + @as(u64, if (kind == .jscan) 1 else 0));
    return std.math.cast(usize, try std.math.add(u64, try std.math.add(u64, call_bytes, word_bytes), index_bytes)) orelse error.InvalidRetentionGeometry;
}

/// Extra live source payload before local retirement (MAIN is charged by the
/// normal coefficient/witness floor; durable RAM inventory by requestUpperBound).
pub fn localUpperBound(counts: @import("../types.zig").BulkCounts, kind: B.layout.Kind, log: u32) !usize {
    if (log < 5 or log > 22) return error.InvalidRetentionGeometry;
    const rows = @as(usize, 1) << @intCast(log);
    var out = try std.math.add(usize, try std.math.mul(usize, B.layout.fixedWidth(kind), try std.math.mul(usize, rows, 4)), (65536 + 256) * @sizeOf(u64));
    if (kind == .jtab) {
        out = try std.math.add(usize, out, try inventoryUpperBound(counts, kind));
        out = try std.math.add(usize, out, B.types.TABLE_ENTRIES * @sizeOf(u32));
    }
    return out;
}
