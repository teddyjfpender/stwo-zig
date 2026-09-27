//! Only the original independently specified SHA+canonical record equations
//! participate in a batch-fold source proof. The old per-edit paths remain an
//! explicit correctness oracle, never part of the new operation census.
const std = @import("std");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Stream = @import("block_v5_memory_source_stream_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
pub fn count(admitted: *const Source.Admitted) !u64 {
    const old = try Stream.census(admitted);
    return std.math.add(u64, old.sha, old.records);
}
pub fn kindAt(admitted: *const Source.Admitted, ordinal: u64) !Eq.Kind {
    if (ordinal >= try count(admitted)) return error.InvalidSourceBatchRecordOrdinal;
    const kind = try Stream.kindAt(admitted, ordinal);
    switch (kind) {
        .sha, .record => {},
        else => return error.InvalidSourceBatchRecordOrdinal,
    }
    return kind;
}
pub const Cursor = struct {
    inner: Stream.Cursor,
    expected: u64,
    emitted: u64 = 0,
    /// Source.opening will never be called: this cursor stops BEFORE edits.
    pub fn init(admitted: Source.Admitted, source: Stream.Source) !Cursor {
        return .{ .inner = try Stream.Cursor.init(admitted, source), .expected = try count(&admitted) };
    }
    pub fn next(self: *Cursor) !?Stream.Chunk {
        if (self.emitted == self.expected) return null;
        const chunk = try self.inner.next() orelse return error.InvalidSourceBatchRecordOrdinal;
        const expected_kind = try kindAt(&self.inner.admitted, self.emitted);
        if (!std.meta.eql(chunk.kind, expected_kind)) return error.InvalidSourceBatchRecordOrdinal;
        self.emitted += 1;
        return chunk;
    }
};
