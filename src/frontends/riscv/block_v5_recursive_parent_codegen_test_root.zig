//! Assembled parent body generation only. No witness, child execution proof,
//! recursive proof, worker, device or benchmarking process is created.
const std = @import("std");
const Parent = @import("recursion/air/blake3_native_parent_rows.zig");
const Execution = @import("recursion/air/blake3_execution_parent_sources.zig").Sources;
const Hash = @import("recursion/blake3_native_hash_columns.zig").Owner;
fn native(a: std.mem.Allocator, source: Parent.Sources) anyerror!Parent.Prepared {
    return Parent.prepare(a, source);
}
fn execution(a: std.mem.Allocator, source: Execution) anyerror!Parent.Prepared {
    return Parent.prepare(a, source);
}
fn owned(source: Execution, columns: *Hash, release: Parent.ReleaseRows) anyerror!Parent.Prepared {
    return Parent.prepareReleasingRows(source, columns, release);
}
fn borrowed(source: Execution, columns: *Hash, release: Parent.ReleaseRows) anyerror!@import("recursion/air/blake3_parent_row_storage.zig").Partition {
    return Parent.preparePartitionReleasingRows(source, columns, release);
}
test "direct recursive assembled parent bodies compile with bounded phase scratch" {
    inline for (.{ &native, &execution, &owned, &borrowed }) |function| std.mem.doNotOptimizeAway(function);
}
