const std = @import("std");
const m31_mod = @import("../../fields/m31.zig");
const derive = @import("../derive.zig");
const trace_mod = @import("../trace/component_trace.zig");

const M31 = m31_mod.M31;

pub const LookupRowsAdapter = derive.LookupRowsAdapter;
pub const LookupRowsError = derive.LookupRowsError;

test "air lookup_data: lookup rows adapter allocates and mutates mixed shapes" {
    const alloc = std.testing.allocator;

    const Rows = struct {
        field0: []M31,
        field1: [2][]M31,
    };

    const Adapter = LookupRowsAdapter(Rows);

    var rows = try Adapter.allocUninitialized(alloc, 8);
    defer Adapter.deinit(alloc, &rows);

    try Adapter.forEachRowMut(&rows, 8, struct {
        fn apply(index: usize, row: Adapter.RowMut) void {
            row.get("field0").* = M31.fromU64(index + 1);

            const f1 = row.get("field1");
            f1[0].* = M31.fromU64((index + 1) * 2);
            f1[1].* = M31.fromU64((index + 1) * 3);
        }
    }.apply);

    try std.testing.expect(rows.field0[3].eql(M31.fromU64(4)));
    try std.testing.expect(rows.field1[0][3].eql(M31.fromU64(8)));
    try std.testing.expect(rows.field1[1][3].eql(M31.fromU64(12)));
}

test "air lookup_data: component trace row iteration and lookup rows stay aligned" {
    const alloc = std.testing.allocator;

    const Rows = struct {
        witness: []M31,
    };

    const Trace = trace_mod.ComponentTrace(1);
    const Adapter = LookupRowsAdapter(Rows);

    var trace = try Trace.initUninitialized(alloc, 3);
    defer trace.deinit(alloc);

    var rows = try Adapter.allocUninitialized(alloc, trace.nRows());
    defer Adapter.deinit(alloc, &rows);

    var iter = try trace.iterMut();
    var idx: usize = 0;
    while (iter.next()) |row| : (idx += 1) {
        const value = M31.fromU64(idx + 11);
        row.at(0).* = value;
        rows.witness[idx] = value;
    }

    try std.testing.expectEqual(trace.nRows(), idx);

    var i: usize = 0;
    while (i < idx) : (i += 1) {
        const t = try trace.rowAt(i);
        try std.testing.expect(t[0].eql(rows.witness[i]));
    }
}
