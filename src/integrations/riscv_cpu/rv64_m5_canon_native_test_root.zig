test {
    _ = @import("word16_global_execution/ethereum/canon_native.zig");
    _ = @import("word16_global_execution/ethereum/canon_native_widths.zig");
}
test "canon-native generated rung table has R rungs per family and ascending truth logs" {
    const std = @import("std");
    const Rungs = @import("word16_global_execution/ethereum/canon_native_rungs.zig");
    try std.testing.expectEqual(@as(u32, 4), Rungs.R);
    for (Rungs.CPU) |e| {
        try std.testing.expect(e.rungs.len >= 1 and e.rungs.len <= Rungs.R);
        for (e.rungs) |v| try std.testing.expect(v[0] >= 5 and v[0] <= 23);
    }
    for (Rungs.TRUTH) |e| for (e.logs[1..], 0..) |l, i| try std.testing.expect(l > e.logs[i]);
}
