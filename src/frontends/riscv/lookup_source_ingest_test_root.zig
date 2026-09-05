const std = @import("std");

test {
    _ = @import("air/lookups/tables/source_ingest_test.zig");
    std.testing.refAllDecls(@This());
}
