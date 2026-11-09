test {
    _ = @import("rv64/air/providers/parallel_rows_test.zig");
    _ = @import("rv64/air/word16/alu_test.zig");
    _ = @import("rv64/air/word16/u16_source_test.zig");
    _ = @import("rv64/air/word16/alu_packed_rows_test.zig");
    _ = @import("rv64/air/word16/alu_source_test.zig");
}
test {
    _ = @import("rv64/air/word16/alu_merged_prefix_test.zig");
}
