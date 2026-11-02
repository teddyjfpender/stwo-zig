test {
    _ = @import("tests/rv64_full_capture_test.zig");
}
test {
    _ = @import("tests/rv64_full_statement_test.zig");
    _ = @import("tests/rv64_full_trace_test.zig");
    _ = @import("tests/rv64_full_trace_benchmark_test.zig");
}
