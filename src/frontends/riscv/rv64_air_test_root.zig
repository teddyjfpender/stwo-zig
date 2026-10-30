test {
    _ = @import("rv64/air/tests/relations_test.zig");
    _ = @import("rv64/air/tests/degree_test.zig");
    _ = @import("rv64/air/tests/local_test.zig");
    _ = @import("rv64/air/tests/admission_test.zig");
    _ = @import("rv64/air/tests/encoding_test.zig");
    _ = @import("rv64/air/tests/byte_operations_test.zig");
    _ = @import("rv64/air/tests/representation_model_test.zig");
}
test {
    _ = @import("rv64/air/geometry.zig");
    _ = @import("rv64/air/range/provider.zig");
}
test {
    _ = @import("rv64/air/providers/tables.zig");
}
test {
    _ = @import("rv64/air/full/frame.zig");
}
test {
    _ = @import("rv64/air/full/component.zig");
}
test {
    _ = @import("rv64/air/tests/weighted_sink_test.zig");
}
test {
    _ = @import("rv64/air/tests/inflation_reuse_test.zig");
}
test {
    _ = @import("rv64/air/tests/byte_terms_test.zig");
}
test {
    _ = @import("rv64/air/tests/memory_factoring_test.zig");
}
