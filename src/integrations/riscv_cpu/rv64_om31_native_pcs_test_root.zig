test {
    _ = @import("rv64_recursion/om31_native/test.zig");
}

test {
    _ = @import("rv64_recursion/om31_native/cpu_oods_test.zig");
}

test {
    _ = @import("rv64_recursion/om31_native/cpu_child_test.zig");
}

test {
    _ = @import("rv64_recursion/om31_native/cpu_leaf_test.zig");
}

test {
    _ = @import("rv64_recursion/om31_native/leaf_graph_test.zig");
}

test {
    _ = @import("rv64_recursion/om31_native/outer_wrap_test.zig");
}
