const options = @import("machine_environment_test_options");

comptime {
    if (options.log_size < 4 or options.log_size > 16)
        @compileError("machine-environment test log size must be 4...16");
}

test {
    _ = @import("machine_environment_test.zig");
}
