test {
    _ = @import("cartridge_machine_test_root.zig");
    _ = @import("execution_trace_test_root.zig");
    _ = @import("air/tests/scheduler_test.zig");
    _ = @import("air/tests/scheduler_component_test.zig");
    _ = @import("air/tests/scheduler_binding_test.zig");
    _ = @import("air/tests/machine_scheduler_trace_test.zig");
    _ = @import("air/tests/scheduler_memory_lookup_test.zig");
    _ = @import("air/tests/scheduler_memory_lookup_domain_test.zig");
    _ = @import("air/tests/interrupt_service_memory_lookup_test.zig");
}
