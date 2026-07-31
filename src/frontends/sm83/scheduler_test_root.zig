test {
    _ = @import("cartridge_machine_test_root.zig");
    _ = @import("execution_trace_test_root.zig");
    _ = @import("air/scheduler_test.zig");
    _ = @import("air/scheduler_component_test.zig");
    _ = @import("air/scheduler_binding_test.zig");
    _ = @import("air/machine_scheduler_trace_test.zig");
    _ = @import("air/scheduler_memory_lookup_test.zig");
    _ = @import("air/scheduler_memory_lookup_domain_test.zig");
    _ = @import("air/interrupt_service_memory_lookup_test.zig");
}
