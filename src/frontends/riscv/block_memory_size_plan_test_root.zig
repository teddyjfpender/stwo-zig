//! Fast standalone sizing and partition tests; no STARK proof is constructed.
test {
    _ = @import("air/block/memory_size_plan.zig");
    _ = @import("air/block/memory_instance.zig");
    _ = @import("air/block/memory_component_trace.zig");
}
