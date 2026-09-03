//! Focused tests for the profiled Metal composition authority.

test {
    _ = @import("runtime/base_polynomial_host_graph.zig");
    _ = @import("runtime/backend_composition.zig");
    _ = @import("runtime/composition_device_buckets.zig");
    _ = @import("runtime/composition_dispatch_barrier_test.zig");
    _ = @import("runtime/composition_partition_parity.zig");
    _ = @import("runtime/composition_domain_scratch.zig");
    _ = @import("runtime/base_polynomial_codegen.zig");
    _ = @import("runtime/lookup_polynomial_codegen.zig");
}
