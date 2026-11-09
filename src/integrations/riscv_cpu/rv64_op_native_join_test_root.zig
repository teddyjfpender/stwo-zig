test {
    _ = @import("poseidon2_outer/root_cli_options.zig");
    _ = @import("poseidon2_outer/pure_p2_truth_local_runtime_test.zig");
    _ = @import("poseidon2_outer/pure_p2_setup_cache_heavy_test.zig");
    _ = @import("poseidon2_outer/pure_p2_setup_cache_test.zig");
    _ = @import("poseidon2_outer/pure_p2_op_hooks_test.zig");
    _ = @import("poseidon2_outer/pure_p2_retained_main.zig");
    _ = @import("poseidon2_outer/pure_p2_op_bundle.zig");
    _ = @import("poseidon2_outer/pure_p2_root_sidecar.zig");
    _ = @import("poseidon2_outer/pure_p2_op_inventory_test.zig");
    _ = @import("poseidon2_outer/pure_p2_op_cpu_fixture.zig");
    _ = @import("poseidon2_outer/pure_p2_cpu_fixture.zig");
}
