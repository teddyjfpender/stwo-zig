test {
    @import("std").testing.refAllDecls(@import("prover/block_v7_keccak_window_layout_v1.zig"));
    @import("std").testing.refAllDecls(@import("prover/block_v7_keccak_window_source_v1.zig"));
    @import("std").testing.refAllDecls(@import("prover/block_v7_keccak_window_control_v1.zig"));
    @import("std").testing.refAllDecls(@import("prover/tests/block_v7_keccak_shared_clock_test.zig"));
    @import("std").testing.refAllDecls(@import("prover/block_v7_keccak_window_lookup_v1.zig"));
    @import("std").testing.refAllDecls(@import("prover/tests/block_v7_keccak_window_memory_test.zig"));
}
