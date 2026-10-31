test {
    _ = @import("../../tests/rv64_keccak_bridge_lane_test.zig");
    _ = @import("../../tests/rv64_keccak_lane_test.zig");
    _ = @import("../../tests/rv64_keccak_interaction_parallel_test.zig");
    _ = @import("../../tests/rv64_keccak_gather_test.zig");
    _ = @import("../../tests/rv64_keccak_partial_tail_test.zig");
    _ = @import("../../tests/rv64_keccak_native_diagnostic_test.zig");
    _ = @import("../../tests/rv64_keccak_interaction_dictionary_test.zig");
    _ = @import("../../tests/rv64_keccak_metadata_test.zig");
    _ = @import("../../tests/rv64_keccak_bridge_proof_test.zig");
    _ = @import("../../tests/rv64_keccak_proof_test.zig");
}
