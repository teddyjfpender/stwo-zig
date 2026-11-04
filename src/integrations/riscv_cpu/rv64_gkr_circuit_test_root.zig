//! Experimental actual-wire GKR qualification; no production acceptance.
test {
    _ = @import("rv64_recursion/om31_global_classic_test.zig");
    _ = @import("rv64_recursion/om31_service_main_test.zig");
    _ = @import("rv64_recursion/om31_main_prover_test.zig");
    _ = @import("rv64_recursion/om31_main_only_test.zig");
    _ = @import("rv64_recursion/om31_evaluation_test.zig");
    _ = @import("logup_gkr/om31_circuit_verifier_test.zig");
    _ = @import("rv64_recursion/om31_circuit_lane_test.zig");
    _ = @import("logup_gkr/circuit_verifier_test.zig");
    // M4 diet stream: outer LogUp-GKR cost prototype (measurement only).
    _ = @import("logup_gkr/outer_gkr_diet_test.zig");
}
