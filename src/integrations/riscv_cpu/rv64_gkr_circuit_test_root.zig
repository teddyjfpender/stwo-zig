//! Experimental actual-wire GKR qualification; no production acceptance.
test {
    _ = @import("rv64_recursion/om31_main_only_test.zig");
    _ = @import("rv64_recursion/om31_evaluation_test.zig");
    _ = @import("logup_gkr/om31_circuit_verifier_test.zig");
    _ = @import("rv64_recursion/om31_circuit_lane_test.zig");
    _ = @import("logup_gkr/circuit_verifier_test.zig");
}
