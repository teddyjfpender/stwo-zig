test {
    _ = @import("word16_global_execution/ethereum/observations.zig");
    _ = @import("word16_global_execution/services/gkr_local/resident_layout.zig");
    _ = @import("word16_global_execution/ethereum/gkr_receiver_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/bundle_wire_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/coordinator_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/truth_degree_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/truth_worker_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/truth_test.zig");
}
test {
    _ = @import("word16_global_execution/services/gkr_local/coordinator_beta2_test.zig");
}
test {
    _ = @import("word16_global_execution/ethereum/gkr_main.zig");
}

test {
    _ = @import("word16_global_execution/services/gkr_local/full_isa_test.zig");
}

test {
    _ = @import("word16_global_execution/services/gkr_local/advice_retirement_test.zig");
}
test {
    _ = @import("word16_global_execution/services/gkr_local/coordinator.zig");
}
