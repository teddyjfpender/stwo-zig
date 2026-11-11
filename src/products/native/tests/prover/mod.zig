//! Native backend prover integration tests.

test {
    _ = @import("blake2_dispatch_test.zig");
    _ = @import("fri_scheduler_test.zig");
    _ = @import("fri_test.zig");
    _ = @import("pcs/mod.zig");
    _ = @import("prove_test.zig");
}
