//! Cairo system tests (formerly the default branch of `src/tests.zig`, which
//! no build step selected). Not yet registered as a build step.

const std = @import("std");

test {
    _ = @import("prove_trace_test.zig");
    _ = @import("prover_test.zig");
    _ = @import("source_semantic_pack_test.zig");
    _ = @import("claim_generator_test.zig");
    _ = @import("metal_process_backend_test.zig");
    _ = @import("statement_bootstrap_test.zig");
    std.testing.refAllDecls(@This());
}
