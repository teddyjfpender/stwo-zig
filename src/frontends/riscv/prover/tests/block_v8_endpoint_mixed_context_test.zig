//! Code generation plus actual guarded caller originals. This is not complete
//! mixed-window/bridge qualification, which requires the owning MixedProof.
const std = @import("std");
const Context = @import("../block_v8_endpoint_mixed_context_v1.zig");
test "mixed original context prover and receiver codegen" {
    std.mem.doNotOptimizeAway(&Context.For(true).create);
    std.mem.doNotOptimizeAway(&Context.For(false).create);
}
