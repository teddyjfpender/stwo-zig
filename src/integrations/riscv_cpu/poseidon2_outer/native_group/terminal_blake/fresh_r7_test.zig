//! Receiver-only code generation: never instantiate the producer mode.
test "terminal Blake R7 fresh-only selected source root and nine controls" {
    try @import("actual_shared.zig").ForArithmetic(.r7).runFreshOnly();
}
