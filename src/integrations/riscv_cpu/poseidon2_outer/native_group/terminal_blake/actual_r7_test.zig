//! Explicit experimental eight-role qualification; no production selector.
test "terminal Blake R7 actual selected four native source root and receiver" {
    try @import("actual_shared.zig").ForArithmetic(.r7).run();
}
