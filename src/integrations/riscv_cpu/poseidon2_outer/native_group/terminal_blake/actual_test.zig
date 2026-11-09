//! Retained six-role qualification wrapper; source and control order are unchanged.
test "terminal Blake actual selected four native source root and receiver" {
    try @import("actual_shared.zig").ForArithmetic(.r6).run();
}
