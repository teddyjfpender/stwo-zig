//! Target-independent Cairo code-generation contracts.

pub const eval_program = @import("eval_program.zig");

test {
    _ = eval_program;
}
