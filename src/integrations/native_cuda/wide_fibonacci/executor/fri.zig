//! Wide-Fibonacci facade for the shared resident FRI executor.

const shared = @import("../../common/fri_executor.zig");

pub const run = shared.run;

test {
    _ = @import("pow_decommit.zig");
}
