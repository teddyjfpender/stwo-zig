//! Wide-Fibonacci facade for the shared resident OODS executor.

const shared = @import("../../common/oods_executor.zig");

pub const max_rejection_rounds = shared.max_rejection_rounds;
pub const run = shared.run;
pub const execute = shared.run;
