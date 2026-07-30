//! Wide-Fibonacci facade for shared resident PoW and opening execution.

const shared = @import("../../common/pow_decommit_executor.zig");

pub const pow_search_end = shared.pow_search_end;
pub const executePow = shared.executePow;
pub const executeDecommit = shared.executeDecommit;
