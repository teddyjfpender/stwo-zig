//! Operational two-instance LS sizing. The chosen physical geometry is bound
//! by the ordinary setup/FS; it does not alter the expected execution identity.
const std = @import("std");
const G = @import("../word16_execution/geometry.zig");
const Coverage = @import("../word16_execution/coverage.zig");
pub fn choose(single: G.Geometry, total: u32, enable_ladder: bool) !G.Geometry {
    try single.validate();
    _ = try single.lsCounts(total);
    if (!enable_ladder or single.ls_tail_log != null or total < 32) return single;
    const head_log = std.math.log2_int(u32, total);
    const head_capacity = (@as(u32, 1) << @intCast(head_log)) - 1;
    const tail_log = try Coverage.minimalPrefixLog(total - head_capacity);
    var candidate = single;
    candidate.ls_log = head_log;
    candidate.ls_tail_log = tail_log;
    _ = try candidate.lsCounts(total);
    if (candidate.lsRows() >= single.lsRows()) return single;
    try candidate.validate();
    return candidate;
}
