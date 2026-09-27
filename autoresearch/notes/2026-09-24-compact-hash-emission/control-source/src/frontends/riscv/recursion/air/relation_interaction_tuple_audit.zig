//! Cold tuple-ledger projection for an authenticated interaction plan.

const std = @import("std");

pub fn appendPreparedTupleContributions(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    ledger: *Runtime.TupleLedgerType,
    component: u8,
    rows: []const Runtime.Row,
    domain_mask: u64,
) std.mem.Allocator.Error!void {
    return plan.appendPreparedTupleContributions(ledger, component, rows, domain_mask);
}
