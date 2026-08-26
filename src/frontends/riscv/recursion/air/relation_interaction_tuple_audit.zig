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
    for (rows) |row| {
        const row_entries = plan.preparedEntries(row);
        for (row_entries) |entry| {
            const domain_bit = @as(u64, 1) << @as(
                u6,
                @intCast(@intFromEnum(entry.domain)),
            );
            if (domain_mask & domain_bit == 0) continue;
            try ledger.append(
                entry.domain,
                component,
                entry.ordinal,
                entry.role,
                entry.numerator,
                entry.values[0..entry.arity],
            );
        }
    }
}
