//! Exact resident quotient execution over 23 sources and 27 terms.

const shared = @import("../../common/quotient_executor.zig");

pub fn run(
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    return shared.run(transaction, prepared, ingress, views);
}

pub fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    return shared.runWith(
        Ops,
        transaction,
        prepared,
        ingress,
        views,
    );
}
