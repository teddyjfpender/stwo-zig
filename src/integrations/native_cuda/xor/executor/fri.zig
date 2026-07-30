//! Exact XOR truth-table LogUp FRI schedule beginning after quotient alpha.

const shared = @import("../../common/fri_executor.zig");

pub const first_fri_step: u32 = 13;

pub fn run(
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    return shared.runAt(
        transaction,
        prepared,
        ingress,
        views,
        first_fri_step,
    );
}

pub fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    return shared.runWithAt(
        Ops,
        transaction,
        prepared,
        ingress,
        views,
        first_fri_step,
    );
}
