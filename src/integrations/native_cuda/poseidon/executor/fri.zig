//! Exact Poseidon FRI schedule beginning after quotient alpha.

const shared = @import("../../common/fri_executor.zig");

pub const first_fri_step: u32 = 10;

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
