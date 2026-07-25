//! Exact State v2 PoW and three-tree authenticated opening schedule.

const shared = @import("../../common/pow_decommit_executor.zig");
const first_fri_step = @import("fri.zig").first_fri_step;

pub fn runPow(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return shared.executePowAt(
        transaction,
        prepared,
        views,
        first_fri_step,
    );
}

pub fn runDecommit(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return shared.executeDecommitAt(
        transaction,
        prepared,
        views,
        first_fri_step,
    );
}

pub fn runPowWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return shared.executePowWithAt(
        Ops,
        transaction,
        prepared,
        views,
        first_fri_step,
    );
}

pub fn runDecommitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return shared.executeDecommitWithAt(
        Ops,
        transaction,
        prepared,
        views,
        first_fri_step,
    );
}
