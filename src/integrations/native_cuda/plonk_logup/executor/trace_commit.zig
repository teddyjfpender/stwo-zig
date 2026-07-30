//! Exact Plonk trace prefix: commit preprocessed and main before LogUp.

const NoStatementMix = struct {
    pub fn mix(
        comptime _: type,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {}
};

const Executor = @import(
    "../../common/native_trace_commit.zig",
).ExecutorForWithStatement(
    @import("../plan.zig"),
    @import("../device_trace.zig"),
    NoStatementMix,
);

pub fn generate(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    try Executor.generate(transaction, prepared, &views.base);
}

pub fn commit(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    try Executor.commit(transaction, prepared, &views.base);
}
