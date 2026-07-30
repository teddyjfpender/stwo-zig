//! Exact XOR trace prefix: commit preprocessed and main before LogUp.

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
const device_trace = @import("../device_trace.zig");

pub fn generate(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    const preprocessed = try views.base.trees.require(.preprocessed);
    const main = try views.base.trees.require(.main);
    try device_trace.generate(
        transaction.proofSession(),
        .{
            .preprocessed = preprocessed.coefficients,
            .main = main.coefficients,
            .relation_sources = views.relation.source_values,
        },
        prepared.logical.geometry,
    );
}

pub fn commit(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    try Executor.commit(transaction, prepared, &views.base);
}
