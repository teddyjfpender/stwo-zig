//! Exact 20-source, 28-sample mixed-height OODS execution.

const common = @import("../../common/oods_executor.zig");
const policy = @import("../oods.zig");

pub fn run(
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    const Ops = struct {
        const Transcript = @import(
            "../../../../backends/cuda/runtime/stages/transcript.zig",
        ).Native;
        const Oods = @import(
            "../../../../backends/cuda/runtime/stages/oods.zig",
        ).Native;
        const Capture = @import("../../common/proof_assembly.zig");
    };
    return runWith(Ops, transaction, prepared, ingress, views);
}

pub fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    var storage: [policy.max_batches]policy.Batch = undefined;
    const batches = try policy.buildBatches(
        prepared,
        ingress,
        views,
        &storage,
    );
    try common.runBatchesWithAt(
        Ops,
        transaction,
        prepared,
        views,
        batches,
        .{
            .draw_oods = 9,
            .mix_samples = 10,
            .draw_quotient = 11,
        },
    );
}
