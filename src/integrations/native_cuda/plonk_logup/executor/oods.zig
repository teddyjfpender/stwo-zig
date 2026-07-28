//! Exact 24-source, 28-sample OODS execution and transcript policy.

const common = @import("../../common/oods_executor.zig");
const policy = @import("../oods.zig");

pub fn run(
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    const Ops = struct {
        const Transcript = @import("stwo_cuda_backend").runtime.stages.transcript.Native;
        const Oods = @import("stwo_cuda_backend").runtime.stages.oods.Native;
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
            .draw_oods = 7,
            .mix_samples = 8,
            .draw_quotient = 9,
        },
    );
}
