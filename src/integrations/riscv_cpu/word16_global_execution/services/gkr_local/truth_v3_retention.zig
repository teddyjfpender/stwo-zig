//! Source-derived V3 retained payload. Requested bytes, not total PCS/RSS.
const std = @import("std");
const R = @import("../roster.zig");
const C = @import("truth_v3_catalog.zig");
const W = @import("worker_protocol.zig");
const Worker = @import("truth_v3_worker.zig");
const Plan = @import("retention_plan.zig").RetentionPlan;
fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b);
}
fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b);
}
pub fn forTruth(_: std.mem.Allocator, truth: R.Truth, config: W.PcsConfig, global_limit: usize) !Plan {
    const d = try C.descriptor(truth);
    try Worker.admit(truth, global_limit);
    const n = @as(usize, 1) << @intCast(d.log_size);
    var out = Plan{};
    out.coefficient_bytes = try mul(try mul(n, d.shape.main), 4);
    out.global_output_bytes = try Worker.interactionBytes(truth);
    out.global_scratch_bytes = try Worker.scratchBytes(truth);
    // Include fixed views conservatively even if canonical setup owns them.
    out.global_metadata_bytes = try add(try C.metadataByteUpperBound(truth), try mul(try mul(n, d.shape.fixed), 4));
    const log = try std.math.add(u32, d.log_size, config.fri_config.log_blowup_factor);
    if (log > 30) return error.InvalidRetentionGeometry;
    const nodes = try std.math.sub(usize, try mul(@as(usize, 1) << @intCast(log), 2), 1);
    out.main_merkle_node_bytes = try mul(nodes, @sizeOf(W.H.Hash));
    out.main_merkle_descriptor_bytes = try mul(log + 1, @sizeOf([]W.H.Hash));
    out.main_merkle_bytes = try add(out.main_merkle_node_bytes, out.main_merkle_descriptor_bytes);
    const cols = try add(try add(d.shape.fixed, d.shape.main), d.shape.inter);
    out.owner_header_bytes = try add(@sizeOf(Worker.NativeTruthWorker) + 65536, try mul(cols, 256));
    out.parked_retained_bytes = try add(out.global_metadata_bytes, try add(out.main_merkle_bytes, out.owner_header_bytes));
    out.resident_retained_bytes = try add(out.parked_retained_bytes, out.coefficient_bytes);
    out.stage1_task_bytes = out.resident_retained_bytes;
    out.stage2_task_bytes = try add(out.resident_retained_bytes, try add(out.global_output_bytes, out.global_scratch_bytes));
    return out;
}
