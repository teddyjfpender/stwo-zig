//! Shape-derived retained truth payload, including compact LOCAL query metadata
//! needed after parking. This shares the CPU value-plan, not a total-RSS claim.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const R = @import("../roster.zig");
const W = @import("worker_protocol.zig");
const Worker = @import("truth_worker.zig");
const C = @import("truth_components.zig").Components;
const Local = @import("truth_classic.zig");
const Classic = @import("classic_witness.zig");
const Plan = @import("retention_plan.zig").RetentionPlan;
fn add(x: usize, y: usize) !usize {
    return std.math.add(usize, x, y);
}
fn mul(x: usize, y: usize) !usize {
    return std.math.mul(usize, x, y);
}
fn rows(log: u32) !usize {
    if (log < 5 or log > 26) return error.InvalidRetentionGeometry;
    return @as(usize, 1) << @intCast(log);
}
pub fn forTruth(a: std.mem.Allocator, truth: R.Truth, config: W.PcsConfig, global_limit: usize) !Plan {
    _ = try Worker.truthMass(truth);
    const roles = try C.init(truth, undefined, undefined, &@as([5]W.O, @splat(W.O.zero())));
    const logs = try truth.logs(a, 1);
    defer a.free(logs);
    var out = Plan{};
    var max_log: u32 = 0;
    var all_columns: usize = 0;
    for (logs) |log| {
        out.coefficient_bytes = try add(out.coefficient_bytes, try mul(try rows(log), 4));
        max_log = @max(max_log, log);
    }
    for (roles.items) |role| {
        const n = try rows(role.log_size);
        out.global_output_bytes = try add(out.global_output_bytes, try mul(try mul(role.widths()[2], n), 4));
        out.global_scratch_bytes = @max(out.global_scratch_bytes, try mul(try mul(@min(n, Classic.ROW_CHUNK), Local.inverseCount(role.instance())), 2 * @sizeOf(W.O) + @sizeOf(Classic.Numerator)));
        for (role.widths()) |width| all_columns = try add(all_columns, width);
    }
    if (try add(out.global_output_bytes, out.global_scratch_bytes) > global_limit) return error.WideTruthBudgetExceeded;
    switch (truth) {
        .keccak => |t| {
            const n = try rows(t.setup.log);
            const active_rows = try mul(try std.math.divCeil(usize, t.calls, 2), K.layout.ROWS_PER_PAIR);
            out.global_metadata_bytes = try mul(active_rows, @sizeOf(K.trace.PackedRow));
            out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(n, 4 * K.layout.FIXED));
            out.global_metadata_bytes = try add(out.global_metadata_bytes, (8192 + 1024) * (7 * 4 + 4));
        },
        .secp => |t| {
            const program = S.program.get(t.setup.kind);
            for ([_]S.layout.Kind{ .product, .linear }, t.setup.logs) |kind, log| {
                const active_rows = try mul(t.calls, program.rows(kind == .product));
                out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(active_rows, S.layout.metadataByteCount(kind)));
                // Conservatively include fixed read views even when the canonical source
                // borrows them from immutable setup, covering independently owned sources.
                out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(try rows(log), 4 * S.layout.FIXED));
            }
            out.global_metadata_bytes = try add(out.global_metadata_bytes, (3 + 1) * 256 * 4);
        },
    }
    const merkle_log = try std.math.add(u32, max_log, config.fri_config.log_blowup_factor);
    if (merkle_log > 30) return error.InvalidRetentionGeometry;
    const nodes = try std.math.sub(usize, try mul(@as(usize, 1) << @intCast(merkle_log), 2), 1);
    out.main_merkle_node_bytes = try mul(nodes, @sizeOf(W.H.Hash));
    out.main_merkle_descriptor_bytes = try mul(merkle_log + 1, @sizeOf([]W.H.Hash));
    out.main_merkle_bytes = try add(out.main_merkle_node_bytes, out.main_merkle_descriptor_bytes);
    out.owner_header_bytes = try add(@sizeOf(Worker.TruthWorker) + 65536, try mul(all_columns, 256));
    out.parked_retained_bytes = try add(out.global_metadata_bytes, try add(out.main_merkle_bytes, out.owner_header_bytes));
    out.resident_retained_bytes = try add(out.parked_retained_bytes, out.coefficient_bytes);
    out.stage1_task_bytes = out.resident_retained_bytes;
    out.stage2_task_bytes = try add(out.resident_retained_bytes, try add(out.global_output_bytes, out.global_scratch_bytes));
    return out;
}
