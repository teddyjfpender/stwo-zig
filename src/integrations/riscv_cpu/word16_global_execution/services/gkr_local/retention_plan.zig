//! Shape-derived frontend payload admission. These are requested-byte bounds,
//! not RSS or a bound on all PCS/allocator/kernel scratch. Immutable setup and
//! original capture/advice inventories must be admitted separately.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const W = @import("worker_protocol.zig");
const Components = @import("cpu_components.zig");
const Global = @import("global_cpu.zig");
const Classic = @import("classic_witness.zig");
pub const RetentionPlan = struct {
    coefficient_bytes: usize = 0,
    binding_bytes: usize = 0,
    global_metadata_bytes: usize = 0,
    global_output_bytes: usize = 0,
    gkr_peak_bytes: usize = 0,
    main_merkle_bytes: usize = 0,
    main_merkle_node_bytes: usize = 0,
    main_merkle_descriptor_bytes: usize = 0,
    local_proof_reserve_bytes: usize = 0,
    owner_header_bytes: usize = 0,
    global_scratch_bytes: usize = 0,
    parked_retained_bytes: usize = 0,
    resident_retained_bytes: usize = 0,
    stage1_task_bytes: usize = 0,
    stage2_task_bytes: usize = 0,
};
/// Phase-local task charges, separate from the whole retained-inventory lease.
/// The PCS/witness floor keeps two MAIN payloads plus the larger of the global
/// witness capacity or two complete INTER payloads (raw and native coefficients/
/// one expanded view), and bounded global scratch. GKR working planes only seal.
/// These remain represented-payload estimates, not complete PCS/RSS bounds.
pub const TaskEstimates = struct { stage1: u64, stage2: u64 };
pub fn taskEstimates(plan: RetentionPlan, global_limit: usize) !TaskEstimates {
    if (global_limit == 0) return error.MissingWideGlobalBudget;
    const twice_main = try mul(plan.coefficient_bytes, 2);
    const twice_inter = try mul(try add(plan.binding_bytes, plan.global_output_bytes), 2);
    const stage2_floor = try add(try add(twice_main, @max(global_limit, twice_inter)), plan.global_scratch_bytes);
    return .{
        .stage1 = @intCast(@max(try add(twice_main, @max(plan.gkr_peak_bytes, global_limit)), @max(plan.stage1_task_bytes, plan.stage2_task_bytes))),
        .stage2 = @intCast(@max(stage2_floor, plan.stage2_task_bytes)),
    };
}
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
pub fn forCpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, config: W.PcsConfig, gkr_limit: usize, global_limit: usize) !RetentionPlan {
    return forCpuWithOwnedCheckpoints(a, setup, request, config, gkr_limit, global_limit, false);
}
pub fn forCpuWithOwnedCheckpoints(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, config: W.PcsConfig, gkr_limit: usize, global_limit: usize, checkpointed: bool) !RetentionPlan {
    return forCpuWithTightAdmission(a, setup, request, config, gkr_limit, global_limit, checkpointed, checkpointed);
}
pub fn forCpuWithTightAdmission(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, config: W.PcsConfig, gkr_limit: usize, global_limit: usize, checkpointed: bool, tight: bool) !RetentionPlan {
    const instances = try @import("roster.zig").fromSetup(a, setup);
    defer a.free(instances);
    const numerical = try @import("resource.zig").Plan.forInstancesWithTightAdmission(instances, gkr_limit, checkpointed, tight);
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    const logs = try setup.logs(a, 1);
    defer a.free(logs);
    var out = RetentionPlan{ .binding_bytes = numerical.binding_bytes, .gkr_peak_bytes = numerical.peak_bytes, .local_proof_reserve_bytes = numerical.metadata_bytes };
    var max_log: u32 = 0;
    for (logs) |log| {
        out.coefficient_bytes = try add(out.coefficient_bytes, try mul(try rows(log), 4));
        max_log = @max(max_log, log);
    }
    const merkle_log = try std.math.add(u32, max_log, config.fri_config.log_blowup_factor);
    if (merkle_log > 30) return error.InvalidRetentionGeometry;
    const nodes = try std.math.sub(usize, try mul(@as(usize, 1) << @intCast(merkle_log), 2), 1);
    out.main_merkle_node_bytes = try mul(nodes, @sizeOf(W.H.Hash));
    out.main_merkle_descriptor_bytes = try mul(merkle_log + 1, @sizeOf([]W.H.Hash));
    out.main_merkle_bytes = try add(out.main_merkle_node_bytes, out.main_merkle_descriptor_bytes);
    // Includes column/coefficient/backing descriptors and a conservative header
    // allowance for worker/component owners; value planes are counted separately.
    out.owner_header_bytes = try add(@sizeOf(R.Sources) + 65536, try mul(logs.len, 256));
    out.owner_header_bytes = try add(out.owner_header_bytes, try mul(plan.inter_columns, 256));
    // After local retirement only canonical global row caches, boundary lists,
    // and bridge call records survive. No fixed tables/histograms are retained.
    for (plan.slots) |slot| {
        const n = try rows(slot.log);
        switch (slot.origin) {
            .core => |role| switch (role) {
                .ls, .ls_tail => out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(n, @sizeOf(A.memory.load_store_v2.source.Metadata))),
                .initial, .terminal => out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(n, @sizeOf(A.memory.load_store_v2.boundary_source.Metadata))),
                else => {},
            },
            .bridge => |family| {
                const count = request.calls[@intFromEnum(family)];
                out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(count, if (family == .keccak) @sizeOf(A.crypto.keccak.word16_bridge.types.Call) else @sizeOf(A.crypto.secp256k1.word16_bridge.types.Call)));
            },
        }
        const layout = Global.layout(slot.origin);
        out.global_output_bytes = try add(out.global_output_bytes, try mul(try mul(layout.width(), n), 4));
        const terms = (layout.ram_queries + 1) / 2 + (layout.other_queries + 1) / 2;
        out.global_scratch_bytes = @max(out.global_scratch_bytes, try Classic.scratchByteUpperBound(slot.log, terms));
    }
    out.global_metadata_bytes = try add(out.global_metadata_bytes, try mul(try add(request.base.memory.initial.len, request.base.memory.terminal.len), @sizeOf(A.memory.closed_ram.types.Cell)));
    if (try add(out.global_output_bytes, out.global_scratch_bytes) > global_limit) return error.ClassicWitnessBudgetExceeded;
    out.parked_retained_bytes = try add(try add(out.binding_bytes, out.global_metadata_bytes), try add(out.main_merkle_bytes, try add(out.local_proof_reserve_bytes, out.owner_header_bytes)));
    out.resident_retained_bytes = try add(out.parked_retained_bytes, out.coefficient_bytes);
    // Scheduling estimates cover these represented frontend payloads. Source
    // construction, shared immutable setup and PCS proving scratch are separate.
    out.stage1_task_bytes = try add(out.resident_retained_bytes, out.gkr_peak_bytes);
    out.stage2_task_bytes = try add(out.resident_retained_bytes, try add(out.global_output_bytes, out.global_scratch_bytes));
    return out;
}
