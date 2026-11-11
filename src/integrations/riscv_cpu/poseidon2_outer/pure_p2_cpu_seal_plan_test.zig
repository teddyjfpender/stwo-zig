//! Optional witness-free numerical assessment from the retained, qualified
//! capture declarations. Source constants determine every padded GKR term count.
const std = @import("std");
const core = @import("stwo_core");
const Runtime = @import("pure_p2_op_runtime.zig");
const Cost = @import("pure_p2_op_cost.zig");
const G = @import("../word16_execution/geometry.zig");
const Roster = @import("../word16_global_execution/services/gkr_local/roster.zig");
const Resource = @import("../word16_global_execution/services/gkr_local/resource.zig");
const Instance = @import("../word16_global_execution/services/gkr_local/frame.zig").Instance;
const a = std.testing.allocator;
fn terms(origin: @import("../word16_global_execution/services/gkr_local/frame.zig").Origin, g: G.Geometry) u32 {
    return switch (origin) {
        .core => |role| if (g.cpu_u8_pairs and role == .cpu) @import("../word16_global_execution/services/gkr_local/fractions.zig").cpuTerms(true) else if (g.cpu_u8_pairs and role == .and_table) @import("../word16_global_execution/services/gkr_local/fractions.zig").andTableTerms(true) else Roster.terms(role),
        .bridge => |kind| Roster.bridgeTerms(kind),
        .bulk => |kind| @import("../word16_global_execution/services/gkr_local/bulk_projection.zig").localTerms(kind),
        .sponge => |kind| @import("../word16_global_execution/services/gkr_local/sponge_projection.zig").localTerms(kind),
        .dword => @import("../word16_global_execution/services/gkr_local/dword_projection.zig").LOCAL_TERMS,
        .tower => @import("../word16_global_execution/services/gkr_local/op_tower_projection.zig").LOCAL_TERMS,
    };
}
const CpuCost = struct { ordinal: usize, roles: []const Cost.Role, main_coefficient_bytes: u64, merkle_node_bytes: u64 };
const Cpu = struct {
    ordinal: usize,
    padded_facts: usize,
    local_instances: usize,
    source_checkpoint_plan: Resource.Plan,
    main_coefficients: u64,
    main_merkle_upper: u64,
    retained_baseline_plus_gkr: u64,
    retained_baseline_plus_gkr_and_main: u64,
};

test "OP retained heavy CPU source checkpoint seal assessment uses exact roster constants" {
    const root = std.posix.getenv("STWO_OP_CPU_SEAL_PLAN_ROOT") orelse return error.SkipZigTest;
    const output = std.posix.getenv("STWO_OP_CPU_SEAL_PLAN_OUTPUT") orelse return error.SkipZigTest;
    const plan_path = try std.fs.path.join(a, &.{ root, "pure-p2-native-heavy-retired-plan", "native-op-plan.json" });
    defer a.free(plan_path);
    const cost_path = try std.fs.path.join(a, &.{ root, "pure-p2-native-heavy-retired-plan", "native-op-cost.json" });
    defer a.free(cost_path);
    const metadata_raw = try std.fs.cwd().readFileAlloc(a, plan_path, 8 << 20);
    defer a.free(metadata_raw);
    const costs_raw = try std.fs.cwd().readFileAlloc(a, cost_path, 8 << 20);
    defer a.free(costs_raw);
    const metadata = try std.json.parseFromSlice(struct { metadata: Runtime.Metadata }, a, metadata_raw, .{ .ignore_unknown_fields = true });
    defer metadata.deinit();
    const costs = try std.json.parseFromSlice(struct { cpus: []const CpuCost }, a, costs_raw, .{ .ignore_unknown_fields = true });
    defer costs.deinit();
    try std.testing.expectEqual(@as(usize, 57), metadata.value.metadata.cpus.len);
    try std.testing.expectEqual(metadata.value.metadata.cpus.len, costs.value.cpus.len);
    const baseline: u64 = 25516298742; // Actual all-class cached prepare before witness construction.
    const rows = try a.alloc(Cpu, costs.value.cpus.len);
    defer a.free(rows);
    var max_extra: usize = 0;
    var max_total: u64 = 0;
    for (metadata.value.metadata.cpus, costs.value.cpus, rows, 0..) |declaration, cost, *row, index| {
        var instances: std.ArrayList(Instance) = .empty;
        defer instances.deinit(a);
        var facts: usize = 0;
        for (cost.roles) |role| {
            if (role.origin == .core) {
                var matched = false;
                for (G.shapesForProgramLog(20, declaration.geometry)) |shape| if (shape.role == role.origin.core) {
                    try std.testing.expectEqual(shape.log, role.log);
                    matched = true;
                    break;
                };
                try std.testing.expect(matched);
            }
            const n = terms(role.origin, declaration.geometry);
            if (n == 0) continue;
            // Offsets are deliberately unused by numerical Resource.Plan; this
            // descriptor is never passed to witness/prover/source authority.
            const instance = Instance{ .origin = role.origin, .row_log = role.log, .terms = n, .fixed_offset = 0, .main_offset = 0 };
            facts = try std.math.add(usize, facts, try instance.facts());
            try instances.append(a, instance);
        }
        const resource = try Resource.Plan.forInstancesWithSourceStorage(instances.items, 12 << 30, true);
        const with_gkr = try std.math.add(u64, baseline, resource.peak_bytes);
        const total = try std.math.add(u64, with_gkr, try std.math.add(u64, cost.main_coefficient_bytes, cost.merkle_node_bytes));
        row.* = .{ .ordinal = index, .padded_facts = facts, .local_instances = instances.items.len, .source_checkpoint_plan = resource, .main_coefficients = cost.main_coefficient_bytes, .main_merkle_upper = cost.merkle_node_bytes, .retained_baseline_plus_gkr = with_gkr, .retained_baseline_plus_gkr_and_main = total };
        max_extra = @max(max_extra, resource.peak_bytes);
        max_total = @max(max_total, total);
    }
    try std.fs.cwd().makePath(output);
    var dir = try std.fs.cwd().openDir(output, .{});
    defer dir.close();
    try @import("../word16_execution/driver.zig").writeJson(a, dir, "cpu-seal-plan.json", .{ .schema = "op-heavy-cpu-source-seal-assessment/v1", .proof_verified = false, .modeled_requested_payload_only = true, .measured_retained_capture_and_setup_baseline = baseline, .common_limit = @as(u64, 32) << 30, .child_limit = @as(u64, 12) << 30, .max_source_checkpoint_peak_bytes = max_extra, .max_baseline_gkr_main_payload = max_total, .all_modeled_payloads_fit32GiB = max_total <= @as(u64, 32) << 30, .cpus = rows, .caveat = "Uses qualified frozen declarations with independent source term-count formulas and existing reviewed52B/fact storage. Baseline is measured schema1 cached prepare; schema2 fixed classes differ. MAIN coefficients/full Merkle upper are not scratch, and source construction, fixed leases, binding metadata, allocator/PCS scratch and evolving advice retirement require separate accounting. This is no whole-worker/RSS guarantee and no proof acceptance." });
    std.debug.print("OP_CPU_SEAL_PLAN children={} max_gkr={} max_baseline_plus_gkr_main={} common={} fits_payload={}\n", .{ rows.len, max_extra, max_total, @as(u64, 32) << 30, max_total <= @as(u64, 32) << 30 });
}
