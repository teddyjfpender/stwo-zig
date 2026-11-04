//! Source-experiment only: compare an original real padded leaf assignment with
//! the CPU-only compact padding prototype. No proof or execution acceptance.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("common.zig").Q;
const Padding = Circuit.builder.padding_plan_prototype;
const Schedule = Circuit.builder.witness_plan;
const PP = Circuit.common.preprocessed.PreprocessedCircuit;
pub const Report = struct {
    diagnostic: bool = true,
    accepted: bool = false,
    gpu_supported: bool = false,
    full_variables: usize,
    prefix_variables: usize,
    ranged_variables: usize,
    ordinary_tasks: usize,
    compact_tasks: usize,
    eliminated_tasks: usize,
    descriptors: usize,
    ordinary_seeds: usize,
    compact_seeds: usize,
    ordinary_levels: usize,
    compact_levels: usize,
    all_assignment_values_exact: bool,
    assignment_sha256: [32]u8,
    full_padded_circuit_checked: bool,
    original_circuit_unchanged: bool,
    original_circuit_sha256: [32]u8,
    pp_columns_exact: usize,
    pp_cells_exact: usize,
    compact_plan_ns: u64,
    ordinary_evaluate_ns: u64,
    compact_evaluate_ns: u64,
    assignment_comparison_ns: u64,
    pp_comparison_ns: u64,
    total_ns: u64,
};
fn fingerprint(ctx: *const Circuit.builder.Context(Q)) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, ctx.circuit.n_vars, .little);
    hash.update(&word);
    inline for (.{ "eq", "add", "sub", "mul", "pointwise_mul", "triple_xor", "m31_to_u32", "blake_g_gate", "output" }) |name| {
        const items = @field(ctx.circuit, name).items;
        std.mem.writeInt(u64, &word, items.len, .little);
        hash.update(name);
        hash.update(&word);
        hash.update(std.mem.sliceAsBytes(items));
    }
    inline for (.{ "inputs", "outputs", "ends" }) |name| {
        const items = @field(ctx.circuit.permutation, name).items;
        std.mem.writeInt(u64, &word, items.len, .little);
        hash.update(name);
        hash.update(&word);
        hash.update(std.mem.sliceAsBytes(items));
    }
    return hash.finalResult();
}
pub fn compare(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), provenance: Padding.Provenance, ordinary: Schedule.Plan) !Report {
    var total = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const original_fingerprint = fingerprint(ctx);
    var compact = try Padding.Plan.build(a, ctx, provenance);
    defer compact.deinit();
    const compact_plan_ns = timer.lap();
    try std_testing_expect_unsupported.check(&compact);
    const old_values = try Schedule.evaluate(a, ctx, ordinary);
    defer a.free(old_values);
    const ordinary_evaluate_ns = timer.lap();
    const new_values = try compact.evaluate(a, ctx);
    defer a.free(new_values);
    const compact_evaluate_ns = timer.lap();
    if (!std.mem.eql(u8, std.mem.sliceAsBytes(old_values), std.mem.sliceAsBytes(new_values))) return error.PaddingRangeAssignmentMismatch;
    var assignment_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(old_values), &assignment_digest, .{});
    const assignment_comparison_ns = timer.lap();
    var cells: usize = 0;
    var columns: usize = 0;
    {
        var original_pp = try PP.fromBuilderCircuit(a, &ctx.circuit);
        defer original_pp.deinit(a);
        var after_pp = try PP.fromBuilderCircuit(a, &ctx.circuit);
        defer after_pp.deinit(a);
        for (original_pp.columns, after_pp.columns) |left, right| {
            if (!std.mem.eql(u8, left.id, right.id) or !std.mem.eql(u8, std.mem.sliceAsBytes(left.values), std.mem.sliceAsBytes(right.values))) return error.PaddingRangePreprocessedMismatch;
            columns += 1;
            cells += left.values.len;
        }
    }
    const pp_comparison_ns = timer.lap();
    if (!std.mem.eql(u8, &original_fingerprint, &fingerprint(ctx))) return error.PaddingRangeCircuitMutation;
    var ranged: usize = 0;
    var removed: usize = 0;
    for (compact.ranges) |range| {
        ranged += range.count;
        removed += range.gate_count;
    }
    if (removed != ordinary.tasks.len - compact.prefix_plan.tasks.len or ordinary.seeds.len != compact.prefix_plan.seeds.len or ranged != ctx.circuit.n_vars - provenance.before.variables) return error.PaddingRangeCensusMismatch;
    return .{ .full_variables = ctx.circuit.n_vars, .prefix_variables = provenance.before.variables, .ranged_variables = ranged, .ordinary_tasks = ordinary.tasks.len, .compact_tasks = compact.prefix_plan.tasks.len, .eliminated_tasks = removed, .descriptors = compact.ranges.len, .ordinary_seeds = ordinary.seeds.len, .compact_seeds = compact.prefix_plan.seeds.len, .ordinary_levels = ordinary.level_ends.len, .compact_levels = compact.prefix_plan.level_ends.len, .all_assignment_values_exact = true, .assignment_sha256 = assignment_digest, .full_padded_circuit_checked = true, .original_circuit_unchanged = true, .original_circuit_sha256 = original_fingerprint, .pp_columns_exact = columns, .pp_cells_exact = cells, .compact_plan_ns = compact_plan_ns, .ordinary_evaluate_ns = ordinary_evaluate_ns, .compact_evaluate_ns = compact_evaluate_ns, .assignment_comparison_ns = assignment_comparison_ns, .pp_comparison_ns = pp_comparison_ns, .total_ns = total.read() };
}
// This is an admission assertion, not a test-only std.testing dependency.
const std_testing_expect_unsupported = struct {
    fn check(plan: *const Padding.Plan) !void {
        plan.requireGpuSupported() catch |err| {
            if (err == error.PaddingRangeGpuUnsupported) return;
            return err;
        };
        return error.PaddingGpuAdmissionUnexpectedlyOpen;
    }
};
