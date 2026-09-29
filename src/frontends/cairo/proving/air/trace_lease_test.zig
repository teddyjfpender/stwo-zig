const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const lease_mod = @import("trace_lease.zig");
const component_mod = @import("component.zig");
const composition = @import("../../witness/composition_bundle.zig");
const eval = @import("../../witness/eval_program.zig");
const M31 = core.fields.m31.M31;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;

fn check(a: std.mem.Allocator) !void {
    return checkWithExecutor(a, null);
}
fn checkWithExecutor(a: std.mem.Allocator, executor: ?lease_mod.ExpansionExecutor) !void {
    const coefficients = [_]M31{ M31.fromCanonical(3), M31.fromCanonical(5), M31.fromCanonical(7), M31.fromCanonical(11) };
    const polynomial = try prover.poly.circle.CircleCoefficients.initBorrowed(&coefficients);
    const large = try polynomial.evaluate(std.testing.allocator, prover.poly.circle.CanonicCoset.new(4).circleDomain());
    defer std.testing.allocator.free(large.values);
    const small = try polynomial.evaluate(std.testing.allocator, prover.poly.circle.CanonicCoset.new(3).circleDomain());
    defer std.testing.allocator.free(small.values);
    var pp = [_]Poly{ .{ .log_size = 4, .values = &.{}, .coefficients = polynomial }, .{ .log_size = 5, .values = &.{}, .coefficients = polynomial } };
    var main = [_]Poly{ .{ .log_size = 3, .values = small.values }, .{ .log_size = 3, .values = &.{}, .coefficients = polynomial } };
    var interaction = [_]Poly{.{ .log_size = 4, .values = &.{}, .coefficients = polynomial }};
    var trees = [_][]const Poly{ &pp, &main, &interaction };
    const source = Trace{ .polys = core.pcs.TreeVec([]const Poly).initOwned(&trees), .partition_coefficient_composition = true };
    var instructions = [_]eval.BaseInst{
        .{ .op = .preprocessed_col, .interaction = 0, .a = 0, .dst = 0, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .a = 1, .dst = 1, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .a = 1, .dst = 2, .b = 0, .imm = -1 },
        .{ .op = .trace_col, .interaction = 2, .a = 0, .dst = 3, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .a = 0, .dst = 4, .b = 0, .imm = 0 },
    };
    var parts = [_]composition.Part{.{ .rc_base = 0, .semantic_hash = 0, .program = .{
        .allocator = a,
        .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 3, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 0, .max_base_regs = 5, .max_ext_regs = 0, .domain_log_size = 4 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &instructions,
        .ext_insts = &.{},
        .constraint_roots = &.{},
    } }};
    var spans = [_]composition.TraceSpan{ .{ .tree = 1, .start = 0, .end = 2 }, .{ .tree = 2, .start = 0, .end = 1 } };
    var pp_indices = [_]u32{0};
    var label = [_]u8{'x'};
    const captured = composition.Component{ .label = &label, .instance = 0, .trace_log_size = 3, .evaluation_log_size = 4, .n_constraints = 0, .random_coefficient_offset = 0, .trace_spans = &spans, .preprocessed_indices = &pp_indices, .denominator_inverses = &.{}, .ext_sources = &.{}, .parts = &parts };
    var lease = try lease_mod.Lease.initWithExecutor(a, &source, &captured, executor);
    defer lease.deinit();
    try std.testing.expectEqual(@as(usize, if (executor == null) 3 else 2), lease.buffers.items.len);
    try std.testing.expectEqual(@as(usize, 0), lease.trace().polys.items[0][1].values.len);
    try std.testing.expectEqual(@as(usize, 0), source.polys.items[1][1].values.len);
    const context = component_mod.TraceContext{ .trace = lease.trace(), .captured = &captured, .evaluation_log_size = 4 };
    const pp_read = try component_mod.resolveTrace(&context, 0, 0);
    const short_read = try component_mod.resolveTrace(&context, 1, 1);
    const interaction_read = try component_mod.resolveTrace(&context, 2, 0);
    try std.testing.expectEqualSlices(M31, large.values, pp_read.values);
    try std.testing.expectEqualSlices(M31, small.values, short_read.values);
    try std.testing.expectEqualSlices(M31, large.values, interaction_read.values);
    try std.testing.expectEqual(@as(usize, 2), short_read.shift_amt);
    try std.testing.expectEqual(small.values.ptr, lease.trace().polys.items[1][0].values.ptr);
    // Reusing the now materialized view does not allocate or transform again.
    var nested = try lease_mod.Lease.init(a, lease.trace(), &captured);
    defer nested.deinit();
    try std.testing.expect(nested.expanded == null);
    try std.testing.expectEqual(@as(usize, 0), nested.buffers.items.len);
}

test "Cairo trace lease reconstructs only mask columns and preserves borrowed sources" {
    try check(std.testing.allocator);
}
test "Cairo trace lease releases every reconstruction allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, check, .{});
}
test "Cairo trace lease parallel reconstruction matches serial polynomial values" {
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try check(std.testing.allocator);
}

const ExpansionProbe = struct {
    fn run(_: *anyopaque, a: std.mem.Allocator, requests: []const lease_mod.ExpansionRequest) !void {
        var previous: ?lease_mod.ExpansionRequest = null;
        for (requests) |request| {
            if (previous) |prior| if (prior.log_size == request.log_size)
                try std.testing.expect(prior.values.ptr + prior.values.len == request.values.ptr);
            var tree = try prover.poly.twiddles.precomputeM31(a, prover.poly.circle.CanonicCoset.new(request.log_size).circleDomain().half_coset);
            defer prover.poly.twiddles.deinitM31(a, &tree);
            @memcpy(request.values[0..request.coefficients.len], request.coefficients);
            @memset(request.values[request.coefficients.len..], M31.zero());
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(&.{request.values}, prover.poly.circle.CanonicCoset.new(request.log_size).circleDomain(), .{ .root_coset = tree.root_coset, .twiddles = tree.twiddles, .itwiddles = tree.itwiddles });
            previous = request;
        }
    }
};
fn checkInjected(a: std.mem.Allocator) !void {
    var context: u8 = 0;
    return checkWithExecutor(a, .{ .context = &context, .run = ExpansionProbe.run });
}
test "Cairo trace lease injected reconstruction preserves contiguous domain owners and failure custody" {
    try checkInjected(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkInjected, .{});
}
