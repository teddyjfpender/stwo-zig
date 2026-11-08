//! Typed secure sampling over the shared M31 commitment owner. Retained M31
//! coefficients share one bounded split basis per exact normalized point and
//! geometry. Pool helpers borrow immutable weights and write disjoint outputs.
const std = @import("std");
const core = @import("stwo_core");
const tree_mod = @import("commitment_tree.zig");
const poly = @import("../poly/circle/poly.zig");
const eval_mod = @import("../poly/circle/evaluation.zig");
const RowWork = @import("../lookups/row_work.zig");
const Budget = @import("../host_budget_allocator.zig").HostBudgetAllocator;
const Wide = @import("../poly/circle/point_evaluation_wide.zig");
const TreeVec = core.pcs.TreeVec;
pub const DEFAULT_SCRATCH_LIMIT: usize = 32 << 20;
pub const Options = struct { scratch_limit: usize = DEFAULT_SCRATCH_LIMIT, allow_parallel: bool = true };
pub fn ForField(comptime S: type) type {
    if (S != core.fields.om31.OM31) @compileError("wide sampled values require OM31");
    return struct {
        const Point = core.circle.CirclePoint(S);
        const Target = struct { coefficients: []const core.fields.m31.M31, output: *S };
        const Group = struct { log: u32, point: Point, targets: std.ArrayList(Target) = .empty };
        const Key = [4 + 2 * @sizeOf(S)]u8;
        pub fn evaluateAndReleaseWithWorkRecorder(comptime B: type, comptime H: type, a: std.mem.Allocator, trees: []tree_mod.CommitmentTreeProverForBackend(B, H), points: TreeVec([][]Point), log: u32, recorder: ?*@import("stwo_prover_api").work_profile.Recorder(true)) !TreeVec([][]S) {
            if (recorder != null) return error.UnsupportedWideSamplingWorkProfile;
            return evaluateWithOptions(B, H, a, trees, points, log, .{});
        }
        pub fn evaluateWithOptions(comptime B: type, comptime H: type, a: std.mem.Allocator, trees: []tree_mod.CommitmentTreeProverForBackend(B, H), points: TreeVec([][]Point), log: u32, options: Options) !TreeVec([][]S) {
            if (trees.len != points.items.len) return error.ShapeMismatch;
            const out = try a.alloc([][]S, trees.len);
            errdefer a.free(out);
            var ntrees: usize = 0;
            errdefer for (out[0..ntrees]) |t| {
                for (t) |c| a.free(c);
                a.free(t);
            };
            for (trees, points.items, 0..) |*tree, tree_points, ti| {
                if (tree.columns.len != tree_points.len) return error.ShapeMismatch;
                if (tree.coefficients) |coefficients| if (coefficients.len != tree.columns.len) return error.ShapeMismatch;
                const result = try a.alloc([]S, tree.columns.len);
                var ncols: usize = 0;
                errdefer {
                    for (result[0..ncols]) |c| a.free(c);
                    a.free(result);
                }
                for (tree.columns, tree_points, 0..) |column, ps, ci| {
                    try column.validateRetained();
                    if (ps.len != 0 and column.log_size > log) return error.ShapeMismatch;
                    result[ci] = try a.alloc(S, ps.len);
                    ncols += 1;
                }
                out[ti] = result;
                ntrees += 1;
            }
            var budget = Budget.init(a, options.scratch_limit);
            var grouped = true;
            evaluateGroups(B, H, budget.allocator(), trees, points, out, log, options.allow_parallel) catch |err| {
                if (err == error.OutOfMemory and budget.didExceedBudget()) grouped = false else return err;
            };
            // Metadata and all basis/consumer tasks are gone before fallback or
            // coefficient release. Child allocator OOM always propagates.
            std.debug.assert(budget.live_bytes == 0);
            for (trees, points.items, out) |*tree, tree_points, result| {
                for (tree.columns, tree_points, 0..) |column, ps, ci| {
                    if (ps.len == 0) continue;
                    const retained = try retainedCoefficients(tree, ci);
                    if (grouped and retained != null) continue;
                    var temporary: ?poly.CircleCoefficients = null;
                    defer if (temporary) |*p| p.deinit(a);
                    const coefficients = if (retained) |c| c else blk: {
                        const domain = core.poly.circle.canonic.CanonicCoset.new(column.log_size).circleDomain();
                        temporary = try poly.interpolateFromEvaluation(a, try eval_mod.CircleEvaluation.init(domain, column.values));
                        break :blk temporary.?;
                    };
                    for (ps, 0..) |point, i| result[ci][i] = coefficients.evalAtPointFor(S, point.repeatedDouble(log - column.log_size));
                }
            }
            for (trees) |*tree| tree.releaseCoefficients(a);
            return TreeVec([][]S).initOwned(out);
        }
        fn retainedCoefficients(tree: anytype, ci: usize) !?poly.CircleCoefficients {
            if (tree.coefficients) |coefficients| return coefficients[ci];
            if (tree.columns[ci].coefficient_values) |values| return try poly.CircleCoefficients.initBorrowed(values);
            return null;
        }
        fn key(log: u32, point: Point) Key {
            var result: Key = undefined;
            std.mem.writeInt(u32, result[0..4], log, .little);
            var at: usize = 4;
            for (point.x.toM31Array() ++ point.y.toM31Array()) |v| {
                std.mem.writeInt(u32, result[at..][0..4], v.v, .little);
                at += 4;
            }
            return result;
        }
        fn evaluateGroups(comptime B: type, comptime H: type, a: std.mem.Allocator, trees: []tree_mod.CommitmentTreeProverForBackend(B, H), points: TreeVec([][]Point), out: [][][]S, log: u32, allow_parallel: bool) !void {
            var groups: std.ArrayList(Group) = .empty;
            defer {
                for (groups.items) |*g| g.targets.deinit(a);
                groups.deinit(a);
            }
            var index = std.AutoHashMap(Key, usize).init(a);
            defer index.deinit();
            for (trees, points.items, 0..) |*tree, tree_points, ti| {
                for (tree.columns, tree_points, 0..) |column, ps, ci| {
                    if (ps.len == 0) continue;
                    const coefficients = (try retainedCoefficients(tree, ci)) orelse continue;
                    for (ps, 0..) |point, pi| {
                        const normalized = point.repeatedDouble(log - column.log_size);
                        const k = key(coefficients.log_size, normalized);
                        const at = if (index.get(k)) |existing| existing else blk: {
                            const next = groups.items.len;
                            try groups.append(a, .{ .log = coefficients.log_size, .point = normalized });
                            try index.put(k, next);
                            break :blk next;
                        };
                        try groups.items[at].targets.append(a, .{ .coefficients = coefficients.coeffs, .output = &out[ti][ci][pi] });
                    }
                }
            }
            for (groups.items) |group| {
                var basis = try Wide.Basis.init(a, group.point, group.log);
                defer basis.deinit(a);
                var context = Context{ .basis = basis, .targets = group.targets.items };
                const terms = @as(usize, 1) << @intCast(group.log);
                const minimum = try std.math.divCeil(usize, 4096, terms);
                const enough = group.targets.items.len >= minimum;
                _ = RowWork.forEachRange(group.targets.items.len, &context, .{ .max_shards = if (allow_parallel and enough) RowWork.MAX_SHARDS else 1, .min_rows_per_shard = 1 });
            }
        }
        const Context = struct {
            basis: Wide.Basis,
            targets: []const Target,
            pub fn runRange(ctx: *@This(), _: usize, first: usize, end: usize) void {
                for (ctx.targets[first..end]) |target| target.output.* = ctx.basis.evaluate(target.coefficients);
            }
        };
    };
}
