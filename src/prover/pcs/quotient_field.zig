//! Bounded secure-field quotient fallback. Formula authority is core PCS;
//! committed columns and domain geometry remain base-field representations.
const std = @import("std");
const core = @import("stwo_core");
const geometry = @import("quotient_column_geometry.zig");
const work_profile = @import("stwo_prover_api").work_profile;
const M = core.fields.m31.M31;
const RowWork = @import("../lookups/row_work.zig");
const Pools = @import("../work_pool.zig");
const Walk = @import("quotient_domain_walk.zig").BitReversedCosetWalk;
const TreeVec = core.pcs.TreeVec;
pub fn ForField(comptime S: type) type {
    return struct {
        const Q = core.pcs.ForField(S).quotients;
        const Point = core.circle.CirclePoint(S);
        const Column = @import("../secure_column.zig").SecureColumnByCoordsFor(S);
        const Groups = @import("quotients/coefficient_groups.zig").ForField(S);
        pub const ResourcePlan = Groups.ResourcePlan;
        const DEGREE = @typeInfo(@TypeOf(S.zero().toM31Array())).array.len;
        pub const ColumnEvaluation = geometry.ColumnEvaluation;
        pub const QuotientOpsError = geometry.QuotientOpsError;
        pub const LAZY_QUOTIENT_CHUNK_SIZE = 1024;
        const Inner = S.InnerField;
        pub const ChunkScratchPlan = struct {
            rows: usize,
            batches: usize,
            cells: usize,
            point_bytes: usize,
            denominator_bytes: usize,
            inverse_bytes: usize,
            total_bytes: usize,
            pub fn init(domain_size: usize, batches: usize) !@This() {
                const rows: usize = if (batches == 0) 0 else @min(LAZY_QUOTIENT_CHUNK_SIZE, domain_size);
                const cells = try std.math.mul(usize, rows, batches);
                const points = try std.math.mul(usize, rows, @sizeOf(core.circle.CirclePointM31));
                const half_field = try std.math.mul(usize, cells, @sizeOf(Inner));
                return .{ .rows = rows, .batches = batches, .cells = cells, .point_bytes = points, .denominator_bytes = half_field, .inverse_bytes = half_field, .total_bytes = try std.math.add(usize, points, try std.math.mul(usize, half_field, 2)) };
            }
        };
        pub const MAX_PARALLEL_SCRATCH_BYTES: usize = 8 << 20;
        const RowScratch = struct {
            workspace: Q.RowQuotientWorkspace,
            points: []core.circle.CirclePointM31,
            denominators: []Inner,
            inverses: []Inner,
            fn init(a: std.mem.Allocator, batches: []const Q.ColumnSampleBatch, plan: ChunkScratchPlan) !@This() {
                var workspace = try Q.RowQuotientWorkspace.init(a, batches);
                errdefer workspace.deinit(a);
                const points = try a.alloc(core.circle.CirclePointM31, plan.rows);
                errdefer a.free(points);
                const denominators = try a.alloc(Inner, plan.cells);
                errdefer a.free(denominators);
                const inverses = try a.alloc(Inner, plan.cells);
                return .{ .workspace = workspace, .points = points, .denominators = denominators, .inverses = inverses };
            }
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                self.workspace.deinit(a);
                a.free(self.points);
                a.free(self.denominators);
                a.free(self.inverses);
            }
        };
        fn rowScratchBytes(plan: ChunkScratchPlan, batches: usize) !usize {
            // Three half-field sample components, two half-field row planes,
            // one secure numerator per batch, plus the bounded chunk buffers.
            const workspace = try std.math.mul(usize, batches, 5 * @sizeOf(Inner) + @sizeOf(S));
            return std.math.add(usize, plan.total_bytes, try std.math.add(usize, workspace, @sizeOf(RowScratch)));
        }
        pub const InputMode = enum { bounded_cpu, combined_compatibility, raw_backend };
        pub const LazyQuotientProvider = struct {
            groups: Groups.Plan,
            batches: []Q.ColumnSampleBatch,
            constants: Q.QuotientConstants,
            workspace: Q.RowQuotientWorkspace,
            scratch_plan: ChunkScratchPlan,
            scratch_points: []core.circle.CirclePointM31,
            scratch_denominators: []Inner,
            scratch_inverses: []Inner,
            domain: core.poly.circle.domain.CircleDomain,
            domain_size: usize,
            lifting_log_size: u32,
            parallel_shards: usize = 1,
            backend_residency_handles: []const *anyopaque = &.{},
            pub fn init(a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32) !@This() {
                return initForBackendWithWorkRecorder(void, a, columns, points, values, alpha, log, null);
            }
            pub fn initForBackend(comptime B: type, a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32) !@This() {
                return initForBackendWithWorkRecorder(B, a, columns, points, values, alpha, log, null);
            }
            pub fn initForBackendWithWorkRecorder(comptime B: type, a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32, recorder: ?*work_profile.Recorder(true)) !@This() {
                return initForBackendWithWorkRecorderAndByteLimit(B, a, columns, points, values, alpha, log, recorder, null);
            }
            pub fn initForBackendWithWorkRecorderAndByteLimit(comptime B: type, a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32, recorder: ?*work_profile.Recorder(true), byte_limit: ?usize) !@This() {
                if (recorder != null) return error.UnsupportedWideQuotientWorkProfile;
                if (log == 0 or log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidColumnLogSize;
                if (comptime B != void and @hasDecl(B, "rawQuotientInputs")) if (B.rawQuotientInputs) return error.UnsupportedWideRawQuotientBackend;
                if (columns.items.len != points.items.len or columns.items.len != values.items.len) return error.ShapeMismatch;
                for (columns.items, points.items, values.items) |cols, pts, vals| {
                    if (cols.len != pts.len or cols.len != vals.len) return error.ShapeMismatch;
                    for (cols, pts, vals) |column, ps, vs| {
                        if (ps.len != vs.len) return error.ShapeMismatch;
                        try column.validateRetained();
                        if (ps.len != 0 and (column.log_size == 0 or column.log_size > log)) return error.InvalidColumnLogSize;
                    }
                }
                const size = try geometry.checkedPow2(log);
                var logs = try geometry.buildColumnLogSizes(a, columns);
                defer logs.deinitDeep(a);
                const flat = try geometry.flattenColumnsBorrowed(a, columns);
                defer a.free(flat);
                const batches = try Q.buildColumnSampleBatchesFromParallelInputs(a, points, values, logs, log, alpha);
                errdefer Q.ColumnSampleBatch.deinitSlice(a, batches);
                var constants = try Q.quotientConstants(a, batches);
                errdefer constants.deinit(a);
                var workspace = try Q.RowQuotientWorkspace.init(a, batches);
                errdefer workspace.deinit(a);
                const scratch = try ChunkScratchPlan.init(size, batches.len);
                const group_limit: ?usize = if (byte_limit) |limit| blk: {
                    if (scratch.total_bytes > limit) return error.QuotientScratchBudgetExceeded;
                    break :blk limit - scratch.total_bytes;
                } else null;
                var groups = try Groups.Plan.init(a, flat, batches, &constants, log, group_limit);
                errdefer groups.deinit(a);
                groups.resources.inverse_chunk_scratch_bytes = scratch.total_bytes;
                const per_helper = try rowScratchBytes(scratch, batches.len);
                const scoped = Pools.currentScopedPool();
                const desired: usize = if (scoped) |pool| @min(RowWork.MAX_SHARDS, @min(pool.availableWorkers(), size / RowWork.MIN_ROWS_PER_SHARD)) else 1;
                // Parallelism only consumes the remainder of the admitted
                // owner budget. An exact scalar cap stays a valid scalar path.
                const remaining = if (byte_limit) |limit| limit -| try groups.resources.largeBufferUpperBound() else MAX_PARALLEL_SCRATCH_BYTES;
                const cap = @min(MAX_PARALLEL_SCRATCH_BYTES, remaining);
                const helpers = if (batches.len == 0) 0 else @min(desired -| 1, cap / per_helper);
                groups.resources.parallel_row_scratch_bytes = try std.math.mul(usize, helpers, per_helper);
                const scratch_points = try a.alloc(core.circle.CirclePointM31, scratch.rows);
                errdefer a.free(scratch_points);
                const scratch_denominators = try a.alloc(Inner, scratch.cells);
                errdefer a.free(scratch_denominators);
                const scratch_inverses = try a.alloc(Inner, scratch.cells);
                errdefer a.free(scratch_inverses);
                return .{ .groups = groups, .batches = batches, .constants = constants, .workspace = workspace, .scratch_plan = scratch, .scratch_points = scratch_points, .scratch_denominators = scratch_denominators, .scratch_inverses = scratch_inverses, .domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain(), .domain_size = size, .lifting_log_size = log, .parallel_shards = helpers + 1 };
            }
            pub fn resourcePlan(self: *const @This()) ResourcePlan {
                return self.groups.resources;
            }
            pub fn setBackendResidencyHandles(self: *@This(), handles: []const *anyopaque) void {
                self.backend_residency_handles = handles;
            }
            pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
                a.free(self.scratch_points);
                a.free(self.scratch_denominators);
                a.free(self.scratch_inverses);
                self.groups.deinit(a);
                self.workspace.deinit(a);
                self.constants.deinit(a);
                Q.ColumnSampleBatch.deinitSlice(a, self.batches);
                self.* = undefined;
            }
            pub fn computeChunk(self: *@This(), start: usize, len: usize, coordinates: *[DEGREE][]M) !void {
                const end = std.math.add(usize, start, len) catch return error.ShapeMismatch;
                if (end > self.domain_size) return error.ShapeMismatch;
                for (coordinates) |c| if (c.len < len) return error.ShapeMismatch;
                if (self.batches.len == 0) {
                    for (coordinates) |c| @memset(c[0..len], M.zero());
                    return;
                }
                if (len == 0) return;
                var walk = Walk.init(self.domain, self.lifting_log_size, start);
                var offset: usize = 0;
                while (offset < len) {
                    const count: usize = @min(self.scratch_plan.rows, len - offset);
                    const cells = count * self.batches.len; // checked capacity at init
                    for (self.scratch_points[0..count]) |*point| point.* = walk.next();
                    // The original core quadratic denominator law, with ONE
                    // bounded cross-row batch inverse. Zero-weight poles are
                    // never omitted and no challenge is redrawn on failure.
                    try self.workspace.prepareDenominatorInversesForRowsBatchMajor(self.scratch_points[0..count], self.scratch_denominators[0..cells], self.scratch_inverses[0..cells]);
                    for (0..count) |r| {
                        const position = start + offset + r;
                        const point = self.scratch_points[r];
                        self.workspace.resetNumerators();
                        for (self.workspace.denominator_inverses, 0..) |*inverse, batch| inverse.* = self.scratch_inverses[batch * count + r];
                        for (self.groups.groups) |group| self.workspace.batch_numerators[group.batch_index] = self.workspace.batch_numerators[group.batch_index].add(group.at(position));
                        const value = if (S == core.fields.om31.OM31)
                            try @import("wide_row_finalize.zig").finalize(&self.constants, point.y, self.workspace.batch_numerators, self.workspace.denominator_inverses)
                        else
                            try Q.finalizeRowQuotients(&self.constants, point.y, self.workspace.batch_numerators, self.workspace.denominator_inverses);
                        for (value.toM31Array(), 0..) |v, i| coordinates[i][offset + r] = v;
                    }
                    offset += count;
                }
            }
            pub fn computeAll(self: *@This(), a: std.mem.Allocator, out: *Column) !void {
                if (out.len() != self.domain_size) return error.ShapeMismatch;
                if (self.parallel_shards > 1) {
                    const helpers = try a.alloc(RowScratch, self.parallel_shards - 1);
                    defer a.free(helpers);
                    var initialized: usize = 0;
                    defer for (helpers[0..initialized]) |*helper| helper.deinit(a);
                    for (helpers) |*helper| {
                        helper.* = try RowScratch.init(a, self.batches, self.scratch_plan);
                        initialized += 1;
                    }
                    const Context = struct {
                        provider: *LazyQuotientProvider,
                        helpers: []RowScratch,
                        output: *Column,
                        errors: [RowWork.MAX_SHARDS]?anyerror = .{null} ** RowWork.MAX_SHARDS,
                        pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
                            // Only immutable groups/constants/batches are shared.
                            // Each ordinal owns all mutable row and inverse state.
                            var worker = ctx.provider.*;
                            if (ordinal != 0) {
                                const helper = &ctx.helpers[ordinal - 1];
                                worker.workspace = helper.workspace;
                                worker.scratch_points = helper.points;
                                worker.scratch_denominators = helper.denominators;
                                worker.scratch_inverses = helper.inverses;
                            }
                            var coordinates: [DEGREE][]M = undefined;
                            for (&coordinates, ctx.output.columns) |*coordinate, plane| coordinate.* = plane[first..end];
                            worker.computeChunk(first, end - first, &coordinates) catch |err| {
                                ctx.errors[ordinal] = err;
                            };
                        }
                    };
                    var context = Context{ .provider = self, .helpers = helpers, .output = out };
                    const jobs = RowWork.forEachRange(self.domain_size, &context, .{ .max_shards = self.parallel_shards });
                    for (context.errors[0..jobs]) |maybe_error| if (maybe_error) |err| return err;
                    return;
                }
                var start: usize = 0;
                while (start < self.domain_size) {
                    const len = @min(LAZY_QUOTIENT_CHUNK_SIZE, self.domain_size - start);
                    var coordinates: [DEGREE][]M = undefined;
                    for (&coordinates, out.columns) |*c, plane| c.* = plane[start..][0..len];
                    try self.computeChunk(start, len, &coordinates);
                    start += len;
                }
            }
        };
        pub fn computeFriQuotients(a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32, blowup: u32) !Column {
            _ = blowup;
            var provider = try LazyQuotientProvider.init(a, columns, points, values, alpha, log);
            defer provider.deinit(a);
            var out = try Column.uninitialized(a, provider.domain_size);
            errdefer out.deinit(a);
            try provider.computeAll(a, &out);
            return out;
        }
    };
}
