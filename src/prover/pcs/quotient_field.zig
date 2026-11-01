//! Bounded secure-field quotient fallback. Formula authority is core PCS;
//! committed columns and domain geometry remain base-field representations.
const std = @import("std");
const core = @import("stwo_core");
const geometry = @import("quotient_column_geometry.zig");
const work_profile = @import("stwo_prover_api").work_profile;
const M = core.fields.m31.M31;
const TreeVec = core.pcs.TreeVec;
pub fn ForField(comptime S: type) type {
    return struct {
        const Q = core.pcs.ForField(S).quotients;
        const Point = core.circle.CirclePoint(S);
        const Column = @import("../secure_column.zig").SecureColumnByCoordsFor(S);
        const DEGREE = @typeInfo(@TypeOf(S.zero().toM31Array())).array.len;
        pub const ColumnEvaluation = geometry.ColumnEvaluation;
        pub const QuotientOpsError = geometry.QuotientOpsError;
        pub const LAZY_QUOTIENT_CHUNK_SIZE = 1024;
        pub const InputMode = enum { bounded_cpu, combined_compatibility, raw_backend };
        pub const LazyQuotientProvider = struct {
            columns: []ColumnEvaluation,
            batches: []Q.ColumnSampleBatch,
            constants: Q.QuotientConstants,
            workspace: Q.RowQuotientWorkspace,
            row: []M,
            domain: core.poly.circle.domain.CircleDomain,
            domain_size: usize,
            lifting_log_size: u32,
            backend_residency_handles: []const *anyopaque = &.{},
            pub fn init(a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32) !@This() {
                return initForBackendWithWorkRecorder(void, a, columns, points, values, alpha, log, null);
            }
            pub fn initForBackend(comptime B: type, a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32) !@This() {
                return initForBackendWithWorkRecorder(B, a, columns, points, values, alpha, log, null);
            }
            pub fn initForBackendWithWorkRecorder(comptime B: type, a: std.mem.Allocator, columns: TreeVec([]const ColumnEvaluation), points: TreeVec([][]Point), values: TreeVec([][]S), alpha: S, log: u32, recorder: ?*work_profile.Recorder(true)) !@This() {
                if (recorder != null) return error.UnsupportedWideQuotientWorkProfile;
                if (comptime B != void and @hasDecl(B, "rawQuotientInputs")) if (B.rawQuotientInputs) return error.UnsupportedWideRawQuotientBackend;
                if (columns.items.len != points.items.len or columns.items.len != values.items.len) return error.ShapeMismatch;
                for (columns.items, points.items, values.items) |cols, pts, vals| {
                    if (cols.len != pts.len or cols.len != vals.len) return error.ShapeMismatch;
                    for (cols, pts, vals) |column, ps, vs| {
                        if (ps.len != vs.len) return error.ShapeMismatch;
                        // Coefficient-backed representations require an explicit
                        // expansion lease; never reinterpret coefficients as rows.
                        if (column.coefficient_values != null) return error.UnsupportedWideCoefficientQuotient;
                        try column.validate();
                        if (ps.len != 0 and column.log_size > log) return error.InvalidColumnLogSize;
                    }
                }
                const size = try geometry.checkedPow2(log);
                var logs = try geometry.buildColumnLogSizes(a, columns);
                defer logs.deinitDeep(a);
                const flat = try geometry.flattenColumnsBorrowed(a, columns);
                errdefer a.free(flat);
                const batches = try Q.buildColumnSampleBatchesFromParallelInputs(a, points, values, logs, log, alpha);
                errdefer Q.ColumnSampleBatch.deinitSlice(a, batches);
                var constants = try Q.quotientConstants(a, batches);
                errdefer constants.deinit(a);
                var workspace = try Q.RowQuotientWorkspace.init(a, batches);
                errdefer workspace.deinit(a);
                const row = try a.alloc(M, flat.len);
                return .{ .columns = flat, .batches = batches, .constants = constants, .workspace = workspace, .row = row, .domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain(), .domain_size = size, .lifting_log_size = log };
            }
            pub fn setBackendResidencyHandles(self: *@This(), handles: []const *anyopaque) void {
                self.backend_residency_handles = handles;
            }
            pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
                a.free(self.row);
                self.workspace.deinit(a);
                self.constants.deinit(a);
                Q.ColumnSampleBatch.deinitSlice(a, self.batches);
                a.free(self.columns);
                self.* = undefined;
            }
            pub fn computeChunk(self: *@This(), start: usize, len: usize, coordinates: *[DEGREE][]M) !void {
                const end = std.math.add(usize, start, len) catch return error.ShapeMismatch;
                if (end > self.domain_size) return error.ShapeMismatch;
                for (coordinates) |c| if (c.len < len) return error.ShapeMismatch;
                for (start..end) |position| {
                    for (self.columns, 0..) |column, i| self.row[i] = try column.valueAtLiftingPosition(self.lifting_log_size, position);
                    const point = self.domain.at(core.utils.bitReverseIndex(position, self.lifting_log_size));
                    const value = try Q.accumulateRowQuotientsWithWorkspace(self.batches, self.row, &self.constants, point, &self.workspace);
                    for (value.toM31Array(), 0..) |v, i| coordinates[i][position - start] = v;
                }
            }
            pub fn computeAll(self: *@This(), a: std.mem.Allocator, out: *Column) !void {
                _ = a;
                if (out.len() != self.domain_size) return error.ShapeMismatch;
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
