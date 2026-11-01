//! Per-proof numerator groups. Source coefficients stay compact: only weighted
//! aggregate polynomials are evaluated, using the shared pooled M31 executor.
const std = @import("std");
const core = @import("stwo_core");
const Geometry = @import("../quotient_column_geometry.zig");
const M = core.fields.m31.M31;
pub fn ForField(comptime S: type) type {
    return struct {
        const DEGREE = @typeInfo(@TypeOf(S.zero().toM31Array())).array.len;
        const Q = core.pcs.ForField(S).quotients;
        pub const Group = struct {
            coordinates: [DEGREE][]M,
            batch_index: usize,
            shift_amt: std.math.Log2Int(usize),
            is_direct: bool,
            pub fn deinitCoordinates(self: @This(), a: std.mem.Allocator) void {
                for (self.coordinates) |plane| a.free(plane);
            }
            pub fn at(self: @This(), position: usize) S {
                const row = if (self.is_direct) position else ((position >> self.shift_amt) << 1) + (position & 1);
                var coordinates: [DEGREE]M = undefined;
                for (&coordinates, self.coordinates) |*v, plane| v.* = plane[row];
                return S.fromM31Array(coordinates);
            }
        };
        const Setup = @import("combined_setup.zig").ForCoordinates(DEGREE, Group);
        const Spec = struct { batch: usize, log: u32, coefficients: bool };
        /// Dominant materialized buffers, all checked before their first allocation.
        /// Metadata and small row workspace remain charged to the same allocator.
        pub const ResourcePlan = struct {
            group_count: usize = 0,
            aggregate_evaluation_bytes: usize = 0,
            twiddle_upper_bound_bytes: usize = 0,
            source_lde_reconstruction_bytes: usize = 0,
            pub fn largeBufferUpperBound(self: @This()) !usize {
                return std.math.add(usize, self.aggregate_evaluation_bytes, self.twiddle_upper_bound_bytes);
            }
        };
        pub const Plan = struct {
            groups: []Group,
            resources: ResourcePlan,
            pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
                for (self.groups) |g| g.deinitCoordinates(a);
                a.free(self.groups);
                self.* = undefined;
            }
            pub fn init(a: std.mem.Allocator, columns: []const Geometry.ColumnEvaluation, batches: []const Q.ColumnSampleBatch, constants: *const Q.QuotientConstants, lifting_log: u32, byte_limit: ?usize) !@This() {
                if (batches.len != constants.line_coeffs.len) return error.ShapeMismatch;
                var specs: std.ArrayList(Spec) = .empty;
                defer specs.deinit(a);
                var members: std.ArrayList(Setup.Member) = .empty;
                defer members.deinit(a);
                const nonzero_columns = try a.alloc(?bool, columns.len);
                defer a.free(nonzero_columns);
                @memset(nonzero_columns, null);
                var resources = ResourcePlan{};
                var twiddle_logs = [_]bool{false} ** @bitSizeOf(usize);
                for (batches, 0..) |batch, bi| {
                    if (batch.cols_vals_randpows.len != constants.line_coeffs[bi].len) return error.ShapeMismatch;
                    for (batch.cols_vals_randpows, constants.line_coeffs[bi]) |term, line| {
                        if (term.column_index >= columns.len) return error.ShapeMismatch;
                        const column = columns[term.column_index];
                        try column.validateRetained();
                        if (column.log_size > lifting_log) return error.InvalidColumnLogSize;
                        const source = column.coefficient_values orelse column.values;
                        const nonzero = nonzero_columns[term.column_index] orelse blk: {
                            var found = false;
                            for (source) |v| if (v.v != 0) {
                                found = true;
                                break;
                            };
                            nonzero_columns[term.column_index] = found;
                            break :blk found;
                        };
                        if (!nonzero) continue;
                        const basis = column.coefficient_values != null;
                        var found: ?usize = null;
                        for (specs.items, 0..) |spec, i| if (spec.batch == bi and spec.log == column.log_size and spec.coefficients == basis) {
                            found = i;
                            break;
                        };
                        const group = found orelse blk: {
                            const size = try Geometry.checkedPow2(column.log_size);
                            const bytes = try std.math.mul(usize, try std.math.mul(usize, size, DEGREE), @sizeOf(M));
                            resources.aggregate_evaluation_bytes = try std.math.add(usize, resources.aggregate_evaluation_bytes, bytes);
                            if (basis and !twiddle_logs[column.log_size]) {
                                resources.twiddle_upper_bound_bytes = try std.math.add(usize, resources.twiddle_upper_bound_bytes, try std.math.mul(usize, size, @sizeOf(M)));
                                twiddle_logs[column.log_size] = true;
                            }
                            if (byte_limit) |limit| if (try resources.largeBufferUpperBound() > limit) return error.QuotientScratchBudgetExceeded;
                            try specs.append(a, .{ .batch = bi, .log = column.log_size, .coefficients = basis });
                            break :blk specs.items.len - 1;
                        };
                        try members.append(a, .{ .source = source, .coefficients = line.c.toM31Array(), .view_index = group });
                    }
                }
                resources.group_count = specs.items.len;
                const groups = try a.alloc(Group, specs.items.len);
                errdefer a.free(groups);
                const coefficient_basis = try a.alloc(bool, specs.items.len);
                defer a.free(coefficient_basis);
                var initialized: usize = 0;
                errdefer for (groups[0..initialized]) |g| g.deinitCoordinates(a);
                for (specs.items, 0..) |spec, i| {
                    const size = try Geometry.checkedPow2(spec.log);
                    var coordinates: [DEGREE][]M = undefined;
                    var n: usize = 0;
                    errdefer for (coordinates[0..n]) |plane| a.free(plane);
                    for (&coordinates) |*plane| {
                        plane.* = try a.alloc(M, size);
                        n += 1;
                    }
                    groups[i] = .{ .coordinates = coordinates, .batch_index = spec.batch, .shift_amt = @intCast(lifting_log - spec.log + 1), .is_direct = spec.log == lifting_log };
                    coefficient_basis[i] = spec.coefficients;
                    initialized += 1;
                }
                try Setup.combine(a, groups, members.items);
                try Setup.evaluateCoefficientViews(a, groups, coefficient_basis);
                return .{ .groups = groups, .resources = resources };
            }
        };
    };
}
