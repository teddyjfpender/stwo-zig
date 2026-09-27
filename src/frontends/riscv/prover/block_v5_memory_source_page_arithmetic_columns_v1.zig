//! Independently reconstructable PAGE fixed recipe and actual arithmetic main
//! projection. Receiver fixed construction never evaluates private graph data.
//! Both modes use the original authenticated fusion walk; only segment cohorts
//! enter this PAGE's commitments. Main views borrow the live semantic owner.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Canonical = @import("block_v5_memory_source_page_canonical_component_v1.zig");
const Matrix = @import("block_v5_memory_source_packed_sha_columns_v1.zig").Matrix;
const Input = @import("block_v5_memory_source_page_input_component_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Fusion = @import("../recursion/air/arithmetic_fusion_rows.zig");
const ArithmeticFixed = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig");
const Projection = @import("../recursion/air/blake3_row_columns.zig");
pub const Limits = struct {
    inputs: Input.Limits = .{},
    max_arithmetic_rows: usize = 1 << 24,
    max_fixed_cells: usize = 1 << 28,
    max_main_cells: usize = 1 << 28,
};
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const C = Components.ForKind(kind);
        pub const Descriptor = if (kind == .raw) Raw.Descriptor else Eq.Descriptor;
        pub const Fixed = struct {
            a: std.mem.Allocator,
            plan: Lower.Plan,
            arithmetic: ArithmeticFixed.Fixed,
            source_inputs: C.SourceInput.Plan,
            capture_inputs: C.CaptureInput.Plan,
            canonical: Matrix,
            columns: []Column,
            pub fn deinit(self: *Fixed) void {
                self.a.free(self.columns); // aliases, never a second buffer owner.
                self.canonical.deinit();
                self.capture_inputs.deinit();
                self.source_inputs.deinit();
                self.arithmetic.deinit();
                self.plan.deinit();
                self.* = undefined;
            }
            pub fn init(a: std.mem.Allocator, graph: *const Semantic.Prepared, descriptors: []const Descriptor, source_log: u32, capture_log: u32, limits: Limits) !Fixed {
                if (graph.kind != kind or graph.circuit == null or source_log < 1 or source_log > 12 or capture_log < 1 or capture_log > 14 or
                    (kind == .raw and capture_log != source_log) or limits.max_arithmetic_rows == 0 or limits.max_fixed_cells == 0 or
                    descriptors.len > @as(usize, 1) << @intCast(source_log)) return error.InvalidSourcePageFixedGeometry;
                var lanes: [2]Lower.Lane = undefined;
                const reference = try graph.reference(&lanes);
                var plan = try Lower.Plan.init(a, reference);
                errdefer plan.deinit();
                const counts = plan.counts(.segment_leaf);
                const all = try std.math.add(usize, counts.multiply, try std.math.add(usize, counts.inverse, counts.linear));
                if (all > limits.max_arithmetic_rows) return error.SourcePageArithmeticResourceLimit;
                var arithmetic = try Fusion.materializeFixed(a, &plan, reference, .segment_leaf);
                errdefer arithmetic.deinit();
                var source = try C.SourceInput.Plan.init(a, graph, .source, source_log, limits.inputs);
                errdefer source.deinit();
                var capture = try C.CaptureInput.Plan.init(a, graph, .capture, capture_log, limits.inputs);
                errdefer capture.deinit();
                const canonical_cells = try std.math.mul(usize, Canonical.CANONICAL_FIXED_COUNT, @as(usize, 1) << @intCast(source_log));
                var cells = try std.math.add(usize, canonical_cells, try std.math.add(usize, source.cells.len, capture.cells.len));
                for (arithmetic.columns) |column| cells = try std.math.add(usize, cells, column.values.len);
                if (cells > limits.max_fixed_cells) return error.SourcePageArithmeticResourceLimit;
                var canonical = try Matrix.init(a, Canonical.CANONICAL_FIXED_COUNT, source_log);
                errdefer canonical.deinit();
                for (descriptors, 0..) |descriptor, i| {
                    const row = if (kind == .raw) Canonical.rawFixed(descriptor) else try Canonical.foldFixed(descriptor);
                    try canonical.put(i, &row);
                }
                const columns = try a.alloc(Column, C.ARITHMETIC_FIXED_OFFSET + C.ARITHMETIC_FIXED);
                errdefer a.free(columns);
                @memcpy(columns[0..Canonical.CANONICAL_FIXED_COUNT], canonical.columns);
                const source_offset = Canonical.CANONICAL_FIXED_COUNT;
                for (columns[source_offset..][0..C.SourceInput.FIXED_COUNT], 0..) |*column, i| column.* = .{ .log_size = source_log, .values = source.column(i) };
                const capture_offset = source_offset + C.SourceInput.FIXED_COUNT;
                for (columns[capture_offset..][0..C.CaptureInput.FIXED_COUNT], 0..) |*column, i| column.* = .{ .log_size = capture_log, .values = capture.column(i) };
                @memcpy(columns[C.ARITHMETIC_FIXED_OFFSET..], arithmetic.columns);
                return .{ .a = a, .plan = plan, .arithmetic = arithmetic, .source_inputs = source, .capture_inputs = capture, .canonical = canonical, .columns = columns };
            }
        };
        pub const Main = struct {
            a: std.mem.Allocator,
            /// Only this dot4 projection owns new buffers. The remaining
            /// descriptors borrow genuine direct main owners from Prepared.
            opening: std.ArrayList(Column),
            columns: []Column,
            pub fn deinit(self: *Main) void {
                self.a.free(self.columns);
                for (self.opening.items) |column| self.a.free(column.values);
                self.opening.deinit(self.a);
                self.* = undefined;
            }
            pub fn init(a: std.mem.Allocator, graph: *const Semantic.Prepared, fixed: *const Fixed, limits: Limits) !Main {
                if (graph.kind != kind or graph.columns == null or graph.lowering == null or limits.max_main_cells == 0) return error.SourcePageArithmeticNotMaterialized;
                var lanes: [2]Lower.Lane = undefined;
                const reference = try graph.reference(&lanes);
                try graph.lowering.?.validateAgainst(reference);
                try fixed.plan.validateAgainst(reference);
                const original = &graph.columns.?;
                if (original.opening.len != fixed.arithmetic.counts[0] or original.multiply.log != fixed.arithmetic.logs[1] or original.inverse.log != fixed.arithmetic.logs[2] or original.linear.log != fixed.arithmetic.logs[3])
                    return error.InvalidSourcePageArithmeticProjection;
                var cells: usize = 0;
                inline for (ArithmeticFixed.Airs, 0..) |Air, i| cells = try std.math.add(usize, cells, try std.math.mul(usize, Air.PHYSICAL_MAIN_COLUMN_COUNT, @as(usize, 1) << @intCast(fixed.arithmetic.logs[i])));
                if (cells > limits.max_main_cells) return error.SourcePageArithmeticResourceLimit;
                var opening: std.ArrayList(Column) = .empty;
                errdefer {
                    for (opening.items) |column| a.free(column.values);
                    opening.deinit(a);
                }
                try Projection.project(ArithmeticFixed.Airs[0], a, original.opening, fixed.arithmetic.logs[0], 1, &opening);
                const columns = try a.alloc(Column, C.ARITHMETIC_MAIN);
                var offset: usize = 0;
                for ([_][]const Column{ opening.items, original.multiply.main, original.inverse.main, original.linear.main }) |part| {
                    @memcpy(columns[offset..][0..part.len], part);
                    offset += part.len;
                }
                std.debug.assert(offset == columns.len);
                return .{ .a = a, .opening = opening, .columns = columns };
            }
        };
    };
}
