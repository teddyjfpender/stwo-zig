//! Original hash/table/capture and arithmetic interactions, exactly once in
//! the combined PAGE tree8. All original views remain borrowed and immutable;
//! final interaction columns have uniform independent ownership on failure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Arithmetic = @import("block_v5_memory_source_page_arithmetic_columns_v1.zig");
const ArithmeticFixed = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig");
const RowColumns = @import("../recursion/air/blake3_row_columns.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Providers = @import("../recursion/air/universal_provider_relations.zig");
const TableInteraction = @import("../air/lookups/tables/interaction.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
const ShaAir = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const ShaInteraction = @import("block_v5_memory_source_sha_connector_interaction_v1.zig");
const BlakeAir = @import("block_v5_memory_source_blake_capture_air_v1.zig");
const BlakeInteraction = @import("block_v5_memory_source_blake_capture_interaction_v1.zig");
pub const Limits = struct { max_cells: usize = 1 << 28, input: @import("block_v5_memory_source_page_input_component_v1.zig").Limits = .{} };
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const C = Components.ForKind(kind);
        const A = Arithmetic.ForKind(kind);
        pub const Premix = struct {
            cores: *const C.CoreColumns.Columns,
            source_main: []const Column,
            capture_fixed: []const Column,
            capture_main: []const Column,
            source_log: u32,
            capture_log: u32,
            logical_source_rows: u32,
            compressions: u32,
            first_circuit: u32,
        };
        pub const Generated = struct {
            a: std.mem.Allocator,
            columns: []Column,
            claims: C.Claims,
            pub fn deinit(self: *Generated) void {
                for (self.columns) |column| self.a.free(column.values);
                self.a.free(self.columns);
                self.* = undefined;
            }
        };
        pub fn generate(a: std.mem.Allocator, premix: Premix, fixed: *const A.Fixed, main: *const A.Main, relations: *const Universal.UniversalRelations, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Generated {
            if (limits.max_cells == 0 or premix.source_log != fixed.source_inputs.row_log or premix.capture_log != fixed.capture_inputs.row_log or
                premix.source_main.len != C.SOURCE_MAIN or premix.capture_fixed.len != C.CAPTURE_FIXED or premix.capture_main.len != C.CAPTURE_MAIN or
                premix.source_log < 1 or premix.source_log > 12 or premix.capture_log < 1 or premix.capture_log > 14 or
                premix.logical_source_rows > @as(u32, 1) << @intCast(premix.source_log) or main.columns.len != C.ARITHMETIC_MAIN)
                return error.InvalidSourcePageInteractionGeometry;
            const source_rows = @as(usize, 1) << @intCast(premix.source_log);
            const capture_rows = @as(usize, 1) << @intCast(premix.capture_log);
            for (premix.source_main) |column| if (column.log_size != premix.source_log or column.values.len != source_rows) return error.InvalidSourcePageInteractionGeometry;
            for (premix.capture_fixed) |column| if (column.log_size != premix.capture_log or column.values.len != capture_rows) return error.InvalidSourcePageInteractionGeometry;
            for (premix.capture_main) |column| if (column.log_size != premix.capture_log or column.values.len != capture_rows) return error.InvalidSourcePageInteractionGeometry;
            var cells = try std.math.add(usize, try std.math.mul(usize, source_rows, C.SourceInput.INTERACTION_COUNT), try std.math.mul(usize, capture_rows, C.CaptureInput.INTERACTION_COUNT + C.CAPTURE_INTERACTION));
            inline for (C.CoreAirs, 0..) |Air, i| cells = try std.math.add(usize, cells, try std.math.mul(usize, premix.cores.owners[i].main[0].values.len, Air.INTERACTION_COLUMN_COUNT));
            for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |table_kind| cells = try std.math.add(usize, cells, try std.math.mul(usize, Tables.size(table_kind), TableInteraction.N_COLUMNS));
            inline for (ArithmeticFixed.Airs, 0..) |Air, i| cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(fixed.arithmetic.logs[i]), Air.INTERACTION_COLUMN_COUNT));
            if (cells > limits.max_cells) return error.SourcePageInteractionResourceLimit;
            try relations.validate();
            var arithmetic_lease = try arithmetic_setup.lease();
            defer arithmetic_lease.deinit();
            const providers = try Providers.SharedProviderRelations.init(relations);
            var output: std.ArrayList(Column) = .empty;
            errdefer {
                for (output.items) |column| a.free(column.values);
                output.deinit(a);
            }
            var claims: C.Claims = undefined;
            inline for (C.CoreAirs, 0..) |Air, i| {
                const owned = &premix.cores.owners[i];
                const metadata: []const M = @alignCast(std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(owned.fixed)));
                const view = try RowColumns.compactColumnView(Air, owned.main, metadata, owned.fixed.len, owned.log);
                var generated = try Framework.Runtime(Binding.Binding(Air).Runtime).generatePreparedFromColumns(a, &premix.cores.plans[i], view, owned.log, relations, @splat(M.zero()));
                defer generated.deinit(a);
                claims.core[i] = generated.claimed_sum;
                for (generated.columns) |values| try appendCopy(a, &output, values, owned.log);
            }
            for (&premix.cores.counters, C.CoreAirs.len..) |*counter, i| {
                var generated = try TableInteraction.generate(a, counter, &providers.native);
                defer generated.deinit(a);
                claims.core[i] = generated.claim;
                for (&generated.columns) |*values| {
                    try output.append(a, .{ .log_size = Tables.logSize(counter.kind), .values = values.* });
                    values.* = &.{};
                }
            }
            const wire = relations.get(.recursion_wire);
            var source_view: [C.SOURCE_MAIN][]const M = undefined;
            var capture_view: [C.CAPTURE_MAIN][]const M = undefined;
            var capture_fixed: [C.CAPTURE_FIXED][]const M = undefined;
            for (&source_view, premix.source_main) |*view, column| view.* = column.values;
            for (&capture_view, premix.capture_main) |*view, column| view.* = column.values;
            for (&capture_fixed, premix.capture_fixed) |*view, column| view.* = column.values;
            if (kind == .raw) {
                var generated = try ShaInteraction.generate(a, .{ .fixed = &capture_fixed, .original = &source_view, .captures = &capture_view, .row_log = premix.source_log, .logical_rows = premix.logical_source_rows }, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, try std.math.mul(u64, premix.compressions, 32), limits.max_cells);
                defer generated.deinit();
                claims.capture = generated.claim;
                for (0..ShaAir.INTERACTION_COUNT) |i| try appendCopy(a, &output, generated.cells[i * source_rows ..][0..source_rows], premix.source_log);
            } else {
                var generated = try BlakeInteraction.generate(a, .{ .fixed = &capture_fixed, .main = &capture_view, .row_log = premix.capture_log, .compressions = premix.compressions, .first_circuit = premix.first_circuit }, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, try std.math.mul(u64, premix.compressions, BlakeAir.requestMass()), limits.max_cells);
                defer generated.deinit();
                claims.capture = generated.claim;
                for (0..BlakeAir.INTERACTION_COUNT) |i| try appendCopy(a, &output, generated.cells[i * capture_rows ..][0..capture_rows], premix.capture_log);
            }
            var source_generated = try C.SourceInput.generate(a, &fixed.source_inputs, source_view[0..C.SourceInput.MAIN_COUNT], .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, limits.input);
            defer source_generated.deinit();
            claims.source_inputs = source_generated.claim;
            for (0..C.SourceInput.INTERACTION_COUNT) |i| try appendCopy(a, &output, source_generated.cells[i * source_rows ..][0..source_rows], premix.source_log);
            var capture_generated = try C.CaptureInput.generate(a, &fixed.capture_inputs, &capture_view, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, limits.input);
            defer capture_generated.deinit();
            claims.capture_inputs = capture_generated.claim;
            for (0..C.CaptureInput.INTERACTION_COUNT) |i| try appendCopy(a, &output, capture_generated.cells[i * capture_rows ..][0..capture_rows], premix.capture_log);
            var offset: usize = 0;
            inline for (ArithmeticFixed.Airs, 0..) |Air, i| {
                const metadata: []const M = @alignCast(std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(fixed.arithmetic.fixed[i])));
                const columns = main.columns[offset..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT];
                const view = try RowColumns.compactColumnView(Air, columns, metadata, fixed.arithmetic.counts[i], fixed.arithmetic.logs[i]);
                var padding: Air.Row = @splat(M.zero());
                inline for (Components.ARITHMETIC_PARAMETERS[i], 0..) |parameter, parameter_index| {
                    padding[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT + parameter_index] = parameter;
                }
                var generated = try Framework.Runtime(Binding.Binding(Air).Runtime).generatePreparedFromColumns(a, &arithmetic_setup.plans[i], view, fixed.arithmetic.logs[i], relations, padding);
                defer generated.deinit(a);
                claims.arithmetic[i] = generated.claimed_sum;
                for (generated.columns) |values| try appendCopy(a, &output, values, fixed.arithmetic.logs[i]);
                offset += Air.PHYSICAL_MAIN_COLUMN_COUNT;
            }
            return .{ .a = a, .columns = try output.toOwnedSlice(a), .claims = claims };
        }
    };
}
fn appendCopy(a: std.mem.Allocator, output: *std.ArrayList(Column), values: []const M, log: u32) !void {
    const owned = try a.dupe(M, values);
    output.append(a, .{ .log_size = log, .values = owned }) catch |failure| {
        a.free(owned);
        return failure;
    };
}
