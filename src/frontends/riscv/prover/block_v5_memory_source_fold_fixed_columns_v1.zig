//! Fresh public FOLD fixed columns. No private operations, compression trace,
//! G/XOR witness, digest or input word is evaluated in this reconstruction.
//! The independently pinned descriptor inventory selects exact canonical
//! compression schedules; semantic equations separately prove recipe validity.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Premix = @import("block_v5_memory_source_fold_premix_v1.zig");
const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Project = @import("../recursion/air/blake3_row_columns.zig");
const Topology = @import("../recursion/air/blake3_compression_plan.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
pub fn geometry(page: Protocol.Page, first_circuit: u32, rows: []const Semantic.FoldRow, limits: Blake.Limits) !Blake.Geometry {
    if (rows.len != page.count or rows.len > limits.max_operations or first_circuit == 0 or limits.max_cells == 0 or limits.max_capture_metadata_bytes == 0)
        return error.InvalidSourceFoldFixedInventory;
    var compressions: u32 = 0;
    var frames: u32 = 0;
    for (rows) |row| {
        try row.descriptor.validate();
        if (row.first_compression != compressions) return error.InvalidSourceFoldFixedInventory;
        try Recipe.requireRecipes(row.descriptor.kind, row.descriptor.height, row.recipes, row.first_compression, row.compressions);
        compressions = try std.math.add(u32, compressions, row.compressions);
        frames = try std.math.add(u32, frames, @intCast(row.recipes.len));
    }
    if (compressions > limits.max_compressions or @as(u64, first_circuit) + compressions > core.fields.m31.Modulus)
        return error.SourcePackedBlakeResourceLimit;
    const counts = [2]usize{ try std.math.mul(usize, compressions, 56), try std.math.mul(usize, compressions, 16) };
    const logs = [2]u32{ try Direct.rowLog(counts[0]), try Direct.rowLog(counts[1]) };
    const capture_log = try Direct.rowLog(compressions);
    var cells = try std.math.mul(usize, @as(usize, 1) << @intCast(capture_log), Blake.CAPTURE_MAIN_COUNT + Blake.CAPTURE_FIXED_COUNT);
    inline for (Blake.Airs, 0..) |Air, i| {
        cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(logs[i]), Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT));
        cells = try std.math.add(usize, cells, try std.math.mul(usize, counts[i], Air.PREPROCESSED_COLUMN_COUNT));
    }
    for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |kind| cells = try std.math.add(usize, cells, Tables.size(kind));
    if (cells > limits.max_cells or try std.math.mul(usize, frames, @sizeOf(Blake.FrameCapture)) > limits.max_capture_metadata_bytes) return error.SourcePackedBlakeResourceLimit;
    return .{ .operations = page.count, .first_ordinal = page.first, .first_circuit = first_circuit, .compressions = compressions, .frames = frames, .logs = logs, .capture_log = capture_log, .cells = cells };
}
pub const Columns = struct {
    a: std.mem.Allocator,
    source: Blake.Matrix,
    core: std.ArrayList(Column),
    capture: Blake.Matrix,
    pub fn deinit(self: *Columns) void {
        self.capture.deinit();
        for (self.core.items) |column| self.a.free(column.values);
        self.core.deinit(self.a);
        self.source.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, expected: Protocol.FoldPin, rows: []const Semantic.FoldRow, limits: Blake.Limits) !Columns {
        if (expected.page.row_log < 1 or expected.page.row_log > 12 or expected.page.count > @as(u32, 1) << @intCast(expected.page.row_log) or
            @as(u64, expected.page.first) + expected.page.count > core.fields.m31.Modulus or
            !std.meta.eql(expected.geometry, try geometry(expected.page, expected.geometry.first_circuit, rows, limits)) or
            !std.meta.eql(expected.inventory_id, try Premix.inventoryId(expected.page, expected.geometry.first_circuit, rows))) return error.InvalidSourceFoldFixedInventory;
        var source = try Blake.Matrix.init(a, Premix.SOURCE_FIXED_COUNT, expected.page.row_log);
        errdefer source.deinit();
        var capture = try Blake.Matrix.init(a, Blake.CAPTURE_FIXED_COUNT, expected.geometry.capture_log);
        errdefer capture.deinit();
        for (rows, 0..) |row, ordinal| {
            const value = [_]M{ M.one(), M.fromCanonical(@intFromEnum(row.descriptor.kind)), M.fromCanonical(row.descriptor.height), M.fromCanonical(@intCast(expected.page.first + ordinal)) };
            try source.put(ordinal, &value);
            for (row.recipes) |recipe| for (0..recipe.compression_count) |block| {
                const local = recipe.first_compression + @as(u32, @intCast(block));
                const fixed = [_]M{ M.one(), M.fromCanonical(expected.geometry.first_circuit + local), M.fromCanonical(@intCast(ordinal)), M.fromCanonical(recipe.slot), M.fromCanonical(@intCast(block)), M.fromCanonical(recipe.multiplicity) };
                try capture.put(local, &fixed);
            };
        }
        var columns: std.ArrayList(Column) = .empty;
        errdefer {
            for (columns.items) |column| a.free(column.values);
            columns.deinit(a);
        }
        const topology = Topology.canonical();
        inline for (Blake.Airs, .{ 56, 16 }, 0..) |Air, count, i| {
            const metadata = try a.alloc(Storage.FixedRow(Air), try std.math.mul(usize, expected.geometry.compressions, count));
            defer a.free(metadata);
            for (0..expected.geometry.compressions) |compression| {
                const circuit = expected.geometry.first_circuit + @as(u32, @intCast(compression));
                for (0..count) |slot| {
                    const row = if (i == 0) blk: {
                        const call = topology.g[slot];
                        var uses: [4]u32 = undefined;
                        for (&uses, call.output) |*use, id| use.* = topology.uses[id];
                        break :blk try Air.fixedRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = uses });
                    } else blk: {
                        const call = topology.xor[slot];
                        break :blk try Air.fixedRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = topology.uses[call.output] });
                    };
                    metadata[compression * count + slot] = Storage.compactFixed(Air, row);
                }
            }
            try Project.projectFixed(Air, a, metadata, expected.geometry.logs[i], &columns);
        }
        for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |kind| try Project.tablePreprocessed(a, kind, &columns);
        return .{ .a = a, .source = source, .core = columns, .capture = capture };
    }
};
