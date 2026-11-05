//! Exact classic OM31 outer trace geometry without dense PP/witness creation.
//! This is a circuit-construction census, not an outer proof or a timing model.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const PP = circuit.common.preprocessed;
const List = circuit.common.component_list;
pub const Entry = struct { name: []const u8, log: u32, rows: u64, main_columns: usize, inter_columns: usize, main_cells: u64, inter_cells: u64 };
pub const Census = struct {
    n_vars: u32,
    raw_rows: circuit.common.finalize.ComponentSizes,
    padded_rows: circuit.common.finalize.ComponentSizes,
    fixed_cells: u64,
    main_cells: u64,
    inter_cells: u64,
    total_cells: u64,
    components: [List.N_COMPONENTS]Entry,
};
pub fn measure(ctx: *const C.Context) !Census {
    const view = PP.CircuitView.fromBuilder(&ctx.circuit);
    const padded = circuit.common.finalize.computePaddedSizes(view);
    const layout = try PP.ColumnLayout.fromComponentSizes(padded);
    const logs = (try List.circuitComponentLogSizes(&layout)).toArray();
    var out = Census{ .n_vars = ctx.circuit.n_vars, .raw_rows = circuit.common.finalize.rawComponentSizes(view), .padded_rows = padded, .fixed_cells = 0, .main_cells = 0, .inter_cells = 0, .total_cells = 0, .components = undefined };
    for (layout.entries) |column| out.fixed_cells += @as(u64, 1) << @intCast(column.log_size);
    for (&out.components, List.component_facts.toArray(), List.COMPONENT_NAMES, logs) |*entry, fact, name, log| {
        const rows = @as(u64, 1) << @intCast(log);
        // The shared component facts count QM31 (4-coordinate) interaction
        // columns. The classic OM31 outer uses the same pairs in 8 coordinates.
        const inter = 2 * fact.interaction_columns;
        entry.* = .{ .name = name, .log = log, .rows = rows, .main_columns = fact.trace_columns, .inter_columns = inter, .main_cells = rows * fact.trace_columns, .inter_cells = rows * inter };
        out.main_cells += entry.main_cells;
        out.inter_cells += entry.inter_cells;
    }
    out.total_cells = out.fixed_cells + out.main_cells + out.inter_cells;
    return out;
}
pub fn report(a: std.mem.Allocator, ctx: *const C.Context, label: []const u8) !Census {
    const census = try measure(ctx);
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-native-recursive-circuit-geometry/v1", .label = label, .status = "exact constructed classic OM31 outer geometry; no outer proof", .census = census }, .{});
    defer a.free(json);
    std.debug.print("D2_RECURSIVE_CENSUS {s}\n", .{json});
    return census;
}
