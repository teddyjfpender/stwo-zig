//! One DEEP scalar source per sample coordinate feeds both DEEP arithmetic and
//! secure composition inputs. The parent must bind these sources to the
//! transcript encoding; these rows alone do not authenticate sampled values.
//! encoding_uses adds explicit secure consumers such as field-byte encoding.
const std = @import("std");
const core = @import("stwo_core");
const composition_mod = @import("blake3_execution_composition.zig");
const deep_mod = @import("blake3_native_deep.zig");
const sample_links = @import("blake3_sample_links.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const pack = @import("qm31_pack_wire.zig");
const scalar = @import("scalar_wire_source.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const Borrowed = @import("blake3_recursive_column_rows_v1.zig");
pub const Columns = struct {
    sources: Direct.ForAir(scalar),
    packs: Direct.ForAir(pack),
    pub fn deinit(self: *Columns) void {
        self.sources.deinit();
        self.packs.deinit();
        self.* = undefined;
    }
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    packs: []pack.Row,
    fixed_packs: []pack.Row,
    /// Replace the DEEP sample-input producer rows, not additional producers.
    sources: []scalar.Row,
    fixed_sources: []scalar.Row,
    columns: ?Columns = null,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn appendInputs(self: *const Prepared, b: anytype) !void {
        if (self.columns) |columns| {
            if (self.sources.len != 0 or self.fixed_sources.len != 0 or self.packs.len != 0 or self.fixed_packs.len != 0)
                return error.InvalidExecutionSampleLink;
            try columns.sources.requireFinished();
            try columns.packs.requireFinished();
            try b.appendBorrowed(12, try Borrowed.ForAir(scalar).init(columns.sources.main, columns.sources.fixed));
            try b.appendBorrowed(11, try Borrowed.ForAir(pack).init(columns.packs.main, columns.packs.fixed));
        } else {
            try b.append(12, self.sources, self.fixed_sources);
            try b.append(11, self.packs, self.fixed_packs);
        }
    }
};
/// Explicit legacy row oracle. Canonical parent preparation uses prepareColumns.
pub fn prepare(a: std.mem.Allocator, composition: *const composition_mod.Prepared, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, encoding_uses: u32) !Prepared {
    return prepareMode(false, a, composition, deep, composition_circuit, deep_circuit, encoding_uses);
}
pub fn prepareColumns(a: std.mem.Allocator, composition: *const composition_mod.Prepared, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, encoding_uses: u32) !Prepared {
    return prepareMode(true, a, composition, deep, composition_circuit, deep_circuit, encoding_uses);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, composition: *const composition_mod.Prepared, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, encoding_uses: u32) !Prepared {
    try composition.circuit.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    if (composition.sources.len != composition.circuit.input_count or composition.inputs.len != composition.sources.len) return error.InvalidExecutionSampleLink;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator(); // Legacy output rows only, never scratch.
    const count = try deep.graph.profile().sampleCount();
    const scalar_count = try std.math.mul(usize, count, 4);
    if (direct and scalar_count > 1 << 24) return error.InvalidTraceShape;
    const mapped = try sample_links.build(a, &deep.graph, count, 0);
    defer a.free(mapped);
    const composition_scratch = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(composition_scratch);
    const deep_scratch = try a.alloc(u32, deep.graph.nodes.len);
    defer a.free(deep_scratch);
    const composition_uses = try lower.computeUseCountsInto(composition.circuit.graph(), composition_scratch);
    const deep_uses = try lower.computeUseCountsInto(deep.graph.graph(), deep_scratch);
    const nodes = try a.alloc(u32, count);
    defer a.free(nodes);
    const missing = std.math.maxInt(u32);
    @memset(nodes, missing);
    var pack_count: usize = 0;
    for (composition.sources, 0..) |source, node| switch (source) {
        .sample => |sample| {
            if (sample >= count or nodes[sample] != missing) return error.InvalidExecutionSampleLink;
            nodes[sample] = @intCast(node);
            if (try std.math.add(u32, composition_uses[node], encoding_uses) != 0) pack_count += 1;
        },
        else => {},
    };
    for (nodes) |node| if (node == missing) return error.InvalidExecutionSampleLink;
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) {
        var sources_columns = try Direct.ForAir(scalar).init(a, scalar_count);
        errdefer sources_columns.deinit();
        var packs_columns = try Direct.ForAir(pack).init(a, pack_count);
        errdefer packs_columns.deinit();
        // Publish only completed owners. A fallible aggregate assignment can
        // write the optional destination before its last field initializes;
        // outer cleanup must never see that partial ownership state.
        columns = .{ .sources = sources_columns, .packs = packs_columns };
    }
    const sources: []scalar.Row = if (direct) &.{} else try temp.alloc(scalar.Row, scalar_count);
    const fixed_sources: []scalar.Row = if (direct) &.{} else try temp.alloc(scalar.Row, scalar_count);
    const packs: []pack.Row = if (direct) &.{} else try temp.alloc(pack.Row, pack_count);
    const fixed_packs: []pack.Row = if (direct) &.{} else try temp.alloc(pack.Row, pack_count);
    // Scalars retain sample-coordinate order even when composition nodes are
    // enumerated in a different order. Only one transient row is ever formed.
    for (nodes, mapped, 0..) |node, link, sample| {
        const value = composition.inputs[node];
        const weight = try std.math.add(u32, composition_uses[node], encoding_uses);
        for (link.deep, value.toM31Array(), 0..) |deep_node, coordinate, word| {
            if (!deep.evaluation.values[deep_node].eql(Q.fromBase(coordinate))) return error.InvalidExecutionSampleLink;
            const uses = try std.math.add(u32, deep_uses[deep_node], weight);
            const row = try scalar.logicalRow(deep_circuit, deep_node, uses, coordinate);
            if (direct) try columns.?.sources.append(row) else {
                sources[sample * 4 + word] = row;
                fixed_sources[sample * 4 + word] = try scalar.logicalRow(deep_circuit, deep_node, uses, M.zero());
            }
        }
    }
    var next_pack: usize = 0;
    // Pack schedule/order exactly matches the legacy composition-node walk.
    for (composition.sources, 0..) |source, node| switch (source) {
        .sample => |sample| {
            const weight = try std.math.add(u32, composition_uses[node], encoding_uses);
            // Unused composition samples still feed DEEP, but need no pack row.
            if (weight != 0) {
                const schedule = pack.Schedule{ .source_circuit = deep_circuit, .source_nodes = mapped[sample].deep, .destination_circuit = composition_circuit, .destination_wire = @intCast(node) };
                const row = try pack.weightedLogicalRow(schedule, composition.inputs[node], weight);
                if (direct) try columns.?.packs.append(row) else {
                    packs[next_pack] = row;
                    fixed_packs[next_pack] = try pack.weightedFixedRow(schedule, weight);
                }
                next_pack += 1;
            }
        },
        else => {},
    };
    if (next_pack != pack_count) return error.InvalidExecutionSampleLink;
    if (columns) |*owned| {
        try owned.sources.requireFinished();
        try owned.packs.requireFinished();
    }
    return .{ .arena = arena, .packs = packs, .fixed_packs = fixed_packs, .sources = sources, .fixed_sources = fixed_sources, .columns = columns };
}
