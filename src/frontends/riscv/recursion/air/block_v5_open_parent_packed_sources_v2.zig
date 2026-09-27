//! Constrained coordinate unpacking for nested public supply. Four private
//! base-field graph inputs are joined by QM31 packing AIR to one public tuple.
//! The independent public consume has opposite sign to that packed provider.
const std = @import("std");
const core = @import("stwo_core");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
pub const CIRCUIT: u32 = 4_200_004;
pub fn attach(payloads: *@import("blake3_execution_payloads.zig").Prepared, composition: *const @import("blake3_execution_composition.zig").Prepared, source: anytype) !void {
    return attachTerms(payloads, composition, source.terms);
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn attachTermsForParity(payloads: *@import("blake3_execution_payloads.zig").Prepared, composition: *const @import("blake3_execution_composition.zig").Prepared, terms: []const @import("../block_v5_open_child_frames_v2.zig").Term) !void {
        return attachTerms(payloads, composition, terms);
    }
} else struct {};
fn attachTerms(payloads: *@import("blake3_execution_payloads.zig").Prepared, composition: *const @import("blake3_execution_composition.zig").Prepared, terms: []const @import("../block_v5_open_child_frames_v2.zig").Term) !void {
    if (payloads.nested_columns != null) return error.InvalidV5NestedPackedSource;
    var scratch = std.heap.ArenaAllocator.init(payloads.arena.child_allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    const direct = payloads.columns != null;
    const scalar_count = try std.math.mul(usize, terms.len, 4);
    var columns: ?@import("blake3_execution_payloads.zig").NestedColumns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try @import("blake3_execution_payloads.zig").NestedColumns.init(payloads.arena.child_allocator, .{ scalar_count, terms.len });
    const nodes = try a.alloc([4]u32, terms.len);
    const seen = try a.alloc([4]bool, terms.len);
    @memset(seen, @splat(false));
    for (composition.sources, 0..) |kind, node| if (kind == .packed_public_input) {
        const index = kind.packed_public_input;
        if (index >= 4 * terms.len or seen[index / 4][index % 4]) return error.InvalidV5NestedPackedSource;
        seen[index / 4][index % 4] = true;
        nodes[index / 4][index % 4] = @intCast(node);
    };
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try a.alloc(u32, composition.circuit.nodes.len));
    const rows: []scalar.Row = if (direct) &.{} else try a.alloc(scalar.Row, scalar_count);
    const fixed: []scalar.Row = if (direct) &.{} else try a.alloc(scalar.Row, rows.len);
    const packs: []pack.Row = if (direct) &.{} else try a.alloc(pack.Row, terms.len);
    const fixed_packs: []pack.Row = if (direct) &.{} else try a.alloc(pack.Row, packs.len);
    for (terms, nodes, seen, 0..) |term, tuple, found, i| {
        for (found) |present| if (!present) return error.MissingV5NestedPackedSource;
        for (tuple, term.coordinates, 0..) |node, value, part| {
            if (!composition.inputs[node].eql(core.fields.qm31.QM31.fromBase(value))) return error.UntrustedV5NestedPackedSource;
            const weight = try std.math.add(u32, uses[node], 1);
            const row = try scalar.logicalRow(1500, node, weight, value);
            if (direct) try columns.?.append(12, row) else {
                rows[4 * i + part] = row;
                fixed[4 * i + part] = try scalar.logicalRow(1500, node, weight, core.fields.m31.M31.zero());
            }
        }
        const schedule = pack.Schedule{ .source_circuit = 1500, .source_nodes = tuple, .destination_circuit = CIRCUIT, .destination_wire = @intCast(i) };
        const row = try pack.logicalRow(schedule, core.fields.qm31.QM31.fromM31Array(term.coordinates));
        if (direct) try columns.?.append(11, row) else {
            packs[i] = row;
            fixed_packs[i] = try pack.fixedRow(schedule);
        }
    }
    if (columns) |*owned| {
        try owned.finish();
        payloads.nested_columns = columns;
    } else {
        // Publish all legacy outputs only after every allocation succeeds.
        const output = payloads.arena.allocator();
        const new_sources = try append(scalar.Row, output, payloads.claim_sources, rows);
        const new_fixed = try append(scalar.Row, output, payloads.fixed_claim_sources, fixed);
        const new_packs = try append(pack.Row, output, payloads.claim_packs, packs);
        const new_fixed_packs = try append(pack.Row, output, payloads.fixed_claim_packs, fixed_packs);
        payloads.claim_sources = new_sources;
        payloads.fixed_claim_sources = new_fixed;
        payloads.claim_packs = new_packs;
        payloads.fixed_claim_packs = new_fixed_packs;
    }
}
fn append(comptime T: type, a: std.mem.Allocator, previous: []T, extra: []const T) ![]T {
    const result = try a.alloc(T, try std.math.add(usize, previous.len, extra.len));
    @memcpy(result[0..previous.len], previous);
    @memcpy(result[previous.len..], extra);
    return result;
}
