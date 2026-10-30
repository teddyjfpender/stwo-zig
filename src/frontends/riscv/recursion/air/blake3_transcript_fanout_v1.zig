//! Constrained fan-out of already authenticated selected challenge coordinates.
//! One scalar-route row consumes each original scalar exactly once and emits
//! an alias with verifier-owned multiplicity. This is an OPEN relation gadget;
//! neither supplied values nor these rows alone authenticate a challenge.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("blake3_transcript_witness.zig");
pub const Air = @import("scalar_wire_source.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    rows: []Air.Row,
    outputs: []T.DrawOutput,
    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.rows);
        self.allocator.free(self.outputs);
        self.* = undefined;
    }
};
/// `uses` is per exported scalar, not per extension field. Each output's
/// destination retains its original role; child-specific remapping belongs to
/// the independently admitted consumer schedule.
pub fn prepare(a: std.mem.Allocator, alias_circuit: u32, sources: []const T.DrawOutput, uses: []const u32, values: []const core.fields.m31.M31) !Prepared {
    const p = core.fields.m31.Modulus;
    if (sources.len == 0 or sources.len > 4096 or alias_circuit >= p) return error.InvalidTranscriptFanout;
    var count: usize = 0;
    for (sources, 0..) |source, i| {
        if ((source.words != 4 and source.words != 8) or source.source.circuit >= p or source.source.circuit == alias_circuit or @as(u64, source.source.first_wire) + source.words > p) return error.InvalidTranscriptFanout;
        if (source.words != @as(usize, if (source.role == .universal) 8 else 4)) return error.InvalidTranscriptFanout;
        for (sources[0..i]) |prior| {
            if (overlappingRoles(source.role, prior.role) or
                (source.source.circuit == prior.source.circuit and source.source.first_wire < prior.source.first_wire + prior.words and prior.source.first_wire < source.source.first_wire + source.words)) return error.InvalidTranscriptFanout;
        }
        count = try std.math.add(usize, count, source.words);
    }
    if (count != uses.len or count != values.len or count >= p) return error.InvalidTranscriptFanout;
    for (uses, values) |multiplicity, value| if (multiplicity == 0 or multiplicity >= p or value.v >= p) return error.InvalidTranscriptFanout;
    const rows = try a.alloc(Air.Row, count);
    errdefer a.free(rows);
    const outputs = try a.dupe(T.DrawOutput, sources);
    errdefer a.free(outputs);
    var cursor: usize = 0;
    for (sources, outputs) |source, *output| {
        output.source = .{ .circuit = alias_circuit, .first_wire = @intCast(cursor) };
        for (0..source.words) |i| rows[cursor + i] = try Air.routedRow(alias_circuit, @intCast(cursor + i), uses[cursor + i], source.source.circuit, source.source.first_wire + @as(u32, @intCast(i)), values[cursor + i]);
        cursor += source.words;
    }
    return .{ .allocator = a, .rows = rows, .outputs = outputs };
}
fn overlappingRoles(left: T.OutputRole, right: T.OutputRole) bool {
    if (std.meta.eql(left, right)) return true;
    if (left == .universal and right == .universal_half) return left.universal == right.universal_half.relation;
    if (right == .universal and left == .universal_half) return right.universal == left.universal_half.relation;
    return false;
}
