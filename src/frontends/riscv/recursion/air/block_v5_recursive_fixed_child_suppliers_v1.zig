//! ORIGINAL ScopedChild.collect from independent fixed transcript/graph ports.
//! No private replay or Verified object is supplied. Admission of the concrete
//! public source recipe and term roster belongs to the independent family.
const std = @import("std");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
pub fn collect(a: std.mem.Allocator, transcript_fixed: anytype, composition: anytype, term_count: usize, child: u32, comptime PUBLIC_CIRCUIT: u32) ![]Bus.Wire {
    if (child >= 4) return error.InvalidRecursiveFixedChildCount;
    try composition.circuit.validate();
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    inline for (.{ transcript_fixed.root_reads, transcript_fixed.payload_reads }) |reads| {
        for (reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
            for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) {
                const offset = std.math.cast(u32, coordinate) orelse return error.InvalidV5NestedPublicSchedule;
                const wire = try std.math.add(u32, receipt.source.first_wire, offset);
                try wires.append(a, .{ .circuit = PUBLIC_CIRCUIT, .wire = wire, .uses = uses, .child = child, .kind = .child_cell, .coordinate = wire });
            };
        };
    }
    const counts = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), counts);
    if (composition.sources.len != composition.circuit.input_count) return error.InvalidV5NestedPublicSchedule;
    for (composition.sources, 0..) |source, node| {
        if (source == .packed_public_input and source.packed_public_input % 4 == 0) {
            const index = source.packed_public_input / 4;
            if (index >= term_count) return error.InvalidV5NestedPublicSchedule;
            try wires.append(a, .{ .circuit = @import("block_v5_open_parent_packed_sources_v2.zig").CIRCUIT, .wire = index, .uses = 1, .negative = true, .child = child, .kind = .child_term, .coordinate = index });
        } else if (source == .public_input and uses[node] != 0) {
            return error.UnexpectedScopedChildSpanInput;
        }
    }
    return wires.toOwnedSlice(a);
}
