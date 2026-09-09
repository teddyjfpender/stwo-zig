//! Canonical detached-parent typed AIR roster. Production, verification and
//! backend catalog export consume this exact versioned override sequence.
const air = @import("mod.zig");

pub const LOGICAL_ROWS = rows: {
    var result: [29]air.universal_catalog.Entry = undefined;
    var count: usize = 0;
    for (air.universal_catalog.LOGICAL_ROWS, 0..) |entry, index| {
        if (index >= 15 and index < 20) continue;
        result[count] = .{
            .Air = switch (index) {
                10 => air.field_statement_word_v3,
                11 => air.detached_graph_input_v1,
                12 => air.detached_poseidon_graph_v1,
                13 => air.fixed_wire_v3,
                // This VM-only slot is unused by legacy detached parents.
                // The versioned semantic digest admits its detached meaning.
                14 => air.detached_opening_accumulate4_v1,
                30 => air.qm31_mul_add_v1,
                else => entry.Air,
            },
            .row = entry.row,
            .requires_location = entry.requires_location and index != 30,
        };
        count += 1;
    }
    if (count != result.len) @compileError("detached parent active catalog drift");
    break :rows result;
};
