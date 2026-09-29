//! Source-derived LogUp descriptors for the current Cairo witness ABI.
const std = @import("std");
const frontend = @import("stwo_cairo_frontend");
const relations = frontend.witness.relation_bundle;

pub fn derive(allocator: std.mem.Allocator, proof: *const frontend.proof_plan.CairoProofPlan, programs: frontend.witness.bundle.Bundle, topology: frontend.witness.feed_topology.Loaded, implicit: relations.Bundle) !relations.Bundle {
    var entries: std.ArrayList(relations.Component) = .empty;
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
            for (entry.traces) |trace| allocator.free(trace.descriptors);
            allocator.free(entry.traces);
        }
        entries.deinit(allocator);
    }
    for (proof.components) |component| {
        const relation_name = if (std.mem.eql(u8, component.name, "memory_id_to_small")) "memory_id_to_big" else component.name;
        var found = false;
        for (entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, relation_name)) {
                found = true;
                break;
            }
        }
        if (found) continue; // Memory-value component instances share one descriptor family.
        const name = try allocator.dupe(u8, relation_name);
        errdefer allocator.free(name);
        if (topology.find(component.name)) |source| {
            const program = programs.find(component.name) orelse return error.MissingCanonicalWitness;
            var compiled = try frontend.witness.interaction_topology.compileProgram(allocator, source, program.program);
            errdefer compiled.deinit();
            const traces = try allocator.alloc(relations.Trace, 1);
            errdefer allocator.free(traces);
            traces[0] = .{ .part = .component, .layout = .lookup_words, .layout_arg = source.lookup_words_per_row, .output_columns = @intCast(compiled.columnCount()), .descriptors = compiled.descriptors };
            try entries.append(allocator, .{ .name = name, .lookup_words = source.lookup_words_per_row, .traces = traces });
        } else {
            // These implicit families are also used by the accepted CPU/Metal
            // transaction. All recorded-witness families use current IR above.
            if (!std.mem.eql(u8, component.name, "memory_address_to_id") and
                !std.mem.eql(u8, component.name, "memory_id_to_big") and
                !std.mem.eql(u8, component.name, "memory_id_to_small") and
                !std.mem.eql(u8, component.name, "verify_bitwise_xor_12"))
                return error.MissingCanonicalInteractionTopology;
            const entry = implicit.find(relation_name) orelse return error.MissingImplicitInteractionTopology;
            const traces = try allocator.alloc(relations.Trace, entry.traces.len);
            errdefer allocator.free(traces);
            var initialized: usize = 0;
            errdefer for (traces[0..initialized]) |trace| allocator.free(trace.descriptors);
            for (entry.traces) |trace| {
                traces[initialized] = trace;
                traces[initialized].descriptors = try allocator.dupe(u32, trace.descriptors);
                initialized += 1;
            }
            try entries.append(allocator, .{ .name = name, .lookup_words = entry.lookup_words, .traces = traces });
        }
    }
    return .{ .allocator = allocator, .graph_hash = std.mem.readInt(u64, topology.sha256[0..8], .little), .components = try entries.toOwnedSlice(allocator) };
}
