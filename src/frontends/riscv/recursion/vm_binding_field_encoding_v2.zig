//! Versioned field preimage for graphs with authenticated native sparse roots.
//! Ordinary source tags retain V1 encodings; roots occupy a disjoint tag.
const graph = @import("air/composition_circuit.zig");
const legacy = @import("vm_binding_field_encoding_v1.zig");

pub fn encode(encoder: anytype, binding: graph.VmInputBinding) !void {
    switch (binding.source) {
        .native_continuation_root => |side| {
            try encoder.word(binding.node_id);
            try encoder.word(@as(u32, 8));
            try encoder.word(side);
            try encoder.word(@as(u32, 0));
        },
        .statement_word => return error.StatementRootsRequireNewFieldEncoding,
        else => try legacy.encode(encoder, binding),
    }
}
