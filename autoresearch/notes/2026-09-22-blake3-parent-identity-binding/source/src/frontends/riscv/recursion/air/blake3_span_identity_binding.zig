//! Parent identity input authority derived from the sealed BLAKE3 Span graph.
const std = @import("std");
const identity = @import("../span_identity_blake3.zig");
const graph = @import("../statement_semantics_circuit_blake3.zig");
const input = @import("blake3_span_identity_inputs.zig");
const row11 = @import("statement_semantics_input_witness_blake3.zig");
const parent_scope = @import("statement_input.zig").PARENT_STATEMENT_SCOPE;
const N = @typeInfo(identity.StatementWords).array.len;
pub const Plan = struct {
    inputs: input.Plan,
    statement_inputs: row11.Preprocessed,
    pub fn deinit(self: *Plan) void {
        self.statement_inputs.deinit();
        self.inputs.deinit();
        self.* = undefined;
    }
};

/// Replaces the base row-11 input schedule for this graph instance. Existing
/// graph fanout is preserved and packing consumers are added exactly once.
/// The parent scope is active in every proof kind; inactive child scopes cannot
/// accidentally be hashed through this entry point.
pub fn buildParent(a: std.mem.Allocator, circuit: *const graph.Circuit, purpose: identity.Purpose, ids: input.Circuits) !Plan {
    try circuit.validate();
    var nodes: [N]u32 = undefined;
    var slots: [N]usize = undefined;
    var seen: [N]bool = @splat(false);
    for (circuit.inputBindings(), 0..) |binding, slot| switch (binding.source) {
        .statement => |source| if (source.scope == parent_scope) {
            if (source.index >= N or seen[source.index] or !std.meta.eql(source.active_kinds, row11.ProofKindSet.ALL)) return error.InvalidIdentityParentBinding;
            nodes[source.index] = binding.node_id;
            slots[source.index] = slot;
            seen[source.index] = true;
        },
        else => {},
    };
    for (seen) |present| if (!present) return error.InvalidIdentityParentBinding;
    var prepared = try input.build(a, purpose, ids, &nodes);
    errdefer prepared.deinit();
    const bindings = try a.dupe(row11.InputBinding, circuit.inputBindings());
    defer a.free(bindings);
    for (slots, prepared.source_uses) |slot, extra| bindings[slot].use_count = try std.math.add(u32, bindings[slot].use_count, extra);
    return .{ .inputs = prepared, .statement_inputs = try row11.Preprocessed.init(a, ids.scalar, bindings) };
}
