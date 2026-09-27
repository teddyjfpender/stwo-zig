//! Parent identity input authority derived from the sealed BLAKE3 Span graph.
const std = @import("std");
const identity = @import("../span_identity_blake3.zig");
const graph = @import("../statement_semantics_circuit_blake3.zig");
const input = @import("blake3_span_identity_inputs.zig");
const hashing = @import("blake3_span_identity_hash.zig");
const row11 = @import("statement_semantics_input_witness_blake3.zig");
const parent_scope = @import("statement_input.zig").PARENT_STATEMENT_SCOPE;
const N = @typeInfo(identity.StatementWords).array.len;
pub const Prepared = struct {
    inputs: input.Rows,
    hash: hashing.Prepared,
    pub fn deinit(self: *Prepared) void {
        self.hash.deinit();
        self.* = undefined;
    }
};
pub const Plan = struct {
    purpose: identity.Purpose,
    circuits: input.Circuits,
    inputs: input.Plan,
    statement_inputs: row11.Preprocessed,
    /// The plan must be retained as verifier-owned authority after buildParent.
    pub fn prepare(self: *const Plan, a: std.mem.Allocator, words: *const identity.StatementWords, claim: identity.Digest) !Prepared {
        try self.statement_inputs.validate();
        const encoded = try input.prepare(&self.inputs, words);
        return .{ .inputs = encoded, .hash = try hashing.prepare(a, self.purpose, .{ .circuit = self.circuits.bytes, .first_wire = 0 }, self.circuits.hash, words, claim) };
    }
    /// The claim is public; statement values are absent from this constructor.
    pub fn trusted(self: *const Plan, a: std.mem.Allocator, claim: identity.Digest) !Prepared {
        try self.statement_inputs.validate();
        const fixed = try input.trusted(&self.inputs);
        return .{ .inputs = fixed, .hash = try hashing.trusted(a, self.purpose, .{ .circuit = self.circuits.bytes, .first_wire = 0 }, self.circuits.hash, claim) };
    }
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
    return .{ .purpose = purpose, .circuits = ids, .inputs = prepared, .statement_inputs = try row11.Preprocessed.init(a, ids.scalar, bindings) };
}
