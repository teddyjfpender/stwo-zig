//! Full-width execution sources for the shared parent row assembler.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Graph = @import("composition_circuit.zig").CircuitGraph;
pub const Sources = struct {
    pub const execution = true;
    composition: *const @import("blake3_execution_composition.zig").Prepared,
    transcript: *const @import("blake3_native_transcript.zig").Prepared,
    deep: *const @import("blake3_native_deep.zig").Prepared,
    fri: *const @import("blake3_native_fri.zig").Prepared,
    payloads: *const @import("blake3_execution_payloads.zig").Prepared,
    challenges: *const @import("blake3_execution_challenges.zig").Prepared,
    terminal: *const @import("blake3_native_terminal_encoding.zig").Prepared,
    queries: *const @import("blake3_native_queries.zig").Prepared,
    openings: *const @import("blake3_native_openings.zig").Prepared,
    roots: *const @import("blake3_execution_roots.zig").Prepared,
    paths: *const @import("blake3_stark_paths.zig").Prepared,
    pub fn graphs(self: Sources) [3]Graph {
        return .{ self.composition.circuit.graph(), self.deep.graph.graph(), self.fri.graph.graph() };
    }
    pub fn evaluations(self: Sources) [3][]const Q {
        return .{ self.composition.values, self.deep.evaluation.values, self.fri.evaluation.values };
    }
    /// The enclosing preparation admits the execution key/capture. Reevaluate
    /// retained arithmetic here before accepting it as a row source.
    pub fn validate(self: Sources, a: std.mem.Allocator) !void {
        try self.composition.circuit.validate();
        if (!std.mem.eql(u8, &self.composition.identity(), &self.composition.seal)) return error.InvalidExecutionComposition;
        const replay = try a.alloc(Q, self.composition.values.len);
        defer a.free(replay);
        try self.composition.circuit.evaluateInto(self.composition.inputs, replay);
        for (replay, self.composition.values) |actual, expected| if (!actual.eql(expected)) return error.InvalidExecutionComposition;
        try self.deep.graph.validateEvaluation(&self.deep.evaluation);
        try self.fri.evaluation.validateAgainst(&self.fri.graph);
    }
    pub fn externalInputs(self: Sources, a: std.mem.Allocator) ![]u32 {
        var nodes: std.ArrayList(u32) = .empty;
        errdefer nodes.deinit(a);
        for (self.composition.sources, 0..) |source, node| if (source == .public_input)
            try nodes.append(a, @intCast(node));
        return nodes.toOwnedSlice(a);
    }
    pub fn appendInputs(self: Sources, b: anytype) !void {
        try self.challenges.appendInputs(b);
        try self.payloads.appendClaims(b);
        try self.payloads.samples.appendInputs(b);
        try self.fri.appendInputs(b);
        try self.queries.appendInputs(b);
        try self.openings.appendInputs(b);
        try self.roots.appendKey(b);
        try self.roots.appendMain(b);
        try self.roots.appendWords(b);
    }
};
