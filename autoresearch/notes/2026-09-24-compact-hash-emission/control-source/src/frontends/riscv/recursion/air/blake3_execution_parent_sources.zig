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
    pub fn appendInputs(self: Sources, b: anytype) !void {
        try b.append(12, self.challenges.rows, self.challenges.fixed);
        try b.append(11, self.challenges.packs, self.challenges.fixed_packs);
        try b.append(12, self.payloads.claim_sources, self.payloads.fixed_claim_sources);
        try b.append(11, self.payloads.claim_packs, self.payloads.fixed_claim_packs);
        try b.append(12, self.payloads.samples.sources, self.payloads.samples.fixed_sources);
        try b.append(11, self.payloads.samples.packs, self.payloads.samples.fixed_packs);
        try b.append(12, self.fri.sources, self.fri.fixed_sources);
        try b.append(12, self.fri.destinations, self.fri.fixed_destinations);
        try b.append(12, self.queries.rows, self.queries.fixed);
        try b.append(12, self.openings.rows, self.openings.fixed);
        try b.append(2, &self.roots.key, &self.roots.key);
        try b.append(9, self.roots.words, self.roots.fixed_words);
    }
};
