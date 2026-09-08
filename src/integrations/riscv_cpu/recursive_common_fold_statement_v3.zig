//! Owned common-fold statement semantics, using the existing row-11 circuit.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const air = recursion.air;
const circuit_mod = recursion.statement_semantics_circuit;
const statement_source = recursion.segment_statement_outer_source;
const graph_mod = air.composition_circuit;
const public = @import("recursive_field_node_public_v2.zig");
const M31 = core.fields.m31.M31;
const Row11 = [air.statement_semantics_input.LOGICAL_INPUT_COUNT]M31;
const Words = recursion.span_statement.StatementWords;

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: circuit_mod.Circuit,
    nodes: []graph_mod.Node,
    graph: graph_mod.CircuitGraph,
    evaluation: circuit_mod.Evaluation,
    semantics_rows: []Row11,
    identity: [32]u8,

    pub fn init(allocator: std.mem.Allocator, left: *const public.NodePublicV2, right: *const public.NodePublicV2, parent: *const public.NodePublicV2) !Prepared {
        const left_words = try words(left);
        const right_words = try words(right);
        const parent_words = try words(parent);
        var circuit = try circuit_mod.build(allocator);
        errdefer circuit.deinit();
        const nodes = try allocator.alloc(graph_mod.Node, circuit.nodeCount());
        errdefer allocator.free(nodes);
        statement_source.convertGraphNodes(circuit.graph().nodes(), nodes);
        const graph = try graph_mod.CircuitGraph.authenticate(nodes, circuit.graph().outputs(), statement_source.LOWERING_GRAPH_DIGEST);
        var evaluation = try circuit.evaluate(allocator, circuit_mod.Witness.forBinary(&left_words, &right_words, &parent_words));
        errdefer evaluation.deinit();
        var preprocessing = try air.statement_semantics_input_witness.Preprocessed.init(allocator, statement_source.STATEMENT_CIRCUIT_ID, circuit.inputBindings());
        defer preprocessing.deinit();
        const semantics_rows = try allocator.alloc(Row11, preprocessing.rows.len);
        errdefer allocator.free(semantics_rows);
        for (semantics_rows, preprocessing.rows, evaluation.inputs()) |*row, metadata, value|
            row.* = try air.statement_semantics_input_witness.logicalRow(metadata, try value.tryIntoM31(), .binary_node);
        var result = Prepared{ .allocator = allocator, .circuit = circuit, .nodes = nodes, .graph = graph, .evaluation = evaluation, .semantics_rows = semantics_rows, .identity = undefined };
        result.identity = result.contentIdentity();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.semantics_rows);
        self.evaluation.deinit();
        self.allocator.free(self.nodes);
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Prepared) !void {
        try self.circuit.validate();
        try self.graph.validate();
        if (!std.mem.eql(u8, &self.graph.identity_digest, &statement_source.LOWERING_GRAPH_DIGEST) or
            !std.mem.eql(u8, &self.identity, &self.contentIdentity())) return error.CommonFoldStatementMismatch;
    }

    pub fn sharedInput(self: *const Prepared) !recursion.binary_fri_outer_source.SharedArithmeticInput {
        try self.validate();
        return recursion.binary_fri_outer_source.SharedArithmeticInput.seal(.{
            .circuit_id = statement_source.STATEMENT_CIRCUIT_ID,
            .active_in = .binary,
            .circuit_identity = self.circuit.identity_digest,
            .graph = self.graph,
        }, .{ .circuit_identity = self.evaluation.circuit_identity, .values = self.evaluation.values() });
    }

    fn contentIdentity(self: *const Prepared) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/common-fold-statement/v3\x00");
        hash.update(&self.circuit.identity_digest);
        hash.update(&self.graph.identity_digest);
        hash.update(std.mem.sliceAsBytes(self.evaluation.storage));
        hash.update(std.mem.sliceAsBytes(self.semantics_rows));
        return hash.finalResult();
    }
};

fn words(node: *const public.NodePublicV2) !Words {
    try node.validate();
    var result: Words = undefined;
    for (&result, node.statement_words) |*value, word| value.* = M31.fromCanonical(word);
    return result;
}
