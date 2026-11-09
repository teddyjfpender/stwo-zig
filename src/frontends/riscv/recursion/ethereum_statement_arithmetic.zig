//! Immutable arithmetic admission for Ethereum's statement and public claim.
//! Rows 11 and 15 supply the inputs; shared arithmetic AIR evaluates both DAGs.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const statement = @import("statement_semantics_circuit.zig");
const claim = @import("vm_public_semantics_circuit.zig");
const public_source = @import("segment_public_outer_source.zig");
const statement_source = @import("segment_statement_outer_source.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");

pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 2;

/// Construction authenticates and copies both graphs and their evaluations.
/// Internal reads borrow deeply const buffers from private storage. No caller
/// can adopt storage or supply a cached validation bit. Destroy after consumers.
pub const Prepared = opaque {
    pub fn init(
        allocator: std.mem.Allocator,
        statement_circuit: *const statement.Circuit,
        statement_evaluation: *const statement.Evaluation,
        claim_reference: *const claim.ClaimReference,
        claim_prepared: *const claim.ClaimPrepared,
    ) !*Prepared {
        return initWithClaimPolicy(.segment, allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared);
    }

    pub fn initForEthereumNativeRoots(
        allocator: std.mem.Allocator,
        statement_circuit: *const statement.Circuit,
        statement_evaluation: *const statement.Evaluation,
        claim_reference: *const claim.ClaimReference,
        claim_prepared: *const claim.ClaimPrepared,
    ) !*Prepared {
        return initWithClaimPolicy(.native_roots, allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared);
    }

    pub fn initForEthereumInitialInputs(
        allocator: std.mem.Allocator,
        statement_circuit: *const statement.Circuit,
        statement_evaluation: *const statement.Evaluation,
        claim_reference: *const claim.ClaimReference,
        claim_prepared: *const claim.ClaimPrepared,
    ) !*Prepared {
        return initWithClaimPolicy(.initial_inputs, allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared);
    }

    fn initWithClaimPolicy(
        comptime policy: enum { segment, native_roots, initial_inputs },
        allocator: std.mem.Allocator,
        statement_circuit: *const statement.Circuit,
        statement_evaluation: *const statement.Evaluation,
        claim_reference: *const claim.ClaimReference,
        claim_prepared: *const claim.ClaimPrepared,
    ) !*Prepared {
        try statement_circuit.validate();
        try claim_reference.validate();
        // A self-consistent producer seal is not circuit admission. Rebuild the
        // fixed Ethereum policy from capacity and compare its complete identity.
        var expected_claim = switch (policy) {
            .segment => try claim.ClaimReference.initForSegmentV2(allocator, claim_reference.shape, public_source.CLAIM_CIRCUIT_ID),
            .native_roots => try claim.ClaimReference.initForEthereumNativeRoots(allocator, claim_reference.shape, public_source.CLAIM_CIRCUIT_ID),
            .initial_inputs => try claim.ClaimReference.initForEthereumInitialInputs(allocator, claim_reference.shape, public_source.CLAIM_CIRCUIT_ID),
        };
        defer expected_claim.deinit();
        if (!std.mem.eql(u8, &expected_claim.authority_digest, &claim_reference.authority_digest))
            return error.EthereumStatementArithmeticMismatch;
        try claim_prepared.validateAgainst(claim_reference);
        if (claim_reference.circuit_id != public_source.CLAIM_CIRCUIT_ID or
            !std.mem.eql(u8, &statement_circuit.identity_digest, &statement_evaluation.circuit_identity))
            return error.EthereumStatementArithmeticMismatch;
        try public_source.validateArithmeticEvaluation(statement_circuit.graph(), statement_evaluation.inputs(), statement_evaluation.values());
        try public_source.validateArithmeticEvaluation(&claim_reference.circuit, claim_prepared.input_values, claim_prepared.evaluation.values);
        if (!try statement_circuit.graph().outputsAreZero(statement_evaluation.values()))
            return error.EthereumStatementArithmeticMismatch;

        const value = try allocator.create(Storage);
        errdefer allocator.destroy(value);
        var initialized: usize = 0;
        errdefer for (0..initialized) |index| {
            value.graphs[index].deinit();
            allocator.free(value.values[index]);
        };
        value.allocator = allocator;
        const circuits = .{ statement_circuit.graph(), &claim_reference.circuit };
        const input_evaluations = .{ statement_evaluation.values(), claim_prepared.evaluation.values };
        const identities = .{ statement_circuit.identity_digest, claim_reference.authority_digest };
        const ids = .{ statement_source.STATEMENT_CIRCUIT_ID, public_source.CLAIM_CIRCUIT_ID };
        inline for (0..LANE_COUNT) |index| {
            var graph = try public_source.OwnedGraph.init(allocator, circuits[index]);
            errdefer graph.deinit();
            const values = try allocator.dupe(QM31, input_evaluations[index]);
            value.graphs[index] = graph;
            value.values[index] = values;
            value.lanes[index] = .{ .circuit_id = ids[index], .active_in = .segment, .circuit_identity = identities[index], .graph = graph.graph };
            initialized += 1;
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/ethereum-statement-arithmetic/v4\x00");
        var version: [2]u8 = undefined;
        std.mem.writeInt(u16, &version, SCHEMA_VERSION, .little);
        hash.update(&version);
        for (value.lanes) |lane| {
            var id: [4]u8 = undefined;
            std.mem.writeInt(u32, &id, lane.circuit_id, .little);
            hash.update(&id);
            hash.update(&lane.circuit_identity);
            hash.update(&lane.graph.identity_digest);
        }
        value.identity = hash.finalResult();
        return @ptrCast(value);
    }

    pub fn deinit(self: *Prepared) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        for (&value.graphs, value.values) |*graph, values| {
            graph.deinit();
            allocator.free(values);
        }
        allocator.destroy(value);
    }

    pub fn lanes(self: *const Prepared) [LANE_COUNT]lowering.Lane {
        return storage(self).lanes;
    }

    /// Version and fixed circuit structure only; witness values are AIR inputs.
    pub fn identity(self: *const Prepared) [32]u8 {
        return storage(self).identity;
    }

    pub fn evaluations(self: *const Prepared) [LANE_COUNT]lowering.Evaluation {
        const value = storage(self);
        var result: [LANE_COUNT]lowering.Evaluation = undefined;
        for (&result, value.lanes, value.values) |*destination, lane, values|
            destination.* = .{ .circuit_identity = lane.circuit_identity, .values = values };
        return result;
    }

    fn storage(self: *const Prepared) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};

const Storage = struct {
    allocator: std.mem.Allocator,
    graphs: [LANE_COUNT]public_source.OwnedGraph,
    values: [LANE_COUNT][]QM31,
    lanes: [LANE_COUNT]lowering.Lane,
    identity: [32]u8,
};
