//! Immutable custody for authenticated statement and public-claim arithmetic.
//! Rows 11 and 15 supply the inputs; shared arithmetic AIR evaluates both DAGs.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const statement = @import("stwo_riscv_recursion").statement_semantics_circuit;
const claim = @import("stwo_riscv_recursion").vm_public_semantics_circuit;
const public_source = @import("stwo_riscv_recursion").segment_public_outer_source;
const statement_source = @import("stwo_riscv_recursion").segment_statement_outer_source;
const lowering = @import("stwo_riscv_rv32").recursion.air.verifier_arithmetic_lowering;

pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 2;

/// Static policy operation: the product supplies an independently rebuilt
/// reference, never a cached validation bit, mutable storage or runtime callback.
pub fn ForClaimPolicy(comptime Policy: type) type {
    return struct {
        pub fn init(
            allocator: std.mem.Allocator,
            statement_circuit: *const statement.Circuit,
            statement_evaluation: *const statement.Evaluation,
            claim_reference: *const claim.ClaimReference,
            claim_prepared: *const claim.ClaimPrepared,
        ) !*Prepared {
            try statement_circuit.validate();
            try claim_reference.validate();
            // A self-consistent producer seal is not circuit admission. Rebuild the
            // selected fixed policy from capacity and compare its complete identity.
            var expected_claim = try Policy.rebuild(allocator, claim_reference.shape);
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
            hash.update(Policy.IDENTITY_DOMAIN);
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
    };
}

/// Constructor-owned graphs and evaluations. No public adoption API exists.
pub const Prepared = opaque {
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
